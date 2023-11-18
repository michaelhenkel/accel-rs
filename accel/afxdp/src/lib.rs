use std::{sync::{Arc, Mutex}, ffi::CString, os::fd::AsRawFd, hash::Hasher};
use std::hash::Hash;
use core::time::Duration;
use aya::maps::{XskMap, MapData, HashMap as AyaHashMap};
use log::info;
use s2n_quic::provider::io::xdp::tx::{Error,PayloadBuffer, Message};
use s2n_quic_xdp::{
    if_xdp::{self, XdpFlags},
    umem::{
        self, Umem,
    },
    io::{
        rx::{self, Driver as _, WithCooldown},
        tx,
    },
    ring,
    socket,
    syscall, 
};
use s2n_quic_core::{
    io::{
        rx::Rx as _,
        tx::{Tx as _, Queue}
    },
    xdp::path,
    inet::ExplicitCongestionNotification,
};
use tokio::io::unix::AsyncFd;
use common::InterfaceQueue;

#[derive(Clone)]
pub struct AfXdp{
    ifidx: u32,
    interface: String,
    rx_queue_len: u32,
    tx_queue_len: u32,
    frame_size: u32,
    rx_cooldown: u16,
    queue_ids: Vec<u32>,
}

impl Hash for AfXdp {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.interface.hash(state);
        self.rx_queue_len.hash(state);
        self.tx_queue_len.hash(state);
        self.frame_size.hash(state);
        self.rx_cooldown.hash(state);
        self.queue_ids.hash(state);
    }
}

impl PartialEq for AfXdp {
    fn eq(&self, other: &Self) -> bool {
        self.interface == other.interface
    }
}

impl Eq for AfXdp {}

impl AfXdp {
    pub fn new(
            ifidx: u32,
            interface: String,
            rx_queue_len: u32,
            tx_queue_len: u32,
            frame_size: u32,
            rx_cooldown: u16,
            queue_ids: Vec<u32>) -> Self {
        Self{
            ifidx,
            interface,
            rx_queue_len,
            tx_queue_len,
            frame_size,
            rx_cooldown,
            queue_ids,
        }
    }
    pub fn setup(&mut self, xsk_map: Arc<Mutex<XskMap<MapData>>>, interface_queue_map: Arc<Mutex<AyaHashMap<MapData, InterfaceQueue, u32>>>, intf_counter: u32) -> anyhow::Result<(
        rx::Rx<WithCooldown<Arc<AsyncFd<socket::Fd>>>>,
        tx::Tx<tx::BusyPoll>,
    )>{
        let fill_ring_len = self.rx_queue_len * 2;
        let completion_ring_len = self.tx_queue_len;
        let max_queues = self.queue_ids.len() as u32;
        let umem_size = (self.rx_queue_len + self.tx_queue_len) * max_queues;
        let umem = umem::Builder {
            frame_count: umem_size,
            frame_size: self.frame_size,
            ..Default::default()
        }
        .build()?;
        let mut address = if_xdp::Address {
            flags: XdpFlags::USE_NEED_WAKEUP & XdpFlags::SHARED_UMEM,
            ..Default::default()
        };
        address.set_if_name(&CString::new(self.interface.clone())?)?;

        let mut shared_umem_fd = None;
        let mut tx_channels = vec![];
        let mut rx_channels = vec![];
        let mut rx_fds = vec![];

        let mut desc = umem.frames();

        // iterate over all of the queues and create sockets for each one
        for queue_id in &self.queue_ids {
            let socket = socket::Fd::open()?;

            // if we've already attached a socket to the UMEM, then reuse the first FD
            if let Some(fd) = shared_umem_fd {
                address.set_shared_umem(&fd);
            } else {
                socket.attach_umem(&umem)?;
                shared_umem_fd = Some(socket.as_raw_fd());
            }

            // set the queue id to the current value
            address.queue_id = queue_id.clone();

            // file descriptors can only be added once so wrap it in an Arc
            let async_fd = Arc::new(AsyncFd::new(socket.clone())?);

            // get the offsets for each of the rings
            let offsets = syscall::offsets(&socket)?;

            {
                // create a pair of rings for receiving packets
                let mut fill = ring::Fill::new(socket.clone(), &offsets, fill_ring_len)?;
                let rx = ring::Rx::new(socket.clone(), &offsets, self.rx_queue_len)?;

                // remember the FD so we can add it to the XSK map later
                rx_fds.push((queue_id, socket.clone()));

                // put descriptors in the Fill queue
                fill.init((&mut desc).take(self.rx_queue_len as _));

                let cooldown = s2n_quic_core::task::cooldown::Cooldown::new(self.rx_cooldown);

                rx_channels.push(rx::Channel {
                    rx,
                    fill,
                    driver: async_fd.clone().with_cooldown(cooldown),
                });
            };

            {
                // create a pair of rings for transmitting packets
                let mut completion =
                    ring::Completion::new(socket.clone(), &offsets, completion_ring_len)?;
                let tx = ring::Tx::new(socket.clone(), &offsets, self.tx_queue_len)?;

                // put descriptors in the completion queue
                completion.init((&mut desc).take(self.tx_queue_len as _));

                tx_channels.push(tx::Channel {
                    tx,
                    completion,
                    driver: tx::BusyPoll,
                });
            };

            // finally bind the socket to the configured address
            syscall::bind(&socket, &mut address)?;
        }
        for (rx_fd, fd) in rx_fds {
            let interface_queue = InterfaceQueue{
                ifidx: self.ifidx,
                queue: *rx_fd,
            };
            let mut interface_queue_map = interface_queue_map.lock().unwrap();
            interface_queue_map.insert(interface_queue, intf_counter, 0)?;
            let mut xsk_map = xsk_map.lock().unwrap();
            xsk_map.set(intf_counter, fd, 0)?;
            info!("added socket for if/queue {}/{} with idx {}", self.ifidx, rx_fd, intf_counter);
        }
        // make sure we've allocated all descriptors from the UMEM to a queue
        assert_eq!(desc.count(), 0, "descriptors have been leaked");
        let state = Default::default();
        let tx = tx::Tx::new(tx_channels, umem.clone(), state);
        let rx = rx::Rx::new(rx_channels, umem);
        Ok((rx, tx))
    }

    pub async fn send(&self,
            mut tx: tx::Tx<tx::BusyPoll>,
            mut t_rx: tokio::sync::mpsc::Receiver<Vec<Packet>>
        )
    {
        let mut needs_poll = false;
        loop {
            if core::mem::take(&mut needs_poll) {
                if tx.ready().await.is_err() {
                    break;
                }
            }
            while let Some(packet_list) = t_rx.recv().await {
                info!("sending {} packets", packet_list.len());
                for packet in &packet_list {
                    tx.queue(|queue| {
                        queue.push(packet.clone()).unwrap();
                    });
                }
            }

            maybe_yield().await;
        }
    }

    pub async fn recv<F>(&self,
            mut rx: rx::Rx<WithCooldown<Arc<AsyncFd<socket::Fd>>>>,
            f: F
        )
    where
    F: FnOnce(&mut rx::Queue<WithCooldown<Arc<AsyncFd<socket::Fd>>>>) + Clone,
    {
        while rx.ready().await.is_ok() {
            rx.queue(f.clone());
            maybe_yield().await;
        }
    }
}



async fn maybe_yield() {
    use ::rand::prelude::*;
    if thread_rng().gen() {
        tokio::task::yield_now().await;
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub path: path::Tuple,
    pub ecn: ExplicitCongestionNotification,
    pub counter: u32,
    pub data: Vec<u8>,
}

/// Make it easy to write the packet to the TX queue
impl Message for Packet {
    type Handle = path::Tuple;

    fn path_handle(&self) -> &Self::Handle {
        &self.path
    }

    fn ecn(&mut self) -> ExplicitCongestionNotification {
        self.ecn
    }

    fn delay(&mut self) -> Duration {
        Default::default()
    }

    fn ipv6_flow_label(&mut self) -> u32 {
        self.counter
    }

    fn can_gso(&self, _: usize, _: usize) -> bool {
        false
    }

    fn write_payload(&mut self, mut payload: PayloadBuffer, _gso: usize) -> Result<usize, Error> {
        payload.write(self.data.as_slice())
    }
}