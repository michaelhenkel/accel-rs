use std::{collections::{HashMap, HashSet}, sync::Arc, ffi::CString, os::unix::io::AsRawFd, any};
use aya::maps::{XskMap, MapData};
use common::BthHdr;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use log::info;
use tokio::{
    task::JoinHandle,
    sync::RwLock, io::unix::AsyncFd,
};
use cli_server::cli_server::cli_server::UdpServerStats;
use s2n_quic_xdp::{
    if_xdp::{self, XdpFlags},
    umem::{
        self, Umem, Builder
    },
    io::{
        self,
        rx::{self, Rx, Driver as _, WithCooldown, Queue},
        tx::{self, Tx},
    },
    ring,
    socket as afxdp_socket,
    syscall,
    
};

use s2n_quic::provider::io::xdp::encoder;

use s2n_quic_core::{
    inet::ExplicitCongestionNotification,
    io::{
        rx::{Queue as _, Rx as _},
        tx::{Error, Message, PayloadBuffer, Queue as _, Tx as _},
    },
    sync::atomic_waker,
    xdp::path,
};
use core::{mem::size_of, time::Duration};

const BUFF_SIZE: usize = 2048;
const BUF_NUM: usize = 65535 * 2;
const BATCH_SIZE: usize = 64;

pub struct UdpServer{
    zero_copy: bool,
    interface_map: HashMap<String, u32>,
    queues: Option<Vec<(u8,u8)>>,
}

pub enum UdpServerCommand{
    Get{tx: tokio::sync::oneshot::Sender<UdpServerStats>},
    Reset{tx: tokio::sync::oneshot::Sender<UdpServerStats>},
}

pub enum StatsCommand{
    Get(tokio::sync::oneshot::Sender<String>),
}

#[derive(Default)]
pub struct StatsMap{
    pub last_expected: u32,
    pub last_seq_num: u32,
    pub rx_packets: usize,
    pub out_of_order: u32,
    pub in_order: u32,
    pub ooo_packets: HashSet<u32>
}

type SetupResult = anyhow::Result<(
    umem::Umem,
    Vec<rx::Channel<WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>>,
    Vec<(u32, afxdp_socket::Fd)>,
    Vec<tx::Channel<tx::BusyPoll>>,
)>;

impl UdpServer{
    pub fn new(zero_copy: bool, interface_map: HashMap<String, u32>, queues: Option<Vec<(u8,u8)>>) -> UdpServer {
        UdpServer{
            zero_copy,
            interface_map,
            queues,
        }
    }

    pub async fn setup(&self, interface: String, queue_ids: Vec<u32>) -> SetupResult{
        let frame_size = BUFF_SIZE as u32;
        let rx_queue_len = 8192 * 2;
        let tx_queue_len = 8192;
        let fill_ring_len = rx_queue_len * 2;
        let completion_ring_len = tx_queue_len;
        let rx_cooldown = 10;

        //let max_queues = syscall::max_queues(&interface);
        let max_queues = queue_ids.len() as u32;
        let umem_size = (rx_queue_len + tx_queue_len) * max_queues;
        //let umem_size = BUF_NUM as u32;
        // create a UMEM
        let umem = umem::Builder {
            frame_count: umem_size,
            frame_size,
            ..Default::default()
        }
        .build()?;

        // setup the address we're going to bind to
        let mut address = if_xdp::Address {
            flags: XdpFlags::USE_NEED_WAKEUP,
            ..Default::default()
        };
        address.set_if_name(&CString::new(interface.clone())?)?;

        let mut shared_umem_fd = None;
        let mut tx_channels = vec![];
        let mut rx_channels = vec![];
        let mut rx_fds = vec![];

        let mut desc = umem.frames();

        // iterate over all of the queues and create sockets for each one
        for queue_id in 0..max_queues {
            let socket = afxdp_socket::Fd::open()?;

            // if we've already attached a socket to the UMEM, then reuse the first FD
            if let Some(fd) = shared_umem_fd {
                address.set_shared_umem(&fd);
            } else {
                socket.attach_umem(&umem)?;
                shared_umem_fd = Some(socket.as_raw_fd());
            }

            // set the queue id to the current value
            address.queue_id = queue_id;

            // file descriptors can only be added once so wrap it in an Arc
            let async_fd = Arc::new(AsyncFd::new(socket.clone())?);

            // get the offsets for each of the rings
            let offsets = syscall::offsets(&socket)?;

            {
                // create a pair of rings for receiving packets
                let mut fill = ring::Fill::new(socket.clone(), &offsets, fill_ring_len)?;
                let rx = ring::Rx::new(socket.clone(), &offsets, rx_queue_len)?;

                // remember the FD so we can add it to the XSK map later
                rx_fds.push((queue_id, socket.clone()));

                // put descriptors in the Fill queue
                fill.init((&mut desc).take(rx_queue_len as _));

                let cooldown = s2n_quic_core::task::cooldown::Cooldown::new(rx_cooldown);

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
                let tx = ring::Tx::new(socket.clone(), &offsets, tx_queue_len)?;

                // put descriptors in the completion queue
                completion.init((&mut desc).take(tx_queue_len as _));

                tx_channels.push(tx::Channel {
                    tx,
                    completion,
                    driver: tx::BusyPoll,
                });
            };

            // finally bind the socket to the configured address
            syscall::bind(&socket, &mut address)?;
        }

        // make sure we've allocated all descriptors from the UMEM to a queue
        assert_eq!(desc.count(), 0, "descriptors have been leaked");

        Ok((umem, rx_channels, rx_fds, tx_channels))
    }


    pub async fn run(&self, mut xsk_map: XskMap<MapData>, mut ctrl_rx: tokio::sync::mpsc::Receiver<UdpServerCommand>) -> anyhow::Result<()>{
        info!("running udp server");

        let stats_map = Arc::new(RwLock::new(StatsMap::default()));
        let stats_map_clone = Arc::clone(&stats_map);
        let mut jh_list: Vec<JoinHandle<Result<(), Error>>> = Vec::new();
        let jh = tokio::spawn( async move{
            loop {
                match ctrl_rx.recv().await{
                    Some(msg) => {
                        match msg {
                            UdpServerCommand::Get{tx} => {
                                let stats_map = stats_map.read().await;
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                    in_order: stats_map.in_order as i32,
                                };
                                match tx.send(udp_server_stats){
                                    Ok(_) => {  },
                                    Err(_e) => { info!("failed to send stats reply"); },
                                }
                            },
                            UdpServerCommand::Reset{tx} => {                                
                                let mut stats_map = stats_map.write().await;
                                let udp_server_stats = UdpServerStats{
                                    rx: stats_map.rx_packets as i32,
                                    out_of_order: stats_map.out_of_order as i32,
                                    in_order: stats_map.in_order as i32,
                                };
                                stats_map.rx_packets = 0;
                                stats_map.out_of_order = 0;
                                stats_map.last_seq_num = 0;
                                stats_map.last_expected = 0;
                                stats_map.in_order = 0;
                                stats_map.ooo_packets.clear();
                                match tx.send(udp_server_stats){
                                    Ok(_) => {  },
                                    Err(_e) => { info!("failed to send stats reply"); },
                                }
                            },
                        } 
                    },
                    None => {
                        info!("ctrl channel closed");
                        break;
                    }
                }
            }
            Ok(())
        });
        jh_list.push(jh);

        for (intf, _intf_idx) in &self.interface_map {
            let stats_map = Arc::clone(&stats_map_clone);
            info!("creating afxdp socket for interface {}", intf);
            let queues = if let Some(queues) = &self.queues{
                queues.clone()
            } else {
                vec![(0,0)]
            };
            //let mut queue_list = Vec::new();
            for (queue, core) in queues{
                let stats_map = Arc::clone(&stats_map);

                //queue_list.push(queue as u32);
                let (umem, rx, rx_fds, tx) = match self.setup(intf.clone(), vec![queue as u32]).await{
                    Ok(res) => {
                        res
                    },
                    Err(e) => { panic!("failed to setup interface {}: {}", intf, e); },
                };
                for (rx_fd, fd) in rx_fds {
                    info!("adding rx_fd {} to xsk map", rx_fd);
                    xsk_map.set(rx_fd, fd, 0)?;
                }
    
    
    
                let jh = tokio::spawn( async move{
                    let core = core_affinity::CoreId { id: core as usize };
                    core_affinity::set_for_current(core);
                    let mut encoder = encoder::Config::default();
                    encoder.set_checksum(false);
                    let io_rx = rx::Rx::new(rx, umem.clone());
                    let io_tx = tx::Tx::new(tx, umem, encoder);
                    
                    recv(io_rx, stats_map).await;
                    Ok(())
                    
                });
                jh_list.push(jh);
                
            }
            /*
            let (umem, rx, rx_fds, tx) = match self.setup(intf.clone(), queue_list).await{
                Ok(res) => {
                    res
                },
                Err(e) => { panic!("failed to setup interface {}: {}", intf, e); },
            };
            for (rx_fd, fd) in rx_fds {
                info!("adding rx_fd {} to xsk map", rx_fd);
                xsk_map.set(rx_fd, fd, 0)?;
            }



            let jh = tokio::spawn( async move{
                let mut encoder = encoder::Config::default();
                encoder.set_checksum(false);
                let io_rx = rx::Rx::new(rx, umem.clone());
                let io_tx = tx::Tx::new(tx, umem, encoder);
                
                recv(io_rx, stats_map).await;
                Ok(())
                
            });
            jh_list.push(jh);
            */
    
        }

        
        futures::future::join_all(jh_list).await;
        info!("udp server finished");
        Ok(())
    }
}

async fn recv(mut rx: Rx<WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>, stats_map: Arc<RwLock<StatsMap>>) {
    //let mut rx = Rx::new(inputs, umem);
    info!("starting udp server recv");
    //let mut actual = s2n_quic_core::interval_set::IntervalSet::default();

    while rx.ready().await.is_ok() {
        let mut stats_map = stats_map.write().await;
        rx.queue(|queue| {
            //let mut packet_list = Vec::new();
            queue.for_each(|header, payload| {
                //info!("received packet");
                stats_map.rx_packets += 1;
                let data_ptr = payload.as_ptr() as usize;
                //let eth_hdr = data_ptr as *const EthHdr;
                //info!("source mac addr: {:x?}", unsafe { (*eth_hdr).src_addr } );

                let bth_hdr = data_ptr as *const BthHdr;
                let seq_num = {
                    let seq_num = unsafe { (*bth_hdr).psn_seq };
                    u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]])
                };
                //info!("received packet with seq num {}", seq_num);
                //packet_list.push(bth_hdr);
                if stats_map.last_seq_num > 0 {
                    if stats_map.last_seq_num + 1 != seq_num {
                        stats_map.out_of_order += 1;
                        stats_map.ooo_packets.insert(seq_num);
                        stats_map.last_expected = stats_map.last_seq_num + 1;
                    } else {
                        stats_map.last_seq_num = seq_num;
                        stats_map.in_order += 1;
                    }
                } else {
                    stats_map.in_order += 1;
                    stats_map.last_seq_num = seq_num;
                }
                loop {
                    let l = stats_map.last_seq_num + 1;
                    if stats_map.ooo_packets.remove(&(l)){
                        stats_map.last_seq_num += 1;
                    } else {
                        break;
                    }
                }
            });
        });
        maybe_yield().await;
    }
}



async fn maybe_yield() {
    use ::rand::prelude::*;
    if thread_rng().gen() {
        tokio::task::yield_now().await;
    }
}

#[derive(Debug)]
struct Packet {
    pub path: path::Tuple,
    pub ecn: ExplicitCongestionNotification,
    pub counter: u32,
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
        payload.write(&self.counter.to_be_bytes())
    }
}