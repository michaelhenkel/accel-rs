use arraydeque::{ArrayDeque, Wrapping};
use afxdp::{
    mmap_area::MmapArea,
    socket::{
        Socket as AfXdpSocket,
        SocketOptions,
        SocketRx,
        SocketTx,
        SocketNewError
    },
    umem::{
        Umem,
        UmemCompletionQueue,
        UmemFillQueue
    },
    PENDING_LEN,
    buf_mmap::BufMmap,
};
use libbpf_sys::{
    XSK_RING_CONS__DEFAULT_NUM_DESCS,
    XSK_RING_PROD__DEFAULT_NUM_DESCS,
};
use std::sync::Arc;
use std::cmp::min;

const COMPLETION_RING_SIZE: u32 = XSK_RING_CONS__DEFAULT_NUM_DESCS;
const FILL_RING_SIZE: u32 = XSK_RING_PROD__DEFAULT_NUM_DESCS;

#[derive(Debug, Clone, Copy, Default)]
pub struct BufCustom {}

pub struct Socket<'a>{
    pub cq: UmemCompletionQueue<'a, BufCustom>,
    pub fq: UmemFillQueue<'a, BufCustom>,
    pub socket: SocketType<'a>,
    pub v: ArrayDeque<[BufMmap<'a, BufCustom>; PENDING_LEN], Wrapping>,
    pub fq_deficit: usize,
}

pub enum SocketRxTx{
    Rx,
    Tx,
}

impl <'a>Socket<'a>{
    pub fn new(area: Arc<MmapArea<'a, BufCustom>>, bufs: &mut Vec<BufMmap<'a, BufCustom>>, socket_type: SocketRxTx, intf: String, buf_num: usize, zero_copy: bool) -> Socket<'a> {
        let intf = intf.as_str();
        let umem = Umem::new(
            area.clone(),
            COMPLETION_RING_SIZE,
            FILL_RING_SIZE,
        );
        let (umem1, cq, mut fq) = match umem {
            Ok(umem) => umem,
            Err(err) => panic!("no umem for you: {:?}", err),
        };
        let mut options = SocketOptions::default();
        options.zero_copy_mode = zero_copy;
        options.copy_mode = !zero_copy;
        
        let (_skt, skt_type) = match socket_type{
            SocketRxTx::Rx => {
                let socket: Result<(Arc<AfXdpSocket<'_, BufCustom>>, SocketRx<'_, BufCustom>), SocketNewError> = AfXdpSocket::new_rx(
                    umem1.clone(),
                    intf,
                    0,
                    COMPLETION_RING_SIZE,
                    options,
                    1
                );
                let (skt, rx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Rx(rx))
            },
            SocketRxTx::Tx => {
                let socket = AfXdpSocket::new_tx(
                    umem1.clone(),
                    intf,
                    0,
                    FILL_RING_SIZE,
                    //4096,
                    options,
                    1
                );
                let (skt, tx) = match socket {
                    Ok(skt) => skt,
                    Err(err) => panic!("no socket for you: {:?}", err),
                };
                (skt, SocketType::Tx(tx))
            },
        };
        let r = fq.fill(
            bufs,
            min(FILL_RING_SIZE as usize, buf_num),
        );
        match r {
            Ok(n) => {
                if n != min(FILL_RING_SIZE as usize, buf_num) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        buf_num, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }


        //unsafe { xsk_socket__update_xskmap(xsk_sock, map_fd) };

        let v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        Socket { cq, fq, socket: skt_type, v, fq_deficit: 0 }

    }
}

pub enum SocketType<'a>{
    Rx(SocketRx<'a, BufCustom>),
    Tx(SocketTx<'a, BufCustom>),
}