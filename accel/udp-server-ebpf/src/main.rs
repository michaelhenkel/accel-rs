#![no_std]
#![no_main]

use core::mem::zeroed;

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::{HashMap, XskMap, LpmTrie},
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{
    ptr_at, Stats,
    InterfaceQueue,
    BthHdr,
    InterfaceConfig,
    DethHdr,
    MadHdr,
    CmConnectReply,
    CmConnectRequest,
    //CmReadyToUse,
    QpState,
    CmState,
    //CmDisconnectRequest,
    //CmDisconnectReply
};

#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u32, Stats> =
    HashMap::<u32, Stats>::with_max_entries(128, 0);

#[map(name = "XSKMAP")]
static XSKMAP: XskMap = XskMap::with_max_entries(8, 0);

#[map(name = "INTERFACEQUEUEMAP")]
static INTERFACEQUEUEMAP: HashMap<InterfaceQueue, u32> =
    HashMap::<InterfaceQueue, u32>::with_max_entries(100, 0);

#[map(name = "QPSTATE")]
static QPSTATE: HashMap<[u8;3], QpState> =
    HashMap::<[u8;3], QpState>::with_max_entries(1000, 0);

#[map(name = "CMSTATE")]
static CMSTATE: HashMap<[u8;8], CmState> =
    HashMap::<[u8;8], CmState>::with_max_entries(1000, 0);

#[xdp]
pub fn udp_server(ctx: XdpContext) -> u32 {
    match try_udp_server(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_udp_server(ctx: XdpContext) -> Result<u32, u32> {
    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)
        .ok_or(xdp_action::XDP_ABORTED)?;
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ipv4_hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)
        .ok_or(xdp_action::XDP_ABORTED)?;
    if unsafe { (*ipv4_hdr).proto } != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_hdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)
        .ok_or(xdp_action::XDP_ABORTED)?;
    if u16::from_be(unsafe { (*udp_hdr).dest }) != 4791 && u16::from_be(unsafe { (*udp_hdr).dest }) != 4792{
        warn!(&ctx, "received UDP packet with dest port {}", u16::from_be(unsafe { (*udp_hdr).dest }));
        return Ok(xdp_action::XDP_PASS);
    }
    let bth_hdr = ptr_at::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
        .ok_or(xdp_action::XDP_ABORTED)?;



    let dest_qp = unsafe { (*bth_hdr).dest_qpn };
    let dest_qp_dec = u32::from_be_bytes([0, dest_qp[0], dest_qp[1], dest_qp[2]]);
    let op_code = u8::from_be(unsafe { (*bth_hdr).opcode });
    let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };

    if (dest_qp_dec == 0 || dest_qp_dec == 1) && op_code == 100 {
        info!(&ctx, "cm mgmt packet");
        let mad_hdr = ptr_at::<MadHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
        let transaction_id = unsafe { (*mad_hdr).transaction_id };
        let transaction_id_dec = u64::from_be_bytes([transaction_id[0], transaction_id[1], transaction_id[2], transaction_id[3], transaction_id[4], transaction_id[5], transaction_id[6], transaction_id[7]]);
        match u16::to_be(unsafe{ (*mad_hdr).attribute_id }){
            16 => { 
                info!(&ctx, "cm connect request packet");
                let cm_state = &CmState{
                    qp_id: [0, 0, 0],
                    state: 1,
                    first_psn: 0,
                };
                CMSTATE.insert(&transaction_id, cm_state, 0).map_err(|_| xdp_action::XDP_ABORTED)?;
            },
            19 => {
                info!(&ctx, "cm connect reply packet");
                let connect_reply_hdr = ptr_at::<CmConnectReply>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                let cm_state = CMSTATE.get_ptr_mut(&transaction_id);
                match cm_state {
                    Some(cm_state) => {
                        let local_qpn = unsafe { (*connect_reply_hdr).local_qpn };
                        let starting_psn = unsafe { (*connect_reply_hdr).starting_psn };
                        let starting_psn = u32::from_be_bytes([0, starting_psn[0], starting_psn[1], starting_psn[2]]);
                        unsafe { 
                            (*cm_state).state = 2;
                            (*cm_state).qp_id =  local_qpn;
                            (*cm_state).first_psn = starting_psn;
                        };
                    },
                    None => {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            },
            20 => {
                info!(&ctx, "cm ready to use packet");
                //let ready_to_use_hdr = ptr_at::<CmReadyToUse>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                let cm_state = CMSTATE.get_ptr_mut(&transaction_id);
                match cm_state {
                    Some(cm_state) => { 
                        unsafe { (*cm_state).state = 3 };
                        let qp_id = unsafe { (*cm_state).qp_id };
                        let qp_state = QpState{
                            qp_id,
                            first_psn: unsafe { (*cm_state).first_psn },
                            last_psn: unsafe { (*cm_state).first_psn - 1 },
                            out_of_order: 0,
                            rx_counter: 0,
                        };
                        QPSTATE.insert(&qp_id, &qp_state, 0).map_err(|_| xdp_action::XDP_ABORTED)?;
                    },
                    None => {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            },
            21 => {
                info!(&ctx, "cm disconnect request packet");
                //let disconnect_req_hdr = ptr_at::<CmDisconnectRequest>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                let cm_state = CMSTATE.get_ptr_mut(&transaction_id);
                match cm_state {
                    Some(cm_state) => { 
                        unsafe { (*cm_state).state = 4 };
                    },
                    None => {
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            },
            22 => {
                info!(&ctx, "cm disconnect reply packet");
                //let disconnect_repl_hdr = ptr_at::<CmDisconnectReply>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                let qp_id = match unsafe { CMSTATE.get(&transaction_id) }{
                    Some(cm_state) => { 
                        (*cm_state).qp_id
                    },
                    None => {
                        return Ok(xdp_action::XDP_DROP);
                    }
                };
                let qp_id_dec = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
                match QPSTATE.remove(&qp_id){
                    Ok(()) => {
                        info!(&ctx, "qp_state removed for qp_id {}", qp_id_dec);
                    },
                    Err(_) => {
                        info!(&ctx, "qp_state not found for qp_id {}", qp_id_dec);
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
                match CMSTATE.remove(&transaction_id){
                    Ok(()) => {
                        info!(&ctx, "cm_state removed for transaction_id {}", transaction_id_dec);
                    },
                    Err(_) => {
                        info!(&ctx, "cm_state not found for transaction_id {}", transaction_id_dec);
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            },
            _ => {
                warn!(&ctx, "unknown cm packet");
                return Ok(xdp_action::XDP_PASS);
            }
        }
        
        let queue_idx = unsafe { (*ctx.ctx).rx_queue_index };
        let interface_queue = InterfaceQueue{
            ifidx: if_idx,
            queue: queue_idx,
        };
        let queue_idx = match unsafe { INTERFACEQUEUEMAP.get(&interface_queue )}{
            Some(queue_idx) => {
                info!(
                    &ctx,
                    "received BTH packet with opcode {} and dest qpn {} on queue {}",
                    op_code, dest_qp_dec, *queue_idx
                );
                queue_idx
            },
            None => {
                info!(
                    &ctx,
                    "received BTH packet with opcode {} and dest qpn {} on unknown queue",
                    op_code, dest_qp_dec);
                return Ok(xdp_action::XDP_DROP)
            },
        };
        match XSKMAP.redirect(*queue_idx, xdp_action::XDP_DROP as u64){
            Ok(res) => {
                info!(&ctx, "redirected to queue {} with res {}", *queue_idx, res);
                return Ok(res);
            },
            Err(e) => {
                info!(&ctx, "error redirecting to queue {}: {}", *queue_idx, e);
                return Ok(xdp_action::XDP_ABORTED);
            }
        }
    }

    let ingress_if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&ingress_if_idx).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };

    let seq_num = unsafe { (*bth_hdr).psn_seq };
    let seq_num = u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]]);

    if let Some(qp_state) = QPSTATE.get_ptr_mut(&dest_qp){
        if unsafe { (*qp_state).last_psn + 1 } != seq_num {
            unsafe { (*statsmap).ooo += 1 };
        }
        unsafe { (*qp_state).last_psn = seq_num };
    }

    return Ok(xdp_action::XDP_ABORTED);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

