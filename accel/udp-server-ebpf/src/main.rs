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
};

#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u32, Stats> =
    HashMap::<u32, Stats>::with_max_entries(128, 0);

#[map(name = "XSKMAP")]
static XSKMAP: XskMap = XskMap::with_max_entries(8, 0);

#[map(name = "INTERFACEQUEUEMAP")]
static INTERFACEQUEUEMAP: HashMap<InterfaceQueue, u32> =
    HashMap::<InterfaceQueue, u32>::with_max_entries(100, 0);

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

    let dest_qpn = unsafe { (*bth_hdr).dest_qpn };
    let dest_qpn_dec = u32::from_be_bytes([0, dest_qpn[0], dest_qpn[1], dest_qpn[2]]);
    let op_code = u8::from_be(unsafe { (*bth_hdr).opcode });
    let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    info!(
        &ctx,
        "received BTH packet with opcode {} and dest qpn {}",
        op_code, dest_qpn_dec
    );
    if dest_qpn_dec == 1 && op_code == 100 {
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
                    op_code, dest_qpn_dec, *queue_idx
                );
                queue_idx
            },
            None => {
                info!(
                    &ctx,
                    "received BTH packet with opcode {} and dest qpn {} on unknown queue",
                    op_code, dest_qpn_dec);
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
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&if_idx).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };
    return Ok(xdp_action::XDP_ABORTED);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

