#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::{HashMap, XskMap},
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{
    ptr_at, Stats,
    FlowKey, FlowNextHop,
    //STATS_MAP_NAME, FLOW_TABLE_NAME,
};


#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(2048, 0);

#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u32, Stats> =
    HashMap::<u32, Stats>::with_max_entries(128, 0);

#[map(name = "XSKMAP")]
static XSKMAP: XskMap = XskMap::with_max_entries(8, 0);

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
    let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&if_idx).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };
    let queue_idx = unsafe { (*ctx.ctx).rx_queue_index };
    XSKMAP.redirect(queue_idx, xdp_action::XDP_DROP as u64)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}



