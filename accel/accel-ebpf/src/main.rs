#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use accel_common::{ptr_at, Stats};

#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u8, Stats> =
    HashMap::<u8, Stats>::with_max_entries(1, 0);

#[xdp]
pub fn accel(ctx: XdpContext) -> u32 {
    match try_accel(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_accel(ctx: XdpContext) -> Result<u32, u32> {
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
    if u16::from_be(unsafe { (*udp_hdr).dest }) != 4791 {
        warn!(&ctx, "received UDP packet with dest port {}", u16::from_be(unsafe { (*udp_hdr).dest }));
        return Ok(xdp_action::XDP_PASS);
    }
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&0).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };
    Ok(xdp_action::XDP_REDIRECT)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}



