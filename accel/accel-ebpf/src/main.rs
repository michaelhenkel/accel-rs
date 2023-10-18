#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::info;
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
    info!(&ctx, "received a packet");
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
    if unsafe { (*udp_hdr).dest } != 4791 {
        return Ok(xdp_action::XDP_PASS);
    }
    match unsafe { STATSMAP.get_ptr_mut(&0) }{
        Some(stats) => {
            unsafe { (*stats).rx += 1}
        },
        None => {
            let stats = Stats{
                rx: 1,
            };
            unsafe { STATSMAP.insert(&0, &stats, 0) }.map_err(|_| xdp_action::XDP_ABORTED)?;
        }
    }
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&0).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };
    Ok(xdp_action::XDP_DROP)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}



