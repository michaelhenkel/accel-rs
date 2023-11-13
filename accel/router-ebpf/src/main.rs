#![no_std]
#![no_main]

use core::mem::zeroed;
use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::{HashMap, XskMap, lpm_trie::{LpmTrie, Key}}, helpers::bpf_redirect,
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};
use common::{
    ptr_at, Stats, FlowKey, FlowNextHop, RouteNextHop, BthHdr,
};




#[map(name = "STATSMAP")]
static mut STATSMAP: HashMap<u32, Stats> =
    HashMap::<u32, Stats>::with_max_entries(128, 0);

#[map(name = "FLOWTABLE")]
static mut FLOWTABLE: HashMap<FlowKey, FlowNextHop> =
    HashMap::<FlowKey, FlowNextHop>::with_max_entries(2048, 0);

#[map(name = "FLOWLETSIZE")]
static mut FLOWLETSIZE: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[map(name = "LASTSEQ")]
static mut LASTSEQ: HashMap<u8, u32> =
    HashMap::<u8, u32>::with_max_entries(1, 0);

#[map(name = "ROUTETABLE")]
static mut ROUTETABLE: LpmTrie<u32, [RouteNextHop;32]> =
    LpmTrie::<u32, [RouteNextHop;32]>::with_max_entries(2048, 0);

#[map(name = "XSKMAP")]
static XSKMAP: XskMap = XskMap::with_max_entries(2048, 0);

#[xdp]
pub fn router(ctx: XdpContext) -> u32 {
    match try_router(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_router(ctx: XdpContext) -> Result<u32, u32> {
    let eth_hdr = ptr_at_mut::<EthHdr>(&ctx, 0)
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
    let flow_next_hop = if let Some((flow_next_hop, flow_key)) = get_v4_next_hop_from_flow_table(&ctx){
        if flow_next_hop.flowlet_size > 0 && flow_next_hop.counter % (flow_next_hop.flowlet_size + 1) == 0 {
            let packet_count = flow_next_hop.counter;
            let current_link = flow_next_hop.current_link;
            delete_flow(&ctx, flow_key);
            if let Some(flow_next_hop) = get_next_hop_from_route_table(&ctx, packet_count, current_link){
                flow_next_hop
            } else {
                info!(&ctx, "no flow info found, pass");
                return Ok(xdp_action::XDP_PASS);
            }
        } else {
            flow_next_hop
        }
    } else {
        if let Some(flow_next_hop) = get_next_hop_from_route_table(&ctx, 0, 0){
            flow_next_hop
        } else {
            info!(&ctx, "no flow info found, pass");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    let if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let statsmap = unsafe { STATSMAP.get_ptr_mut(&if_idx).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };
    let last_seq = match unsafe { LASTSEQ.get_ptr_mut(&0) }{
        Some(seq_num) => seq_num,
        None => {
            unsafe { LASTSEQ.insert(&0, &0, 0) }.map_err(|_| xdp_action::XDP_ABORTED)?;
            unsafe { LASTSEQ.get_ptr_mut(&0).ok_or(xdp_action::XDP_ABORTED)? }
        }
    };
    let bth_hdr = ptr_at::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
    let seq_num = unsafe { (*bth_hdr).psn_seq };
    let seq_num = u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]]);
    if unsafe { *last_seq } > 0 {
        if seq_num != unsafe { *last_seq + 1 } {
            unsafe { (*statsmap).ooo += 1 };
        }
    } else {}
    unsafe { *last_seq = seq_num };
    unsafe { (*eth_hdr).dst_addr = flow_next_hop.dst_mac };
    unsafe { (*eth_hdr).src_addr = flow_next_hop.src_mac };
    let if_idx = flow_next_hop.ifidx;
    let res = unsafe { bpf_redirect(if_idx, 0)};
    Ok(res as u32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}


#[inline(always)]
pub fn delete_flow(ctx: &XdpContext, flow_key: FlowKey){
    if let Err(e) = unsafe { FLOWTABLE.remove(&flow_key) }{
        info!(ctx, "flow_next_hop remove failed: {}", e);
    }
}

#[inline(always)]
pub fn get_v4_next_hop_from_flow_table(ctx: &XdpContext) -> Option<(FlowNextHop, FlowKey)>{
    let ipv4_hdr_ptr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let udp_hdr_ptr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let mut flow_key: FlowKey = unsafe { zeroed() };
    flow_key.dst_ip = unsafe { (*ipv4_hdr_ptr).dst_addr };
    flow_key.src_ip = unsafe { (*ipv4_hdr_ptr).src_addr };
    flow_key.dst_port = unsafe { (*udp_hdr_ptr).dest };
    flow_key.src_port = unsafe { (*udp_hdr_ptr).source };
    flow_key.ip_proto = unsafe { (*ipv4_hdr_ptr).proto as u8 };
    match unsafe { FLOWTABLE.get_ptr_mut(&flow_key) } {
        Some(fnh) => {
            unsafe { (*fnh).counter += 1 };
            return Some((unsafe { *fnh }, flow_key.clone()))
        }
        None => {
            warn!(ctx, "flow_next_hop not found");
            return None;
        }
    }
}

#[inline(always)]
pub fn get_next_hop_from_route_table(ctx: &XdpContext, mut packet_count: u32, mut current_link: u32) -> Option<FlowNextHop>{
    let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let udp_hdr_ptr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
    let src_ip = unsafe { (*ip_hdr_ptr).src_addr };

    let flowlet_size = if let Some(flowlet_size) = unsafe { FLOWLETSIZE.get(&0) }{
        *flowlet_size
    } else {
        0
    };

    let key: Key<u32> = Key::new(32,dst_ip);
    if let Some(next_hop_list) = unsafe { ROUTETABLE.get(&key) } {
        let mut total_next_hops = 0;
        for i in 0..32{
            let nh = next_hop_list[i];
            let idx = (i + 1) as u32;
            if nh.total_next_hops == idx{
                total_next_hops = idx;
                break;
            }
        }
        
        if total_next_hops == 0 {
            info!(ctx, "no next hop found");
            return None;
        }

        if current_link == 0 {
            current_link = 1;
        }else if current_link == total_next_hops{
            current_link = 1;
        } else {
            current_link += 1;
        }
        
        let rnh = if (current_link - 1) < next_hop_list.len() as u32 {
            next_hop_list[(current_link-1) as usize]
        } else {
            next_hop_list[0]
        };

        let flow_next_hop = FlowNextHop{
            dst_ip,
            src_ip,
            dst_mac: rnh.dst_mac,
            src_mac: rnh.src_mac,
            ifidx: rnh.ifidx,
            counter: { packet_count += 1; packet_count},
            current_link,
            flowlet_size,
        };
    
        let mut flow_key: FlowKey = unsafe { zeroed() };
        flow_key.dst_ip = dst_ip;
        flow_key.src_ip = src_ip;
        flow_key.dst_port = unsafe { (*udp_hdr_ptr).dest };
        flow_key.src_port = unsafe { (*udp_hdr_ptr).source };
        flow_key.ip_proto = unsafe { (*ip_hdr_ptr).proto as u8 };
        if let Err(_e) = unsafe { FLOWTABLE.insert(&flow_key, &flow_next_hop, 0) }{
            return None;
        }
        return Some(flow_next_hop)


    } else {
        info!(ctx, "no next hop found");
        return None;
    };


 

}





