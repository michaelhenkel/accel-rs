#![no_std]
use core::{mem::{self, zeroed, size_of}, hash::Hash, borrow::Borrow};
use aya_bpf::{
    programs::XdpContext,
    helpers::{bpf_csum_diff, bpf_fib_lookup},
    bindings::bpf_fib_lookup as fib_lookup, cty::c_void,
    macros::map,
    maps::{HashMap, lpm_trie::Key}, maps::{Array, LpmTrie},
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    udp::UdpHdr,
};
use aya_log_ebpf::{warn, info};

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct BthHdr{
    pub opcode: u8,
    pub sol_event: u8,
    pub part_key: u16,
    pub res: u8,
    pub dest_qpn: [u8;3],
    pub ack: u8,
    pub psn_seq: [u8;3],
}
impl BthHdr {
    pub const LEN: usize = mem::size_of::<BthHdr>();
}

#[derive(Clone, Copy, Debug)]
pub struct CtrlSequence{
    pub num_packet: u32,
    pub first: u32,
    pub last: u32,
    pub qp_id: u32,
    pub start_end: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowNextHop {
    pub src_mac: [u8;6],
    pub dst_mac: [u8;6],
    pub src_ip: u32,
    pub dst_ip: u32,
    pub ifidx: u32,
    pub flowlet_size: u32,
    pub counter: u32,
    pub current_link: u32
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowNextHop {}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct InterfaceConfig{
    pub role: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceConfig {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}


#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RouteNextHop {
    pub ip: u32,
    pub ifidx: u32,
    pub src_mac: [u8;6],
    pub dst_mac: [u8;6],
    pub total_next_hops: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteNextHop {}


#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub rx: u32,
    pub ooo: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

#[inline(always)]
pub fn mac_to_int(mac: [u8;6]) -> u64 {
    let mut mac_dec: u64 = 0;
    for i in 0..6 {
        mac_dec = mac_dec << 8;
        mac_dec = mac_dec | mac[i] as u64;
    }
    mac_dec
}

#[inline(always)]
fn _csum(data_start: *mut u32, data_size: u32, csum: u32) -> u16 {
    let cs = unsafe { bpf_csum_diff(0 as *mut u32, 0, data_start, data_size, csum) };
    _csum_fold_helper(cs)
}

#[inline(always)]
fn _csum_fold_helper(csum: i64) -> u16 {
    let mut sum = csum;
    for _ in 0..4 {
        if sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !sum as u16
}



#[inline(always)]
pub fn get_next_hop(ctx: &XdpContext, flow_table: HashMap<FlowKey, FlowNextHop>) -> Option<FlowNextHop>{
    let ip_hdr_ptr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let udp_hdr_ptr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let dst_ip = unsafe { (*ip_hdr_ptr).dst_addr };
    let src_ip = unsafe { (*ip_hdr_ptr).src_addr };
    let mut params: fib_lookup = unsafe { zeroed() };
    params.family = 2;
    params.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    params.__bindgen_anon_4.ipv4_dst = dst_ip;
    let params_ptr: *mut fib_lookup = &mut params as *mut _;

    let _param_size = size_of::<fib_lookup>();        
    let ctx_ptr = ctx.ctx as *mut _ as *mut c_void;
    let ret: i64 = unsafe {
        bpf_fib_lookup(ctx_ptr, params_ptr, 64, 0)
    };
    if ret != 0 {
        return None;
    }
    let flow_next_hop = FlowNextHop{
        dst_ip: unsafe { params.__bindgen_anon_4.ipv4_dst },
        src_ip: unsafe { params.__bindgen_anon_3.ipv4_src },
        dst_mac: params.dmac,
        src_mac: params.smac,
        ifidx: params.ifindex,
        counter: 0,
        flowlet_size: 0,
        current_link: 0,
    };

    let mut flow_key: FlowKey = unsafe { zeroed() };
    flow_key.dst_ip = dst_ip;
    flow_key.src_ip = src_ip;
    flow_key.dst_port = unsafe { (*udp_hdr_ptr).dest };
    flow_key.src_port = unsafe { (*udp_hdr_ptr).source };
    flow_key.ip_proto = unsafe { (*ip_hdr_ptr).proto as u8 };
    if let Err(_e) = flow_table.insert(&flow_key, &flow_next_hop, 0) {
        return None;
    }
    Some(flow_next_hop)
}