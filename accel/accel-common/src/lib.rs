#![no_std]

use core::mem;
use aya_bpf::programs::XdpContext;

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
#[derive(Clone, Copy)]
pub struct Stats {
    pub rx: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

