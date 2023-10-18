#![no_std]

use core::mem;
use aya_bpf::programs::XdpContext;

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

