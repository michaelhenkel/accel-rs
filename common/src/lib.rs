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
#[derive(Debug, Copy, Clone, Default)]
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct InvariantCrc{
    pub crc: u32,
}
impl InvariantCrc {
    pub const LEN: usize = mem::size_of::<InvariantCrc>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct DethHdr{
    pub queue_key: u32,
    pub res: u8,
    pub src_qpn: [u8;3],
}
impl DethHdr {
    pub const LEN: usize = mem::size_of::<DethHdr>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct MadHdr{
    pub base_version: u8,
    pub mgmt_class: u8,
    pub class_version: u8,
    pub method: u8,
    pub status: u16,
    pub class_specific: u16,
    pub transaction_id: [u8;8],
    pub attribute_id: u16,
    pub res: u16,
    pub attribute_modifier: u32,
}

impl MadHdr {
    pub const LEN: usize = mem::size_of::<MadHdr>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CmConnectRequest{
    pub local_comm_id: u32,
    pub res: u32,
    pub ip_cm_service_id: IpCmServiceId,
    pub local_ca_guid: [u8;8],
    pub res2: u32,
    pub local_q_key: u32,
    pub local_qpn: [u8;3],
    pub responder_resources: u8,
    pub local_eecn: [u8;3],
    pub initiator_depth: u8,
    pub remote_eecn: [u8;3],
    pub remote_cm_response_timeout: u8,
    pub starting_psn: [u8;3],
    pub local_cm_response_timeout: u8,
    pub partition_key: u16,
    pub path_packet_payload_mtu: u8,
    pub max_cm_retries: u8,
    pub primary_local_port_lid: u16,
    pub primary_remote_port_lid: u16,
    pub ghost1: [u8;10],
    pub ghost2: u16,
    pub primary_local_port_gid: u32,
    pub ghost3: [u8;10],
    pub ghost4: u16,
    pub primary_remote_port_gid: u32,
    pub primary_flow_label: [u8;3],
    pub ghost5: u8,
    pub primary_traffic_class: u8,
    pub primary_hop_limit: u8,
    pub primary_subnet_local: u8,
    pub primary_local_ack_timeout: u8,
    pub alternate_local_port_lid: u16,
    pub alternate_remote_port_lid: u16,
    pub alternate_local_port_gid: [u8;16],
    pub alternate_remote_port_gid: [u8;16],
    pub alternate_flow_label: [u8;3],
    pub ghost6: u8,
    pub alternate_traffic_class: u8,
    pub alternate_hop_limit: u8,
    pub alternate_subnet_local: u8,
    pub alternate_local_ack_timeout: u8,
    pub ip_cm_private_data: IpCmPrivateData,
}

impl CmConnectRequest {
    pub const LEN: usize = mem::size_of::<CmConnectRequest>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct IpCmPrivateData{
    pub ip_cm_major_minor_version: u8,
    pub ip_cm_ip_version: u8,
    pub ip_cm_source_port: u16,
    pub ghost1: [u8;12],
    pub ip_cm_source_ip: u32,
    pub ghost2: [u8;12],
    pub ip_cm_destination_ip: u32,
    pub ip_cm_consumer_private_data: [u32;14],
}

impl IpCmPrivateData {
    pub const LEN: usize = mem::size_of::<IpCmPrivateData>();
    
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct IpCmServiceId{
    pub prefix: [u8;5],
    pub protocol: u8,
    pub destination_port: u16,
}

impl IpCmServiceId {
    pub const LEN: usize = mem::size_of::<IpCmServiceId>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CmConnectReply{
    pub local_comm_id: u32,
    pub remote_comm_id: u32,
    pub local_q_key: u32,
    pub local_qpn: [u8;3],
    pub res: u8,
    pub local_ee_context_number: [u8;3],
    pub res2: u8,
    pub starting_psn: [u8;3],
    pub res3: u8,
    pub responder_resources: u8,
    pub initiator_depth: u8,
    pub target_ack_delay: u8,
    pub rnr_retry_count: u8,
    pub local_ca_guid: [u8;8],
}

impl CmConnectReply {
    pub const LEN: usize = mem::size_of::<CmConnectReply>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CmReadyToUse{
    pub local_comm_id: u32,
    pub remote_comm_id: u32,
}

impl CmReadyToUse {
    pub const LEN: usize = mem::size_of::<CmReadyToUse>();
    
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CmDisconnectRequest{
    pub local_comm_id: u32,
    pub remote_comm_id: u32,
    pub remote_qpn_eecn: [u8;3],
}

impl CmDisconnectRequest {
    pub const LEN: usize = mem::size_of::<CmDisconnectRequest>();
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CmDisconnectReply{
    pub local_comm_id: u32,
    pub remote_comm_id: u32,
}

impl CmDisconnectReply {
    pub const LEN: usize = mem::size_of::<CmDisconnectReply>();
}
/*
    Base Transport Header
        Opcode: Unreliable Datagram (UD) - SEND only (100)
        0... .... = Solicited Event: False
        .0.. .... = MigReq: False
        ..00 .... = Pad Count: 0
        .... 0000 = Header Version: 0
        Partition Key: 65535
        Reserved: 00
        Destination Queue Pair: 0x000001
        1... .... = Acknowledge Request: True
        .000 0000 = Reserved (7 bits): 0
        Packet Sequence Number: 38
    DETH - Datagram Extended Transport Header
        Queue Key: 0x0000000080010000
        Reserved: 00
        Source Queue Pair: 0x00000001
    MAD Header - Common Management Datagram
        Base Version: 0x01
        Management Class: 0x07
        Class Version: 0x02
        Method: Send() (0x03)
        Status: 0x0000
        Class Specific: 0x0000
        Transaction ID: 0x0000000431544474
        Attribute ID: 0x0010
        Reserved: 0000
        Attribute Modifier: 0x00000000
        MAD Data Payload: 7444543100000000000000000106485302163efffe8aa52a000000000000000000006200…
    CM ConnectRequest
        Local Communication ID: 0x74445431
        Reserved: 00000000
        IP CM ServiceID
        Local CA GUID: 0x02163efffe8aa52a
        Reserved: 00000000
        Local Q_Key: 0x00000000
        Local QPN: 0x000062
        Responder Resources: 0x00
        Local EECN: 0x000000
        Initiator Depth: 0x00
        Remote EECN: 0x000000
        Starting PSN: 0x7bd9a3
        Partition Key: 0xffff
        Primary Local Port LID: 65535
        Primary Remote Port LID: 65535
        Primary Local Port GID: 14.0.0.2
        Primary Remote Port GID: 17.0.0.2
        Primary Traffic Class: 0x00
        Primary Hop Limit: 0x40
        Alternate Local Port LID: 0
        Alternate Remote Port LID: 0
        Alternate Local Port GID: 00000000000000000000000000000000
        Alternate Remote Port GID: 00000000000000000000000000000000
        Alternate Traffic Class: 0x00
        Alternate Hop Limit: 0x00
        IP CM Private Data
    Invariant CRC: 0x5cb29bbf

    IP CM Private Data
    0000 .... = IP CM Major Version: 0x0
    .... 0000 = IP CM Minor Version: 0x0
    0100 .... = IP CM IP Version: 0x4
    .... 0000 = IP CM Reserved: 0x0
    IP CM Source Port: 0x8e1a
    IP CM Source IP: 14.0.0.2
    IP CM Destination IP: 17.0.0.2

    IP CM ServiceID
    Prefix: 0000000001
    Protocol: 0x06
    Destination Port: 0x4853

    CM ConnectReply
    Local Communication ID: 0x1428868f
    Remote Communication ID: 0x75445431
    Local Q_Key: 0x00000000
    Local QPN: 0x00001e
    Reserved: 00
    Local EE Context Number: 0x000000
    Reserved: 00
    Starting PSN: 0x8d28b6
    Reserved: 00
    Responder Resources: 0x00
    Initiator Depth: 0x00
    0111 1... = Target ACK Delay: 0x0f
    .... .00. = Failover Accepted: 0x0
    .... ...0 = End-To-End Flow Control: 0x0
    111. .... = RNR Retry Count: 0x7
    ...0 .... = SRQ: 0x0
    .... 0000 = Reserved: 0x0
    Local CA GUID: 0x02163efffee62998
    PrivateData: 000000000000000000000000000000000000000000000000000000000000000000000000…

CM ReadyToUse
    Local Communication ID: 0x75445431
    Remote Communication ID: 0x1428868f
    PrivateData: 000000000000000000000000000000000000000000000000000000000000000000000000…

CM DisconnectRequest
    Local Communication ID: 0x74445431
    Remote Communication ID: 0x1a28868f
    Remote QPN/EECN: 0x00001f
    Reserved: 00
    PrivateData: 000000000000000000000000000000000000000000000000000000000000000000000000…

CM DisconnectReply
    Local Communication ID: 0x1a28868f
    Remote Communication ID: 0x74445431
    PrivateData: 000000000000000000000000000000000000000000000000000000000000000000000000…


*/

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QpState{
    pub qp_id: [u8;3],
    pub first_psn: u32,
    pub last_psn: u32,
    pub in_order: u8,
    pub state: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for QpState {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CmState{
    pub qp_id: [u8;3],
    pub first_psn: u32,
    pub last_psn: u32,
    pub in_order: u8,
    pub state: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CmState {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InterfaceQueue {
    pub ifidx: u32,
    pub queue: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceQueue {}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct InterfaceConfig{
    pub role: u8,
    pub order: u8,
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