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
    ptr_at,
    Stats,
    FlowKey,
    FlowNextHop,
    RouteNextHop,
    BthHdr,
    InterfaceConfig,
    InterfaceQueue,
    DethHdr,
    MadHdr,
    CmConnectReply,
    CmConnectRequest,
    CmReadyToUse,
    QpState,
    CmState,
    CmDisconnectRequest,
    CmDisconnectReply
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


#[map(name = "INTERFACEQUEUEMAP")]
static INTERFACEQUEUEMAP: HashMap<InterfaceQueue, u32> =
    HashMap::<InterfaceQueue, u32>::with_max_entries(100, 0);

#[map(name = "INTERFACECONFIGMAP")]
static INTERFACECONFIGMAP: HashMap<u32, InterfaceConfig> =
    HashMap::<u32, InterfaceConfig>::with_max_entries(5, 0);

#[map(name = "QPSTATE")]
static QPSTATE: HashMap<[u8;3], QpState> =
    HashMap::<[u8;3], QpState>::with_max_entries(1000, 0);

#[map(name = "CMSTATE")]
static CMSTATE: HashMap<[u8;8], CmState> =
    HashMap::<[u8;8], CmState>::with_max_entries(1000, 0);

enum Role{
    Access,
    Fabric,
}

enum Cm{
    ConnectRequest(*const CmConnectRequest),
    ConnectReply(*const CmConnectReply),
    ReadyToUse(*const CmReadyToUse),
    DisconnectRequest(*const CmDisconnectRequest),
    DisconnectReply(*const CmDisconnectReply),
}

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
        return Ok(xdp_action::XDP_PASS);
    }
    let ingress_if_idx = unsafe { (*ctx.ctx).ingress_ifindex };
    let queue_idx = unsafe { (*ctx.ctx).rx_queue_index };
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
    

    unsafe { (*eth_hdr).dst_addr = flow_next_hop.dst_mac };
    unsafe { (*eth_hdr).src_addr = flow_next_hop.src_mac };
    let nh_if_idx = flow_next_hop.ifidx;

    
    let bth_hdr = ptr_at::<BthHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
    let dest_qp = unsafe { (*bth_hdr).dest_qpn };
    let dest_qp_dec = u32::from_be_bytes([0, dest_qp[0], dest_qp[1], dest_qp[2]]);
    if dest_qp_dec == 0 || dest_qp_dec == 1 {
        //info!(&ctx, "cm mgmt packet");
        let mad_hdr = ptr_at::<MadHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
        let cm = match u16::to_be(unsafe{ (*mad_hdr).attribute_id }){
            16 => { 
                //info!(&ctx, "cm connect request packet");
                let connect_request_hdr = ptr_at::<CmConnectRequest>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                Cm::ConnectRequest(connect_request_hdr)
            },
            19 => { 
                //info!(&ctx, "cm connect reply packet");
                let connect_reply_hdr = ptr_at::<CmConnectReply>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                Cm::ConnectReply(connect_reply_hdr)
            },
            20 => { 
                //info!(&ctx, "cm ready to use packet");
                let ready_to_use_hdr = ptr_at::<CmReadyToUse>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                Cm::ReadyToUse(ready_to_use_hdr)
            },
            21 => {
                //info!(&ctx, "cm disconnect request packet");
                let disconnect_req_hdr = ptr_at::<CmDisconnectRequest>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                Cm::DisconnectRequest(disconnect_req_hdr)
            },
            22 => {
                //info!(&ctx, "cm disconnect reply packet");
                let disconnect_repl_hdr = ptr_at::<CmDisconnectReply>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN + MadHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
                Cm::DisconnectReply(disconnect_repl_hdr)
            },
            _ => {
                warn!(&ctx, "unknown cm packet");
                return Ok(xdp_action::XDP_PASS);
            }
        };
        let mad_hdr = ptr_at::<MadHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + BthHdr::LEN + DethHdr::LEN).ok_or(xdp_action::XDP_ABORTED)?;
        let transaction_id = unsafe { (*mad_hdr).transaction_id };
        let transaction_id_dec = u64::from_be_bytes([transaction_id[0], transaction_id[1], transaction_id[2], transaction_id[3], transaction_id[4], transaction_id[5], transaction_id[6], transaction_id[7]]);
        let cm_state = CMSTATE.get_ptr_mut(&transaction_id);
        match cm{
            Cm::ConnectRequest(conn_req) => {
                match cm_state {
                    Some(_) => { 
                    },
                    None => {
                        //info!(&ctx, "cm connect request, setting cm_state, transaction_id {}", transaction_id_dec);
                        let starting_psn = unsafe { (*conn_req).starting_psn };
                        let starting_psn = u32::from_be_bytes([0, starting_psn[0], starting_psn[1], starting_psn[2]]);
                        let cm_state = CmState{
                            qp_id: [0, 0, 0],
                            state: 0,
                            first_psn: starting_psn,
                            last_psn: 0,
                            in_order: 0,
                        };
                        CMSTATE.insert(&transaction_id, &cm_state, 0).map_err(|_| xdp_action::XDP_ABORTED)?;
                    }
                }
            },
            Cm::ConnectReply(conn_repl) => {
                match cm_state {
                    Some(cm_state) => { 
                        unsafe { (*cm_state).state = 1 };
                        let local_qpn = unsafe { (*conn_repl).local_qpn };
                        let local_qpn_dec = u32::from_be_bytes([0, local_qpn[0], local_qpn[1], local_qpn[2]]);
                        unsafe { (*cm_state).qp_id = local_qpn };
                        let starting_psn = unsafe { (*conn_repl).starting_psn };
                        let starting_psn = u32::from_be_bytes([0, starting_psn[0], starting_psn[1], starting_psn[2]]);
                        unsafe { (*cm_state).first_psn = starting_psn };
                        unsafe { (*cm_state).last_psn = starting_psn-1 };
                        //info!(&ctx, "connect reply, setting first_psn {}, last_psn {} for qp_id {}", unsafe { (*cm_state).first_psn }, unsafe { (*cm_state).last_psn }, local_qpn_dec);
                    },
                    None => {}
                }
            },
            Cm::ReadyToUse(_ready_to_use) => {
                match cm_state {
                    Some(cm_state) => { 
                        unsafe { (*cm_state).state = 2 };
                        let qp_id = unsafe { (*cm_state).qp_id };
                        let qp_id_dec = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
                        let qp_state = QpState{
                            qp_id,
                            first_psn: unsafe { (*cm_state).first_psn },
                            last_psn: unsafe { (*cm_state).last_psn },
                            state: 2,
                            in_order: 1,
                        };
                        QPSTATE.insert(&qp_id, &qp_state, 0).map_err(|_| xdp_action::XDP_ABORTED)?;
                        //info!(&ctx, "ready to use, setting first_psn {}, last_psn {} for qp_id {}", unsafe { (*cm_state).first_psn }, unsafe { (*cm_state).last_psn }, qp_id_dec);
                    },
                    None => {}
                }
            },
            Cm::DisconnectRequest(_disconnect_req) => {
                match cm_state {
                    Some(cm_state) => { 
                        //info!(&ctx, "disconnect request, setting state to 3 for qp_id {}", transaction_id_dec);
                        unsafe { (*cm_state).state = 3 };
                    },
                    None => {
                        //info!(&ctx,"disconnect request, cm_state not found for transaction_id {}", transaction_id_dec)
                    }
                }
            },
            Cm::DisconnectReply(_disconnect_repl) => {
                let qp_id = match cm_state {
                    Some(cm_state) => {
                        //info!(&ctx, "disconnect reply, removing cm_state for transaction_id {}", transaction_id_dec);
                        unsafe { (*cm_state).qp_id }
                    },
                    None => { [0,0,0] }
                };
                let qp_id_dec = u32::from_be_bytes([0, qp_id[0], qp_id[1], qp_id[2]]);
                match QPSTATE.remove(&qp_id){
                    Ok(()) => {
                        //info!(&ctx, "qp_state removed for qp_id {}", qp_id_dec);
                    },
                    Err(_) => {
                        //info!(&ctx, "qp_state not found for qp_id {}", qp_id_dec);
                    }
                }
                match CMSTATE.remove(&transaction_id){
                    Ok(()) => {
                        //info!(&ctx, "cm_state removed for transaction_id {}", transaction_id_dec);
                    },
                    Err(_) => {
                        //info!(&ctx, "cm_state not found for transaction_id {}", transaction_id_dec);
                    }
                }
            },
        }
        let res = unsafe { bpf_redirect(nh_if_idx, 0)};
        return Ok(res as u32)
    }

    let op_code = u8::from_be(unsafe { (*bth_hdr).opcode });
    // we don't care for send only or ack
    if op_code == 4 || op_code == 17 {
        let res = unsafe { bpf_redirect(nh_if_idx, 0)};
        return Ok(res as u32)
    }

    let statsmap = unsafe { STATSMAP.get_ptr_mut(&ingress_if_idx).ok_or(xdp_action::XDP_ABORTED)? };
    unsafe { (*statsmap).rx += 1 };

    let seq_num = unsafe { (*bth_hdr).psn_seq };
    let seq_num = u32::from_be_bytes([0, seq_num[0], seq_num[1], seq_num[2]]);

    let qp_state = match QPSTATE.get_ptr_mut(&dest_qp){
        Some(qp_state) => {
            //info!(&ctx, "qp_state found for qp_id {}", dest_qp_dec);
            qp_state
        },
        None => {
            //info!(&ctx, "qp_state not found for qp_id {}", dest_qp_dec);
            let res = unsafe { bpf_redirect(nh_if_idx, 0)};
            return Ok(res as u32)
        },
    };



    if seq_num != unsafe { (*qp_state).last_psn + 1 } {
        //info!(&ctx, "out of order seq {}, expected {}", seq_num, unsafe { (*qp_state).last_psn + 1 });
        unsafe { (*statsmap).ooo += 1 };
    } else {
        //info!(&ctx, "in order seq {}, expected {}", seq_num, unsafe { (*qp_state).last_psn + 1 });
        unsafe { (*qp_state).last_psn = seq_num };
        let res = unsafe { bpf_redirect(nh_if_idx, 0)};
        return Ok(res as u32)
    }

    let role = match unsafe { INTERFACECONFIGMAP.get(&ingress_if_idx)} {
        Some(interface_config) => {
            if interface_config.role == 0 {
                Role::Access
            } else if interface_config.role == 1{
                Role::Fabric
            } else {
                info!(&ctx, "no role found for if_idx {}", ingress_if_idx);
                return Ok(xdp_action::XDP_DROP)
            }
        },
        None => {
            let res = unsafe { bpf_redirect(nh_if_idx, 0)};
            return Ok(res as u32)
        },
    };

    //let res = unsafe { bpf_redirect(if_idx, 0)};
    //return Ok(res as u32);

    

    //info!(&ctx, "packets out of order seq {}, last_seq {} on if_idx {}, redirecting to xskmap", seq_num, unsafe { *last_seq }, if_idx);

    match role{
        Role::Access => {
            let res = unsafe { bpf_redirect(nh_if_idx, 0)};
            return Ok(res as u32)
        },
        Role::Fabric => {
            let interface_queue = InterfaceQueue{
                ifidx: ingress_if_idx,
                queue: queue_idx,
            };
            let queue_idx = match unsafe { INTERFACEQUEUEMAP.get(&interface_queue )}{
                Some(queue_idx) => {
                    queue_idx
                },
                None => {
                    return Ok(xdp_action::XDP_DROP)
                },
            };
        
            match XSKMAP.redirect(*queue_idx, xdp_action::XDP_DROP as u64){
                Ok(res) => {
                    return Ok(res)
                },
                Err(_e) => {
                    let res = unsafe { bpf_redirect(nh_if_idx, 0)};
                    return Ok(res as u32)
                }
            }
        },
    }
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





