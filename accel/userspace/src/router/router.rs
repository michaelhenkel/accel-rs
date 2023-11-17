use core::panic;
use std::{collections::{HashMap, BTreeMap}, net::{Ipv4Addr, IpAddr}, fmt::Display, sync::{Arc, Mutex}, hash::Hasher, hash::Hash};
use aya::maps::{XskMap, MapData, LpmTrie, lpm_trie::Key, HashMap as AyaHashMap};
use common::{RouteNextHop, InterfaceConfig};
use log::info;
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Error, Handle, IpVersion};
use netlink_packet_route::{rtnl::{
        route::nlas as route_nlas,
        link::nlas as link_nlas,
        neighbour::nlas as neighbour_nlas,
    }, RouteMessage};
use pnet::{
    self,
    packet::{
        ethernet::{
            MutableEthernetPacket,
            EtherTypes,
        },
        arp::{MutableArpPacket, ArpHardwareTypes, ArpOperations, ArpPacket}, Packet, ipv4}, util::MacAddr, ipnetwork::IpNetwork
};
use s2n_quic_xdp::{
    io::rx::{self, WithCooldown},
    socket as afxdp_socket, if_xdp,
};
use afxdp::{self, AfXdp};
use s2n_quic_core::{io::rx::Queue, xdp::path::{LocalAddress, RemoteAddress}, inet::ethernet::MacAddress};
use s2n_quic_core::inet::ip;
use s2n_quic_core::io::tx::Tx as _;
use s2n_quic_core::io::tx::Queue as _;
use tokio::{io::unix::AsyncFd, task::JoinHandle};

use crate::config::config::{Interface,Role};

const BUFF_SIZE: usize = 2048;

#[derive(Debug)]
pub struct RouteTable{
    pub routes: HashMap<u8,Route>,
}

impl Display for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix_len, routes) in &self.routes{
            for (prefix, next_hop_list) in routes{
                write!(f, "dst: {}/{}, next_hop_list: [", Ipv4Addr::from(*prefix), prefix_len)?;
                for next_hop in next_hop_list{
                    write!(f, "{}", next_hop)?;
                }
                write!(f, "]\n")?;
            }
        }
        Ok(())
    }
}

type Route = HashMap<u32, Vec<NextHop>>;

#[derive(Debug, Clone)]
pub struct NextHop {
    pub ip: u32,
    pub local_if_idx: u32,
    pub local_mac: [u8; 6],
    pub neigh_mac: [u8; 6],
    pub total_next_hops: u32,
}

impl Into<RouteNextHop> for NextHop{
    fn into(self) -> RouteNextHop {
        RouteNextHop{
            ip: self.ip,
            ifidx: self.local_if_idx,
            src_mac: self.local_mac,
            dst_mac: self.neigh_mac,
            total_next_hops: self.total_next_hops
        }
    }
}

impl Display for NextHop{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ nh_ip: {}, local_if_idx: {}, local_mac: {}, neigh_mac: {} }}", Ipv4Addr::from(self.ip), self.local_if_idx, mac_to_string(self.local_mac), mac_to_string(self.neigh_mac))
    }
}

pub fn mac_to_string(mac: [u8;6]) -> String{
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

#[derive(Clone)]
pub struct FlowKey{
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Hash for FlowKey{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
    }
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src_ip == other.src_ip && self.dst_ip == other.dst_ip && self.src_port == other.src_port && self.dst_port == other.dst_port
    }
}

impl Eq for FlowKey {}

type FlowTable = HashMap<FlowKey, u32>;

pub struct Router{
    pub route_table: RouteTable,
    interface_map: HashMap<String, Interface>,
    endpoints: Option<Vec<String>>,
    in_order: Option<bool>,
    xsk_map_list: Arc<Mutex<Vec<XskMap<MapData>>>>,
    interface_xsk_map: Arc<Mutex<AyaHashMap<MapData, u32, u32>>>,
    interface_config_map: Arc<Mutex<AyaHashMap<MapData, u32, InterfaceConfig>>>,
}

impl Router{
    pub fn new(
            interface_map: HashMap<String, Interface>,
            endpoints: Option<Vec<String>>,
            in_order: Option<bool>,
            xsk_map_list: Arc<Mutex<Vec<XskMap<MapData>>>>,
            interface_xsk_map: Arc<Mutex<AyaHashMap<MapData, u32, u32>>>,
            interface_config_map: Arc<Mutex<AyaHashMap<MapData, u32, InterfaceConfig>>>,
        ) -> Router {
            Router{
                route_table: RouteTable{
                    routes: HashMap::new()
                },
                interface_map,
                endpoints,
                in_order,
                xsk_map_list,
                interface_xsk_map,
                interface_config_map,
            }
    }
    pub async fn run(&mut self, mut route_table: LpmTrie<MapData, u32, [RouteNextHop;32]>) -> anyhow::Result<()>{
        info!("running router");
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
    
        if let Err(e) = self.get_routes(handle.clone(), IpVersion::V4).await {
            eprintln!("{e}");
        }
        if let Err(e) = self.get_routes_for_local_endpoints(handle, self.endpoints.clone()).await {
            eprintln!("{e}");
        }
        for (prefix_len, routes) in &self.route_table.routes{
            for (prefix, next_hop_list) in routes{
                let mut route_next_hop_list = [RouteNextHop::default(); 32];
                let mut i = 0;
                for next_hop in next_hop_list{
                    route_next_hop_list[i] = next_hop.clone().into();
                    route_next_hop_list[i].total_next_hops = next_hop_list.len() as u32;
                    i += 1;
                }
                let key = Key::new(*prefix_len as u32, *prefix);
                route_table
                    .insert(&key, route_next_hop_list, 0)?;
            }
        }
        let p_len = 32;
        let prefix = u32::from(Ipv4Addr::new(17, 0, 0, 2)).to_be();
        info!("getting next hop for prefix {}/{}", Ipv4Addr::from(prefix), p_len);
        let key = Key::new(p_len, prefix);
        info!("getting key data: {:?}, key prefix_len {}", key.data(), key.prefix_len());
        if let Ok(res) = route_table.get(&key, 0){
            for x in res {
                info!("{:?}", x);
            }
        }
        info!("done getting routes");
        info!("");
        info!("{}", self.route_table);

        let mut jh_list: Vec<JoinHandle<Result<(), Error>>> = Vec::new();
        let interface_channel_map = HashMap::new();

        let route_table_mutex = Arc::new(Mutex::new(route_table));
        let interface_channel_map_mutex = Arc::new(Mutex::new(interface_channel_map));

        if self.in_order.is_some() && self.in_order.unwrap(){
            let mut counter: usize = 0;
            for (intf_name, intf) in &self.interface_map {
                let mut flow_table = FlowTable::new();
                info!("setting up afxdp for interface {}, index {}", intf_name, intf.idx.unwrap());
                let interface_xsk_map = self.interface_xsk_map.clone();
                let mut interface_xsk_map = interface_xsk_map.lock().unwrap();
                interface_xsk_map.insert(intf.idx.unwrap(), counter as u32, 0)?;
                let xsk_map_list = self.xsk_map_list.clone();
                let mut xsk_map_list = xsk_map_list.lock().unwrap();
                let xsk_map = xsk_map_list.get_mut(counter).unwrap();
                let xsk_map_mutex = Arc::new(Mutex::new(xsk_map));
                let interface_config_map = self.interface_config_map.clone();
                let mut interface_config_map = interface_config_map.lock().unwrap();
                let route_table = Arc::clone(&route_table_mutex);
                let interface_channel_map = Arc::clone(&interface_channel_map_mutex);
                let interface_channel_map_mutex = Arc::clone(&interface_channel_map_mutex);
                let frame_size = BUFF_SIZE as u32;
                let rx_queue_len = 8192 * 2;
                let tx_queue_len = 8192;
                let rx_cooldown = 10;
                let mut af_xdp = AfXdp::new(intf.idx.unwrap(), intf_name.clone(), rx_queue_len, tx_queue_len, frame_size, rx_cooldown, intf.queues.clone());
                let (rx_channel, tx_channel) = af_xdp.setup(xsk_map_mutex, counter).unwrap();
                let mut interface_channel_map = interface_channel_map.lock().unwrap();
                match intf.role{
                    Role::Access => {
                        info!("setting up tx for access interface {}", intf_name);
                        interface_channel_map.insert(intf.idx.unwrap(), tx_channel);
                        interface_config_map.insert(intf.idx.unwrap(), InterfaceConfig{
                            role: 0,
                        }, 0)?;
                    },
                    Role::Fabric => {
                        info!("setting up rx for fabric interface {}", intf_name);
                        interface_config_map.insert(intf.idx.unwrap(), InterfaceConfig{
                            role: 1,
                        }, 0)?;
                        let rx_f = move |queue: &mut rx::Queue<'_, WithCooldown<Arc<AsyncFd<afxdp_socket::Fd>>>>| {
                            queue.for_each(|mut _header, payload| {
                                _header.path.swap();
                                let dst_prefix = match _header.path.remote_address.ip{
                                    ip::IpAddress::Ipv4(ipv4) => {
                                        let slice: &[u8;4] = ipv4.as_bytes().try_into().unwrap();
                                        u32::from_be_bytes(*slice).to_be()
                                    },
                                    _ => {
                                        panic!("IPv6 not supported");
                                    },
                                };
                                let src_prefix = match _header.path.local_address.ip{
                                    ip::IpAddress::Ipv4(ipv4) => {
                                        let slice: &[u8;4] = ipv4.as_bytes().try_into().unwrap();
                                        u32::from_be_bytes(*slice).to_be()
                                    },
                                    _ => {
                                        panic!("IPv6 not supported");
                                    },
                                };

                                let dst_port = _header.path.remote_address.port;

                                let src_port = _header.path.local_address.port;

                                let flow_key = FlowKey{
                                    src_ip: src_prefix,
                                    dst_ip: dst_prefix,
                                    src_port,
                                    dst_port,
                                };
                                let if_idx = if let Some(if_idx) = flow_table.get(&flow_key) {
                                    if_idx.clone()
                                } else {
                                    let prefix_len = 32;
                                    let key = Key::new(prefix_len, prefix);
                                    let route_table = route_table.lock().unwrap();
                                    let mut if_idx = None;
                                    if let Ok(res) = route_table.get(&key, 0){
                                        for next_hop in res {
                                            if_idx = Some(next_hop.ifidx);
                                            break;
                                        }
                                    }
                                    if let Some(if_idx) = if_idx {
                                        flow_table.insert(flow_key, if_idx);
                                        if_idx
                                    } else {
                                        panic!("route not found for u32 prefix {}/32", prefix);
                                    }
                                };

                                let mut interface_channel_map = interface_channel_map_mutex.lock().unwrap();
                                let tx_channel = interface_channel_map.get_mut(&if_idx).unwrap();
                                //info!("sending packet {:#?}", _header.path);
                                let packet = afxdp::Packet{
                                    path: _header.path,
                                    ecn: _header.ecn,
                                    counter: 0,
                                    data: payload.to_vec(),
                                };
                                tx_channel.queue(|queue| {
                                    //info!("sending packet");
                                    queue.push(packet.clone()).unwrap();
                                });

                            });
                        };
                        let jh = tokio::spawn( async move{
                            af_xdp.recv(rx_channel, rx_f.clone()).await;
                            Ok(())
                        });
                        jh_list.push(jh);
                    }
                }
                counter += 1;
            }
        }
        if !jh_list.is_empty(){
            info!("waiting for all {} threads to finish", jh_list.len());
            futures::future::join_all(jh_list).await;
        }     
        Ok(())
    }



    async fn get_routes_for_local_endpoints(&mut self,handle: Handle, endpoints: Option<Vec<String>>) -> anyhow::Result<(), Error> {
        let mut next_hop_list = Vec::new();
        if let Some(endpoints) = &endpoints{
            for endpoint in endpoints{
                let endpoint = if let Ok(endpoint) = endpoint.parse::<Ipv4Addr>(){
                    endpoint
                } else {
                    panic!("endpoint is not a valid ipv4 address");
                };
                match get_oif(handle.clone(), endpoint.clone()).await{
                    Ok(oif) => {
                        match oif{
                            Some(oif) => {
                                match get_local_mac(handle.clone(), oif).await{
                                    Ok(res) => {
                                        if let Some(local_mac) = res {
                                            info!("local_mac: {}", mac_to_string(local_mac.clone().try_into().unwrap()));
                                            let local_mac: [u8;6] = local_mac.clone().try_into().unwrap();
                                            let local_mac = MacAddr::from(local_mac);
                                            info!("sending arp");
                                            match send_arp(endpoint, oif, local_mac).await{
                                                Ok(res) => {
                                                    if let Some(dst_mac) = res {
                                                        let next_hop = NextHop{
                                                            ip: u32::from(endpoint).to_be(),
                                                            local_if_idx: oif,
                                                            local_mac: local_mac.clone().try_into().unwrap(),
                                                            neigh_mac: dst_mac.octets().try_into().unwrap(),
                                                            total_next_hops: 0,
                                                        };
                                                        next_hop_list.push(next_hop);
                                                        info!("received packet, dst_mac: {}", dst_mac.to_string());
                                                    } else {
                                                        info!("received packet, dst_mac not found");
                                                    }
                                                },
                                                Err(e) => {
                                                    panic!("error sending arp: {:?}", e);
                                                }
                                            }
                                        } else {
                                            panic!("local_mac not found");
                                        }
                                    },
                                    Err(e) => {
                                        panic!("error getting local mac: {:?}", e);
                                    }
                                }
                            },
                            None => {
                                panic!("oif not found")
                            }
                        }
                    },
                    Err(e) => {
                        panic!("error getting oif: {:?}", e);
                    }
                }
            }
        }
        for nh in &next_hop_list{
            let dst_prefix = nh.ip;
            let dst_prefix_len: u8 = 32;

            if let Some(routes) = self.route_table.routes.get_mut(&dst_prefix_len){
                if let Some(_next_hop_list) = routes.get_mut(&dst_prefix){
                    _next_hop_list.extend(vec![nh.clone()]);
                } else {
                    routes.insert(dst_prefix, vec![nh.clone()]);
                }
            } else {
                let mut route = HashMap::new();
                route.insert(dst_prefix, vec![nh.clone()]);
                self.route_table.routes.insert(dst_prefix_len, route);
            }
        }
        Ok(())
    }
    async fn get_routes(&mut self,handle: Handle, ip_version: IpVersion) -> anyhow::Result<(), Error> {
        let mut routes = handle.route().get(ip_version).execute();
        while let Some(route_msg) = routes.try_next().await? {
            if let Some((dst_prefix, dst_prefix_len)) = &route_msg.destination_prefix(){
                let mut next_hop_list = Vec::new();
                info!("route_msg {:?}", route_msg);
                if route_msg.header.protocol == 3 {
                    if let Some(gateway_ip) = &route_msg.gateway(){
                        if let Some(intf_idx) = &route_msg.output_interface(){
                            if let Ok(next_hop) = get_next_hop(handle.clone(), gateway_ip, *intf_idx).await{
                                if let Some(next_hop) = next_hop{
                                    next_hop_list.push(next_hop);
                                }
                            } else {
                                panic!("next hop not found");
                            }
                        } else {
                            panic!("output interface not found");
                        }
                    } else {
                        for nla in &route_msg.nlas{
                            match nla {
                                route_nlas::Nla::MultiPath(nh_list) => {
                                    for nh in nh_list{
                                        if let Some(gateway_ip) = &nh.gateway(){
                                            if let Ok(next_hop) = get_next_hop(handle.clone(), gateway_ip, nh.interface_id).await{
                                                if let Some(next_hop) = next_hop{
                                                    next_hop_list.push(next_hop);
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                } else if route_msg.header.protocol == 2 {
                    /* 
                    if let Some(intf_idx) = &route_msg.output_interface(){
                        let dst_prefix = if let IpAddr::V4(ipv4_addr) = dst_prefix {
                            let dst_prefix: Ipv4Addr = *ipv4_addr;
                            u32::from(dst_prefix).to_be()
                        } else {
                            panic!("IPv6 not supported");
                        };
                        let local_mac = if let Some(local_mac) = get_local_mac(handle.clone(), *intf_idx).await?{
                            local_mac
                        } else {
                            panic!("local mac not found");
                        };
                        let local_mac: [u8;6] = local_mac.clone().try_into().unwrap();
                        let next_hop = NextHop{
                            ip: dst_prefix,
                            local_if_idx: *intf_idx,
                            local_mac,
                            neigh_mac: [0;6],
                            total_next_hops: 0,
                        };
                        next_hop_list.push(next_hop);
                    }
                    */
                }
                if next_hop_list.len() > 0 {
                    let dst_prefix = if let IpAddr::V4(ipv4_addr) = dst_prefix {
                        let dst_prefix: Ipv4Addr = *ipv4_addr;
                        u32::from(dst_prefix).to_be()
                    } else {
                        panic!("IPv6 not supported");
                    };
                    if let Some(routes) = self.route_table.routes.get_mut(dst_prefix_len){
                        if let Some(_next_hop_list) = routes.get_mut(&dst_prefix){
                            _next_hop_list.extend(next_hop_list);
                        } else {
                            routes.insert(dst_prefix, next_hop_list);
                        }
                    } else {
                        let mut route = HashMap::new();
                        route.insert(dst_prefix, next_hop_list);
                        self.route_table.routes.insert(*dst_prefix_len, route);
                    }
                }
            }
        }
        Ok(())
    }
}

async fn get_oif(handle: Handle, dst_ip: Ipv4Addr) -> anyhow::Result<Option<u32>> {
    let mut dst_map: BTreeMap<u8, RouteMessage> = BTreeMap::new();
    let mut routes = handle.route().get(IpVersion::V4).execute();
    while let Some(route_msg) = routes.try_next().await? {
        if let Some((dst_prefix, dst_prefix_len)) = &route_msg.destination_prefix(){
            let ip_network = IpNetwork::new(*dst_prefix, *dst_prefix_len).unwrap();
            if ip_network.contains(std::net::IpAddr::V4(dst_ip)){
                dst_map.insert(dst_prefix_len.clone(), route_msg.clone());
            }
        }
    }
    for (_, route_msg) in dst_map.iter().rev(){
        if route_msg.output_interface().is_some(){
            return Ok(route_msg.output_interface());
        }
    }
    Ok(None)
}

async fn get_next_hop(handle: Handle, gateway_ip: &IpAddr, intf_idx: u32) -> anyhow::Result<Option<NextHop>, Error> {
    let gateway_ip = if let IpAddr::V4(ipv4_addr) = gateway_ip {
        let gateway_ip: Ipv4Addr = *ipv4_addr;
        gateway_ip
    } else {
        panic!("IPv6 not supported");
    };
    let local_mac = if let Some(local_mac) = get_local_mac(handle.clone(), intf_idx).await?{
        local_mac
    } else {
        panic!("local mac not found");
    };

    let neigh_mac = if let Some(neigh_mac) = get_neighbour_mac(handle.clone(), intf_idx).await?{
        neigh_mac
    } else {
        let local_mac: [u8;6] = local_mac.clone().try_into().unwrap();
        let mac = MacAddr::from(local_mac);
        if let Ok(res) = send_arp(gateway_ip, intf_idx, mac).await{
            if let Some(mac) = res{
                mac.octets()
            } else {
                panic!("neighbour mac not found");
            }
        } else {
            panic!("neighbour mac not found");
        }.to_vec()
    };

    let nh = NextHop{
        ip: u32::from(gateway_ip).to_be(),
        local_if_idx: intf_idx,
        local_mac: if let Ok(local_mac) = local_mac.clone().try_into(){
            local_mac
        } else {
            panic!("local mac is not 6 bytes");
        },
        neigh_mac: if let Ok(neigh_mac) = neigh_mac.try_into(){
            neigh_mac
        } else {
            panic!("neighbour mac is not 6 bytes");
        },
        total_next_hops: 0,
    };

    Ok(Some(nh))
}

async fn get_neighbour_mac(handle: Handle, if_idx: u32) -> anyhow::Result<Option<Vec<u8>>, Error> {

    let mut neighbours = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();
    while let Some(neigh) = neighbours.try_next().await? {
        if neigh.header.ifindex == if_idx{
            for nla in &neigh.nlas{
                match nla{
                    neighbour_nlas::Nla::LinkLocalAddress(addr) => {
                        return Ok(Some(addr.to_vec()));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(None)
}

async fn get_local_mac(handle: Handle, index: u32) -> anyhow::Result<Option<Vec<u8>>, Error> {
    let mut links = handle.link().get().match_index(index).execute();
    let msg = if let Some(msg) = links.try_next().await? {
        msg
    } else {
        eprintln!("no link with index {index} found");
        return Ok(None);
    };
    assert!(links.try_next().await?.is_none());

    for nla in msg.nlas.into_iter() {
        match nla{
            link_nlas::Nla::Address(addr) => {
                return Ok(Some(addr.to_vec()))
            }
            _ => {}
        }
    }
    Ok(None)
}

async fn send_arp(dst_ip: Ipv4Addr, intf_idx: u32, src_mac: MacAddr) -> anyhow::Result<Option<pnet::datalink::MacAddr>> {
    let all_interfaces = pnet::datalink::interfaces();
    let interface = if let Some(interface) = all_interfaces
        .iter()
        .find(|e| e.index == intf_idx){
            interface
    } else {
        panic!("interface not found");
    };
    let dst_addr: std::net::IpAddr = dst_ip.into();
    let mut src_ip = None;
    for ip in &interface.ips{
        info!("ip: {}, dst_address: {}", ip.ip(), dst_addr);
        if ip.contains(dst_addr) {
            src_ip = Some(ip.ip());
        }
    }
    let src_ip = if let Some(src_ip) = src_ip{
        if let IpAddr::V4(ipv4_addr) = &src_ip {
            let src_ip: Ipv4Addr = *ipv4_addr;
            src_ip
        } else {
            panic!("IPv6 not supported");
        }
    } else {
        panic!("src ip not found {:#?}", src_ip);
    };
    let(mut tx, mut rx) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);
    arp_packet.set_target_hw_addr(MacAddr::broadcast());
    arp_packet.set_target_proto_addr(dst_ip);

    info!("sending arp packet. src_mac {}, dst_mac {}, src_ip {}, dst_ip {}", src_mac, MacAddr::broadcast(), src_ip, dst_ip);

    ethernet_packet.set_payload(arp_packet.packet());
    if let Some(res) = tx.send_to(ethernet_packet.packet(), None) {
        match res {
            Ok(_) => {
                info!("arp packet sent");
            },
            Err(e) => {
                panic!("failed to send packet: {:?}", e);
            }
        }
    } else {
        panic!("failed to send packet");
    }
    let start = tokio::time::Instant::now();
    loop {
        let buf = rx.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == dst_ip
            && arp.get_target_hw_addr() == interface.mac.unwrap()
        {
            println!("Received reply");
            return Ok(Some(arp.get_sender_hw_addr()));
        }
        if start.elapsed() > tokio::time::Duration::from_secs(1) {
            return Ok(None);
        }
    }
}