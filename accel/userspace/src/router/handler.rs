use std::{collections::HashMap, sync::{Arc, Mutex}};

use aya::{include_bytes_aligned, Bpf, maps::{LpmTrie, MapData, XskMap, HashMap as AyaHashMap}};
use cli_server::StatsMsg;
use common::RouteNextHop;
use log::info;
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use tokio::task::JoinHandle;
use crate::handler::handler::{self, StatsHandler};
use super::super::config::config::{Interface, LoadBalancer};
use super::router::Router;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RouterHandler{
    pub interfaces: Vec<Interface>,
    pub endpoints: Option<Vec<String>>,
    pub load_balancer: Option<LoadBalancer>,
    pub in_order: Option<bool>,
}

#[async_trait]
impl handler::ProgramHandler for RouterHandler{
    fn name(&self) -> String{
        "router".to_string()
    }
    fn interfaces(&self) -> Vec<Interface>{
        self.interfaces.clone()
    }
    fn bpf_bytes(&self) -> &[u8] {
        include_bytes_aligned!("../../../target/bpfel-unknown-none/release/router")
    }
    fn program(self) -> handler::Program {
        handler::Program::Router(self)
    }
    async fn handle(&self, mut bpf: Bpf, interface_map: HashMap<String, Interface>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>{
        info!("router handler started");  
        let mut join_handlers = Vec::new();
        
        let route_table = if let Some(route_table) = bpf.take_map("ROUTETABLE"){
            let route_table_map: LpmTrie<MapData, u32, [RouteNextHop;32]> = LpmTrie::try_from(route_table).unwrap();
            route_table_map
        } else {
            panic!("ROUTETABLE map not found");
        };

        if let Some(flowlet_size_map) = bpf.map_mut("FLOWLETSIZE"){
            let mut flowlet_size_map: AyaHashMap<_, u8, u32> = AyaHashMap::try_from(flowlet_size_map).unwrap();
            let flowlet_size = if let Some(load_balancer) = &self.load_balancer{
                load_balancer.flowlet_size
            } else {
                0
            };
            flowlet_size_map.insert(0, flowlet_size as u32, 0)?;
        } else {
            panic!("FLOWLETSIZE map not found");
        };

        let xsk_map_1 = if let Some(xsk_map_1) = bpf.take_map("XSKMAP1") {
            XskMap::try_from(xsk_map_1)?   
        } else {
            panic!("XSKMAP1 map not found");
        };

        let xsk_map_2 = if let Some(xsk_map_2) = bpf.take_map("XSKMAP2") {
            XskMap::try_from(xsk_map_2)?   
        } else {
            panic!("XSKMAP2 map not found");
        };

        let xsk_map_3 = if let Some(xsk_map_3) = bpf.take_map("XSKMAP3") {
            XskMap::try_from(xsk_map_3)?   
        } else {
            panic!("XSKMAP3 map not found");
        };

        let xsk_map_4 = if let Some(xsk_map_4) = bpf.take_map("XSKMAP4") {
            XskMap::try_from(xsk_map_4)?   
        } else {
            panic!("XSKMAP4 map not found");
        };

        let xsk_map_5 = if let Some(xsk_map_5) = bpf.take_map("XSKMAP5") {
            XskMap::try_from(xsk_map_5)?   
        } else {
            panic!("XSKMAP5 map not found");
        };

        let mut xsk_map_list = Vec::new();
        xsk_map_list.push(xsk_map_1);
        xsk_map_list.push(xsk_map_2);
        xsk_map_list.push(xsk_map_3);
        xsk_map_list.push(xsk_map_4);
        xsk_map_list.push(xsk_map_5);

        let xsk_map_list_mutex = Arc::new(Mutex::new(xsk_map_list));

        let interface_xsk_map = if let Some(interface_xsk_map) = bpf.take_map("INTERFACEXSKMAP") {
            AyaHashMap::try_from(interface_xsk_map)?
        } else {
            panic!("INTERFACEXSKMAP map not found");
        };

        let interface_xsk_map_mutex = Arc::new(Mutex::new(interface_xsk_map));

        let interface_config_map = if let Some(interface_config_map) = bpf.take_map("INTERFACECONFIGMAP") {
            AyaHashMap::try_from(interface_config_map)?
        } else {
            panic!("INTERFACECONFIGMAP map not found");
        };

        let interface_config_map_mutex = Arc::new(Mutex::new(interface_config_map));

        let mut router_s = Router::new(interface_map.clone(), self.endpoints.clone(), self.in_order, xsk_map_list_mutex, interface_xsk_map_mutex, interface_config_map_mutex);
        let router_jh = tokio::spawn(async move {
            if let Err(e) = router_s.run(route_table).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(router_jh);

        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            let stats_handler = StatsHandler{};
            stats_handler.stats_handler(bpf, interface_map, stats_rx, None).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;

        Ok(())
    }
}