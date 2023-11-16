use std::collections::HashMap;

use aya::{include_bytes_aligned, Bpf, maps::{LpmTrie, MapData, XskMap, HashMap as AyaHashMap}};
use cli_server::StatsMsg;
use common::RouteNextHop;
use log::info;
use tokio::task::JoinHandle;
use crate::handler::handler::{self, StatsHandler};
use super::super::config::config::{Interface, LoadBalancer};
use super::router::Router;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct RouterHandler{
    pub interfaces: Vec<Interface>,
    pub endpoints: Option<Vec<String>>,
    pub loadbalacer: Option<LoadBalancer>,
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
            let flowlet_size = if let Some(load_balancer) = &self.loadbalacer{
                load_balancer.flowlet_size
            } else {
                0
            };
            flowlet_size_map.insert(0, flowlet_size as u32, 0)?;
        } else {
            panic!("FLOWLETSIZE map not found");
        };

        let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP") {
            XskMap::try_from(xsk_map)?   
        } else {
            panic!("XSKMAP map not found");
        };

        let mut router_s = Router::new(interface_map.clone(), self.endpoints.clone(), true);
        let router_jh = tokio::spawn(async move {
            if let Err(e) = router_s.run(route_table, xsk_map).await{
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