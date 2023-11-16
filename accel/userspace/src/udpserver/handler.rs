use std::collections::HashMap;

use aya::{include_bytes_aligned, Bpf, maps::{LpmTrie, MapData, XskMap, HashMap as AyaHashMap}};
use cli_server::StatsMsg;
use common::RouteNextHop;
use log::info;
use tokio::task::JoinHandle;
use crate::handler::handler::{self, StatsHandler};
use super::super::config::config::{Interface, LoadBalancer};
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use super::udpserver::UdpServer;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct UdpServerHandler{
    interfaces: Vec<Interface>,
}

#[async_trait]
impl handler::ProgramHandler for UdpServerHandler{
    fn name(&self) -> String{
        "udp_server".to_string()
    }
    fn interfaces(&self) -> Vec<Interface>{
        self.interfaces.clone()
    }
    fn bpf_bytes(&self) -> &[u8] {
        include_bytes_aligned!("../../../target/bpfel-unknown-none/release/udp-server")
    }
    fn program(self) -> handler::Program {
        handler::Program::UdpServer(self)
    }
    async fn handle(&self, mut bpf: Bpf, interface_map: HashMap<String, Interface>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>{
        info!("udp server handler started");  
        let mut join_handlers = Vec::new();
        
        let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP") {
            XskMap::try_from(xsk_map)?   
        } else {
            panic!("XSKMAP map not found");
        };

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let udp_s = UdpServer::new(interface_map.clone());
        let udp_server_jh = tokio::spawn(async move {
            if let Err(e) = udp_s.run(xsk_map, rx).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(udp_server_jh);


        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            let stats_handler = StatsHandler{};
            stats_handler.stats_handler(bpf, interface_map, stats_rx, Some(tx)).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;

        Ok(())
    }
}