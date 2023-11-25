use std::{collections::HashMap, sync::{Arc, Mutex}};

use aya::{include_bytes_aligned, Bpf, maps::{LpmTrie, MapData, XskMap, HashMap as AyaHashMap}};
use cli_server::StatsMsg;
use common::InterfaceQueue;
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

        let xsk_map = Arc::new(Mutex::new(xsk_map));

        let interface_queue_map = if let Some(interface_queue_map) = bpf.take_map("INTERFACEQUEUEMAP") {
            AyaHashMap::try_from(interface_queue_map)?
        } else {
            panic!("INTERFACEQUEUEMAP map not found");
        };

        let interface_queue_map_mutex = Arc::new(Mutex::new(interface_queue_map));

        let cm_state_map = if let Some(cm_state_map) = bpf.take_map("CMSTATE") {
            AyaHashMap::try_from(cm_state_map)?
        } else {
            panic!("CMSTATE map not found");
        };

        let cm_state_map_mutex = Arc::new(Mutex::new(cm_state_map));

        let qp_state_map = if let Some(qp_state_map) = bpf.take_map("QPSTATE") {
            AyaHashMap::try_from(qp_state_map)?
        } else {
            panic!("QPSTATE map not found");
        };

        let qp_state_map_mutex = Arc::new(Mutex::new(qp_state_map));

        

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let udp_s = UdpServer::new(interface_map.clone(), xsk_map, interface_queue_map_mutex, cm_state_map_mutex, qp_state_map_mutex);
        let udp_server_jh = tokio::spawn(async move {
            if let Err(e) = udp_s.run(rx).await{
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