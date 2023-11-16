use async_trait::async_trait;
use aya::{
    Bpf,
    maps::HashMap as AyaHashMap
};
use cli_server::Action;
use cli_server::cli_server::cli_server::{ProgramType as CliProgram, StatsType, stats_reply};
use log::info;
use std::collections::HashMap;
use cli_server::StatsMsg;
use crate::config::config::Interface;

use super::super::config::config;
use super::super::udpserver;
use super::super::router;
use serde::{Serialize, Deserialize};
use common::Stats;

#[async_trait]
pub trait ProgramHandler: Send + Sync{
    fn name(&self) -> String;
    fn interfaces(&self) -> Vec<config::Interface>;
    fn bpf_bytes(&self) -> &[u8];
    fn program(self) -> Program;
    async fn handle(&self, mut bpf: Bpf, interface_map: HashMap<String, config::Interface>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>;
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Program{
    Router(router::handler::RouterHandler),
    UdpServer(udpserver::handler::UdpServerHandler),
}

impl PartialEq for dyn ProgramHandler{
    fn eq(&self, other: &dyn ProgramHandler) -> bool{
        self.name() == other.name()
    }
}

pub struct StatsHandler{

}

impl StatsHandler{
    pub async fn stats_handler(&self, mut bpf: Bpf, iface_map: HashMap<String, Interface>, mut rx: tokio::sync::mpsc::Receiver<cli_server::StatsMsg> , udp_tx: Option<tokio::sync::mpsc::Sender<udpserver::udpserver::UdpServerCommand>>) -> anyhow::Result<()>{
        info!("stats handler spawned");
        let mut stats_map = if let Some(stats_map) = bpf.map_mut("STATSMAP"){
            let stats_map: AyaHashMap<_, u32, Stats> = AyaHashMap::try_from(stats_map).unwrap();
            stats_map
        } else {
            panic!("STATS map not found");
        };
        for (intf_name, intf) in &iface_map {
            info!("stats handler setting stats map for interface {} with index {}", intf_name, intf.idx.unwrap());
            stats_map.insert(intf.idx.unwrap(), Stats::default(), 0)?;
        }
        loop {
            while let Some(stats_msg) = rx.recv().await{
                match stats_msg.stats_type{
                    StatsType::Interface => {
                        if let Some(intf) = iface_map.get(&stats_msg.iface){
                            match stats_msg.action{
                                Action::Get => {
                                    if let Ok(stats) = stats_map.get(&intf.idx.unwrap(), 0){
                                        let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                                            rx: stats.rx as i32,
                                            ooo: stats.ooo as i32,
                                        };
                                        if let Err(e) = stats_msg.tx.send(stats_reply::Stats::InterfaceStats(iface_stats)){
                                            panic!("Failed to send stats to client");
                                        }
                                    } else {
                                        info!("stats handler failed to find stats for interface {} index {}", stats_msg.iface, intf.idx.unwrap());
                                    }
                                },
                                Action::Reset => {
                                    if let Ok(mut stats) = stats_map.get(&intf.idx.unwrap(), 0){
                                        let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                                            rx: stats.rx as i32,
                                            ooo: stats.ooo as i32,
                                        };
                                        stats.rx = 0;
                                        stats.ooo = 0;
                                        stats_map.insert(intf.idx.unwrap(), &stats, 0)?;
                                        if let Err(e) = stats_msg.tx.send(stats_reply::Stats::InterfaceStats(iface_stats)){
                                            panic!("Failed to send stats to client");
                                        }
                                    } else {
                                        info!("stats handler failed to find stats for interface {} index {}", stats_msg.iface, intf.idx.unwrap());
                                    }
                                },
                            }
                        } else {
                            info!("stats handler failed to find index interface {}", stats_msg.iface);
                        }
                    },
                    StatsType::Program => {
                        match stats_msg.program{
                            CliProgram::Router => {
                            },
                            CliProgram::UdpServer => {
                                let (udp_stats_tx, udp_stats_rx) = tokio::sync::oneshot::channel();
                                match stats_msg.action{
                                    Action::Get => {
                                        let udp_command = udpserver::udpserver::UdpServerCommand::Get { tx: udp_stats_tx };
                                        if let Err(e) = udp_tx.clone().unwrap().send(udp_command).await{
                                            panic!("Failed to send stats to udp server: {}", e);
                                        };
                                    },
                                    Action::Reset => {
                                        let udp_command = udpserver::udpserver::UdpServerCommand::Reset { tx: udp_stats_tx };
                                        if let Err(e) = udp_tx.clone().unwrap().send(udp_command).await{
                                            panic!("Failed to send stats to udp server: {}", e);
                                        };
                                    },
                                }
                                
    
                                let udp_stats = udp_stats_rx.await.unwrap();
                                if let Err(e) = stats_msg.tx.send(stats_reply::Stats::UdpServerStats(udp_stats)){
                                    panic!("Failed to send stats to client");
                                }
                            },
                        };
                    },
                }
            }
        }
    }
}