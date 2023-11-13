use std::collections::HashMap;


use log::info;
use tonic::{transport::Server, Request, Response, Status};

pub mod cli_server;

use cli_server::cli_server::{StatsReply, StatsRequest, ProgramType, StatsType, stats_reply};
use cli_server::cli_server::stats_server::{Stats, StatsServer};

pub struct CliServer{
    program_tx_map: HashMap<String, tokio::sync::mpsc::Sender<StatsMsg>>
}

impl CliServer{
    pub fn new(program_tx_map: HashMap<String, tokio::sync::mpsc::Sender<StatsMsg>>) -> Self{
        CliServer{
            program_tx_map,
        }
    }
}

#[tonic::async_trait]
impl Stats for CliServer{
    async fn get(&self, request: Request<StatsRequest>) -> Result<Response<StatsReply>, Status> {
        let res = send(request, Action::Get, &self.program_tx_map).await?;
        Ok(res)
    }
    async fn reset(&self, request: Request<StatsRequest>) -> Result<Response<StatsReply>, Status> {
        let res = send(request, Action::Reset, &self.program_tx_map).await?;
        Ok(res)
    }
}

async fn send(request: Request<StatsRequest>, action: Action, program_tx_map: &HashMap<String, tokio::sync::mpsc::Sender<StatsMsg>>) -> Result<Response<StatsReply>, Status> {
    let req = request.into_inner();
    let p = match req.program_type{
        0 => {
            ProgramType::UdpServer
        },
        1 => {
            ProgramType::Router
        },
        _ => {
            return Err(Status::internal(format!("Invalid program number")));
        },
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let stats_msg = StatsMsg{
        iface: req.interface.clone(),
        program: p,
        tx,
        stats_type: req.stats_type(),
        action,
    };
    let program_name = match p {
        ProgramType::UdpServer => "udp_server".to_string(),
        ProgramType::Router => "router".to_string(),
    };
    if let Some(tx) = program_tx_map.get(&program_name){
        if let Err(e) = tx.send(stats_msg).await{
            return Err(Status::internal(format!("Failed to send stats request: {}", e)));
        }
    } else {
        return Err(Status::internal(format!("program {} not found", program_name)));
    }
    let stats_reply = match rx.await {
        Ok(stats_reply) => {
            stats_reply
        },
        Err(e) => {
            return Err(Status::internal(format!("Failed to receive stats reply: {}", e)));
        }
    };
    let reply = StatsReply{
        stats: Some(stats_reply),
    };
    Ok(Response::new(reply))
}

pub async fn run(intf_tx_map: HashMap<String, tokio::sync::mpsc::Sender<StatsMsg>>) -> anyhow::Result<()>{
    let addr = "127.0.0.1:50051".parse().unwrap();
    info!("CLI server running at {}", addr);
    let cli_server = CliServer::new(intf_tx_map);
    let res = Server::builder()
        .add_service(StatsServer::new(cli_server))
        .serve(addr)
        .await;
    Ok(res?)
}

pub struct StatsMsg {
    pub iface: String,
    pub program: ProgramType,
    pub stats_type: StatsType,
    pub tx: tokio::sync::oneshot::Sender<stats_reply::Stats>,
    pub action: Action,
}

pub enum Action{
    Get,
    Reset,
}
