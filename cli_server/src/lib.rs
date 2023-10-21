use std::collections::HashMap;

use tonic::{transport::Server, Request, Response, Status};

pub mod cli_server;

use cli_server::cli_server::{StatsReply, StatsRequest, InterfaceStats};
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
        let req = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stats_msg = StatsMsg{
            iface: req.interface.clone(),
            program: req.program.clone(),
            tx,
        };
        if let Some(tx) = self.program_tx_map.get(&req.program){
            if let Err(e) = tx.send(stats_msg).await{
                return Err(Status::internal(format!("Failed to send stats request: {}", e)));
            }
        } else {
            return Err(Status::internal(format!("Interface {} not found", req.program)));
        }
        let interface_stats = match rx.await {
            Ok(stats_reply) => {
                stats_reply
            },
            Err(e) => {
                return Err(Status::internal(format!("Failed to receive stats reply: {}", e)));
            }
        };
        let reply = StatsReply{
            interface_stats: Some(interface_stats),
        };
        Ok(Response::new(reply))
    }
    async fn reset(&self, _request: Request<StatsRequest>) -> Result<Response<StatsReply>, Status> {
        //let req = request.into_inner();
        let reply = StatsReply{
            interface_stats: Some(InterfaceStats{
                rx: 0,
            }),
        };
        Ok(Response::new(reply))
    }
}

pub async fn run(intf_tx_map: HashMap<String, tokio::sync::mpsc::Sender<StatsMsg>>) -> anyhow::Result<()>{
    let addr = "127.0.0.1:50051".parse().unwrap();
    let cli_server = CliServer::new(intf_tx_map);
    let res = Server::builder()
        .add_service(StatsServer::new(cli_server))
        .serve(addr)
        .await;
    Ok(res?)
}

pub struct StatsMsg {
    pub iface: String,
    pub program: String,
    pub tx: tokio::sync::oneshot::Sender<InterfaceStats>
}
