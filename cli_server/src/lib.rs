use tonic::{transport::Server, Request, Response, Status};

pub mod cli_server;

use cli_server::cli_server::{StatsReply, StatsRequest, InterfaceStats};
use cli_server::cli_server::stats_server::{Stats, StatsServer};

pub struct CliServer{
    tx: tokio::sync::mpsc::Sender<StatsMsg>,
}

impl CliServer{
    pub fn new(tx: tokio::sync::mpsc::Sender<StatsMsg>) -> Self{
        CliServer{
            tx,
        }
    }
}

#[tonic::async_trait]
impl Stats for CliServer{
    async fn get(&self, request: Request<StatsRequest>) -> Result<Response<StatsReply>, Status> {
        let req = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stats_msg = StatsMsg{
            iface: req.name,
            tx,
        };
        if let Err(e) = self.tx.send(stats_msg).await{
            return Err(Status::internal(format!("Failed to send stats request: {}", e)));
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

pub async fn run(tx: tokio::sync::mpsc::Sender<StatsMsg>) -> anyhow::Result<()>{
    let addr = "[::1]:50051".parse().unwrap();
    let cli_server = CliServer::new(tx);
    let res = Server::builder()
        .add_service(StatsServer::new(cli_server))
        .serve(addr)
        .await;
    Ok(res?)
}

pub struct StatsMsg {
    pub iface: String,
    pub tx: tokio::sync::oneshot::Sender<InterfaceStats>
}
