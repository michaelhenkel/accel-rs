use aya::maps::MapData;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::{HashMap as AyaHashMap, XskMap, lpm_trie::{LpmTrie, Key}}};
use aya_log::BpfLogger;
use clap::{Parser, Subcommand};
use log::{info, warn, debug};
use tokio::signal;
use cli_server::{self, StatsMsg};
use common::{
    Stats,
    RouteNextHop
};
use anyhow::Context;
use tokio::task::JoinHandle;
use std::{
    collections::HashMap,
    str::FromStr,
    ffi::CString,
    io::{Error, ErrorKind}
};
use udp_server;
use router;
use async_trait::async_trait;

#[derive(Parser)]
struct Opt {
    #[clap(short, long)]
    programs: Vec<Program>,
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum ProgramName{
    Accel,
    UdpServer,
    Router,
}

impl FromStr for ProgramName{
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accel" => Ok(ProgramName::Accel),
            "udp_server" => Ok(ProgramName::UdpServer),
            "router" => Ok(ProgramName::Router),
            _ => Err(format!("Program type {} not found", s)),
        }
    }
}

impl ToString for ProgramName{
    fn to_string(&self) -> String {
        match self {
            ProgramName::Accel => "accel".to_string(),
            ProgramName::UdpServer => "udp_server".to_string(),
            ProgramName::Router => "router".to_string(),
        }
    }
}

#[derive(Subcommand, Clone, Debug)]
enum Program {
    Program{
        #[clap(short, long)]
        program_name: ProgramName,
        #[clap(short, long)]
        interfaces: Vec<String>,
    },
}

impl FromStr for Program{
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split(":");
        let program_name = iter.next().unwrap();
        let interfaces = iter.next().unwrap();
        Ok(Program::Program{
            program_name: ProgramName::from_str(program_name)?,
            interfaces: interfaces.split(",").map(|x| x.to_string()).collect(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut join_handlers = Vec::new();
    let mut program_tx_map = HashMap::new();

    let bpf_loader_map = HashMap::from([
        (ProgramName::Accel, include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/accel")),
        (ProgramName::UdpServer, include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/udp-server")),
        (ProgramName::Router, include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/router")),
    ]);
    
    for p in opt.programs{
        match p {
            Program::Program { program_name, interfaces } => {
                let name = program_name.to_string();
                info!("Loading program {} on interfaces {:?}", name.to_string(), interfaces);
                let mut bpf = if let Some(b) = bpf_loader_map.get(&program_name){
                    let bpf = Bpf::load(b).context("failed to load BPF program")?;
                    bpf
                } else {
                    panic!("Program {} not found", name);
                };        
                if let Err(e) = BpfLogger::init(&mut bpf) {
                    warn!("failed to initialize eBPF logger: {}", e);
                }
        
                let program: &mut Xdp = bpf.program_mut(&name).unwrap().try_into()?;
                program.load()?;
                let mut interface_map = HashMap::new();
                for iface in interfaces{
                    info!("attaching XDP program {} to interface {}", name, iface);
                    program.attach(&iface, XdpFlags::DRV_MODE)
                        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
                    let intf_idx = get_interface_index(&iface)?;
                    interface_map.insert(iface.clone(), intf_idx);
                }

                info!("setting up stats handler for program {}", name);
                let (tx, rx) = tokio::sync::mpsc::channel(100);

                let program_handler: Box<dyn ProgramHandler> = match program_name{
                    ProgramName::UdpServer => {
                        Box::new(UdpServerHandler{})
                    },
                    ProgramName::Accel => {
                        Box::new(AccelHandler{})
                    },
                    ProgramName::Router => {
                        Box::new(RouterHandler{})
                    }
                };
                

                let jh = tokio::spawn(async move {
                    info!("program handler spawned");
                    if let Err(e) = program_handler.handle(bpf, interface_map, rx).await{
                        return Err(e);
                    }
                    Ok(())
                });
                join_handlers.push(jh);

                program_tx_map.insert(name.clone(), tx.clone());
    
                info!("stats handler set up for program {}", name);
            }
        }
    }
    info!("preparing CLI server start");
    let cli_server_handler = tokio::spawn(async move {
        info!("Starting CLI server");
        if let Err(e) = cli_server::run(program_tx_map).await{
            return Err(e);
        }
        Ok(())
    });
    join_handlers.push(cli_server_handler);


    futures::future::join_all(join_handlers).await;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

pub struct ProgramMsg{
    pub program_name: ProgramName,
    pub tx: tokio::sync::oneshot::Sender<String>,
}

#[async_trait]
trait ProgramHandler: Send + Sync{
    async fn handle(&self, bpf: Bpf, interface_map: HashMap<String, u32>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>;
}

pub struct RouterHandler{

}

pub enum RouteMsg{
    AddRoute{
        prefix_len: u8,
        prefix: u32,
        next_hop: RouteNextHop,
    }
}

#[async_trait]
impl ProgramHandler for RouterHandler{
    async fn handle(&self, mut bpf: Bpf, interface_map: HashMap<String, u32>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>{
        info!("router handler started");  
        let mut join_handlers = Vec::new();
        

        
        let route_table = if let Some(route_table) = bpf.take_map("ROUTETABLE"){
            let route_table_map: LpmTrie<MapData, u32, RouteNextHop> = LpmTrie::try_from(route_table).unwrap();
            route_table_map
        } else {
            panic!("ROUTETABLE map not found");
        };

        let mut router_s = router::Router::new();
        let router_jh = tokio::spawn(async move {
            if let Err(e) = router_s.run(route_table).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(router_jh);

        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            stats_handler(bpf, interface_map, stats_rx).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;

        Ok(())
    }
}

pub struct AccelHandler{

}

#[async_trait]
impl ProgramHandler for AccelHandler{
    async fn handle(&self, bpf: Bpf, interface_map: HashMap<String, u32>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>{
        let mut join_handlers: Vec<JoinHandle<Result<(), anyhow::Error>>> = Vec::new();
        let stats_handler_jh = tokio::spawn(async move {
            stats_handler(bpf, interface_map, stats_rx).await?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;
        Ok(())
    }
}

pub struct UdpServerHandler{

}

#[async_trait]
impl ProgramHandler for UdpServerHandler{
    async fn handle(&self, mut bpf: Bpf, interface_map: HashMap<String, u32>, stats_rx: tokio::sync::mpsc::Receiver<StatsMsg>) -> anyhow::Result<()>{
        info!("udp server handler started");  
        let mut join_handlers = Vec::new();
        
        let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP") {
            XskMap::try_from(xsk_map)?   
        } else {
            panic!("XSKMAP map not found");
        };
        let udp_s = udp_server::UdpServer::new(false, interface_map.clone());
        let udp_server_jh = tokio::spawn(async move {
            if let Err(e) = udp_s.run(xsk_map).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(udp_server_jh);

        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            stats_handler(bpf, interface_map, stats_rx).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;

        Ok(())
    }
}

async fn stats_handler(mut bpf: Bpf, iface_map: HashMap<String, u32>, mut rx: tokio::sync::mpsc::Receiver<cli_server::StatsMsg>) -> anyhow::Result<()>{
    info!("stats handler spawned");
    let mut stats_map = if let Some(stats_map) = bpf.map_mut("STATSMAP"){
        let stats_map: AyaHashMap<_, u32, Stats> = AyaHashMap::try_from(stats_map).unwrap();
        stats_map
    } else {
        panic!("STATS map not found");
    };
    for (intf, intf_idx) in &iface_map {
        info!("stats handler setting stats map for interface {} with index {}", intf, intf_idx);
        stats_map.insert(intf_idx.clone(), Stats::default(), 0)?;
    }
    loop {
        while let Some(stats_msg) = rx.recv().await{
            if let Some(iface_idx) = iface_map.get(&stats_msg.iface){
                if let Ok(stats) = stats_map.get(iface_idx, 0){
                    let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                        rx: stats.rx as i32,
                    };
                    if let Err(e) = stats_msg.tx.send(iface_stats){
                        panic!("Failed to send stats to client: {}", e.rx);
                    }
                } else {
                    info!("stats handler failed to find stats for interface {} index {}", stats_msg.iface, iface_idx);
                }
            } else {
                info!("stats handler failed to find index interface {}", stats_msg.iface);
            }
        }
    }
}

fn get_interface_index(interface_name: &str) -> Result<u32, Error> {
    let interface_name_cstring = CString::new(interface_name)?;
    let interface_index = unsafe { libc::if_nametoindex(interface_name_cstring.as_ptr()) };
    if interface_index == 0 {
        Err(Error::new(ErrorKind::NotFound, "Interface not found"))
    } else {
        Ok(interface_index)
    }
}
