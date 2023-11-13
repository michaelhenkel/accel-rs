use aya::maps::MapData;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, 
    maps::{HashMap as AyaHashMap, XskMap, lpm_trie::LpmTrie, Array
}};
use aya_log::BpfLogger;
use clap::builder::ValueParserFactory;
use clap::{Parser, Subcommand, Args, ValueEnum};
use log::{info, warn, debug};
use tokio::signal;
use cli_server::{self, StatsMsg, Action};
use common::{
    Stats,
    RouteNextHop
};
use anyhow::Context;
use tokio::task::JoinHandle;
use std::sync::{Arc, Mutex};
use std::{
    collections::HashMap,
    str::FromStr,
    ffi::CString,
    io::{Error, ErrorKind}
};
use udp_server::{self, UdpServerCommand};
use router;
use async_trait::async_trait;
use cli_server::cli_server::cli_server::{ProgramType as CliProgram, StatsType, stats_reply};

#[derive(Parser)]
struct Opt {
    #[clap(short, long)]
    programs: Vec<Program>,
    #[clap(short, long)]
    flowlet_size: Option<u32>,
    #[clap(short, long)]
    endpoints: Option<Vec<String>>,
    #[arg(short = 'q', value_parser = parse_key_val::<u8, u8>)]
    queues: Option<Vec<(u8, u8)>>,
    #[clap(short, long)]
    zero_copy: Option<bool>,
}

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

#[derive(Debug, Args, Clone)]
struct StashPushArgs {
    #[arg(short, long)]
    message: Option<String>,
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
                let name: String = program_name.to_string();
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
                        Box::new(UdpServerHandler{
                            queues: opt.queues.clone(),
                            zero_copy: opt.zero_copy
                        })
                    },
                    ProgramName::Accel => {
                        Box::new(AccelHandler{})
                    },
                    ProgramName::Router => {
                        let flowlet_size = if let Some(flowlet_size) = opt.flowlet_size{
                            flowlet_size
                        } else {
                            0
                        };
                        Box::new(RouterHandler{
                            flowlet_size,
                            endpoints: opt.endpoints.clone()
                        })
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
    flowlet_size: u32,
    endpoints: Option<Vec<String>>,
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
            let route_table_map: LpmTrie<MapData, u32, [RouteNextHop;32]> = LpmTrie::try_from(route_table).unwrap();
            route_table_map
        } else {
            panic!("ROUTETABLE map not found");
        };

        if let Some(flowlet_size_map) = bpf.map_mut("FLOWLETSIZE"){
            let mut flowlet_size_map: AyaHashMap<_, u8, u32> = AyaHashMap::try_from(flowlet_size_map).unwrap();
            flowlet_size_map.insert(0, self.flowlet_size, 0)?;
        } else {
            panic!("FLOWLETSIZE map not found");
        };

        let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP") {
            XskMap::try_from(xsk_map)?   
        } else {
            panic!("XSKMAP map not found");
        };

        let mut router_s = router::Router::new(false, interface_map.clone(), self.endpoints.clone());
        let router_jh = tokio::spawn(async move {
            if let Err(e) = router_s.run(route_table, xsk_map).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(router_jh);

        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            stats_handler(bpf, interface_map, stats_rx, None).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
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
            stats_handler(bpf, interface_map, stats_rx, None).await?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;
        Ok(())
    }
}

pub struct UdpServerHandler{
    queues: Option<Vec<(u8,u8)>>,
    zero_copy: Option<bool>,
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

        let zero_copy = if let Some(zero_copy) = self.zero_copy{
            zero_copy
        } else {
            false
        };
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let udp_s = udp_server::UdpServer::new(zero_copy, interface_map.clone(), self.queues.clone());
        let udp_server_jh = tokio::spawn(async move {
            if let Err(e) = udp_s.run(xsk_map, rx).await{
                return Err(e);
            }
            Ok(())
        });

        join_handlers.push(udp_server_jh);


        let stats_handler_jh: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            stats_handler(bpf, interface_map, stats_rx, Some(tx.clone())).await.map_err(|e| anyhow::anyhow!("stats handler failed: {}", e))?;
            Ok(())
        });
        join_handlers.push(stats_handler_jh);
        futures::future::join_all(join_handlers).await;

        Ok(())
    }
}

async fn stats_handler(mut bpf: Bpf, iface_map: HashMap<String, u32>, mut rx: tokio::sync::mpsc::Receiver<cli_server::StatsMsg> , udp_tx: Option<tokio::sync::mpsc::Sender<UdpServerCommand>>) -> anyhow::Result<()>{
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
            match stats_msg.stats_type{
                StatsType::Interface => {
                    if let Some(iface_idx) = iface_map.get(&stats_msg.iface){
                        match stats_msg.action{
                            Action::Get => {
                                if let Ok(stats) = stats_map.get(iface_idx, 0){
                                    let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                                        rx: stats.rx as i32,
                                        ooo: stats.ooo as i32,
                                    };
                                    if let Err(e) = stats_msg.tx.send(stats_reply::Stats::InterfaceStats(iface_stats)){
                                        panic!("Failed to send stats to client");
                                    }
                                } else {
                                    info!("stats handler failed to find stats for interface {} index {}", stats_msg.iface, iface_idx);
                                }
                            },
                            Action::Reset => {
                                if let Ok(mut stats) = stats_map.get(iface_idx, 0){
                                    let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                                        rx: stats.rx as i32,
                                        ooo: stats.ooo as i32,
                                    };
                                    stats.rx = 0;
                                    stats.ooo = 0;
                                    stats_map.insert(iface_idx, &stats, 0)?;
                                    if let Err(e) = stats_msg.tx.send(stats_reply::Stats::InterfaceStats(iface_stats)){
                                        panic!("Failed to send stats to client");
                                    }
                                } else {
                                    info!("stats handler failed to find stats for interface {} index {}", stats_msg.iface, iface_idx);
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
                                    let udp_command = UdpServerCommand::Get { tx: udp_stats_tx };
                                    if let Err(e) = udp_tx.clone().unwrap().send(udp_command).await{
                                        panic!("Failed to send stats to udp server: {}", e);
                                    };
                                },
                                Action::Reset => {
                                    let udp_command = UdpServerCommand::Reset { tx: udp_stats_tx };
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

fn get_interface_index(interface_name: &str) -> Result<u32, Error> {
    let interface_name_cstring = CString::new(interface_name)?;
    let interface_index = unsafe { libc::if_nametoindex(interface_name_cstring.as_ptr()) };
    if interface_index == 0 {
        Err(Error::new(ErrorKind::NotFound, "Interface not found"))
    } else {
        Ok(interface_index)
    }
}
