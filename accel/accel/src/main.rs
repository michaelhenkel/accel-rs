use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::{HashMap as AyaHashMap, XskMap}};
use aya_log::BpfLogger;
use clap::{Parser, Subcommand};
use log::{info, warn, debug};
use tokio::signal;
use cli_server;
use common::Stats;
use anyhow::Context;
use std::{
    collections::HashMap,
    str::FromStr,
    ffi::CString,
    io::{Error, ErrorKind}
};
use udp_server;

#[derive(Parser)]
struct Opt {
    #[clap(short, long)]
    programs: Vec<Program>,
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
enum ProgramName{
    Accel,
    UdpServer,
}

impl FromStr for ProgramName{
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accel" => Ok(ProgramName::Accel),
            "udp_server" => Ok(ProgramName::UdpServer),
            _ => Err(format!("Program type {} not found", s)),
        }
    }
}

impl ToString for ProgramName{
    fn to_string(&self) -> String {
        match self {
            ProgramName::Accel => "accel".to_string(),
            ProgramName::UdpServer => "udp_server".to_string(),
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
                    warn!("Program {} not found", name);
                    continue;
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

                for (intf, intf_idx) in &interface_map{
                    if let Some(stats_map) = bpf.map_mut("STATSMAP") {
                        let mut stats_map: AyaHashMap<_, u32, Stats> = AyaHashMap::try_from(stats_map).unwrap();
                        let stats = Stats{
                            rx: 0,
                        };
                        info!("Inserting stats for interface {} into STATS map", intf_idx);
                        stats_map.insert(intf_idx, &stats, 0).unwrap();
                    } else {
                        panic!("STATS map not found");
                    }
                    match program_name{
                        ProgramName::UdpServer => {           
                            let xsk_map = if let Some(xsk_map) = bpf.take_map("XSKMAP") {
                                XskMap::try_from(xsk_map)?   
                            } else {
                                panic!("XSKMAP map not found");
                            };
                            let mut udp_s = udp_server::UdpServer::new(intf.to_string(), intf_idx.clone(), xsk_map);
                            let udp_server_handler = tokio::spawn(async move {
                                if let Err(e) = udp_s.run().await{
                                    return Err(e);
                                }
                                Ok(())
                            });
                            join_handlers.push(udp_server_handler);
                        },
                        _ => {}
                    }
                }
                let (tx, rx) = tokio::sync::mpsc::channel(100);
                let stats_handler_jh = tokio::spawn(async move {
                    if let Err(e) = stats_handler(bpf, interface_map, rx).await{
                        return Err(e);
                    }
                    Ok(())
                });
                program_tx_map.insert(name, tx.clone());
                join_handlers.push(stats_handler_jh);
            }
        }
    }
    let cli_server_handler = tokio::spawn(async move {
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

async fn stats_handler(bpf: Bpf, iface_map: HashMap<String, u32>, mut rx: tokio::sync::mpsc::Receiver<cli_server::StatsMsg>) -> anyhow::Result<()>{
    let stats_map = if let Some(stats_map) = bpf.map("STATSMAP"){
        let stats_map: AyaHashMap<_, u32, Stats> = AyaHashMap::try_from(stats_map).unwrap();
        stats_map
    } else {
        panic!("STATS map not found");
    };
    loop {
        while let Some(stats_msg) = rx.recv().await{
            if let Some(iface_idx) = iface_map.get(&stats_msg.iface){
                if let Ok(stats) = stats_map.get(iface_idx, 0){
                    let iface_stats = cli_server::cli_server::cli_server::InterfaceStats{
                        rx: stats.rx as i32,
                    };
                    if let Err(e) = stats_msg.tx.send(iface_stats){
                        warn!("Failed to send stats to client: {}", e.rx);
                    }
                }
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
