use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf, maps::HashMap as AyaHashMap};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use cli_server;
use accel_common::Stats;
use anyhow::Context;
use std::collections::HashMap;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let iface = opt.iface;

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/accel"
    ))?;

    let interface_map = HashMap::from([
        (iface.clone(), 0 as u8)
    ]);

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("accel").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::DRV_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let (tx, rx) = tokio::sync::mpsc::channel(100);

    let mut join_handlers = Vec::new();
    let stats_handler_jh = tokio::spawn(async move {
        if let Err(e) = stats_handler(bpf, interface_map, rx).await{
            return Err(e);
        }
        Ok(())
    });
    join_handlers.push(stats_handler_jh);
    let cli_server_handler = tokio::spawn(async move {
        if let Err(e) = cli_server::run(tx).await{
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

async fn stats_handler(mut bpf: Bpf, iface_map: HashMap<String, u8>, mut rx: tokio::sync::mpsc::Receiver<cli_server::StatsMsg>) -> anyhow::Result<()>{
    let stats_map = if let Some(stats_map) = bpf.map_mut("STATSMAP"){
        let stats_map: AyaHashMap<_, u8, Stats> = AyaHashMap::try_from(stats_map).unwrap();
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
