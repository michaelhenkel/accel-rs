use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, debug, warn};
use tokio::signal;
use cli_server;
use anyhow::Context;
use std::{
    collections::HashMap,
    ffi::CString,
    io::{Error, ErrorKind}
};
use userspace::config::config;
use userspace::handler::handler;
use serde_yaml;


#[derive(Parser)]
struct Opt {
    #[clap(short, long)]
    config: Option<String>
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

    let config = match opt.config{
        Some(config) => {
            //read config yaml into config struct
            let config = std::fs::read_to_string(config).context("failed to read config file")?;
            let config: config::Config = serde_yaml::from_str(&config).context("failed to parse config file")?;
            Some(config)
        },
        None => { None }
    };

    let mut join_handlers = Vec::new();
    let mut program_tx_map = HashMap::new();

    if let Some(config) = config{
        for program in config.programs{
            let program_handler: Box<dyn handler::ProgramHandler> = match program{
                handler::Program::Router(program) => {
                    Box::new(program)
                },
                handler::Program::UdpServer(program) => {
                    Box::new(program)
                }
            };
            let mut bpf = Bpf::load(program_handler.bpf_bytes()).context("failed to load BPF program")?;
            if let Err(e) = BpfLogger::init(&mut bpf) {
                warn!("failed to initialize eBPF logger: {}", e);
            }
            let program: &mut Xdp = bpf.program_mut(&program_handler.name()).unwrap().try_into()?;
            program.load()?;

            let mut interface_idx_map = HashMap::new();

            for mut intf in program_handler.interfaces(){
                let intf_idx = get_interface_index(&intf.name.clone())?;
                intf.idx = Some(intf_idx);
                program.attach(&intf.name, XdpFlags::DRV_MODE)
                .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
                interface_idx_map.insert(intf.name.clone(), intf);
            }

            info!("setting up stats handler for program {}", program_handler.name());
            let (tx, rx) = tokio::sync::mpsc::channel(100);
            program_tx_map.insert(program_handler.name(), tx.clone());
            info!("stats handler set up for program {}", program_handler.name());
            let jh = tokio::spawn(async move {
                info!("program handler spawned");
                if let Err(e) = program_handler.handle(bpf, interface_idx_map, rx).await{
                    return Err(e);
                }
                Ok(())
            });
            join_handlers.push(jh);
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

fn get_interface_index(interface_name: &str) -> Result<u32, Error> {
    let interface_name_cstring = CString::new(interface_name)?;
    let interface_index = unsafe { libc::if_nametoindex(interface_name_cstring.as_ptr()) };
    if interface_index == 0 {
        Err(Error::new(ErrorKind::NotFound, "Interface not found"))
    } else {
        Ok(interface_index)
    }
}
