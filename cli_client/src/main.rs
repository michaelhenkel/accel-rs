use cli_server::cli_server::cli_server::stats_client::StatsClient;
use cli_server::cli_server::cli_server::{StatsRequest, ProgramType, StatsType};
use clap::{Parser, Subcommand};


#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Clone)]
enum Command {
    Get{
        #[clap(short, long)]
        interface: String,
        #[clap(short, long)]
        program: String,
        #[clap(short, long)]
        stats_type: String
    },
    Reset{
        #[clap(short, long)]
        interface: String,
        #[clap(short, long)]
        program: String,
        #[clap(short, long)]
        stats_type: String
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StatsClient::connect("http://127.0.0.1:50051").await?;

    let args = Arguments::parse();

    match args.command{
        Command::Get{interface, program, stats_type} => {
            let p = match program.as_str(){
                "udp_server" => {
                    ProgramType::UdpServer
                },
                "router" => {
                    ProgramType::Router
                },
                _ => {
                    return Err("Invalid program number".into());
                }
            };
            let stats_type = match stats_type.as_str(){
                "interface" => {
                    StatsType::Interface
                },
                "program" => {
                    StatsType::Program
                },
                _ => {
                    return Err("Invalid stats type".into());
                }
            };
            let request = tonic::Request::new(StatsRequest {
                interface,
                program_type: p.into(), 
                stats_type: stats_type.into(),
            });
            let response = client.get(request).await?;
            println!("RESPONSE={:?}", response.into_inner().stats.unwrap());
        },
        Command::Reset{interface, program, stats_type} => {
            let p = match program.as_str(){
                "udp_server" => {
                    ProgramType::UdpServer
                },
                "router" => {
                    ProgramType::Router
                },
                _ => {
                    return Err("Invalid program number".into());
                }
            };
            let stats_type = match stats_type.as_str(){
                "interface" => {
                    StatsType::Interface
                },
                "program" => {
                    StatsType::Program
                },
                _ => {
                    return Err("Invalid stats type".into());
                }
            };
            let request = tonic::Request::new(StatsRequest {
                interface,
                program_type: p.into(),
                stats_type: stats_type.into(),
            });
            let response = client.reset(request).await?;
            println!("RESPONSE={:?}", response.into_inner().stats.unwrap());
        },
    }
    Ok(())
}