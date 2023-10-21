use cli_server::cli_server::cli_server::stats_client::StatsClient;
use cli_server::cli_server::cli_server::StatsRequest;
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
        program: String
    },
    Reset{
        #[clap(short, long)]
        interface: String,
        #[clap(short, long)]
        program: String
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StatsClient::connect("http://127.0.0.1:50051").await?;

    let args = Arguments::parse();

    match args.command{
        Command::Get{interface, program} => {
            let request = tonic::Request::new(StatsRequest {
                interface,
                program, 
            });
            let response = client.get(request).await?;
            println!("RESPONSE={:?}", response.into_inner().interface_stats.unwrap());
        },
        Command::Reset{interface, program} => {
            let request = tonic::Request::new(StatsRequest {
                interface,
                program, 
            });
            let response = client.reset(request).await?;
            println!("RESPONSE={:?}", response);
        },
    }
    Ok(())
}