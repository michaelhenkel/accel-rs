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
        interface_name: String,
    },
    Reset{
        interface_name: String,
    },
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StatsClient::connect("http://[::1]:50051").await?;

    let args = Arguments::parse();

    match args.command{
        Command::Get{interface_name} => {
            let request = tonic::Request::new(StatsRequest {
                name: interface_name,
            });
            let response = client.get(request).await?;
            println!("RESPONSE={:?}", response);
        },
        Command::Reset{interface_name} => {
            let request = tonic::Request::new(StatsRequest {
                name: interface_name
            });
            let response = client.reset(request).await?;
            println!("RESPONSE={:?}", response);
        },
    }
    Ok(())
}