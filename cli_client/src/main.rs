use anyhow::{anyhow, Error};
use cli_server::cli_server::cli_server::stats_client::StatsClient;
use cli_server::cli_server::cli_server::StatsRequest;
use clap::Parser;


#[derive(Parser)]
struct Arguments {
    command: Command,
}
#[derive(Clone)]
enum Command {
    Get(String),
    Reset(String),
}

impl std::str::FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "get" => Ok(Command::Get("all".into())),
            "reset" => Ok(Command::Reset("all".into())),
            _ => Err(anyhow!("Invalid Command mode")),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = StatsClient::connect("http://[::1]:50051").await?;

    let args = Arguments::parse();

    match args.command{
        Command::Get(name) => {
            let request = tonic::Request::new(StatsRequest {
                name,
            });
            let response = client.get(request).await?;
            println!("RESPONSE={:?}", response);
        },
        Command::Reset(name) => {
            let request = tonic::Request::new(StatsRequest {
                name,
            });
            let response = client.reset(request).await?;
            println!("RESPONSE={:?}", response);
        },
    }
    Ok(())
}