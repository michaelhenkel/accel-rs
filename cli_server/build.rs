fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .out_dir("src/cli_server")
        .compile(
            &["proto/cli_server.proto"], 
            &[""]
        ).unwrap();
    Ok(())
    }