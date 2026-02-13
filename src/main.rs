use clap::{Parser, Subcommand};
use torrent::Torrent;

mod beencode;
mod decoder;
mod torrent;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a bencoded string
    Decode { value: String },
    /// Print information about a torrent file
    Info { torrent: String },
    /// Find peers for a torrent
    Peers { torrent: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Decode { value } => {
            let decoded = beencode::decode(value.as_bytes())
                .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;
            println!("{}", decoded.to_json().to_string());
        }
        Commands::Info { torrent } => {
            let t = Torrent::from_file(torrent)?;
            let info_hash = t.info_hash();

            println!("Tracker URL: {}", t.announce);
            if let torrent::Keys::SingleFile { length } = t.info.keys {
                println!("Length: {}", length);
            }
            println!("Info Hash: {}", hex::encode(info_hash));
            println!("Piece Length: {}", t.info.piece_length);
            println!("Piece Hashes:");
            for hash in t.piece_hashes() {
                println!("{}", hash);
            }
        }
        Commands::Peers { torrent } => {
            let t = Torrent::from_file(torrent)?;
            let peers = t.peers().await?;
            for peer in peers {
                println!("{}:{}", peer.ip, peer.port);
            }
        }
    }

    Ok(())
}
