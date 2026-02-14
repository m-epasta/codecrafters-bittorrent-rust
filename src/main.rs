use anyhow::Context;
use clap::{Parser, Subcommand};
use torrent::Torrent;

mod beencode;
mod decoder;
mod download;
mod peer;
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
    /// Establish a handshake via a tcp conn
    Handshake { torrent: String, peer: String },
    /// Download a piece
    DownloadPiece {
        #[arg(short)]
        output: String,
        torrent: String,
        piece: u32,
    },
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
        Commands::Handshake { torrent, peer } => {
            let tcp_peer = tokio::net::TcpStream::connect(peer)
                .await
                .context("connect to peer")?;
            crate::peer::handshake(torrent, tcp_peer)
                .await
                .context("failed handshake")?;
        }
        Commands::DownloadPiece {
            output,
            torrent,
            piece,
        } => {
            let t = Torrent::from_file(&torrent)?;
            let peers = t.peers().await?;
            let peer = peers.first().context("no peers found")?;

            let tcp_peer = tokio::net::TcpStream::connect(format!("{}:{}", peer.ip, peer.port))
                .await
                .context("connect to peer")?;

            let piece_data = crate::download::download_piece(torrent, tcp_peer, piece)
                .await
                .context("failed to download piece")?;

            // Verify hash
            let hash = t.piece_hashes()[piece as usize].clone();
            let mut hasher = sha1::Sha1::new();
            use sha1::Digest;
            hasher.update(&piece_data);
            let result = hex::encode(hasher.finalize());

            if result != hash {
                anyhow::bail!("piece hash mismatch");
            }

            std::fs::write(output, piece_data).context("failed to write piece to file")?;
        }
    }

    Ok(())
}
