use anyhow::Context;
use clap::{Parser, Subcommand};
use torrent::Torrent;

use crate::peer::PeerMessage;

mod beencode;
mod decoder;
mod download;
mod magnet;
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
    #[command(name = "download_piece")]
    DownloadPiece {
        #[arg(short)]
        output: String,
        torrent: String,
        piece: u32,
    },
    /// Download the whole file
    Download {
        #[arg(short)]
        output: String,
        torrent: String,
        #[arg(short, long)]
        workers: Option<usize>,
    },
    #[command(name = "magnet_parse")]
    MagnetParse { link: String },
    #[command(name = "magnet_handshake")]
    MagnetHandshake { link: String },
    #[command(name = "magnet_info")]
    MagnetInfo { link: String },
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
        Commands::Download {
            output,
            torrent,
            workers,
        } => {
            crate::download::download_all(torrent, output, workers)
                .await
                .context("failed to download file")?;
        }
        Commands::MagnetParse { link } => magnet::Magnet::info(&link)?,
        Commands::MagnetHandshake { link } => {
            let m = magnet::parse_magnet_link(&link)?;
            let peers = m.peers().await?;
            let peer = peers.first().context("no peers found")?;

            let mut tcp_peer = tokio::net::TcpStream::connect(format!("{}:{}", peer.ip, peer.port))
                .await
                .context("connect to peer")?;

            let handshake = crate::peer::Handshake::new(m.info_hash, rand::random::<[u8; 20]>())
                .with_extension();
            handshake.write_to(&mut tcp_peer).await?;

            let response = crate::peer::Handshake::read_from(&mut tcp_peer).await?;
            assert_eq!(response.length, 19, "Invalid handshake length");
            assert_eq!(
                &response.bittorrent, b"BitTorrent protocol",
                "Invalid protocol string"
            );
            assert_eq!(
                response.info_hash, m.info_hash,
                "Info hash mismatch from peer"
            );
            println!("Peer ID: {}", hex::encode(response.peer_id));

            let supports_extensions = (response.reserved[5] & 0x10) != 0;
            if !supports_extensions {
                // Peer doesnt support extensions
                return Ok(());
            }

            // Send extension handshake FIRST (as per BEP 10 "as soon as possible")
            magnet::send_extension_handshake(&mut tcp_peer).await?;

            loop {
                let message = crate::peer::PeerMessage::read_from(&mut tcp_peer).await?;

                match message {
                    Some(PeerMessage::Bitfield(_pieces)) => {
                        // Ignore bitfield
                    }
                    Some(PeerMessage::Extended {
                        extended_id,
                        payload,
                    }) => {
                        if extended_id == 0 {
                            // Extension handshake
                            let handshake_dict: serde_json::Value =
                                serde_bencode::from_bytes(&payload)?;

                            // Extract `ut_metadata`
                            if let Some(m) = handshake_dict.get("m") {
                                if let Some(ut_id) = m.get("ut_metadata") {
                                    let ut_metadata_id = ut_id.as_i64().unwrap() as u8;
                                    println!("Peer Metadata Extension ID: {}", ut_metadata_id);
                                    break;
                                }
                            }
                        }
                    }
                    Some(PeerMessage::Have(_)) => {
                        // Ignore HAVE messages during handshake
                    }
                    _ => anyhow::bail!("Unexpected PeerMessage. Got: {:?}", message),
                }
            }
        }
        Commands::MagnetInfo { link } => {
            let m = magnet::parse_magnet_link(&link)?;
            println!("Tracker URL: {}", m.announce);
            println!("Info Hash: {}", hex::encode(m.info_hash));

            let peers = m.peers().await?;
            let peer = peers.first().context("no peers found")?;

            let mut tcp_peer = tokio::net::TcpStream::connect(format!("{}:{}", peer.ip, peer.port))
                .await
                .context("connect to peer")?;

            let handshake = crate::peer::Handshake::new(m.info_hash, rand::random::<[u8; 20]>())
                .with_extension();
            handshake.write_to(&mut tcp_peer).await?;

            let response = crate::peer::Handshake::read_from(&mut tcp_peer).await?;
            println!("Peer ID: {}", hex::encode(response.peer_id));

            let supports_extensions = (response.reserved[5] & 0x10) != 0;
            if !supports_extensions {
                anyhow::bail!("Peer doesn't support extensions");
            }

            // Send extension handshake FIRST
            magnet::send_extension_handshake(&mut tcp_peer).await?;

            loop {
                let message = crate::peer::PeerMessage::read_from(&mut tcp_peer).await?;

                match message {
                    Some(PeerMessage::Bitfield(_)) => {}
                    Some(PeerMessage::Extended {
                        extended_id,
                        payload,
                    }) => {
                        if extended_id == 0 {
                            // Extension handshake
                            let handshake_dict: serde_json::Value =
                                serde_bencode::from_bytes(&payload)?;

                            // Extract `ut_metadata`
                            if let Some(m_dict) = handshake_dict.get("m") {
                                if let Some(ut_id) = m_dict.get("ut_metadata") {
                                    let ut_metadata_id = ut_id.as_i64().unwrap() as u8;

                                    // Send metadata request
                                    magnet::send_metadata_request(&mut tcp_peer, ut_metadata_id)
                                        .await?;
                                }
                            }
                        } else {
                            if let Some(split_idx) = find_bencode_dict_end(&payload) {
                                let metadata_bytes = &payload[split_idx..];
                                let info: torrent::Info =
                                    serde_bencode::from_bytes(metadata_bytes)?;

                                if let torrent::Keys::SingleFile { length } = info.keys {
                                    println!("Length: {}", length);
                                } else if let torrent::Keys::MultiFile { files } = info.keys {
                                    let total_length: u64 = files.iter().map(|f| f.length).sum();
                                    println!("Length: {}", total_length);
                                }
                                println!("Piece Length: {}", info.piece_length);
                                println!("Piece Hashes:");
                                for hash in info.pieces.chunks_exact(20).map(hex::encode) {
                                    println!("{}", hash);
                                }
                                return Ok(());
                            }
                        }
                    }
                    Some(PeerMessage::Have(_)) => {}
                    _ => {} // Ignore other messages
                }
            }
        }
    }

    Ok(())
}

fn find_bencode_dict_end(bytes: &[u8]) -> Option<usize> {
    let mut depth = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'd' | b'l' => {
                depth += 1;
                i += 1;
            }
            b'i' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'e' {
                    i += 1;
                }
                i += 1;
            }
            b'e' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'0'..=b'9' => {
                let mut len_str = String::new();
                while i < bytes.len() && bytes[i] != b':' {
                    len_str.push(bytes[i] as char);
                    i += 1;
                }
                i += 1;
                if let Ok(len) = len_str.parse::<usize>() {
                    i += len;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}
