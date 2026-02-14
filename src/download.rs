use crate::Torrent;
use crate::peer::{Handshake, PeerMessage};
use anyhow::Context;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

pub async fn download_piece(
    torrent_path: String,
    mut tcp_peer: TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    let t = Torrent::from_file(torrent_path)?;
    download_piece_from_peer(&t, &mut tcp_peer, piece_index).await
}

async fn download_piece_from_peer(
    t: &Torrent,
    tcp_peer: &mut TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    // 1. Handshake
    let handshake = Handshake::new(t.info_hash(), rand::random::<[u8; 20]>());
    handshake.write_to(&mut *tcp_peer).await?;
    let _response = Handshake::read_from(&mut *tcp_peer).await?;

    // 2. Wait for Bitfield
    loop {
        let msg = PeerMessage::read_from(&mut *tcp_peer)
            .await?
            .context("expected bitfield")?;
        match msg {
            PeerMessage::Bitfield(_) => break,
            PeerMessage::Unchoke | PeerMessage::Interested | PeerMessage::Choke => continue,
            _ => break, // Some peers might skip bitfield if they have everything or nothing
        }
    }

    // 3. Send Interested
    PeerMessage::Interested.write_to(&mut *tcp_peer).await?;

    // 4. Wait for Unchoke
    loop {
        let msg = PeerMessage::read_from(&mut *tcp_peer)
            .await?
            .context("expected unchoke")?;
        match msg {
            PeerMessage::Unchoke => break,
            _ => continue,
        }
    }

    // 5. Request blocks (Pipelined)
    let piece_length = t.piece_length(piece_index) as u32;
    let block_size = 16 * 1024;
    let num_blocks = (piece_length + block_size - 1) / block_size;
    let mut piece_data = vec![0u8; piece_length as usize];

    let mut requested_blocks = 0;
    let mut received_blocks = 0;
    const MAX_PENDING: usize = 10; // Safer pipelining

    while received_blocks < num_blocks {
        // Fill the pipeline
        while requested_blocks < num_blocks
            && (requested_blocks - received_blocks) < MAX_PENDING as u32
        {
            let begin = requested_blocks * block_size;
            let length = if requested_blocks == num_blocks - 1 {
                piece_length - begin
            } else {
                block_size
            };

            PeerMessage::Request {
                index: piece_index,
                begin,
                length,
            }
            .write_to(&mut *tcp_peer)
            .await?;

            requested_blocks += 1;
        }

        // Receive Piece (or handle other messages)
        let msg = PeerMessage::read_from(&mut *tcp_peer)
            .await?
            .context("connection closed during download")?;

        match msg {
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                if index != piece_index {
                    anyhow::bail!("received block for wrong piece: {}", index);
                }
                piece_data[begin as usize..(begin + block.len() as u32) as usize]
                    .copy_from_slice(&block);
                received_blocks += 1;
            }
            PeerMessage::Choke => anyhow::bail!("Peer choked us during download"),
            PeerMessage::Unchoke => continue,
            _ => continue,
        }
    }

    Ok(piece_data)
}

pub async fn download_all(torrent_path: String, output_path: String) -> anyhow::Result<()> {
    let t = Arc::new(Torrent::from_file(&torrent_path)?);
    let peers = t.peers().await?;
    let num_pieces = t.info.pieces.len() / 20;

    let piece_indices: VecDeque<u32> = (0..num_pieces as u32).collect();
    let piece_queue = Arc::new(Mutex::new(piece_indices));
    let (result_tx, mut result_rx) = mpsc::channel::<(u32, Vec<u8>)>(num_pieces as usize);

    // Limit active workers to avoid overwhelming the tester or being rate-limited
    let num_workers = peers.len().min(5);
    let mut tasks = Vec::new();

    for i in 0..num_workers {
        let peer_addr = peers[i].clone();
        let t_clone = Arc::clone(&t);
        let piece_queue_clone = Arc::clone(&piece_queue);
        let result_tx_clone = result_tx.clone();

        let task = tokio::spawn(async move {
            let mut tcp_peer =
                match TcpStream::connect(format!("{}:{}", peer_addr.ip, peer_addr.port)).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        eprintln!("Worker {} failed to connect to {}: {}", i, peer_addr.ip, e);
                        return;
                    }
                };

            loop {
                let piece_idx = {
                    let mut queue = piece_queue_clone.lock().await;
                    queue.pop_front()
                };

                let piece_idx = match piece_idx {
                    Some(idx) => idx,
                    None => break,
                };

                match download_piece_from_peer(&t_clone, &mut tcp_peer, piece_idx).await {
                    Ok(data) => {
                        if result_tx_clone.send((piece_idx, data)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Worker {} error on piece {}: {}", i, piece_idx, e);
                        let mut queue = piece_queue_clone.lock().await;
                        queue.push_back(piece_idx);
                        break;
                    }
                }
            }
        });
        tasks.push(task);
    }

    drop(result_tx);

    let mut pieces_data = vec![None; num_pieces as usize];
    let mut received_count = 0;

    while let Some((idx, data)) = result_rx.recv().await {
        pieces_data[idx as usize] = Some(data);
        received_count += 1;
        if received_count == num_pieces {
            break;
        }
    }

    if received_count < num_pieces {
        anyhow::bail!(
            "Download failed: requested {}, received {}",
            num_pieces,
            received_count
        );
    }

    let mut file_data = Vec::with_capacity(t.length() as usize);
    for piece in pieces_data {
        file_data.extend(piece.expect("piece missing after successful count"));
    }

    tokio::fs::write(output_path, file_data).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_send_msg() {
        let (client, mut server) = duplex(1024);
        let msg = PeerMessage::Interested;

        // Spawn a task to send the message
        tokio::spawn(async move {
            let _ = msg.write_to(client).await;
        });

        // Read from server
        let received = PeerMessage::read_from(&mut server).await.unwrap().unwrap();
        assert_eq!(received, PeerMessage::Interested);
    }
}
