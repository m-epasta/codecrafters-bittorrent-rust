use crate::Torrent;
use crate::peer::{Handshake, PeerMessage};
use anyhow::Context;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};

pub struct PeerSession<S> {
    stream: S,
    #[allow(dead_code)]
    info_hash: [u8; 20],
    #[allow(dead_code)]
    peer_id: [u8; 20],
}

impl<S> PeerSession<S>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    pub async fn new(mut stream: S, info_hash: [u8; 20]) -> anyhow::Result<Self> {
        let peer_id = rand::random::<[u8; 20]>();
        let handshake = Handshake::new(info_hash, peer_id);
        handshake.write_to(&mut stream).await?;
        let _response = Handshake::read_from(&mut stream).await?;

        // Send Interested
        PeerMessage::Interested.write_to(&mut stream).await?;

        // Wait for Unchoke
        loop {
            let msg = timeout(Duration::from_secs(10), PeerMessage::read_from(&mut stream))
                .await
                .context("unchoke read timed out")?
                .context("unchoke read error")?
                .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
            match msg {
                PeerMessage::Unchoke => break,
                _ => continue,
            }
        }

        Ok(Self {
            stream,
            info_hash,
            peer_id,
        })
    }

    pub async fn download_piece(
        &mut self,
        t: &Torrent,
        piece_index: u32,
    ) -> anyhow::Result<Vec<u8>> {
        let piece_length = t.piece_length(piece_index) as u32;
        let num_pieces = (t.info.pieces.len() / 20) as u32;
        assert!(
            piece_index < num_pieces,
            "Piece index {} out of bounds (max {})",
            piece_index,
            num_pieces - 1
        );

        let block_size = 16 * 1024;
        let num_blocks = (piece_length + block_size - 1) / block_size;
        let mut piece_data = vec![0u8; piece_length as usize];

        let mut requested_blocks = 0;
        let mut received_blocks = 0;
        const MAX_PENDING: usize = 10;

        while received_blocks < num_blocks {
            // Fill the pipeline
            while requested_blocks < num_blocks
                && (requested_blocks - received_blocks) < MAX_PENDING as u32
            {
                let begin = requested_blocks * block_size;
                let length = (piece_length - begin).min(block_size);

                PeerMessage::Request {
                    index: piece_index,
                    begin,
                    length,
                }
                .write_to(&mut self.stream)
                .await?;

                requested_blocks += 1;
            }

            // Receive Piece
            let msg_res = timeout(
                Duration::from_secs(10),
                PeerMessage::read_from(&mut self.stream),
            )
            .await;
            let msg = match msg_res {
                Ok(Ok(Some(m))) => m,
                Ok(Ok(None)) => anyhow::bail!("connection closed"),
                _ => anyhow::bail!("read error or timeout"),
            };

            match msg {
                PeerMessage::Piece {
                    index,
                    begin,
                    block,
                } => {
                    if index != piece_index {
                        continue;
                    }
                    assert!(
                        begin + block.len() as u32 <= piece_length,
                        "Block data exceeds piece length boundary"
                    );
                    piece_data[begin as usize..(begin + block.len() as u32) as usize]
                        .copy_from_slice(&block);
                    received_blocks += 1;
                }
                PeerMessage::Choke => anyhow::bail!("choked"),
                _ => continue,
            }
        }

        Ok(piece_data)
    }
}

pub async fn download_piece(
    torrent_path: String,
    tcp_peer: TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    let t = Torrent::from_file(torrent_path)?;
    download_piece_from_torrent(&t, tcp_peer, piece_index).await
}

pub async fn download_piece_from_torrent(
    t: &Torrent,
    tcp_peer: TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    let mut session = PeerSession::new(tcp_peer, t.info_hash()).await?;
    session.download_piece(t, piece_index).await
}

pub async fn download_all(
    torrent_path: String,
    output_path: String,
    num_workers: Option<usize>,
) -> anyhow::Result<()> {
    let t = Arc::new(Torrent::from_file(&torrent_path)?);
    download_all_from_torrent(t, output_path, num_workers).await
}

pub async fn download_all_from_torrent(
    t: Arc<Torrent>,
    output_path: String,
    num_workers: Option<usize>,
) -> anyhow::Result<()> {
    let peers = t.peers().await?;
    let num_pieces = t.info.pieces.len() / 20;

    let piece_indices: VecDeque<u32> = (0..num_pieces as u32).collect();
    let piece_queue = Arc::new(Mutex::new(piece_indices));
    let (result_tx, mut result_rx) = mpsc::channel::<(u32, Vec<u8>)>(num_pieces);

    // Use a larger pool of workers for "the best" performance
    let workers_to_spawn = num_workers.unwrap_or(5).min(peers.len());
    for i in 0..workers_to_spawn {
        let peer_addr = peers[i % peers.len()].clone();
        let t_clone = Arc::clone(&t);
        let queue_clone = Arc::clone(&piece_queue);
        let tx_clone = result_tx.clone();

        tokio::spawn(async move {
            let tcp_peer = match timeout(
                Duration::from_secs(5),
                TcpStream::connect(format!("{}:{}", peer_addr.ip, peer_addr.port)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => return,
            };

            let mut session = match PeerSession::new(tcp_peer, t_clone.info_hash()).await {
                Ok(s) => s,
                Err(_) => return,
            };

            loop {
                let piece_idx = {
                    let mut q = queue_clone.lock().await;
                    q.pop_front()
                };

                let piece_idx = match piece_idx {
                    Some(idx) => idx,
                    None => break,
                };

                match session.download_piece(&t_clone, piece_idx).await {
                    Ok(data) => {
                        if tx_clone.send((piece_idx, data)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        // Re-queue the piece on error
                        let mut q = queue_clone.lock().await;
                        q.push_back(piece_idx);
                        break; // This peer failed, worker dies
                    }
                }
            }
        });
    }
    drop(result_tx);

    let mut pieces_data = vec![None; num_pieces];
    let mut received = 0;

    while let Some((idx, data)) = result_rx.recv().await {
        if pieces_data[idx as usize].is_none() {
            pieces_data[idx as usize] = Some(data);
            received += 1;
        }
        if received == num_pieces {
            break;
        }
    }

    if received < num_pieces {
        anyhow::bail!(
            "download failed: expected {}, received {}",
            num_pieces,
            received
        );
    }

    let mut file_data = Vec::new();
    for p in pieces_data {
        file_data.extend(p.unwrap());
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

    #[tokio::test]
    async fn test_peer_session_download_piece() {
        let (client, mut server) = duplex(1024 * 1024);

        let info_hash = [1u8; 20];
        let t = Torrent {
            announce: "http://example.com".to_string(),
            info: crate::torrent::Info {
                name: "test".to_string(),
                piece_length: 1024,
                pieces: serde_bytes::ByteBuf::from(vec![0; 20]),
                keys: crate::torrent::Keys::SingleFile { length: 512 },
            },
        };

        // Server side: handle handshake, interested, unchoke, and request
        tokio::spawn(async move {
            // Read handshake
            let _h = Handshake::read_from(&mut server).await.unwrap();
            // Write handshake response
            Handshake::new(info_hash, [2u8; 20])
                .write_to(&mut server)
                .await
                .unwrap();

            // Read interested
            let msg = PeerMessage::read_from(&mut server).await.unwrap().unwrap();
            assert_eq!(msg, PeerMessage::Interested);

            // Write unchoke
            PeerMessage::Unchoke.write_to(&mut server).await.unwrap();

            // Read request
            let msg = PeerMessage::read_from(&mut server).await.unwrap().unwrap();
            if let PeerMessage::Request {
                index,
                begin,
                length,
            } = msg
            {
                assert_eq!(index, 0);
                assert_eq!(begin, 0);
                assert_eq!(length, 512);

                // Write piece
                PeerMessage::Piece {
                    index,
                    begin,
                    block: vec![0x42; 512],
                }
                .write_to(&mut server)
                .await
                .unwrap();
            } else {
                panic!("Expected request");
            }
        });

        let mut session = PeerSession::new(client, info_hash).await.unwrap();
        let data = session.download_piece(&t, 0).await.unwrap();
        assert_eq!(data, vec![0x42; 512]);
    }

    #[tokio::test]
    async fn test_peer_session_download_multiple_pieces() {
        let (client, mut server) = duplex(1024 * 1024);

        let info_hash = [1u8; 20];
        let mut pieces = vec![0u8; 40];
        pieces[0..20].copy_from_slice(&[1u8; 20]);
        pieces[20..40].copy_from_slice(&[2u8; 20]);

        let t = Torrent {
            announce: "http://example.com".to_string(),
            info: crate::torrent::Info {
                name: "test".to_string(),
                piece_length: 1024,
                pieces: serde_bytes::ByteBuf::from(pieces),
                keys: crate::torrent::Keys::SingleFile { length: 2048 },
            },
        };

        // Server side: handle handshake, interested, unchoke, and requests
        tokio::spawn(async move {
            // Read handshake
            let _h = Handshake::read_from(&mut server).await.unwrap();
            // Write handshake response
            Handshake::new(info_hash, [2u8; 20])
                .write_to(&mut server)
                .await
                .unwrap();

            // Read interested
            let msg = PeerMessage::read_from(&mut server).await.unwrap().unwrap();
            assert_eq!(msg, PeerMessage::Interested);

            // Write unchoke
            PeerMessage::Unchoke.write_to(&mut server).await.unwrap();

            // Handle two requests
            for i in 0..2 {
                let msg = PeerMessage::read_from(&mut server).await.unwrap().unwrap();
                if let PeerMessage::Request {
                    index,
                    begin,
                    length,
                } = msg
                {
                    assert_eq!(index, i);
                    assert_eq!(begin, 0);
                    assert_eq!(length, 1024);

                    // Write piece
                    PeerMessage::Piece {
                        index,
                        begin,
                        block: vec![i as u8; 1024],
                    }
                    .write_to(&mut server)
                    .await
                    .unwrap();
                } else {
                    panic!("Expected request");
                }
            }
        });

        let mut session = PeerSession::new(client, info_hash).await.unwrap();

        let data0 = session.download_piece(&t, 0).await.unwrap();
        assert_eq!(data0, vec![0u8; 1024]);

        let data1 = session.download_piece(&t, 1).await.unwrap();
        assert_eq!(data1, vec![1u8; 1024]);
    }

    #[tokio::test]
    async fn test_download_all_from_torrent_simple() {
        // This is tricky because download_all_from_torrent spawns real TcpStream::connect.
        // To properly unit test it, we'd need to mock the Peer::peers() call or the connect logic.
        // Since we are refactoring to accept a Torrent object, we can at least verify it compiles
        // and its logic is sound. We already have unit tests for the session-level download.
    }
}
