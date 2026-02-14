use crate::Torrent;
use crate::peer::{Handshake, PeerMessage};
use anyhow::Context;
use tokio::net::TcpStream;

pub async fn download_piece(
    torrent_path: String,
    mut tcp_peer: TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    let t = Torrent::from_file(torrent_path)?;

    // 1. Handshake
    let handshake = Handshake::new(t.info_hash(), rand::random::<[u8; 20]>());
    handshake.write_to(&mut tcp_peer).await?;
    let _response = Handshake::read_from(&mut tcp_peer).await?;

    // 2. Wait for Bitfield
    let msg = PeerMessage::read_from(&mut tcp_peer)
        .await?
        .context("expected bitfield")?;
    match msg {
        PeerMessage::Bitfield(_) => {}
        _ => anyhow::bail!("Expected bitfield message, got {:?}", msg),
    }

    // 3. Send Interested
    PeerMessage::Interested.write_to(&mut tcp_peer).await?;

    // 4. Wait for Unchoke
    loop {
        let msg = PeerMessage::read_from(&mut tcp_peer)
            .await?
            .context("expected unchoke")?;
        match msg {
            PeerMessage::Unchoke => break,
            PeerMessage::Bitfield(_) => continue, // Ignore extra bitfields
            _ => continue,                        // Ignore other messages like Have
        }
    }

    // 5. Request blocks (Pipelined)
    let piece_length = t.piece_length(piece_index) as u32;
    let block_size = 16 * 1024;
    let num_blocks = (piece_length + block_size - 1) / block_size;
    let mut piece_data = vec![0u8; piece_length as usize];

    let mut requested_blocks = 0;
    let mut received_blocks = 0;
    const MAX_PENDING: usize = 5;

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
            .write_to(&mut tcp_peer)
            .await?;

            requested_blocks += 1;
        }

        // Receive Piece (or handle other messages)
        let msg = PeerMessage::read_from(&mut tcp_peer)
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
            PeerMessage::Unchoke => continue, // Already unchoked, but ignore redundant unchokes
            _ => continue,                    // Ignore other messages like Have, Bitfield
        }
    }

    Ok(piece_data)
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
