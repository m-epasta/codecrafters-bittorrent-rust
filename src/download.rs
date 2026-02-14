use crate::peer::{Handshake, PeerMessage};
use crate::Torrent;
use anyhow::Context;
use tokio::net::TcpStream;

pub async fn download_piece(
    torrent_path: String,
    mut tcp_peer: TcpStream,
    piece_index: u32,
) -> anyhow::Result<Vec<u8>> {
    let t = Torrent::from_file(torrent_path)?;

    // 1. Handshake
    let handshake = Handshake::new(t.info_hash(), *b"00112233445566778899");
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

    // 5. Request blocks
    let piece_length = t.piece_length(piece_index) as u32;
    let block_size = 16 * 1024;
    let num_blocks = (piece_length + block_size - 1) / block_size;
    let mut piece_data = vec![0u8; piece_length as usize];

    for i in 0..num_blocks {
        let begin = i * block_size;
        let length = if i == num_blocks - 1 {
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

        // Receive Piece
        let msg = PeerMessage::read_from(&mut tcp_peer)
            .await?
            .context("expected piece")?;
        match msg {
            PeerMessage::Piece {
                index,
                begin: b,
                block,
            } => {
                assert_eq!(index, piece_index);
                assert_eq!(b, begin);
                piece_data[begin as usize..(begin + length) as usize].copy_from_slice(&block);
            }
            _ => anyhow::bail!("Expected piece message, got {:?}", msg),
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
