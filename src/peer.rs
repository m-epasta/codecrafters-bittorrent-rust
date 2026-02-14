use crate::Torrent;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Handshake {
    pub length: u8,
    pub bittorrent: [u8; 19],
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self {
            length: 19,
            bittorrent: *b"BitTorrent protocol",
            reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    pub async fn write_to<W>(&self, mut stream: W) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        };
        stream.write_all(bytes).await?;
        Ok(())
    }

    pub async fn read_from<R>(mut stream: R) -> Result<Self>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut bytes = [0u8; std::mem::size_of::<Self>()];
        stream.read_exact(&mut bytes).await?;

        Ok(unsafe { std::ptr::read(bytes.as_ptr() as *const Self) })
    }
}

pub async fn handshake(torrent: String, mut tcp_peer: TcpStream) -> Result<()> {
    let t = Torrent::from_file(torrent)?;

    let handshake = Handshake::new(t.info_hash(), rand::random::<[u8; 20]>());
    handshake.write_to(&mut tcp_peer).await?;

    let response = Handshake::read_from(&mut tcp_peer).await?;

    assert_eq!(response.length, 19);
    assert_eq!(&response.bittorrent, b"BitTorrent protocol");
    println!("Peer ID: {}", hex::encode(response.peer_id));

    Ok(())
}

// Message IDs as constants
const ID_CHOKE: u8 = 0;
const ID_UNCHOKE: u8 = 1;
const ID_INTERESTED: u8 = 2;
const ID_HAVE: u8 = 4;
const ID_BITFIELD: u8 = 5;
const ID_REQUEST: u8 = 6;
const ID_PIECE: u8 = 7;

#[derive(Debug, PartialEq)]
pub enum PeerMessage {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
}

#[allow(dead_code)]
impl PeerMessage {
    /// Get the message ID for this message (None for KeepAlive)
    pub fn id(&self) -> Option<u8> {
        match self {
            PeerMessage::KeepAlive => None,
            PeerMessage::Choke => Some(ID_CHOKE),
            PeerMessage::Unchoke => Some(ID_UNCHOKE),
            PeerMessage::Interested => Some(ID_INTERESTED),
            PeerMessage::Have(_) => Some(ID_HAVE),
            PeerMessage::Bitfield(_data) => Some(ID_BITFIELD),
            PeerMessage::Request { .. } => Some(ID_REQUEST),
            PeerMessage::Piece { .. } => Some(ID_PIECE),
        }
    }

    pub async fn write_to<W>(&self, mut stream: W) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        match self {
            PeerMessage::KeepAlive => {
                stream.write_all(&0u32.to_be_bytes()).await?;
            }

            PeerMessage::Choke | PeerMessage::Unchoke | PeerMessage::Interested => {
                // Length = 1 (just the ID)
                stream.write_all(&1u32.to_be_bytes()).await?; // length prefix
                stream.write_all(&[self.id().unwrap()]).await?; // message ID
            }

            PeerMessage::Have(index) => {
                stream.write_all(&5u32.to_be_bytes()).await?;
                stream.write_all(&[ID_HAVE]).await?;
                stream.write_all(&index.to_be_bytes()).await?;
            }

            PeerMessage::Bitfield(data) => {
                // Length = 1 (ID) + data.len()
                let len = 1 + data.len();
                stream.write_all(&(len as u32).to_be_bytes()).await?; // length prefix
                stream.write_all(&[ID_BITFIELD]).await?; // message ID
                stream.write_all(data).await?; // bitfield data
            }

            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                // Length = 1 (ID) + 12 (3x u32) = 13
                stream.write_all(&13u32.to_be_bytes()).await?; // length prefix
                stream.write_all(&[ID_REQUEST]).await?; // message ID
                stream.write_all(&index.to_be_bytes()).await?;
                stream.write_all(&begin.to_be_bytes()).await?;
                stream.write_all(&length.to_be_bytes()).await?;
            }

            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                // Length = 1 (ID) + 8 (2x u32) + block.len()
                let len = 9 + block.len();
                stream.write_all(&(len as u32).to_be_bytes()).await?; // length prefix
                stream.write_all(&[ID_PIECE]).await?; // message ID
                stream.write_all(&index.to_be_bytes()).await?;
                stream.write_all(&begin.to_be_bytes()).await?;
                stream.write_all(block).await?;
            }
        }

        Ok(())
    }

    pub async fn read_from<R>(mut stream: R) -> Result<Option<Self>>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut length_buf = [0u8; 4];
        if stream.read_exact(&mut length_buf).await.is_err() {
            return Ok(None); // Connection closed
        }
        let length = u32::from_be_bytes(length_buf) as usize;

        // Keep alive
        if length == 0 {
            return Ok(Some(PeerMessage::KeepAlive));
        }

        let mut id_buf = [0u8; 1];
        stream.read_exact(&mut id_buf).await?;

        match id_buf[0] {
            ID_CHOKE if length == 1 => Ok(Some(PeerMessage::Choke)),
            ID_UNCHOKE if length == 1 => Ok(Some(PeerMessage::Unchoke)),
            ID_INTERESTED if length == 1 => Ok(Some(PeerMessage::Interested)),

            ID_HAVE if length == 5 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                let index = u32::from_be_bytes(buf);
                Ok(Some(PeerMessage::Have(index)))
            }

            ID_BITFIELD => {
                let mut data = vec![0u8; length - 1];
                if !data.is_empty() {
                    stream.read_exact(&mut data).await?;
                }

                Ok(Some(PeerMessage::Bitfield(data)))
            }

            ID_REQUEST if length == 13 => {
                let mut buf = [0u8; 12];
                stream.read_exact(&mut buf).await?;
                let index = u32::from_be_bytes(buf[0..4].try_into()?);
                let begin = u32::from_be_bytes(buf[4..8].try_into()?);
                let len = u32::from_be_bytes(buf[8..12].try_into()?);
                Ok(Some(PeerMessage::Request {
                    index,
                    begin,
                    length: len,
                }))
            }

            ID_PIECE => {
                // Read index and begin
                let mut header = [0u8; 8];
                stream.read_exact(&mut header).await?;
                let index = u32::from_be_bytes(header[0..4].try_into()?);
                let begin = u32::from_be_bytes(header[4..8].try_into()?);

                // Read block
                let block_len = length - 9;
                let mut block = vec![0u8; block_len];
                if block_len > 0 {
                    stream.read_exact(&mut block).await?;
                }

                Ok(Some(PeerMessage::Piece {
                    index,
                    begin,
                    block,
                }))
            }

            _ => anyhow::bail!("Unknown message ID: {}", id_buf[0]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_handshake_write_read() {
        let (mut client, mut server) = duplex(1024);

        let info_hash = [1u8; 20];
        let peer_id = [2u8; 20];

        let handshake = Handshake::new(info_hash, peer_id);

        // Write from client to server
        handshake.write_to(&mut client).await.unwrap();

        // Read from server
        let received = Handshake::read_from(&mut server).await.unwrap();

        assert_eq!(received.length, 19);
        assert_eq!(received.bittorrent, *b"BitTorrent protocol");
        assert_eq!(received.info_hash, info_hash);
        assert_eq!(received.peer_id, peer_id);
    }

    #[tokio::test]
    async fn test_peer_message_serialization() {
        let (mut client, mut server) = duplex(1024);

        let messages = vec![
            PeerMessage::KeepAlive,
            PeerMessage::Unchoke,
            PeerMessage::Interested,
            PeerMessage::Bitfield(vec![0xAA, 0xBB]),
            PeerMessage::Request {
                index: 1,
                begin: 2,
                length: 3,
            },
            PeerMessage::Piece {
                index: 1,
                begin: 2,
                block: vec![0x11, 0x22],
            },
        ];

        for msg in messages {
            msg.write_to(&mut client).await.unwrap();
            let received = PeerMessage::read_from(&mut server).await.unwrap().unwrap();

            match (&msg, &received) {
                (PeerMessage::KeepAlive, PeerMessage::KeepAlive) => {}
                (PeerMessage::Unchoke, PeerMessage::Unchoke) => {}
                (PeerMessage::Interested, PeerMessage::Interested) => {}
                (PeerMessage::Bitfield(d1), PeerMessage::Bitfield(d2)) => assert_eq!(d1, d2),
                (
                    PeerMessage::Request {
                        index: i1,
                        begin: b1,
                        length: l1,
                    },
                    PeerMessage::Request {
                        index: i2,
                        begin: b2,
                        length: l2,
                    },
                ) => {
                    assert_eq!(i1, i2);
                    assert_eq!(b1, b2);
                    assert_eq!(l1, l2);
                }
                (
                    PeerMessage::Piece {
                        index: i1,
                        begin: b1,
                        block: bl1,
                    },
                    PeerMessage::Piece {
                        index: i2,
                        begin: b2,
                        block: bl2,
                    },
                ) => {
                    assert_eq!(i1, i2);
                    assert_eq!(b1, b2);
                    assert_eq!(bl1, bl2);
                }
                _ => panic!("Message mismatch: expected {:?}, got {:?}", msg, received),
            }
        }
    }
}
