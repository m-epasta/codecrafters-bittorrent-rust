use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{borrow::Cow, fs, net::Ipv4Addr, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: u64,
    pub pieces: serde_bytes::ByteBuf,
    #[serde(flatten)]
    pub keys: Keys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Keys {
    SingleFile { length: u64 },
    MultiFile { files: Vec<File> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    pub length: u64,
    pub path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    pub interval: Option<u64>,
    pub peers: serde_bytes::ByteBuf,
}

impl Torrent {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content: Vec<u8> = fs::read(path).context("Failed to read torrent file")?;
        let torrent: Torrent =
            serde_bencode::from_bytes(&content).context("Failed to decode bencode")?;
        Ok(torrent)
    }

    pub fn info_hash(&self) -> [u8; 20] {
        let info_encoded = serde_bencode::to_bytes(&self.info).expect("Failed to encode section");

        let mut hasher = Sha1::new();
        hasher.update(info_encoded);
        let result = hasher.finalize();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn piece_hashes(&self) -> Vec<String> {
        self.info.pieces.chunks_exact(20).map(hex::encode).collect()
    }

    pub fn length(&self) -> u64 {
        match &self.info.keys {
            Keys::SingleFile { length } => *length,
            Keys::MultiFile { files } => files.iter().map(|f| f.length).sum(),
        }
    }

    pub fn piece_length(&self, piece_index: u32) -> u64 {
        let total_length = self.length();
        let piece_length = self.info.piece_length;
        let num_pieces = (total_length + piece_length - 1) / piece_length;
        if piece_index as u64 == num_pieces - 1 {
            let last_length = total_length % piece_length;
            if last_length == 0 {
                piece_length
            } else {
                last_length
            }
        } else {
            piece_length
        }
    }

    pub async fn peers(&self) -> Result<Vec<Peer>, anyhow::Error> {
        let mut url = reqwest::Url::parse(&self.announce).context("parse announce url")?;
        let info_hash = self.info_hash();

        let peer_id = rand::random::<[u8; 20]>();
        let url = url
            .query_pairs_mut()
            .encoding_override(Some(&|input: &str| {
                if input == "info_hash_placeholder" {
                    Cow::Owned(info_hash.to_vec())
                } else if input == "peer_id_placeholder" {
                    Cow::Owned(peer_id.to_vec())
                } else {
                    Cow::Borrowed(input.as_bytes())
                }
            }))
            .append_pair("info_hash", "info_hash_placeholder")
            .append_pair("peer_id", "peer_id_placeholder")
            .append_pair("port", "6081")
            .append_pair("uploaded", "0")
            .append_pair("downloaded", "0")
            .append_pair("left", &self.length().to_string())
            .append_pair("compact", "1")
            .finish();

        let res = reqwest::Client::new().get(url.clone()).send().await?;
        let bytes = res.bytes().await?;
        let tracker_response: TrackerResponse =
            serde_bencode::from_bytes(&bytes).context("decode tracker response")?;

        let peers = tracker_response
            .peers
            .chunks_exact(6)
            .map(|chunk| {
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                Peer { ip, port }
            })
            .collect();

        Ok(peers)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_bytes::ByteBuf;

    #[test]
    fn test_torrent_length_single_file() {
        let torrent = Torrent {
            announce: "http://tracker.com".to_string(),
            info: Info {
                name: "test".to_string(),
                piece_length: 256,
                pieces: ByteBuf::from(vec![0; 20]),
                keys: Keys::SingleFile { length: 1024 },
            },
        };
        assert_eq!(torrent.length(), 1024);
    }

    #[test]
    fn test_torrent_length_multi_file() {
        let torrent = Torrent {
            announce: "http://tracker.com".to_string(),
            info: Info {
                name: "test".to_string(),
                piece_length: 256,
                pieces: ByteBuf::from(vec![0; 20]),
                keys: Keys::MultiFile {
                    files: vec![
                        File {
                            length: 512,
                            path: vec!["file1".to_string()],
                        },
                        File {
                            length: 512,
                            path: vec!["file2".to_string()],
                        },
                    ],
                },
            },
        };
        assert_eq!(torrent.length(), 1024);
    }

    #[test]
    fn test_torrent_piece_hashes() {
        let mut pieces = vec![0u8; 40];
        pieces[0..20].copy_from_slice(&[1u8; 20]);
        pieces[20..40].copy_from_slice(&[2u8; 20]);

        let torrent = Torrent {
            announce: "http://tracker.com".to_string(),
            info: Info {
                name: "test".to_string(),
                piece_length: 256,
                pieces: ByteBuf::from(pieces),
                keys: Keys::SingleFile { length: 1024 },
            },
        };

        let hashes = torrent.piece_hashes();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], hex::encode(&[1u8; 20]));
        assert_eq!(hashes[1], hex::encode(&[2u8; 20]));
    }
}
