use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{fs, path::Path};

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

    pub fn piece_hash(&self) -> Vec<String> {
        self.info.pieces.chunks_exact(20).map(hex::encode).collect()
    }
}
