use anyhow::Context;
use serde::{Deserialize, Serialize};
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
}
