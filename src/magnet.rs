use anyhow::{Context, Result, anyhow};
use reqwest::Url;
use std::{borrow::Cow, net::Ipv4Addr};

pub struct Magnet {
    pub info_hash: [u8; 20],
    pub announce: String,
}

impl Magnet {
    pub fn info(link: &str) -> Result<()> {
        let magnet = parse_magnet_link(link).context("parse magnet")?;
        println!("Tracker URL: {}", magnet.announce);
        println!("Info Hash: {}", hex::encode(magnet.info_hash));
        Ok(())
    }

    pub async fn peers(&self) -> Result<Vec<crate::torrent::Peer>> {
        let mut url = Url::parse(&self.announce).context("parse announce url")?;
        let info_hash = self.info_hash;
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
            .append_pair("left", "0") // Magnet links often don't have length until metadata is fetched
            .append_pair("compact", "1")
            .finish();

        let res = reqwest::Client::new().get(url.clone()).send().await?;
        let bytes = res.bytes().await?;
        let tracker_response: crate::torrent::TrackerResponse =
            serde_bencode::from_bytes(&bytes).context("decode tracker response")?;

        let peers = tracker_response
            .peers
            .chunks_exact(6)
            .map(|chunk| {
                let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                crate::torrent::Peer { ip, port }
            })
            .collect();

        Ok(peers)
    }
}

pub fn parse_magnet_link(link: &str) -> Result<Magnet> {
    let parsed_url = Url::parse(link).context("parse URL")?;
    let mut announce = None;
    let mut hash = None;

    for (k, v) in parsed_url.query_pairs() {
        match k {
            Cow::Borrowed("tr") => announce = Some(v.to_string()),
            Cow::Borrowed("xt") => {
                let h = v
                    .strip_prefix("urn:btih:")
                    .ok_or(anyhow!("invalid hash format"))?;
                let decoded = hex::decode(h).context("invalid hex in magnet link")?;
                let h_arr: [u8; 20] = decoded
                    .try_into()
                    .map_err(|_| anyhow!("invalid hash length"))?;
                hash = Some(h_arr);
            }

            _ => continue,
        }
    }

    if announce.is_none() || hash.is_none() {
        return Err(anyhow!("empty hash or announce"));
    }

    Ok(Magnet {
        info_hash: hash.unwrap(),
        announce: announce.unwrap(),
    })
}
