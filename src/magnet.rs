use anyhow::{Context, Result, anyhow};
use reqwest::Url;
use std::{borrow::Cow, net::Ipv4Addr};
use tokio::net::TcpStream;

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
            .append_pair("left", "999") // Non-zero value required by some trackers to return peers
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

    let info_hash = hash.unwrap();
    assert_eq!(
        info_hash.len(),
        20,
        "Info hash must be exactly 20 bytes (this should be caught by try_into but extra safety)"
    );

    Ok(Magnet {
        info_hash,
        announce: announce.unwrap(),
    })
}

#[derive(serde::Serialize)]
struct ExtensionHandshake {
    m: std::collections::BTreeMap<String, u8>,
}

pub async fn send_extension_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut m_dict = std::collections::BTreeMap::new();
    m_dict.insert("ut_metadata".to_string(), 16); // We'll use ID 16 for our metadata requests

    let handshake = ExtensionHandshake { m: m_dict };
    let payload = serde_bencode::to_bytes(&handshake)?;

    // Create an EXTENDED message (not a Handshake)
    let ext_message = crate::PeerMessage::Extended {
        extended_id: 0, // 0 = handshake
        payload,
    };

    // Write using PeerMessage's write_to, not Handshake's write_to
    ext_message.write_to(stream).await?;

    Ok(())
}

pub async fn fetch_info(link: &str) -> Result<crate::torrent::Info> {
    let m = parse_magnet_link(link)?;
    let peers = m.peers().await?;
    let peer = peers.first().context("no peers found")?;

    let mut tcp_peer = tokio::net::TcpStream::connect(format!("{}:{}", peer.ip, peer.port))
        .await
        .context("connect to peer")?;

    let handshake =
        crate::peer::Handshake::new(m.info_hash, rand::random::<[u8; 20]>()).with_extension();
    handshake.write_to(&mut tcp_peer).await?;

    let _response = crate::peer::Handshake::read_from(&mut tcp_peer).await?;

    // Send extension handshake FIRST
    send_extension_handshake(&mut tcp_peer).await?;

    loop {
        let message = crate::peer::PeerMessage::read_from(&mut tcp_peer).await?;

        match message {
            Some(crate::PeerMessage::Bitfield(_)) => {}
            Some(crate::PeerMessage::Extended {
                extended_id,
                payload,
            }) => {
                if extended_id == 0 {
                    #[derive(serde::Deserialize)]
                    struct ExtensionHandshake {
                        m: std::collections::BTreeMap<String, u8>,
                    }
                    if let Ok(handshake) = serde_bencode::from_bytes::<ExtensionHandshake>(&payload)
                    {
                        if let Some(&ut_metadata_id) = handshake.m.get("ut_metadata") {
                            send_metadata_request(&mut tcp_peer, ut_metadata_id).await?;
                        }
                    }
                } else {
                    if let Some(split_idx) = crate::beencode::find_dict_end(&payload) {
                        let metadata_bytes = &payload[split_idx..];
                        let info: crate::torrent::Info = serde_bencode::from_bytes(metadata_bytes)?;
                        return Ok(info);
                    }
                }
            }
            Some(crate::PeerMessage::Have(_)) => {}
            _ => {}
        }
    }
}

#[derive(serde::Serialize)]
struct MetadataRequest {
    msg_type: u8,
    piece: u32,
}

pub async fn send_metadata_request(stream: &mut TcpStream, extension_id: u8) -> Result<()> {
    let request = MetadataRequest {
        msg_type: 0, // request
        piece: 0,
    };
    let payload = serde_bencode::to_bytes(&request)?;

    let ext_message = crate::PeerMessage::Extended {
        extended_id: extension_id,
        payload,
    };

    ext_message.write_to(stream).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_magnet_link() {
        let link = "magnet:?xt=urn:btih:ad21d9af0b0014e2163b2f293b48232921021703&dn=test.txt&tr=http%3A%2F%2Ftracker.com%2Fannounce";
        let magnet = parse_magnet_link(link).unwrap();

        assert_eq!(magnet.announce, "http://tracker.com/announce");
        assert_eq!(
            hex::encode(magnet.info_hash),
            "ad21d9af0b0014e2163b2f293b48232921021703"
        );
    }

    #[test]
    fn test_extension_handshake_serialization() {
        let mut m_dict = std::collections::BTreeMap::new();
        m_dict.insert("ut_metadata".to_string(), 16u8);

        let handshake = ExtensionHandshake { m: m_dict };
        let encoded = serde_bencode::to_bytes(&handshake).unwrap();

        // Expected: d1:md11:ut_metadatai16eee
        assert_eq!(encoded, b"d1:md11:ut_metadatai16eee");
    }

    #[test]
    fn test_metadata_request_serialization() {
        let request = MetadataRequest {
            msg_type: 0,
            piece: 0,
        };
        let encoded = serde_bencode::to_bytes(&request).unwrap();
        // Expected: d8:msg_typei0e5:piecei0ee
        assert_eq!(encoded, b"d8:msg_typei0e5:piecei0ee");
    }

    #[test]
    fn test_parse_magnet_link_invalid() {
        let link = "magnet:?xt=urn:btih:invalid&tr=http%3A%2F%2Ftracker.com%2Fannounce";
        assert!(parse_magnet_link(link).is_err());
    }
}
