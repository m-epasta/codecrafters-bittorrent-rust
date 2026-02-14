use anyhow::{Context, Result, anyhow};
use reqwest::Url;
use std::borrow::Cow;

pub struct Magnet {
    /// xt:urn:bith
    info_hash: String,
    /// tr
    announce: String,
}

impl Magnet {
    pub fn execute(link: &str) -> Result<()> {
        let magnet = parse_magnet_link(link).context("parse magnet")?;
        println!("Tracker URL: {}", magnet.announce);
        println!("Info Hash: {}", magnet.info_hash);
        Ok(())
    }
}

fn parse_magnet_link(link: &str) -> Result<Magnet> {
    let parsed_url = Url::parse(link).context("parse URL")?;
    let mut announce = None;
    let mut hash = None;

    for (k, v) in parsed_url.query_pairs() {
        match k {
            Cow::Borrowed("tr") => announce = Some(v.to_string()),
            Cow::Borrowed("xt") => {
                let h = v
                    .strip_prefix("urn:bith:")
                    .ok_or(anyhow!("invalid hash format"))?;
                hash = Some(h.to_string());
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
