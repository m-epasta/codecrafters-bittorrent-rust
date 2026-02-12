use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Bencode {
    Integer(i64),
    List(Vec<Bencode>),
    Dictionary(std::collections::BTreeMap<String, Bencode>),
    String(#[serde(with = "serde_bytes")] Vec<u8>),
}

impl Bencode {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Bencode::String(bytes) => {
                serde_json::Value::String(String::from_utf8_lossy(bytes).to_string())
            }
            Bencode::Integer(int) => serde_json::Value::Number((*int).into()),
            Bencode::List(list) => {
                serde_json::Value::Array(list.iter().map(|v| v.to_json()).collect())
            }
            Bencode::Dictionary(dict) => {
                let mut map = serde_json::Map::new();
                for (k, v) in dict {
                    map.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(map)
            }
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<Bencode, serde_bencode::Error> {
    serde_bencode::from_bytes(bytes)
}
