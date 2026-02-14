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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_decode_integer() {
        let bytes = b"i42e";
        let decoded = decode(bytes).unwrap();
        match decoded {
            Bencode::Integer(n) => assert_eq!(n, 42),
            _ => panic!("Expected Integer, got {:?}", decoded),
        }
        assert_eq!(decoded.to_json(), json!(42));
    }

    #[test]
    fn test_decode_string() {
        let bytes = b"5:hello";
        let decoded = decode(bytes).unwrap();
        match &decoded {
            Bencode::String(s) => assert_eq!(s, b"hello"),
            _ => panic!("Expected String, got {:?}", decoded),
        }
        assert_eq!(decoded.to_json(), json!("hello"));
    }

    #[test]
    fn test_decode_list() {
        let bytes = b"li42e5:helloe";
        let decoded = decode(bytes).unwrap();
        match &decoded {
            Bencode::List(l) => {
                assert_eq!(l.len(), 2);
                match &l[0] {
                    Bencode::Integer(n) => assert_eq!(*n, 42),
                    _ => panic!("Expected Integer at index 0"),
                }
                match &l[1] {
                    Bencode::String(s) => assert_eq!(s, b"hello"),
                    _ => panic!("Expected String at index 1"),
                }
            }
            _ => panic!("Expected List, got {:?}", decoded),
        }
        assert_eq!(decoded.to_json(), json!([42, "hello"]));
    }

    #[test]
    fn test_decode_dictionary() {
        let bytes = b"d3:foo3:bare";
        let decoded = decode(bytes).unwrap();
        match &decoded {
            Bencode::Dictionary(d) => {
                assert_eq!(d.len(), 1);
                match d.get("foo").unwrap() {
                    Bencode::String(s) => assert_eq!(s, b"bar"),
                    _ => panic!("Expected String for key 'foo'"),
                }
            }
            _ => panic!("Expected Dictionary, got {:?}", decoded),
        }
        assert_eq!(decoded.to_json(), json!({"foo": "bar"}));
    }
}
