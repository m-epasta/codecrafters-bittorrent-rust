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

pub fn find_dict_end(bytes: &[u8]) -> Option<usize> {
    let mut depth = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'd' | b'l' => {
                depth += 1;
                i += 1;
            }
            b'i' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'e' {
                    i += 1;
                }
                i += 1;
            }
            b'e' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'0'..=b'9' => {
                let mut len_str = String::new();
                while i < bytes.len() && bytes[i] != b':' {
                    len_str.push(bytes[i] as char);
                    i += 1;
                }
                i += 1;
                if let Ok(len) = len_str.parse::<usize>() {
                    i += len;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_find_dict_end_simple() {
        let data = b"d3:foo3:bare";
        assert_eq!(find_dict_end(data), Some(12));
    }

    #[test]
    fn test_find_dict_end_nested() {
        let data = b"d1:md11:ut_metadatai16eee";
        assert_eq!(find_dict_end(data), Some(25));
    }

    #[test]
    fn test_find_dict_end_with_binary() {
        let mut data = b"d1:v4:infoe".to_vec();
        data.extend_from_slice(b"d1:ai1ee");
        assert_eq!(find_dict_end(&data), Some(11));
    }

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
