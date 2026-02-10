use serde_bencode;
use serde_json::{self, Value};

pub fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    if encoded_value.chars().next().unwrap().is_ascii_digit() {
        // let colon_index = encoded_value.find(':').unwrap();
        // let number_string = &encoded_value[..colon_index];
        // let number = number_string.parse::<usize>().unwrap();
        // let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
        // serde_json::Value::String(string.to_string())
        let decoded_value = serde_bencode::from_str(encoded_value)
            .unwrap_or(format!("failed to decode string {}", encoded_value));
        Value::String(decoded_value)
    } else if encoded_value.starts_with("i") {
        if let Some(end) = encoded_value.find("e") {
            let int_str = &encoded_value[1..end];
            let num = int_str.parse::<u64>().unwrap();
            Value::Number(num.into())
        } else {
            panic!("Invalid integer format; Usage: i<base 10 integer>e")
        }
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}
