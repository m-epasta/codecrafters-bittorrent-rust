#![cfg(never)]
#![allow(unused)]

use serde_json::{self, Map, Value};

pub fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, usize) {
    if encoded_value.chars().next().unwrap().is_ascii_digit() {
        decode_string(encoded_value)
    } else if encoded_value.starts_with("i")
        && (encoded_value.chars().nth(1).unwrap().is_ascii_digit()
            || encoded_value.chars().nth(1).unwrap() == '-')
    {
        decode_integer(encoded_value)
    } else if encoded_value.starts_with("l") {
        decode_list(encoded_value)
    } else if encoded_value.starts_with("d") {
        decode_dict(encoded_value)
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

fn decode_string(encoded_value: &str) -> (Value, usize) {
    let colon_index = encoded_value.find(':').unwrap();
    let number_string = &encoded_value[..colon_index];
    let number = number_string.parse::<usize>().unwrap();
    let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
    let total_len = colon_index + 1 + number;
    (Value::String(string.to_string()), total_len)
}

fn decode_integer(encoded_value: &str) -> (Value, usize) {
    if let Some(end_index) = encoded_value.find('e') {
        let int_str = &encoded_value[1..end_index];
        let num = int_str.parse::<i64>().unwrap(); // i64 for base 10 integer
        (Value::Number(num.into()), end_index + 1)
    } else {
        panic!("Invalid integer format; Usage: i<base 10 integer>e")
    }
}

fn decode_list(encoded_value: &str) -> (Value, usize) {
    let mut l = Vec::new();
    let mut idx: usize = 1;
    while idx < encoded_value.len() {
        if encoded_value.as_bytes()[idx] == b'e' {
            break;
        }

        let (decoded_value, consumed) = decode_bencoded_value(&encoded_value[idx..]);
        l.push(decoded_value);
        idx += consumed;
    }

    (Value::Array(l), idx + 1) // +1 so we consume the trailing `e`
}

fn decode_dict(encoded_value: &str) -> (Value, usize) {
    let mut dict = Map::new();
    let mut idx: usize = 1;

    while idx < encoded_value.len() {
        if encoded_value.as_bytes()[idx] == b'e' {
            idx += 1;
            break;
        }

        let (k, c) = decode_string(&encoded_value[idx..]);
        idx += c;
        let k_str = k.as_str().unwrap();

        let (v, consumed) = decode_bencoded_value(&encoded_value[idx..]);
        dict.insert(k_str.to_string(), v);
        idx += consumed;
    }

    (Value::Object(dict), idx)
}
