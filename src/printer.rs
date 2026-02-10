use serde_json;

pub fn printer(cmd: &str, dval: serde_json::Value) {
    if cmd == "decode" {
        dval.to_string();
        println!("{}", dval);
    }
}
