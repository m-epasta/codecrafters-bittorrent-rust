use std::env;

mod decoder;
mod printer;

// Usage: your_program.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decoder::decode_bencoded_value(encoded_value);
        printer::printer(command, decoded_value);
    } else {
        println!("unknown command: {}", args[1])
    }
}
