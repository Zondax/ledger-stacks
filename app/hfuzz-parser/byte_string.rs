use rslib::parser::ByteString;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            if let Ok(mut tx) = ByteString::from_bytes(data) {};
        });
    }
}
