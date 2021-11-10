use rslib::parser::ParsedObj;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            if let Ok(mut tx) = ParsedObj::from_bytes(data) {
                if tx.read(data).is_err() {
                    return;
                }
                if ParsedObj::validate(&mut tx).is_err() {
                    return;
                }
            };
        });
    }
}
