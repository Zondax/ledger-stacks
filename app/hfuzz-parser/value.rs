use rslib::parser::Value;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            let mut value = if let Ok(op) = Value::from_bytes(data) {
                op
            } else {
                return;
            };
        });
    }
}
