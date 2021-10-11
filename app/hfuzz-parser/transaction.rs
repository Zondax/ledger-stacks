use rslib::parser::Transaction;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            if let Ok(mut tx) = Transaction::from_bytes(data) {
                let first = tx.clone();

                if tx.read(data).is_err() {
                    return;
                }
                assert_eq!(tx, first);
                if Transaction::validate(&mut tx).is_err() {
                    return;
                }
            };
        });
    }
}
