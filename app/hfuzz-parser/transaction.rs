use rslib::parser::Transaction;

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            let mut transaction = if let Ok(tx) = Transaction::from_bytes(data) {
                tx
            } else {
                return;
            };
            let first = transaction.clone();

            if transaction.read(data).is_err() {
                return;
            }

            assert_eq!(transaction, first);

            match Transaction::validate(&mut transaction) {
                Ok(_) => {}
                _ => return,
            }
        });
    }
}
