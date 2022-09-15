## Install dependencies
for , example for Debian base distributions:
```bash
sudo apt install build-essential binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
```
Install honggfuzz commands to build with instrumentation and fuzz
```bash
# installs hfuzz and honggfuzz subcommands in cargo
cargo install honggfuzz
```
## Run the fuzzer:
to run the fuzzer for the transaction target, which allows us to fuzz
the parser.
```bash
RUSTFLAGS="-Znew-llvm-pass-manager=no" cargo hfuzz run transaction
```
