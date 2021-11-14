# Fuzzing

This crate uses [honggfuzz-rs](https://crates.io/crates/honggfuzz), a wrapper around the `Honggfuzz` fuzzer developed by Google.

### Set-up

If you are using Ubuntu, install the following system dependencies:

```bash
sudo apt install build-essential binutils-dev libunwind-dev libblocksruntime-dev
```

Then the `honggfuzz-rs` CLI application:

```bash
cargo install honggfuzz
```

### Running

Start fuzzing a desirable target:

```bash
cd hfuzz-parser && cargo hfuzz run transaction
```

### Debugging

If there are crashes reported, debug the application with the generated input to figure out where the problem is.
The supported debuggers are: *lldb*, *rust-gdb*, *gdb*, *rust-lldb*. By default *rust-lldb* is used  but,
this can be changed using the __HFUZZ_DEBUGGER__ env variable:

```bash
export HFUZZ_DEBUGGER="rust-gdb"
cd hfuzz-parser
HFUZZ_BUILD_ARGS="--features baking" cargo hfuzz run-debug transaction hfuzz_workspace/transaction/*.fuzz
```

*note*: There could be more than one *.fuzz* file.
