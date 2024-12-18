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
make rust_fuzz
```

### Debugging

If there are crashes reported, debug the application with the generated input to figure out where the problem is.
The supported debuggers are: _lldb_, _rust-gdb_, _gdb_, _rust-lldb_. By default _rust-lldb_ is used:

```bash
cd hfuzz-parser
cargo hfuzz run-debug transaction hfuzz_workspace/*/*.fuzz

```

To opt to use _gdb_ instead of `lldb`, you can configure it before running the debugger with:

```bash
export HFUZZ_DEBUGGER="rust-gdb"

```

This will deploy a **gdb** console with a backtrace with the first crash

_note_: There could be more than one _.fuzz_ file.
