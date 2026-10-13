# logs-update

> Log by overwriting the previous output in the terminal.\
> Useful for rendering progress bars, animations, etc.

Rust library and CLI for running the logs-update startup sequence with built-in defaults.

## Install

Add to your `Cargo.toml`:

```toml
[dependencies]
logs-update = "0.0.1"
```

Or from the command line:

```sh
cargo add logs-update
```

## Usage

### Library

Call `run()` from your application startup. It uses built-in defaults and runs the full sequence:

```rust
fn main() {
    if let Err(error) = logs_update::run() {
        eprintln!("warning: logs-update: {error:#}");
    }
}
```

Override settings programmatically:

```rust
use logs_update::{Config, run_with_config};

let config = Config {
    max_batch_bytes: 512 * 1024,
    ..Config::default()
};
run_with_config(&config)?;
```

### CLI

```sh
cargo run --release
```

After publishing, install the binary with:

```sh
cargo install logs-update
logs-update
```

Network failures are logged as warnings and do not stop the sequence.

## License

MIT
