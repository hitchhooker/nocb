# nocb

X11 clipboard manager with compression and blob storage.

## Features

- Content-addressed storage with blake3 hashing
- Automatic compression for large text (zstd)
- Image support (png/jpeg/gif/bmp/webp)
- SQLite database with WAL mode
- 100MB clipboard entry support
- Zero-copy clipboard serving
- Memory zeroization for sensitive data

## Install

```bash
cargo install --path .
```

## Usage

Start daemon:
```bash
nocb daemon &
```

List history:
```bash
nocb list
```

Copy from history (with fzf):
```bash
nocb list | fzf | nocb copy
```

Clear history:
```bash
nocb clear
```

## Configuration

`~/.config/nocb/config.toml` is created on first run:

```toml
cache_dir = "~/.cache/nocb"
max_entries = 10000
max_display_length = 200
trim_whitespace = true
use_primary = false
blacklist = ["KeePassXC"]
```

## Storage

- Database: `~/.cache/nocb/index.db`
- Blobs: `~/.cache/nocb/blobs/`
- Large text (>4KB) is compressed with zstd

## Requirements

- X11 (Linux only)
- Rust 1.70+

## License

MIT
