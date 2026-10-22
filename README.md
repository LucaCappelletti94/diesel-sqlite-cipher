# diesel-sqlite-cipher

[![CI](https://github.com/connetto-rs/diesel-sqlite-cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/connetto-rs/diesel-sqlite-cipher/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/connetto-rs/diesel-sqlite-cipher/graph/badge.svg)](https://codecov.io/gh/connetto-rs/diesel-sqlite-cipher)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=LucaCappelletti94_diesel-sqlite-cipher&metric=alert_status)](https://sonarcloud.io/project/overview?id=LucaCappelletti94_diesel-sqlite-cipher)
[![Mutation testing](https://img.shields.io/badge/mutation%20testing-cargo--mutants-blue)](https://mutants.rs/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/connetto-rs/diesel-sqlite-cipher/blob/main/LICENSE)

Typed `PRAGMA key` and `ATTACH ... KEY` for Diesel with `SQLCipher` or `SQLite3` Multiple Ciphers. `RawKey` accepts exactly 32 bytes, stores their textual raw-key encoding without a heap allocation, and zeroizes its storage on drop. Both operations reject a connection without an active page codec.

```rust
use diesel::{Connection, SqliteConnection};
use diesel_sqlite_cipher::{Error, Key, RawKey, SqliteCipherConnectionExt};

# fn main() -> Result<(), Error> {
let directory = tempfile::tempdir().unwrap();
let main_path = directory.path().join("main.db");
let shared_path = directory.path().join("shared.db");
let mut connection = SqliteConnection::establish(main_path.to_str().unwrap()).unwrap();
let key = RawKey::from_bytes([0x42; 32]);
match Key(&key).set(&mut connection, None) {
    Ok(()) => connection.attach_database_with_key(shared_path.to_str().unwrap(), "shared", &key)?,
    Err(Error::CodecUnavailable) => eprintln!("An active page codec is required"),
    Err(error) => return Err(error),
}
# Ok(())
# }
```

The application selects the linked codec, for example through `libsqlite3-sys/bundled-sqlcipher`. `SQLite3` Multiple Ciphers requires file-backed databases with a raw-key-capable scheme and its codec `VFS`. Set the key before reading the schema, since assigning `PRAGMA key` does not authenticate an existing file.

Normal Diesel query diagnostics redact keys, and authorization checks remain active. Explicit raw SQLite tracing and authorizer callbacks are privileged and can inspect key-bearing SQL. Zeroization covers controlled Rust key buffers and the shared pragma serializer's SQL buffer, with SQLite allocations and compiler temporaries outside that guarantee.

This crate requires the shared sensitive pragma API on [Luca's Diesel fork](https://github.com/LucaCappelletti94/diesel/tree/upstream/secret-safe-key-diagnostics). Applications must use the same Diesel Git source and branch so their connection types match.
