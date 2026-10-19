# diesel-sqlite-cipher

[![CI](https://github.com/LucaCappelletti94/diesel-sqlite-cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/diesel-sqlite-cipher/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/diesel-sqlite-cipher/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/diesel-sqlite-cipher)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=LucaCappelletti94_diesel-sqlite-cipher&metric=alert_status)](https://sonarcloud.io/project/overview?id=LucaCappelletti94_diesel-sqlite-cipher)
[![Mutation testing](https://img.shields.io/badge/mutation%20testing-cargo--mutants-blue)](https://mutants.rs/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/diesel-sqlite-cipher/blob/main/LICENSE)

Typed `ATTACH ... KEY` for Diesel with `SQLCipher` or `SQLite3` Multiple Ciphers. `RawKey` accepts exactly 32 bytes, stores their textual raw-key encoding without a heap allocation, and zeroizes its storage on drop. Connections without an active page codec are rejected.

```rust
use diesel::{Connection, SqliteConnection};
use diesel_sqlite_cipher::{Error, RawKey, SqliteCipherConnectionExt};

# fn main() -> Result<(), Error> {
let directory = tempfile::tempdir().unwrap();
let path = directory.path().join("shared.db");
let mut connection = SqliteConnection::establish(":memory:").unwrap();
let key = RawKey::from_bytes([0x42; 32]);
match connection.attach_database_with_key(path.to_str().unwrap(), "shared", &key) {
    Ok(()) => {}
    Err(Error::CodecUnavailable) => eprintln!("An active page codec is required"),
    Err(error) => return Err(error),
}
# Ok(())
# }
```

The application selects the linked codec, for example through `libsqlite3-sys/bundled-sqlcipher`. `SQLite3` Multiple Ciphers requires file-backed encrypted databases with a raw-key-capable scheme and its codec `VFS`.

Paths, schema names, and keys are bound as text. Normal query diagnostics redact keys, and authorization remains active. Explicit raw SQLite tracing and authorizer callbacks are privileged, with native SQLite allocations and compiler temporaries outside the zeroization guarantee.

Codec detection uses the public pragma reader API on [Luca's Diesel fork](https://github.com/LucaCappelletti94/diesel/tree/sqlite-public-pragma). Applications must use the same Diesel Git source and branch so their connection types match.
