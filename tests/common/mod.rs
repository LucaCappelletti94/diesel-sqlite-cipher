use std::path::Path;

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sqlite::pragma::{ConnectionPragma, PerConnection, Pragma, PragmaLiteral, WritePragma};
use diesel_sqlite_cipher::{Error, RawKey, SqliteCipherConnectionExt};

diesel::table! {
    proof (id) {
        id -> Integer,
        payload -> Text,
    }
}

struct Cipher;

impl Pragma for Cipher {
    const NAME: &'static str = "cipher";
    type Scope = PerConnection;
}

impl WritePragma for Cipher {
    fn value(&self) -> PragmaLiteral {
        PragmaLiteral::Keyword("sqlcipher")
    }
}

struct Legacy;

impl Pragma for Legacy {
    const NAME: &'static str = "legacy";
    type Scope = PerConnection;
}

impl WritePragma for Legacy {
    fn value(&self) -> PragmaLiteral {
        4.into()
    }
}

pub(super) fn connect(path: &str) -> SqliteConnection {
    let mut connection = SqliteConnection::establish(path).unwrap();
    Cipher.set(&mut connection).unwrap();
    Legacy.set(&mut connection).unwrap();
    connection
}

pub(super) fn codec_available() -> bool {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probe.db");
    let mut connection = connect(":memory:");
    let key = RawKey::from_bytes([0xab; 32]);
    let result = connection.attach_database_with_key(path.to_str().unwrap(), "probe", &key);
    let available = match result {
        Ok(()) => true,
        Err(Error::CodecUnavailable) => false,
        Err(error) => panic!("codec probe failed with {error}"),
    };
    if let Ok(expected) = std::env::var("DIESEL_SQLITE_CIPHER_TEST_CODEC") {
        match expected.as_str() {
            "none" => assert!(!available),
            "sqlcipher" | "sqlite3mc" => assert!(available),
            _ => panic!("unknown expected codec"),
        }
    }
    available
}

pub(super) fn create_independent_database(path: &Path) {
    let mut connection = connect(path.to_str().unwrap());
    connection
        .batch_execute(
            "PRAGMA key = \"x'abababababababababababababababababababababababababababababababab'\"",
        )
        .unwrap();
    connection
        .batch_execute("CREATE TABLE proof (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        .unwrap();
    diesel::insert_into(proof::table)
        .values((proof::id.eq(1), proof::payload.eq("independent raw key")))
        .execute(&mut connection)
        .unwrap();
}
