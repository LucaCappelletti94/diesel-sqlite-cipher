//! Key statements against ordinary SQLite and native page codecs.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

use diesel::connection::{InstrumentationEvent, SimpleConnection};
use diesel::prelude::*;
use diesel::sqlite::pragma::{
    ConnectionPragma, PerConnection, Pragma, PragmaLiteral, ReadPragma, WritePragma,
};
use diesel::sqlite::{AuthorizerContext, AuthorizerDecision};
use diesel_sqlite_cipher::{Error, Key, RawKey, SqliteCipherConnectionExt};

mod source {
    diesel::table! {
        proof (id) {
            id -> Integer,
            payload -> Text,
        }
    }
}

use source::proof;

mod attached {
    diesel::table! {
        shared.proof (id) {
            id -> Integer,
            payload -> Text,
        }
    }
}

struct Cipher;

impl Pragma for Cipher {
    const NAME: &'static str = "cipher";
    type Scope = PerConnection;
}

impl WritePragma for Cipher {
    fn value(&self) -> PragmaLiteral<'_> {
        PragmaLiteral::Text("sqlcipher")
    }
}

struct Legacy;

impl Pragma for Legacy {
    const NAME: &'static str = "legacy";
    type Scope = PerConnection;
}

impl WritePragma for Legacy {
    fn value(&self) -> PragmaLiteral<'_> {
        4.into()
    }
}

struct DatabaseList;

impl Pragma for DatabaseList {
    const NAME: &'static str = "database_list";
    type Scope = PerConnection;
}

impl ReadPragma for DatabaseList {
    type SqlType = (
        diesel::sql_types::Integer,
        diesel::sql_types::Text,
        diesel::sql_types::Text,
    );
    type Row = (i32, String, String);
}

fn connect(path: &str) -> SqliteConnection {
    let mut connection = SqliteConnection::establish(path).unwrap();
    Cipher.set(&mut connection).unwrap();
    Legacy.set(&mut connection).unwrap();
    connection
}

fn codec_available() -> bool {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probe.db");
    let mut connection = connect(path.to_str().unwrap());
    let key = RawKey::from_bytes([0xab; 32]);
    let result = Key(&key).set(&mut connection, None);
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

fn create_independent_database(path: &Path) {
    let mut connection = connect(path.to_str().unwrap());
    connection
        .batch_execute_sensitive(
            c"PRAGMA key = \"x'abababababababababababababababababababababababababababababababab'\"",
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

#[test]
fn missing_codec_cannot_silently_key_or_attach() {
    if codec_available() {
        return;
    }
    let mut connection = connect(":memory:");
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        Key(&key).set(&mut connection, None),
        Err(Error::CodecUnavailable)
    ));
    assert!(matches!(
        connection.attach_database_with_key(":memory:", "shared", &key),
        Err(Error::CodecUnavailable)
    ));
    let schemas = DatabaseList::get_all(&mut connection).unwrap();
    assert!(schemas.iter().all(|(_, name, _)| name != "shared"));
}

#[test]
fn key_reads_a_file_created_by_an_independent_raw_statement() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let key = RawKey::from_bytes([0xab; 32]);
    let mut connection = connect(path.to_str().unwrap());
    Key(&key).set(&mut connection, None).unwrap();
    let payload = proof::table
        .select(proof::payload)
        .first::<String>(&mut connection)
        .unwrap();
    assert_eq!(payload, "independent raw key");
    let bytes = std::fs::read(path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
}

#[test]
fn wrong_main_key_cannot_read_an_existing_file() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let mut connection = connect(path.to_str().unwrap());
    let wrong = RawKey::from_bytes([0xcd; 32]);
    Key(&wrong).set(&mut connection, None).unwrap();
    assert!(matches!(
        proof::table.count().get_result::<i64>(&mut connection),
        Err(diesel::result::Error::DatabaseError(_, _))
    ));
}

#[test]
fn explicit_attach_key_reads_a_file_with_a_different_main_key() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source'file.db");
    create_independent_database(&path);
    let main_path = directory.path().join("main.db");
    let mut connection = connect(main_path.to_str().unwrap());
    let main = RawKey::from_bytes([0x11; 32]);
    Key(&main).set(&mut connection, None).unwrap();
    let attached = RawKey::from_bytes([0xab; 32]);
    connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &attached)
        .unwrap();
    let payload = attached::proof::table
        .select(attached::proof::payload)
        .first::<String>(&mut connection)
        .unwrap();
    assert_eq!(payload, "independent raw key");
}

#[test]
fn wrong_attach_key_leaves_no_schema_and_allows_a_correct_retry() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let mut connection = connect(":memory:");
    let wrong = RawKey::from_bytes([0xcd; 32]);
    assert!(matches!(
        connection.attach_database_with_key(path.to_str().unwrap(), "shared", &wrong),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
    let schemas = DatabaseList::get_all(&mut connection).unwrap();
    assert!(schemas.iter().all(|(_, name, _)| name != "shared"));
    let correct = RawKey::from_bytes([0xab; 32]);
    connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &correct)
        .unwrap();
    assert_eq!(
        attached::proof::table
            .select(attached::proof::payload)
            .first::<String>(&mut connection)
            .unwrap(),
        "independent raw key"
    );
}

#[test]
fn schema_names_are_values_rather_than_sql() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attached.db");
    let mut connection = connect(":memory:");
    let key = RawKey::from_bytes([0xab; 32]);
    let schema = "shared'\"; DETACH main; --";
    connection
        .attach_database_with_key(path.to_str().unwrap(), schema, &key)
        .unwrap();
    let schemas = DatabaseList::get_all(&mut connection).unwrap();
    assert!(schemas.iter().any(|(_, name, _)| name == schema));
    assert!(schemas.iter().any(|(_, name, _)| name == "main"));
}

#[test]
fn key_and_attach_keep_authorization_active() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let main_path = directory.path().join("main.db");
    let attached_path = directory.path().join("attached.db");
    let mut connection = connect(main_path.to_str().unwrap());
    connection.on_authorize(|event| match event {
        AuthorizerContext::Pragma(pragma) if pragma.name == Some("key") => AuthorizerDecision::Deny,
        AuthorizerContext::Attach(_) => AuthorizerDecision::Deny,
        _ => AuthorizerDecision::Allow,
    });
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        Key(&key).set(&mut connection, None),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
    assert!(matches!(
        connection.attach_database_with_key(attached_path.to_str().unwrap(), "shared", &key),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
    assert!(
        DatabaseList::get_all(&mut connection)
            .unwrap()
            .iter()
            .all(|(_, name, _)| name != "shared")
    );
}

#[test]
fn codec_probe_authorization_errors_remain_query_errors() {
    let mut connection = connect(":memory:");
    connection.on_authorize(|_| AuthorizerDecision::Deny);
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        Key(&key).set(&mut connection, None),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
}

#[test]
fn successful_and_failed_key_operations_keep_secrets_out_of_diagnostics() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let main_path = directory.path().join("main.db");
    let mut connection = connect(main_path.to_str().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&log);
    connection.set_instrumentation(move |event: InstrumentationEvent<'_>| {
        let mut output = output.lock();
        output.push(format!("{event:?}"));
        match event {
            InstrumentationEvent::StartQuery { query, .. }
            | InstrumentationEvent::FinishQuery { query, .. } => {
                output.push(format!("{query}"));
                output.push(format!("{query:?}"));
            }
            _ => {}
        }
    });
    let correct = RawKey::from_bytes([0xab; 32]);
    Key(&correct).set(&mut connection, None).unwrap();
    let error = Key(&correct)
        .set(&mut connection, Some("missing_schema"))
        .unwrap_err();
    assert!(matches!(error, Error::Query(_)));
    log.lock().push(format!("{error} {error:?}"));
    let wrong = RawKey::from_bytes([0xcd; 32]);
    let error = connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &wrong)
        .unwrap_err();
    log.lock().push(format!("{error} {error:?}"));
    connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &correct)
        .unwrap();
    assert_eq!(
        attached::proof::table
            .select(attached::proof::payload)
            .first::<String>(&mut connection)
            .unwrap(),
        "independent raw key"
    );
    let error = connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &correct)
        .unwrap_err();
    log.lock().push(format!("{error} {error:?}"));
    assert!(log.lock().iter().all(|message| {
        !message.contains("abababababababab") && !message.contains("cdcdcdcdcdcdcdcd")
    }));
}
