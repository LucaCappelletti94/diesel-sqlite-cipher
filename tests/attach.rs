//! Keyed attachment against ordinary SQLite and native page codecs.

mod common;

use std::path::Path;
use std::sync::Arc;

use diesel::connection::{InstrumentationEvent, SimpleConnection};
use diesel::prelude::*;
use diesel::sqlite::pragma::{ConnectionPragma, PerConnection, Pragma, ReadPragma};
use diesel::sqlite::{AuthorizerContext, AuthorizerDecision};
use diesel_sqlite_cipher::{Error, RawKey, SqliteCipherConnectionExt};
use parking_lot::Mutex;

use common::{codec_available, connect, create_independent_database};

mod attached {
    diesel::table! {
        shared.proof (id) {
            id -> Integer,
            payload -> Text,
        }
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

fn independently_keyed_main(path: &Path) -> SqliteConnection {
    let mut connection = connect(path.to_str().unwrap());
    connection
        .batch_execute(
            "PRAGMA key = \"x'1111111111111111111111111111111111111111111111111111111111111111'\"",
        )
        .unwrap();
    connection
}

#[test]
fn missing_codec_cannot_silently_attach() {
    if codec_available() {
        return;
    }
    let mut connection = connect(":memory:");
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        connection.attach_database_with_key(":memory:", "shared", &key),
        Err(Error::CodecUnavailable)
    ));
    let schemas = DatabaseList::get_all(&mut connection).unwrap();
    assert!(schemas.iter().all(|(_, name, _)| name != "shared"));
}

#[test]
fn explicit_attach_key_reads_a_file_with_a_different_main_key() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source'file.db");
    create_independent_database(&path);
    let mut connection = independently_keyed_main(&directory.path().join("main.db"));
    let key = RawKey::from_bytes([0xab; 32]);
    connection
        .attach_database_with_key(path.to_str().unwrap(), "shared", &key)
        .unwrap();
    let payload = attached::proof::table
        .select(attached::proof::payload)
        .first::<String>(&mut connection)
        .unwrap();
    assert_eq!(payload, "independent raw key");
    let bytes = std::fs::read(path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
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
fn attach_keeps_authorization_active() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attached.db");
    let mut connection = connect(":memory:");
    connection.on_authorize(|event| match event {
        AuthorizerContext::Attach(_) => AuthorizerDecision::Deny,
        _ => AuthorizerDecision::Allow,
    });
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        connection.attach_database_with_key(path.to_str().unwrap(), "shared", &key),
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
        connection.attach_database_with_key(":memory:", "shared", &key),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
}

#[test]
fn ignored_codec_probes_cannot_silently_attach() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unverified.db");
    let mut connection = connect(":memory:");
    connection.on_authorize(|event| match event {
        AuthorizerContext::Pragma(pragma)
            if matches!(pragma.name, Some("cipher_version" | "cipher")) =>
        {
            AuthorizerDecision::Ignore
        }
        _ => AuthorizerDecision::Allow,
    });
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        connection.attach_database_with_key(path.to_str().unwrap(), "shared", &key),
        Err(Error::CodecUnavailable)
    ));
    assert!(!path.exists());
    assert!(
        DatabaseList::get_all(&mut connection)
            .unwrap()
            .iter()
            .all(|(_, name, _)| name != "shared")
    );
}

#[test]
fn fallback_probe_authorization_errors_remain_query_errors() {
    let mut connection = connect(":memory:");
    connection.on_authorize(|event| match event {
        AuthorizerContext::Pragma(pragma) if pragma.name == Some("cipher_version") => {
            AuthorizerDecision::Ignore
        }
        AuthorizerContext::Pragma(pragma) if pragma.name == Some("cipher") => {
            AuthorizerDecision::Deny
        }
        _ => AuthorizerDecision::Allow,
    });
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        connection.attach_database_with_key(":memory:", "shared", &key),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
}

#[test]
fn successful_and_failed_attaches_keep_secrets_out_of_diagnostics() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let mut connection = independently_keyed_main(&directory.path().join("main.db"));
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
