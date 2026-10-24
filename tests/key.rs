//! Raw key assignment against ordinary SQLite and native page codecs.

mod common;

use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sql_types::Text;
use diesel::sqlite::{AuthorizerContext, AuthorizerDecision};
use diesel_sqlite_cipher::{Error, Key, RawKey};

use common::{codec_available, connect, create_independent_database, instrumentation_log, proof};

mod attached {
    diesel::table! {
        auxiliary.proof (id) {
            id -> Integer,
            payload -> Text,
        }
    }
}

#[test]
fn missing_codec_cannot_silently_key() {
    if codec_available() {
        return;
    }
    let mut connection = connect(":memory:");
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        Key(&key).set(&mut connection, None),
        Err(Error::CodecUnavailable)
    ));
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
}

#[test]
fn schema_key_assignment_preserves_the_main_database_key() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let main_path = directory.path().join("main.db");
    let attached_path = directory.path().join("schema'file.db");
    create_independent_database(&main_path);
    let main_key = RawKey::from_bytes([0xab; 32]);
    let attached_key = RawKey::from_bytes([0xcd; 32]);
    {
        let mut connection = connect(main_path.to_str().unwrap());
        Key(&main_key).set(&mut connection, None).unwrap();
        assert_eq!(
            proof::table
                .select(proof::payload)
                .first::<String>(&mut connection)
                .unwrap(),
            "independent raw key"
        );
        diesel::sql_query("ATTACH DATABASE ? AS ? KEY ''")
            .bind::<Text, _>(attached_path.to_str().unwrap())
            .bind::<Text, _>("auxiliary")
            .execute(&mut connection)
            .unwrap();
        Key(&attached_key)
            .set(&mut connection, Some("auxiliary"))
            .unwrap();
        connection
            .batch_execute(
                "CREATE TABLE auxiliary.proof (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
            )
            .unwrap();
        diesel::insert_into(attached::proof::table)
            .values((
                attached::proof::id.eq(7),
                attached::proof::payload.eq("schema-specific key"),
            ))
            .execute(&mut connection)
            .unwrap();
    }
    let mut attached_connection = connect(attached_path.to_str().unwrap());
    Key(&attached_key)
        .set(&mut attached_connection, None)
        .unwrap();
    assert_eq!(
        proof::table
            .select(proof::payload)
            .first::<String>(&mut attached_connection)
            .unwrap(),
        "schema-specific key"
    );
    let mut main_connection = connect(main_path.to_str().unwrap());
    Key(&main_key).set(&mut main_connection, None).unwrap();
    assert_eq!(
        proof::table
            .select(proof::payload)
            .first::<String>(&mut main_connection)
            .unwrap(),
        "independent raw key"
    );
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
fn key_keeps_authorization_active() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("main.db");
    let mut connection = connect(path.to_str().unwrap());
    connection.on_authorize(|event| match event {
        AuthorizerContext::Pragma(pragma) if pragma.name == Some("key") => AuthorizerDecision::Deny,
        _ => AuthorizerDecision::Allow,
    });
    let key = RawKey::from_bytes([0xab; 32]);
    assert!(matches!(
        Key(&key).set(&mut connection, None),
        Err(Error::Query(diesel::result::Error::DatabaseError(_, _)))
    ));
}

#[test]
fn successful_and_failed_key_assignments_keep_secrets_out_of_diagnostics() {
    if !codec_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    create_independent_database(&path);
    let mut connection = connect(path.to_str().unwrap());
    let (log, instrumentation) = instrumentation_log();
    connection.set_instrumentation(instrumentation);
    let correct = RawKey::from_bytes([0xab; 32]);
    Key(&correct).set(&mut connection, None).unwrap();
    assert_eq!(
        proof::table
            .select(proof::payload)
            .first::<String>(&mut connection)
            .unwrap(),
        "independent raw key"
    );
    let error = Key(&correct)
        .set(&mut connection, Some("missing_schema"))
        .unwrap_err();
    assert!(matches!(error, Error::Query(_)));
    log.lock().push(format!("{error} {error:?}"));
    assert!(
        log.lock()
            .iter()
            .all(|message| !message.contains("abababababababab"))
    );
}
