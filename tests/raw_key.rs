//! Raw-key binding and diagnostic boundaries.

use std::fmt::{self, Write as _};

use diesel::prelude::*;
use diesel::sql_types::Text;
use diesel_sqlite_cipher::RawKey;

#[test]
fn raw_key_text_binding_encodes_every_byte() {
    #[derive(diesel::QueryableByName)]
    struct EncodedKey {
        #[diesel(sql_type = Text)]
        encoded: String,
    }

    let mut connection = SqliteConnection::establish(":memory:").unwrap();
    let mut expected = String::with_capacity(67);
    for start in (0..256).step_by(32) {
        let bytes: [u8; 32] = std::array::from_fn(|offset| u8::try_from(start + offset).unwrap());
        let key = RawKey::from_bytes(bytes);
        expected.clear();
        expected.push_str("x'");
        for byte in bytes {
            write!(&mut expected, "{byte:02x}").unwrap();
        }
        expected.push('\'');
        let actual = diesel::sql_query("SELECT ? AS encoded")
            .bind::<Text, _>(&key)
            .get_result::<EncodedKey>(&mut connection)
            .unwrap();
        assert_eq!(actual.encoded, expected);
    }
}

#[test]
fn debug_does_not_disclose_the_raw_key() {
    let key = RawKey::from_bytes([0xab; 32]);
    let diagnostics = format!("{key:?} {key:#?}");
    assert!(!diagnostics.contains("abababab"));
}

#[test]
fn debug_propagates_formatter_failure() {
    struct RejectWrite;

    impl fmt::Write for RejectWrite {
        fn write_str(&mut self, _value: &str) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    let key = RawKey::from_bytes([0xab; 32]);
    assert!(write!(&mut RejectWrite, "{key:?}").is_err());
}
