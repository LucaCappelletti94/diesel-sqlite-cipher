#![doc = include_str!("../README.md")]

mod attach;
mod codec;
mod error;
mod key;

pub use attach::SqliteCipherConnectionExt;
pub use error::Error;
pub use key::RawKey;

#[cfg(doctest)]
mod compile_fail_tests {
    //! ```compile_fail
    //! use diesel::{Connection, SqliteConnection};
    //! use diesel_sqlite_cipher::SqliteCipherConnectionExt;
    //! let mut connection = SqliteConnection::establish(":memory:").unwrap();
    //! connection.attach_database_with_key(":memory:", "shared", &[0u8; 32]);
    //! ```
}
