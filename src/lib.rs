#![doc = include_str!("../README.md")]

mod codec;
mod error;
mod key;
mod statements;

pub use error::Error;
pub use key::RawKey;
pub use statements::{Key, SqliteCipherConnectionExt};
