use diesel::sqlite::SqliteConnection;
use diesel::sqlite::pragma::{PerSchema, Pragma, PragmaLiteral, SchemaPragma, WritePragma};

use crate::codec::require_codec;
use crate::{Error, RawKey};

/// A codec-checked raw key assignment.
#[derive(Debug)]
pub struct Key<'a>(
    /// The raw key to assign.
    pub &'a RawKey,
);

impl Key<'_> {
    /// Sets a schema's raw key before its first read.
    ///
    /// # Errors
    ///
    /// [`Error::CodecUnavailable`] or a query failure.
    pub fn set(
        &self,
        connection: &mut SqliteConnection,
        schema: Option<&str>,
    ) -> Result<(), Error> {
        require_codec(connection, schema)?;
        KeyPragma(self.0).set(connection, schema)?;
        Ok(())
    }
}

struct KeyPragma<'a>(&'a RawKey);

impl Pragma for KeyPragma<'_> {
    const NAME: &'static str = "key";
    type Scope = PerSchema;
}

impl WritePragma for KeyPragma<'_> {
    fn value(&self) -> PragmaLiteral<'_> {
        PragmaLiteral::SensitiveText(self.0.literal())
    }
}
