use diesel::query_builder::{AstPass, QueryFragment, QueryId};
use diesel::query_dsl::{RunQueryDsl, RunQueryDslSupport};
use diesel::result::QueryResult;
use diesel::sql_types::Text;
use diesel::sqlite::pragma::{PerSchema, Pragma, PragmaLiteral, SchemaPragma, WritePragma};
use diesel::sqlite::{Sqlite, SqliteConnection};

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

/// Typed key statements for a SQLite connection with an active page codec.
pub trait SqliteCipherConnectionExt {
    /// Attaches a database with its raw key bound as text.
    ///
    /// # Errors
    ///
    /// [`Error::CodecUnavailable`] or a query failure.
    ///
    /// ```compile_fail
    /// use diesel::{Connection, SqliteConnection};
    /// use diesel_sqlite_cipher::SqliteCipherConnectionExt;
    /// let mut connection = SqliteConnection::establish(":memory:").unwrap();
    /// connection.attach_database_with_key(":memory:", "shared", &[0u8; 32]);
    /// ```
    fn attach_database_with_key(
        &mut self,
        path: &str,
        schema: &str,
        key: &RawKey,
    ) -> Result<(), Error>;
}

impl SqliteCipherConnectionExt for SqliteConnection {
    fn attach_database_with_key(
        &mut self,
        path: &str,
        schema: &str,
        key: &RawKey,
    ) -> Result<(), Error> {
        require_codec(self, None)?;
        AttachDatabaseWithKey { path, schema, key }.execute(self)?;
        Ok(())
    }
}

struct AttachDatabaseWithKey<'a> {
    path: &'a str,
    schema: &'a str,
    key: &'a RawKey,
}

impl QueryId for AttachDatabaseWithKey<'_> {
    type QueryId = ();
    const HAS_STATIC_QUERY_ID: bool = false;
}

impl QueryFragment<Sqlite> for AttachDatabaseWithKey<'_> {
    fn walk_ast<'b>(&'b self, mut output: AstPass<'_, 'b, Sqlite>) -> QueryResult<()> {
        output.unsafe_to_cache_prepared();
        output.push_sql("ATTACH DATABASE ");
        output.push_bind_param::<Text, _>(self.path)?;
        output.push_sql(" AS ");
        output.push_bind_param::<Text, _>(self.schema)?;
        output.push_sql(" KEY ");
        output.push_bind_param::<Text, _>(self.key)?;
        Ok(())
    }
}

impl RunQueryDslSupport for AttachDatabaseWithKey<'_> {}
