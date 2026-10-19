use diesel::query_builder::{AstPass, QueryFragment, QueryId};
use diesel::query_dsl::{RunQueryDsl, RunQueryDslSupport};
use diesel::result::QueryResult;
use diesel::sql_types::Text;
use diesel::sqlite::{Sqlite, SqliteConnection};

use crate::codec::require_codec;
use crate::{Error, RawKey};

/// Typed encrypted attachment for a SQLite connection with an active page codec.
pub trait SqliteCipherConnectionExt {
    /// Attaches a database with its raw key bound as text.
    ///
    /// ```
    /// use diesel::{Connection, SqliteConnection};
    /// use diesel_sqlite_cipher::{Error, RawKey, SqliteCipherConnectionExt};
    ///
    /// # fn main() -> Result<(), Error> {
    /// let directory = tempfile::tempdir().unwrap();
    /// let path = directory.path().join("shared.db");
    /// let mut connection = SqliteConnection::establish(":memory:").unwrap();
    /// let key = RawKey::from_bytes([0x42; 32]);
    /// match connection.attach_database_with_key(
    ///     path.to_str().unwrap(),
    ///     "shared",
    ///     &key,
    /// ) {
    ///     Ok(()) => {}
    ///     Err(Error::CodecUnavailable) => eprintln!("An active page codec is required"),
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::CodecUnavailable`] or a query failure.
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
        require_codec(self)?;
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
