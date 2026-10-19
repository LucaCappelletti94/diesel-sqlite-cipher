use diesel::deserialize::{self, FromSql};
use diesel::result::Error as QueryError;
use diesel::sql_types::Text;
use diesel::sqlite::pragma::{
    ConnectionPragma, PerConnection, PerSchema, Pragma, ReadPragma, SchemaPragma,
};
use diesel::sqlite::{Sqlite, SqliteConnection};

use crate::Error;

#[derive(diesel::deserialize::FromSqlRow)]
struct CodecReply(bool);

impl FromSql<Text, Sqlite> for CodecReply {
    fn from_sql(
        mut value: <Sqlite as diesel::backend::Backend>::RawValue<'_>,
    ) -> deserialize::Result<Self> {
        Ok(Self(!value.read_text().is_empty()))
    }
}

struct CipherVersion;

impl Pragma for CipherVersion {
    const NAME: &'static str = "cipher_version";
    type Scope = PerConnection;
}

impl ReadPragma for CipherVersion {
    type SqlType = Text;
    type Row = CodecReply;
}

struct CipherName;

impl Pragma for CipherName {
    const NAME: &'static str = "cipher";
    type Scope = PerSchema;
}

impl ReadPragma for CipherName {
    type SqlType = Text;
    type Row = CodecReply;
}

pub(crate) fn require_codec(connection: &mut SqliteConnection) -> Result<(), Error> {
    match CipherVersion::get(connection) {
        Ok(CodecReply(true)) => return Ok(()),
        Ok(CodecReply(false)) | Err(QueryError::NotFound) => {}
        Err(error) => return Err(error.into()),
    }
    match CipherName::get(connection, None) {
        Ok(CodecReply(true)) => Ok(()),
        Ok(CodecReply(false)) | Err(QueryError::NotFound) => Err(Error::CodecUnavailable),
        Err(error) => Err(error.into()),
    }
}
