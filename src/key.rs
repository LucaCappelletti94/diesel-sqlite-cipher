use std::fmt;

use arrayvec::ArrayString;
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;
use diesel::sqlite::Sqlite;
use zeroize::{Zeroize, Zeroizing};

/// A fixed-size raw codec key with zeroizing storage and redacted diagnostics.
pub struct RawKey {
    literal: Zeroizing<ArrayString<67>>,
}

impl RawKey {
    /// Consumes and erases 32 key bytes, encoding the codec's textual raw-key form.
    ///
    /// ```compile_fail
    /// use diesel_sqlite_cipher::RawKey;
    /// let key = RawKey::from_bytes([0; 64]);
    /// ```
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut literal = Zeroizing::new(ArrayString::new());
        literal.push_str("x'");
        for byte in &bytes {
            literal.push(char::from(HEX[usize::from(byte >> 4)]));
            literal.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        literal.push('\'');
        bytes.zeroize();
        Self { literal }
    }

    pub(crate) fn literal(&self) -> &str {
        self.literal.as_str()
    }
}

impl fmt::Debug for RawKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawKey([REDACTED])")
    }
}

impl ToSql<Text, Sqlite> for RawKey {
    fn to_sql<'b>(&'b self, output: &mut Output<'b, '_, Sqlite>) -> serialize::Result {
        <str as ToSql<Text, Sqlite>>::to_sql(self.literal(), output)
    }
}
