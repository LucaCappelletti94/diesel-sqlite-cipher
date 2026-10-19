/// Failure to apply a codec key statement.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No active page codec answered its capability pragma.
    #[error("no active SQLCipher or SQLite3 Multiple Ciphers codec")]
    CodecUnavailable,
    /// The codec probe or key statement failed.
    #[error(transparent)]
    Query(#[from] diesel::result::Error),
}
