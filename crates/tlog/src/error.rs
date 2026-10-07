use std::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The tile store failed.
    Store(String),
    /// A tile or entry bundle the log needs isn't there, or doesn't parse.
    Corrupt(String),
    /// An earlier append failed midway; reopen the log from its store.
    Broken,
    EntryTooLarge(usize),
    /// A request for an index or size the log doesn't have.
    OutOfRange(String),
    /// A proof didn't verify.
    BadProof(&'static str),
    /// A signed note is malformed or has no signature we trust.
    BadNote(String),
    Sign(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "tile store: {e}"),
            Self::Corrupt(e) => write!(f, "log store is corrupt: {e}"),
            Self::Broken => f.write_str("log is broken after a failed append; reopen it"),
            Self::EntryTooLarge(n) => write!(f, "entry of {n} bytes exceeds 65535"),
            Self::OutOfRange(e) => write!(f, "out of range: {e}"),
            Self::BadProof(e) => write!(f, "proof does not verify: {e}"),
            Self::BadNote(e) => write!(f, "bad signed note: {e}"),
            Self::Sign(e) => write!(f, "signing: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
