pub mod ekem;
pub mod ewe;
pub mod svd;
mod utils;
pub use ekem::*;
pub use ewe::*;
pub use svd::*;
use thiserror::Error;
pub use utils::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to load a CRS from a file {0}: {1}")]
    LoadCRSError(String, String),
    #[error("failed to set up FFT for size {0}: {1}")]
    FFTError(usize, String),
    #[error("failed to generate a trusted setup: {0}")]
    GenCRSError(String),
    #[error("failed to generate a singing key: {0}")]
    GenSingingKeyError(String),
    #[error("failed to generate a verifying key: {0}")]
    GenDigestError(String),
    #[error("failed to generate an opening at index {0}: {1}")]
    OpeningError(u64, String),
    #[error("failed to compute a hasher from fp12 to bytes: {0}")]
    HasherFp12ToBytesError(String),
    #[error("failed to compute a symmetric encryption scheme: {0}")]
    SymEncSchemeError(String),
    // #[error("failed to compute a hash-to-field from {0}")]
    // HashToFieldeError(String),
}
