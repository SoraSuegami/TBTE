pub mod tbte;
mod utils;
pub use tbte::*;
use thiserror::Error;
pub use utils::*;
pub mod shamir;
pub use shamir::*;

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
    #[error("{0} pds is not enough for t+1={1}")]
    NotEnoughPdsError(u64, u64),
    #[error("the expected eid {0} does not match the eid {1} in the ciphertext")]
    EidMismatchError(u64, u64),
    // #[error("failed to compute a hasher from fp12 to bytes: {0}")]
    // HasherFp12ToBytesError(String),
    // #[error("failed to compute a symmetric encryption scheme: {0}")]
    // SymEncSchemeError(String),
    // // #[error("failed to compute a hash-to-field from {0}")]
    // HashToFieldeError(String),
}
