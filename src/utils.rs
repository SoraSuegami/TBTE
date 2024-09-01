use crate::Error;
use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, *};
use sha2::{Digest, Sha256};

pub fn pairing(g1s: &[FsG1], g2s: &[FsG2]) -> Result<blst_fp12, Error> {
    debug_assert_eq!(g1s.len(), g2s.len());
    let mut pairing_blst = Pairing::new(false, &[]);
    for (g1, g2) in g1s.iter().zip(g2s.iter()) {
        let mut g1_affine = blst_p1_affine::default();
        let mut g2_affine = blst_p2_affine::default();
        unsafe {
            blst_p1_to_affine(&mut g1_affine, &g1.0);
            blst_p2_to_affine(&mut g2_affine, &g2.0);
            pairing_blst.raw_aggregate(&g2_affine, &g1_affine);
        }
    }
    Ok(pairing_blst.as_fp12().final_exp())
}

pub trait HasherFp12ToBytes: Send + Sync {
    fn hash(&self, input: &blst_fp12) -> Result<Vec<u8>, Error>;
}

#[derive(Debug, Clone, Default)]
pub struct Sha256HasherFp12ToBytes;

impl HasherFp12ToBytes for Sha256HasherFp12ToBytes {
    fn hash(&self, input: &blst_fp12) -> Result<Vec<u8>, Error> {
        Ok(Sha256::digest(&input.to_bendian()).to_vec())
    }
}

impl Sha256HasherFp12ToBytes {
    pub fn new() -> Self {
        Self::default()
    }
}

pub trait SymEncScheme: Sync {
    fn enc(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>;
    fn dec(&self, key: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error>;
}

#[derive(Debug, Clone, Default)]
pub struct OneTimePadScheme;

impl SymEncScheme for OneTimePadScheme {
    fn enc(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        if key.len() != msg.len() {
            return Err(Error::SymEncSchemeError(
                "Error from OneTimePadSchem: key and msg must have the same length".to_string(),
            ));
        }
        Ok(key.iter().zip(msg.iter()).map(|(k, m)| k ^ m).collect())
    }

    fn dec(&self, key: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
        if key.len() != ct.len() {
            return Err(Error::SymEncSchemeError(
                "Error from OneTimePadScheme: key and ct must have the same length".to_string(),
            ));
        }
        Ok(key.iter().zip(ct.iter()).map(|(k, c)| k ^ c).collect())
    }
}

impl OneTimePadScheme {
    pub fn new() -> Self {
        Self::default()
    }
}
