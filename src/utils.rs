use crate::Error;
use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use kzg::Fr;
use rand::Rng;
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

pub fn lagrange_basises(domain: &[FsFr], target: &FsFr) -> Vec<FsFr> {
    if let Some(idx) = domain.into_iter().position(|x| x == target) {
        let mut out = vec![FsFr::zero(); domain.len()];
        out[idx] = FsFr::one();
        return out;
    }
    let len = domain.len();
    let mut all_prod = FsFr::one();
    for x in domain.into_iter() {
        all_prod = all_prod.mul(&target.sub(&x));
    }
    let mut out = vec![];
    for idx in 0..len {
        let numerator = all_prod.div(&target.sub(&domain[idx])).unwrap();
        let mut denominator = FsFr::one();
        for j in 0..len {
            if idx == j {
                continue;
            }
            denominator = denominator.mul(&domain[idx].sub(&domain[j]));
        }
        out.push(numerator.div(&denominator).unwrap());
    }
    out
}

pub trait HasherFp12ToBytes: Send + Sync {
    fn hash(&self, input: &blst_fp12) -> Result<[u8; 32], Error>;
}

#[derive(Debug, Clone, Default)]
pub struct Sha256HasherFp12ToBytes;

impl HasherFp12ToBytes for Sha256HasherFp12ToBytes {
    fn hash(&self, input: &blst_fp12) -> Result<[u8; 32], Error> {
        Ok(Sha256::digest(&input.to_bendian()).into())
    }
}

impl Sha256HasherFp12ToBytes {
    pub fn new() -> Self {
        Self::default()
    }
}

pub trait SymEncScheme: Send + Sync {
    type Ct: Send + Sync;
    fn enc<R: Rng>(&self, key: &[u8], msg: &[u8], rng: &mut R) -> Result<Self::Ct, Error>;
    fn dec(&self, key: &[u8], ct: &Self::Ct) -> Result<Vec<u8>, Error>;
    fn ct_size(ct: &Self::Ct) -> u64;
}

#[derive(Debug, Clone, Default)]
pub struct ChaCha20EncScheme;

impl SymEncScheme for ChaCha20EncScheme {
    type Ct = (Vec<u8>, [u8; 12]);
    fn enc<R: Rng>(&self, key: &[u8], msg: &[u8], rng: &mut R) -> Result<Self::Ct, Error> {
        let nonce = rng.gen::<[u8; 12]>();
        let mut cipher = ChaCha20::new(key.into(), &nonce.into());
        let mut buffer = msg.to_vec();
        cipher.apply_keystream(&mut buffer);
        Ok((buffer.to_vec(), nonce))
    }

    fn dec(&self, key: &[u8], ct: &Self::Ct) -> Result<Vec<u8>, Error> {
        let (enc, nonce) = ct;
        let mut buffer = enc.to_vec();
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn ct_size(ct: &Self::Ct) -> u64 {
        (ct.0.len() + ct.1.len()) as u64
    }
}

impl ChaCha20EncScheme {
    pub fn new() -> Self {
        Self::default()
    }
}

// #[derive(Debug, Clone, Default)]
// pub struct OneTimePadScheme;

// impl SymEncScheme for OneTimePadScheme {
//     fn enc(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
//         if key.len() != msg.len() {
//             return Err(Error::SymEncSchemeError(
//                 "Error from OneTimePadSchem: key and msg must have the same length".to_string(),
//             ));
//         }
//         Ok(key.iter().zip(msg.iter()).map(|(k, m)| k ^ m).collect())
//     }

//     fn dec(&self, key: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
//         if key.len() != ct.len() {
//             return Err(Error::SymEncSchemeError(
//                 "Error from OneTimePadScheme: key and ct must have the same length".to_string(),
//             ));
//         }
//         Ok(key.iter().zip(ct.iter()).map(|(k, c)| k ^ c).collect())
//     }
// }

// impl OneTimePadScheme {
//     pub fn new() -> Self {
//         Self::default()
//     }
// }
