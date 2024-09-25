use crate::pairing;
use crate::Error;
use blst::blst_scalar;
use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
use hex;
use itertools::*;
pub use kzg::eip_4844::FIELD_ELEMENTS_PER_BLOB;
use kzg::{eip_4844::*, FFTSettings, Fr, G1Mul, G2Mul, KZGSettings, PairingVerify, G1, G2};
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, *};
use rust_kzg_blst::{consts::*, eip_4844::*, utils::*};
use sha2::{Digest, Sha256};
pub mod kzg_tbte;
pub use kzg_tbte::*;
use rayon::prelude::*;

pub trait TbteScheme: Send + Sync {
    type CRS: Send + Sync;
    type SecretKey;
    type PublicKey: Send + Sync;
    type EpochId: Send + Sync;
    type Tag: Clone + Send + Sync;
    type Plaintext: Send + Sync;
    type Ct: Send + Sync;
    type Digest: Send + Sync;
    type PartialDec: Send + Sync;

    fn load_crs_from_filepath(&self, filepath: &str) -> Result<Self::CRS, Error>;

    fn setup_crs(&self, scale: usize, secret: [u8; 32]) -> Result<Self::CRS, Error>;

    fn setup_keys(
        &self,
        crs: Self::CRS,
        threshold: u64,
        num_parties: u64,
    ) -> Result<(Vec<Self::SecretKey>, Self::PublicKey), Error>;

    fn enc(
        &self,
        pk: &Self::PublicKey,
        eid: &Self::EpochId,
        index: u64,
        tag: &Self::Tag,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ct, Error>;

    fn digest(&self, pk: &Self::PublicKey, tags: &[Self::Tag]) -> Result<Self::Digest, Error>;

    fn batch_dec(
        &self,
        sk: &Self::SecretKey,
        eid: &Self::EpochId,
        digest: &Self::Digest,
    ) -> Result<Self::PartialDec, Error>;

    fn combine(
        &self,
        pk: &Self::PublicKey,
        eid: &Self::EpochId,
        cts: &[Self::Ct],
        tags: &[Self::Tag],
        pds: &[Self::PartialDec],
    ) -> Result<Vec<Self::Plaintext>, Error>;

    fn enc_batch(
        &self,
        pk: &Self::PublicKey,
        eid: &Self::EpochId,
        indices: &[u64],
        tags: &[Self::Tag],
        plaintexts: &[Self::Plaintext],
    ) -> Result<Vec<Self::Ct>, Error> {
        indices
            .par_iter()
            .zip(tags.par_iter())
            .zip(plaintexts.par_iter())
            .map(|((&index, tag), plaintext)| self.enc(pk, eid, index, tag, plaintext))
            .collect()
    }
}
