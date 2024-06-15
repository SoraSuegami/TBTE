use crate::pairing;
use crate::svd::*;
use crate::Error;
use crate::HasherFp12ToBytes;
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

#[derive(Debug, Clone, Default)]
pub struct EkemCt {
    pub g2s: Vec<FsG2>,
    pub dst: Vec<u8>,
}

impl EkemCt {
    pub fn new(g2s: Vec<FsG2>, dst: Vec<u8>) -> Self {
        Self { g2s, dst }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EkemKey(pub Vec<u8>);

impl EkemKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key.to_vec())
    }
}

pub fn ekem_enc<H: HasherFp12ToBytes>(
    crs: &CRS,
    hasher: &H,
    vk: &VerifyingKey,
    time: TimeEpoch,
    dst: &[u8],
    index: u64,
    signing_target: &SingingTarget,
) -> Result<(EkemCt, EkemKey), Error> {
    let secret = FsFr::rand();
    let fft_settings = crs.0.get_fft_settings();
    let roots_of_unity = fft_settings.get_roots_of_unity();
    let factor = vk.vk.mul(&roots_of_unity[index as usize]).sub(&vk.tau_vk);
    let g2s = vec![G2_GENERATOR, factor]
        .into_iter()
        .map(|g2| g2.mul(&secret))
        .collect_vec();
    let time_random_point = TimeRandomPoint::gen(vk, time, dst)?;
    let signing_target_g1 = G1_GENERATOR.mul(signing_target);
    let sum = signing_target_g1.add(&time_random_point.0);
    let secret_sum = sum.mul(&secret);
    let h = pairing(&[secret_sum], &[vk.vk])?;
    let key = hasher.hash(&h)?;
    Ok((EkemCt::new(g2s, dst.to_vec()), EkemKey::new(key)))
}

pub fn ekem_dec<H: HasherFp12ToBytes>(
    ct: &EkemCt,
    hasher: &H,
    signature: &Signature,
    opening: &Opening,
) -> Result<EkemKey, Error> {
    let h = pairing(&[signature.0, opening.proof], &[ct.g2s[0], ct.g2s[1]])?;
    let key = hasher.hash(&h)?;
    Ok(EkemKey::new(key))
}

#[cfg(test)]
mod tests {
    use crate::Sha256HasherFp12ToBytes;

    use super::*;

    #[test]
    fn test_ekem_valid_case() {
        let crs = CRS::load_from_filepath("trusted_setup.txt").unwrap();
        let sk = SingingKey::rand();
        let vk = VerifyingKey::gen(&crs, &sk);
        let time = 1;
        let dst = b"dst";
        let mut siging_targets = vec![];
        for _ in 0..FIELD_ELEMENTS_PER_BLOB {
            siging_targets.push(FsFr::rand());
        }
        let digest = SvdDigest::gen(&crs, &siging_targets).unwrap();
        let sign = sk.sign(&crs, &digest, time, dst).unwrap();
        let hasher = Sha256HasherFp12ToBytes::new();
        for idx in 0..FIELD_ELEMENTS_PER_BLOB {
            let opening = Opening::gen(&crs, &siging_targets, idx as u64).unwrap();
            let (ct, key_enc) = ekem_enc(
                &crs,
                &hasher,
                &vk,
                time,
                dst,
                idx as u64,
                &siging_targets[idx],
            )
            .unwrap();
            let key_dec = ekem_dec(&ct, &hasher, &sign, &opening).unwrap();
            assert_eq!(key_enc, key_dec);
            // println!("idx {} is valid", idx);
        }
    }
}
