use crate::ekem_dec;
use crate::ekem_enc;
use crate::pairing;
use crate::svd::*;
use crate::EkemCt;
use crate::EkemKey;
use crate::Error;
use crate::HasherFp12ToBytes;
use crate::SymEncScheme;
use blst::blst_scalar;
use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
use hex;
use itertools::*;
pub use kzg::eip_4844::FIELD_ELEMENTS_PER_BLOB;
use kzg::{eip_4844::*, FFTSettings, Fr, G1Mul, G2Mul, KZGSettings, PairingVerify, G1, G2};
use rayon::prelude::*;
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, *};
use rust_kzg_blst::{consts::*, eip_4844::*, utils::*};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct EweCt {
    msg_ct: Vec<u8>,
    ekem_ct: EkemCt,
}

impl EweCt {
    pub fn new(msg_ct: Vec<u8>, ekem_ct: EkemCt) -> Self {
        Self { msg_ct, ekem_ct }
    }
}

pub fn ewe_enc<H: HasherFp12ToBytes, S: SymEncScheme>(
    crs: &CRS,
    hasher: &H,
    enc_scheme: &S,
    vk: &VerifyingKey,
    time: TimeEpoch,
    dst: &[u8],
    index: u64,
    signing_target: &SingingTarget,
    msg: &[u8],
) -> Result<EweCt, Error> {
    let (ekem_ct, ekem_key) = ekem_enc(crs, hasher, vk, time, dst, index, signing_target)?;
    let msg_ct = enc_scheme.enc(&ekem_key.0, msg)?;
    Ok(EweCt::new(msg_ct, ekem_ct))
}

pub fn ewe_enc_batch<H: HasherFp12ToBytes, S: SymEncScheme>(
    crs: &CRS,
    hasher: &H,
    enc_scheme: &S,
    vk: &VerifyingKey,
    time: TimeEpoch,
    dst: &[u8],
    msg_of_signing_targets: &[(u64, SingingTarget, Vec<u8>)],
) -> Result<Vec<(u64, SingingTarget, EweCt)>, Error> {
    let ekem_encs: Vec<_> = msg_of_signing_targets
        .par_iter()
        .map(|(index, signing_target, msg)| {
            let ct = ewe_enc(
                crs,
                hasher,
                enc_scheme,
                vk,
                time,
                dst,
                *index,
                signing_target,
                msg,
            )?;
            Ok::<_, Error>((*index, *signing_target, ct))
        })
        .collect::<Result<_, _>>()?;
    Ok(ekem_encs)
}

pub fn ewe_dec<H: HasherFp12ToBytes, S: SymEncScheme>(
    ct: &EweCt,
    hasher: &H,
    enc_scheme: &S,
    signature: &Signature,
    opening: &Opening,
) -> Result<Vec<u8>, Error> {
    let ekem_key = ekem_dec(&ct.ekem_ct, hasher, signature, opening)?;
    enc_scheme.dec(&ekem_key.0, &ct.msg_ct)
}

pub fn ewe_dec_batch<H: HasherFp12ToBytes, S: SymEncScheme>(
    crs: &CRS,
    cts: &[(u64, SingingTarget, EweCt)],
    hasher: &H,
    enc_scheme: &S,
    signature: &Signature,
    signing_targets: &[SingingTarget],
) -> Result<Vec<Vec<u8>>, Error> {
    let openings = signing_targets
        .par_iter()
        .enumerate()
        .map(|(idx, _)| Opening::gen(crs, signing_targets, idx as u64))
        .collect::<Result<Vec<Opening>, Error>>()?;
    let msgs: Vec<_> = cts
        .par_iter()
        .zip(openings)
        .map(|((_, _, ct), opening)| ewe_dec(ct, hasher, enc_scheme, signature, &opening))
        .collect::<Result<_, _>>()?;
    Ok(msgs)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::OneTimePadScheme;
    use crate::Sha256HasherFp12ToBytes;
    use ark_std::{end_timer, start_timer};
    use rand;
    use rand::Rng;

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
        let digest_timer = start_timer!(|| "digest");
        let digest = SvdDigest::gen(&crs, &siging_targets).unwrap();
        end_timer!(digest_timer);
        let sign = sk.sign(&crs, &digest, time, dst).unwrap();
        let hasher = Sha256HasherFp12ToBytes::new();
        let enc_scheme = OneTimePadScheme::new();
        let mut rng = rand::thread_rng();
        for idx in 0..FIELD_ELEMENTS_PER_BLOB {
            let msg = [rng.gen(); 32];
            let enc_timer = start_timer!(|| "enc");
            let ct = ewe_enc(
                &crs,
                &hasher,
                &enc_scheme,
                &vk,
                time,
                dst,
                idx as u64,
                &siging_targets[idx],
                &msg,
            )
            .unwrap();
            end_timer!(enc_timer);
            let dec_timer = start_timer!(|| "opening + dec");
            let opening = Opening::gen(&crs, &siging_targets, idx as u64).unwrap();
            let dec_msg = ewe_dec(&ct, &hasher, &enc_scheme, &sign, &opening).unwrap();
            end_timer!(dec_timer);
            assert_eq!(msg.to_vec(), dec_msg);
        }
    }

    #[test]
    fn test_ewe_batch_valid_case() {
        let crs = CRS::load_from_filepath("trusted_setup.txt").unwrap();
        let sk = SingingKey::rand();
        let vk = VerifyingKey::gen(&crs, &sk);
        let time = 1;
        let dst = b"dst";
        let mut siging_targets = vec![];
        for _ in 0..FIELD_ELEMENTS_PER_BLOB {
            siging_targets.push(FsFr::rand());
        }
        let digest_timer = start_timer!(|| "digest");
        let digest = SvdDigest::gen(&crs, &siging_targets).unwrap();
        end_timer!(digest_timer);
        let sign = sk.sign(&crs, &digest, time, dst).unwrap();
        let hasher = Sha256HasherFp12ToBytes::new();
        let enc_scheme = OneTimePadScheme::new();
        let mut rng = rand::thread_rng();
        let msg_of_signing_targets: Vec<_> = (0..FIELD_ELEMENTS_PER_BLOB)
            .map(|idx| {
                let msg = [rng.gen(); 32];
                (idx as u64, siging_targets[idx], msg.to_vec())
            })
            .collect();
        let enc_timer = start_timer!(|| "enc");
        let cts = ewe_enc_batch(
            &crs,
            &hasher,
            &enc_scheme,
            &vk,
            time,
            dst,
            &msg_of_signing_targets,
        )
        .unwrap();
        end_timer!(enc_timer);
        let dec_timer = start_timer!(|| "dec");
        let msgs = ewe_dec_batch(&crs, &cts, &hasher, &enc_scheme, &sign, &siging_targets).unwrap();
        end_timer!(dec_timer);
        for (idx, msg) in msgs.iter().enumerate() {
            assert_eq!(msg_of_signing_targets[idx].2, msg.to_vec());
        }
    }
}
