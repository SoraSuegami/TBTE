use crate::*;
use blst::{
    blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_fp12_one, blst_fp6, blst_hash_to_g1,
    blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine, blst_p2_to_affine, Pairing,
};
use fft_settings::FsFFTSettings;
use itertools::Itertools;
use kzg::common_utils::reverse_bit_order;
use kzg::{
    eip_4844::*, FFTSettings, Fr, G1LinComb, G1Mul, G2Mul, KZGSettings, PairingVerify, Poly, FFTG1,
    G1, G2,
};
use kzg_settings::FsKZGSettings;
use rand::rngs::OsRng;
use rayon::prelude::*;
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, poly::*, *};
use rust_kzg_blst::{consts::*, eip_4844::*, utils::*};

#[derive(Debug, Clone, Default)]
pub struct KZGPublicKey {
    pub num_parties: u64,
    pub corrupt_threshold: u64,
    pub pk0: FsG2,
    pub pk1: FsG2,
    pub crs: FsKZGSettings,
}

impl KZGPublicKey {
    pub fn data_sizes(&self) -> (u64, u64) {
        let pk0_size = self.pk0.to_bytes().len() as u64;
        let pk1_size = self.pk1.to_bytes().len() as u64;
        let pk_size = pk0_size + pk1_size;
        let crs_size = {
            let g1_size: u64 = self
                .crs
                .secret_g1
                .iter()
                .map(|v| v.to_bytes().len() as u64)
                .sum();
            let g2_size: u64 = self
                .crs
                .secret_g2
                .iter()
                .map(|v| v.to_bytes().len() as u64)
                .sum();
            g1_size + g2_size
        };
        (pk_size, crs_size)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KZGTag(pub FsFr);

impl Into<Vec<u8>> for KZGTag {
    fn into(self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl From<Vec<u8>> for KZGTag {
    fn from(bytes: Vec<u8>) -> Self {
        Self(FsFr::from_bytes(&bytes).unwrap())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KZGCt<S: SymEncScheme> {
    eid: u64,
    idx: u64,
    tag: KZGTag,
    s: FsG2,
    u: FsG2,
    ct_m: S::Ct,
}

impl<S: SymEncScheme> KZGCt<S> {
    pub fn data_size(&self) -> u64 {
        let tag_size = self.tag.0.to_bytes().len() as u64;
        let s_size = self.s.to_bytes().len() as u64;
        let u_size = self.u.to_bytes().len() as u64;
        let ct_m_size = S::ct_size(&self.ct_m) as u64;
        8 + 8 + tag_size + s_size + u_size + ct_m_size
    }
}

#[derive(Debug, Clone, Default)]
pub struct KZGTbteScheme<H: HasherFp12ToBytes, S: SymEncScheme> {
    dst: Vec<u8>,
    hasher: H,
    sym_enc: S,
}

impl<H: HasherFp12ToBytes, S: SymEncScheme> TbteScheme for KZGTbteScheme<H, S> {
    type CRS = FsKZGSettings;
    type SecretKey = (u64, FsFr);
    type PublicKey = KZGPublicKey;
    type EpochId = u64;
    type Tag = KZGTag;
    type Plaintext = Vec<u8>;
    type Ct = KZGCt<S>;
    type Digest = FsG1;
    type PartialDec = (u64, FsG1);

    fn load_crs_from_filepath(&self, filepath: &str) -> Result<Self::CRS, Error> {
        load_trusted_setup_filename_rust(filepath)
            .map_err(|e| Error::LoadCRSError(filepath.to_string(), e.to_string()))
    }

    // k = 2^k
    fn setup_crs(&self, scale: usize, secret: [u8; 32]) -> Result<Self::CRS, Error> {
        let n: usize = 1 << scale;
        let (mut secret_g1, secret_g2) = generate_trusted_setup_eval_form(scale, secret);

        let fft_settings =
            FsFFTSettings::new(scale).map_err(|e| Error::FFTError(n, e.to_string()))?;
        reverse_bit_order(&mut secret_g1).unwrap();
        FsKZGSettings::new(&secret_g1, &secret_g2, n, &fft_settings)
            .map_err(|e| Error::GenCRSError(e.to_string()))
    }

    fn setup_keys(
        &self,
        crs: Self::CRS,
        corrupt_threshold: u64,
        num_parties: u64,
    ) -> Result<(Vec<Self::SecretKey>, Self::PublicKey), Error> {
        let msk = FsFr::rand();
        let pk = KZGPublicKey {
            num_parties,
            corrupt_threshold,
            pk0: G2_GENERATOR.mul(&msk),
            pk1: crs.secret_g2[1].mul(&msk),
            crs,
        };
        let shamir = ShamirSecretSharing::new(num_parties, corrupt_threshold);
        let sks = shamir.share(msk);
        Ok((sks, pk))
    }

    fn enc(
        &self,
        pk: &Self::PublicKey,
        eid: &Self::EpochId,
        index: u64,
        tag: &Self::Tag,
        plaintext: &Self::Plaintext,
    ) -> Result<Self::Ct, Error> {
        let s = FsFr::rand();
        let crs = &pk.crs;
        let fft_settings = crs.get_fft_settings();
        let roots_of_unity = fft_settings.get_roots_of_unity();
        let u = pk
            .pk0
            .mul(&roots_of_unity[index as usize])
            .sub(&pk.pk1)
            .mul(&s);
        let eid_rand = self.compute_eid_rand(eid);
        let k_g1 = G1_GENERATOR.mul(&tag.0).add(&eid_rand).mul(&s);
        let k = pairing(&[k_g1], &[pk.pk0])?;
        let key = self.hasher.hash(&k)?;
        let mut rng = OsRng;
        let ct_m = self.sym_enc.enc(&key, plaintext, &mut rng)?;
        Ok(KZGCt {
            eid: *eid,
            idx: index,
            tag: tag.clone(),
            s: G2_GENERATOR.mul(&s),
            u,
            ct_m,
        })
    }

    fn digest(&self, pk: &Self::PublicKey, tags: &[Self::Tag]) -> Result<Self::Digest, Error> {
        let polynomial: FsPoly = FsPoly::from_coeffs(&tags.into_iter().map(|v| v.0).collect_vec());
        pk.crs
            .commit_to_poly(&polynomial)
            .map_err(|e| Error::GenDigestError(e.to_string()))
    }

    fn batch_dec(
        &self,
        sk: &Self::SecretKey,
        eid: &Self::EpochId,
        digest: &Self::Digest,
    ) -> Result<Self::PartialDec, Error> {
        let eid_rand = self.compute_eid_rand(eid);
        let (idx, s) = sk;
        let pd: FsG1 = digest.add(&eid_rand).mul(s);
        Ok((*idx, pd))
    }

    fn combine(
        &self,
        pk: &Self::PublicKey,
        eid: &Self::EpochId,
        cts: &[Self::Ct],
        tags: &[Self::Tag],
        pds: &[Self::PartialDec],
    ) -> Result<Vec<Self::Plaintext>, Error> {
        if pds.len() <= pk.corrupt_threshold as usize {
            return Err(Error::NotEnoughPdsError(
                pds.len() as u64,
                pk.corrupt_threshold + 1,
            ));
        }
        let pds = &pds[0..pk.corrupt_threshold as usize + 1];
        let domain = pds
            .iter()
            .map(|(idx, _)| FsFr::from_u64(*idx))
            .collect_vec();
        let basis = lagrange_basises(&domain, &FsFr::zero());
        let pd = pds
            .iter()
            .zip(basis.iter())
            .fold(FsG1::zero(), |acc, ((_, d), b)| acc.add(&d.mul(b)));

        let crs = &pk.crs;
        let roots_of_unity = crs.get_fft_settings().get_roots_of_unity();
        let tags_vec: Vec<_> = tags.iter().map(|v| v.0).collect();

        let plaintexts: Vec<_> = cts
            .par_iter()
            .enumerate()
            .map(|(idx, ct)| {
                if ct.eid != *eid {
                    return Err(Error::EidMismatchError(*eid, ct.eid));
                }
                let (opening, _) =
                    compute_kzg_proof_rust_generic_len(&tags_vec, &roots_of_unity[idx], crs)
                        .map_err(|e| Error::OpeningError(idx as u64, e.to_string()))?;
                let pairinged = pairing(&[pd.clone(), opening], &[ct.s, ct.u])?;
                let key = self.hasher.hash(&pairinged)?;
                let plaintext = self.sym_enc.dec(&key, &ct.ct_m)?;
                // let plaintext = unsafe {
                //     let ret = Box::new(blst_fp12 {
                //         fp6: [blst_fp6::default(); 2],
                //     });
                //     let ret_ptr = Box::into_raw(ret);
                //     blst_fp12_mul(ret_ptr, &ct.k, &pairinged);
                //     // g^0=1, thus the plaintext is false if the result is 1
                //     let is_false = blst_fp12_is_one(ret_ptr as *const blst_fp12);
                //     let _ = Box::from_raw(ret_ptr);
                //     !is_false
                // };
                Ok(plaintext)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(plaintexts)
    }
}

impl<H: HasherFp12ToBytes, S: SymEncScheme> KZGTbteScheme<H, S> {
    pub fn new(dst: Vec<u8>, hasher: H, sym_enc: S) -> Self {
        Self {
            dst,
            hasher,
            sym_enc,
        }
    }

    pub fn compute_eid_rand(&self, eid: &<Self as TbteScheme>::EpochId) -> FsG1 {
        let mut msg = Vec::new();
        msg.extend_from_slice(&eid.to_le_bytes());
        let mut out = FsG1::default();
        let aug = [];
        unsafe {
            blst_hash_to_g1(
                &mut out.0,
                msg.as_ptr(),
                msg.len(),
                self.dst.as_ptr(),
                self.dst.len(),
                aug.as_ptr(),
                0,
            )
        };
        out
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use rand::Rng;
    use rand::{self, thread_rng};

    #[test]
    fn test_kzg_tbte_t1_n3_b32() {
        let hasher = Sha256HasherFp12ToBytes::new();
        let sym_enc = ChaCha20EncScheme::new();
        let tbte = KZGTbteScheme::new(b"dst".to_vec(), hasher, sym_enc);
        let mut rng = thread_rng();
        let secret = rng.gen::<[u8; 32]>();
        let crs = tbte.setup_crs(5, secret).unwrap();
        let (sks, pk) = tbte.setup_keys(crs, 1, 3).unwrap();
        let eid = 1;
        let mut tags = vec![];
        for _ in 0..32 {
            tags.push(KZGTag(FsFr::rand()));
        }
        let plaintexts = tags
            .iter()
            .map(|_| rng.gen::<[u8; 1]>().to_vec())
            .collect_vec();
        let enc_timer = start_timer!(|| "enc");
        let cts = tbte
            .enc_batch(
                &pk,
                &eid,
                &(0u64..32 as u64).collect_vec(),
                &tags,
                &plaintexts,
            )
            .unwrap();
        // tags.iter()
        //     .enumerate()
        //     .map(|(idx, tag)| tbte.enc(&pk, &eid, idx as u64, tag, &plaintexts[idx]))
        //     .collect::<Result<Vec<_>, _>>()
        //     .unwrap();
        end_timer!(enc_timer);
        let digest_timer = start_timer!(|| "digest");
        let digest = tbte.digest(&pk, &tags).unwrap();
        end_timer!(digest_timer);
        let pd_timer = start_timer!(|| "pd");
        let pds = sks
            .iter()
            .map(|sk| tbte.batch_dec(sk, &eid, &digest))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        end_timer!(pd_timer);
        let combine_timer = start_timer!(|| "combine");
        let recovered = tbte.combine(&pk, &eid, &cts, &tags, &pds).unwrap();
        end_timer!(combine_timer);
        assert_eq!(plaintexts, recovered);
    }
}
