use crate::*;
use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
use fft_settings::FsFFTSettings;
use itertools::Itertools;
use kzg::common_utils::reverse_bit_order;
use kzg::{
    eip_4844::*, FFTSettings, Fr, G1LinComb, G1Mul, G2Mul, KZGSettings, PairingVerify, Poly, FFTG1,
    G1, G2,
};
use kzg_settings::FsKZGSettings;
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, poly::*, *};
use rust_kzg_blst::{consts::*, eip_4844::*, utils::*};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KZGSigningTarget(pub FsFr);

impl Into<Vec<u8>> for KZGSigningTarget {
    fn into(self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl From<Vec<u8>> for KZGSigningTarget {
    fn from(bytes: Vec<u8>) -> Self {
        Self(FsFr::from_bytes(&bytes).unwrap())
    }
}

#[derive(Debug, Clone, Default)]
pub struct KZGSvdScheme {
    dst: Vec<u8>,
}

impl SvdScheme for KZGSvdScheme {
    type CRS = FsKZGSettings;
    type SigningKey = FsFr;
    type VerifyingKey = (FsG2, FsG2);
    type TimeEpoch = u64;
    type TimeRandomPoint = FsG1;
    type SigningTarget = KZGSigningTarget;
    type SvdDigest = FsG1;
    type Signature = FsG1;
    type Opening = FsG1;

    fn load_crs_from_filepath(&self, filepath: &str) -> Result<Self::CRS, Error> {
        load_trusted_setup_filename_rust(filepath)
            .map_err(|e| Error::LoadCRSError(filepath.to_string(), e.to_string()))
    }

    // k = 2^k
    fn gen_crs(&self, scale: usize, secret: [u8; 32]) -> Result<Self::CRS, Error> {
        let n: usize = 1 << scale;
        let (mut secret_g1, secret_g2) = generate_trusted_setup_eval_form(scale, secret);

        let fft_settings =
            FsFFTSettings::new(scale).map_err(|e| Error::FFTError(n, e.to_string()))?;
        reverse_bit_order(&mut secret_g1).unwrap();
        FsKZGSettings::new(&secret_g1, &secret_g2, n, &fft_settings)
            .map_err(|e| Error::GenCRSError(e.to_string()))
    }

    fn gen_keys(&self, crs: &Self::CRS) -> Result<(Self::SigningKey, Self::VerifyingKey), Error> {
        let sk = FsFr::rand();
        let vk = (G2_GENERATOR.mul(&sk), crs.secret_g2[1].mul(&sk));
        Ok((sk, vk))
    }

    fn gen_time_random_point(
        &self,
        vk: &Self::VerifyingKey,
        time: Self::TimeEpoch,
    ) -> Result<Self::TimeRandomPoint, Error> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&vk.0.to_bytes());
        msg.extend_from_slice(&vk.1.to_bytes());
        msg.extend_from_slice(&time.to_le_bytes());
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
        Ok(out)
    }

    fn digest(
        &self,
        crs: &Self::CRS,
        signing_targets: &[Self::SigningTarget],
    ) -> Result<Self::SvdDigest, Error> {
        let polynomial: FsPoly =
            FsPoly::from_coeffs(&signing_targets.into_iter().map(|v| v.0).collect_vec());
        // blob_to_polynomial_generic_len(&signing_targets.into_iter().map(|v| v.0).collect_vec())
        //     .map_err(|e| Error::GenDigestError(e.to_string()))?;
        crs.commit_to_poly(&polynomial)
            .map_err(|e| Error::GenDigestError(e.to_string()))
    }

    fn sign(
        &self,
        sk: &Self::SigningKey,
        crs: &Self::CRS,
        digest: &Self::SvdDigest,
        time: Self::TimeEpoch,
    ) -> Result<Self::Signature, Error> {
        let vk = (G2_GENERATOR.mul(sk), crs.secret_g2[1].mul(sk));
        let time_random_point = self.gen_time_random_point(&vk, time)?;
        let signed_point = digest.add(&time_random_point);
        let signature = signed_point.mul(sk);
        Ok(signature)
    }

    fn open(
        &self,
        crs: &Self::CRS,
        signing_targets: &[Self::SigningTarget],
        index: u64,
    ) -> Result<Self::Opening, Error> {
        let roots_of_unity = crs.get_fft_settings().get_roots_of_unity();
        let (proof, _) = compute_kzg_proof_rust_generic_len(
            &signing_targets.into_iter().map(|v| v.0).collect_vec(),
            &roots_of_unity[index as usize],
            crs,
        )
        .map_err(|e| Error::OpeningError(index, e.to_string()))?;
        Ok(proof)
    }

    fn verify(
        &self,
        crs: &Self::CRS,
        vk: &Self::VerifyingKey,
        time: Self::TimeEpoch,
        index: u64,
        signing_target: &Self::SigningTarget,
        signature: &Self::Signature,
        opening: &Self::Opening,
    ) -> Result<bool, Error> {
        let fft_settings = crs.get_fft_settings();
        let roots_of_unity = fft_settings.get_roots_of_unity();
        let factor = vk.0.mul(&roots_of_unity[index as usize]).sub(&vk.1);
        let time_random_point = self.gen_time_random_point(vk, time)?;
        let signing_target_g1 = G1_GENERATOR.mul(&signing_target.0);
        let sum = signing_target_g1.add(&time_random_point);
        let h_from_ins = pairing(&[sum], &[vk.0])?;
        let h_from_w = pairing(
            &[signature.clone(), opening.clone()],
            &[G2_GENERATOR, factor],
        )?;
        let result = blst_fp12::finalverify(&h_from_ins, &h_from_w);
        Ok(result)
    }
}

impl KZGSvdScheme {
    pub fn new(dst: Vec<u8>) -> Self {
        Self { dst }
    }
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
    fn test_svd_valid_case_1024() {
        let ekem = KZGEkemScheme::new(Sha256HasherFp12ToBytes::new(), b"dst".to_vec());
        let svd = &ekem.svd;
        let mut rng = rand::thread_rng();
        let secret = [rng.gen(); 32];
        let crs: kzg_settings::FsKZGSettings = svd.gen_crs(10, secret).unwrap();
        // svd.load_crs_from_filepath("trusted_setup.txt").unwrap();
        let (sk, vk) = svd.gen_keys(&crs).unwrap();
        let time = 1;
        let mut signing_targets = vec![];
        for _ in 0..1024 {
            signing_targets.push(KZGSigningTarget(FsFr::rand()));
        }
        let digest_timer = start_timer!(|| "digest");
        let digest = svd.digest(&crs, &signing_targets).unwrap();
        end_timer!(digest_timer);
        let sign = svd.sign(&sk, &crs, &digest, time).unwrap();
        for idx in 0..1024 {
            let opening_timer = start_timer!(|| "opening");
            let opening = svd.open(&crs, &signing_targets, idx as u64).unwrap();
            end_timer!(opening_timer);
            let verify_timer = start_timer!(|| "verify");
            let result = svd
                .verify(
                    &crs,
                    &vk,
                    time,
                    idx as u64,
                    &signing_targets[idx],
                    &sign,
                    &opening,
                )
                .unwrap();
            end_timer!(verify_timer);
            assert!(result);
        }
    }

    #[test]
    fn test_svd_valid_case_4096() {
        let ekem = KZGEkemScheme::new(Sha256HasherFp12ToBytes::new(), b"dst".to_vec());
        let svd = &ekem.svd;
        let crs: kzg_settings::FsKZGSettings =
            svd.load_crs_from_filepath("trusted_setup.txt").unwrap();
        // svd.load_crs_from_filepath("trusted_setup.txt").unwrap();
        let (sk, vk) = svd.gen_keys(&crs).unwrap();
        let time = 1;
        let mut signing_targets = vec![];
        for _ in 0..4096 {
            signing_targets.push(KZGSigningTarget(FsFr::rand()));
        }
        let digest_timer = start_timer!(|| "digest");
        let digest = svd.digest(&crs, &signing_targets).unwrap();
        end_timer!(digest_timer);
        let sign = svd.sign(&sk, &crs, &digest, time).unwrap();
        for idx in 0..4096 {
            let opening_timer = start_timer!(|| "opening");
            let opening = svd.open(&crs, &signing_targets, idx as u64).unwrap();
            end_timer!(opening_timer);
            let verify_timer = start_timer!(|| "verify");
            let result = svd
                .verify(
                    &crs,
                    &vk,
                    time,
                    idx as u64,
                    &signing_targets[idx],
                    &sign,
                    &opening,
                )
                .unwrap();
            end_timer!(verify_timer);
            assert!(result);
        }
    }
}
