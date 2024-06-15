use blst::{
    blst_fp12, blst_hash_to_g1, blst_p1_affine, blst_p1_cneg, blst_p1_to_affine, blst_p2_affine,
    blst_p2_to_affine, Pairing,
};
pub use kzg::eip_4844::FIELD_ELEMENTS_PER_BLOB;
use kzg::{eip_4844::*, FFTSettings, Fr, G1Mul, G2Mul, KZGSettings, PairingVerify, G1, G2};
use kzg_settings::FsKZGSettings;
use rust_kzg_blst::types::{fr::*, g1::*, g2::*, *};
use rust_kzg_blst::{consts::*, eip_4844::*, utils::*};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SvdError {
    #[error("failed to load a CRS from a file {0}: {1}")]
    LoadCRSError(String, String),
    #[error("failed to generate a singing key: {0}")]
    GenSingingKeyError(String),
    #[error("failed to generate a verifying key: {0}")]
    GenDigestError(String),
    #[error("failed to generate an opening at index {0}: {1}")]
    OpeningError(u64, String),
}

#[derive(Debug, Clone, Default)]
pub struct CRS(pub FsKZGSettings);

impl CRS {
    pub fn load_from_filepath(filepath: &str) -> Result<Self, SvdError> {
        let setting = load_trusted_setup_filename_rust(filepath)
            .map_err(|e| SvdError::LoadCRSError(filepath.to_string(), e.to_string()))?;
        Ok(Self(setting))
    }

    pub fn tau_g1s(&self) -> &[FsG1] {
        &self.0.secret_g1
    }

    pub fn tau_g2s(&self) -> &[FsG2] {
        &self.0.secret_g2
    }
}

#[derive(Debug, Clone, Default)]
pub struct SingingKey(pub FsFr);

impl SingingKey {
    pub fn new(secret: [u8; 32]) -> Result<Self, SvdError> {
        FsFr::from_bytes(&secret)
            .map_err(|err| SvdError::GenSingingKeyError(err.to_string()))
            .map(Self)
    }

    pub fn rand() -> Self {
        Self(FsFr::rand())
    }

    pub fn sign(
        &self,
        crs: &CRS,
        digest: &Digest,
        time: TimeEpoch,
        dst: &[u8],
    ) -> Result<Signature, SvdError> {
        Signature::gen(crs, &self, digest, time, dst)
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerifyingKey {
    pub vk: FsG2,
    pub tau_vk: FsG2,
}

impl VerifyingKey {
    pub fn new(vk: FsG2, tau_vk: FsG2) -> Self {
        Self { vk, tau_vk }
    }

    pub fn gen(crs: &CRS, sk: &SingingKey) -> Self {
        let vk = G2_GENERATOR.mul(&sk.0);
        let tau_vk = crs.tau_g2s()[1].mul(&sk.0);
        Self::new(vk, tau_vk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.vk.to_bytes());
        bytes.extend_from_slice(&self.tau_vk.to_bytes());
        bytes
    }
}

pub type TimeEpoch = u64;

#[derive(Debug, Clone, Default)]
pub struct TimeRandomPoint(pub FsG1);

impl TimeRandomPoint {
    pub fn gen(vk: &VerifyingKey, time: TimeEpoch, dst: &[u8]) -> Result<Self, SvdError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&vk.to_bytes());
        msg.extend_from_slice(&time.to_le_bytes());
        let mut out = FsG1::default();
        let aug = [];
        unsafe {
            blst_hash_to_g1(
                &mut out.0,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                aug.as_ptr(),
                0,
            )
        };
        Ok(Self(out))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

pub type SingingTarget = FsFr;

#[derive(Debug, Clone, Default)]
pub struct Digest(pub FsG1);

impl Digest {
    pub fn gen(crs: &CRS, signing_targets: &[SingingTarget]) -> Result<Self, SvdError> {
        blob_to_kzg_commitment_rust(signing_targets, &crs.0)
            .map_err(|e| SvdError::GenDigestError(e.to_string()))
            .map(Self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Signature(pub FsG1);

impl Signature {
    pub fn gen(
        crs: &CRS,
        sk: &SingingKey,
        digest: &Digest,
        time: TimeEpoch,
        dst: &[u8],
    ) -> Result<Self, SvdError> {
        let vk = VerifyingKey::gen(crs, sk);
        let time_random_point = TimeRandomPoint::gen(&vk, time, dst).unwrap();
        let signed_point = digest.0.add(&time_random_point.0);
        let signature = signed_point.mul(&sk.0);
        Ok(Self(signature))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Opening {
    pub index: u64,
    pub target: FsFr,
    pub proof: FsG1,
}

impl Opening {
    pub fn gen(crs: &CRS, signing_targets: &[SingingTarget], index: u64) -> Result<Self, SvdError> {
        let roots_of_unity = crs.0.get_fft_settings().get_roots_of_unity();
        let (proof, _) =
            compute_kzg_proof_rust(signing_targets, &roots_of_unity[index as usize], &crs.0)
                .map_err(|e| SvdError::OpeningError(index, e.to_string()))?;
        Ok(Self {
            index,
            target: signing_targets[index as usize],
            proof,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SvdInstanceVectors {
    pub g2: FsG2,
    pub h: blst_fp12,
    pub dst: Vec<u8>,
}

impl SvdInstanceVectors {
    pub fn new(g2: FsG2, h: blst_fp12, dst: Vec<u8>) -> Self {
        Self { g2, h, dst }
    }

    pub fn gen(
        crs: &CRS,
        vk: &VerifyingKey,
        time: TimeEpoch,
        dst: &[u8],
        index: u64,
        signing_target: &SingingTarget,
    ) -> Result<Self, SvdError> {
        let fft_settings = crs.0.get_fft_settings();
        let roots_of_unity = fft_settings.get_roots_of_unity();
        let factor = vk.vk.mul(&roots_of_unity[index as usize]).sub(&vk.tau_vk);
        // println!("factor: {:?}", factor);
        let time_random_point = TimeRandomPoint::gen(vk, time, dst)?;
        let signing_target_g1 = G1_GENERATOR.mul(signing_target);
        let sum = signing_target_g1.add(&time_random_point.0);
        let mut g1_affine = blst_p1_affine::default();
        let mut g2_affine = blst_p2_affine::default();
        let h = unsafe {
            blst_p1_to_affine(&mut g1_affine, &sum.0);
            blst_p2_to_affine(&mut g2_affine, &vk.vk.0);
            let mut pairing_blst = Pairing::new(false, dst);
            pairing_blst.raw_aggregate(&g2_affine, &g1_affine);
            pairing_blst.as_fp12().final_exp()
        };
        Ok(Self {
            g2: factor,
            h,
            dst: dst.to_vec(),
        })
    }

    pub fn verify(&self, signature: &Signature, opening: &Opening) -> Result<bool, SvdError> {
        let mut g11 = blst_p1_affine::default();
        let mut g12 = blst_p2_affine::default();
        let mut g21 = blst_p1_affine::default();
        let mut g22 = blst_p2_affine::default();
        let result = unsafe {
            blst_p1_to_affine(&mut g11, &signature.0 .0);
            blst_p2_to_affine(&mut g12, &G2_GENERATOR.0);
            blst_p1_to_affine(&mut g21, &opening.proof.0);
            blst_p2_to_affine(&mut g22, &self.g2.0);
            let mut pairing_blst = Pairing::new(false, &self.dst);
            pairing_blst.raw_aggregate(&g12, &g11);
            pairing_blst.raw_aggregate(&g22, &g21);
            let h = pairing_blst.as_fp12().final_exp();
            blst_fp12::finalverify(&h, &self.h)
        };
        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_case() {
        let crs = CRS::load_from_filepath("trusted_setup.txt").unwrap();
        let sk = SingingKey::rand();
        let vk = VerifyingKey::gen(&crs, &sk);
        let time = 1;
        let dst = b"dst";
        let mut siging_targets = vec![];
        for _ in 0..FIELD_ELEMENTS_PER_BLOB {
            siging_targets.push(FsFr::rand());
        }
        let digest = Digest::gen(&crs, &siging_targets).unwrap();
        let sign = sk.sign(&crs, &digest, time, dst).unwrap();
        for idx in 0..FIELD_ELEMENTS_PER_BLOB {
            let opening = Opening::gen(&crs, &siging_targets, idx as u64).unwrap();
            let instance = SvdInstanceVectors::gen(
                &crs,
                &vk,
                time,
                dst,
                idx as u64,
                &siging_targets[idx as usize],
            )
            .unwrap();
            assert!(instance.verify(&sign, &opening).unwrap());
            println!("idx {} is valid", idx);
        }
    }
}
