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
pub struct ShamirSecretSharing {
    pub num_shares: u64,
    pub corrupt_threshold: u64,
}

impl ShamirSecretSharing {
    pub fn new(num_shares: u64, corrupt_threshold: u64) -> Self {
        Self {
            num_shares,
            corrupt_threshold,
        }
    }

    pub fn share(&self, secret: FsFr) -> Vec<(u64, FsFr)> {
        let mut evals = vec![(0, secret)];
        for idx in 0..self.corrupt_threshold {
            evals.push((idx + 1, FsFr::rand()));
        }
        let domain = (0..=self.corrupt_threshold)
            .map(|idx| FsFr::from_u64(idx as u64))
            .collect_vec();
        for target in (self.corrupt_threshold + 1)..=self.num_shares {
            let basises = lagrange_basises(&domain, &FsFr::from_u64(target as u64));
            let eval = basises
                .iter()
                .zip(evals.iter())
                .fold(FsFr::zero(), |acc, (b, (_, e))| acc.add(&b.mul(e)));
            evals.push((target, eval));
        }
        evals.remove(0);
        debug_assert_eq!(evals.len() as u64, self.num_shares);
        evals
    }

    pub fn recover(&self, shares: &[(u64, FsFr)]) -> Result<FsFr, Error> {
        if shares.len() <= self.corrupt_threshold as usize {
            return Err(Error::NotEnoughPdsError(
                shares.len() as u64,
                self.corrupt_threshold + 1,
            ));
        }
        let domain = shares.iter().map(|(x, _)| FsFr::from_u64(*x)).collect_vec();
        let basis = lagrange_basises(&domain, &FsFr::zero());
        let secret = shares
            .iter()
            .zip(basis.iter())
            .fold(FsFr::zero(), |acc, ((_, e), b)| acc.add(&b.mul(e)));
        Ok(secret)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_shamir_n10_t3() {
        let shamir = ShamirSecretSharing::new(8, 3);
        let secret = FsFr::rand();
        let shares = shamir.share(secret);
        println!("shares: {:?}", shares);
        let recovery_shares1 = shares[0..4].to_vec();
        let recovered1 = shamir.recover(&recovery_shares1).unwrap();
        assert_eq!(secret, recovered1);
        let recovery_shares2 = shares[4..8].to_vec();
        let recovered2 = shamir.recover(&recovery_shares2).unwrap();
        assert_eq!(secret, recovered2);
    }
}
