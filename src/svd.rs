use crate::Error;
pub mod kzg_svd;
pub use kzg_svd::*;
use rayon;

pub trait SvdScheme {
    type CRS: Send + Sync;
    type SigningKey;
    type VerifyingKey: Send + Sync;
    type TimeEpoch: Send + Sync;
    type TimeRandomPoint: Send + Sync;
    type SigningTarget: Clone + Send + Sync;
    type SvdDigest: Send + Sync;
    type Signature: Send + Sync;
    type Opening: Send + Sync;

    fn load_crs_from_filepath(&self, filepath: &str) -> Result<Self::CRS, Error>;
    fn gen_keys(&self, crs: &Self::CRS) -> Result<(Self::SigningKey, Self::VerifyingKey), Error>;
    fn gen_time_random_point(
        &self,
        vk: &Self::VerifyingKey,
        time: Self::TimeEpoch,
    ) -> Result<Self::TimeRandomPoint, Error>;
    fn digest(
        &self,
        crs: &Self::CRS,
        signing_targets: &[Self::SigningTarget],
    ) -> Result<Self::SvdDigest, Error>;
    fn sign(
        &self,
        sk: &Self::SigningKey,
        crs: &Self::CRS,
        digest: &Self::SvdDigest,
        time: Self::TimeEpoch,
    ) -> Result<Self::Signature, Error>;
    fn open(
        &self,
        crs: &Self::CRS,
        signing_targets: &[Self::SigningTarget],
        index: u64,
    ) -> Result<Self::Opening, Error>;

    fn verify(
        &self,
        crs: &Self::CRS,
        vk: &Self::VerifyingKey,
        time: Self::TimeEpoch,
        index: u64,
        signing_target: &Self::SigningTarget,
        signature: &Self::Signature,
        opening: &Self::Opening,
    ) -> Result<bool, Error>;
}
