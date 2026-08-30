use crate::crypto::traits::Hasher;
use digest::Digest;

pub struct Sha256;
pub struct Sha512;
pub struct Sha3_256;
pub struct Blake2b512;

impl Hasher for Sha256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(data).to_vec()
    }
}

impl Hasher for Sha512 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        sha2::Sha512::digest(data).to_vec()
    }
}

impl Hasher for Sha3_256 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        sha3::Sha3_256::digest(data).to_vec()
    }
}

impl Hasher for Blake2b512 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake2::Blake2b512::digest(data).to_vec()
    }
}

