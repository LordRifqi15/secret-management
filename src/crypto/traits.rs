use zeroize::ZeroizeOnDrop;

pub use crate::domain::errors::CryptoError;

pub trait AeadCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

pub trait Signer: ZeroizeOnDrop {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait Verifier {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

pub trait KeyExchanger: ZeroizeOnDrop {
    fn public_key(&self) -> Vec<u8>;
    fn exchange(&self, peer_public: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// ponytail: sync only, no associated types — add when second impl needs them
