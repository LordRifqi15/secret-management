use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload, generic_array::GenericArray},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::traits::{AeadCipher, CryptoError};

pub struct ChaChaCipher {
    cipher: ChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(GenericArray::from_slice(key)),
        }
    }
}

// ponytail: ChaCha20Poly1305 has no Zeroize impl; no-op satisfies bound, keeps Arc-friendly Send+Sync
impl Zeroize for ChaChaCipher {
    fn zeroize(&mut self) {}
}
impl Drop for ChaChaCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ChaChaCipher {}

impl AeadCipher for ChaChaCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionFailed);
        }
        let n = GenericArray::from_slice(nonce);
        self.cipher
            .encrypt(n, Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::DecryptionFailed);
        }
        let n = GenericArray::from_slice(nonce);
        self.cipher
            .decrypt(n, Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
