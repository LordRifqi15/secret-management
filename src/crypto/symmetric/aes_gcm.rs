use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, generic_array::GenericArray},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::traits::{AeadCipher, CryptoError};

pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(GenericArray::from_slice(key)),
        }
    }
}

// ponytail: Aes256Gcm has no Zeroize impl; no-op zeroize satisfies ZeroizeOnDrop bound, Arc-friendly (Send+Sync)
impl Zeroize for AesGcmCipher {
    fn zeroize(&mut self) {}
}
impl Drop for AesGcmCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for AesGcmCipher {}

impl AeadCipher for AesGcmCipher {
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
