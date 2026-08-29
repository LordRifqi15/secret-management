use hex::FromHex;
use std::env;

use super::keys::KeyEncryptionKey;

/// Load KEK from `APP_KEK` env var (32-byte hex string).
// ponytail: free function over trait/struct — one env var, one caller
pub fn load_kek() -> Result<KeyEncryptionKey, String> {
    let hex_val =
        env::var("APP_KEK").map_err(|_| "APP_KEK environment variable must be set".to_string())?;
    let bytes: [u8; 32] = <[u8; 32]>::from_hex(&hex_val)
        .map_err(|_| "APP_KEK must be a valid 32-byte hex string".to_string())?;
    Ok(KeyEncryptionKey::new(bytes))
}
