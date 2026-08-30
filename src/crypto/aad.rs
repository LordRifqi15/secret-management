/// CanonicalAad — BSSN-compliant deterministic AAD encoding.
///
/// Binary format (deterministic, no JSON):
///   for each field in [tenant_id, purpose, key_id, algorithm]:
///     4-byte big-endian length || raw bytes
/// Total capacity 128 bytes (16 overhead + up to 112 payload).
/// `encode()` is deterministic; same inputs => same bytes.
pub struct CanonicalAad {
    pub tenant_id: String,
    pub purpose: String,
    pub key_id: String,
    pub algorithm: String,
}

impl CanonicalAad {
    pub fn new(
        tenant_id: impl Into<String>,
        purpose: impl Into<String>,
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            purpose: purpose.into(),
            key_id: key_id.into(),
            algorithm: algorithm.into(),
        }
    }

    /// Length-prefixed binary encoding.
    /// Capacity 128 — pre-allocates 128, does not grow beyond needed.
    pub fn encode(&self) -> Vec<u8> {
        // ponytail: Vec with capacity 128 avoids realloc for compliant inputs
        let mut out = Vec::with_capacity(128);
        for field in [&self.tenant_id, &self.purpose, &self.key_id, &self.algorithm] {
            let bytes = field.as_bytes();
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Minimal runnable check — asserts correct bytes, no test framework needed.
    pub fn demo() {
        // simple vector: "a","b","c","d"
        let aad = Self::new("a", "b", "c", "d");
        let enc = aad.encode();
        let expected: Vec<u8> = vec![
            0, 0, 0, 1, b'a', //
            0, 0, 0, 1, b'b', //
            0, 0, 0, 1, b'c', //
            0, 0, 0, 1, b'd', //
        ];
        assert_eq!(enc, expected);

        // deterministic check
        let aad2 = Self::new("tenant1", "encrypt", "primary", "aes256-gcm");
        let e1 = aad2.encode();
        let e2 = aad2.encode();
        assert_eq!(e1, e2);

        // longer example — verify length prefix correctness
        let aad3 = Self::new("tenant1", "encrypt", "primary", "aes256-gcm");
        let enc3 = aad3.encode();
        // manual construction
        let mut manual = Vec::with_capacity(128);
        for s in ["tenant1", "encrypt", "primary", "aes256-gcm"] {
            manual.extend_from_slice(&(s.len() as u32).to_be_bytes());
            manual.extend_from_slice(s.as_bytes());
        }
        assert_eq!(enc3, manual);
        assert!(enc3.len() <= 128, "capacity 128 exceeded");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_deterministic_and_prefixed() {
        CanonicalAad::demo();
    }
}
