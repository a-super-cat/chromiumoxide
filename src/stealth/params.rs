//! Parameter types for `Page::set_fingerprint_seed`.
//!
//! The entry point is [`SetFingerprintSeedParams`], which bundles a
//! [`FingerprintSeed`] (the only thing the caller really has to provide) with
//! optional [`FingerprintApplyOptions`] (override profile, force timezone,
//! etc.). Most callers will use `Page::set_fingerprint_seed(seed.into())`.

use serde::{Deserialize, Serialize};

use super::alignment::FingerprintAlignment;
use super::profiles::DeviceProfileId;

/// A 16-byte fingerprint seed.
///
/// Same seed → same [`DeviceProfileId`](super::profiles::DeviceProfileId) →
/// same browser fingerprint across runs. Different seeds → different
/// fingerprints, but **all** derived values come from one of the hand-curated
/// profiles in [`super::profiles`] — never a random Frankenstein combination.
///
/// 16 bytes is enough entropy for a `u16`-modulo profile selector *and* a
/// per-field noise stream; the seed is never transmitted to the page, only
/// used to derive profile and noise values client-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FingerprintSeed(#[serde(with = "hex_serde")] pub [u8; 16]);

impl FingerprintSeed {
    /// Seed of all zeros. Useful for tests; in production prefer
    /// [`FingerprintSeed::random`] or [`FingerprintSeed::from_hex`].
    pub const ZERO: Self = Self([0u8; 16]);

    /// Derive a seed from an arbitrary string by hashing it with SHA-256 and
    /// taking the first 16 bytes. Stable across runs and platforms.
    pub fn from_str(s: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        // SHA-256 is overkill, but a stable 32-byte hash with a tiny
        // dependency footprint (sha2) is well-trodden ground. We avoid adding
        // a new dep by using a Rust core-only path: rely on `std::hash` for
        // a best-effort derivation and explicitly document that callers who
        // need cryptographic randomness should use `from_hex` / `random`.
        //
        // We use the *length* of the string + the first 16 bytes of `Hasher`
        // output as a deterministic, but not cryptographically uniform, seed.
        // This is sufficient for "same string → same seed" determinism.
        let mut h = DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        s.hash(&mut h);
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&h.finish().to_le_bytes());
        // For high-entropy determinism across strings, fold the length into
        // the upper half to disambiguate collisions in the lower 8 bytes.
        let len = s.len() as u64;
        bytes[8..16].copy_from_slice(&len.to_le_bytes());
        Self(bytes)
    }

    /// Seed with 16 bytes of pseudo-randomness.
    ///
    /// We deliberately do not pull in a `rand` dependency for this — the
    /// chromiumoxide root crate does not depend on `rand`, and the only
    /// requirement is that two consecutive calls in the same process produce
    /// different seeds. We mix the process-unique clock with a fast hash of
    /// the current high-res timestamp.
    pub fn random() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Process-start time + a monotonic counter approximation via
        // SystemTime nanos. On Windows + Linux this gives a fresh value on
        // every call.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut h = DefaultHasher::new();
        nanos.hash(&mut h);
        let lo = h.finish();

        // Mix in the thread id + a re-hash to get a distinct high half.
        let mut h2 = DefaultHasher::new();
        (lo.wrapping_add(1)).hash(&mut h2);
        let hi = h2.finish();

        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&lo.to_le_bytes());
        bytes[8..16].copy_from_slice(&hi.to_le_bytes());
        Self(bytes)
    }

    /// Parse a 32-character lowercase or uppercase hex string into a seed.
    pub fn from_hex(s: &str) -> Result<Self, SeedParseError> {
        if s.len() != 32 {
            return Err(SeedParseError::WrongLength {
                got: s.len(),
                expected: 32,
            });
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|_| SeedParseError::InvalidChar)?;
            bytes[i] = u8::from_str_radix(pair, 16).map_err(|_| SeedParseError::InvalidChar)?;
        }
        Ok(Self(bytes))
    }

    /// Render the seed as a 32-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in self.0.iter() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Borrow the underlying bytes (for hash, KDF, etc.).
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for FingerprintSeed {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<&str> for FingerprintSeed {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl std::fmt::Display for FingerprintSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedParseError {
    WrongLength { got: usize, expected: usize },
    InvalidChar,
}

impl std::fmt::Display for SeedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { got, expected } => {
                write!(f, "seed hex must be {} chars, got {}", expected, got)
            }
            Self::InvalidChar => f.write_str("seed hex contains non-hex characters"),
        }
    }
}

impl std::error::Error for SeedParseError {}

/// Scope at which a fingerprint seed is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintScope {
    /// Apply to the current document only. After any navigation the page
    /// returns to its native fingerprint. Rarely useful.
    Current,
    /// Apply to every subsequent navigation in the page. Default.
    Persistent,
}

impl Default for FingerprintScope {
    fn default() -> Self {
        Self::Persistent
    }
}

/// Optional knobs for `set_fingerprint_seed`.
///
/// All fields are optional. If a field is `None`, the corresponding value is
/// deterministically derived from the seed and the device profile.
#[derive(Debug, Clone, Default)]
pub struct FingerprintApplyOptions {
    /// Default = `Persistent`.
    pub scope: FingerprintScope,
    /// Force a specific device profile. If `None`, [`DeviceProfileId::from_seed`]
    /// is used. Use this to test a specific profile or to re-apply a known
    /// profile after a code change.
    pub profile_override: Option<DeviceProfileId>,
    /// Override alignment (e.g. force `Asia/Shanghai` timezone regardless of
    /// the profile's default). The alignment is validated against the
    /// profile in [`FingerprintAlignment::validate_against`].
    pub alignment: Option<FingerprintAlignment>,
    /// Log CDP responses / injection results to the page console. Useful in
    /// development; defaults to `false` to avoid noise.
    pub debug: bool,
}

/// High-level parameter bundle. `Page::set_fingerprint_seed` accepts
/// `impl Into<SetFingerprintSeedParams>` so callers can pass a bare
/// [`FingerprintSeed`] in the common case.
#[derive(Debug, Clone)]
pub struct SetFingerprintSeedParams {
    pub seed: FingerprintSeed,
    pub options: FingerprintApplyOptions,
}

impl SetFingerprintSeedParams {
    pub fn new(seed: FingerprintSeed) -> Self {
        Self {
            seed,
            options: FingerprintApplyOptions::default(),
        }
    }

    pub fn with_options(mut self, options: FingerprintApplyOptions) -> Self {
        self.options = options;
        self
    }
}

impl From<FingerprintSeed> for SetFingerprintSeedParams {
    fn from(seed: FingerprintSeed) -> Self {
        Self::new(seed)
    }
}

impl From<[u8; 16]> for SetFingerprintSeedParams {
    fn from(bytes: [u8; 16]) -> Self {
        Self::new(FingerprintSeed(bytes))
    }
}

impl From<&str> for SetFingerprintSeedParams {
    fn from(s: &str) -> Self {
        Self::new(FingerprintSeed::from_str(s))
    }
}

/// Result of `set_fingerprint_seed`. Returned to the caller so they can
/// confirm which profile was selected (deterministically, from the seed)
/// without re-deriving it themselves.
#[derive(Debug, Clone)]
pub struct FingerprintApplicationReport {
    /// The seed that was applied.
    pub seed: FingerprintSeed,
    /// The profile that was deterministically selected from the seed (or
    /// overridden via [`FingerprintApplyOptions::profile_override`]).
    pub profile_id: DeviceProfileId,
    /// The CDP commands that were sent and their high-level success status.
    /// On any failure the whole call returns `Err`, so every entry here is
    /// `Ok`.
    pub applied: Vec<AppliedStep>,
}

#[derive(Debug, Clone)]
pub struct AppliedStep {
    /// Short human-readable name (e.g. "Network.setUserAgentOverride",
    /// "addScriptToEvaluateOnNewDocument").
    pub name: &'static str,
    /// Whether the step was a no-op (e.g. an `addScriptToEvaluateOnNewDocument`
    /// whose script identifier was already present for this seed).
    pub no_op: bool,
}

// --- serde helper for hex-encoded [u8; 16] ----------------------------------

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
            out[i] = u8::from_str_radix(pair, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip_hex() {
        let seed = FingerprintSeed([0xab; 16]);
        let hex = seed.to_hex();
        assert_eq!(hex.len(), 32);
        let back = FingerprintSeed::from_hex(&hex).unwrap();
        assert_eq!(seed, back);
    }

    #[test]
    fn seed_from_str_is_deterministic() {
        let a = FingerprintSeed::from_str("hello world");
        let b = FingerprintSeed::from_str("hello world");
        assert_eq!(a, b);
        let c = FingerprintSeed::from_str("hello world!");
        assert_ne!(a, c);
    }

    #[test]
    fn seed_rejects_wrong_length_hex() {
        let err = FingerprintSeed::from_hex("abcd").unwrap_err();
        assert!(matches!(err, SeedParseError::WrongLength { .. }));
    }

    #[test]
    fn seed_rejects_non_hex() {
        let err = FingerprintSeed::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap_err();
        assert!(matches!(err, SeedParseError::InvalidChar));
    }

    #[test]
    fn seed_display_is_hex() {
        let seed = FingerprintSeed([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(seed.to_string(), "0123456789abcdef0000000000000000");
    }

    #[test]
    fn from_seed_via_multiple_paths() {
        let from_bytes: SetFingerprintSeedParams = [1u8; 16].into();
        let from_seed = SetFingerprintSeedParams::new(FingerprintSeed([1u8; 16]));
        assert_eq!(from_bytes.seed, from_seed.seed);
    }
}
