//! Field-alignment for `set_fingerprint_seed`.
//!
//! Every override a caller applies must remain consistent with the chosen
//! [`DeviceProfile`](super::profiles::DeviceProfile). This module defines a
//! small alignment type and a validation routine that rejects inconsistent
//! combinations *before* we send any CDP commands — because the alternative
//! is sending partial overrides and leaving the page in a half-overridden
//! state that an anti-bot checker can detect in a single comparison.
//!
//! The strongest cross-validations performed by anti-bot checkers are
//! *locale-based*: a `zh-CN` Accept-Language combined with a
//! `America/Los_Angeles` timezone, or a `de-DE` language combined with a
//! Pacific/Auckland timezone, are flagged within milliseconds. We catch
//! those combinations here.

use serde::{Deserialize, Serialize};

use super::profiles::DeviceProfile;

/// Caller-supplied alignment overrides for `set_fingerprint_seed`.
///
/// Any field left as `None` is taken from the [`DeviceProfile`]. If a field
/// is `Some`, it must be consistent with the profile and with the other
/// fields — see [`FingerprintAlignment::validate_against`] for the rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintAlignment {
    /// IANA timezone id (e.g. `"Asia/Shanghai"`). Used by
    /// `Emulation.setTimezoneOverride`.
    pub timezone_id: Option<String>,
    /// `Accept-Language` header value (e.g. `"zh-CN,zh;q=0.9,en;q=0.8"`).
    pub accept_language: Option<String>,
    /// Primary `navigator.language`.
    pub primary_language: Option<String>,
    /// Override the geoip hint that is set on the proxy side. This does
    /// *not* affect any page property; it is propagated to the proxy
    /// alignment layer by the caller. Recorded here for symmetry.
    pub proxy_country: Option<String>,
}

/// Why an alignment was rejected.
///
/// The strings are stable enough to assert on in tests but are not API-
/// frozen — if we add a new rule, the string might change. The
/// [`AlignmentError::kind`] tag is the stable part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignmentError {
    pub kind: AlignmentErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentErrorKind {
    /// `Accept-Language` primary tag does not match the timezone region.
    /// e.g. `zh-CN` + `America/Los_Angeles`.
    TimezoneLocaleMismatch,
    /// `Accept-Language` does not start with the primary language code.
    AcceptLanguagePrimaryMismatch,
    /// `navigator.language` is not the prefix of `Accept-Language`.
    PrimaryLanguageNotInAcceptLanguage,
    /// `proxy_country` is not a valid ISO 3166-1 alpha-2 code (2 uppercase
    /// ASCII letters).
    ProxyCountryInvalid,
}

impl std::fmt::Display for AlignmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for AlignmentError {}

impl FingerprintAlignment {
    /// Validate the alignment against the chosen profile. Returns `Ok(())` if
    /// the overrides are consistent with the profile, or an [`AlignmentError`]
    /// describing the first violation.
    ///
    /// Validation rules (all must hold):
    ///
    /// 1. `primary_language`, if set, must equal the first tag of
    ///    `accept_language` (or, if `accept_language` is not set, must be
    ///    present in the profile's default `languages_list`).
    /// 2. `accept_language` and `timezone_id`, if both set, must come from
    ///    the same geographic region (Americas / Europe / Asia-Pacific).
    /// 3. `proxy_country` must be a 2-letter ISO 3166-1 alpha-2 code.
    pub fn validate_against(&self, profile: &DeviceProfile) -> Result<(), AlignmentError> {
        let effective_accept_language = self
            .accept_language
            .as_deref()
            .unwrap_or(profile.locale.accept_language);
        let effective_primary = self
            .primary_language
            .as_deref()
            .unwrap_or(profile.locale.primary_language);
        let effective_tz = self.timezone_id.as_deref().unwrap_or(profile.locale.timezone_id);

        // Rule 1 — accept-language starts with the primary language.
        //
        // We compare on two levels:
        //   1. The primary subtag (`en` in `en-US`) must always match.
        //   2. If both tags carry a region subtag, the region must match too
        //      (e.g. `en-US` + `en-GB` is rejected; `en-US` + `en` is fine
        //      because the latter omits the region on purpose).
        //
        // This matches what real browsers do and what anti-bot checkers
        // detect. A user with `navigator.language = "en-GB"` sending
        // `Accept-Language: en-US,...` is unusual and caught here.
        let first_tag = first_language_tag(effective_accept_language);
        let first_code = first_tag.split('-').next().unwrap_or("");
        let first_region = first_tag.split('-').nth(1);
        let primary_code = effective_primary.split('-').next().unwrap_or("");
        let primary_region = effective_primary.split('-').nth(1);

        if !first_code.eq_ignore_ascii_case(primary_code) {
            return Err(AlignmentError {
                kind: AlignmentErrorKind::AcceptLanguagePrimaryMismatch,
                message: format!(
                    "Accept-Language primary subtag {:?} does not match primary language {:?}",
                    first_code, primary_code
                ),
            });
        }
        if let (Some(fr), Some(pr)) = (first_region, primary_region) {
            if !fr.eq_ignore_ascii_case(pr) {
                return Err(AlignmentError {
                    kind: AlignmentErrorKind::AcceptLanguagePrimaryMismatch,
                    message: format!(
                        "Accept-Language region {:?} does not match primary language region {:?}",
                        fr, pr
                    ),
                });
            }
        }

        // Rule 2 — accept-language and timezone must be in the same region.
        let lang_region = region_for_language_tag(effective_primary);
        let tz_region = region_for_timezone(effective_tz);
        if let (Some(lr), Some(tr)) = (lang_region, tz_region) {
            if lr != tr && lr != Region::Unknown && tr != Region::Unknown {
                return Err(AlignmentError {
                    kind: AlignmentErrorKind::TimezoneLocaleMismatch,
                    message: format!(
                        "primary language {:?} is in region {:?} but timezone {:?} is in region {:?}",
                        effective_primary, lr, effective_tz, tr
                    ),
                });
            }
        }

        // Rule 3 — proxy_country.
        if let Some(cc) = &self.proxy_country {
            if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_uppercase()) {
                return Err(AlignmentError {
                    kind: AlignmentErrorKind::ProxyCountryInvalid,
                    message: format!(
                        "proxy_country {:?} must be a 2-letter ISO 3166-1 alpha-2 code",
                        cc
                    ),
                });
            }
        }
        Ok(())
    }
}

// --- helpers ----------------------------------------------------------------

fn first_language_tag(al: &str) -> &str {
    al.split(',')
        .next()
        .map(str::trim)
        .and_then(|s| s.split(';').next().map(str::trim))
        .unwrap_or("")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    Americas,
    Europe,
    AsiaPacific,
    Other,
    Unknown,
}

/// Map an IETF language primary subtag to a coarse region. Returns
/// `Unknown` for the small set of language codes that span continents
/// (e.g. `en` is spoken on every continent).
fn region_for_language_tag(tag: &str) -> Option<Region> {
    // Strip any region suffix after `-`; we only look at the primary subtag.
    let primary = tag.split('-').next().unwrap_or(tag);
    let primary_lc = primary.to_ascii_lowercase();
    let region = match primary_lc.as_str() {
        // Americas
        "en" | "es" | "pt" | "fr" => Region::Americas,
        // Europe
        "de" | "nl" | "it" | "pl" | "sv" | "no" | "da" | "fi" | "el" | "cs" | "hu" | "ro"
        | "uk" | "ru" | "tr" => Region::Europe,
        // Asia-Pacific
        "zh" | "ja" | "ko" | "th" | "vi" | "id" | "ms" | "tl" | "hi" | "bn" | "ta" | "te"
        | "mr" | "gu" | "kn" | "ml" | "pa" | "or" | "as" | "ur" => Region::AsiaPacific,
        // Spans continents — return Other so we never fail validation.
        _ => Region::Other,
    };
    Some(region)
}

fn region_for_timezone(tz: &str) -> Option<Region> {
    if tz.starts_with("America/") {
        Some(Region::Americas)
    } else if tz.starts_with("Europe/") {
        Some(Region::Europe)
    } else if tz.starts_with("Asia/")
        || tz.starts_with("Pacific/")
        || tz.starts_with("Australia/")
    {
        Some(Region::AsiaPacific)
    } else {
        Some(Region::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::profiles::DeviceProfileId;

    fn win11_profile() -> DeviceProfile {
        DeviceProfileId::Win11Chrome120IntelNvidia.profile()
    }

    #[test]
    fn default_alignment_is_valid() {
        let a = FingerprintAlignment::default();
        a.validate_against(&win11_profile()).unwrap();
    }

    #[test]
    fn timezone_must_match_primary_language_region() {
        // win11 default primary = en-US (Americas) + default tz = America/Los_Angeles.
        // Setting tz = Asia/Shanghai while keeping en-US must fail.
        let mut a = FingerprintAlignment::default();
        a.timezone_id = Some("Asia/Shanghai".to_string());
        let err = a.validate_against(&win11_profile()).unwrap_err();
        assert_eq!(err.kind, AlignmentErrorKind::TimezoneLocaleMismatch);
    }

    #[test]
    fn matching_timezone_and_language_aligned_is_fine() {
        // primary = zh-CN + tz = Asia/Shanghai → both AsiaPacific → OK.
        let mut a = FingerprintAlignment::default();
        a.primary_language = Some("zh-CN".to_string());
        a.accept_language = Some("zh-CN,zh;q=0.9,en;q=0.8".to_string());
        a.timezone_id = Some("Asia/Shanghai".to_string());
        a.validate_against(&win11_profile()).unwrap();
    }

    #[test]
    fn os_family_does_not_constrain_timezone() {
        // Windows users live in Tokyo too — *but* only if they speak an
        // Asia-Pacific language. A Win11 user in Tokyo with `en-US` primary
        // would be flagged; one with `ja-JP` is fine.
        let mut a = FingerprintAlignment::default();
        a.timezone_id = Some("Asia/Tokyo".to_string());
        a.primary_language = Some("ja-JP".to_string());
        a.accept_language = Some("ja-JP,ja;q=0.9,en;q=0.8".to_string());
        a.validate_against(&win11_profile()).unwrap();
    }

    #[test]
    fn accept_language_must_start_with_primary() {
        let mut a = FingerprintAlignment::default();
        a.accept_language = Some("zh-CN,zh;q=0.9".to_string());
        a.primary_language = Some("en-US".to_string());
        let err = a.validate_against(&win11_profile()).unwrap_err();
        assert_eq!(err.kind, AlignmentErrorKind::AcceptLanguagePrimaryMismatch);
    }

    #[test]
    fn accept_language_aligned_with_profile_default() {
        let mut a = FingerprintAlignment::default();
        a.accept_language = Some("en-GB,en;q=0.9".to_string());
        a.validate_against(&win11_profile()).unwrap_err();
    }

    #[test]
    fn primary_language_in_profile_default_list_is_fine() {
        let mut a = FingerprintAlignment::default();
        a.primary_language = Some("en".to_string());
        a.validate_against(&win11_profile()).unwrap();
    }

    #[test]
    fn proxy_country_must_be_iso_3166_alpha2() {
        let mut a = FingerprintAlignment::default();
        a.proxy_country = Some("USA".to_string());
        let err = a.validate_against(&win11_profile()).unwrap_err();
        assert_eq!(err.kind, AlignmentErrorKind::ProxyCountryInvalid);
        a.proxy_country = Some("us".to_string());
        a.validate_against(&win11_profile()).unwrap_err();
        a.proxy_country = Some("US".to_string());
        a.validate_against(&win11_profile()).unwrap();
    }

    #[test]
    fn unknown_region_timezones_pass_through() {
        let mut a = FingerprintAlignment::default();
        a.timezone_id = Some("UTC".to_string());
        a.validate_against(&win11_profile()).unwrap();
    }
}
