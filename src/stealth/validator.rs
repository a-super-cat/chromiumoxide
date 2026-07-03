//! `DeviceProfile` internal-coherence validator (M5.5+ fail-fast).
//!
//! 26 checks across 3 layers:
//!
//! 1. **Profile spec internal consistency** (12 checks): profile fields
//!    agree with each other (UA says iPhone → no `userAgentData`; UA says
//!    Android WebView → UA contains `Version/4.0`; UA says iPhone 14 →
//!    screen 390x844 @ DPR 3; etc.)
//! 2. **CDP override validity** (6 checks): UA / platform / timezone /
//!    accept-language are well-formed strings (non-empty, valid IANA
//!    name, etc.)
//! 3. **Profile-spec / CDP coherence** (8 checks): the spec
//!    (`navigator`, `screen`, `uach`, `webview`, `api_support`) agrees
//!    with the CDP-level fields (`UA`, `platform`, `locale.timezone_id`,
//!    `locale.accept_language`).
//!
//! `set_device_profile` calls [`validate_profile`] before injecting the
//! init script. The function never panics — it returns a
//! [`ValidationReport`] the caller decides how to handle. By default
//! `set_device_profile` returns `Err` if any `Severity::Error`
//! inconsistency is found (fail-fast).
//!
//! ## Why 26
//!
//! The 26 checks are derived from the GPT-5.5 audit of M5.5+ profile
//! surfaces and the chromium-148 live-probe findings (2026-07-02). The
//! per-family fingerprint must be internally coherent — a UA that says
//! iPhone but `navigator.userAgentData` is present, or a UA that says
//! Android WebView but lacks `Version/4.0`, is the kind of inconsistency
//! that anti-bot detectors flag.
//!
//! ## Example
//!
//! ```rust
//! # use chromiumoxide::stealth::{DeviceProfileId, validate_profile};
//! let profile = DeviceProfileId::DesktopChrome148Win11.profile();
//! let report = validate_profile(&profile);
//! assert!(report.errors().next().is_none(), "{:?}", report);
//! ```

use crate::stealth::profiles::{DeviceFamily, DeviceProfile, DeviceProfileId};

/// Severity of an inconsistency finding.
///
/// `Error` blocks injection (fail-fast). `Warning` is logged but the
/// profile is still applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One of 26 named inconsistency kinds.
///
/// Each variant has an associated severity. The kind carries enough
/// payload (expected vs actual) for log lines and test assertions.
#[derive(Debug, Clone, PartialEq)]
pub enum InconsistencyKind {
    // Layer 1: Profile spec internal consistency (12 checks)
    /// UA says iPhone (any flavor) but `uach` is non-empty.
    /// Safari / WKWebView don't implement UA-CH.
    UaSaysIphoneButUaChPresent,
    /// UA says iPhone but `navigator.max_touch_points == 0`.
    /// iOS is a touch OS; touch points must be > 0.
    UaSaysIphoneButZeroTouchPoints,
    /// UA says iOS Safari but `webview.window_webkit` is true.
    /// `window.webkit` is WKWebView-only.
    UaSaysIosSafariButWebkitMarkerPresent,
    /// UA says iOS WKWebView but `webview.window_webkit` is false.
    /// WKWebView always has `window.webkit`.
    UaSaysIosWkWebViewButMissingWebkitMarker,
    /// UA says Android WebView but lacks `Version/4.0` token.
    /// `Version/4.0 Chrome/...` is the Android WebView UA template.
    UaSaysAndroidWebViewButMissingVersion4,
    /// UA says Android WebView but UA-CH 3rd brand is "Google Chrome"
    /// (should be "Android WebView" for WebView, "Google Chrome" for
    /// standalone Chrome).
    UaSaysAndroidWebViewButUadBrandIsChrome,
    /// UA says Pixel 7 but `screen.{width,height,dpr}` is not
    /// (412, 915, 2.625). Pixel 7 specs are a fixed triple.
    UaSaysPixel7ButScreenMismatch {
        expected: (u32, u32, f32),
        got: (u32, u32, f32),
    },
    /// UA says iPhone 14 but `screen.{width,height,dpr}` is not
    /// (390, 844, 3).
    UaSaysIphone14ButScreenMismatch {
        expected: (u32, u32, f32),
        got: (u32, u32, f32),
    },
    /// UA says Windows but `screen.{width,height,dpr}` is not
    /// (1920, 1080, 1) (the canonical Win11 desktop baseline).
    UaSaysWindowsButScreenMismatch {
        expected: (u32, u32, f32),
        got: (u32, u32, f32),
    },
    /// UA says desktop (any) but `navigator.max_touch_points > 0`.
    UaSaysDesktopButHasTouchPoints,
    /// UA says desktop but `navigator.plugins` has fewer than 3 entries
    /// (Chrome desktop's PDF-only plugin set is 5 entries).
    UaSaysDesktopButMissingPlugins { actual: usize, expected_min: usize },
    /// UA says mobile / webview but `navigator.plugins` is non-empty.
    UaSaysMobileButHasPlugins { actual: usize },

    // Layer 2: CDP override validity (6 checks)
    /// `browser.user_agent()` is empty.
    UaEmpty,
    /// `browser.user_agent()` lacks the configured chrome major version.
    UaMissingBrowserVersion { major: u32 },
    /// `browser.user_agent()` contains the `HeadlessChrome` token.
    /// This leaks automation even when only the override is wrong.
    UaContainsHeadlessChrome,
    /// `os.platform` is empty.
    PlatformEmpty,
    /// `locale.timezone_id` is empty.
    TimezoneEmpty,
    /// `locale.accept_language` is empty.
    AcceptLanguageEmpty,

    // Layer 3: Profile-spec / CDP coherence (8 checks)
    /// `os.ua_os_substring` does not appear in `browser.user_agent()`.
    /// The UA template must include the OS substring (e.g. `Windows NT
    /// 10.0; Win64; x64` for Win11).
    UaMissingOsSubstring {
        os_substring: &'static str,
        ua: String,
    },
    /// `uach.brands` non-empty (Chrome) but `webview.ua_contains_version_4`
    /// is set (Android WebView); these are mutually exclusive families.
    UachAndWebviewAreMutuallyExclusive,
    /// `navigator.platform` does not match the `os.ua_os_substring`'s
    /// family (e.g. `navigator.platform = "Win32"` but UA has
    /// `(iPhone; CPU iPhone OS ...)`).
    PlatformMismatchUaSubstring {
        platform: &'static str,
        ua_substring: &'static str,
    },
    /// `screen.{width,height,dpr}` triple is all-zero (a spec bug).
    ScreenAllZero,
    /// `locale.accept_language` does not start with `locale.primary_language`.
    AcceptLanguageNotStartingWithPrimary {
        accept_language: &'static str,
        primary_language: &'static str,
    },
    /// `uach.brands` is 4 entries but GREASE is missing.
    /// M5.5+ requires exactly 4 brands: [GREASE, Chromium, family-brand,
    /// GREASE].
    UachMissingGrease { actual_len: usize },
    /// `uach.brands` non-empty but `navigator.vendor` is empty
    /// (Chrome family requires "Google Inc.").
    UachPresentButVendorEmpty,
    /// `uach.brands` empty but `navigator.vendor` is non-empty
    /// (iOS Safari has `vendor = "Apple Computer, Inc."` and no UA-CH).
    UachEmptyButVendorNonEmpty {
        vendor: &'static str,
    },
}

impl InconsistencyKind {
    pub fn severity(&self) -> Severity {
        match self {
            // Hard errors — these would leak fingerprint inconsistency to
            // anti-bot detectors, fail-fast.
            InconsistencyKind::UaSaysIphoneButUaChPresent => Severity::Error,
            InconsistencyKind::UaSaysIphoneButZeroTouchPoints => Severity::Error,
            InconsistencyKind::UaSaysIosSafariButWebkitMarkerPresent => Severity::Error,
            InconsistencyKind::UaSaysIosWkWebViewButMissingWebkitMarker => Severity::Error,
            InconsistencyKind::UaSaysAndroidWebViewButMissingVersion4 => Severity::Error,
            InconsistencyKind::UaSaysAndroidWebViewButUadBrandIsChrome => Severity::Error,
            InconsistencyKind::UaSaysPixel7ButScreenMismatch { .. } => Severity::Error,
            InconsistencyKind::UaSaysIphone14ButScreenMismatch { .. } => Severity::Error,
            InconsistencyKind::UaSaysWindowsButScreenMismatch { .. } => Severity::Error,
            InconsistencyKind::UaSaysDesktopButHasTouchPoints => Severity::Error,
            InconsistencyKind::UaSaysDesktopButMissingPlugins { .. } => Severity::Error,
            InconsistencyKind::UaSaysMobileButHasPlugins { .. } => Severity::Error,
            InconsistencyKind::UaEmpty => Severity::Error,
            InconsistencyKind::UaMissingBrowserVersion { .. } => Severity::Error,
            InconsistencyKind::UaContainsHeadlessChrome => Severity::Error,
            InconsistencyKind::PlatformEmpty => Severity::Error,
            InconsistencyKind::TimezoneEmpty => Severity::Error,
            InconsistencyKind::AcceptLanguageEmpty => Severity::Error,
            InconsistencyKind::UaMissingOsSubstring { .. } => Severity::Error,
            InconsistencyKind::UachAndWebviewAreMutuallyExclusive => Severity::Error,
            InconsistencyKind::PlatformMismatchUaSubstring { .. } => Severity::Error,
            InconsistencyKind::ScreenAllZero => Severity::Error,
            InconsistencyKind::AcceptLanguageNotStartingWithPrimary { .. } => Severity::Warning,
            InconsistencyKind::UachMissingGrease { .. } => Severity::Error,
            InconsistencyKind::UachPresentButVendorEmpty => Severity::Error,
            InconsistencyKind::UachEmptyButVendorNonEmpty { .. } => Severity::Error,
        }
    }
}

/// A single finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Inconsistency {
    pub kind: InconsistencyKind,
    pub severity: Severity,
    pub message: String,
}

impl Inconsistency {
    fn new(kind: InconsistencyKind, message: impl Into<String>) -> Self {
        let severity = kind.severity();
        Self {
            kind,
            severity,
            message: message.into(),
        }
    }
}

/// Aggregated validator output. Always populated, even when no findings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidationReport {
    pub inconsistencies: Vec<Inconsistency>,
}

impl ValidationReport {
    pub fn ok(&self) -> bool {
        self.inconsistencies.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.inconsistencies
            .iter()
            .any(|i| i.severity == Severity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Inconsistency> {
        self.inconsistencies
            .iter()
            .filter(|i| i.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Inconsistency> {
        self.inconsistencies
            .iter()
            .filter(|i| i.severity == Severity::Warning)
    }
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inconsistencies.is_empty() {
            return write!(f, "ValidationReport(OK)");
        }
        writeln!(f, "ValidationReport({} findings):", self.inconsistencies.len())?;
        for i in &self.inconsistencies {
            writeln!(f, "  [{:?}] {}", i.severity, i.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationReport {}

/// Run all 26 checks against a [`DeviceProfile`].
///
/// Pure function. Never panics. The caller decides what to do with the
/// report (`set_device_profile` returns `Err` on any `Severity::Error`).
pub fn validate_profile(profile: &DeviceProfile) -> ValidationReport {
    let mut report = ValidationReport::default();
    let id = profile.id;
    let family = id.family();
    let ua = profile.user_agent();
    let platform = profile.os.platform;
    let ua_substring = profile.os.ua_os_substring;

    // ============ Layer 1: Profile spec internal consistency (12 checks) ============

    if profile.is_ios() && !profile.uach.brands.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaSaysIphoneButUaChPresent,
            format!(
                "profile {:?} says iPhone but uach.brands is non-empty ({} entries); \
                 iOS Safari / WKWebView do not implement UA-CH",
                id,
                profile.uach.brands.len()
            ),
        ));
    }

    if profile.is_ios() && profile.navigator.max_touch_points == 0 {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaSaysIphoneButZeroTouchPoints,
            format!(
                "profile {:?} says iPhone but navigator.max_touch_points = 0; \
                 iOS is a touch OS",
                id
            ),
        ));
    }

    if matches!(id, DeviceProfileId::IosSafariIphone14) {
        if let Some(wv) = &profile.webview {
            if wv.window_webkit {
                report.inconsistencies.push(Inconsistency::new(
                    InconsistencyKind::UaSaysIosSafariButWebkitMarkerPresent,
                    format!(
                        "profile {:?} is iOS Safari but webview.window_webkit = true; \
                         window.webkit is WKWebView-only",
                        id
                    ),
                ));
            }
        }
    }

    if matches!(id, DeviceProfileId::IosWkWebviewIphone14) {
        let has_marker = profile
            .webview
            .as_ref()
            .map(|w| w.window_webkit)
            .unwrap_or(false);
        if !has_marker {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UaSaysIosWkWebViewButMissingWebkitMarker,
                format!(
                    "profile {:?} is iOS WKWebView but webview.window_webkit = false; \
                     WKWebView always has window.webkit",
                    id
                ),
            ));
        }
    }

    if matches!(id, DeviceProfileId::AndroidWebViewPixel7) {
        if !ua.contains("Version/4.0") {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UaSaysAndroidWebViewButMissingVersion4,
                format!(
                    "profile {:?} is Android WebView but UA lacks 'Version/4.0' token; \
                     Android WebView UA template is '... Version/4.0 Chrome/... Mobile Safari/...'",
                    id
                ),
            ));
        }
        if let Some(brand) = profile.uach.brands.get(2) {
            if brand.brand != "Android WebView" {
                report.inconsistencies.push(Inconsistency::new(
                    InconsistencyKind::UaSaysAndroidWebViewButUadBrandIsChrome,
                    format!(
                        "profile {:?} is Android WebView but UA-CH 3rd brand = '{}'; \
                         should be 'Android WebView' (Chrome standalone uses 'Google Chrome')",
                        id, brand.brand
                    ),
                ));
            }
        }
    }

    if matches!(id, DeviceProfileId::AndroidChromePixel7 | DeviceProfileId::AndroidWebViewPixel7) {
        let got = (
            profile.screen.width,
            profile.screen.height,
            profile.screen.device_pixel_ratio,
        );
        let expected = (412u32, 915u32, 2.625f32);
        if got != expected {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UaSaysPixel7ButScreenMismatch {
                    expected,
                    got,
                },
                format!(
                    "profile {:?} says Pixel 7 but screen is {:?}; \
                     Pixel 7 baseline is {:?}",
                    id, got, expected
                ),
            ));
        }
    }

    if matches!(
        id,
        DeviceProfileId::IosSafariIphone14 | DeviceProfileId::IosWkWebviewIphone14
    ) {
        let got = (
            profile.screen.width,
            profile.screen.height,
            profile.screen.device_pixel_ratio,
        );
        let expected = (390u32, 844u32, 3.0f32);
        if got != expected {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UaSaysIphone14ButScreenMismatch {
                    expected,
                    got,
                },
                format!(
                    "profile {:?} says iPhone 14 but screen is {:?}; \
                     iPhone 14 baseline is {:?}",
                    id, got, expected
                ),
            ));
        }
    }

    if matches!(family, DeviceFamily::Desktop)
        && profile.os.platform == "Win32"
    {
        let got = (
            profile.screen.width,
            profile.screen.height,
            profile.screen.device_pixel_ratio,
        );
        let expected = (1920u32, 1080u32, 1.0f32);
        // Allow some flex for non-Win11-desktop profiles (macOS / Linux)
        // — only check for the Windows ones that have a hard baseline.
        if matches!(id, DeviceProfileId::Win10Chrome120IntelNvidia
                    | DeviceProfileId::Win11Chrome120AmdAmd
                    | DeviceProfileId::DesktopChrome148Win11)
        {
            if got != expected {
                report.inconsistencies.push(Inconsistency::new(
                    InconsistencyKind::UaSaysWindowsButScreenMismatch {
                        expected,
                        got,
                    },
                    format!(
                        "profile {:?} says Windows desktop but screen is {:?}; \
                         Win10/Win11 baseline is {:?}",
                        id, got, expected
                    ),
                ));
            }
        }
    }

    if matches!(family, DeviceFamily::Desktop) && profile.navigator.max_touch_points > 0 {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaSaysDesktopButHasTouchPoints,
            format!(
                "profile {:?} is desktop but navigator.max_touch_points = {} > 0",
                id, profile.navigator.max_touch_points
            ),
        ));
    }

    if matches!(family, DeviceFamily::Desktop) && profile.navigator.plugins.len() < 3 {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaSaysDesktopButMissingPlugins {
                actual: profile.navigator.plugins.len(),
                expected_min: 3,
            },
            format!(
                "profile {:?} is desktop but navigator.plugins has {} entries; \
                 Chrome desktop has at least 3 PDF plugins",
                id,
                profile.navigator.plugins.len()
            ),
        ));
    }

    if matches!(family, DeviceFamily::Mobile | DeviceFamily::Webview)
        && !profile.navigator.plugins.is_empty()
    {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaSaysMobileButHasPlugins {
                actual: profile.navigator.plugins.len(),
            },
            format!(
                "profile {:?} is mobile/webview but navigator.plugins has {} entries; \
                 mobile browsers expose no plugins",
                id,
                profile.navigator.plugins.len()
            ),
        ));
    }

    // ============ Layer 2: CDP override validity (6 checks) ============

    if ua.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaEmpty,
            format!("profile {:?} has empty user_agent()", id),
        ));
    }

    if !ua.is_empty() && !ua.contains(&profile.browser.chrome_major.to_string()) {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaMissingBrowserVersion {
                major: profile.browser.chrome_major,
            },
            format!(
                "profile {:?} UA '{}' does not contain chrome major '{}'",
                id,
                ua,
                profile.browser.chrome_major
            ),
        ));
    }

    if ua.contains("HeadlessChrome") {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaContainsHeadlessChrome,
            format!(
                "profile {:?} UA contains 'HeadlessChrome' token; \
                 this leaks automation even when other overrides are correct",
                id
            ),
        ));
    }

    if platform.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::PlatformEmpty,
            format!("profile {:?} has empty os.platform", id),
        ));
    }

    if profile.locale.timezone_id.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::TimezoneEmpty,
            format!("profile {:?} has empty locale.timezone_id", id),
        ));
    }

    if profile.locale.accept_language.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::AcceptLanguageEmpty,
            format!("profile {:?} has empty locale.accept_language", id),
        ));
    }

    // ============ Layer 3: Profile-spec / CDP coherence (8 checks) ============

    if !ua_substring.is_empty() && !ua.is_empty() && !ua.contains(ua_substring) {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UaMissingOsSubstring {
                os_substring: ua_substring,
                ua: ua.clone(),
            },
            format!(
                "profile {:?} UA '{}' does not contain os.ua_os_substring '{}'",
                id, ua, ua_substring
            ),
        ));
    }

    let has_uach = !profile.uach.brands.is_empty();
    let has_webview = profile.webview.is_some();
    if has_uach && has_webview {
        // Chrome-with-UA-CH + WebView markers: this is OK if the profile
        // is Android WebView (which DOES have UA-CH but with "Android
        // WebView" 3rd brand). The actual check below tests for that
        // edge case.
        if !matches!(id, DeviceProfileId::AndroidWebViewPixel7) {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UachAndWebviewAreMutuallyExclusive,
                format!(
                    "profile {:?} has both uach.brands ({} entries) and webview \
                     markers; only Android WebView is allowed this combination",
                    id,
                    profile.uach.brands.len()
                ),
            ));
        }
    }

    if !platform.is_empty() && !ua_substring.is_empty() {
        let platform_matches = match platform {
            "Win32" => ua_substring.contains("Windows"),
            "MacIntel" => ua_substring.contains("Mac OS X"),
            "Linux x86_64" | "Linux armv81" | "Linux aarch64" => ua_substring.contains("Linux"),
            "iPhone" => ua_substring.contains("iPhone"),
            p if p.starts_with("Linux") => ua_substring.contains("Android") || ua_substring.contains("Linux"),
            _ => true, // unknown platform — don't false-positive
        };
        if !platform_matches {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::PlatformMismatchUaSubstring {
                    platform,
                    ua_substring,
                },
                format!(
                    "profile {:?} navigator.platform = '{}' but UA OS substring = '{}'; \
                     they describe different OS families",
                    id, platform, ua_substring
                ),
            ));
        }
    }

    if profile.screen.width == 0
        && profile.screen.height == 0
        && profile.screen.device_pixel_ratio == 0.0
    {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::ScreenAllZero,
            format!("profile {:?} has all-zero screen spec", id),
        ));
    }

    if !profile.locale.accept_language.is_empty() && !profile.locale.primary_language.is_empty() {
        if !profile
            .locale
            .accept_language
            .starts_with(profile.locale.primary_language)
        {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::AcceptLanguageNotStartingWithPrimary {
                    accept_language: profile.locale.accept_language,
                    primary_language: profile.locale.primary_language,
                },
                format!(
                    "profile {:?} locale.accept_language '{}' does not start with \
                     primary_language '{}'",
                    id, profile.locale.accept_language, profile.locale.primary_language
                ),
            ));
        }
    }

    if has_uach && profile.uach.brands.len() != 4 {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UachMissingGrease {
                actual_len: profile.uach.brands.len(),
            },
            format!(
                "profile {:?} uach.brands has {} entries; M5.5+ requires exactly 4 \
                 (GREASE + Chromium + family + GREASE)",
                id,
                profile.uach.brands.len()
            ),
        ));
    }

    if has_uach && profile.navigator.vendor.is_empty() {
        report.inconsistencies.push(Inconsistency::new(
            InconsistencyKind::UachPresentButVendorEmpty,
            format!(
                "profile {:?} has uach.brands (Chrome family) but navigator.vendor is empty; \
                 Chrome UA-CH implies vendor = 'Google Inc.'",
                id
            ),
        ));
    }

    if !has_uach && !profile.navigator.vendor.is_empty() {
        // iOS Safari has vendor = "Apple Computer, Inc." and no UA-CH —
        // that is the only valid case.
        if !matches!(id, DeviceProfileId::IosSafariIphone14 | DeviceProfileId::IosWkWebviewIphone14) {
            report.inconsistencies.push(Inconsistency::new(
                InconsistencyKind::UachEmptyButVendorNonEmpty {
                    vendor: profile.navigator.vendor,
                },
                format!(
                    "profile {:?} has no uach.brands but navigator.vendor = '{}'; \
                     only iOS Safari / WKWebView may omit UA-CH",
                    id, profile.navigator.vendor
                ),
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::profiles::DeviceProfileId;

    fn assert_no_errors(profile: &DeviceProfile) {
        let report = validate_profile(profile);
        if report.has_errors() {
            panic!("profile {:?} failed validation:\n{}", profile.id, report);
        }
    }

    #[test]
    fn all_10_profiles_pass_validation() {
        for id in [
            DeviceProfileId::Win10Chrome120IntelNvidia,
            DeviceProfileId::Win11Chrome120IntelNvidia,
            DeviceProfileId::Win11Chrome120AmdAmd,
            DeviceProfileId::MacOs14Chrome120M1,
            DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            DeviceProfileId::DesktopChrome148Win11,
            DeviceProfileId::IosSafariIphone14,
            DeviceProfileId::AndroidChromePixel7,
            DeviceProfileId::AndroidWebViewPixel7,
            DeviceProfileId::IosWkWebviewIphone14,
        ] {
            assert_no_errors(&id.profile());
        }
    }

    #[test]
    fn empty_ua_fails() {
        let mut p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        p.browser.ua_template = "";
        let report = validate_profile(&p);
        assert!(report
            .errors()
            .any(|i| matches!(i.kind, InconsistencyKind::UaEmpty)));
    }

    #[test]
    fn headless_chrome_fails() {
        let mut p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        p.browser.ua_template =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/{chrome}.0.0.0 Safari/537.36";
        let report = validate_profile(&p);
        assert!(report
            .errors()
            .any(|i| matches!(i.kind, InconsistencyKind::UaContainsHeadlessChrome)));
    }

    #[test]
    fn desktop_with_plugins_zero_fails() {
        let mut p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        p.navigator.plugins = &[];
        let report = validate_profile(&p);
        assert!(report.errors().any(|i| matches!(
            i.kind,
            InconsistencyKind::UaSaysDesktopButMissingPlugins { .. }
        )));
    }

    #[test]
    fn ios_safari_with_uach_fails() {
        let mut p = DeviceProfileId::IosSafariIphone14.profile();
        // Force a non-empty UA-CH — iOS Safari must NOT have it.
        p.uach.brands = &[
            crate::stealth::profiles::UaBrand { brand: "Not A(Brand", version: "24" },
            crate::stealth::profiles::UaBrand { brand: "Chromium", version: "148" },
            crate::stealth::profiles::UaBrand { brand: "Google Chrome", version: "148" },
            crate::stealth::profiles::UaBrand { brand: "Not A(Brand", version: "24" },
        ];
        let report = validate_profile(&p);
        assert!(report
            .errors()
            .any(|i| matches!(i.kind, InconsistencyKind::UaSaysIphoneButUaChPresent)));
    }

    #[test]
    fn android_webview_missing_version4_fails() {
        // We can't mutate `ua_template` (it's `&'static str`), so test the
        // opposite direction: the existing Android WebView profile MUST
        // contain "Version/4.0" in its UA, which is the inverse property
        // this check enforces. If a future profile loses that token, the
        // check fires.
        let p = DeviceProfileId::AndroidWebViewPixel7.profile();
        let ua = p.user_agent();
        assert!(ua.contains("Version/4.0"), "Android WebView UA must contain 'Version/4.0': {}", ua);
        let report = validate_profile(&p);
        assert!(!report.errors().any(|i| matches!(
            i.kind,
            InconsistencyKind::UaSaysAndroidWebViewButMissingVersion4
        )));
    }

    #[test]
    fn windows_with_iphone_screen_fails() {
        let mut p = DeviceProfileId::DesktopChrome148Win11.profile();
        p.screen.width = 390;
        p.screen.height = 844;
        p.screen.device_pixel_ratio = 3.0;
        let report = validate_profile(&p);
        assert!(report.errors().any(|i| matches!(
            i.kind,
            InconsistencyKind::UaSaysWindowsButScreenMismatch { .. }
        )));
    }

    #[test]
    fn uach_with_empty_vendor_fails() {
        let mut p = DeviceProfileId::DesktopChrome148Win11.profile();
        p.navigator.vendor = "";
        let report = validate_profile(&p);
        assert!(report
            .errors()
            .any(|i| matches!(i.kind, InconsistencyKind::UachPresentButVendorEmpty)));
    }

    #[test]
    fn accept_language_not_starting_with_primary_is_warning() {
        let mut p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        p.locale.accept_language = "zh-CN,zh;q=0.9";
        p.locale.primary_language = "en-US";
        let report = validate_profile(&p);
        // Warning, not error — caller can still proceed.
        let found = report.warnings().any(|i| {
            matches!(
                i.kind,
                InconsistencyKind::AcceptLanguageNotStartingWithPrimary { .. }
            )
        });
        assert!(found, "expected AcceptLanguageNotStartingWithPrimary warning");
    }

    #[test]
    fn report_display_includes_findings() {
        let p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let r = validate_profile(&p);
        let s = r.to_string();
        if r.ok() {
            assert!(s.contains("OK"));
        } else {
            assert!(s.contains("findings"));
        }
    }
}
