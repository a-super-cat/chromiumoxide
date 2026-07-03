//! Discrete device profiles used by `set_fingerprint_seed` (M5) and
//! `set_device_profile` (M5.5+).
//!
//! ## Design (M5 → M5.5+ evolution)
//!
//! **M5** had 5 desktop Chrome 120 profiles, derivable from a 16-byte
//! [`FingerprintSeed`](crate::stealth::FingerprintSeed) via
//! [`DeviceProfileId::from_seed`]. Schema: navigator, hardware, locale, webgl.
//!
//! **M5.5+** adds:
//!
//! - 5 new profile families: Desktop Chrome 148 Win11, iOS Safari iPhone 14,
//!   Android Chrome Pixel 7, Android System WebView Pixel 7, iOS WKWebView
//!   iPhone 14. These are accessible via [`DeviceProfileId`] and the new
//!   [`set_device_profile`](crate::stealth::Page::set_device_profile) API.
//! - New schema fields: [`NavigatorSpec`], [`ScreenSpec`], [`UaChSpec`],
//!   [`ApiSupportSpec`], [`WebViewSpec`].
//! - UA-CH `brands` list extended from 2 to 4 entries (real Chrome 148
//!   stable uses 4 brands including 2 GREASE entries).
//! - iOS Safari / iOS WKWebView: `navigator.userAgentData` removed entirely
//!   (Safari doesn't implement UA-CH).
//!
//! ## "Complete fingerprint set" requirement
//!
//! Every [`DeviceProfile`] is a hand-curated, internally consistent set of
//! values for OS / browser / hardware / locale / WebGL / UA-CH / screen /
//! API support. Profiles are NOT procedurally generated — that produces
//! fingerprints that cross-validating anti-bot checkers (CreepJS,
//! fingerprint.com, etc.) detect in one comparison. Each profile is a real,
//! shipped combination.
//!
//! ## M5.5+ device families
//!
//! - `DesktopChrome148Win11` — Windows 11 / Chrome 148 / Intel i7 / NVIDIA
//! - `IosSafariIphone14` — iOS 17.4 / Safari 17.4 / iPhone 14 (JS-surface only on chromium)
//! - `AndroidChromePixel7` — Android 14 / Chrome 148 / Pixel 7
//! - `AndroidWebViewPixel7` — Android 14 / System WebView 148 / Pixel 7
//! - `IosWkWebviewIphone14` — iOS 17.4 / WKWebView / iPhone 14 (JS-surface only)
//!
//! ## Engine limitation
//!
//! Per GPT-5.5 foreign-aid consultation: a Chromium 148 binary cannot
//! become WebKit at the engine level. iOS Safari / iOS WKWebView profiles
//! are best-effort JS-surface alignment; WebKit-only behavior, Safari API
//! gaps, CSS/media quirks, event timing, storage behavior, networking/TLS
//! traits will remain Chromium. Backend systems that fingerprint the JS
//! surface are what we can satisfy; visual rendering differs.

use serde::{Deserialize, Serialize};

// ============================================================================
//  Public API
// ============================================================================

/// Stable identifier for a [`DeviceProfile`].
///
/// M5: 5 desktop Chrome 120 variants, derived from seed via
/// [`DeviceProfileId::from_seed`] (5-way modulo).
///
/// M5.5+: 5 new variants for mobile / webview families, accessible via
/// [`Page::set_device_profile`](crate::stealth::Page::set_device_profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeviceProfileId {
    // === M5 desktop (Chrome 120 era, kept for back-compat with m6 step 1/2) ===
    /// Windows 11 / Chrome 120 / Intel i7-12700K / NVIDIA RTX 3080
    Win11Chrome120IntelNvidia,
    /// Windows 10 / Chrome 120 / Intel i7-9700K / NVIDIA GTX 1080
    Win10Chrome120IntelNvidia,
    /// macOS 14.4 / Chrome 120 / Apple M1 / Apple GPU
    MacOs14Chrome120M1,
    /// Ubuntu 22.04 / Chrome 120 / Intel Xeon E5 / Mesa
    LinuxUbuntuChrome120XeonMesa,
    /// Windows 11 / Chrome 120 / AMD Ryzen 7 5800X / AMD Radeon RX 6800
    Win11Chrome120AmdAmd,

    // === M5.5+ families ===
    /// Windows 11 / Chrome 148 / Intel i7-13700K / NVIDIA RTX 4070
    DesktopChrome148Win11,
    /// iOS 17.4 / Safari 17.4 / iPhone 14 — JS-surface only on chromium binary
    IosSafariIphone14,
    /// Android 14 / Chrome 148 / Pixel 7
    AndroidChromePixel7,
    /// Android 14 / System WebView 148 / Pixel 7
    AndroidWebViewPixel7,
    /// iOS 17.4 / WKWebView / iPhone 14 — JS-surface only on chromium binary
    IosWkWebviewIphone14,
}

impl DeviceProfileId {
    /// Number of hand-curated profiles. Keep this in sync with the enum
    /// variants. M5.5+ note: not all 10 are reachable from a single seed
    /// modulo — only the 5 M5 desktop variants are used by
    /// [`DeviceProfileId::from_seed`]. The 5 new families are reachable
    /// only via [`set_device_profile`](crate::stealth::Page::set_device_profile).
    pub const COUNT: usize = 10;

    /// M5 seed-derivation count. The 5 new families (idx 5..9) are NOT
    /// seed-reachable; they are an explicit pick. This constant is used by
    /// [`DeviceProfileId::from_seed`] to keep the M5 mapping intact.
    const SEED_REACHABLE_COUNT: usize = 5;

    /// Map a 16-byte seed deterministically into one of the
    /// [`DeviceProfileId`] variants. The same seed always yields the same id.
    ///
    /// Uses the first two bytes of the seed as a little-endian `u16` and takes
    /// it modulo [`DeviceProfileId::SEED_REACHABLE_COUNT`]. This is
    /// intentionally trivial — the property we need is *stability*, not
    /// cryptographic uniformity. The 5 M5.5+ families (idx 5..9) are NOT
    /// reachable from a seed; they must be picked explicitly.
    pub fn from_seed(seed: &[u8; 16]) -> Self {
        let n = u16::from_le_bytes([seed[0], seed[1]]) as usize;
        let idx = n % Self::SEED_REACHABLE_COUNT;
        match idx {
            0 => Self::Win11Chrome120IntelNvidia,
            1 => Self::Win10Chrome120IntelNvidia,
            2 => Self::MacOs14Chrome120M1,
            3 => Self::LinuxUbuntuChrome120XeonMesa,
            4 => Self::Win11Chrome120AmdAmd,
            _ => unreachable!("modulo SEED_REACHABLE_COUNT guards against this"),
        }
    }

    /// Look up the full [`DeviceProfile`] for this id.
    pub fn profile(self) -> DeviceProfile {
        match self {
            Self::Win11Chrome120IntelNvidia => DeviceProfile::win11_chrome120_intel_nvidia(),
            Self::Win10Chrome120IntelNvidia => DeviceProfile::win10_chrome120_intel_nvidia(),
            Self::MacOs14Chrome120M1 => DeviceProfile::macos14_chrome120_m1(),
            Self::LinuxUbuntuChrome120XeonMesa => {
                DeviceProfile::linux_ubuntu_chrome120_xeon_mesa()
            }
            Self::Win11Chrome120AmdAmd => DeviceProfile::win11_chrome120_amd_amd(),
            Self::DesktopChrome148Win11 => DeviceProfile::desktop_chrome148_win11(),
            Self::IosSafariIphone14 => DeviceProfile::ios_safari_iphone14(),
            Self::AndroidChromePixel7 => DeviceProfile::android_chrome_pixel7(),
            Self::AndroidWebViewPixel7 => DeviceProfile::android_webview_pixel7(),
            Self::IosWkWebviewIphone14 => DeviceProfile::ios_wkwebview_iphone14(),
        }
    }

    /// Short, human-readable label for logs and UI.
    pub fn label(self) -> &'static str {
        match self {
            Self::Win11Chrome120IntelNvidia => "Win11 Chrome120 Intel+NVIDIA",
            Self::Win10Chrome120IntelNvidia => "Win10 Chrome120 Intel+NVIDIA",
            Self::MacOs14Chrome120M1 => "macOS14 Chrome120 M1",
            Self::LinuxUbuntuChrome120XeonMesa => "Ubuntu22 Chrome120 Xeon+Mesa",
            Self::Win11Chrome120AmdAmd => "Win11 Chrome120 AMD+AMD",
            Self::DesktopChrome148Win11 => "Win11 Chrome148 Intel+NVIDIA",
            Self::IosSafariIphone14 => "iOS17.4 Safari iPhone14",
            Self::AndroidChromePixel7 => "Android14 Chrome148 Pixel7",
            Self::AndroidWebViewPixel7 => "Android14 WebView148 Pixel7",
            Self::IosWkWebviewIphone14 => "iOS17.4 WKWebView iPhone14",
        }
    }
}

/// High-level device category. Used by stealth launch-arg logic
/// (per-family BrowserConfig) and by the validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFamily {
    Desktop,
    Mobile,
    Webview,
}

impl DeviceProfileId {
    /// Family categorization. Desktop / Mobile / Webview.
    pub fn family(self) -> DeviceFamily {
        match self {
            Self::Win11Chrome120IntelNvidia
            | Self::Win10Chrome120IntelNvidia
            | Self::MacOs14Chrome120M1
            | Self::LinuxUbuntuChrome120XeonMesa
            | Self::Win11Chrome120AmdAmd
            | Self::DesktopChrome148Win11 => DeviceFamily::Desktop,
            Self::IosSafariIphone14 | Self::AndroidChromePixel7 => DeviceFamily::Mobile,
            Self::AndroidWebViewPixel7 | Self::IosWkWebviewIphone14 => DeviceFamily::Webview,
        }
    }
}

// ============================================================================
//  Field structs (existing M5)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsInfo {
    /// `navigator.platform` (e.g. `"Win32"`, `"MacIntel"`, `"Linux x86_64"`,
    /// `"iPhone"`, `"Linux armv81"`).
    pub platform: &'static str,
    /// `navigator.userAgentData` `platform` (e.g. `"Windows"`, `"macOS"`,
    /// `"Linux"`, `"iOS"`, `"Android"`). Empty for iOS Safari (UA-CH absent).
    pub user_agent_data_platform: &'static str,
    /// `navigator.userAgentData` `platformVersion` (e.g. `"15.0.0"`). Empty
    /// for iOS Safari.
    pub user_agent_data_platform_version: &'static str,
    /// `navigator.userAgent` OS substring (e.g. `"Windows NT 10.0; Win64; x64"`).
    pub ua_os_substring: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserInfo {
    /// `navigator.userAgent` template, with `{chrome}` substituted at runtime.
    pub ua_template: &'static str,
    /// Chrome major version. Used in UA string + UA-CH brands.
    pub chrome_major: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareInfo {
    /// `navigator.hardwareConcurrency`.
    pub hardware_concurrency: u8,
    /// `navigator.deviceMemory` (GB). Unused on iOS Safari (always 0/undef).
    pub device_memory: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocaleInfo {
    /// `Accept-Language` header value.
    pub accept_language: &'static str,
    /// `navigator.language`.
    pub primary_language: &'static str,
    /// `navigator.languages` (full list, ordered by q-value descending).
    pub languages_list: &'static [&'static str],
    /// IANA timezone id.
    pub timezone_id: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebGlInfo {
    /// `UNMASKED_VENDOR_WEBGL`.
    pub unmasked_vendor: &'static str,
    /// `UNMASKED_RENDERER_WEBGL`.
    pub unmasked_renderer: &'static str,
}

// ============================================================================
//  Field structs (M5.5+ additions)
// ============================================================================

/// `navigator.*` properties that weren't in the M5 schema.
///
/// M5 only had `platform`. M5.5+ adds the full navigator surface for
/// internal-coherence validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NavigatorSpec {
    /// `navigator.vendor` (e.g. `"Google Inc."`, `"Apple Computer, Inc."`).
    pub vendor: &'static str,
    /// `navigator.productSub` (always `"20030107"` for Chrome/Safari).
    pub product_sub: &'static str,
    /// `navigator.maxTouchPoints` (0 for desktop, 5+ for mobile).
    pub max_touch_points: u8,
    /// `navigator.plugins` — list of (name, filename) pairs. Empty for
    /// mobile Safari / WKWebView / Android Chrome / Android WebView. Desktop
    /// Chrome has 5 standard PDF plugins.
    pub plugins: &'static [(&'static str, &'static str)],
    /// `navigator.mimeTypes` — list of MIME strings. Empty for non-desktop.
    pub mime_types: &'static [&'static str],
}

/// Window / screen physical + CSS dimensions + DPR.
///
/// The JS payload overrides `window.screen.*` and `window.devicePixelRatio`
/// to match this spec. M5 didn't expose these (M1 GPU patch was the only
/// M1-M3 surface that touched screen, and it didn't reach JS).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScreenSpec {
    /// `screen.width` (CSS px).
    pub width: u32,
    /// `screen.height` (CSS px).
    pub height: u32,
    /// `screen.availWidth` (CSS px, excludes taskbar).
    pub avail_width: u32,
    /// `screen.availHeight` (CSS px, excludes taskbar).
    pub avail_height: u32,
    /// `window.devicePixelRatio`.
    pub device_pixel_ratio: f32,
}

/// UA-CH (`navigator.userAgentData`) HighEntropyValues fields.
///
/// M5 had a hardcoded subset (architecture="x86", bitness="64", model="",
/// uaFullVersion="", wow64=false). M5.5+ makes these per-profile, adds
/// 4-entry `brands` list (with GREASE), and sets `mobile` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaChSpec {
    /// 4-entry `brands` list. Order: [GREASE, Chromium, "Google Chrome" or
    /// "Android WebView", GREASE]. GREASE brand uses a random "Not A(Brand"
    /// style string with a 24-style version. iOS Safari: empty (UA-CH absent).
    pub brands: &'static [UaBrand],
    /// `navigator.userAgentData.uaFullVersion` (e.g. `"148.0.7559.0"`).
    /// Empty for iOS Safari.
    pub full_version: &'static str,
    /// `navigator.userAgentData.architecture` (e.g. `"x86"`, `"arm"`).
    /// Empty for iOS Safari.
    pub architecture: &'static str,
    /// `navigator.userAgentData.bitness` (e.g. `"64"`).
    /// Empty for iOS Safari.
    pub bitness: &'static str,
    /// `navigator.userAgentData.model` (e.g. `""` for desktop, `"Pixel 7"`
    /// for mobile). Empty for iOS Safari and desktop.
    pub model: &'static str,
    /// `navigator.userAgentData.mobile` (true for mobile / webview).
    pub mobile: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaBrand {
    pub brand: &'static str,
    pub version: &'static str,
}

/// API support flags. Used to mark `navigator.getBattery` /
/// `Accelerometer` / etc. as present or absent in the JS payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiSupportSpec {
    /// `navigator.getBattery` is callable (Chrome desktop removed this in
    /// recent versions; Chrome mobile / WebView has it).
    pub battery: bool,
    /// `Accelerometer` / `Gyroscope` / `Magnetometer` are present (Android
    /// Chrome / WebView; absent on desktop Chrome and iOS).
    pub sensor: bool,
    /// `WebGL2RenderingContext` is present (true on all modern).
    pub webgl2: bool,
    /// `OffscreenCanvas` is supported (Chrome yes, Safari no).
    pub offscreen_canvas: bool,
    /// `navigator.serviceWorker` is callable (Chrome yes, Android WebView
    /// usually no unless enabled by embedder).
    pub service_worker: bool,
}

/// WebView-specific markers. Only populated for Webview families.
///
/// The JS payload sets `window.webkit` stub and conditionally sends
/// `X-Requested-With` request header (via CDP extraHTTPHeaders, not
/// directly in JS). The presence/absence of these is the most reliable
/// webview-vs-standalone-browser signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebViewSpec {
    /// UA contains `Version/4.0` token (Android WebView UA template).
    pub ua_contains_version_4: bool,
    /// `X-Requested-With` request header value (Android WebView convention;
    /// iOS WKWebView doesn't use this).
    pub x_requested_with: Option<&'static str>,
    /// `window.webkit` is present (iOS WKWebView convention; Android WebView
    /// does not have `window.webkit`).
    pub window_webkit: bool,
    /// `window.webkit.messageHandlers` is present (iOS WKWebView when
    /// embedder defines JS handlers; Android WebView doesn't).
    pub webkit_message_handlers: bool,
    /// `Build.FINGERPRINT` (Android only, set in JS as a getter for any
    /// page that explicitly asks via `navigator.userAgentData` or
    /// `Build.FINGERPRINT` stub).
    pub build_fingerprint: Option<&'static str>,
}

// ============================================================================
//  DeviceProfile (extended)
// ============================================================================

/// A hand-curated, internally consistent device profile.
///
/// All fields must come from the same shipped device family. Cross-family
/// combinations (e.g. macOS UA + Windows `navigator.platform`) are detected
/// in one comparison by every modern fingerprinting library and are
/// forbidden here by construction. See the "complete fingerprint set"
/// requirement in module docs.
///
/// Note: `Eq` is not derived because `ScreenSpec::device_pixel_ratio` is
/// `f32`. `PartialEq` is enough for tests (`assert_eq!` works on `PartialEq`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceProfile {
    pub id: DeviceProfileId,
    pub family: DeviceFamily,
    pub os: OsInfo,
    pub browser: BrowserInfo,
    pub hardware: HardwareInfo,
    pub locale: LocaleInfo,
    pub webgl: WebGlInfo,

    // === M5.5+ fields ===
    pub navigator: NavigatorSpec,
    pub screen: ScreenSpec,
    pub uach: UaChSpec,
    pub api_support: ApiSupportSpec,
    pub webview: Option<WebViewSpec>,
}

impl DeviceProfile {
    /// Render the full `User-Agent` string from [`BrowserInfo::ua_template`]
    /// and the configured `chrome_major` version.
    pub fn user_agent(&self) -> String {
        self.browser
            .ua_template
            .replace("{chrome}", &self.browser.chrome_major.to_string())
    }

    /// Whether the family is mobile (real mobile or webview with mobile UA).
    /// Used by init script to decide whether to override `navigator.plugins`
    /// to empty, set touch points, etc.
    pub fn is_mobile(&self) -> bool {
        matches!(self.id.family(), DeviceFamily::Mobile | DeviceFamily::Webview)
    }

    /// Whether the family is iOS Safari or iOS WKWebView. The init script
    /// must delete `navigator.userAgentData` for these (Safari doesn't
    /// implement UA-CH).
    pub fn is_ios(&self) -> bool {
        matches!(self.id, DeviceProfileId::IosSafariIphone14 | DeviceProfileId::IosWkWebviewIphone14)
    }

    // ============================================================
    //  M5 desktop profiles (Chrome 120 era, back-compat with m6 step 1/2)
    // ============================================================

    /// Windows 11, Chrome 120, Intel i7-12700K (16C/24T), NVIDIA RTX 3080.
    pub const fn win11_chrome120_intel_nvidia() -> Self {
        Self {
            id: DeviceProfileId::Win11Chrome120IntelNvidia,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "Win32",
                user_agent_data_platform: "Windows",
                user_agent_data_platform_version: "15.0.0",
                ua_os_substring: "Windows NT 10.0; Win64; x64",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 120,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 16,
                device_memory: 8,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/Los_Angeles",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (NVIDIA)",
                unmasked_renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 \
                                    Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1040,
                device_pixel_ratio: 1.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "120" },
                    UaBrand { brand: "Google Chrome", version: "120" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "120.0.6099.130",
                architecture: "x86",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// Windows 10, Chrome 120, Intel i7-9700K (8C/8T), NVIDIA GTX 1080.
    pub const fn win10_chrome120_intel_nvidia() -> Self {
        Self {
            id: DeviceProfileId::Win10Chrome120IntelNvidia,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "Win32",
                user_agent_data_platform: "Windows",
                user_agent_data_platform_version: "0.1.0",
                ua_os_substring: "Windows NT 10.0; Win64; x64",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 120,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 8,
                device_memory: 8,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (NVIDIA)",
                unmasked_renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 \
                                    Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1040,
                device_pixel_ratio: 1.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "120" },
                    UaBrand { brand: "Google Chrome", version: "120" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "120.0.6099.130",
                architecture: "x86",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// macOS 14.4, Chrome 120, Apple M1.
    pub const fn macos14_chrome120_m1() -> Self {
        Self {
            id: DeviceProfileId::MacOs14Chrome120M1,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "MacIntel",
                user_agent_data_platform: "macOS",
                user_agent_data_platform_version: "14.4.1",
                ua_os_substring: "Macintosh; Intel Mac OS X 10_15_7",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 120,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 8,
                device_memory: 8,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/Los_Angeles",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (Apple)",
                unmasked_renderer: "ANGLE (Apple, Apple M1, OpenGL 4.1)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 2560,
                height: 1600,
                avail_width: 2560,
                avail_height: 1555,
                device_pixel_ratio: 2.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "120" },
                    UaBrand { brand: "Google Chrome", version: "120" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "120.0.6099.130",
                architecture: "arm",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// Ubuntu 22.04, Chrome 120, Intel Xeon E5-2690v4 (14C/28T), Mesa.
    pub const fn linux_ubuntu_chrome120_xeon_mesa() -> Self {
        Self {
            id: DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "Linux x86_64",
                user_agent_data_platform: "Linux",
                user_agent_data_platform_version: "6.5.0",
                ua_os_substring: "X11; Linux x86_64",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 120,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 14,
                device_memory: 16,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/Chicago",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Mesa/X.org",
                unmasked_renderer: "Mesa llvmpipe (LLVM 15.0.7, 256 bits)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1080,
                device_pixel_ratio: 1.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "120" },
                    UaBrand { brand: "Google Chrome", version: "120" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "120.0.6099.130",
                architecture: "x86",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// Windows 11, Chrome 120, AMD Ryzen 7 5800X (8C/16T), AMD Radeon RX 6800.
    pub const fn win11_chrome120_amd_amd() -> Self {
        Self {
            id: DeviceProfileId::Win11Chrome120AmdAmd,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "Win32",
                user_agent_data_platform: "Windows",
                user_agent_data_platform_version: "15.0.0",
                ua_os_substring: "Windows NT 10.0; Win64; x64",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 120,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 16,
                device_memory: 16,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "Europe/London",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (AMD)",
                unmasked_renderer: "ANGLE (AMD, AMD Radeon RX 6800 \
                                    Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1040,
                device_pixel_ratio: 1.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "120" },
                    UaBrand { brand: "Google Chrome", version: "120" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "120.0.6099.130",
                architecture: "x86",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    // ============================================================
    //  M5.5+ profile families (per GPT-5.5 foreign-aid consultation)
    // ============================================================

    /// Windows 11, Chrome 148, Intel i7-13700K, NVIDIA RTX 4070.
    ///
    /// Replaces the M5 `Win11Chrome120IntelNvidia` as the "modern" desktop
    /// Chrome 148 default. Same shape, bumped Chrome version, new GPU
    /// generation, 4-entry UA-CH brands with GREASE.
    pub const fn desktop_chrome148_win11() -> Self {
        Self {
            id: DeviceProfileId::DesktopChrome148Win11,
            family: DeviceFamily::Desktop,
            os: OsInfo {
                platform: "Win32",
                user_agent_data_platform: "Windows",
                user_agent_data_platform_version: "15.0.0",
                ua_os_substring: "Windows NT 10.0; Win64; x64",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36",
                chrome_major: 148,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 16,
                device_memory: 16,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (NVIDIA)",
                unmasked_renderer:
                    "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 0,
                plugins: &[
                    ("PDF Viewer", "internal-pdf-viewer"),
                    ("Chrome PDF Viewer", "internal-pdf-viewer"),
                    ("Chromium PDF Viewer", "internal-pdf-viewer"),
                    ("Microsoft Edge PDF Viewer", "internal-pdf-viewer"),
                    ("WebKit built-in PDF", "internal-pdf-viewer"),
                ],
                mime_types: &["application/pdf", "text/pdf"],
            },
            screen: ScreenSpec {
                width: 1920,
                height: 1080,
                avail_width: 1920,
                avail_height: 1040,
                device_pixel_ratio: 1.0,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "148" },
                    UaBrand { brand: "Google Chrome", version: "148" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "148.0.7778.218",
                architecture: "x86",
                bitness: "64",
                model: "",
                mobile: false,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// iOS 17.4 / Safari 17.4 / iPhone 14.
    ///
    /// **Engine limitation**: on a chromium binary, this is JS-surface only
    /// (UA / navigator / canvas / WebGL string alignment). WebKit-only
    /// behavior, Safari API gaps, CSS/media quirks, event timing, storage
    /// behavior, networking/TLS remain chromium. Use for backend systems that
    /// fingerprint the JS surface; not for visual rendering.
    pub const fn ios_safari_iphone14() -> Self {
        Self {
            id: DeviceProfileId::IosSafariIphone14,
            family: DeviceFamily::Mobile,
            os: OsInfo {
                platform: "iPhone",
                user_agent_data_platform: "",          // Safari: UA-CH absent
                user_agent_data_platform_version: "",
                ua_os_substring: "iPhone; CPU iPhone OS 17_4 like Mac OS X",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 \
                     Mobile/15E148 Safari/604.1",
                chrome_major: 17, // Safari version, not Chrome
            },
            hardware: HardwareInfo {
                hardware_concurrency: 6,
                device_memory: 0, // Safari: deviceMemory is undefined
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Apple Inc.",
                unmasked_renderer: "Apple GPU",
            },
            navigator: NavigatorSpec {
                vendor: "Apple Computer, Inc.",
                product_sub: "20030107",
                max_touch_points: 5,
                plugins: &[], // Safari: plugins is empty
                mime_types: &[], // Safari: mimeTypes is empty
            },
            screen: ScreenSpec {
                width: 390,
                height: 844,
                avail_width: 390,
                avail_height: 844,
                device_pixel_ratio: 3.0,
            },
            uach: UaChSpec {
                brands: &[], // Safari: UA-CH absent
                full_version: "",
                architecture: "",
                bitness: "",
                model: "",
                mobile: true,
            },
            api_support: ApiSupportSpec {
                battery: false, // Safari: battery API absent
                sensor: false,
                webgl2: true,
                offscreen_canvas: false, // Safari: OffscreenCanvas absent
                service_worker: true,
            },
            webview: None,
        }
    }

    /// Android 14 / Chrome 148 / Pixel 7.
    pub const fn android_chrome_pixel7() -> Self {
        Self {
            id: DeviceProfileId::AndroidChromePixel7,
            family: DeviceFamily::Mobile,
            os: OsInfo {
                platform: "Linux armv81",
                user_agent_data_platform: "Android",
                user_agent_data_platform_version: "14.0.0",
                ua_os_substring: "Linux; Android 14; Pixel 7",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Mobile Safari/537.36",
                chrome_major: 148,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 8,
                device_memory: 8,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (Google)",
                unmasked_renderer: "ANGLE (Google, Vulkan 1.3.0 (Mali-G710), \
                                    SwiftShader driver)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 5,
                plugins: &[], // Mobile Chrome: plugins is empty
                mime_types: &[],
            },
            screen: ScreenSpec {
                width: 412,
                height: 915,
                avail_width: 412,
                avail_height: 915,
                device_pixel_ratio: 2.625,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "148" },
                    UaBrand { brand: "Google Chrome", version: "148" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "148.0.7778.218",
                architecture: "arm",
                bitness: "64",
                model: "Pixel 7",
                mobile: true,
            },
            api_support: ApiSupportSpec {
                battery: true, // Android Chrome has Battery API
                sensor: true,   // Accelerometer / Gyroscope / Magnetometer present
                webgl2: true,
                offscreen_canvas: true,
                service_worker: true,
            },
            webview: None,
        }
    }

    /// Android 14 / System WebView 148 / Pixel 7.
    ///
    /// Distinct from `android_chrome_pixel7` in: UA template has
    /// `Version/4.0` + `Build/UQ1A...`, UA-CH 3rd brand is `"Android WebView"`
    /// not `"Google Chrome"`, `service_worker=false` (typical embedder
    /// config), `Build.FINGERPRINT` exposed, `X-Requested-With` is the
    /// standard convention but is per-embedder so we mark `None` for the
    /// generic profile.
    pub const fn android_webview_pixel7() -> Self {
        Self {
            id: DeviceProfileId::AndroidWebViewPixel7,
            family: DeviceFamily::Webview,
            os: OsInfo {
                platform: "Linux armv81",
                user_agent_data_platform: "Android",
                user_agent_data_platform_version: "14.0.0",
                ua_os_substring: "Linux; Android 14; Pixel 7 Build/UQ1A.240205.004",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/UQ1A.240205.004) \
                     AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 \
                     Chrome/{chrome}.0.0.0 Mobile Safari/537.36",
                chrome_major: 148,
            },
            hardware: HardwareInfo {
                hardware_concurrency: 8,
                device_memory: 8,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US", "en"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Google Inc. (Google)",
                unmasked_renderer: "ANGLE (Google, Vulkan 1.3.0 (Mali-G710), \
                                    SwiftShader driver)",
            },
            navigator: NavigatorSpec {
                vendor: "Google Inc.",
                product_sub: "20030107",
                max_touch_points: 5,
                plugins: &[],
                mime_types: &[],
            },
            screen: ScreenSpec {
                width: 412,
                height: 915,
                avail_width: 412,
                avail_height: 915,
                device_pixel_ratio: 2.625,
            },
            uach: UaChSpec {
                brands: &[
                    UaBrand { brand: "Not A(Brand", version: "24" },
                    UaBrand { brand: "Chromium", version: "148" },
                    UaBrand { brand: "Android WebView", version: "148" },
                    UaBrand { brand: "Not A(Brand", version: "24" },
                ],
                full_version: "148.0.7778.218",
                architecture: "arm",
                bitness: "64",
                model: "Pixel 7",
                mobile: true,
            },
            api_support: ApiSupportSpec {
                battery: true,
                sensor: true, // embedder grants sensors
                webgl2: true,
                offscreen_canvas: true,
                service_worker: false, // WebView typically disables SW
            },
            webview: Some(WebViewSpec {
                ua_contains_version_4: true,
                x_requested_with: None, // per-embedder
                window_webkit: false,
                webkit_message_handlers: false,
                build_fingerprint: Some("google/panther/panther:14/UQ1A.240205.004/11010316:user/release-keys"),
            }),
        }
    }

    /// iOS 17.4 / WKWebView / iPhone 14.
    ///
    /// **Engine limitation**: on a chromium binary, JS-surface only.
    /// WKWebView UA has `Version/X.X Safari/X.X` REMOVED (it's just
    /// `Mobile/15E148` at the end), and `window.webkit.messageHandlers`
    /// is present.
    pub const fn ios_wkwebview_iphone14() -> Self {
        Self {
            id: DeviceProfileId::IosWkWebviewIphone14,
            family: DeviceFamily::Webview,
            os: OsInfo {
                platform: "iPhone",
                user_agent_data_platform: "", // iOS: UA-CH absent
                user_agent_data_platform_version: "",
                ua_os_substring: "iPhone; CPU iPhone OS 17_4 like Mac OS X",
            },
            browser: BrowserInfo {
                ua_template:
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                chrome_major: 17, // Safari version (referenced for UA-CH — not used here)
            },
            hardware: HardwareInfo {
                hardware_concurrency: 6,
                device_memory: 0,
            },
            locale: LocaleInfo {
                accept_language: "en-US,en;q=0.9",
                primary_language: "en-US",
                languages_list: &["en-US"],
                timezone_id: "America/New_York",
            },
            webgl: WebGlInfo {
                unmasked_vendor: "Apple Inc.",
                unmasked_renderer: "Apple GPU",
            },
            navigator: NavigatorSpec {
                vendor: "Apple Computer, Inc.",
                product_sub: "20030107",
                max_touch_points: 5,
                plugins: &[],
                mime_types: &[],
            },
            screen: ScreenSpec {
                width: 390,
                height: 844,
                avail_width: 390,
                avail_height: 844,
                device_pixel_ratio: 3.0,
            },
            uach: UaChSpec {
                brands: &[], // iOS: UA-CH absent
                full_version: "",
                architecture: "",
                bitness: "",
                model: "",
                mobile: true,
            },
            api_support: ApiSupportSpec {
                battery: false,
                sensor: false,
                webgl2: true,
                offscreen_canvas: false,
                service_worker: true,
            },
            webview: Some(WebViewSpec {
                ua_contains_version_4: false,
                x_requested_with: None, // iOS doesn't use this
                window_webkit: true,
                webkit_message_handlers: true, // when embedder defines
                build_fingerprint: None,
            }),
        }
    }
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_to_profile_is_deterministic() {
        let seed = [0u8; 16];
        let a = DeviceProfileId::from_seed(&seed);
        let b = DeviceProfileId::from_seed(&seed);
        assert_eq!(a, b);
    }

    #[test]
    fn first_byte_modulo_selects_one_of_5_m5_profiles() {
        // 0..4 → M5 desktop profiles; 5..255 → still wraps to 0..4
        for byte in [0u8, 5, 10, 15, 20, 100, 200, 255] {
            let mut seed = [0u8; 16];
            seed[0] = byte;
            let id = DeviceProfileId::from_seed(&seed);
            // Must be one of the 5 M5 desktop variants (NOT the 5 M5.5+ families)
            assert!(matches!(
                id,
                DeviceProfileId::Win11Chrome120IntelNvidia
                    | DeviceProfileId::Win10Chrome120IntelNvidia
                    | DeviceProfileId::MacOs14Chrome120M1
                    | DeviceProfileId::LinuxUbuntuChrome120XeonMesa
                    | DeviceProfileId::Win11Chrome120AmdAmd
            ));
        }
    }

    #[test]
    fn all_5_m5_desktop_profiles_have_consistent_os_ua_substring() {
        for id in [
            DeviceProfileId::Win11Chrome120IntelNvidia,
            DeviceProfileId::Win10Chrome120IntelNvidia,
            DeviceProfileId::MacOs14Chrome120M1,
            DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            DeviceProfileId::Win11Chrome120AmdAmd,
        ] {
            let p = id.profile();
            match p.family {
                DeviceFamily::Desktop => {
                    if id == DeviceProfileId::MacOs14Chrome120M1 {
                        assert_eq!(p.os.platform, "MacIntel");
                        assert!(p.os.ua_os_substring.contains("Macintosh"));
                    } else if id == DeviceProfileId::LinuxUbuntuChrome120XeonMesa {
                        assert_eq!(p.os.platform, "Linux x86_64");
                        assert!(p.os.ua_os_substring.contains("X11; Linux"));
                    } else {
                        assert_eq!(p.os.platform, "Win32");
                        assert!(p.os.ua_os_substring.contains("Windows NT"));
                    }
                }
                _ => panic!("not desktop"),
            }
        }
    }

    #[test]
    fn m55_ios_profiles_have_empty_uach() {
        // iOS Safari and iOS WKWebView: UA-CH absent (Safari doesn't implement it)
        for id in [
            DeviceProfileId::IosSafariIphone14,
            DeviceProfileId::IosWkWebviewIphone14,
        ] {
            let p = id.profile();
            assert!(p.uach.brands.is_empty(), "{:?} should have empty UA-CH brands", id);
            assert!(p.uach.full_version.is_empty(), "{:?} should have empty uaFullVersion", id);
            assert!(p.os.user_agent_data_platform.is_empty(), "{:?} should have empty uad platform", id);
            assert!(p.is_ios(), "should be iOS");
            assert!(p.is_mobile());
            assert_eq!(p.hardware.device_memory, 0, "iOS Safari has no deviceMemory");
        }
    }

    #[test]
    fn m55_android_chrome_has_battery_and_sensors() {
        let p = DeviceProfileId::AndroidChromePixel7.profile();
        assert!(p.api_support.battery);
        assert!(p.api_support.sensor);
        assert!(p.api_support.service_worker);
        assert!(!p.is_ios());
        assert!(p.is_mobile());
        assert_eq!(p.hardware.device_memory, 8);
        assert_eq!(p.uach.model, "Pixel 7");
        assert!(p.uach.mobile);
    }

    #[test]
    fn m55_android_webview_distinct_from_chrome_via_brands() {
        // Android WebView: 3rd brand is "Android WebView", not "Google Chrome"
        let chrome = DeviceProfileId::AndroidChromePixel7.profile();
        let webview = DeviceProfileId::AndroidWebViewPixel7.profile();
        assert_eq!(chrome.uach.brands[2].brand, "Google Chrome");
        assert_eq!(webview.uach.brands[2].brand, "Android WebView");
        // WebView UA template contains "Version/4.0" — Chrome doesn't
        let chrome_ua = chrome.user_agent();
        let webview_ua = webview.user_agent();
        assert!(!chrome_ua.contains("Version/4.0"));
        assert!(webview_ua.contains("Version/4.0"));
        // WebView has no service worker (typical)
        assert!(!webview.api_support.service_worker);
        assert!(webview.webview.is_some());
        assert!(chrome.webview.is_none());
    }

    #[test]
    fn m55_ios_wkwebview_has_window_webkit_marker() {
        let safari = DeviceProfileId::IosSafariIphone14.profile();
        let wkwebview = DeviceProfileId::IosWkWebviewIphone14.profile();
        // iOS Safari has no window.webkit
        assert!(!safari.webview.map(|w| w.window_webkit).unwrap_or(false));
        // iOS WKWebView has window.webkit + messageHandlers
        let wv = wkwebview.webview.expect("wkwebview has webview spec");
        assert!(wv.window_webkit);
        assert!(wv.webkit_message_handlers);
        // Both have `Version/X.X Safari/X.X` removed from UA
        assert!(!wkwebview.user_agent().contains("Safari/"));
        // sanity: iOS Safari UA does contain Mobile/15E148
        assert!(safari.user_agent().contains("Mobile/15E148"));
    }

    #[test]
    fn m55_profiles_have_4_brand_uach_with_grease() {
        for id in [
            DeviceProfileId::DesktopChrome148Win11,
            DeviceProfileId::AndroidChromePixel7,
            DeviceProfileId::AndroidWebViewPixel7,
        ] {
            let p = id.profile();
            assert_eq!(p.uach.brands.len(), 4, "{:?} should have 4 UA-CH brands", id);
            // 1st and 4th should be GREASE-style "Not A(Brand"
            assert_eq!(p.uach.brands[0].brand, "Not A(Brand", "{:?} brands[0]", id);
            assert_eq!(p.uach.brands[3].brand, "Not A(Brand", "{:?} brands[3]", id);
        }
    }

    #[test]
    fn m5_profiles_have_4_brand_uach_with_grease_after_m55() {
        // M5 desktop profiles were also extended to 4-entry brands in M5.5+
        for id in [
            DeviceProfileId::Win11Chrome120IntelNvidia,
            DeviceProfileId::Win10Chrome120IntelNvidia,
            DeviceProfileId::MacOs14Chrome120M1,
            DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            DeviceProfileId::Win11Chrome120AmdAmd,
        ] {
            let p = id.profile();
            assert_eq!(p.uach.brands.len(), 4, "{:?} should have 4 UA-CH brands", id);
        }
    }

    #[test]
    fn all_10_profiles_have_deterministic_user_agent() {
        for id in [
            DeviceProfileId::Win11Chrome120IntelNvidia,
            DeviceProfileId::Win10Chrome120IntelNvidia,
            DeviceProfileId::MacOs14Chrome120M1,
            DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            DeviceProfileId::Win11Chrome120AmdAmd,
            DeviceProfileId::DesktopChrome148Win11,
            DeviceProfileId::IosSafariIphone14,
            DeviceProfileId::AndroidChromePixel7,
            DeviceProfileId::AndroidWebViewPixel7,
            DeviceProfileId::IosWkWebviewIphone14,
        ] {
            let p = id.profile();
            let ua1 = p.user_agent();
            let ua2 = p.user_agent();
            assert_eq!(ua1, ua2);
            assert!(!ua1.is_empty());
        }
    }
}
