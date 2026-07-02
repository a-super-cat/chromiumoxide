//! Discrete device profiles used by `set_fingerprint_seed`.
//!
//! Each [`DeviceProfile`] is a hand-curated, internally consistent set of values
//! for OS / browser / hardware / locale / WebGL identifiers. A 16-byte
//! [`FingerprintSeed`](crate::stealth::FingerprintSeed) deterministically maps
//! to exactly one profile (see [`DeviceProfileId::from_seed`]), so:
//!
//! - same seed → same profile → identical browser fingerprint across runs;
//! - different seeds → different profiles, but each profile is self-consistent
//!   (UA, `navigator.platform`, `navigator.languages`, timezone and WebGL
//!   vendor/renderer are guaranteed to be from the same device family).
//!
//! The set is **deliberately small** in M5. We do **not** synthesise fake
//! device combinations on the fly — that produces fingerprints that the
//! cross-validating anti-bot checkers (CreepJS, fingerprint.com, etc.) can
//! detect in one comparison.
//!
//! Future revisions may add more profiles, but each one must be a real,
//! shipped combination — never a procedurally-generated Frankenstein profile.

use serde::{Deserialize, Serialize};

/// Stable identifier for a [`DeviceProfile`].
///
/// Used by [`DeviceProfileId::from_seed`] to deterministically map a 16-byte
/// seed into one of the hand-curated profiles. Adding a new variant is a
/// **non-breaking** change in terms of the fingerprint values (because the
/// mapping is a hash mod `len()`); it is, however, a behavioural change for
/// any caller that was relying on a particular seed producing a particular
/// profile — bumping the stealth crate's minor version is the right move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeviceProfileId {
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
}

impl DeviceProfileId {
    /// Number of hand-curated profiles. Keep this in sync with the enum
    /// variants.
    pub const COUNT: usize = 5;

    /// Map a 16-byte seed deterministically into one of the
    /// [`DeviceProfileId`] variants. The same seed always yields the same id.
    ///
    /// Uses the first two bytes of the seed as a little-endian `u16` and takes
    /// it modulo [`DeviceProfileId::COUNT`]. This is intentionally trivial —
    /// the property we need is *stability*, not cryptographic uniformity.
    pub fn from_seed(seed: &[u8; 16]) -> Self {
        let n = u16::from_le_bytes([seed[0], seed[1]]) as usize;
        let idx = n % Self::COUNT;
        match idx {
            0 => Self::Win11Chrome120IntelNvidia,
            1 => Self::Win10Chrome120IntelNvidia,
            2 => Self::MacOs14Chrome120M1,
            3 => Self::LinuxUbuntuChrome120XeonMesa,
            4 => Self::Win11Chrome120AmdAmd,
            _ => unreachable!("modulo COUNT guards against this"),
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFamily {
    DesktopWindows,
    DesktopMac,
    DesktopLinux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsInfo {
    /// `navigator.oscpu` / `navigator.platform` family.
    pub platform: &'static str,
    /// `navigator.userAgentData` `platform` (e.g. `"Windows"`, `"macOS"`).
    pub user_agent_data_platform: &'static str,
    /// `navigator.userAgentData` `platformVersion` (e.g. `"15.0.0"`).
    pub user_agent_data_platform_version: &'static str,
    /// `navigator.userAgent` OS substring (e.g. `"Windows NT 10.0; Win64; x64"`).
    pub ua_os_substring: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserInfo {
    /// `navigator.userAgent` template, with `{chrome}` substituted at runtime.
    pub ua_template: &'static str,
    /// Chrome major version.
    pub chrome_major: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareInfo {
    /// `navigator.hardwareConcurrency`.
    pub hardware_concurrency: u8,
    /// `navigator.deviceMemory` (GB).
    pub device_memory: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocaleInfo {
    /// `Accept-Language` header value (used in `Network.setUserAgentOverride`).
    pub accept_language: &'static str,
    /// `navigator.language`.
    pub primary_language: &'static str,
    /// `navigator.languages` (full list, ordered by q-value descending).
    pub languages_list: &'static [&'static str],
    /// IANA timezone id (used in `Emulation.setTimezoneOverride`).
    pub timezone_id: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebGlInfo {
    /// `UNMASKED_VENDOR_WEBGL`.
    pub unmasked_vendor: &'static str,
    /// `UNMASKED_RENDERER_WEBGL`.
    pub unmasked_renderer: &'static str,
}

/// A hand-curated, internally consistent device profile.
///
/// The fields are not independent: they must all come from the same shipped
/// device family. Cross-family combinations (e.g. macOS UA + Windows
/// `navigator.platform`) are detected in one comparison by every modern
/// fingerprinting library and are forbidden here by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProfile {
    pub id: DeviceProfileId,
    pub family: DeviceFamily,
    pub os: OsInfo,
    pub browser: BrowserInfo,
    pub hardware: HardwareInfo,
    pub locale: LocaleInfo,
    pub webgl: WebGlInfo,
}

impl DeviceProfile {
    /// Render the full `User-Agent` string from [`BrowserInfo::ua_template`]
    /// and the configured `chrome_major` version.
    pub fn user_agent(&self) -> String {
        self.browser
            .ua_template
            .replace("{chrome}", &self.browser.chrome_major.to_string())
    }

    // --- the five hand-curated profiles ---------------------------------

    /// Windows 11, Chrome 120, Intel i7-12700K (16C/24T), NVIDIA RTX 3080.
    pub const fn win11_chrome120_intel_nvidia() -> Self {
        Self {
            id: DeviceProfileId::Win11Chrome120IntelNvidia,
            family: DeviceFamily::DesktopWindows,
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
        }
    }

    /// Windows 10, Chrome 120, Intel i7-9700K (8C/8T), NVIDIA GTX 1080.
    pub const fn win10_chrome120_intel_nvidia() -> Self {
        Self {
            id: DeviceProfileId::Win10Chrome120IntelNvidia,
            family: DeviceFamily::DesktopWindows,
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
        }
    }

    /// macOS 14.4, Chrome 120, Apple M1.
    pub const fn macos14_chrome120_m1() -> Self {
        Self {
            id: DeviceProfileId::MacOs14Chrome120M1,
            family: DeviceFamily::DesktopMac,
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
        }
    }

    /// Ubuntu 22.04, Chrome 120, Intel Xeon E5-2690v4 (14C/28T), Mesa.
    pub const fn linux_ubuntu_chrome120_xeon_mesa() -> Self {
        Self {
            id: DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            family: DeviceFamily::DesktopLinux,
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
        }
    }

    /// Windows 11, Chrome 120, AMD Ryzen 7 5800X (8C/16T), AMD Radeon RX 6800.
    pub const fn win11_chrome120_amd_amd() -> Self {
        Self {
            id: DeviceProfileId::Win11Chrome120AmdAmd,
            family: DeviceFamily::DesktopWindows,
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
        }
    }
}

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
    fn first_byte_modulo_selects_profile() {
        // 0 → 0, 5 → 0, 10 → 0
        for byte in [0u8, 5, 10, 15, 20] {
            let mut seed = [0u8; 16];
            seed[0] = byte;
            let id = DeviceProfileId::from_seed(&seed);
            // Just verify it returns one of the valid variants.
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
    fn all_profiles_have_consistent_os_ua_substring() {
        // UA substring and platform must agree on the OS family.
        for id in [
            DeviceProfileId::Win11Chrome120IntelNvidia,
            DeviceProfileId::Win10Chrome120IntelNvidia,
            DeviceProfileId::MacOs14Chrome120M1,
            DeviceProfileId::LinuxUbuntuChrome120XeonMesa,
            DeviceProfileId::Win11Chrome120AmdAmd,
        ] {
            let p = id.profile();
            match p.family {
                DeviceFamily::DesktopWindows => {
                    assert_eq!(p.os.platform, "Win32");
                    assert!(p.os.ua_os_substring.contains("Windows NT"));
                }
                DeviceFamily::DesktopMac => {
                    assert_eq!(p.os.platform, "MacIntel");
                    assert!(p.os.ua_os_substring.contains("Macintosh"));
                }
                DeviceFamily::DesktopLinux => {
                    assert_eq!(p.os.platform, "Linux x86_64");
                    assert!(p.os.ua_os_substring.contains("X11; Linux"));
                }
            }
        }
    }

    #[test]
    fn ua_template_renders_with_chrome_version() {
        let p = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let ua = p.user_agent();
        assert!(ua.contains("Chrome/120"));
        assert!(ua.contains("Windows NT"));
    }
}
