//! Per-family launch arg computation (M5.5+).
//!
//! M5 used a single `BrowserConfig` shape for all profiles — desktop
//! defaults applied to everything. M5.5+ adds per-family launch arg
//! computation so mobile / webview profiles get the right viewport
//! size, touch events, and language flags at process launch.
//!
//! ## What changes per family
//!
//! | Knob | Desktop | Mobile | Webview |
//! |------|---------|--------|---------|
//! | `window_size` | profile screen (e.g. 1920x1080) | profile screen (e.g. 412x915) | profile screen |
//! | `--lang` | `profile.locale.primary_language` (e.g. `en-US`) | same | same |
//! | `--touch-events` | not set | `enabled` | `enabled` |
//! | `--enable-features=ConversionMeasurement` | not set | enabled | enabled |
//!
//! ## Why these knobs
//!
//! Chromium exposes most "mobile emulation" via CDP
//! (`setDeviceMetricsOverride`, `setTouchEmulationEnabled`), not launch
//! args. The launch args here affect the **outer shell** (window size
//! for OS-level scaling, lang for `Accept-Language` header default,
//! touch events for the underlying input pipeline). The CDP-level
//! overrides are applied per-page in
//! [`set_device_profile`](crate::stealth::Page::set_device_profile).
//!
//! ## Usage
//!
//! ```no_run
//! # use chromiumoxide::{Browser, BrowserConfig};
//! # use chromiumoxide::stealth::{DeviceProfileId, launch_args_for_family};
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = DeviceProfileId::AndroidChromePixel7.profile();
//! let args = launch_args_for_family(&profile);
//! let cfg = BrowserConfig::builder()
//!     .chrome_executable("D:\\chromium-148-build\\out\\Release\\chrome.exe")
//!     .no_sandbox()
//!     .window_size(profile.screen.width, profile.screen.height)
//!     .args(args)
//!     .build()?;
//! let (browser, _handler) = Browser::launch(cfg).await?;
//! # Ok(()) }
//! ```

use crate::stealth::profiles::{DeviceProfile, DeviceProfileId};

/// Per-family launch arg set. Pure data — caller applies to a
/// `BrowserConfig` via the builder's `args()` method.
///
/// Returned vector is **append-only** — caller-supplied args should
/// be passed via a separate `args()` chain, not prepended here.
pub fn launch_args_for_family(profile: &DeviceProfile) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    // --lang: chromium's default Accept-Language header is derived from
    // the --lang flag. Setting it here means HTTP requests sent before
    // the CDP Network.setUserAgentOverride lands will still carry the
    // right language. (After CDP lands, the override takes precedence.)
    args.push(format!("--lang={}", profile.locale.primary_language));

    // Touch events: mobile and webview families need touch-enabled
    // input pipeline. Without this, pointermove events are simulated as
    // mouse, and pages that check `matchMedia('(pointer: coarse)')`
    // report the wrong value.
    if profile.is_mobile() {
        args.push("--touch-events=enabled".to_string());

        // ConversionMeasurement is a Chrome mobile / WebView feature
        // for attribution. Desktop Chromium has it disabled by default;
        // enabling it for mobile profiles brings the binary closer to
        // a real mobile device. Safe to enable for both Android Chrome
        // and Android System WebView.
        args.push("--enable-features=ConversionMeasurement".to_string());
    }

    // WebView-specific: Android System WebView uses a different
    // process model. We don't change launch args for it (chromium
    // binary is the same), but the JS payload (init script) handles
    // the webview-specific fingerprinting surfaces.

    args
}

/// Per-family window size for `BrowserConfigBuilder::window_size`.
///
/// Convenience: returns `(width, height)` from the profile's
/// `screen` spec. Use this when you want OS-level window manager
/// sizing to match the profile.
pub fn window_size_for_family(profile: &DeviceProfile) -> (u32, u32) {
    (profile.screen.width, profile.screen.height)
}

/// Convenience overload: same as [`launch_args_for_family`] but takes
/// a [`DeviceProfileId`] directly.
pub fn launch_args_for_family_id(profile_id: DeviceProfileId) -> Vec<String> {
    launch_args_for_family(&profile_id.profile())
}

/// Convenience overload: same as [`window_size_for_family`] but takes
/// a [`DeviceProfileId`] directly.
pub fn window_size_for_family_id(profile_id: DeviceProfileId) -> (u32, u32) {
    window_size_for_family(&profile_id.profile())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::profiles::DeviceProfileId;

    #[test]
    fn desktop_gets_lang_no_touch() {
        let p = DeviceProfileId::DesktopChrome148Win11.profile();
        let args = launch_args_for_family(&p);
        // Should have --lang but not --touch-events.
        assert!(args.iter().any(|a| a.starts_with("--lang=")));
        assert!(!args.iter().any(|a| a == "--touch-events=enabled"));
    }

    #[test]
    fn mobile_chrome_gets_touch_and_lang() {
        let p = DeviceProfileId::AndroidChromePixel7.profile();
        let args = launch_args_for_family(&p);
        assert!(args.iter().any(|a| a.starts_with("--lang=en-US")));
        assert!(args.iter().any(|a| a == "--touch-events=enabled"));
        assert!(args.iter().any(|a| a == "--enable-features=ConversionMeasurement"));
    }

    #[test]
    fn webview_gets_touch_and_lang() {
        let p = DeviceProfileId::AndroidWebViewPixel7.profile();
        let args = launch_args_for_family(&p);
        assert!(args.iter().any(|a| a.starts_with("--lang=")));
        assert!(args.iter().any(|a| a == "--touch-events=enabled"));
    }

    #[test]
    fn ios_safari_gets_touch_and_lang() {
        let p = DeviceProfileId::IosSafariIphone14.profile();
        let args = launch_args_for_family(&p);
        assert!(args.iter().any(|a| a.starts_with("--lang=en-US")));
        assert!(args.iter().any(|a| a == "--touch-events=enabled"));
    }

    #[test]
    fn ios_wkwebview_gets_touch_and_lang() {
        let p = DeviceProfileId::IosWkWebviewIphone14.profile();
        let args = launch_args_for_family(&p);
        assert!(args.iter().any(|a| a.starts_with("--lang=")));
        assert!(args.iter().any(|a| a == "--touch-events=enabled"));
    }

    #[test]
    fn win10_desktop_chrome120_gets_lang_no_touch() {
        let p = DeviceProfileId::Win10Chrome120IntelNvidia.profile();
        let args = launch_args_for_family(&p);
        assert!(args.iter().any(|a| a.starts_with("--lang=")));
        assert!(!args.iter().any(|a| a == "--touch-events=enabled"));
    }

    #[test]
    fn window_size_for_family_matches_screen_spec() {
        let p = DeviceProfileId::AndroidChromePixel7.profile();
        let (w, h) = window_size_for_family(&p);
        assert_eq!(w, p.screen.width);
        assert_eq!(h, p.screen.height);
        assert_eq!((w, h), (412, 915));
    }

    #[test]
    fn id_overloads_match_full_profile() {
        let profile_args = launch_args_for_family(&DeviceProfileId::IosSafariIphone14.profile());
        let id_args = launch_args_for_family_id(DeviceProfileId::IosSafariIphone14);
        assert_eq!(profile_args, id_args);

        let profile_size = window_size_for_family(&DeviceProfileId::IosSafariIphone14.profile());
        let id_size = window_size_for_family_id(DeviceProfileId::IosSafariIphone14);
        assert_eq!(profile_size, id_size);
    }

    #[test]
    fn lang_arg_uses_primary_language() {
        // All current profiles use en-US as primary; verify the
        // derived --lang matches.
        for id in [
            DeviceProfileId::DesktopChrome148Win11,
            DeviceProfileId::IosSafariIphone14,
            DeviceProfileId::AndroidChromePixel7,
            DeviceProfileId::AndroidWebViewPixel7,
            DeviceProfileId::IosWkWebviewIphone14,
        ] {
            let p = id.profile();
            let args = launch_args_for_family(&p);
            let lang_arg = format!("--lang={}", p.locale.primary_language);
            assert!(
                args.contains(&lang_arg),
                "profile {:?} expected lang arg '{}' in {:?}",
                id, lang_arg, args
            );
        }
    }
}
