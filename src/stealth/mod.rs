//! `Page::set_fingerprint_seed` — apply a deterministic browser fingerprint
//! to the current CDP page.
//!
//! This is the M5 prototype. It applies the following 9 overrides, all
//! deterministically derived from a 16-byte
//! [`FingerprintSeed`](params::FingerprintSeed) and a hand-curated
//! [`DeviceProfile`](profiles::DeviceProfile):
//!
//! | Field | Path |
//! |---|---|
//! | `navigator.webdriver` | JS (delete + `defineProperty` → `undefined`) |
//! | `navigator.platform` | JS |
//! | `navigator.language` / `navigator.languages` | JS |
//! | `navigator.hardwareConcurrency` / `navigator.deviceMemory` | JS |
//! | `navigator.userAgentData` (UA-CH) | JS |
//! | Canvas `getImageData` / `toDataURL` / `toBlob` | JS (LSB noise, seed-derived) |
//! | `WebGLRenderingContext.getParameter` (UNMASKED_VENDOR/RENDERER) | JS |
//! | `AnalyserNode.getFloatFrequencyData` | JS (constant offset, seed-derived) |
//! | User-Agent header | CDP `Network.setUserAgentOverride` |
//! | Timezone | CDP `Emulation.setTimezoneOverride` |
//!
//! Wire strategy: **hybrid**. We both
//! 1. send the script via `Page.addScriptToEvaluateOnNewDocument` (so it
//!    re-runs on every future navigation), and
//! 2. evaluate the script once on the current document via `Runtime.evaluate`
//!    (so the current document is also covered without needing a refresh).
//!
//! Both are necessary because stock Chromium does not yet have a `Stealth`
//! CDP domain — we use the existing `Page` / `Network` / `Emulation` /
//! `Runtime` domains. The script is **idempotent** (`window.__stealth_applied`
//! guard), so the double-injection is safe.
//!
//! ## Stability
//!
//! `FingerprintSeed::from_str` / `FingerprintSeed::from_hex` / `DeviceProfileId::from_seed`
//! are all stable. Given the same seed, the *exact same* fingerprint is
//! produced on every run, on every platform.

pub mod alignment;
pub mod launch_args;
pub mod params;
pub mod profiles;
pub mod script;
pub mod validator;

pub use alignment::{AlignmentError, AlignmentErrorKind, FingerprintAlignment};
pub use params::{
    AppliedStep, FingerprintApplicationReport, FingerprintApplyOptions, FingerprintScope,
    FingerprintSeed, SeedParseError, SetFingerprintSeedParams,
};
pub use profiles::{DeviceFamily, DeviceProfile, DeviceProfileId};
pub use script::{
    build_init_script, derive_audio_offset, derive_canvas_noise_pixels, CANVAS_NOISE_PIXEL_COUNT,
};
pub use validator::{
    validate_profile, Inconsistency, InconsistencyKind, ValidationReport, Severity,
};
pub use launch_args::{
    launch_args_for_family, launch_args_for_family_id, window_size_for_family,
    window_size_for_family_id,
};

use crate::cdp::browser_protocol::emulation::SetTimezoneOverrideParams;
use crate::cdp::browser_protocol::network::SetUserAgentOverrideParams;
use crate::cdp::browser_protocol::page::AddScriptToEvaluateOnNewDocumentParams;
use crate::cdp::js_protocol::runtime::EvaluateParams;
use crate::error::{CdpError, Result};
use crate::page::Page;

impl Page {
    /// Apply a deterministic fingerprint seed to this page.
    ///
    /// The seed deterministically selects a
    /// [`DeviceProfileId`](profiles::DeviceProfileId) (and, through it, a
    /// device profile), and then applies every field listed in the module
    /// docs. The application is **idempotent within a page**: if the page
    /// already has `window.__stealth_applied` set, the JS script returns
    /// early and only the CDP-level overrides (UA, timezone) are re-asserted.
    ///
    /// The call returns a [`FingerprintApplicationReport`] describing which
    /// profile was selected and which steps were applied.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use chromiumoxide::{Browser, BrowserConfig};
    /// # use chromiumoxide::stealth::FingerprintSeed;
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// # let (browser, _handler) = Browser::launch(BrowserConfig::builder().with_head().build()?).await?;
    /// # let page = browser.new_page("about:blank").await?;
    /// let report = page
    ///     .set_fingerprint_seed(FingerprintSeed::from_str("user-42"))
    ///     .await?;
    /// println!("selected profile: {:?}", report.profile_id);
    /// # Ok(()) }
    /// ```
    pub async fn set_fingerprint_seed(
        &self,
        params: impl Into<SetFingerprintSeedParams>,
    ) -> Result<FingerprintApplicationReport> {
        let params = params.into();
        let seed = params.seed;
        let opts = params.options;

        // 1. Pick the profile (override or seed-derived).
        let profile_id = opts
            .profile_override
            .unwrap_or_else(|| DeviceProfileId::from_seed(seed.as_bytes()));
        let profile = profile_id.profile();

        // 1a. M5.5+ fail-fast: validate profile spec before injection.
        let report = validate_profile(&profile);
        if report.has_errors() {
            return Err(CdpError::msg(format!(
                "DeviceProfile {:?} (from seed) failed validation:\n{}",
                profile_id, report
            )));
        }
        for w in report.warnings() {
            tracing::warn!(target: "chromiumoxide::stealth", "{}", w.message);
        }

        // 2. Validate any caller-supplied alignment.
        if let Some(align) = &opts.alignment {
            align.validate_against(&profile)?;
        }

        // 3. Build the JS payload.
        let script = build_init_script(&profile, &seed);
        let mut applied = Vec::with_capacity(4);

        // 4. Apply the CDP-level overrides that must precede the script
        //    (UA + Accept-Language header, timezone).
        let effective_ua = profile.user_agent();
        let effective_accept_language = opts
            .alignment
            .as_ref()
            .and_then(|a| a.accept_language.clone())
            .unwrap_or_else(|| profile.locale.accept_language.to_string());
        let effective_platform = profile.os.platform.to_string();

        let ua_params = SetUserAgentOverrideParams {
            user_agent: effective_ua,
            accept_language: Some(effective_accept_language),
            platform: Some(effective_platform),
            user_agent_metadata: None,
        };
        self.execute(ua_params).await?;
        applied.push(AppliedStep {
            name: "Network.setUserAgentOverride",
            no_op: false,
        });

        let effective_tz = opts
            .alignment
            .as_ref()
            .and_then(|a| a.timezone_id.clone())
            .unwrap_or_else(|| profile.locale.timezone_id.to_string());
        let tz_params = SetTimezoneOverrideParams {
            timezone_id: effective_tz,
        };
        self.execute(tz_params).await?;
        applied.push(AppliedStep {
            name: "Emulation.setTimezoneOverride",
            no_op: false,
        });

        // 5. addScriptToEvaluateOnNewDocument — runs on every future nav.
        let add_params = AddScriptToEvaluateOnNewDocumentParams {
            source: script.clone(),
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        };
        self.execute(add_params).await?;
        applied.push(AppliedStep {
            name: "Page.addScriptToEvaluateOnNewDocument",
            no_op: false,
        });

        // 6. Runtime.evaluate on the current document.
        //
        // CRITICAL: we route the evaluation through `evaluate_expression`,
        // not `self.execute(EvaluateParams)`. The latter sends
        // `Runtime.evaluate` with no `contextId`, and Chrome routes that
        // to the *isolated* (utility) world of the target — a different
        // JS realm whose `window` and `Navigator.prototype` are not the
        // main world's. Changes to the isolated world's `Navigator`
        // prototype are not visible from the main world, so stealth's
        // property overrides silently fail.
        //
        // `evaluate_expression` resolves the main-world `ExecutionContextId`
        // internally and pins the evaluation there. The script's effects
        // (Navigator.prototype getter overrides, `window.__stealth_*`
        // sentinels) are then visible to subsequent main-world code
        // (e.g. page scripts, fingerprint detection pages).
        let _ = self.evaluate_expression(script).await?;
        applied.push(AppliedStep {
            name: "Runtime.evaluate",
            no_op: false,
        });

        Ok(FingerprintApplicationReport {
            seed,
            profile_id,
            applied,
        })
    }

    /// Apply a specific [`DeviceProfile`] directly (M5.5+).
    ///
    /// Unlike [`set_fingerprint_seed`](Page::set_fingerprint_seed), this API
    /// does **not** derive the profile from a seed — it uses the profile
    /// the caller specifies. Use this to switch the page's fingerprint to
    /// a known, hand-curated family (e.g. `IosSafariIphone14` for a
    /// mobile-compat test) without going through the seed-derivation
    /// hash.
    ///
    /// The five M5 desktop profiles (Chrome 120 era) are reachable via
    /// both APIs. The five M5.5+ families (Chrome 148, iOS Safari, Android
    /// Chrome, Android System WebView, iOS WKWebView) are reachable only via
    /// this API — they are not in the seed-derivation hash.
    ///
    /// The applied `BrowserContext` fingerprint is **deterministic per
    /// profile** (not per seed) — calling `set_device_profile(X)` twice
    /// produces identical fingerprints.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use chromiumoxide::{Browser, BrowserConfig};
    /// # use chromiumoxide::stealth::DeviceProfileId;
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// # let (browser, _handler) = Browser::launch(BrowserConfig::builder().with_head().build()?).await?;
    /// # let page = browser.new_page("about:blank").await?;
    /// let report = page.set_device_profile(DeviceProfileId::AndroidChromePixel7).await?;
    /// println!("switched to profile: {:?}", report.profile_id);
    /// // ... later, switch to a different family:
    /// let report2 = page.set_device_profile(DeviceProfileId::IosSafariIphone14).await?;
    /// # Ok(()) }
    /// ```
    pub async fn set_device_profile(
        &self,
        profile_id: DeviceProfileId,
    ) -> Result<FingerprintApplicationReport> {
        let profile = profile_id.profile();

        // 0. M5.5+ fail-fast: validate profile spec internal consistency
        //    before injection. 26 checks across 3 layers (UA / UA-CH /
        //    navigator / screen / locale / platform / webview). Any
        //    Severity::Error finding → refuse to inject.
        let report = validate_profile(&profile);
        if report.has_errors() {
            return Err(CdpError::msg(format!(
                "DeviceProfile {:?} failed validation:\n{}",
                profile_id, report
            )));
        }
        for w in report.warnings() {
            tracing::warn!(target: "chromiumoxide::stealth", "{}", w.message);
        }

        // 1. CDP-level overrides that must precede the script
        //    (UA + Accept-Language header, timezone).
        let effective_ua = profile.user_agent();
        let effective_accept_language = profile.locale.accept_language.to_string();
        let effective_platform = profile.os.platform.to_string();

        let ua_params = SetUserAgentOverrideParams {
            user_agent: effective_ua,
            accept_language: Some(effective_accept_language),
            platform: Some(effective_platform),
            user_agent_metadata: None,
        };
        self.execute(ua_params).await?;
        let mut applied = Vec::with_capacity(4);
        applied.push(AppliedStep {
            name: "Network.setUserAgentOverride",
            no_op: false,
        });

        let tz_params = SetTimezoneOverrideParams {
            timezone_id: profile.locale.timezone_id.to_string(),
        };
        self.execute(tz_params).await?;
        applied.push(AppliedStep {
            name: "Emulation.setTimezoneOverride",
            no_op: false,
        });

        // 2. Build the script and inject it.
        let script = build_init_script(&profile, &FingerprintSeed::ZERO);
        let add_params = AddScriptToEvaluateOnNewDocumentParams {
            source: script.clone(),
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        };
        self.execute(add_params).await?;
        applied.push(AppliedStep {
            name: "Page.addScriptToEvaluateOnNewDocument",
            no_op: false,
        });

        // 3. Runtime.evaluate on the current document (pinned main world).
        let _ = self.evaluate_expression(script).await?;
        applied.push(AppliedStep {
            name: "Runtime.evaluate",
            no_op: false,
        });

        Ok(FingerprintApplicationReport {
            seed: FingerprintSeed::ZERO,
            profile_id,
            applied,
        })
    }
}

impl From<AlignmentError> for CdpError {
    fn from(err: AlignmentError) -> Self {
        CdpError::msg(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexports_resolve() {
        // Smoke test — just reference each re-export so the `use` lines do
        // not get dead-code-eliminated in a way that would mask a compile
        // break.
        let _: FingerprintSeed = FingerprintSeed::ZERO;
        let _: DeviceProfileId = DeviceProfileId::Win11Chrome120IntelNvidia;
        let _: FingerprintAlignment = FingerprintAlignment::default();
        let _: FingerprintScope = FingerprintScope::Persistent;
        let _: FingerprintApplyOptions = FingerprintApplyOptions::default();
    }

    #[test]
    fn params_default_scope_is_persistent() {
        assert_eq!(FingerprintScope::default(), FingerprintScope::Persistent);
    }
}
