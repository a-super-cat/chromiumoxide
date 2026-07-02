//! Deterministic JavaScript payload generator for `set_fingerprint_seed`.
//!
//! The generated script is injected into every new document via
//! `Page.addScriptToEvaluateOnNewDocument` and *also* evaluated once on the
//! current document via `Runtime.evaluate`. The script is **idempotent** —
//! it sets `window.__stealth_applied` and returns early if the flag is
//! already set, so the double-injection path is safe.
//!
//! The payload does **not** itself reach the network or call back into the
//! Rust side; everything is self-contained JavaScript that runs in the page
//! context before any of the page's own scripts.

use crate::stealth::params::FingerprintSeed;
use crate::stealth::profiles::DeviceProfile;

/// Number of canvas pixels whose LSB we flip per render. Empirically ≤20 is
/// enough to perturb both `getImageData` and `toDataURL`/`toBlob` hashes
/// into a stable new value while staying well below the threshold that
/// visually degrades the canvas.
pub const CANVAS_NOISE_PIXEL_COUNT: usize = 20;

/// Build the init script for the given profile + seed.
///
/// The returned string is guaranteed to be valid JavaScript (we do *not*
/// trust the profile's user_agent string to be JS-safe — we JSON-encode it
/// before splicing into the template) and to be a single IIFE so the global
/// namespace is not polluted.
pub fn build_init_script(profile: &DeviceProfile, seed: &FingerprintSeed) -> String {
    // `navigator.userAgent` is read-only in modern Chrome (Configurable:false)
    // and we override it via CDP `Network.setUserAgentOverride` instead, so
    // we do NOT touch it from the JS payload. The other fields below are
    // settable via `Object.defineProperty` because they are configurable.
    let platform_json = serde_json::to_string(profile.os.platform)
        .expect("static &str cannot fail JSON encoding");
    let primary_lang_json = serde_json::to_string(profile.locale.primary_language)
        .expect("static &str cannot fail JSON encoding");
    let languages_json = serde_json::to_string(profile.locale.languages_list)
        .expect("static array of &strs cannot fail");
    let ua_ch_platform_json = serde_json::to_string(profile.os.user_agent_data_platform)
        .expect("static &str cannot fail JSON encoding");
    let ua_ch_platform_version_json =
        serde_json::to_string(profile.os.user_agent_data_platform_version)
            .expect("static &str cannot fail JSON encoding");
    let hardware_concurrency = profile.hardware.hardware_concurrency;
    let device_memory = profile.hardware.device_memory;
    let webgl_vendor_json = serde_json::to_string(profile.webgl.unmasked_vendor)
        .expect("static &str cannot fail JSON encoding");
    let webgl_renderer_json = serde_json::to_string(profile.webgl.unmasked_renderer)
        .expect("static &str cannot fail JSON encoding");
    let seed_hex = seed.to_hex();
    let noise_pixels_json = serde_json::to_string(&derive_canvas_noise_pixels(seed.as_bytes()))
        .expect("static array of u32 cannot fail");
    let audio_offset = derive_audio_offset(seed.as_bytes());
    let audio_offset_str = format!("{:.17e}", audio_offset);
    let brands_json = build_ua_ch_brands_json(profile);

    format!(
        r#"(function() {{
  // First-line sentinel — must be visible from post-probe even if
  // the rest of the IIFE throws. seed_hex is a hex string and must
  // be quoted — without quotes, JS parses it as decimal and chokes
  // on the embedded `e` (e.g. `9800...e780...`).
  window.__stealth_iife_ran = true;
  window.__stealth_iife_seed = "{seed_hex}";
  // No idempotency guard: a single page can be re-seeded with a
  // different FingerprintSeed (e.g. between A/B test cohorts), and
  // the second call must see the new NOISE_PIXELS, new UA, new
  // profile. Every step below is idempotent — `defineProperty`
  // overwrites the previous getter, and prototype hook functions
  // overwrite previous hooks — so re-applying with a new seed is
  // safe.
  var SEED_HEX = "{seed_hex}";
  var APPLIED_AT = Date.now();

  // Helper: override a property on BOTH Navigator.prototype AND the
  // navigator instance. Modern Chrome defines some properties (webdriver,
  // languages, hardwareConcurrency, deviceMemory) as *own* properties on
  // the instance, with a getter on the prototype. Defining only on the
  // prototype does NOT shadow the instance own property, so we have to
  // hit both. We also `delete` first in case the property is an own
  // data-property (in which case defineProperty would throw).
  function overrideGetter(name, getter) {{
    try {{
      window.__stealth_step = (window.__stealth_step || 0) + 1;
      try {{ delete Navigator.prototype[name]; }} catch (e) {{}}
      Object.defineProperty(Navigator.prototype, name, {{
        get: getter,
        configurable: true,
        enumerable: true,
      }});
    }} catch (e) {{
      window.__stealth_last_err = name + ':proto:' + (e && e.message);
    }}
    try {{
      window.__stealth_step = (window.__stealth_step || 0) + 1;
      try {{ delete navigator[name]; }} catch (e) {{}}
      Object.defineProperty(navigator, name, {{
        get: getter,
        configurable: true,
        enumerable: true,
      }});
    }} catch (e) {{
      window.__stealth_last_err = name + ':inst:' + (e && e.message);
    }}
  }}

  // 1. navigator.webdriver — return undefined, not false. CreepJS checks
  //    `in navigator` to distinguish 'false' from 'undefined'.
  overrideGetter('webdriver', function () {{ return undefined; }});

  // 2. platform
  overrideGetter('platform', function () {{ return {platform_json}; }});

  // 3. language + languages
  overrideGetter('language', function () {{ return {primary_lang_json}; }});
  overrideGetter('languages', function () {{ return {languages_json}; }});

  // 4. hardwareConcurrency + deviceMemory
  overrideGetter('hardwareConcurrency', function () {{ return {hardware_concurrency}; }});
  overrideGetter('deviceMemory', function () {{ return {device_memory}; }});

  // 5. userAgentData (UA-CH) — full HighEntropyValues response
  var UA_DATA = {{
    brands: {brands_json},
    mobile: false,
    platform: {ua_ch_platform_json},
    platformVersion: {ua_ch_platform_version_json},
    architecture: 'x86',
    bitness: '64',
    model: '',
    uaFullVersion: '',
    wow64: false,
    getHighEntropyValues: function (hints) {{
      return Promise.resolve({{
        architecture: 'x86',
        bitness: '64',
        brands: UA_DATA.brands,
        mobile: false,
        model: '',
        platform: UA_DATA.platform,
        platformVersion: UA_DATA.platformVersion,
        uaFullVersion: '',
        wow64: false,
      }});
    }},
    toJSON: function () {{ return UA_DATA; }},
  }};
  overrideGetter('userAgentData', function () {{ return UA_DATA; }});

  // 5. Canvas LSB noise. We use a fixed list of {noise_count} pixel indices
  //    derived from the seed. The same indices are used for getImageData and
  //    toDataURL / toBlob, so any canvas fingerprint is consistent across
  //    APIs.
  var NOISE_PIXELS = {noise_pixels_json};
  // Expose for diagnostic / cross-run hash verification from the host.
  window.__stealth_noise_pixels = NOISE_PIXELS;
  window.__stealth_noise_calls = 0;
  function applyCanvasNoise(ctx, w, h) {{
    if (!ctx) return;
    var img;
    try {{ img = ctx.getImageData(0, 0, w, h); }} catch (e) {{ return; }}
    window.__stealth_noise_calls = (window.__stealth_noise_calls || 0) + 1;
    var data = img.data;
    for (var i = 0; i < NOISE_PIXELS.length; i++) {{
      var idx = NOISE_PIXELS[i] * 4;
      if (idx + 3 < data.length) {{
        data[idx] = data[idx] ^ 0x01;
      }}
    }}
    try {{ ctx.putImageData(img, 0, 0); }} catch (e) {{}}
  }}
  try {{
    var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function () {{
      var img = origGetImageData.apply(this, arguments);
      try {{
        var data = img.data;
        for (var i = 0; i < NOISE_PIXELS.length; i++) {{
          var idx = NOISE_PIXELS[i] * 4;
          if (idx + 3 < data.length) {{
            data[idx] = data[idx] ^ 0x01;
          }}
        }}
      }} catch (e) {{}}
      return img;
    }};
  }} catch (e) {{}}
  try {{
    var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function () {{
      try {{
        var ctx = this.getContext && this.getContext('2d');
        if (ctx) applyCanvasNoise(ctx, this.width, this.height);
      }} catch (e) {{}}
      return origToDataURL.apply(this, arguments);
    }};
  }} catch (e) {{}}
  try {{
    var origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function () {{
      try {{
        var ctx = this.getContext && this.getContext('2d');
        if (ctx) applyCanvasNoise(ctx, this.width, this.height);
      }} catch (e) {{}}
      return origToBlob.apply(this, arguments);
    }};
  }} catch (e) {{}}

  // 6. WebGL vendor / renderer hooks (WebGL1 + WebGL2).
  var WEBGL_VENDOR = {webgl_vendor_json};
  var WEBGL_RENDERER = {webgl_renderer_json};
  function hookWebGL(proto) {{
    if (!proto) return;
    var orig = proto.getParameter;
    proto.getParameter = function (p) {{
      if (p === 37445) return WEBGL_VENDOR;
      if (p === 37446) return WEBGL_RENDERER;
      return orig.apply(this, arguments);
    }};
  }}
  try {{ hookWebGL(WebGLRenderingContext.prototype); }} catch (e) {{}}
  try {{ hookWebGL(WebGL2RenderingContext.prototype); }} catch (e) {{}}

  // 7. AnalyserNode audio fingerprint noise — small constant offset.
  var AUDIO_OFFSET = {audio_offset_str};
  try {{
    var origGetFloat = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function (arr) {{
      var r = origGetFloat.apply(this, arguments);
      try {{
        for (var i = 0; i < r.length; i++) r[i] = r[i] + AUDIO_OFFSET;
      }} catch (e) {{}}
      return r;
    }};
  }} catch (e) {{}}

  window.__stealth_applied = true;
  window.__stealth_seed = SEED_HEX;
  window.__stealth_applied_at = APPLIED_AT;
  if (window.console && console.debug) {{
    console.debug('[smart-browser stealth] applied seed', SEED_HEX);
  }}
}})();
"#,
        primary_lang_json = primary_lang_json,
        languages_json = languages_json,
        ua_ch_platform_json = ua_ch_platform_json,
        ua_ch_platform_version_json = ua_ch_platform_version_json,
        brands_json = brands_json,
        hardware_concurrency = hardware_concurrency,
        device_memory = device_memory,
        noise_count = CANVAS_NOISE_PIXEL_COUNT,
        noise_pixels_json = noise_pixels_json,
        webgl_vendor_json = webgl_vendor_json,
        webgl_renderer_json = webgl_renderer_json,
        audio_offset_str = audio_offset_str,
        seed_hex = seed_hex,
        platform_json = platform_json,
    )
}

/// Default canvas dimensions used by the probe and the noise pixel range.
/// Indexed as a single linear index = `y * WIDTH + x`, so the valid range
/// is `[0, WIDTH * HEIGHT)`.
pub const CANVAS_WIDTH: u32 = 280;
pub const CANVAS_HEIGHT: u32 = 60;
pub const CANVAS_PIXELS: u32 = CANVAS_WIDTH * CANVAS_HEIGHT;

/// Derive 20 canvas-noise pixel indices from a 16-byte seed. The same seed
/// always yields the same list, so the canvas fingerprint is stable across
/// runs and across users with the same seed.
///
/// Each output is a u32 in `[0, CANVAS_PIXELS)` — values outside this range
/// would be silently no-op'd by the canvas hook (the `idx + 3 < data.length`
/// check), defeating the noise. We pack two seed bytes per slot, fold
/// with a per-slot mix of the running index, and reduce mod the canvas size.
pub fn derive_canvas_noise_pixels(seed: &[u8; 16]) -> [u32; CANVAS_NOISE_PIXEL_COUNT] {
    let mut out = [0u32; CANVAS_NOISE_PIXEL_COUNT];
    for (i, slot) in out.iter_mut().enumerate() {
        // Use two seed bytes per slot, with a per-slot index mix so
        // adjacent slots don't share the same pair of bytes.
        let b0 = seed[(i * 2) % 16] as u32;
        let b1 = seed[(i * 2 + 1) % 16] as u32;
        let mut v = (b0 << 8) | b1; // 0..=65535
        // Mix the slot index in to break the obvious pattern if the seed
        // bytes happen to be the same for two consecutive slots.
        v ^= (i as u32).wrapping_mul(0x9e3779b9);
        *slot = v % CANVAS_PIXELS;
    }
    out
}

/// Derive the AnalyserNode offset (in `f64`, range ±1e-7) from the seed.
pub fn derive_audio_offset(seed: &[u8; 16]) -> f64 {
    let bytes = [seed[2], seed[3], seed[4], seed[5]];
    let n = i32::from_le_bytes(bytes);
    // Map to [-1.0, 1.0]
    let normalized = (n as f64) / (i32::MAX as f64);
    normalized * 1e-7
}

fn build_ua_ch_brands_json(profile: &DeviceProfile) -> String {
    // UA-CH `brands` is always exactly 2 entries, each
    // `{brand: "Chromium" / "Google Chrome", version: "<trimmed>"}`.
    let ver = profile.browser.chrome_major;
    let brands = vec![
        serde_json::json!({ "brand": "Google Chrome", "version": format!("{}", ver) }),
        serde_json::json!({ "brand": "Chromium", "version": format!("{}", ver) }),
    ];
    serde_json::to_string(&brands).expect("static json! cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::profiles::DeviceProfileId;

    #[test]
    fn same_seed_yields_same_noise_pixels() {
        let seed = [0u8; 16];
        let a = derive_canvas_noise_pixels(&seed);
        let b = derive_canvas_noise_pixels(&seed);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_yield_different_pixels() {
        let a = derive_canvas_noise_pixels(&[0u8; 16]);
        let b = derive_canvas_noise_pixels(&[1u8; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn audio_offset_in_expected_range() {
        for byte in 0u8..=255 {
            let mut seed = [0u8; 16];
            seed[2] = byte;
            let off = derive_audio_offset(&seed);
            assert!(off.abs() <= 1e-7, "offset {} out of range", off);
        }
    }

    #[test]
    fn init_script_is_idempotent_marker() {
        let profile = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);
        assert!(script.contains("__stealth_applied"));
        // Must be one IIFE.
        assert!(script.starts_with("(function"));
    }

    #[test]
    fn init_script_contains_profile_values() {
        let profile = DeviceProfileId::MacOs14Chrome120M1.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);
        assert!(script.contains("MacIntel"));
        assert!(script.contains("Apple M1"));
        // Seed hex (16 bytes) → 32 hex chars.
        assert!(script.contains("00000000000000000000000000000000"));
    }

    #[test]
    fn init_script_user_agent_is_not_in_payload() {
        // We do NOT override `navigator.userAgent` from JS — it is read-only
        // in modern Chrome (Configurable:false) and is set via
        // `Network.setUserAgentOverride` in the CDP layer instead. The
        // payload should not contain the user-agent string at all.
        let profile = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);
        assert!(!script.contains("Mozilla/5.0"));
    }

    #[test]
    fn init_script_contains_webgl_constants() {
        let profile = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);
        // WebGL constants 37445 (UNMASKED_VENDOR) and 37446 (UNMASKED_RENDERER).
        assert!(script.contains("37445"));
        assert!(script.contains("37446"));
        assert!(script.contains("Google Inc. (NVIDIA)"));
    }
}
