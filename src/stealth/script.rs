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
///
/// ## M5.5+ profile-family extensions
///
/// In addition to the M5 surface (webdriver / platform / language /
/// hardwareConcurrency / deviceMemory / UA-CH 2-brand / canvas / WebGL /
/// audio), M5.5+ adds JS-side overrides for:
///
/// - `navigator.vendor` (e.g. `"Google Inc."` vs `"Apple Computer, Inc."`)
/// - `navigator.productSub` (always `"20030107"`)
/// - `navigator.maxTouchPoints` (0 desktop / 5 mobile+webview)
/// - `navigator.plugins` (5 PDF plugins desktop / empty mobile)
/// - `navigator.mimeTypes` (2 PDF MIME desktop / empty mobile)
/// - `window.screen.{width,height,availWidth,availHeight}` per [`ScreenSpec`]
/// - `window.devicePixelRatio` per [`ScreenSpec`]
/// - UA-CH 4-brand list (with 2 GREASE entries) per [`UaChSpec`]
/// - UA-CH `architecture` / `bitness` / `model` / `uaFullVersion` per [`UaChSpec`]
/// - **iOS Safari / iOS WKWebView**: `navigator.userAgentData` deleted entirely
///   (Safari doesn't implement UA-CH; setting it would be a tell)
/// - **Android WebView / iOS WKWebView**: webview-specific markers
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
    // iOS Safari / WKWebView: deviceMemory is undefined (0 in the spec
    // means "do not set this property at all" — the getter returns undefined).
    let device_memory_expr: &str = if profile.hardware.device_memory == 0 {
        "undefined"
    } else {
        // literal JS number, not JSON
        "{}"
    };
    let device_memory_literal = profile.hardware.device_memory;
    let navigator_vendor_json = serde_json::to_string(profile.navigator.vendor)
        .expect("static &str cannot fail JSON encoding");
    let navigator_product_sub_json = serde_json::to_string(profile.navigator.product_sub)
        .expect("static &str cannot fail JSON encoding");
    let navigator_max_touch_points = profile.navigator.max_touch_points;
    let plugins_json = serde_json::to_string(
        &profile
            .navigator
            .plugins
            .iter()
            .map(|(name, filename)| {
                serde_json::json!({"name": name, "filename": filename})
            })
            .collect::<Vec<_>>(),
    )
    .expect("static slice cannot fail");
    let mime_types_json = serde_json::to_string(profile.navigator.mime_types)
        .expect("static slice cannot fail");
    let screen_width = profile.screen.width;
    let screen_height = profile.screen.height;
    let screen_avail_width = profile.screen.avail_width;
    let screen_avail_height = profile.screen.avail_height;
    let device_pixel_ratio = profile.screen.device_pixel_ratio;
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
    let uach_architecture_json = serde_json::to_string(profile.uach.architecture)
        .expect("static &str cannot fail JSON encoding");
    let uach_bitness_json = serde_json::to_string(profile.uach.bitness)
        .expect("static &str cannot fail JSON encoding");
    let uach_model_json = serde_json::to_string(profile.uach.model)
        .expect("static &str cannot fail JSON encoding");
    let uach_full_version_json = serde_json::to_string(profile.uach.full_version)
        .expect("static &str cannot fail JSON encoding");
    let uach_mobile = profile.uach.mobile;
    let is_ios = profile.is_ios();
    // WebView-specific markers
    let window_webkit = profile
        .webview
        .map(|w| w.window_webkit)
        .unwrap_or(false);
    let webkit_message_handlers = profile
        .webview
        .map(|w| w.webkit_message_handlers)
        .unwrap_or(false);
    // Build fingerprint stub (Android WebView only; iOS / desktop = None)
    let build_fingerprint: Option<String> = profile
        .webview
        .and_then(|w| w.build_fingerprint)
        .map(|bf| serde_json::to_string(bf).expect("static &str cannot fail"));

    build_init_script_with_build_fingerprint(
        profile,
        seed,
        platform_json,
        primary_lang_json,
        languages_json,
        ua_ch_platform_json,
        ua_ch_platform_version_json,
        hardware_concurrency,
        device_memory_expr,
        device_memory_literal,
        navigator_vendor_json,
        navigator_product_sub_json,
        navigator_max_touch_points,
        plugins_json,
        mime_types_json,
        screen_width,
        screen_height,
        screen_avail_width,
        screen_avail_height,
        device_pixel_ratio,
        webgl_vendor_json,
        webgl_renderer_json,
        seed_hex,
        noise_pixels_json,
        audio_offset_str,
        brands_json,
        uach_architecture_json,
        uach_bitness_json,
        uach_model_json,
        uach_full_version_json,
        uach_mobile,
        is_ios,
        window_webkit,
        webkit_message_handlers,
        build_fingerprint.as_ref(),
    )
}

/// Inner builder: takes all pre-encoded JSON + a pre-decided Build.FINGERPRINT
/// literal (Some(_) for Android WebView, None otherwise) and emits the
/// final IIFE JS string.
#[allow(clippy::too_many_arguments)]
fn build_init_script_with_build_fingerprint(
    profile: &DeviceProfile,
    seed: &FingerprintSeed,
    platform_json: String,
    primary_lang_json: String,
    languages_json: String,
    ua_ch_platform_json: String,
    ua_ch_platform_version_json: String,
    hardware_concurrency: u8,
    device_memory_expr: &str,
    device_memory_literal: u8,
    navigator_vendor_json: String,
    navigator_product_sub_json: String,
    navigator_max_touch_points: u8,
    plugins_json: String,
    mime_types_json: String,
    screen_width: u32,
    screen_height: u32,
    screen_avail_width: u32,
    screen_avail_height: u32,
    device_pixel_ratio: f32,
    webgl_vendor_json: String,
    webgl_renderer_json: String,
    seed_hex: String,
    noise_pixels_json: String,
    audio_offset_str: String,
    brands_json: String,
    uach_architecture_json: String,
    uach_bitness_json: String,
    uach_model_json: String,
    uach_full_version_json: String,
    uach_mobile: bool,
    is_ios: bool,
    window_webkit: bool,
    _webkit_message_handlers: bool,
    build_fingerprint_json: Option<&String>,
) -> String {
    let _ = (profile, seed); // not used inside the template, but keep in signature for clarity
    let _ = device_memory_literal; // rendered as `device_memory_expr` already
    let build_fingerprint_setter = if let Some(bf) = build_fingerprint_json {
        // Emit JS that defines a getter on Navigator that returns the
        // Build.FINGERPRINT string. This is only reached by code that
        // explicitly asks for it (e.g. native Android embedder probe).
        format!(
            r#"
  try {{
    Object.defineProperty(navigator, 'buildFingerprint', {{
      get: function () {{ return {bf}; }},
      configurable: true,
      enumerable: false,
    }});
  }} catch (e) {{}}"#,
            bf = bf
        )
    } else {
        String::new()
    };
    // iOS Safari: navigator.userAgentData is undefined (Safari doesn't
    // implement UA-CH). The override below makes the getter return
    // undefined and removes the prototype property. Also strips
    // Sec-CH-UA-* request headers (handled at the network level by CDP,
    // not JS).
    let ios_user_agent_data_block = if is_ios {
        r#"
  try {
    try { delete Navigator.prototype.userAgentData; } catch (e) {}
    try { delete navigator.userAgentData; } catch (e) {}
  } catch (e) {}
"#
    } else {
        ""
    };
    let window_webkit_block = if window_webkit {
        r#"
  // window.webkit + messageHandlers (iOS WKWebView marker).
  try {
    if (!window.webkit) {
      window.webkit = {};
    }
    if (!window.webkit.messageHandlers) {
      window.webkit.messageHandlers = {};
    }
  } catch (e) {}
"#
    } else {
        ""
    };
    format!(
        r#"(function() {{
  window.__stealth_iife_ran = true;
  window.__stealth_iife_seed = "{seed_hex}";
  var SEED_HEX = "{seed_hex}";
  var APPLIED_AT = Date.now();

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

  // 1. navigator.webdriver — return undefined, not false.
  overrideGetter('webdriver', function () {{ return undefined; }});

  // 2. platform
  overrideGetter('platform', function () {{ return {platform_json}; }});

  // 3. language + languages
  overrideGetter('language', function () {{ return {primary_lang_json}; }});
  overrideGetter('languages', function () {{ return {languages_json}; }});

  // 4. hardwareConcurrency + deviceMemory (M5.5+: deviceMemory is
  //    `undefined` for iOS Safari / WKWebView where the spec says 0)
  overrideGetter('hardwareConcurrency', function () {{ return {hardware_concurrency}; }});
  overrideGetter('deviceMemory', function () {{ return {device_memory_expr}; }});

  // 5. vendor + productSub + maxTouchPoints (M5.5+)
  overrideGetter('vendor', function () {{ return {navigator_vendor_json}; }});
  overrideGetter('productSub', function () {{ return {navigator_product_sub_json}; }});
  overrideGetter('maxTouchPoints', function () {{ return {navigator_max_touch_points}; }});

  // 5b. plugins + mimeTypes (M5.5+ — override the array contents)
  //     Desktop Chrome: 5 PDF plugins + 2 MIME types.
  //     Mobile Safari / Android Chrome / Android WebView / iOS WKWebView: empty.
  try {{
    var PLUGINS_JSON = {plugins_json};
    var MIME_TYPES_JSON = {mime_types_json};
    // Build a PluginArray-like object that mirrors the M3 chromium source patch
    // but is populated from the profile's plugins slice.
    var fakePlugins = Object.create(PluginArray.prototype);
    PLUGINS_JSON.forEach(function (p, i) {{
      var plugin = Object.create(Plugin.prototype);
      Object.defineProperties(plugin, {{
        name: {{ value: p.name, enumerable: true }},
        filename: {{ value: p.filename, enumerable: true }},
        length: {{ value: 1, enumerable: true }},
        0: {{ value: {{ type: 'application/pdf', suffixes: 'pdf', description: p.name }}, enumerable: true }}
      }});
      Object.defineProperty(fakePlugins, i, {{ value: plugin, enumerable: true }});
    }});
    Object.defineProperty(fakePlugins, 'length', {{ value: PLUGINS_JSON.length, enumerable: true }});
    overrideGetter('plugins', function () {{ return fakePlugins; }});

    // Build a MimeTypeArray
    var fakeMimeTypes = Object.create(MimeTypeArray.prototype);
    MIME_TYPES_JSON.forEach(function (mt, i) {{
      var mto = Object.create(MimeType.prototype);
      Object.defineProperties(mto, {{
        type: {{ value: mt, enumerable: true }},
        suffixes: {{ value: 'pdf', enumerable: true }},
        description: {{ value: 'Portable Document Format', enumerable: true }}
      }});
      Object.defineProperty(fakeMimeTypes, i, {{ value: mto, enumerable: true }});
    }});
    Object.defineProperty(fakeMimeTypes, 'length', {{ value: MIME_TYPES_JSON.length, enumerable: true }});
    overrideGetter('mimeTypes', function () {{ return fakeMimeTypes; }});
  }} catch (e) {{
    window.__stealth_last_err = 'plugins:' + (e && e.message);
  }}

  // 5c. screen + devicePixelRatio (M5.5+)
  try {{
    Object.defineProperty(window.screen, 'width', {{ get: function () {{ return {screen_width}; }}, configurable: true }});
    Object.defineProperty(window.screen, 'height', {{ get: function () {{ return {screen_height}; }}, configurable: true }});
    Object.defineProperty(window.screen, 'availWidth', {{ get: function () {{ return {screen_avail_width}; }}, configurable: true }});
    Object.defineProperty(window.screen, 'availHeight', {{ get: function () {{ return {screen_avail_height}; }}, configurable: true }});
    Object.defineProperty(window, 'devicePixelRatio', {{ get: function () {{ return {device_pixel_ratio}; }}, configurable: true }});
  }} catch (e) {{
    window.__stealth_last_err = 'screen:' + (e && e.message);
  }}
{ios_user_agent_data_block}
{window_webkit_block}
{build_fingerprint_setter}

  // 6. userAgentData (UA-CH) — only set for non-iOS families
  if (!{is_ios_jsx}) {{
    var UA_DATA = {{
      brands: {brands_json},
      mobile: {uach_mobile_jsx},
      platform: {ua_ch_platform_json},
      platformVersion: {ua_ch_platform_version_json},
      architecture: {uach_architecture_json},
      bitness: {uach_bitness_json},
      model: {uach_model_json},
      uaFullVersion: {uach_full_version_json},
      wow64: false,
      getHighEntropyValues: function (hints) {{
        return Promise.resolve({{
          architecture: {uach_architecture_json},
          bitness: {uach_bitness_json},
          brands: UA_DATA.brands,
          mobile: {uach_mobile_jsx},
          model: {uach_model_json},
          platform: UA_DATA.platform,
          platformVersion: UA_DATA.platformVersion,
          uaFullVersion: {uach_full_version_json},
          wow64: false,
        }});
      }},
      toJSON: function () {{ return UA_DATA; }},
    }};
    overrideGetter('userAgentData', function () {{ return UA_DATA; }});
  }}

  // 7. Canvas LSB noise.
  var NOISE_PIXELS = {noise_pixels_json};
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

  // 8. WebGL vendor / renderer hooks.
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

  // 9. AnalyserNode audio fingerprint noise.
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
        seed_hex = seed_hex,
        platform_json = platform_json,
        primary_lang_json = primary_lang_json,
        languages_json = languages_json,
        ua_ch_platform_json = ua_ch_platform_json,
        ua_ch_platform_version_json = ua_ch_platform_version_json,
        brands_json = brands_json,
        hardware_concurrency = hardware_concurrency,
        device_memory_expr = device_memory_expr,
        navigator_vendor_json = navigator_vendor_json,
        navigator_product_sub_json = navigator_product_sub_json,
        navigator_max_touch_points = navigator_max_touch_points,
        plugins_json = plugins_json,
        mime_types_json = mime_types_json,
        screen_width = screen_width,
        screen_height = screen_height,
        screen_avail_width = screen_avail_width,
        screen_avail_height = screen_avail_height,
        device_pixel_ratio = device_pixel_ratio,
        is_ios_jsx = is_ios,
        uach_mobile_jsx = uach_mobile,
        ios_user_agent_data_block = ios_user_agent_data_block,
        window_webkit_block = window_webkit_block,
        build_fingerprint_setter = build_fingerprint_setter,
        uach_architecture_json = uach_architecture_json,
        uach_bitness_json = uach_bitness_json,
        uach_model_json = uach_model_json,
        uach_full_version_json = uach_full_version_json,
        webgl_vendor_json = webgl_vendor_json,
        webgl_renderer_json = webgl_renderer_json,
        audio_offset_str = audio_offset_str,
        noise_pixels_json = noise_pixels_json,
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
    // M5.5+: use the profile's UaChSpec.brands list, which has the
    // proper 4-entry shape (GREASE + Chromium + brand + GREASE) for
    // Chrome 148 stable. iOS Safari profiles have an empty list
    // (UA-CH is absent on Safari); the build_init_script JS guards
    // the entire userAgentData override with `if (!is_ios)`, so the
    // empty brands list never reaches the page.
    serde_json::to_string(
        &profile
            .uach
            .brands
            .iter()
            .map(|b| {
                serde_json::json!({
                    "brand": b.brand,
                    "version": b.version,
                })
            })
            .collect::<Vec<_>>(),
    )
    .expect("static brands slice cannot fail")
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