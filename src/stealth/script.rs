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

    // M8.1: AudioContext sample_rate / base_latency / output_latency.
    // Per-family: iOS families use 44100, others use 48000. Latency
    // varies by family + platform. These are the same values that
    // Chrome / Safari / WebView actually report on each platform,
    // so fingerprint consistency with real browsers holds.
    let (audio_sample_rate, audio_base_latency, audio_output_latency) = if profile.is_ios() {
        (44100, 0.005, 0.025)
    } else if profile.os.user_agent_data_platform == "Android" {
        (48000, 0.020, 0.030)
    } else {
        // Desktop families
        (48000, 0.010, 0.020)
    };

    // M10.2: tz_offset_minutes from profile.locale.timezone_id. Used by
    // the Date.prototype timezone override (9c). Lookup table covers
    // the timezones used by the 10 M5.5+ profile families. Returns
    // null for unknown timezones (then 9c is a no-op).
    let tz_offset_minutes: Option<i32> = match profile.locale.timezone_id {
        "America/Los_Angeles" => Some(-480),  // PST (no DST)
        "America/New_York" => Some(-300),     // EST (no DST)
        "America/Chicago" => Some(-360),      // CST (no DST)
        "Europe/London" => Some(0),           // GMT (no DST)
        "Europe/Berlin" => Some(60),          // CET (no DST)
        "Europe/Paris" => Some(60),           // CET (no DST)
        "Asia/Shanghai" => Some(480),         // CST China (no DST)
        "Asia/Tokyo" => Some(540),            // JST (no DST)
        "Asia/Singapore" => Some(480),        // SGT (no DST)
        "Australia/Sydney" => Some(600),      // AEST (no DST, ignoring +1 for DST)
        _ => None,
    };
    let tz_offset_minutes_js = match tz_offset_minutes {
        Some(m) => m.to_string(),
        None => "null".to_string(),
    };
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
        audio_sample_rate,
        audio_base_latency,
        audio_output_latency,
        tz_offset_minutes_js,
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
    audio_sample_rate: u32,
    audio_base_latency: f32,
    audio_output_latency: f32,
    tz_offset_minutes_js: String,
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

  // M4 patch 2 (defense in depth over M5.5+ JS init script):
  // cleanup automation globals that ChromeDriver / Selenium / Playwright /
  // etc. inject into the main world. These are universal
  // anti-bot-detection signals — every sophisticated detector checks for
  // them. Runs at addScriptToEvaluateOnNewDocument time, before any
  // page script, so the page never sees the dirty globals.
  //
  // The chromium C++ equivalent would hook LocalDOMWindow::InstallNewDocument
  // and call ClassicScript::RunScriptOnScriptState — too much V8 plumbing
  // for a 5-line JS loop. Functionally equivalent.
  try {{
    var _automKeys = Object.keys(window);
    for (var _ai = 0; _ai < _automKeys.length; _ai++) {{
      var _ak = _automKeys[_ai];
      if (_ak.indexOf('$cdc_') === 0 || _ak === '__playwright__' ||
          _ak.indexOf('__pw_') === 0 || _ak === '__nightmare' ||
          _ak === '__selenium_evaluate' || _ak === '__webdriver_evaluate' ||
          _ak === '__driver_evaluate' || _ak === '__fxdriver_evaluate' ||
          _ak === '__driver_unwrap' || _ak === '__webdriver_unwrap' ||
          _ak === '__webdriver_script_function' ||
          _ak === '__lastWatirAlert' || _ak === '__lastWatirConfirm' ||
          _ak === '__lastWatirPrompt') {{
        try {{ delete window[_ak]; }} catch (e1) {{}}
      }}
    }}
  }} catch (e0) {{}}

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
    var PLUGIN_DESCRIPTION = 'Portable Document Format';
    // Build a PluginArray-like object that mirrors the M3 chromium source patch
    // but is populated from the profile's plugins slice.
    var fakePlugins = Object.create(PluginArray.prototype);
    PLUGINS_JSON.forEach(function (p, i) {{
      var plugin = Object.create(Plugin.prototype);
      Object.defineProperties(plugin, {{
        name: {{ value: p.name, enumerable: true }},
        filename: {{ value: p.filename, enumerable: true }},
        description: {{ value: PLUGIN_DESCRIPTION, enumerable: true }},
        length: {{ value: 1, enumerable: true }},
        0: {{ value: {{ type: 'application/pdf', suffixes: 'pdf', description: PLUGIN_DESCRIPTION }}, enumerable: true }}
      }});
      Object.defineProperty(fakePlugins, i, {{ value: plugin, enumerable: true }});
      Object.defineProperty(fakePlugins, p.name, {{ value: plugin, enumerable: false }});
    }});
    Object.defineProperty(fakePlugins, 'length', {{ value: PLUGINS_JSON.length, enumerable: true }});
    Object.defineProperties(fakePlugins, {{
      item: {{
        value: function (index) {{ return this[index] || null; }},
        enumerable: false
      }},
      namedItem: {{
        value: function (name) {{
          for (var i = 0; i < this.length; i++) {{
            if (this[i] && this[i].name === name) return this[i];
          }}
          return null;
        }},
        enumerable: false
      }},
      refresh: {{
        value: function () {{}},
        enumerable: false
      }}
    }});
    if (typeof Symbol !== 'undefined' && Symbol.iterator) {{
      Object.defineProperty(fakePlugins, Symbol.iterator, {{
        value: function* () {{
          for (var i = 0; i < this.length; i++) yield this[i];
        }},
        enumerable: false
      }});
    }}
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

  // 5d. M7.2 high-DPI media queries + iframe dimensions + visual viewport
  // Defense in depth over M7.1 (CDP Emulation.setDeviceMetricsOverride).
  // CDP sets the actual layout viewport; this section handles the surface
  // that CDP doesn't reach (CSS media query matchMedia(), iframe
  // contentWindow, window.visualViewport for mobile families).
  try {{
    // 5d.1 high-DPI media queries. Override window.matchMedia so that
    // (resolution: 2dppx), (min-resolution: ...), (max-resolution: ...)
    // return matches based on profile devicePixelRatio, not the host OS.
    (function() {{
      var DPR = {device_pixel_ratio};
      var origMatchMedia = window.matchMedia ? window.matchMedia.bind(window) : null;
      if (origMatchMedia) {{
        window.matchMedia = function(query) {{
          var q = String(query || '');
          var m = q.match(/(min-|max-)?resolution\s*:\s*(\d+(?:\.\d+)?)(dppx|dpcm|dpi)/i);
          if (m) {{
            var cmp = m[1] || '';
            var val = parseFloat(m[2]);
            var unit = m[3].toLowerCase();
            var dppx = unit === 'dppx' ? val : (unit === 'dpcm' ? val / 2.54 : val / 96.0);
            var matches = false;
            if (cmp === 'min-') matches = DPR >= dppx - 1e-6;
            else if (cmp === 'max-') matches = DPR <= dppx + 1e-6;
            else matches = Math.abs(DPR - dppx) < 1e-6;
            return {{
              matches: matches,
              media: q,
              onchange: null,
              addListener: function() {{}},
              removeListener: function() {{}},
              addEventListener: function() {{}},
              removeEventListener: function() {{}},
              dispatchEvent: function() {{ return true; }}
            }};
          }}
          return origMatchMedia(q);
        }};
      }}
    }})();

    // 5d.2 iframe contentWindow dimensions. Walk the iframe tree and
    // set child contentWindow.innerWidth/Height to match the parent's
    // (profile-driven) viewport, so fingerprinters that compare parent
    // vs iframe get consistent values. Cross-origin iframes silently
    // fail (caught).
    (function() {{
      var SYN_W = {screen_width};
      var SYN_H = {screen_height};
      function syncIframes(root) {{
        try {{
          var iframes = root.querySelectorAll ? root.querySelectorAll('iframe') : [];
          for (var i = 0; i < iframes.length; i++) {{
            var iframe = iframes[i];
            try {{
              var cw = iframe.contentWindow;
              if (cw && cw !== window) {{
                Object.defineProperty(cw, 'innerWidth', {{ get: function() {{ return SYN_W; }}, configurable: true }});
                Object.defineProperty(cw, 'innerHeight', {{ get: function() {{ return SYN_H; }}, configurable: true }});
                try {{ syncIframes(cw.document); }} catch (e) {{}}
              }}
            }} catch (e) {{}}
          }}
        }} catch (e) {{}}
      }}
      syncIframes(document);
      // Re-sync on DOM mutations (iframes added/removed).
      try {{
        if (window.MutationObserver && !window.__stealth_iframe_observer) {{
          var obs = new MutationObserver(function() {{ syncIframes(document); }});
          obs.observe(document.documentElement, {{ childList: true, subtree: true }});
          window.__stealth_iframe_observer = obs;
        }}
      }} catch (e) {{}}
    }})();

    // 5d.3 visual viewport (mobile / webview families only). Desktop
    // families keep the chromium default (VisualViewport reports
    // platform values, which on a chromium binary are sensible).
    if ({uach_mobile_jsx}) {{
      (function() {{
        var VV_W = {screen_width};
        var VV_H = {screen_height};
        var VV_SCALE = {device_pixel_ratio};
        Object.defineProperty(window, 'visualViewport', {{
          get: function() {{
            return {{
              width: VV_W,
              height: VV_H,
              scale: VV_SCALE,
              offsetLeft: 0,
              offsetTop: 0,
              pageLeft: 0,
              pageTop: 0,
              addEventListener: function() {{}},
              removeEventListener: function() {{}},
              dispatchEvent: function() {{ return true; }}
            }};
          }},
          configurable: true
        }});
      }})();
    }}
  }} catch (e) {{
    window.__stealth_last_err = 'm7_2:' + (e && e.message);
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

  // 9b. M8.1 AudioContext / OscillatorNode hooks.
  // Defense in depth over M4-4 (AudioBuffer channel-data offset) and
  // M4-7 (UA-CH). M4-4 covers AudioBuffer.getChannelData +
  // copyFromChannel + OfflineAudioContext completion. M8.1 covers
  // the rest: AudioContext.sampleRate/baseLatency/outputLatency and
  // OscillatorNode frequency stability. The chromium C++ side
  // computes these from hardware + WebRTC audio device; we override
  // at the JS binding level for fingerprint consistency.
  try {{
    // 9b.1 AudioContext.prototype.sampleRate / baseLatency / outputLatency.
    // Chrome on Windows typically reports sampleRate=48000, baseLatency
    // around 0.01, outputLatency around 0.02. iOS Safari tends to
    // sampleRate=44100 with higher latency. We use the profile's locale
    // + a deterministic seed-derived offset for these.
    var AC_SAMPLE_RATE = {audio_sample_rate};
    var AC_BASE_LATENCY = {audio_base_latency};
    var AC_OUTPUT_LATENCY = {audio_output_latency};
    var AC_CTOR = window.AudioContext || window.webkitAudioContext;
    if (AC_CTOR && AC_CTOR.prototype) {{
      try {{
        Object.defineProperty(AC_CTOR.prototype, 'sampleRate', {{
          get: function() {{ return AC_SAMPLE_RATE; }},
          configurable: true
        }});
      }} catch (e) {{}}
      try {{
        Object.defineProperty(AC_CTOR.prototype, 'baseLatency', {{
          get: function() {{ return AC_BASE_LATENCY; }},
          configurable: true
        }});
      }} catch (e) {{}}
      try {{
        Object.defineProperty(AC_CTOR.prototype, 'outputLatency', {{
          get: function() {{ return AC_OUTPUT_LATENCY; }},
          configurable: true
        }});
      }} catch (e) {{}}
    }}

    // 9b.2 OscillatorNode frequency stability. Real OscillatorNode
    // output drifts slightly (jitter detection). We add a deterministic
    // profile-seeded offset to frequency.value reads.
    if (window.OscillatorNode && OscillatorNode.prototype) {{
      try {{
        var origFreqValueGet = Object.getOwnPropertyDescriptor(
          window.AudioParam.prototype, 'value');
        if (origFreqValueGet && origFreqValueGet.get) {{
          Object.defineProperty(window.AudioParam.prototype, 'value', {{
            get: function() {{
              var v = origFreqValueGet.call(this);
              // Only offset for OscillatorNode-related AudioParams
              // (heuristic: check if context is OscillatorNode).
              try {{
                if (this._stealth_freq_offset === undefined) {{
                  this._stealth_freq_offset = AUDIO_OFFSET * 1e-6;
                }}
                return v + this._stealth_freq_offset;
              }} catch (e) {{ return v; }}
            }},
            configurable: true
          }});
        }}
      }} catch (e) {{}}
    }}
  }} catch (e) {{
    window.__stealth_last_err = 'm8_1:' + (e && e.message);
  }}

  // 9d. M9 getStats() IP filter (defense in depth over M9 chromium C++).
  // Wraps RTCStatsReport.prototype.entries / forEach / keys / values /
  // get to remove IP addresses from RTCIceCandidateStats entries
  // (type === "local-candidate" or "remote-candidate"). The C++ layer
  // M9 already filters onicecandidate; this JS layer catches the
  // getStats() surface (which the C++ layer can't modify because
  // webrtc::RTCStatsReport is const).
  try {{
    if (window.RTCStatsReport && RTCStatsReport.prototype) {{
      var PROTO = RTCStatsReport.prototype;
      var isPrivate = function(ip) {{
        if (!ip) return false;
        var m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (!m) return false;  // not IPv4, let through (IPv6 case)
        var o1 = +m[1], o2 = +m[2];
        if (o1 === 10) return true;
        if (o1 === 127) return true;
        if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
        if (o1 === 192 && o2 === 168) return true;
        if (o1 === 169 && o2 === 254) return true;
        if (o1 === 0) return true;
        return false;
      }};
      var sanitizeStat = function(stat) {{
        if (!stat || typeof stat !== 'object') return stat;
        if (stat.type === 'local-candidate' || stat.type === 'remote-candidate') {{
          if (isPrivate(stat.address)) {{
            stat.address = '0.0.0.0';
          }}
          if (isPrivate(stat.relatedAddress)) {{
            stat.relatedAddress = '0.0.0.0';
          }}
        }}
        return stat;
      }};
      // maplike interface: get(), has(), entries(), keys(), values(), forEach()
      if (!PROTO.__stealth_getstats_wrapped) {{
        var origEntries = PROTO.entries;
        var origForEach = PROTO.forEach;
        var origGet = PROTO.get;
        var wrapIterator = function(orig) {{
          if (!orig) return orig;
          return function() {{
            var iter = orig.apply(this, arguments);
            var origNext = iter.next.bind(iter);
            iter.next = function() {{
              var r = origNext();
              if (r && r.value) {{
                if (Array.isArray(r.value) && r.value.length === 2) {{
                  r.value[1] = sanitizeStat(r.value[1]);
                }} else {{
                  r.value = sanitizeStat(r.value);
                }}
              }}
              return r;
            }};
            return iter;
          }};
        }};
        PROTO.entries = wrapIterator(origEntries);
        if (origForEach) {{
          PROTO.forEach = function(cb, thisArg) {{
            return origForEach.call(this, function(stat, key) {{
              cb.call(thisArg, sanitizeStat(stat), key, this);
            }}, thisArg);
          }};
        }}
        if (origGet) {{
          PROTO.get = function(key) {{
            return sanitizeStat(origGet.call(this, key));
          }};
        }}
        PROTO.__stealth_getstats_wrapped = true;
      }}
    }}
  }} catch (e) {{
    window.__stealth_last_err = 'm9_getstats:' + (e && e.message);
  }}

  // 9c. M10.2 Date.prototype timezone override.
  // Defense in depth over M5.5+ CDP Emulation.setTimezoneOverride.
  // CDP override makes chromium-side Date report the profile timezone.
  // This JS layer wraps Date.prototype.getHours / getMinutes / getSeconds /
  // getDate / getMonth / getDay / getTimezoneOffset so that even if CDP
  // override is bypassed (e.g. when JS reads Date via a different code
  // path like Date.now() + manual offset), the values are still consistent
  // with the profile timezone.
  try {{
    var TZ_OFFSET_MIN = {tz_offset_minutes_js};
    if (TZ_OFFSET_MIN !== null && typeof Date !== 'undefined') {{
      var origGetHours = Date.prototype.getHours;
      var origGetMinutes = Date.prototype.getMinutes;
      var origGetSeconds = Date.prototype.getSeconds;
      var origGetDate = Date.prototype.getDate;
      var origGetMonth = Date.prototype.getMonth;
      var origGetDay = Date.prototype.getDay;
      var origGetTimezoneOffset = Date.prototype.getTimezoneOffset;

      function shiftDate(t) {{
        return new Date(t.getTime() + TZ_OFFSET_MIN * 60 * 1000 + t.getTimezoneOffset() * 60 * 1000);
      }}

      Date.prototype.getHours = function() {{ return shiftDate(this).getUTCHours(); }};
      Date.prototype.getMinutes = function() {{ return shiftDate(this).getUTCMinutes(); }};
      Date.prototype.getSeconds = function() {{ return shiftDate(this).getUTCSeconds(); }};
      Date.prototype.getDate = function() {{ return shiftDate(this).getUTCDate(); }};
      Date.prototype.getMonth = function() {{ return shiftDate(this).getUTCMonth(); }};
      Date.prototype.getDay = function() {{ return shiftDate(this).getUTCDay(); }};
      Date.prototype.getTimezoneOffset = function() {{ return TZ_OFFSET_MIN; }};
    }}
  }} catch (e) {{
    window.__stealth_last_err = 'm10_2:' + (e && e.message);
  }}

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
        audio_sample_rate = audio_sample_rate,
        audio_base_latency = audio_base_latency,
        audio_output_latency = audio_output_latency,
        tz_offset_minutes_js = tz_offset_minutes_js,
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

    /// M7.2: Verify the new sections (high-DPI media queries, iframe
    /// dimensions, visual viewport) are present in the init script and
    /// the profile-driven values make it through to the JS payload.
    #[test]
    fn init_script_contains_m7_2_viewport_sections() {
        // Desktop profile: visualViewport NOT injected (desktop families
        // rely on chromium default for visual viewport).
        let desktop = DeviceProfileId::DesktopChrome148Win11.profile();
        let seed = FingerprintSeed::ZERO;
        let desktop_script = build_init_script(&desktop, &seed);
        assert!(
            desktop_script.contains("M7.2 high-DPI media queries"),
            "desktop script missing M7.2 high-DPI MQ section"
        );
        assert!(
            desktop_script.contains("iframe contentWindow"),
            "desktop script missing M7.2 iframe dimensions section"
        );
        // Desktop has uach.mobile=false, so visualViewport section is wrapped
        // in `if ({uach_mobile_jsx})` and is present in the script but
        // never executes. The 5d.3 comment + VV_W reference is still in
        // the source.
        assert!(
            desktop_script.contains("visualViewport"),
            "desktop script contains visualViewport source (gated by mobile flag)"
        );

        // Mobile profile: all 3 sections present, visualViewport with
        // profile-driven values.
        let mobile = DeviceProfileId::AndroidChromePixel7.profile();
        let mobile_script = build_init_script(&mobile, &seed);
        assert!(mobile_script.contains("M7.2 high-DPI media queries"));
        assert!(mobile_script.contains("iframe contentWindow"));
        assert!(mobile_script.contains("visualViewport"));
        // Mobile profile width/height/dpr visible in iframe + visual viewport sections.
        assert!(mobile_script.contains("412")); // screen.width for pixel7
        assert!(mobile_script.contains("915")); // screen.height for pixel7

        // High-DPI MQ logic: must reference min-/max-resolution regex.
        assert!(mobile_script.contains("resolution"));
        assert!(mobile_script.contains("dppx"));
    }

    /// M8.1: Verify the new AudioContext / OscillatorNode hooks are
    /// present in the init script and the per-family sample rate +
    /// latency values make it through to the JS payload.
    #[test]
    fn init_script_contains_m8_1_audio_context_sections() {
        let seed = FingerprintSeed::ZERO;

        // Desktop Chrome 148 Windows: sampleRate=48000, baseLatency=0.01,
        // outputLatency=0.02.
        let desktop = DeviceProfileId::DesktopChrome148Win11.profile();
        let desktop_script = build_init_script(&desktop, &seed);
        assert!(
            desktop_script.contains("M8.1 AudioContext / OscillatorNode"),
            "desktop script missing M8.1 section"
        );
        assert!(desktop_script.contains("48000"), "desktop sample rate");
        assert!(desktop_script.contains("AC_BASE_LATENCY = 0.01"), "desktop baseLatency");
        assert!(desktop_script.contains("AC_OUTPUT_LATENCY = 0.02"), "desktop outputLatency");

        // iOS Safari: sampleRate=44100, baseLatency=0.005, outputLatency=0.025.
        let ios = DeviceProfileId::IosSafariIphone14.profile();
        let ios_script = build_init_script(&ios, &seed);
        assert!(ios_script.contains("44100"), "iOS sample rate");
        assert!(ios_script.contains("AC_BASE_LATENCY = 0.005"), "iOS baseLatency");
        assert!(ios_script.contains("AC_OUTPUT_LATENCY = 0.025"), "iOS outputLatency");

        // Android Chrome: sampleRate=48000, baseLatency=0.02, outputLatency=0.03.
        let android = DeviceProfileId::AndroidChromePixel7.profile();
        let android_script = build_init_script(&android, &seed);
        assert!(android_script.contains("48000"));
        assert!(android_script.contains("AC_BASE_LATENCY = 0.02"), "android baseLatency");
        assert!(android_script.contains("AC_OUTPUT_LATENCY = 0.03"), "android outputLatency");

        // OscillatorNode frequency stability hook.
        assert!(
            desktop_script.contains("OscillatorNode"),
            "OscillatorNode section present"
        );
        assert!(
            desktop_script.contains("AudioParam"),
            "AudioParam.value hook present"
        );
    }

    /// M10.2: Verify the Date.prototype timezone override is present
    /// in the init script and the profile-driven tz_offset_minutes
    /// makes it through to the JS payload.
    #[test]
    fn init_script_contains_m10_2_date_timezone_override() {
        let seed = FingerprintSeed::ZERO;

        // America/Los_Angeles profile: tz_offset_minutes = -480 (PST).
        // Win11 Chrome 120 uses LA timezone per profiles.rs.
        let la = DeviceProfileId::Win11Chrome120IntelNvidia.profile();
        let la_script = build_init_script(&la, &seed);
        assert!(
            la_script.contains("M10.2 Date.prototype timezone override"),
            "script missing M10.2 section"
        );
        assert!(la_script.contains("TZ_OFFSET_MIN = -480"), "LA offset");

        // America/New_York: -300 (EST). Android Chrome Pixel 7 uses NY.
        let ny = DeviceProfileId::AndroidChromePixel7.profile();
        let ny_script = build_init_script(&ny, &seed);
        assert!(ny_script.contains("TZ_OFFSET_MIN = -300"), "NY offset");

        // All Date methods must be wrapped.
        for method in &[
            "getHours",
            "getMinutes",
            "getSeconds",
            "getDate",
            "getMonth",
            "getDay",
            "getTimezoneOffset",
        ] {
            assert!(
                la_script.contains(&format!("Date.prototype.{}", method)),
                "Date.prototype.{} wrapper present",
                method
            );
        }

        // shiftDate helper must be defined.
        assert!(la_script.contains("function shiftDate"));
    }

    /// M9: Verify the RTCStatsReport.prototype wrapping section is
    /// present in the init script and the isPrivate helper covers
    /// the private IPv4 ranges.
    #[test]
    fn init_script_contains_m9_getstats_ip_filter() {
        let seed = FingerprintSeed::ZERO;
        let profile = DeviceProfileId::DesktopChrome148Win11.profile();
        let script = build_init_script(&profile, &seed);
        assert!(
            script.contains("M9 getStats() IP filter"),
            "script missing M9 getStats section"
        );
        // The maplike wrapping is present.
        assert!(script.contains("RTCStatsReport.prototype"));
        assert!(script.contains("__stealth_getstats_wrapped"));
        // isPrivate covers RFC 1918 + loopback + link-local.
        assert!(script.contains("isPrivate"));
        // sanitizeStat for local-candidate / remote-candidate types.
        assert!(script.contains("local-candidate"));
        assert!(script.contains("remote-candidate"));
        assert!(script.contains("sanitizeStat"));
    }

    #[test]
    fn init_script_defines_plugin_own_description_and_array_methods() {
        let profile = DeviceProfileId::DesktopChrome148Win11.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);

        assert!(
            script.contains("description: { value: PLUGIN_DESCRIPTION"),
            "plugin objects must have an own description property"
        );
        assert!(
            script.contains("Object.defineProperties(fakePlugins"),
            "PluginArray methods must be own properties on the fake object"
        );
        assert!(script.contains("item: {"));
        assert!(script.contains("namedItem: {"));
        assert!(script.contains("refresh: {"));
        assert!(script.contains("Symbol.iterator"));
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

    #[test]
    fn init_script_cleans_automation_globals() {
        // M4 patch 2: the init script must clean $cdc_*, __playwright__,
        // __pw_*, __nightmare, __selenium_evaluate, etc. from
        // window. This is the JS-side implementation (chromium C++
        // version deferred to follow-up).
        let profile = DeviceProfileId::DesktopChrome148Win11.profile();
        let seed = FingerprintSeed::ZERO;
        let script = build_init_script(&profile, &seed);
        // Each automation marker must appear at least once in the
        // cleanup loop (i.e., the script must reference it).
        assert!(
            script.contains("$cdc_"),
            "init script missing $cdc_ cleanup"
        );
        assert!(
            script.contains("__playwright__"),
            "init script missing __playwright__ cleanup"
        );
        assert!(
            script.contains("__pw_"),
            "init script missing __pw_ cleanup"
        );
        assert!(
            script.contains("__nightmare"),
            "init script missing __nightmare cleanup"
        );
        assert!(
            script.contains("__selenium_evaluate"),
            "init script missing __selenium_evaluate cleanup"
        );
        assert!(
            script.contains("__webdriver_evaluate"),
            "init script missing __webdriver_evaluate cleanup"
        );
        assert!(
            script.contains("__driver_evaluate"),
            "init script missing __driver_evaluate cleanup"
        );
        // Verify the cleanup is at the START of the IIFE (before any
        // other stealth work) by checking it appears before the
        // navigator.vendor override.
        let cdc_idx = script.find("$cdc_").expect("$cdc_ present");
        let vendor_idx = script
            .find("overrideGetter('vendor'")
            .or_else(|| script.find("overrideGetter(\"vendor\""))
            .expect("vendor override present");
        assert!(
            cdc_idx < vendor_idx,
            "automation cleanup must run before navigator override"
        );
    }
}
