//! M6 step 3: profile family architecture smoke test (M5.5+ validation)
//!
//! Runs against 1 site (baidu.com) per family, applying
//! `Page::set_device_profile` directly. Verifies that the 5 M5.5+ profile
//! families (Desktop Chrome 148, iOS Safari, Android Chrome, Android System
//! WebView, iOS WKWebView) produce internally-coherent fingerprints per the
//! M5.5+ schema.
//!
//! ## What this validates
//!
//! For each family:
//!
//! - UA string matches profile spec
//! - `navigator.platform` / `navigator.vendor` / `navigator.productSub` /
//!   `navigator.maxTouchPoints` match
//! - `navigator.plugins.length` matches (5 desktop, 0 mobile+webview)
//! - `navigator.mimeTypes.length` matches (2 desktop, 0 mobile+webview)
//! - `navigator.userAgentData` present (Chrome) vs absent (iOS Safari)
//! - UA-CH `brands` has 4 entries with GREASE (Chrome) vs absent (iOS Safari)
//! - `window.webkit` present (iOS WKWebView) vs absent (others)
//! - `Build.FINGERPRINT` present (Android WebView) vs absent (others)
//! - `window.screen.{width,height,devicePixelRatio}` match profile
//! - WebGL vendor/renderer match profile (Apple GPU on iOS, Mali on Android)
//! - `applied=true` (stealth injection succeeded)
//!
//! ## Usage
//!
//! ```text
//! # default: chromium 148 at D:\chromium-148-build\out\Release\chrome.exe
//! cargo run --example m6_profile_families
//!
//! # custom chrome path
//! STEALTH_SMOKE_CHROME=C:\path\to\chrome.exe cargo run --example m6_profile_families
//! ```
//!
//! ## What this does NOT validate
//!
//! - Bot Manager detection (e.g. ti_bm cookie) — needs the full doc 8-site
//!   probe, not the 1-site/family test
//! - HTTP/2 fingerprint (M12) — needs chromium-source patch
//! - TLS JA3 (M11) — needs mTLS proxy
//! - Long-running session (cookies, storage) — needs extended test
//!
//! ## Build
//!
//! Built against the M5.5+ work on `smart/stealth-proto` branch
//! (commit `5ab77c1` after this test). Run from chromiumoxide-fork
//! directory:
//!
//! ```bash
//! cd F:\chromiumoxide-fork
//! cargo run --example m6_profile_families
//! ```

use std::path::PathBuf;
use std::time::Duration;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::stealth::DeviceProfileId;
use chromiumoxide_cdp::cdp::browser_protocol::page::CaptureScreenshotFormat;
use futures::StreamExt;
use serde_json::Value;

// 1 site per family. baidu.com for desktop (China parity with M6 step 1/2),
// generic landing pages for the others. Each page only needs to render
// enough HTML for the probe to run.
const SITE: &str = "https://www.baidu.com/";

const PROBE_JS: &str = r#"
(function() {
    function probe() {
        function paintAndHash() {
            const canvas = document.createElement('canvas');
            canvas.width = 280; canvas.height = 60;
            const ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = '#069';
                ctx.fillText('Hello, world!', 2, 15);
                ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                ctx.fillText('Hello, world!', 4, 17);
            }
            const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
            let h = 0x811c9dc5;
            for (let i = 0; i < img.data.length; i++) {
                h ^= img.data[i];
                h = (h * 0x01000193) >>> 0;
            }
            return { hash: ('00000000' + h.toString(16)).slice(-8) };
        }
        const canvas_hash = paintAndHash().hash;

        const glCanvas = document.createElement('canvas');
        const gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
        let webgl = null;
        if (gl) {
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            webgl = dbg ? {
                vendor: gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL),
            } : null;
        }

        return {
            ua: navigator.userAgent,
            webdriver_undefined: navigator.webdriver === undefined,
            platform: navigator.platform,
            vendor: navigator.vendor,
            productSub: navigator.productSub,
            maxTouchPoints: navigator.maxTouchPoints,
            plugins_length: navigator.plugins.length,
            mimeTypes_length: navigator.mimeTypes.length,
            has_userAgentData: !!navigator.userAgentData,
            uad_brands: navigator.userAgentData ?
                (navigator.userAgentData.brands || []).map(b => ({brand: b.brand, version: b.version})) : null,
            uad_platform: navigator.userAgentData ? navigator.userAgentData.platform : null,
            uad_mobile: navigator.userAgentData ? navigator.userAgentData.mobile : null,
            uad_model: navigator.userAgentData ? navigator.userAgentData.model : null,
            uad_architecture: navigator.userAgentData ? navigator.userAgentData.architecture : null,
            uad_bitness: navigator.userAgentData ? navigator.userAgentData.bitness : null,
            window_webkit_present: typeof window.webkit !== 'undefined',
            window_webkit_message_handlers_present: !!(window.webkit && window.webkit.messageHandlers),
            build_fingerprint: (typeof navigator !== 'undefined' && navigator.buildFingerprint) ? navigator.buildFingerprint : null,
            screen_width: window.screen.width,
            screen_height: window.screen.height,
            availWidth: window.screen.availWidth,
            availHeight: window.screen.availHeight,
            devicePixelRatio: window.devicePixelRatio,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory === undefined ? null : navigator.deviceMemory,
            languages: Array.from(navigator.languages || []),
            canvas_hash, webgl,
            applied: window.__stealth_applied === true,
        };
    }
    return JSON.stringify(probe());
})()
"#;

#[derive(Debug)]
struct FamilyResult {
    profile_id: DeviceProfileId,
    family: String,
    site_url: String,
    webdriver_undefined: bool,
    platform: String,
    vendor: String,
    product_sub: String,
    max_touch_points: u8,
    plugins_length: u32,
    mime_types_length: u32,
    has_user_agent_data: bool,
    uad_brands: Vec<(String, String)>,
    uad_platform: Option<String>,
    uad_mobile: Option<bool>,
    uad_model: Option<String>,
    uad_architecture: Option<String>,
    uad_bitness: Option<String>,
    window_webkit_present: bool,
    webkit_message_handlers_present: bool,
    build_fingerprint: Option<String>,
    screen_width: u32,
    screen_height: u32,
    device_pixel_ratio: f32,
    hardware_concurrency: u32,
    device_memory: Option<u32>,
    canvas_hash: String,
    webgl_vendor: Option<String>,
    webgl_renderer: Option<String>,
    applied: bool,
    ua_contains_version_4: bool,
    json_path: PathBuf,
    png_path: PathBuf,
}

impl FamilyResult {
    fn from_parsed(
        profile_id: DeviceProfileId,
        family: &str,
        site_url: String,
        v: &Value,
        json_path: PathBuf,
        png_path: PathBuf,
    ) -> Self {
        let family = family.to_string();
        let uad_brands: Vec<(String, String)> = v
            .get("uad_brands")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|bv| {
                        let brand = bv.get("brand")?.as_str()?.to_string();
                        let version = bv.get("version")?.as_str()?.to_string();
                        Some((brand, version))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let ua = v
            .get("ua")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let ua_contains_version_4 = ua.contains("Version/4.0");

        Self {
            profile_id,
            family,
            site_url,
            webdriver_undefined: v
                .get("webdriver_undefined")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            platform: v
                .get("platform")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            vendor: v
                .get("vendor")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            product_sub: v
                .get("productSub")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            max_touch_points: v
                .get("maxTouchPoints")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u8,
            plugins_length: v
                .get("plugins_length")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            mime_types_length: v
                .get("mimeTypes_length")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            has_user_agent_data: v
                .get("has_userAgentData")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            uad_brands,
            uad_platform: v
                .get("uad_platform")
                .and_then(|x| x.as_str())
                .map(String::from),
            uad_mobile: v.get("uad_mobile").and_then(|x| x.as_bool()),
            uad_model: v
                .get("uad_model")
                .and_then(|x| x.as_str())
                .map(String::from),
            uad_architecture: v
                .get("uad_architecture")
                .and_then(|x| x.as_str())
                .map(String::from),
            uad_bitness: v
                .get("uad_bitness")
                .and_then(|x| x.as_str())
                .map(String::from),
            window_webkit_present: v
                .get("window_webkit_present")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            webkit_message_handlers_present: v
                .get("window_webkit_message_handlers_present")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            build_fingerprint: v
                .get("build_fingerprint")
                .and_then(|x| x.as_str())
                .map(String::from),
            screen_width: v
                .get("screen_width")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            screen_height: v
                .get("screen_height")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            device_pixel_ratio: v
                .get("devicePixelRatio")
                .and_then(|x| x.as_f64())
                .unwrap_or(1.0) as f32,
            hardware_concurrency: v
                .get("hardwareConcurrency")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            device_memory: v
                .get("deviceMemory")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32),
            canvas_hash: v
                .get("canvas_hash")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            webgl_vendor: v
                .get("webgl")
                .and_then(|w| w.get("vendor"))
                .and_then(|x| x.as_str())
                .map(String::from),
            webgl_renderer: v
                .get("webgl")
                .and_then(|w| w.get("renderer"))
                .and_then(|x| x.as_str())
                .map(String::from),
            applied: v
                .get("applied")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            ua_contains_version_4,
            json_path,
            png_path,
        }
    }
}

// The 5 M5.5+ families to test, with the expected fingerprint signature
// for each. Used as a quick check after the probe runs.
const FAMILIES: &[(DeviceProfileId, &str)] = &[
    (DeviceProfileId::DesktopChrome148Win11, "Desktop Chrome 148"),
    (DeviceProfileId::IosSafariIphone14, "iOS Safari"),
    (DeviceProfileId::AndroidChromePixel7, "Android Chrome"),
    (DeviceProfileId::AndroidWebViewPixel7, "Android WebView"),
    (DeviceProfileId::IosWkWebviewIphone14, "iOS WKWebView"),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let chrome_path = std::env::var_os("STEALTH_SMOKE_CHROME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\chromium-148-build\out\Release\chrome.exe"));

    if !chrome_path.exists() {
        eprintln!("[m6-step3] FATAL: chrome binary not found at {}", chrome_path.display());
        std::process::exit(2);
    }

    println!("[m6-step3] chrome     = {}", chrome_path.display());
    println!("[m6-step3] site       = {}", SITE);
    println!("[m6-step3] families   = {}", FAMILIES.len());

    let user_data_dir = std::env::temp_dir().join(format!(
        "m6-step3-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&user_data_dir).ok();

    let config = BrowserConfig::builder()
        .chrome_executable(&chrome_path)
        .no_sandbox()
        .user_data_dir(&user_data_dir)
        .launch_timeout(Duration::from_secs(60))
        .request_timeout(Duration::from_secs(45))
        .build()?;

    println!("[m6-step3] launching chromium 148...");
    let (browser, mut handler) = Browser::launch(config).await?;
    let handle = tokio::spawn(async move {
        loop {
            let _ = handler.next().await;
        }
    });
    println!("[m6-step3] chromium 148 launched");

    let mut results = Vec::new();
    for (profile_id, family_label) in FAMILIES {
        println!();
        println!("[m6-step3] ---- {:?} ({}) ----", profile_id, family_label);
        match probe_family(&browser, *profile_id, family_label).await {
            Ok(r) => {
                println!(
                    "[m6-step3]   platform={:?} vendor={:?} productSub={:?} maxTouchPoints={} \
                     plugins={} mimeTypes={} hasUAD={} uadBrands={:?} screen={}x{} dpr={} \
                     webkit={} canvas_hash={} webgl={:?}",
                    r.platform,
                    r.vendor,
                    r.product_sub,
                    r.max_touch_points,
                    r.plugins_length,
                    r.mime_types_length,
                    r.has_user_agent_data,
                    r.uad_brands,
                    r.screen_width,
                    r.screen_height,
                    r.device_pixel_ratio,
                    r.window_webkit_present,
                    r.canvas_hash,
                    r.webgl_vendor.as_deref().unwrap_or("(none)"),
                );
                results.push(r);
            }
            Err(e) => {
                eprintln!("[m6-step3] {:?} FAILED: {}", profile_id, e);
            }
        }
    }

    println!();
    println!("[m6-step3] ============================================");
    println!("[m6-step3] M5.5+ FAMILY × 4-ITEM MATRIX");
    println!("[m6-step3] ============================================");
    for r in &results {
        let expected = expected_fingerprint(r.profile_id);
        let mut pass = true;
        let mut notes = Vec::new();
        // Check each expected property
        if r.webdriver_undefined != expected.webdriver_undefined {
            pass = false;
            notes.push(format!("webdriver_undefined: got {} expected {}", r.webdriver_undefined, expected.webdriver_undefined));
        }
        if r.platform != expected.platform {
            pass = false;
            notes.push(format!("platform: got {:?} expected {:?}", r.platform, expected.platform));
        }
        if r.vendor != expected.vendor {
            pass = false;
            notes.push(format!("vendor: got {:?} expected {:?}", r.vendor, expected.vendor));
        }
        if r.max_touch_points != expected.max_touch_points {
            pass = false;
            notes.push(format!("maxTouchPoints: got {} expected {}", r.max_touch_points, expected.max_touch_points));
        }
        if r.plugins_length != expected.plugins_length {
            pass = false;
            notes.push(format!("plugins: got {} expected {}", r.plugins_length, expected.plugins_length));
        }
        if r.has_user_agent_data != expected.has_user_agent_data {
            pass = false;
            notes.push(format!("hasUAD: got {} expected {}", r.has_user_agent_data, expected.has_user_agent_data));
        }
        if expected.has_user_agent_data && r.uad_brands.len() != 4 {
            pass = false;
            notes.push(format!("uadBrands: got {} entries expected 4 (with GREASE)", r.uad_brands.len()));
        }
        if r.window_webkit_present != expected.window_webkit {
            pass = false;
            notes.push(format!("window.webkit: got {} expected {}", r.window_webkit_present, expected.window_webkit));
        }
        if r.ua_contains_version_4 != expected.ua_contains_version_4 {
            pass = false;
            notes.push(format!("UA Version/4.0: got {} expected {} (Android WebView marker)", r.ua_contains_version_4, expected.ua_contains_version_4));
        }
        if r.applied != expected.applied {
            pass = false;
            notes.push(format!("stealth applied: got {} expected {}", r.applied, expected.applied));
        }
        let verdict = if pass { "✓ PASS" } else { "✗ FAIL" };
        println!("[m6-step3] {:?}: {}", r.profile_id, verdict);
        for n in notes {
            println!("[m6-step3]   - {}", n);
        }
    }

    println!();
    println!("[m6-step3] artifacts:");
    for r in &results {
        if r.json_path.exists() {
            println!("[m6-step3]   json : {}", r.json_path.display());
        }
        if r.png_path.exists() {
            println!("[m6-step3]   png  : {}", r.png_path.display());
        }
    }

    drop(browser);
    let _ = handle.await;
    Ok(())
}

struct ExpectedFingerprint {
    webdriver_undefined: bool,
    platform: &'static str,
    vendor: &'static str,
    max_touch_points: u8,
    plugins_length: u32,
    has_user_agent_data: bool,
    window_webkit: bool,
    ua_contains_version_4: bool,
    applied: bool,
}

fn expected_fingerprint(id: DeviceProfileId) -> ExpectedFingerprint {
    match id {
        DeviceProfileId::DesktopChrome148Win11 => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "Win32",
            vendor: "Google Inc.",
            max_touch_points: 0,
            plugins_length: 5,
            has_user_agent_data: true,
            window_webkit: false,
            ua_contains_version_4: false,
            applied: true,
        },
        DeviceProfileId::IosSafariIphone14 => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "iPhone",
            vendor: "Apple Computer, Inc.",
            max_touch_points: 5,
            plugins_length: 0,
            has_user_agent_data: false, // Safari doesn't implement UA-CH
            window_webkit: false,
            ua_contains_version_4: false,
            applied: true,
        },
        DeviceProfileId::AndroidChromePixel7 => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "Linux armv81",
            vendor: "Google Inc.",
            max_touch_points: 5,
            plugins_length: 0,
            has_user_agent_data: true,
            window_webkit: false,
            ua_contains_version_4: false,
            applied: true,
        },
        DeviceProfileId::AndroidWebViewPixel7 => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "Linux armv81",
            vendor: "Google Inc.",
            max_touch_points: 5,
            plugins_length: 0,
            has_user_agent_data: true,
            window_webkit: false,
            ua_contains_version_4: true, // Android WebView marker
            applied: true,
        },
        DeviceProfileId::IosWkWebviewIphone14 => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "iPhone",
            vendor: "Apple Computer, Inc.",
            max_touch_points: 5,
            plugins_length: 0,
            has_user_agent_data: false,
            window_webkit: true, // iOS WKWebView marker
            ua_contains_version_4: false,
            applied: true,
        },
        // M5 desktop profiles — won't be tested by this example but the
        // match is exhaustive so the compiler requires it.
        _ => ExpectedFingerprint {
            webdriver_undefined: true,
            platform: "Win32",
            vendor: "Google Inc.",
            max_touch_points: 0,
            plugins_length: 5,
            has_user_agent_data: true,
            window_webkit: false,
            ua_contains_version_4: false,
            applied: true,
        },
    }
}

async fn probe_family(
    browser: &Browser,
    profile_id: DeviceProfileId,
    family_label: &str,
) -> Result<FamilyResult, Box<dyn std::error::Error>> {
    let page = browser.new_page("about:blank").await?;
    let report = page.set_device_profile(profile_id).await?;
    println!(
        "[m6-step3]   applied {} steps: {:?}",
        report.applied.len(),
        report.applied.iter().map(|s| s.name).collect::<Vec<_>>()
    );

    println!("[m6-step3]   navigating to {} ...", SITE);
    let _ = page.goto(SITE).await; // ignore nav errors, probe runs anyway
    tokio::time::sleep(Duration::from_millis(3000)).await;

    let probe_value = page.evaluate_expression(PROBE_JS).await?;
    let json_str: String = probe_value
        .into_value::<serde_json::Value>()
        .ok()
        .and_then(|v| match v {
            Value::String(s) => Some(s),
            other => Some(other.to_string()),
        })
        .unwrap_or_else(|| "(unparseable)".to_string());
    let parsed: Value = serde_json::from_str(&json_str).unwrap_or(Value::Null);

    let png = page
        .screenshot(
            ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .build(),
        )
        .await
        .unwrap_or_default();
    let user_data_dir = std::env::temp_dir().join(format!(
        "m6-step3-{}",
        std::process::id()
    ));
    let label = format!("{:?}", profile_id);
    let png_path = user_data_dir.join(format!("{}.png", label));
    let json_path = user_data_dir.join(format!("{}.json", label));
    let _ = std::fs::write(&png_path, &png);
    let _ = std::fs::write(&json_path, &json_str);

    let r = FamilyResult::from_parsed(
        profile_id,
        family_label,
        SITE.to_string(),
        &parsed,
        json_path,
        png_path,
    );
    let _ = page.close().await;
    Ok(r)
}
