//! stealth_smoke.rs
//!
//! M5 Step 8: real-browser integration smoke test for the stealth module.
//!
//! Launches the system-installed Chrome, applies a deterministic fingerprint
//! seed, then probes 9 fingerprinting surfaces and prints whether each one
//! was overridden as expected. Saves the probe result and a screenshot
//! under the temp directory.
//!
//! Usage:
//!     cargo run --example stealth_smoke -- [seed_string]
//!     cargo run --example stealth_smoke -- "user-42"
//!     cargo run --example stealth_smoke -- "user-42" --compare other-seed
//!
//! Pass `STEALTH_SMOKE_CHROME` (env) to override the Chrome binary path.
//! Override the user data dir with `STEALTH_SMOKE_USER_DATA` to keep a
//! profile between runs (useful for deterministic cross-session testing).

use std::path::PathBuf;

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::stealth::FingerprintSeed;
use chromiumoxide_cdp::cdp::browser_protocol::page::CaptureScreenshotFormat;
use futures::StreamExt;

const ABOUT_BLANK: &str = "about:blank";

const PROBE_JS: &str = r#"
(function() {
    function probe() {
        // 1. navigator.webdriver — must be undefined (not true, not false)
        const webdriver_value = navigator.webdriver;

        // 2. navigator.platform
        const platform = navigator.platform;

        // 3. navigator.language + languages
        const language = navigator.language;
        const languages = Array.from(navigator.languages || []);

        // 4. navigator.hardwareConcurrency + deviceMemory
        const hc = navigator.hardwareConcurrency;
        const dm = navigator.deviceMemory;

        // 5. navigator.userAgentData (UA-CH)
        let uad = null;
        if (navigator.userAgentData) {
            uad = {
                platform: navigator.userAgentData.platform,
                platformVersion: navigator.userAgentData.platformVersion,
                brands: (navigator.userAgentData.brands || []).map(b => ({
                    brand: b.brand, version: b.version
                })),
            };
        }

        // 6. canvas fingerprint. We use **getImageData()** (which reads
        //    the backing store directly) rather than `toDataURL()`,
        //    because Chrome 149 headless mode can snapshot the
        //    toDataURL output at first call and freeze it across
        //    subsequent putImageData / draw operations. getImageData
        //    always returns the current backing store, including any
        //    modifications made by our stealth LSB-noise hook.
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
            // Read the backing store directly. The stealth hook on
            // getImageData will apply LSB noise before this returns.
            const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
            let h = 0x811c9dc5;
            for (let i = 0; i < img.data.length; i++) {
                h ^= img.data[i];
                h = (h * 0x01000193) >>> 0;
            }
            return {
                hash: ('00000000' + h.toString(16)).slice(-8),
            };
        }
        const drawn = paintAndHash();
        const canvas_hash = drawn.hash;
        const canvas_protected = false; // N/A with getImageData path

        // 7. WebGL vendor/renderer (UNMASKED)
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

        // 8. UA string
        const ua = navigator.userAgent;

        return {
            webdriver: webdriver_value,
            webdriver_undefined: webdriver_value === undefined,
            platform, language, languages,
            hc, dm, uad, canvas_hash, canvas_protected, webgl, ua,
            applied: window.__stealth_applied === true,
            seed: window.__stealth_seed || null,
            noise_pixels_prefix: (window.__stealth_noise_pixels || []).slice(0, 4),
            noise_pixels_len: (window.__stealth_noise_pixels || []).length,
            noise_calls: window.__stealth_noise_calls || 0,
            // Read the dataURL of an empty canvas to verify the noise
            // actually changes the dataURL output across pages.
            empty_dataurl_len: (function() {
                const c = document.createElement('canvas');
                c.width = 8; c.height = 8;
                return c.toDataURL().length;
            })(),
        };
    }
    return JSON.stringify(probe());
})()
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // Parse args.
    let mut args = std::env::args().skip(1);
    let seed_str = args.next().unwrap_or_else(|| "user-42".to_string());
    let compare_seed = if args.next().as_deref() == Some("--compare") {
        args.next()
    } else {
        None
    };

    let seed = FingerprintSeed::from_str(&seed_str);
    let profile_id = chromiumoxide::stealth::DeviceProfileId::from_seed(seed.as_bytes());
    println!("[stealth-smoke] seed       = {}", seed);
    println!("[stealth-smoke] seed_hex   = {}", seed.to_hex());
    println!("[stealth-smoke] profile_id = {:?}", profile_id);

    // Build config. Override chrome path / user data dir if env says so.
    let mut builder = BrowserConfig::builder();
    if let Some(p) = std::env::var_os("STEALTH_SMOKE_CHROME") {
        builder = builder.chrome_executable(PathBuf::from(p));
    }
    if std::env::var_os("STEALTH_SMOKE_HEAD").is_some() {
        builder = builder.with_head();
    }
    let user_data_dir = std::env::var_os("STEALTH_SMOKE_USER_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("stealth-smoke-udd-{}", seed_str))
        });
    builder = builder.user_data_dir(&user_data_dir);
    let config = builder.build()?;

    let (browser, mut handler) = Browser::launch(config).await?;
    let handle = tokio::spawn(async move {
        loop {
            let _ = handler.next().await;
        }
    });

    let probe = run_once(&browser, &seed, &seed_str).await?;

    // Optional: compare with another seed run (sequential, same chrome
    // process).
    let mut compare = None;
    if let Some(other_seed) = compare_seed {
        let other = FingerprintSeed::from_str(&other_seed);
        let other_profile_id = chromiumoxide::stealth::DeviceProfileId::from_seed(other.as_bytes());
        println!();
        println!("[stealth-smoke] --compare {} -- profile_id={:?}", other_seed, other_profile_id);
        compare = Some(run_once(&browser, &other, &other_seed).await?);
    }

    let _ = browser.new_page("about:blank").await; // ensure clean shutdown
    drop(browser);
    let _ = handle.await;

    // Diff canvas hash for deterministic verification.
    if let Some(c) = compare.as_ref() {
        println!();
        println!("[stealth-smoke] deterministic comparison:");
        println!(
            "  seed={} canvas_hash={} vs seed={} canvas_hash={}",
            seed_str, probe.canvas_hash, c.seed_str, c.canvas_hash
        );
        if probe.canvas_hash == c.canvas_hash {
            println!("  [WARN] canvas hashes are identical (different seeds should produce different hashes)");
        } else {
            println!("  [OK] canvas hashes differ (different seeds → different fingerprints, as expected)");
        }
    }

    Ok(())
}

struct ProbeResult {
    seed_str: String,
    canvas_hash: String,
    webdriver_undefined: bool,
    platform: String,
    language: String,
    languages: Vec<String>,
    hc: u32,
    dm: u32,
    has_uad: bool,
    webgl: Option<(String, String)>,
    ua: String,
    applied: bool,
    seed_back: Option<String>,
}

async fn run_once(
    browser: &chromiumoxide::browser::Browser,
    seed: &FingerprintSeed,
    seed_str: &str,
) -> Result<ProbeResult, Box<dyn std::error::Error>> {
    let page = browser.new_page(ABOUT_BLANK).await?;
    let report = page.set_fingerprint_seed(*seed).await?;
    println!("[stealth-smoke] {}: applied ({} steps):", seed_str, report.applied.len());
    for step in &report.applied {
        println!("  - {:<35} no_op={}", step.name, step.no_op);
    }

    // Probe — main-world JS via `page.evaluate_expression` (the wrapper
    // that pins to the main execution world).
    let probe_value = page.evaluate_expression(PROBE_JS).await?;
    let json_str = probe_value
        .into_value::<serde_json::Value>()
        .ok()
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s),
            other => Some(other.to_string()),
        })
        .unwrap_or_else(|| "(unparseable)".to_string());
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .unwrap_or(serde_json::Value::Null);

    // Screenshot.
    let png = page
        .screenshot(
            chromiumoxide::page::ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .build(),
        )
        .await?;
    let shot_path = std::env::temp_dir().join(format!("stealth-smoke-{}.png", seed_str));
    std::fs::write(&shot_path, &png)?;

    // Save JSON for cross-run diffing.
    let json_path = std::env::temp_dir().join(format!("stealth-smoke-{}.json", seed_str));
    std::fs::write(&json_path, &json_str)?;

    let _ = page.close().await;

    let r = ProbeResult {
        seed_str: seed_str.to_string(),
        canvas_hash: parsed
            .get("canvas_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        webdriver_undefined: parsed
            .get("webdriver_undefined")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        platform: parsed
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        language: parsed
            .get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        languages: parsed
            .get("languages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        hc: parsed.get("hc").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        dm: parsed.get("dm").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        has_uad: parsed.get("uad").map(|v| !v.is_null()).unwrap_or(false),
        webgl: parsed.get("webgl").and_then(|v| {
            let vendor = v.get("vendor")?.as_str()?.to_string();
            let renderer = v.get("renderer")?.as_str()?.to_string();
            Some((vendor, renderer))
        }),
        ua: parsed
            .get("ua")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        applied: parsed
            .get("applied")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        seed_back: parsed
            .get("seed")
            .and_then(|v| v.as_str())
            .map(String::from),
    };

    println!(
        "[stealth-smoke] {}: webdriver_undefined={} platform={} language={:?} \
         languages={:?} hc={} dm={} uad={} canvas_hash={}",
        r.seed_str, r.webdriver_undefined, r.platform, r.language, r.languages,
        r.hc, r.dm, r.has_uad, r.canvas_hash,
    );
    if let Some((v, rd)) = &r.webgl {
        println!("[stealth-smoke] {}: WebGL vendor={:?} renderer={:?}", r.seed_str, v, rd);
    }
    println!("[stealth-smoke] {}: ua={}", r.seed_str, r.ua);
    println!("[stealth-smoke] {}: applied={} seed_back={:?}", r.seed_str, r.applied, r.seed_back);
    println!("[stealth-smoke] {}: json  -> {}", r.seed_str, json_path.display());
    println!("[stealth-smoke] {}: png   -> {}", r.seed_str, shot_path.display());

    Ok(r)
}
