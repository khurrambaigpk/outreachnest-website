// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first` makes THIS script run for the admin panel paths AND the new
// /api/activate endpoint before Cloudflare's normal static-file serving kicks in; every other page
// on the site bypasses this file entirely and is served exactly as before, unchanged.
//
// v2 (27 Aug 2026) — replaced HTTP Basic Auth with a proper session-cookie login.
// v3 (27 Aug 2026) — SESSION_MAX_AGE_SECONDS cap + admin.html pagehide logout beacon.
// v4 (27 Aug 2026) — added the automated free-trial activation system (/api/activate):
//   Problem this solves: the free trial previously required Mariyam to manually generate and
//   send a license key by hand (up to 24hr wait) — this was identified as a major reason people
//   who download the trial never actually activate it and try the product.
//   Design constraints (explicit, from the business owner):
//     1. A key must NEVER be issued without a real, verified Gumroad purchase first — this
//        endpoint calls Gumroad's own License Verification API (server-side, using the secret-free
//        public verify endpoint) and refuses to generate anything unless Gumroad confirms the
//        submitted license key is real, unused for a DIFFERENT machine, and not refunded/disputed/
//        chargebacked.
//     2. Must be resistant to abuse/hacking:
//        - Per-IP rate limiting (Workers KV) — throttles automated key-farming attempts.
//        - Strict input validation (regex) on both license_key and hwid before they touch any
//          logic — rejects malformed/injection-shaped input immediately.
//        - One Gumroad license key can only ever be bound to ONE machine (HWID) — enforced via a
//          KV lookup; a second machine trying to reuse someone else's purchased key is rejected.
//        - The generated activation key format/signature is byte-identical to the existing
//          Windows app's own offline `_verify_key()` logic (same HMAC-SHA256 secret + Base32
//          encoding) — nothing about the app itself changes, and the underlying
//          `_LICENSE_SECRET` exposure inside the distributed .exe (a pre-existing condition, not
//          introduced by this change) is unchanged and was intentionally left out of this task's
//          scope (a separate, bigger future project would be required to fix that at the source).
//        - ONE FREE TRIAL PER PC, EVER — not just "one trial per license key". Without this, someone
//          could claim a fresh $0 Gumroad checkout (a new email each time) and keep re-activating
//          unlimited free trials on the same machine by uninstalling/reinstalling. A KV record
//          (`trial_used:<HWID>`) remembers which license_key first claimed the trial on each PC;
//          a second, different license_key trying to claim another trial on that same PC is
//          rejected and pointed to the paid plans (Monthly/Half-Yearly/Annual, still handled
//          manually via WhatsApp payment-proof, unchanged) instead of getting a free key. The
//          SAME license_key reinstalling on the SAME PC still works exactly as before (idempotent).

const ADMIN_USER = "mariyam";
const ADMIN_PASS = "Nest2026!Falcon91";
const SESSION_SECRET = "on-8f3k2m9x7q1z5w4v6t0r8y2u3i7o1p9a4s6d";
const SESSION_MAX_AGE_SECONDS = 2 * 60 * 60; // 2-hour absolute cap, enforced server-side regardless of browser cookie behavior
const COOKIE_NAME = "on_admin_session";

// ── Activation system config ────────────────────────────────────────────────
const GUMROAD_PRODUCT_ID = "BZVGpilp2DHoSlq47Zlcjg=="; // "OutreachNest Finder — Multi-Engine Lead Finder" product's API product_id (NOT the URL permalink)
const LICENSE_SECRET = "ON_MASTER_2025_KhurramBaig_ABL_SecretKey_8x7z"; // must match _LICENSE_SECRET in vendor_finder_windows_app.py exactly
const PLAN_IDS = { annual: 1, trial7: 3, halfyear: 4, monthly: 5 };
const TRIAL_DAYS_FALLBACK = 3; // used only if the live admin_settings.json fetch fails
const ADMIN_SETTINGS_URL = "https://raw.githubusercontent.com/khurrambaigpk/outreachnest-settings/main/admin_settings.json";
const RATE_LIMIT_MAX_PER_HOUR = 15;
const LICENSE_KEY_RE = /^[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}$/i;
const HWID_RE = /^[0-9A-F]{16}$/i;
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function makeSessionToken() {
  const expiry = Date.now() + SESSION_MAX_AGE_SECONDS * 1000;
  const sig = await hmacSign(String(expiry), SESSION_SECRET);
  return `${expiry}.${sig}`;
}

async function verifySessionToken(token) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [expiryStr, sig] = parts;
  if (!/^[0-9]+$/.test(expiryStr)) return false;
  const expected = await hmacSign(expiryStr, SESSION_SECRET);
  if (sig !== expected) return false;
  return Date.now() < parseInt(expiryStr, 10);
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function loginPageHtml(showError) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login — OutreachNest</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:20px}
.box{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;box-shadow:0 8px 30px rgba(0,0,0,.06);text-align:center}
.lock{font-size:38px;margin-bottom:10px}
h1{font-size:22px;margin:0 0 6px;color:#16261f}
p{color:#6b6459;font-size:13.5px;margin:0 0 20px}
input{width:100%;padding:12px 14px;margin-bottom:12px;border:1px solid #d8d0c0;border-radius:8px;font-size:14px}
button{width:100%;padding:12px;border:none;border-radius:8px;background:#1f4d3a;color:#fff;font-weight:600;font-size:14.5px;cursor:pointer}
button:hover{background:#173c2d}
.err{background:#fbe9e9;color:#a33;border-radius:8px;padding:9px 12px;font-size:13px;margin-bottom:14px}
</style>
</head>
<body>
<div class="box">
<div class="lock">🔐</div>
<h1>Admin Access</h1>
<p>OutreachNest Blog Editor</p>
${showError ? '<div class="err">❌ Incorrect username or password.</div>' : ""}
<form method="POST">
<input type="text" name="username" placeholder="Username" autocomplete="username" required autofocus>
<input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
<button type="submit">Unlock →</button>
</form>
</div>
</body>
</html>`;
}

// ── Activation key generation (byte-identical port of the app's algorithm) ──
function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) {
    let chunk = bits.slice(i, i + 5);
    if (chunk.length < 5) chunk = chunk.padEnd(5, "0");
    out += B32_ALPHABET[parseInt(chunk, 2)];
  }
  return out;
}

async function sha256Bytes(strOrBytes) {
  const data = typeof strOrBytes === "string" ? new TextEncoder().encode(strOrBytes) : strOrBytes;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

async function generateActivationKey(plan, days, uidInt, hwidStr) {
  const planId = PLAN_IDS[plan];
  if (planId === undefined) throw new Error("unknown plan: " + plan);

  const hwidHashFull = await sha256Bytes(hwidStr);
  const hwidHash = hwidHashFull.slice(0, 4);

  const uidBytes = new Uint8Array(3);
  uidBytes[0] = (uidInt >> 16) & 0xff;
  uidBytes[1] = (uidInt >> 8) & 0xff;
  uidBytes[2] = uidInt & 0xff;

  const daysBytes = new Uint8Array(2);
  daysBytes[0] = (days >> 8) & 0xff;
  daysBytes[1] = days & 0xff;

  const payload = new Uint8Array(10);
  payload[0] = planId;
  payload.set(daysBytes, 1);
  payload.set(uidBytes, 3);
  payload.set(hwidHash, 6);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(LICENSE_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigFull = new Uint8Array(await crypto.subtle.sign("HMAC", key, payload));
  const sig = sigFull.slice(0, 4);

  const raw = new Uint8Array(14);
  raw.set(payload, 0);
  raw.set(sig, 10);

  const b32 = base32Encode(raw);
  const groups = [];
  for (let i = 0; i < b32.length; i += 5) groups.push(b32.slice(i, i + 5));
  return groups.join("-");
}

// Deterministic small "uid" (0..0xFFFFFF) derived from the license key itself, so re-submitting
// the same already-bound license_key + hwid always regenerates the exact same activation key
// (idempotent — supports the customer reinstalling the app without contacting support again).
async function uidFromLicenseKey(licenseKey) {
  const h = await sha256Bytes(licenseKey.toUpperCase());
  return (h[0] << 16) | (h[1] << 8) | h[2];
}

async function getTrialDays(env) {
  try {
    const cached = await env.LICENSE_KV.get("cache:trial_days");
    if (cached) {
      const n = parseInt(cached, 10);
      if (n > 0) return n;
    }
  } catch (e) {
    // KV unavailable — fall through to live fetch / fallback
  }
  try {
    const resp = await fetch(ADMIN_SETTINGS_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (resp.ok) {
      const data = await resp.json();
      const days = parseInt(data?.plans?.trial7?.days, 10);
      if (days > 0) {
        try {
          await env.LICENSE_KV.put("cache:trial_days", String(days), { expirationTtl: 3600 });
        } catch (e) {
          // best-effort cache only
        }
        return days;
      }
    }
  } catch (e) {
    // network/parse failure — use fallback below
  }
  return TRIAL_DAYS_FALLBACK;
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=UTF-8" },
  });
}

async function handleActivate(request, env) {
  if (request.method !== "POST") {
    return jsonResponse({ success: false, error: "Method not allowed." }, 405);
  }

  // ── Rate limit (per IP, per hour) — defense-in-depth against key-farming ──
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  try {
    const bucket = Math.floor(Date.now() / 3600000); // changes once per hour
    const rlKey = `rl:${ip}:${bucket}`;
    const current = parseInt((await env.LICENSE_KV.get(rlKey)) || "0", 10);
    if (current >= RATE_LIMIT_MAX_PER_HOUR) {
      return jsonResponse(
        { success: false, error: "Too many attempts. Please try again later or contact queries@getoutreachnest.com." },
        429
      );
    }
    await env.LICENSE_KV.put(rlKey, String(current + 1), { expirationTtl: 3600 });
  } catch (e) {
    // If KV itself is unreachable, fail OPEN on rate limiting but the Gumroad-verify step below
    // still gates everything on a real purchase, so this is not a bypass of the core protection.
  }

  // ── Parse + validate input ──
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ success: false, error: "Invalid request body." }, 400);
  }

  const licenseKeyRaw = String(body?.license_key || "").trim();
  const hwidRaw = String(body?.hwid || "").trim().toUpperCase();

  if (!LICENSE_KEY_RE.test(licenseKeyRaw)) {
    return jsonResponse(
      { success: false, error: "That doesn't look like a valid Gumroad license key. Check your confirmation email and try again." },
      400
    );
  }
  if (!HWID_RE.test(hwidRaw)) {
    return jsonResponse(
      { success: false, error: "That doesn't look like a valid PC ID (HWID). Copy it exactly as shown in the app." },
      400
    );
  }
  const licenseKey = licenseKeyRaw.toUpperCase();

  // ── Verify the purchase with Gumroad BEFORE generating anything ──
  let gumroadData;
  try {
    const params = new URLSearchParams({
      product_id: GUMROAD_PRODUCT_ID,
      license_key: licenseKey,
      increment_uses_count: "false",
    });
    const gr = await fetch("https://api.gumroad.com/v2/licenses/verify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    gumroadData = await gr.json();
  } catch (e) {
    return jsonResponse(
      { success: false, error: "Could not verify your license key right now. Please try again in a minute." },
      502
    );
  }

  if (!gumroadData || gumroadData.success !== true) {
    return jsonResponse(
      { success: false, error: "That license key was not found. Please double-check the key from your Gumroad confirmation email." },
      400
    );
  }

  const purchase = gumroadData.purchase || {};
  if (purchase.refunded || purchase.disputed || purchase.chargebacked) {
  return jsonResponse(
      { success: false, error: "This purchase is no longer valid (refunded or disputed). Contact queries@getoutreachnest.com if this is a mistake." },
      400
    );
  }

  // ── One license key = one machine (HWID binding via KV) ──
  const bindKey = `bind:${licenseKey}`;
  let boundHwid = null;
  try {
    boundHwid = await env.LICENSE_KV.get(bindKey);
  } catch (e) {
    return jsonResponse({ success: false, error: "Activation system temporarily unavailable. Please try again shortly." }, 503);
  }

  if (boundHwid && boundHwid !== hwidRaw) {
    return jsonResponse(
      {
        success: false,
        error: "This license key is already activated on a different PC. Each free trial license works on one PC only. Contact queries@getoutreachnest.com if you need help.",
      },
      409
    );
  }

  // ── One free trial per PC, ever (independent of how many license keys get thrown at it) ──
  // Without this, someone could claim a fresh $0 Gumroad "purchase" (a new email each time) and
  // keep re-activating unlimited free trials on the SAME machine by uninstalling/reinstalling.
  // boundHwid is only set once bindKey below has been written for THIS exact license_key, so
  // reaching this point with boundHwid falsy means: this specific license_key has never
  // activated anything yet — check whether this PC has already used its one lifetime trial
  // under a DIFFERENT license_key before allowing it.
  if (!boundHwid) {
    const trialKey = `trial_used:${hwidRaw}`;
    let usedByLicense = null;
    try {
      usedByLicense = await env.LICENSE_KV.get(trialKey);
    } catch (e) {
      return jsonResponse({ success: false, error: "Activation system temporarily unavailable. Please try again shortly." }, 503);
    }

    if (usedByLicense && usedByLicense !== licenseKey) {
      return jsonResponse(
        {
          success: false,
          error:
            "The free trial has already been used on this PC. To keep using OutreachNest Finder, please choose a Monthly, Half-Yearly, or Annual plan and send payment proof on WhatsApp (+923006321406) to get your key.",
        },
        403
      );
    }

    try {
      await env.LICENSE_KV.put(bindKey, hwidRaw);
      if (!usedByLicense) {
        await env.LICENSE_KV.put(trialKey, licenseKey);
      }
    } catch (e) {
      return jsonResponse({ success: false, error: "Activation system temporarily unavailable. Please try again shortly." }, 503);
    }
  }

  // ── Generate the activation key (same algorithm the app verifies offline) ──
  const days = await getTrialDays(env);
  const uid = await uidFromLicenseKey(licenseKey);
  const activationKey = await generateActivationKey("trial7", days, uid, hwidRaw);

  return jsonResponse({ success: true, key: activationKey, plan: "trial7", days });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/activate") {
      return handleActivate(request, env);
    }

    const isAdminPath = url.pathname === "/admin" || url.pathname === "/admin.html";

    if (!isAdminPath) {
      return env.ASSETS.fetch(request);
    }

    // Logout: clear the cookie and show the login form again.
    if (url.searchParams.get("logout") === "1") {
      return new Response(loginPageHtml(false), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=UTF-8",
          "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
        },
      });
    }

    // Login form submission.
    if (request.method === "POST") {
      let user = "", pass = "";
      try {
        const form = await request.formData();
        user = form.get("username") || "";
        pass = form.get("password") || "";
      } catch (e) {
        // fall through with empty creds -> treated as wrong password
      }

      if (user === ADMIN_USER && pass === ADMIN_PASS) {
        const token = await makeSessionToken();
        return new Response(null, {
          status: 302,
          headers: {
            Location: url.pathname,
            "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }

      return new Response(loginPageHtml(true), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }

    // Normal page view: check the session cookie.
    const token = getCookie(request, COOKIE_NAME);
    const valid = await verifySessionToken(token);
    if (!valid) {
      return new Response(loginPageHtml(false), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=UTF-8" },
      });
    }

    return env.ASSETS.fetch(request);
  },
};
