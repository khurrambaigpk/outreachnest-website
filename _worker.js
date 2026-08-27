// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first = ["/admin", "/admin.html"]` makes THIS script run for those
// two paths before Cloudflare's normal static-file serving kicks in; every other page on the site
// bypasses this file entirely and is served exactly as before, unchanged.
//
// v2 (27 Aug 2026) — replaced HTTP Basic Auth with a proper session-cookie login.
// Why: browsers cache Basic Auth credentials at the PROCESS level (until Chrome is fully quit,
// not just when a window/tab is closed), so there was no way to make "close the window -> log out
// again" work while using Basic Auth. This version shows its own login form, and on success sets
// a signed, HttpOnly session cookie with NO Max-Age — a "session cookie", which browsers are
// SUPPOSED to clear when the whole browser is closed.
//
// v3 (27 Aug 2026) — two more layers, because relying on the browser alone to clear a "session
// cookie" turned out to be unreliable: some Chrome setups keep running in the background after
// every window is closed (see chrome://settings/system -> "Continue running background apps"),
// which keeps the cookie alive too.
//   1. SESSION_MAX_AGE_SECONDS shortened from 8 hours to 2 hours — an absolute cap enforced by
//      THIS SERVER (checked on every request, independent of what the browser does), so a
//      forgotten-open tab automatically needs a fresh login again after 2 hours no matter what.
//   2. admin.html now sends an explicit logout signal (navigator.sendBeacon) when its page is
//      being closed/hidden (the `pagehide` event) — this actively asks the server to invalidate
//      the session the moment the tab/window closes, instead of passively hoping the browser's
//      session-cookie behavior kicks in. Between the two, "close the window" now reliably logs
//      out even on a Chrome setup that keeps a background process alive.
//
// To change the password later: edit ADMIN_USER / ADMIN_PASS below, then re-upload this file the
// same way as any other website file. To force everyone to log in again immediately (e.g. after a
// password change), also change SESSION_SECRET to any new random string — that instantly
// invalidates every previously-issued session cookie. To change how long an open tab stays logged
// in before it's forced to re-login, change SESSION_MAX_AGE_SECONDS below.

const ADMIN_USER = "mariyam";
const ADMIN_PASS = "Nest2026!Falcon91";
const SESSION_SECRET = "on-8f3k2m9x7q1z5w4v6t0r8y2u3i7o1p9a4s6d";
const SESSION_MAX_AGE_SECONDS = 2 * 60 * 60; // 2-hour absolute cap, enforced server-side regardless of browser cookie behavior
const COOKIE_NAME = "on_admin_session";

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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
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
        // No Max-Age/Expires on purpose: this makes it a "session cookie" that browsers are
        // supposed to clear when the browser is fully closed. admin.html's pagehide beacon
        // (see v3 note above) backs this up with an active logout on tab/window close, and
        // SESSION_MAX_AGE_SECONDS caps how long it can live either way.
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
