// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first` makes THIS script run for the admin panel paths AND the new
// /api/activate endpoint before Cloudflare's normal static-file serving kicks in; every other page
// on the site bypasses this file entirely and is served exactly as before, unchanged.
//
// v2 (27 Aug 2026) — replaced HTTP Basic Auth with a proper session-cookie login.
// v3 (27 Aug 2026) — SESSION_MAX_AGE_SECONDS cap + admin.html pagehide logout beacon.
// v4 (27 Aug 2026) — added the automated free-trial activation system (/api/activate):
// v11 (11 Sep 2026) — Added "image" field to BlogPosting JSON-LD schema (was missing,
//   causing Google Rich Results "non-critical issue"). Uses the same OG_IMAGE constant
//   already used for og:image and twitter:image tags — no per-post change needed.
// v10 (11 Sep 2026) — Fixed BlogPosting JSON-LD: removed escHtml() from JSON values (was
//   producing &amp; instead of & for titles like "PLC & SCADA", causing structured data
//   validation errors). Added XSS protection via unicode escapes on JSON output instead.
//   Added noindex meta tag to admin login page and activate page.
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
// v5 (Sep 2026) — server-side per-post meta injection for /post?p=SLUG:
// v6 (Sep 2026) — shortened 9 too-long post titles (under 60 chars total);
//   server-side per-post meta injection already fixed duplicate-title/description errors.
// v7 (Sep 2026) — removed server-side hidden <h1> injection (was causing Ahrefs
//   "Multiple H1 tags" error on all 22 post pages). The injection was added under the
//   mistaken assumption that post.html has no static H1 — it does: line 77 has
//   <h1 id="aTitle"></h1> which JavaScript fills with the post title. The hidden
//   off-screen H1 was therefore a second duplicate H1, counted by Ahrefs even though
//   invisible to users. Removing it leaves exactly one H1 per post page.
// v8 (Sep 2026) — three Ahrefs errors fixed in one pass:
//   (a) Added 5 slugs that were in sitemap.xml but missing from POSTS_META
//       (solar-guest-post-cost-2026, signs-guest-post-site-hurt-rankings,
//        electrical-contractor-seo-backlinks, vet-electronics-repair-guest-post-site,
//        guest-posting-vs-pbn-links-difference). Without entries here the worker
//       served the unmodified template whose canonical is /post, causing
//       "Non-canonical page in sitemap (5 pages)" in Ahrefs.
//   (b) injectPostMeta() now injects/replaces JSON-LD with a BlogPosting schema —
//       fixes "Structured data validation error" (post pages had Organization schema).
//   (c) Unknown-slug branch now adds noindex to the response, so the generic /post
//       URL is not counted as an indexable page — fixes "Indexable page not in sitemap".

const ADMIN_USER = "mariyam";
const ADMIN_PASS = "Nest2026!Falcon91";
const SESSION_SECRET = "on-8f3k2m9x7q1z5w4v6t0r8y2u3i7o1p9a4s6d";
const SESSION_MAX_AGE_SECONDS = 2 * 60 * 60; // 2-hour absolute cap, enforced server-side regardless of browser cookie behavior
const COOKIE_NAME = "on_admin_session";

// ── Activation system config ────────────────────────────────────────────────
const GUMROAD_PRODUCT_ID = "BZVGpilp2DHoSlq47Zlcjg=="; // "OutreachNest Finder — Multi-Engine Lead Finder" product's API product_id (NOT the URL permalink)
const LICENSE_SECRET = "ON_MASTER_2026_OutreachNest_60e77519e1b796a6_SecretKey"; // must match _LICENSE_SECRET in vendor_finder_windows_app.py exactly — rotated here 30 Aug 2026 to match the app-side rotation done in V12.19.23 (this Worker file had been missed until now)

// ── Ed25519 hardening (added 28 Aug 2026) ───────────────────────────────────
// Every key generated from here on also carries an Ed25519 signature, made
// with the PRIVATE key below. Only the updated .exe (which ships the matching
// PUBLIC key, never this private one) can verify it — older, already-installed
// customer copies simply never look past byte 14 and keep validating via the
// unchanged HMAC-only path, so nothing breaks for anyone already using the app.
// This PRIVATE key must NEVER go anywhere except here and Mariyam's private
// keygen tool on her own PC — never into the app, never anywhere public.
const ED25519_PRIVATE_KEY_HEX = "94985d37de5845bde4df86379e11635477ed39c96fc7ac0abf2aff175cb9efce";
// Ed25519 private keys import into Web Crypto only via PKCS8 (raw format is
// public-key-only for this algorithm) — this is a fixed 16-byte DER prefix
// (RFC 8410) in front of the 32 raw private-key bytes.
const ED25519_PKCS8_PREFIX_HEX = "302e020100300506032b657004220420";

const PLAN_IDS = { annual: 1, trial7: 3, halfyear: 4, monthly: 5 };
const TRIAL_DAYS_FALLBACK = 3; // used only if the live admin_settings.json fetch fails
const ADMIN_SETTINGS_URL = "https://raw.githubusercontent.com/khurrambaigpk/outreachnest-settings/main/admin_settings.json";
const RATE_LIMIT_MAX_PER_HOUR = 15;
const LICENSE_KEY_RE = /^[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}-[0-9A-F]{8}$/i;
const HWID_RE = /^[0-9A-F]{16}$/i;
const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ── Per-post metadata for server-side injection ──────────────────────────────
// Keyed by the slug that appears after /post?p= in the URL.
// title: the post's unique page title (the " — OutreachNest" suffix is appended automatically).
// desc:  the meta description (keep under 160 chars for Ahrefs/Google).
const POSTS_META = {
  "the-awkward-truth-about-cold-outreach-nobody-tells": {
    title: "The Awkward Truth About Cold Outreach",
    desc: "Most cold outreach doesn't fail because people didn't try hard enough. Find out what actually goes wrong — and how to fix your approach.",
  },
  "finding-electronics-and-appliance-repair-businesse": {
    title: "Electronics Repair Businesses for Outreach",
    desc: "Search appliance, TV, laptop, mobile, UPS, and CCTV repair businesses across cities using OutreachNest Finder's multi-engine search.",
  },
  "sourcing-leads-in-industrial-automation-plc-scada-": {
    title: "Industrial Automation Leads: PLC & SCADA",
    desc: "Find PLC automation firms, SCADA integrators, and instrumentation suppliers for link building or direct outreach at scale.",
  },
  "finding-electrical-contractors-and-panel-builders-": {
    title: "Find Electrical Contractors for Outreach",
    desc: "Search residential, commercial, and industrial electricians, panel builders, and switchgear firms in bulk with OutreachNest Finder.",
  },
  "how-to-find-solar-guest-post-sites-and-leads-in-mi": {
    title: "Find Solar Guest Post Sites and Leads Fast",
    desc: "Find solar blogs, installers, and inverter or battery sites for guest posts and lead outreach — in minutes, not days.",
  },
  "how-agencies-manage-10-niches-without-losing-track": {
    title: "How Agencies Manage 10+ Niches at Once",
    desc: "Running outreach across multiple industries at once usually turns into chaos. Here's how agencies stay organized using niche profiles.",
  },
  "how-to-turn-your-lead-list-into-a-live-google-shee": {
    title: "Turn Your Lead List Into a Live Google Sheet",
    desc: "Manually copying leads into a spreadsheet wastes hours every week. Learn how OutreachNest Finder auto-exports leads to Google Sheets.",
  },
  "why-whatsapp-outreach-gets-higher-response-rates-t": {
    title: "WhatsApp Outreach: Higher Response Rates",
    desc: "Cold email open rates keep falling, but WhatsApp messages get read within minutes. Here's how to use WhatsApp for effective outreach.",
  },
  "outreachnest-finder-features-guide-everything-the-": {
    title: "OutreachNest Finder: Complete Features Guide",
    desc: "A complete walkthrough of every OutreachNest Finder feature — 4-engine search, email extraction, SEO metrics, Google Sheets export, and more.",
  },
  "how-to-find-seo-clients-fast-in-2026": {
    title: "How to Find SEO Clients Fast in 2026",
    desc: "Finding SEO clients does not have to be slow or expensive. Here's a repeatable system for finding and closing new clients fast in 2026.",
  },
  "how-to-build-1-000-link-building-prospects-in-minu": {
    title: "Build 1,000 Link Prospects in Minutes",
    desc: "Most SEO freelancers spend days building prospect lists manually. Here's how to build 1,000+ link building prospects in minutes.",
  },
  "how-to-check-da-pa-dr-without-paying-for-tools": {
    title: "How to Check DA, PA & DR for Free",
    desc: "Learn how SEO freelancers check Domain Authority, Page Authority, and Domain Rating for free using OutreachNest Finder's Chrome Bridge.",
  },
  "spot-real-guest-post-site": {
    title: "How to Spot a Real Guest-Post Site",
    desc: "Not every site that says 'write for us' is worth your link. Here's how to tell real guest post sites from PBNs and link farms.",
  },
  "b2b-lead-list-worth-buying": {
    title: "What Makes a B2B Lead List Worth Buying",
    desc: "Most lead lists are stale and full of dead emails. Here's what separates a lead list worth paying for from a waste of money.",
  },
  "solar-niche-goldmine": {
    title: "Why Solar Is a Link Building Goldmine",
    desc: "Solar is booming, competitive, and full of companies that spend on SEO. Here's why it's one of the best niches for link builders.",
  },
  "cold-email-that-gets-replies": {
    title: "Cold Email Framework That Gets Replies",
    desc: "Long, salesy emails get ignored. Short, specific, human ones get replies. Here's the simple cold email framework that actually works.",
  },
  "warm-up-new-email-domain": {
    title: "Warming Up a New Email Domain the Right Way",
    desc: "Send from a brand-new domain too fast and you land in spam. Here's how to warm up a new email domain properly before outreach.",
  },
  "choosing-solar-installer-guide": {
    title: "How Homeowners Choose a Solar Installer",
    desc: "Understanding how buyers pick a solar company tells you exactly what content and trust signals you need to win more business.",
  },
  "electrical-contractors-online-growth": {
    title: "Why Electrical Contractors Are Underrated",
    desc: "Electrical contractors form one of the largest, most stable B2B markets. Here's how to reach them effectively for outreach.",
  },
  "industrial-automation-high-value-niche": {
    title: "Industrial Automation: Small Niche, Big Value",
    desc: "There aren't many automation companies — but each one is worth serious attention. Here's how to find and reach them for outreach.",
  },
  "electronics-repair-steady-demand": {
    title: "Electronics Repair: A Steady-Demand Niche",
    desc: "Repair shops rarely chase the spotlight, but steady demand and loyal customers make electronics repair a reliable outreach niche.",
  },
  "quality-over-quantity-backlinks": {
    title: "Great Backlinks Beat a Hundred Weak Ones",
    desc: "More links isn't the goal. Relevant links from trusted, real sites move rankings. Here's how to focus your link building for results.",
  },
  // v8: added 5 slugs that were in sitemap.xml but missing from POSTS_META —
  // without entries here the worker serves the unmodified template whose canonical
  // is /post (not /post?p=SLUG), causing "Non-canonical page in sitemap" in Ahrefs.
  "solar-guest-post-cost-2026": {
    title: "How Much Does a Solar Guest Post Cost in 2026",
    desc: "Solar guest post prices range from $50 to $500+. Here's what drives the cost and how to find quality placements at reasonable prices.",
  },
  "signs-guest-post-site-hurt-rankings": {
    title: "Signs a Guest Post Site Will Hurt Your Rankings",
    desc: "Not all guest post sites are safe. Here's how to spot the red flags — thin content, PBN patterns, unnatural link profiles — before you publish.",
  },
  "electrical-contractor-seo-backlinks": {
    title: "How Electrical Contractors Get More SEO Backlinks",
    desc: "Electrical contractors rarely think about link building — which creates real opportunity. Here's how to build links effectively in this niche.",
  },
  "vet-electronics-repair-guest-post-site": {
    title: "How to Vet an Electronics Repair Guest Post Site",
    desc: "Electronics repair blogs look legitimate but some are link farms. Here's a quick vetting checklist to find sites actually worth publishing on.",
  },
  "guest-posting-vs-pbn-links-difference": {
    title: "Guest Posting vs PBN Links: The Real Difference",
    desc: "Both put links on other sites, but the risks and results are completely different. Here's what separates a real guest post link from a PBN link.",
  },
};

const OG_IMAGE = "https://public-files.gumroad.com/k51jvr84ph0hpd9lr2lghnpl7pl6";

// Escape special HTML characters for safe use inside attribute values and text.
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Inject per-post metadata into the raw post.html template string.
// Replaces generic title, canonical, description, and all OG/Twitter tags.
// Also fills the existing <h1 id="aTitle"> element with the post title so that
// static crawlers (Ahrefs raw-HTML pass, Googlebot without JS) see a non-empty H1.
// JavaScript later overwrites it with the same value — no visual difference.
// If a tag is missing from the template (should not happen, but safe), injects
// a minimal set before </head> so the response always has correct values.
//
// title     — full page title including " — OutreachNest" suffix (used for <title> and OG)
// desc      — meta description
// canonical — canonical URL for this post
// h1Text    — raw article title WITHOUT " — OutreachNest" (fills the visible <h1>)
function injectPostMeta(html, title, desc, canonical, h1Text) {
  const safeTitle = escHtml(title);
  const safeDesc = escHtml(desc);
  const safeH1 = escHtml(h1Text || title);

  let out = html
    // <title>
    .replace(/<title>[^<]*<\/title>/i, `<title>${safeTitle}</title>`)
    // canonical
    .replace(/<link\s+rel="canonical"[^>]*>/i, `<link rel="canonical" href="${canonical}" />`)
    // meta description
    .replace(/<meta\s+name="description"[^>]*>/i, `<meta name="description" content="${safeDesc}">`)
    // OG tags
    .replace(/<meta\s+property="og:title"[^>]*>/i, `<meta property="og:title" content="${safeTitle}">`)
    .replace(/<meta\s+property="og:description"[^>]*>/i, `<meta property="og:description" content="${safeDesc}">`)
    .replace(/<meta\s+property="og:url"[^>]*>/i, `<meta property="og:url" content="${canonical}">`)
    .replace(/<meta\s+property="og:image"[^>]*>/i, `<meta property="og:image" content="${OG_IMAGE}">`)
    // Twitter tags
    .replace(/<meta\s+name="twitter:title"[^>]*>/i, `<meta name="twitter:title" content="${safeTitle}">`)
    .replace(/<meta\s+name="twitter:description"[^>]*>/i, `<meta name="twitter:description" content="${safeDesc}">`)
    .replace(/<meta\s+name="twitter:image"[^>]*>/i, `<meta name="twitter:image" content="${OG_IMAGE}">`);

  // Fill the existing <h1 id="aTitle"> in the template with the post title.
  // post.html has <h1 id="aTitle"></h1> (empty — JS fills it after render).
  // Static crawlers that skip JS would see an empty H1; this fills it server-side
  // so every raw-HTML response already has a correct, non-empty H1.
  // JS runs afterward and sets the same text via textContent — no conflict.
  out = out.replace(/<h1\s+id="aTitle"[^>]*><\/h1>/i, `<h1 id="aTitle">${safeH1}</h1>`);

  // Inject/replace BlogPosting structured data (fixes Ahrefs "Structured data
  // validation error"). The generic post.html template has an Organization schema
  // which is wrong for article pages — replace it with a BlogPosting schema so
  // Google and Ahrefs see correct structured data for each individual post.
  // JSON-LD values must NOT be HTML-escaped: JSON.stringify() handles proper JSON
  // string escaping (quotes, backslashes, control chars). Using escHtml() here would
  // turn "PLC & SCADA" into "PLC &amp; SCADA" inside the JSON, which is a literal
  // string value and causes structured data validation errors. Instead, we apply
  // unicode escapes to < and > on the final JSON string for XSS safety only.
  const blogPostingSchema = JSON.stringify({
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "headline": h1Text || title,
    "description": desc,
    "image": OG_IMAGE,
    "url": canonical,
    "author": { "@type": "Organization", "name": "OutreachNest", "url": "https://getoutreachnest.com" },
    "publisher": { "@type": "Organization", "name": "OutreachNest", "url": "https://getoutreachnest.com" },
    "mainEntityOfPage": { "@type": "WebPage", "@id": canonical },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
  const schemaTag = `<script type="application/ld+json">${blogPostingSchema}</script>`;
  // Replace existing JSON-LD block; if none exists, inject before </head>
  const withSchema = out.replace(/<script\s+type="application\/ld\+json">[\s\S]*?<\/script>/i, schemaTag);
  out = (withSchema !== out) ? withSchema : out.replace(/<\/head>/i, schemaTag + '\n</head>');

  // Safety net: if canonical tag was missing in template, inject full tag block before </head>
  if (!out.includes(`href="${canonical}"`)) {
    const inject = [
      `<link rel="canonical" href="${canonical}" />`,
      `<meta name="description" content="${safeDesc}">`,
      `<meta property="og:type" content="article">`,
      `<meta property="og:title" content="${safeTitle}">`,
      `<meta property="og:description" content="${safeDesc}">`,
      `<meta property="og:url" content="${canonical}">`,
      `<meta property="og:image" content="${OG_IMAGE}">`,
      `<meta name="twitter:card" content="summary_large_image">`,
      `<meta name="twitter:title" content="${safeTitle}">`,
      `<meta name="twitter:description" content="${safeDesc}">`,
      `<meta name="twitter:image" content="${OG_IMAGE}">`,
    ].join("\n");
    out = out.replace(/<\/head>/i, inject + "\n</head>");
  }

  return out;
}

// Handle /post?p=SLUG — fetch the post.html template from ASSETS and inject
// per-post metadata before returning it to the visitor (or crawler).
async function handlePostPage(request, env, slug) {
  // Check Cloudflare's edge cache first — avoids Worker invocation entirely on a
  // cache hit, eliminating cold-start latency for AI crawlers and repeat visitors.
  const cache = caches.default;
  const cacheKey = new Request(request.url, { method: "GET" });
  const cachedResp = await cache.match(cacheKey);
  if (cachedResp) return cachedResp;

  // Fetch the static post.html template (without the query string, which is
  // irrelevant to static-file serving — Cloudflare Pages maps /post → post.html).
  const templateUrl = new URL(request.url);
  templateUrl.pathname = "/post";
  templateUrl.search = "";
  const assetResp = await env.ASSETS.fetch(new Request(templateUrl.toString(), { method: "GET" }));

  if (!assetResp.ok) {
    // Template fetch failed — pass through the error response unchanged.
    return assetResp;
  }

  const html = await assetResp.text();
  const meta = POSTS_META[slug];

  if (!meta) {
    // Unknown slug (or /post with no slug at all) — serve the template but add
    // noindex so Ahrefs/Google don't count it as a separate indexable page.
    // This fixes "Indexable page not in sitemap" for the generic /post URL.
    const noindexHtml = html.replace(
      /<meta\s+name="robots"[^>]*>/i,
      '<meta name="robots" content="noindex, follow">'
    );
    return new Response(noindexHtml, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "public, max-age=60",
      },
    });
  }

  const fullTitle = meta.title + " — OutreachNest";
  const canonical = "https://getoutreachnest.com/post?p=" + slug;
  // Pass meta.title (without " — OutreachNest") as the visible H1 text
  const modified = injectPostMeta(html, fullTitle, meta.desc, canonical, meta.title);

  const response = new Response(modified, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      // 1-hour browser cache, 24-hour CDN edge cache — long enough to serve AI
      // crawlers from cache instantly, short enough to pick up post additions.
      "Cache-Control": "public, max-age=3600, s-maxage=86400",
    },
  });

  // Store processed HTML in Cloudflare's edge cache so subsequent requests skip
  // the Worker entirely — eliminates TTFB spikes from cold starts.
  await cache.put(cacheKey, response.clone());
  return response;
}

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
<meta name="robots" content="noindex, nofollow">
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

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

let _ed25519PrivateKeyCache = null;
async function getEd25519PrivateKey() {
  if (_ed25519PrivateKeyCache) return _ed25519PrivateKeyCache;
  const prefix = hexToBytes(ED25519_PKCS8_PREFIX_HEX);
  const rawPriv = hexToBytes(ED25519_PRIVATE_KEY_HEX);
  const pkcs8 = new Uint8Array(prefix.length + rawPriv.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(rawPriv, prefix.length);
  _ed25519PrivateKeyCache = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return _ed25519PrivateKeyCache;
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

  // Ed25519 signature over the same 10-byte payload (see "Ed25519 hardening"
  // note above) — appended after the legacy 14 bytes. Old app copies never
  // read past byte 14, so this is fully backward compatible; updated app
  // copies verify this too for real forgery resistance.
  const edPrivKey = await getEd25519PrivateKey();
  const edSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, edPrivKey, payload));

  const raw = new Uint8Array(10 + 4 + 64);
  raw.set(payload, 0);
  raw.set(sig, 10);
  raw.set(edSig, 14);

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

    // ── Blog post pages: inject per-post metadata server-side ──────────────
    // /post?p=SLUG is the clean-URL pattern for all blog posts. The static
    // post.html template has generic title/description/canonical for ALL posts;
    // this intercepts the request and returns a version with correct values
    // injected for the specific slug before any JavaScript runs, so Ahrefs,
    // Google, and all social OG bots see unique metadata per post.
    if (url.pathname === "/post") {
      const slug = url.searchParams.get("p");
      if (slug) {
        return handlePostPage(request, env, slug);
      }
      // /post with no ?p= param — serve the template with noindex so the bare
      // /post URL is not treated as a separate indexable page by crawlers.
      const rawResp = await env.ASSETS.fetch(request);
      const html = await rawResp.text();
      const noindexHtml = html.replace(
        /<meta\s+name="robots"[^>]*>/i,
        '<meta name="robots" content="noindex, follow">'
      );
      return new Response(noindexHtml, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "public, max-age=3600" },
      });
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
