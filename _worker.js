// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first` makes THIS script run for the admin panel paths AND the new
// /api/activate endpoint before Cloudflare's normal static-file serving kicks in; every other page
// on the site bypasses this file entirely and is served exactly as before, unchanged.
//
// v2 (27 Aug 2026) — replaced HTTP Basic Auth with a proper session-cookie login.
// v3 (27 Aug 2026) — SESSION_MAX_AGE_SECONDS cap + admin.html pagehide logout beacon.
// v4 (27 Aug 2026) — added the automated free-trial activation system (/api/activate):
// v14 (11 Sep 2026) — Extended edge caching to ALL static HTML pages (/blog, /download,
//   /services, /niches, /contact) — not just /. Fixes "Slow page" and "Slow server
//   response for AI crawlers" Ahrefs warnings on /blog and other static pages.
// v13 (11 Sep 2026) — Added IndexNow key file endpoint (/1257f0fc794749fa896e8d3c4e1af272.txt)
//   so search engines can verify ownership and accept IndexNow URL submissions for this site.
// v12 (11 Sep 2026) — Added edge caching for homepage (/) to fix "Slow page" Ahrefs
//   warning. Homepage previously passed straight through to env.ASSETS with no edge
//   caching, causing ~2.3s TTFB on Worker cold starts. Now uses the same caches.default
//   pattern already in use for blog posts (s-maxage=86400, max-age=3600).
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
// ⚠️  ADMIN_PASS and SESSION_SECRET are loaded from Cloudflare Secrets at request
// time (see fetch() below). Set them in the Cloudflare dashboard:
//   Settings → Environment variables → Add secret
//   Names: ADMIN_PASS, SESSION_SECRET
let ADMIN_PASS;
let SESSION_SECRET;
const SESSION_MAX_AGE_SECONDS = 2 * 60 * 60; // 2-hour absolute cap, enforced server-side regardless of browser cookie behavior
const COOKIE_NAME = "on_admin_session";

// ── Activation system config ────────────────────────────────────────────────
const GUMROAD_PRODUCT_ID = "BZVGpilp2DHoSlq47Zlcjg=="; // "OutreachNest Finder — Multi-Engine Lead Finder" product's API product_id (NOT the URL permalink)
// ⚠️  LICENSE_SECRET is loaded from Cloudflare Secrets at request time.
// Set it in the Cloudflare dashboard → Settings → Environment variables → Add secret
// Name: LICENSE_SECRET   Value: must match _LICENSE_SECRET in vendor_finder_windows_app.py exactly
let LICENSE_SECRET;

// ── Ed25519 hardening (added 28 Aug 2026) ───────────────────────────────────
// Every key generated from here on also carries an Ed25519 signature, made
// with the PRIVATE key below. Only the updated .exe (which ships the matching
// PUBLIC key, never this private one) can verify it — older, already-installed
// customer copies simply never look past byte 14 and keep validating via the
// unchanged HMAC-only path, so nothing breaks for anyone already using the app.
// This PRIVATE key must NEVER go anywhere except here and Mariyam's private
// keygen tool on her own PC — never into the app, never anywhere public.
// ⚠️  ED25519_PRIVATE_KEY_HEX is loaded from Cloudflare Secrets at request time.
// Set it in the Cloudflare dashboard → Settings → Environment variables → Add secret
// Name: ED25519_PRIVATE_KEY_HEX
let ED25519_PRIVATE_KEY_HEX;
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
  // v19: All 27 titles & descriptions rewritten to match real search queries.
  // Primary keyword placed early in title; secondary keywords in description.
  "the-awkward-truth-about-cold-outreach-nobody-tells": {
    title: "Why Cold Outreach Fails: Mistakes Nobody Talks About",
    desc: "Cold outreach fails for the same reasons again and again — and most guides miss them. Learn the real reasons your cold emails and DMs don't get replies.",
  },
  "finding-electronics-appliance-repair-businesses": {
    title: "Find Electronics & Appliance Repair Shops for Outreach",
    desc: "Build targeted lists of TV, laptop, mobile, UPS, and CCTV repair shops across cities at scale. Ideal for link building, lead gen, and local outreach.",
  },
  "industrial-automation-leads": {
    title: "Find Industrial Automation Leads: PLC & SCADA",
    desc: "Build B2B lead lists of PLC integrators, SCADA vendors, and instrumentation firms for outreach and link building in the industrial automation niche.",
  },
  "electrical-contractors-panel-builders": {
    title: "Find Electrical Contractors & Panel Builders",
    desc: "Find residential, commercial, and industrial electricians, panel builders, and switchgear companies in bulk for link building and B2B outreach campaigns.",
  },
  "solar-guest-post-sites": {
    title: "How to Find Solar Guest Post Sites & Leads in Minutes",
    desc: "Find solar energy blogs, installer sites, and inverter or battery companies for guest posting and link building — in minutes, not days of manual searching.",
  },
  "how-agencies-manage-10-niches-without-losing-track": {
    title: "How SEO Agencies Manage 10+ Niches Without Losing Track",
    desc: "Running outreach across many industries creates chaos. Here's how SEO agencies use niche profiles to stay organized and scale without confusion.",
  },
  "lead-list-google-sheet": {
    title: "Export Your Lead List to Google Sheets Automatically",
    desc: "Stop copying leads manually into spreadsheets. Learn how OutreachNest auto-exports your lead list to a live Google Sheet, updated in real time.",
  },
  "whatsapp-outreach-response-rates": {
    title: "WhatsApp Outreach: Why It Gets More Replies Than Email",
    desc: "Cold email open rates keep falling. WhatsApp messages get read in minutes. Here's how to run WhatsApp outreach that actually gets replies.",
  },
  "outreachnest-finder-features": {
    title: "OutreachNest Finder Features: Complete Guide (2026)",
    desc: "Full walkthrough of every OutreachNest Finder feature: 4-engine business search, bulk email extraction, DA/PA/DR metrics, Chrome Bridge, and Sheets export.",
  },
  "how-to-find-seo-clients-fast-in-2026": {
    title: "How to Find SEO Clients Fast in 2026 (Step-by-Step)",
    desc: "A repeatable, no-ads system for finding and closing SEO clients in 2026. Build a prospect list, send targeted outreach, and land your next client fast.",
  },
  "link-building-prospects": {
    title: "How to Build 1,000 Link Building Prospects in Minutes",
    desc: "Most SEO freelancers waste days building prospect lists by hand. Here's a faster method to find 1,000+ real link building opportunities quickly.",
  },
  "how-to-check-da-pa-dr-without-paying-for-tools": {
    title: "How to Check DA, PA & DR Without Paying for Tools",
    desc: "Check Domain Authority, Page Authority, and Domain Rating for free using OutreachNest's Chrome Bridge — no Moz or Ahrefs subscription required.",
  },
  "spot-real-guest-post-site": {
    title: "How to Spot Real Guest Post Sites vs PBNs",
    desc: "Not every 'write for us' site is safe. Learn how to identify real guest post opportunities versus link farms and private blog networks before you publish.",
  },
  "b2b-lead-list-worth-buying": {
    title: "What Makes a B2B Lead List Worth Buying in 2026",
    desc: "Most B2B lead lists are stale and full of bounced emails. Here's what separates a lead list worth paying for from one that wastes your outreach budget.",
  },
  "solar-niche-goldmine": {
    title: "Why the Solar Niche Is a Goldmine for Link Building",
    desc: "Solar is competitive, high-budget, and packed with companies actively investing in SEO. Here's why it's one of the best niches for link builders in 2026.",
  },
  "cold-email-that-gets-replies": {
    title: "Cold Email That Gets Replies: A Simple Framework",
    desc: "Long, salesy cold emails get ignored. Short, specific, human ones get replies. Here's the cold email framework that consistently gets responses.",
  },
  "warm-up-new-email-domain": {
    title: "How to Warm Up a New Email Domain Before Cold Outreach",
    desc: "Sending cold emails from a brand-new domain without warming it up sends you straight to spam. Here's the right way to warm up an email domain.",
  },
  "choosing-solar-installer-guide": {
    title: "How Homeowners Choose a Solar Installer",
    desc: "Understanding the buyer journey for solar installations reveals what content and trust signals help marketers, installers, and SEOs win more business.",
  },
  "electrical-contractors-online-growth": {
    title: "Electrical Contractors: An Underrated Marketing Niche",
    desc: "Electrical contractors are a massive, stable B2B sector that most marketers ignore. Here's why that creates real opportunity — and how to reach them.",
  },
  "industrial-automation-high-value-niche": {
    title: "Industrial Automation: A High-Value Outreach Niche",
    desc: "Fewer companies, higher deal value. Here's why industrial automation is worth targeting for B2B outreach and link building — and how to find these firms.",
  },
  "electronics-repair-steady-demand": {
    title: "Electronics Repair: Steady Demand, Low Competition",
    desc: "Repair shops fly under the radar but they're everywhere and always need marketing help. Here's how to tap the electronics repair niche for outreach.",
  },
  "quality-over-quantity-backlinks": {
    title: "Link Building Quality vs Quantity: Which Wins?",
    desc: "100 weak links won't beat 5 relevant links from trusted, real sites. Here's how to shift your link building strategy toward quality that moves rankings.",
  },
  // v8: added 5 slugs that were in sitemap.xml but missing from POSTS_META —
  // without entries here the worker serves the unmodified template whose canonical
  // is /post (not /post?p=SLUG), causing "Non-canonical page in sitemap" in Ahrefs.
  "solar-guest-post-cost-2026": {
    title: "How Much Does a Solar Guest Post Cost in 2026?",
    desc: "Solar guest post prices range from $25 to $500+. Here's what drives the price difference and how to find quality placements at fair market rates.",
  },
  "signs-guest-post-site-hurt-rankings": {
    title: "5 Signs a Guest Post Site Will Hurt Your Rankings",
    desc: "Some guest post sites do more harm than good. Learn how to spot thin content, PBN patterns, and unnatural link profiles before you publish and pay.",
  },
  "electrical-contractor-seo-backlinks": {
    title: "How Electrical Contractors Can Build SEO Backlinks",
    desc: "Electrical contractors rarely do link building — which creates a real opportunity for SEOs. Here's how to earn and build backlinks in this niche.",
  },
  "vet-electronics-repair-guest-post-site": {
    title: "Electronics Repair Guest Post Site Checklist",
    desc: "Electronics repair blogs can be link farms in disguise. Here's a fast vetting checklist to find sites actually worth publishing on vs ones to skip.",
  },
  "guest-posting-vs-pbn-links-difference": {
    title: "Guest Posting vs PBN Links: What's the Real Difference?",
    desc: "Both place links on external sites, but the risks and long-term results are completely different. Here's what actually separates a guest post from a PBN link.",
  },
};

// v26 (15 Sep 2026) — Fix JSON-LD injection for main pages: add CACHE_VERSION to the
//   Workers caches.default key. "Purge Everything" in the Cloudflare dashboard clears the
//   CDN cache but NOT the Workers Cache API (caches.default). v25 was deployed but its
//   injection code never ran because caches.default still held v24's unmodified HTML
//   cached under the plain URL key. Adding ?_cv=v26 to the cache key causes a miss on
//   first request, the injection runs, and the fresh v26 HTML is stored. Next version:
//   just bump CACHE_VERSION → automatic cache bust with no manual purge needed.
// v25 (15 Sep 2026) — JSON-LD structured data for all 6 main static pages.
//   Previously the Worker served /, /blog, /download, /services, /niches, /contact
//   as-is from env.ASSETS with only a caching header added — no HTML modification.
//   This left all 6 pages with zero structured data, which Ahrefs flags as
//   "Missing structured data". v25 reads the HTML as text, injects a page-specific
//   JSON-LD <script> before </head>, then caches and returns the modified HTML.
//   Schemas added:
//     /               → WebSite + Organization (enables sitelinks searchbox, knowledge graph)
//     /download       → SoftwareApplication (enables "Free" badge + OS in Google results)
//     /services       → WebPage + ItemList of service offerings
//     /blog           → Blog schema
//     /niches         → WebPage
//     /contact        → ContactPage
//   Also fixes Services page title ("Services — OutreachNest" → "Guest Posts, B2B Lead
//   Lists & Content Writing — OutreachNest") and meta description (was too short/generic).
//   The PAGE_SCHEMAS constant (module-level) holds all 6 serialized JSON-LD strings with
//   XSS-safe unicode escapes on < and > — same approach as BlogPosting schema.
// v24 (15 Sep 2026) — Dynamic sitemap.xml + internal-link "Read Next" section.
//   (a) /sitemap.xml now generated by the Worker from POSTS_META instead of being
//       a static file. Static file was missing/stale → GSC showed "invalid sitemap".
//       Generated on-the-fly so every new slug in POSTS_META appears automatically.
//       Served with a 24-hour edge cache.
//   (b) "Read Next" section injected before </body> on every post page — adds 2-3
//       dofollow internal links per post. Fixes Ahrefs "Page has only one dofollow
//       incoming internal link" warning on all 27 blog post pages.
//   Note: /robots.txt is NOT overridden here. The static robots.txt already correctly
//   allows AI search bots (GPTBot, ClaudeBot, PerplexityBot, etc.) and blocks only
//   training scrapers (CCBot, Bytespider, Amazonbot). Ahrefs warns about training
//   scrapers being blocked — that is intentional and correct, not a bug.
// v23 (15 Sep 2026) — Non-blocking cache writes via ctx.waitUntil() to cut TTFB.
//   Both handlePostPage and the HTML_PAGES block were doing `await cache.put()`
//   BEFORE returning the response — forcing every cold-cache request to wait for
//   the edge-cache write to finish before the first byte was sent. Switching to
//   ctx.waitUntil(cache.put()) fires the write in the background and returns the
//   response immediately. This shaves 200-400ms off TTFB on first-hit requests
//   (the ones Ahrefs flags as slow). Cache hits are unchanged (fast as before).
// v22 (15 Sep 2026) — Added datePublished & dateModified to BlogPosting JSON-LD schema.
//   Google Rich Results requires datePublished for Article/BlogPosting rich results.
//   All 27 posts now include schema dates (fallback: SITE_PUB_DATE = 2026-09-01).
//   Fixes "Structured data has Google rich results validation error" in Ahrefs.
// v19 (Sep 2026) — Keyword-optimized titles & descriptions for all 27 posts.
// Every title now targets a real search query (keyword-first); descriptions
// include secondary keywords. No structural changes — only POSTS_META strings updated.

// v15: 301 redirects for 8 truncated slugs that Google already indexed.
// Old URLs (cut off at 50 chars by a previous tooling bug) permanently redirect
// to clean canonical slugs. POSTS_META keys updated to use the clean slugs.
const SLUG_REDIRECTS = {
  "finding-electronics-and-appliance-repair-businesse": "finding-electronics-appliance-repair-businesses",
  "sourcing-leads-in-industrial-automation-plc-scada-": "industrial-automation-leads",
  "finding-electrical-contractors-and-panel-builders-": "electrical-contractors-panel-builders",
  "how-to-find-solar-guest-post-sites-and-leads-in-mi": "solar-guest-post-sites",
  "how-to-turn-your-lead-list-into-a-live-google-shee": "lead-list-google-sheet",
  "why-whatsapp-outreach-gets-higher-response-rates-t": "whatsapp-outreach-response-rates",
  "outreachnest-finder-features-guide-everything-the-": "outreachnest-finder-features",
  "how-to-build-1-000-link-building-prospects-in-minu": "link-building-prospects",
};

const OG_IMAGE = "https://public-files.gumroad.com/k51jvr84ph0hpd9lr2lghnpl7pl6";
const SITE_PUB_DATE = "2026-09-01"; // Publication date used in BlogPosting schema
const CACHE_VERSION = "v26"; // Bump this whenever the HTML_PAGES injection changes — forces a cache miss so fresh HTML is generated

// v24: Related posts map — 2-3 relevant slugs per post, grouped by topic.
// Injected as a "Read Next" section before </body> to fix Ahrefs warning
// "Page has only one dofollow incoming internal link" on 27 blog post pages.
// Each entry distributes link equity across the cluster, not just from /blog.
const RELATED_POSTS = {
  // Cold outreach / email cluster
  "the-awkward-truth-about-cold-outreach-nobody-tells": ["cold-email-that-gets-replies", "warm-up-new-email-domain", "whatsapp-outreach-response-rates"],
  "cold-email-that-gets-replies":    ["warm-up-new-email-domain", "the-awkward-truth-about-cold-outreach-nobody-tells", "whatsapp-outreach-response-rates"],
  "warm-up-new-email-domain":        ["cold-email-that-gets-replies", "the-awkward-truth-about-cold-outreach-nobody-tells", "whatsapp-outreach-response-rates"],
  "whatsapp-outreach-response-rates":["cold-email-that-gets-replies", "warm-up-new-email-domain", "how-to-find-seo-clients-fast-in-2026"],

  // SEO clients / agency cluster
  "how-to-find-seo-clients-fast-in-2026":          ["link-building-prospects", "how-agencies-manage-10-niches-without-losing-track", "outreachnest-finder-features"],
  "how-agencies-manage-10-niches-without-losing-track": ["how-to-find-seo-clients-fast-in-2026", "link-building-prospects", "outreachnest-finder-features"],

  // Link building cluster
  "link-building-prospects":              ["quality-over-quantity-backlinks", "spot-real-guest-post-site", "b2b-lead-list-worth-buying"],
  "quality-over-quantity-backlinks":      ["spot-real-guest-post-site", "guest-posting-vs-pbn-links-difference", "link-building-prospects"],
  "spot-real-guest-post-site":            ["guest-posting-vs-pbn-links-difference", "signs-guest-post-site-hurt-rankings", "quality-over-quantity-backlinks"],
  "guest-posting-vs-pbn-links-difference":["spot-real-guest-post-site", "signs-guest-post-site-hurt-rankings", "quality-over-quantity-backlinks"],
  "signs-guest-post-site-hurt-rankings":  ["spot-real-guest-post-site", "guest-posting-vs-pbn-links-difference", "vet-electronics-repair-guest-post-site"],
  "b2b-lead-list-worth-buying":           ["link-building-prospects", "outreachnest-finder-features", "quality-over-quantity-backlinks"],

  // Solar cluster
  "solar-guest-post-sites":       ["solar-niche-goldmine", "solar-guest-post-cost-2026", "spot-real-guest-post-site"],
  "solar-niche-goldmine":         ["solar-guest-post-sites", "solar-guest-post-cost-2026", "link-building-prospects"],
  "solar-guest-post-cost-2026":   ["solar-guest-post-sites", "solar-niche-goldmine", "signs-guest-post-site-hurt-rankings"],
  "choosing-solar-installer-guide":["solar-niche-goldmine", "solar-guest-post-sites", "electrical-contractors-online-growth"],

  // Electronics / repair cluster
  "finding-electronics-appliance-repair-businesses": ["electronics-repair-steady-demand", "vet-electronics-repair-guest-post-site", "outreachnest-finder-features"],
  "electronics-repair-steady-demand":                ["finding-electronics-appliance-repair-businesses", "vet-electronics-repair-guest-post-site", "how-to-find-seo-clients-fast-in-2026"],
  "vet-electronics-repair-guest-post-site":          ["electronics-repair-steady-demand", "signs-guest-post-site-hurt-rankings", "guest-posting-vs-pbn-links-difference"],

  // Electrical contractors cluster
  "electrical-contractors-panel-builders":  ["electrical-contractors-online-growth", "electrical-contractor-seo-backlinks", "finding-electronics-appliance-repair-businesses"],
  "electrical-contractors-online-growth":   ["electrical-contractors-panel-builders", "electrical-contractor-seo-backlinks", "how-to-find-seo-clients-fast-in-2026"],
  "electrical-contractor-seo-backlinks":    ["electrical-contractors-panel-builders", "electrical-contractors-online-growth", "link-building-prospects"],

  // Industrial automation cluster
  "industrial-automation-leads":           ["industrial-automation-high-value-niche", "how-agencies-manage-10-niches-without-losing-track", "link-building-prospects"],
  "industrial-automation-high-value-niche":["industrial-automation-leads", "how-agencies-manage-10-niches-without-losing-track", "b2b-lead-list-worth-buying"],

  // OutreachNest tool cluster
  "outreachnest-finder-features":                ["how-to-check-da-pa-dr-without-paying-for-tools", "lead-list-google-sheet", "how-to-find-seo-clients-fast-in-2026"],
  "how-to-check-da-pa-dr-without-paying-for-tools":["outreachnest-finder-features", "lead-list-google-sheet", "link-building-prospects"],
  "lead-list-google-sheet":                       ["outreachnest-finder-features", "how-to-check-da-pa-dr-without-paying-for-tools", "b2b-lead-list-worth-buying"],
};

// v25: JSON-LD schemas for each of the 6 main static pages.
// Injected server-side before </head> — same XSS-safe unicode-escape approach
// as BlogPosting schema. Fixes Ahrefs "Missing structured data" on all main pages.
const PAGE_SCHEMAS = {
  "/": JSON.stringify([
    {
      "@context": "https://schema.org",
      "@type": "WebSite",
      "url": "https://getoutreachnest.com",
      "name": "OutreachNest",
      "description": "SEO lead generation and link building tools for freelancers and agencies.",
    },
    {
      "@context": "https://schema.org",
      "@type": "Organization",
      "name": "OutreachNest",
      "url": "https://getoutreachnest.com",
      "logo": "https://getoutreachnest.com/favicon.png",
      "description": "OutreachNest builds SEO prospecting and link building tools for freelancers and agencies.",
    },
  ]).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/download": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "OutreachNest Finder",
    "operatingSystem": "Windows",
    "applicationCategory": "BusinessApplication",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD",
      "description": "3-day free trial",
    },
    "description": "OutreachNest Finder finds 1,000 SEO prospects in minutes. Auto-checks DA, PA, DR, extracts emails and syncs to Google Sheets.",
    "url": "https://getoutreachnest.com/download",
    "author": {
      "@type": "Organization",
      "name": "OutreachNest",
      "url": "https://getoutreachnest.com",
    },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/services": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "Guest Posts, B2B Lead Lists & Content Writing — OutreachNest",
    "url": "https://getoutreachnest.com/services",
    "description": "Guest posts on real niche sites ($70–$250), verified B2B lead lists ($75/100 contacts), SEO content writing ($45/1,000 words). Solar, electrical & automation niches.",
    "mainEntity": {
      "@type": "ItemList",
      "name": "OutreachNest SEO Services",
      "itemListElement": [
        { "@type": "ListItem", "position": 1, "name": "Niche Guest Posts", "description": "Real placements on solar, electrical, automation, and electronics sites. $70–$250 per post." },
        { "@type": "ListItem", "position": 2, "name": "Verified B2B Lead Lists", "description": "100 verified business contacts with emails. $75 per 100 leads." },
        { "@type": "ListItem", "position": 3, "name": "SEO Content Writing", "description": "1,000 words of niche-specific, SEO-optimized content. $45 per 1,000 words." },
      ],
    },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/blog": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Blog",
    "name": "OutreachNest Blog — Link Building, Outreach & SEO Tips",
    "url": "https://getoutreachnest.com/blog",
    "description": "Practical insights on link building, guest posting, cold outreach, and SEO lead generation for freelancers and agencies.",
    "publisher": {
      "@type": "Organization",
      "name": "OutreachNest",
      "url": "https://getoutreachnest.com",
    },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/niches": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "Niches — OutreachNest | Solar · Electrical · Automation · Electronics",
    "url": "https://getoutreachnest.com/niches",
    "description": "OutreachNest specializes in four high-value B2B niches: solar energy, electrical contractors, industrial automation, and electronics repair.",
    "isPartOf": { "@type": "WebSite", "url": "https://getoutreachnest.com" },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/contact": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "ContactPage",
    "name": "Get in Touch — OutreachNest",
    "url": "https://getoutreachnest.com/contact",
    "description": "Contact OutreachNest for guest posting services, B2B lead lists, or SEO content writing. We reply fast.",
    "isPartOf": { "@type": "WebSite", "url": "https://getoutreachnest.com" },
  }).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),
};

// Build the "Read Next" HTML block for a given slug — injected before </body>.
// Uses dofollow links (no rel="nofollow") so Google distributes link equity.
function buildRelatedSection(currentSlug) {
  const related = RELATED_POSTS[currentSlug];
  if (!related || related.length === 0) return "";
  const cards = related.map(slug => {
    const meta = POSTS_META[slug];
    if (!meta) return "";
    return `<a href="/post?p=${slug}" style="display:block;padding:14px 16px;background:#f8f9fa;border:1px solid #e2e8f0;border-radius:8px;text-decoration:none;color:#1e293b;font-size:14px;font-weight:500;line-height:1.4;transition:background 0.15s">${escHtml(meta.title)}</a>`;
  }).filter(Boolean).join("\n");
  if (!cards) return "";
  return `\n<section style="max-width:720px;margin:40px auto 0;padding:0 20px 48px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">\n  <h2 style="font-size:16px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin:0 0 14px">Read Next</h2>\n  <div style="display:flex;flex-direction:column;gap:10px">\n${cards}\n  </div>\n</section>`;
}

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
// slug      — post slug, used to build the "Read Next" related-posts section (v24)
function injectPostMeta(html, title, desc, canonical, h1Text, slug) {
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
    "datePublished": SITE_PUB_DATE,
    "dateModified": SITE_PUB_DATE,
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

  // v24: inject "Read Next" related-posts section before </body>.
  // Adds 2-3 dofollow internal links per post — fixes Ahrefs "Page has only one
  // dofollow incoming internal link" warning on all 27 blog post pages.
  if (slug) {
    const relatedHtml = buildRelatedSection(slug);
    if (relatedHtml) {
      out = out.replace(/<\/body>/i, relatedHtml + "\n</body>");
    }
  }

  return out;
}

// Handle /post?p=SLUG — fetch the post.html template from ASSETS and inject
// per-post metadata before returning it to the visitor (or crawler).
async function handlePostPage(request, env, ctx, slug) {
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
  // Also pass slug so injectPostMeta can build the "Read Next" related-posts section (v24)
  const modified = injectPostMeta(html, fullTitle, meta.desc, canonical, meta.title, slug);

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
  // ctx.waitUntil() fires the cache write in the background so the response is
  // returned immediately (v23 change — was `await cache.put(...)` which blocked).
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
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
  async fetch(request, env, ctx) {
    // ── Load secrets from Cloudflare Secrets bindings ──────────────────────
    // These are never hard-coded here; set them in the Cloudflare dashboard
    // under Settings → Environment variables → Secrets.
    ADMIN_PASS            = env.ADMIN_PASS            ?? "";
    SESSION_SECRET        = env.SESSION_SECRET        ?? "";
    LICENSE_SECRET        = env.LICENSE_SECRET        ?? "";
    ED25519_PRIVATE_KEY_HEX = env.ED25519_PRIVATE_KEY_HEX ?? "";
    // Reset the Ed25519 key cache whenever the env binding changes
    // (new deployment with rotated key) — forces fresh importKey().
    _ed25519PrivateKeyCache = null;

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
        // 301 redirect old truncated slugs → clean canonical slugs (v15)
        const newSlug = SLUG_REDIRECTS[slug];
        if (newSlug) {
          return Response.redirect(
            "https://getoutreachnest.com/post?p=" + newSlug,
            301
          );
        }
        return handlePostPage(request, env, ctx, slug);
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

    // IndexNow key verification file — served as plain text so search engines can
    // confirm site ownership and accept IndexNow URL-change submissions.
    if (url.pathname === "/1257f0fc794749fa896e8d3c4e1af272.txt") {
      return new Response("1257f0fc794749fa896e8d3c4e1af272", {
        status: 200,
        headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=86400" },
      });
    }

    // v24: Dynamic sitemap.xml — generated from POSTS_META so it is always in sync.
    // GSC "invalid sitemap" was caused by the static sitemap.xml file being missing
    // or outdated. Now the Worker generates it on the fly from the canonical list.
    if (url.pathname === "/sitemap.xml") {
      const BASE = "https://getoutreachnest.com";
      const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      const SITE_PUB_DATE = "2026-09-01";
      const mainPages = [
        { loc: `${BASE}/`,         lastmod: today,         priority: "1.0", changefreq: "weekly"  },
        { loc: `${BASE}/blog`,     lastmod: today,         priority: "0.9", changefreq: "weekly"  },
        { loc: `${BASE}/download`, lastmod: today,         priority: "0.9", changefreq: "monthly" },
        { loc: `${BASE}/services`, lastmod: today,         priority: "0.8", changefreq: "monthly" },
        { loc: `${BASE}/niches`,   lastmod: today,         priority: "0.8", changefreq: "monthly" },
        { loc: `${BASE}/contact`,  lastmod: today,         priority: "0.7", changefreq: "monthly" },
      ];
      const postEntries = Object.keys(POSTS_META).map(slug => ({
        loc: `${BASE}/post?p=${slug}`,
        lastmod: SITE_PUB_DATE,
        priority: "0.7",
        changefreq: "monthly",
      }));
      const allEntries = [...mainPages, ...postEntries];
      const urlTags = allEntries.map(e =>
        `  <url>\n    <loc>${e.loc}</loc>\n    <lastmod>${e.lastmod}</lastmod>\n    <changefreq>${e.changefreq}</changefreq>\n    <priority>${e.priority}</priority>\n  </url>`
      ).join("\n");
      const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urlTags}\n</urlset>`;
      return new Response(xml, {
        status: 200,
        headers: {
          "Content-Type": "application/xml; charset=UTF-8",
          "Cache-Control": "public, max-age=3600, s-maxage=86400",
        },
      });
    }

    // robots.txt — served as a static file from ASSETS (not overridden here).
    // The existing static robots.txt already correctly: allows all AI SEARCH bots
    // (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, etc.) and intentionally
    // blocks pure training scrapers (CCBot, Bytespider, Amazonbot) which provide
    // no SEO value. Ahrefs "AI bots blocked" warning fires because it lumps training
    // scrapers together with search bots — the configuration is correct as-is.
    // Fall through to env.ASSETS.fetch() below to serve the static file unchanged.

    const isAdminPath = url.pathname === "/admin" || url.pathname === "/admin.html";

    if (!isAdminPath) {
      // Cache all static HTML pages at the edge to eliminate Worker cold-start TTFB.
      // v12 only cached /, but /blog, /download, /services, /niches, /contact all go
      // through env.ASSETS.fetch() uncached — causing Ahrefs "Slow page" and
      // "Slow server response for AI crawlers" warnings on those pages.
      // Static assets (CSS/JS/images) are cached natively by Cloudflare Pages CDN
      // and never reach this Worker, so we only need to cache HTML pages here.
      const HTML_PAGES = new Set(["/", "/index.html", "/blog", "/download", "/services", "/niches", "/contact"]);
      if (HTML_PAGES.has(url.pathname) && request.method === "GET") {
        const cache = caches.default;
        // v26: include CACHE_VERSION in the key so bumping the version busts the Workers cache.
        // caches.default is NOT cleared by "Purge Everything" in the Cloudflare dashboard —
        // it's a separate Workers Cache API store. Without this, re-deploying a new worker version
        // that modifies HTML leaves the old cached HTML in place until its TTL expires (24h).
        const versionedUrl = new URL(request.url);
        versionedUrl.searchParams.set("_cv", CACHE_VERSION);
        const cacheKey = new Request(versionedUrl.href, { method: "GET" });
        const cached = await cache.match(cacheKey);
        if (cached) return cached;
        const resp = await env.ASSETS.fetch(request);
        if (resp.ok) {
          // v25: inject JSON-LD schema for each main page.
          // Normalize /index.html → / for schema lookup; all other paths are canonical.
          const normPath = url.pathname === "/index.html" ? "/" : url.pathname;
          const schema = PAGE_SCHEMAS[normPath];
          let bodyText = await resp.text();
          if (schema) {
            const schemaTag = `<script type="application/ld+json">${schema}</script>`;
            // Replace existing JSON-LD block if present; otherwise inject before </head>
            const withSchema = bodyText.replace(/<script\s+type="application\/ld\+json">[\s\S]*?<\/script>/i, schemaTag);
            bodyText = (withSchema !== bodyText) ? withSchema : bodyText.replace(/<\/head>/i, schemaTag + "\n</head>");
            // v25: also fix Services page title and meta description (too generic in static HTML)
            if (normPath === "/services") {
              bodyText = bodyText
                .replace(/<title>[^<]*<\/title>/i, "<title>Guest Posts, B2B Lead Lists &amp; Content Writing — OutreachNest</title>")
                .replace(/<meta\s+name="description"[^>]*>/i, '<meta name="description" content="Guest posts on real niche sites ($70–$250), verified B2B lead lists ($75/100 contacts), SEO content writing ($45/1,000 words). Solar, electrical &amp; automation niches.">');
            }
          }
          const toCache = new Response(bodyText, {
            status: 200,
            headers: {
              "Content-Type": "text/html; charset=UTF-8",
              "Cache-Control": "public, max-age=3600, s-maxage=86400",
            },
          });
          // v23: non-blocking cache write — return immediately, write in background
          ctx.waitUntil(cache.put(cacheKey, toCache.clone()));
          return toCache;
        }
        return resp;
      }
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
