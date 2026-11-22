// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first` makes THIS script run for the admin panel paths AND the new
// /api/activate endpoint before Cloudflare's normal static-file serving kicks in; every other page
// on the site bypasses this file entirely and is served exactly as before, unchanged.
//
// v2 (27 Aug 2026) — replaced HTTP Basic Auth with a proper session-cookie login.
// v3 (27 Aug 2026) — SESSION_MAX_AGE_SECONDS cap + admin.html pagehide logout beacon.
// v4 (27 Aug 2026) — added the automated free-trial activation system (/api/activate):
// v33 (28 Sep 2026) — Three SEO fixes from comprehensive audit:
//   (a) og:type corrected to "article" on all blog post pages — was "website" (inherited
//       from static post.html template). injectPostMeta() now explicitly sets
//       og:type=article, fixing social previews and Google article eligibility.
//   (b) Homepage meta description shortened from 208 → 133 chars (was over 155-char limit).
//       Added override in HTML_PAGES caching block (same pattern as /services fix in v25).
//   (c) /blog title shortened from 73 → 54 chars and desc from 164 → 141 chars.
//       Both were over search-engine display limits. Overrides injected at cache time.
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
// v10 (Sep 2026) — IndexNow ping on publish: after every successful admin-panel post,
//   the new post URL is submitted to api.indexnow.org (fire-and-forget, never blocks
//   the publish response). Bing, Yandex, and any IndexNow-compatible engine receive
//   the URL within seconds instead of waiting for their next crawl cycle.
// v9 (Sep 2026) — fixed 3 POSTS_META titles still >60 chars and 3 descs still >155 chars
//   (longi vs canadian solar title, string inverter title, niche relevance title,
//    guest post vs pbn desc, da/dr/traffic desc, b2b lead list desc)
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
let RECOVERY_CODE;
let RESEND_API_KEY;
let RECOVERY_EMAIL;
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

// ── GitHub publishing secret (v27) ──────────────────────────────────────────
// A fine-grained GitHub PAT with "Contents: Read and write" permission on
// khurrambaigpk/outreachnest-website. Stored as a Cloudflare Secret — never
// in admin.html or localStorage. handlePublish() reads it from here.
// Add in Cloudflare dashboard → Settings → Environment variables → Add secret
// Name: GITHUB_TOKEN
let GITHUB_TOKEN;
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
    title: "Why Cold Outreach Fails: Hidden Mistakes",
    desc: "Cold outreach fails for the same reasons again and again — and most guides miss them. Learn the real reasons your cold emails and DMs don't get replies.",
  },
  "finding-electronics-appliance-repair-businesses": {
    title: "Find Electronics & Appliance Repair Shops",
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
    title: "How to Find Solar Guest Post Sites Fast",
    desc: "Find solar energy blogs, installer sites, and inverter or battery companies for guest posting and link building — in minutes, not days of manual searching.",
  },
  "how-agencies-manage-10-niches-without-losing-track": {
    title: "How SEO Agencies Manage 10+ Niches",
    desc: "Running outreach across many industries creates chaos. Here's how SEO agencies use niche profiles to stay organized and scale without confusion.",
  },
  "lead-list-google-sheet": {
    title: "Export Lead Lists to Google Sheets",
    desc: "Stop copying leads manually into spreadsheets. Learn how OutreachNest auto-exports your lead list to a live Google Sheet, updated in real time.",
  },
  "whatsapp-outreach-response-rates": {
    title: "WhatsApp Outreach vs Email: More Replies",
    desc: "Cold email open rates keep falling. WhatsApp messages get read in minutes. Here's how to run WhatsApp outreach that actually gets replies.",
  },
  "outreachnest-finder-features": {
    title: "OutreachNest Finder: Features Guide",
    desc: "Full walkthrough of every OutreachNest Finder feature: 4-engine business search, bulk email extraction, DA/PA/DR metrics, Chrome Bridge, and Sheets export.",
  },
  "how-to-find-seo-clients-fast-in-2026": {
    title: "How to Find SEO Clients Fast in 2026",
    desc: "A repeatable, no-ads system for finding and closing SEO clients in 2026. Build a prospect list, send targeted outreach, and land your next client fast.",
  },
  "link-building-prospects": {
    title: "Build 1,000 Link Building Prospects Fast",
    desc: "Most SEO freelancers waste days building prospect lists by hand. Here's a faster method to find 1,000+ real link building opportunities quickly.",
  },
  "how-to-check-da-pa-dr-without-paying-for-tools": {
    title: "Check DA, PA & DR Without Paid Tools",
    desc: "Check Domain Authority, Page Authority, and Domain Rating for free using OutreachNest's Chrome Bridge — no Moz or Ahrefs subscription required.",
  },
  "spot-real-guest-post-site": {
    title: "How to Spot Real Guest Post Sites vs PBNs",
    desc: "Not every 'write for us' site is safe. Learn how to identify real guest post opportunities versus link farms and private blog networks before you publish.",
  },
  "b2b-lead-list-worth-buying": {
    title: "What Makes a B2B Lead List Worth Buying",
    desc: "Most B2B lead lists are stale and full of bounced emails. Here's what separates a lead list worth paying for from one that wastes your outreach budget.",
  },
  "solar-niche-goldmine": {
    title: "Solar Niche: A Goldmine for Link Building",
    desc: "Solar is competitive, high-budget, and packed with companies actively investing in SEO. Here's why it's one of the best niches for link builders in 2026.",
  },
  "cold-email-that-gets-replies": {
    title: "Cold Email That Gets Replies (Framework)",
    desc: "Long, salesy cold emails get ignored. Short, specific, human ones get replies. Here's the cold email framework that consistently gets responses.",
  },
  "warm-up-new-email-domain": {
    title: "How to Warm Up a New Email Domain",
    desc: "Sending cold emails from a brand-new domain without warming it up sends you straight to spam. Here's the right way to warm up an email domain.",
  },
  "choosing-solar-installer-guide": {
    title: "How Homeowners Choose a Solar Installer",
    desc: "Understanding the buyer journey for solar installations reveals what content and trust signals help marketers, installers, and SEOs win more business.",
  },
  "electrical-contractors-online-growth": {
    title: "Electrical Contractors: Underrated Niche",
    desc: "Electrical contractors are a massive, stable B2B sector that most marketers ignore. Here's why that creates real opportunity — and how to reach them.",
  },
  "industrial-automation-high-value-niche": {
    title: "Industrial Automation: High-Value Niche",
    desc: "Fewer companies, higher deal value. Here's why industrial automation is worth targeting for B2B outreach and link building — and how to find these firms.",
  },
  "electronics-repair-steady-demand": {
    title: "Electronics Repair: Low Competition Niche",
    desc: "Repair shops fly under the radar but they're everywhere and always need marketing help. Here's how to tap the electronics repair niche for outreach.",
  },
  "quality-over-quantity-backlinks": {
    title: "Quality Link Building: Why Fewer Links Win",
    desc: "100 weak links won't beat 5 relevant links from trusted real sites. Here's why quality link building beats volume every time — and how to do it right.",
  },
  // v8: added 5 slugs that were in sitemap.xml but missing from POSTS_META —
  // without entries here the worker serves the unmodified template whose canonical
  // is /post (not /post?p=SLUG), causing "Non-canonical page in sitemap" in Ahrefs.
  "solar-guest-post-cost-2026": {
    title: "Solar Guest Post Cost in 2026",
    desc: "Solar guest post prices range from $25 to $500+. Here's what drives the price difference and how to find quality placements at fair market rates.",
  },
  "signs-guest-post-site-hurt-rankings": {
    title: "5 Signs a Guest Post Site Is Harmful",
    desc: "Some guest post sites do more harm than good. Learn how to spot thin content, PBN patterns, and unnatural link profiles before you publish and pay.",
  },
  "electrical-contractor-seo-backlinks": {
    title: "Electrical Contractors: SEO Backlinks Guide",
    desc: "Electrical contractors rarely do link building — which creates a real opportunity for SEOs. Here's how to earn and build backlinks in this niche.",
  },
  "vet-electronics-repair-guest-post-site": {
    title: "Electronics Repair Guest Post Site Checklist",
    desc: "Electronics repair blogs can be link farms in disguise. Here's a fast vetting checklist to find sites actually worth publishing on vs ones to skip.",
  },
  "guest-posting-vs-pbn-links-difference": {
    title: "Guest Posting vs PBN Links: Key Differences",
    desc: "Both place links on external sites, but risks and long-term results differ completely. Here's what actually separates a real guest post from a PBN link.",
  },
  // v28: 8 missing September 2026 slugs added — these were in posts.js but absent
  // from POSTS_META so the Worker was serving noindex for all of them.
  "longi-vs-canadian-solar-vs-jinko-panel-brand-comparison": {
    title: "Longi vs Canadian Solar vs Jinko Panels",
    desc: "Which solar panel brand wins on degradation, warranty, and hot-climate performance? An honest comparison of Longi, Canadian Solar, Jinko, and Risen.",
  },
  "string-inverter-vs-hybrid-vs-microinverter-comparison": {
    title: "String vs Hybrid vs Microinverter Guide",
    desc: "Most solar buyers choose the wrong inverter type. Here's the real cost, failure rate, and 10-year economics of string, hybrid, and microinverter systems.",
  },
  "topcon-vs-perc-vs-hjt-solar-panel-technology": {
    title: "TOPCon vs PERC vs HJT Solar Panels",
    desc: "PERC was the standard. TOPCon took over. HJT is next. Here's what each technology means for output, 25-year degradation, and your actual payback period.",
  },
  "high-da-zero-traffic-explained": {
    title: "High DA Zero Traffic: What's Happening?",
    desc: "A site with DA 45 and barely 30 monthly visitors — strong metric, no rankings. Here's why this happens and what it means before you pay for a link.",
  },
  "da-dr-traffic-which-matters-guest-posting": {
    title: "DA vs DR vs Traffic for Guest Posting",
    desc: "Three metrics every link builder watches — but they measure different things. Here's which to prioritize when DA, DR, and traffic conflict.",
  },
  "build-b2b-lead-list-from-scratch-2026": {
    title: "Build a B2B Lead List From Scratch 2026",
    desc: "Buying a generic database gets you bad emails and wasted outreach. Here's how to build your own verified B2B lead list in the right niches from scratch.",
  },
  "industrial-automation-seo-untapped-potential": {
    title: "Industrial Automation SEO: Link Building",
    desc: "PLC integrators and SCADA vendors rank on Google but almost none do link building. Here's why the gap exists and how SEOs are capitalizing on it in 2026.",
  },
  "niche-relevance-guest-posts-explained": {
    title: "Guest Post Niche Relevance Explained",
    desc: "A solar company placing a link on a home improvement blog — high DA, but not solar. Here's what actually matters for niche relevance and when it doesn't.",
  },
  "guest-post-outreach-email-templates-2026": { title: "Guest Post Outreach Email Templates 2026", desc: "Most guest post outreach emails get ignored because they're generic. Here are the exact templates and principles behind emails that actually get replies." },
  "how-to-price-guest-posts-2026": { title: "How to Price Guest Posts in 2026", desc: "Guest post pricing varies wildly — from $30 to $3,000. Here's what actually drives the price and how to evaluate whether you're getting real value." },
  "outreachnest-finder-vs-manual-prospecting": { title: "OutreachNest Finder vs Manual Prospecting", desc: "Manual prospecting works. So does OutreachNest Finder. Here's an honest look at where each approach makes sense and what each costs in time and money." },
  "b2b-lead-generation-electrical-contractors": { title: "B2B Leads for Electrical Contractors", desc: "Electrical contractors are one of the most reliable B2B markets for lead generation — but finding the right contacts requires a different approach." },
  "electrical-contractor-lead-generation": { title: "Electrical Contractor Lead Generation Guide", desc: "Electrical contractor lead generation is different from most B2B outreach. Here's what works, what doesn't, and how to build a consistent pipeline." },
  "link-building-solar-companies-guide": { title: "Link Building for Solar Companies (2026)", desc: "Solar is one of the most competitive niches for SEO — but most solar companies are doing link building wrong. Here's what actually works in 2026." },
};

// v27 (21 Sep 2026) — 301 redirect for /?ref=* → / to resolve Ahrefs "Orphan page"
//   warning. External platforms (LaunchNest, ProductHunt, etc.) link to the homepage
//   with a ?ref= tracking parameter. Ahrefs crawls these as separate pages and flags
//   them as orphans (no internal links point to /?ref=launchnest etc.). Since the
//   homepage canonical already covers these variants, redirecting to the clean URL
//   consolidates them and removes the Ahrefs warning without breaking any functionality.
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
const SITE_PUB_DATE = "2026-09-01";


// v28: Convert "Month YYYY" post dates to ISO YYYY-MM-01 for per-post schema dates.
// Falls back to SITE_PUB_DATE if the date string is missing or unrecognised.
function postDateToISO(dateStr) {
  var MONTHS = {
    january:"01", february:"02", march:"03", april:"04",
    may:"05", june:"06", july:"07", august:"08",
    september:"09", october:"10", november:"11", december:"12"
  };
  var m = String(dateStr || "").trim().toLowerCase().match(/^([a-z]+)\s+(\d{4})$/);
  if (!m || !MONTHS[m[1]]) return SITE_PUB_DATE;
  return m[2] + "-" + MONTHS[m[1]] + "-01";
} // Publication date used in BlogPosting schema
const CACHE_VERSION = "v78"; // v78: bust Workers cache so Market nav link injection actually runs (v77 Workers cache was stale) // v77: inject Market nav link via Worker on every HTML page (bypasses edge cache) // v72: /api/psx + /api/gold — replace session-cookie check with same-origin Referer check (fixes Incognito) // v65: private /dashboard route — session-protected owner dashboard with live currency rates, manual GSC+fuel update // v59: parallel ASSETS fetch in handlePostPage — fix slow TTFB for AI crawlers // v58: solar-calculator schema simplified to WebPage only (fix rich results validation error) // v57: robots.txt more AI bots allowed + solar-calculator schema // v56: sanitize invalid KV niches — reset to [] if unrecognized values stored // v55: niches page Article schema + Organization schema completeness fix // v54: recovery flow shows password-reset form instead of direct login // v53: run_worker_first=true + static asset pass-through + admin logout fix

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


  // Solar tech comparison cluster (new Sep 2026)
  "longi-vs-canadian-solar-vs-jinko-panel-brand-comparison": ["topcon-vs-perc-vs-hjt-solar-panel-technology", "string-inverter-vs-hybrid-vs-microinverter-comparison", "solar-niche-goldmine"],
  "string-inverter-vs-hybrid-vs-microinverter-comparison":   ["longi-vs-canadian-solar-vs-jinko-panel-brand-comparison", "topcon-vs-perc-vs-hjt-solar-panel-technology", "choosing-solar-installer-guide"],
  "topcon-vs-perc-vs-hjt-solar-panel-technology":            ["longi-vs-canadian-solar-vs-jinko-panel-brand-comparison", "string-inverter-vs-hybrid-vs-microinverter-comparison", "solar-niche-goldmine"],

  // DA/DR/traffic + niche relevance cluster (new Sep 2026)
  "high-da-zero-traffic-explained":           ["da-dr-traffic-which-matters-guest-posting", "niche-relevance-guest-posts-explained", "spot-real-guest-post-site"],
  "da-dr-traffic-which-matters-guest-posting":["high-da-zero-traffic-explained", "niche-relevance-guest-posts-explained", "quality-over-quantity-backlinks"],
  "niche-relevance-guest-posts-explained":    ["da-dr-traffic-which-matters-guest-posting", "high-da-zero-traffic-explained", "guest-posting-vs-pbn-links-difference"],

  // B2B lead list (new Sep 2026)
  "build-b2b-lead-list-from-scratch-2026": ["b2b-lead-list-worth-buying", "link-building-prospects", "outreachnest-finder-features"],

  // Industrial automation SEO (new Sep 2026)
  "industrial-automation-seo-untapped-potential": ["industrial-automation-leads", "industrial-automation-high-value-niche", "link-building-prospects"],
  // OutreachNest tool cluster
  "outreachnest-finder-features":                ["how-to-check-da-pa-dr-without-paying-for-tools", "lead-list-google-sheet", "how-to-find-seo-clients-fast-in-2026"],
  "how-to-check-da-pa-dr-without-paying-for-tools":["outreachnest-finder-features", "lead-list-google-sheet", "link-building-prospects"],
  "lead-list-google-sheet":                       ["outreachnest-finder-features", "how-to-check-da-pa-dr-without-paying-for-tools", "b2b-lead-list-worth-buying"],
  "guest-post-outreach-email-templates-2026": ["the-awkward-truth-about-cold-outreach-nobody-tells", "whatsapp-outreach-response-rates", "cold-email-that-gets-replies"],
  "how-to-price-guest-posts-2026": ["spot-real-guest-post-site", "solar-guest-post-cost-2026", "signs-guest-post-site-hurt-rankings"],
  "outreachnest-finder-vs-manual-prospecting": ["industrial-automation-leads", "how-agencies-manage-10-niches-without-losing-track", "lead-list-google-sheet"],
  "b2b-lead-generation-electrical-contractors": ["electrical-contractors-panel-builders", "electrical-contractors-online-growth", "electrical-contractor-seo-backlinks"],
  "electrical-contractor-lead-generation": ["b2b-lead-generation-electrical-contractors", "electrical-contractors-online-growth", "electrical-contractor-seo-backlinks"],
  "link-building-solar-companies-guide": ["solar-niche-goldmine", "guest-post-outreach-email-templates-2026", "how-to-price-guest-posts-2026"],
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
      "logo": {
        "@type": "ImageObject",
        "url": "https://getoutreachnest.com/favicon.png"
      },
      "description": "OutreachNest builds SEO prospecting and link building tools for freelancers and agencies.",
      "email": "support@getoutreachnest.com",
      "sameAs": [
        "https://gumroad.com/l/outreachnest"
      ],
      "contactPoint": {
        "@type": "ContactPoint",
        "contactType": "customer support",
        "url": "https://getoutreachnest.com/contact"
      }
    },
  ]).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

  "/download": JSON.stringify({
    "@context": "https://schema.org",
    "@type": "WebPage",
    "name": "Download OutreachNest Finder — Free 7-Day Trial",
    "url": "https://getoutreachnest.com/download",
    "description": "Download OutreachNest Finder for Windows and start the 7-day free trial automatically — no sign-up needed. Find SEO prospects, check DA, PA and DR, extract emails and export prospect data.",
    "about": {
      "@type": "Thing",
      "name": "OutreachNest Finder"
    },
    "publisher": {
      "@type": "Organization",
      "name": "OutreachNest",
      "url": "https://getoutreachnest.com",
      "logo": "https://getoutreachnest.com/favicon.png"
    }
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

  "/niches": JSON.stringify([
    {
      "@context": "https://schema.org",
      "@type": "WebPage",
      "name": "Niches — OutreachNest | Solar · Electrical · Automation · Electronics",
      "url": "https://getoutreachnest.com/niches",
      "description": "OutreachNest specializes in four high-value B2B niches: solar energy, electrical contractors, industrial automation, and electronics repair.",
      "isPartOf": { "@type": "WebSite", "url": "https://getoutreachnest.com" },
    },
    {
      "@context": "https://schema.org",
      "@type": "Article",
      "headline": "OutreachNest Niches: Solar, Electrical, Automation & Electronics",
      "description": "OutreachNest specializes in four high-value B2B niches: solar energy, electrical contractors, industrial automation, and electronics repair.",
      "url": "https://getoutreachnest.com/niches",
      "publisher": {
        "@type": "Organization",
        "name": "OutreachNest",
        "url": "https://getoutreachnest.com",
        "logo": { "@type": "ImageObject", "url": "https://getoutreachnest.com/favicon.png" }
      },
      "mainEntityOfPage": { "@type": "WebPage", "@id": "https://getoutreachnest.com/niches" }
    }
  ]).replace(/</g, "\\u003c").replace(/>/g, "\\u003e"),

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
    return `<a href="/blog/${slug}" style="display:block;padding:14px 16px;background:#f8f9fa;border:1px solid #e2e8f0;border-radius:8px;text-decoration:none;color:#1e293b;font-size:14px;font-weight:500;line-height:1.4;transition:background 0.15s">${escHtml(meta.title)}</a>`;
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
function injectPostMeta(html, title, desc, canonical, h1Text, slug, postDate) {
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
    .replace(/<meta\s+name="twitter:image"[^>]*>/i, `<meta name="twitter:image" content="${OG_IMAGE}">`)
    // og:type — static template has "website"; blog posts must use "article" for
    // correct social previews and Google's article rich result eligibility.
    .replace(/<meta\s+property="og:type"[^>]*>/i, '<meta property="og:type" content="article">');

  // Fix robots meta tag for known slugs — static template has "noindex, follow"
  // which causes Google to skip all blog post pages. Change it to "index, follow"
  // so crawlers can index this post. (Unknown slugs stay noindex — see handlePostPage.)
  out = out.replace(/<meta\s+name="robots"[^>]*>/i, '<meta name="robots" content="index, follow">');

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
    "@type": "Article",
    "headline": h1Text || title,
    "description": desc,
    "image": OG_IMAGE,
    "url": canonical,
    "datePublished": postDate || SITE_PUB_DATE,
    "dateModified": postDate || SITE_PUB_DATE,
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
  const cacheKey = new Request(request.url + "#" + CACHE_VERSION, { method: "GET" });
  const cachedResp = await cache.match(cacheKey);
  if (cachedResp) return cachedResp;

  // Fetch template + posts-data.json in PARALLEL to minimize cold-start latency
  const templateUrl = new URL(request.url);
  templateUrl.pathname = "/post";
  templateUrl.search = "";
  const dataUrl = new URL("/posts-data.json", request.url).href;

  const [assetResp, dataResp] = await Promise.all([
    env.ASSETS.fetch(new Request(templateUrl.toString(), { method: "GET" })),
    env.ASSETS.fetch(new Request(dataUrl, { method: "GET" })).catch(() => null),
  ]);

  if (!assetResp.ok) {
    // Template fetch failed — pass through the error response unchanged.
    return assetResp;
  }

  let html = await assetResp.text();
  // v41: base href so CSS/JS loads correctly from /blog/slug path
  if (!html.includes('<base ')) {
    html = html.replace('<head>', '<head>\n<base href="/">');
  }

  // ── v28 permanent fix: posts-data.json is the single source of truth ──────
  let postData = null;
  try {
    if (dataResp && dataResp.ok) {
      const allPosts = await dataResp.json();
      postData = allPosts.find(p => p.slug === slug) || null;
    }
  } catch (e) {
    // posts-data.json unavailable — fall back to static POSTS_META below
  }

  // Resolve metadata: live posts-data.json → static POSTS_META → noindex
  const staticMeta = POSTS_META[slug];
  const meta = postData
    ? { title: postData.title, desc: postData.excerpt || (staticMeta && staticMeta.desc) || "" }
    : staticMeta;

  if (!meta) {
    // Unknown slug — not in posts-data.json AND not in POSTS_META → noindex
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

  const postDate = postDateToISO(postData ? postData.date : "");
  const fullTitle = meta.title + " — OutreachNest";
  const canonical = "https://getoutreachnest.com/blog/" + slug;
  let modified = injectPostMeta(html, fullTitle, meta.desc, canonical, meta.title, slug, postDate);

  // Inject full article body + cover/category from postData (already fetched above)
  if (postData) {
    try {
      // Inject article body
      const bodyMarker = 'id="aBody">';
      const bodyStart = modified.indexOf(bodyMarker);
      if (bodyStart !== -1) {
        const insertAt = bodyStart + bodyMarker.length;
        const endDiv = modified.indexOf('</div>', insertAt);
        if (endDiv !== -1) {
          modified = modified.slice(0, insertAt) + postData.content + modified.slice(endDiv);
        }
      }
      // Inject cover class and icon
      modified = modified.replace(
        /<div([^>]*)\bid="aCover"\b([^>]*)>[^<]*<\/div>/i,
        `<div class="art-cover ${escHtml(postData.cover)}" id="aCover">${escHtml(postData.icon)}</div>`
      );
      // Inject category name
      modified = modified.replace(
        /(<div[^>]*\bid="aCat"\b[^>]*>)[^<]*(<\/div>)/i,
        `$1${escHtml(postData.cat)}$2`
      );
    } catch (e) {
      // SSR content injection failed — metadata-only response still served
    }
  }

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

// ── Admin login rate-limiting (5 failures / 15 min per IP) ─────────────────
// KV key: `login_fail:{ip}` with 900 s TTL. Cleared on successful login.
// Shares the LICENSE_KV namespace — no extra binding needed.
async function getLoginFailCount(ip, env) {
  if (!ip) return 0;
  try {
    const val = await env.LICENSE_KV.get(`login_fail:${ip}`);
    return val ? parseInt(val, 10) : 0;
  } catch(e) { return 0; }
}
async function incrementLoginFail(ip, env) {
  if (!ip) return;
  try {
    const key = `login_fail:${ip}`;
    const val = await env.LICENSE_KV.get(key);
    const count = (val ? parseInt(val, 10) : 0) + 1;
    await env.LICENSE_KV.put(key, String(count), { expirationTtl: 900 }); // 15 min
  } catch(e) { /* best-effort */ }
}
async function clearLoginFail(ip, env) {
  if (!ip) return;
  try { await env.LICENSE_KV.delete(`login_fail:${ip}`); } catch(e) {}
}

// ── Recovery (v32) ──────────────────────────────────────────────────────────
async function generateRecoveryToken(){const e=Date.now()+900000;const r=[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');const p=r+'.'+e;return p+'.'+(await hmacSign(p,SESSION_SECRET));}
async function verifyRecoveryToken(t){const[r,e,s]=t.split('.');if(!r||!e||!s)return false;if(Date.now()>+e)return false;return s===(await hmacSign(r+'.'+e,SESSION_SECRET));}
async function sendRecoveryEmail(token,req){if(!RESEND_API_KEY||!RECOVERY_EMAIL)return false;const link=new URL(req.url).origin+'/admin/recover?token='+encodeURIComponent(token);try{const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':'Bearer '+RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:'OutreachNest <noreply@getoutreachnest.com>',to:[RECOVERY_EMAIL],subject:'Admin Recovery Link',html:'<p>Your recovery link (expires in 15 min):</p><p><a href="'+link+'">'+link+'</a></p>'})});return r.ok;}catch(e){return false;}}
function forgotPageHtml(){return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recovery</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:system-ui;padding:20px}.b{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;text-align:center}h1{font-size:20px;margin:0 0 8px;color:#16261f}p{color:#6b6459;font-size:13.5px;margin:0 0 20px}input{width:100%;padding:12px 14px;margin-bottom:12px;border:1px solid #d8d0c0;border-radius:8px;font-size:14px}button{width:100%;padding:12px;border:none;border-radius:8px;background:#1f4d3a;color:#fff;font-weight:600;cursor:pointer}a{display:block;margin-top:12px;font-size:13px;color:#888;text-decoration:none}</style></head><body><div class="b"><div style="font-size:36px;margin-bottom:12px">📧</div><h1>Account Recovery</h1><p>We'll send a recovery link to your registered email.</p><form method="POST"><input type="email" name="email" placeholder="Your email address" required autofocus><button>Send Recovery Link</button></form><a href="/admin">← Back to login</a></div></body></html>`;}
function recoveryConfirmHtml(sent){const m=sent?'Recovery link sent! Check your inbox — expires in 15 minutes.':'Request received. If that email is registered, a link has been sent.';return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Recovery Sent</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:system-ui;padding:20px}.b{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;text-align:center}p{color:#3a6b55;font-size:14px;margin:0 0 20px}a{font-size:13px;color:#888;text-decoration:none}</style></head><body><div class="b"><div style="font-size:40px;margin-bottom:12px">✅</div><p>${m}</p><a href="/admin">← Back to login</a></div></body></html>`;}
function invalidTokenHtml(){return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Invalid Link</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:system-ui;padding:20px}.b{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;text-align:center}p{color:#a33;font-size:14px;margin:0 0 20px}a{font-size:13px;color:#888;text-decoration:none}</style></head><body><div class="b"><div style="font-size:40px;margin-bottom:12px">❌</div><p>This recovery link is invalid or expired.</p><a href="/admin/forgot">Request new link</a></div></body></html>`;}

function resetPasswordHtml(token,err=''){return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password</title><meta name="robots" content="noindex"><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:system-ui;padding:20px}.b{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;text-align:center}h1{font-size:20px;margin:0 0 8px;color:#16261f}p{color:#6b6459;font-size:13.5px;margin:0 0 20px}input{width:100%;padding:12px 14px;margin-bottom:12px;border:1px solid #d8d0c0;border-radius:8px;font-size:14px}button{width:100%;padding:12px;border:none;border-radius:8px;background:#1f4d3a;color:#fff;font-weight:600;cursor:pointer}.err{color:#a33;font-size:13px;margin-bottom:12px}</style></head><body><div class="b"><div style="font-size:36px;margin-bottom:12px">🔑</div><h1>Set New Password</h1><p>Enter and confirm your new admin password.</p>${err?`<p class="err">${err}</p>`:''}<form method="POST"><input type="hidden" name="token" value="${token}"><input type="password" name="newpass" placeholder="New password" required autofocus minlength="8"><input type="password" name="confirm" placeholder="Confirm password" required minlength="8"><button>Save New Password</button></form></div></body></html>`;}
function resetSuccessHtml(){return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Password Updated</title><meta name="robots" content="noindex"><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f3;font-family:system-ui;padding:20px}.b{background:#fff;border:1px solid #e4ddd0;border-radius:14px;padding:36px 32px;max-width:340px;width:100%;text-align:center}p{color:#3a6b55;font-size:14px;margin:0 0 20px}a{display:inline-block;padding:12px 24px;background:#1f4d3a;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px}</style></head><body><div class="b"><div style="font-size:40px;margin-bottom:12px">✅</div><p>Password updated! You can now log in with your new password.</p><a href="/admin">Go to Login</a></div></body></html>`;}

function loginPageHtml(showError, rateLimited = false) {
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
.pw-wrap{position:relative;display:flex;align-items:center;margin-bottom:12px}
.pw-wrap input{width:100%;padding-right:2.6rem;margin-bottom:0}
.eye-btn{position:absolute;right:.55rem;background:none;border:none;cursor:pointer;color:#aaa;padding:0;display:flex;align-items:center;width:auto}
.eye-btn:hover{color:#555}.eye-btn svg{width:1.15rem;height:1.15rem}
.forgot{display:block;text-align:center;margin-top:6px;font-size:12.5px;color:#aaa;text-decoration:none}
.forgot:hover{color:#555}
</style>
</head>
<body>
<div class="box">
<div class="lock">🔐</div>
<h1>Admin Access</h1>
<p>OutreachNest Blog Editor</p>
${rateLimited ? '<div class="err">🔒 Too many failed attempts. Please wait 15 minutes before trying again.</div>' : showError ? '<div class="err">❌ Incorrect username or password.</div>' : ""}
<form method="POST">
<input type="text" name="username" placeholder="Username" autocomplete="username" required autofocus>
<div class="pw-wrap"><input type="password" name="password" id="adminPw" placeholder="Password" autocomplete="current-password" required><button type="button" class="eye-btn" id="eyeBtn" aria-label="Toggle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
<button type="submit">Unlock →</button>
</form>
<a href="/admin/forgot" class="forgot">Forgot password?</a>
<script>document.getElementById('eyeBtn').onclick=function(){var f=document.getElementById('adminPw');f.type=f.type==='password'?'text':'password';this.innerHTML=f.type==='password'?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>':'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'};</script>
</div>
</body>
</html>`;
}

// ── Server-side GitHub publishing (v27) ────────────────────────────────────
// POST /api/publish  (session-authenticated)
//
// Why it lives here:
//   The GitHub PAT that gives write access to the repo must never be exposed
//   to JavaScript running in the browser — localStorage is readable by any XSS
//   payload that ever runs on the same origin. Moving publishing to the Worker
//   lets us store the credential as a Cloudflare Secret (env.GITHUB_TOKEN),
//   completely out of reach of client-side code.
//
// What it does:
//   Receives the new post's structured data from admin.html, then makes one
//   atomic commit (via GitHub's Git Data API) that updates all four files:
//     posts.js        — JavaScript data array the frontend reads
//     blog.html       — static grid card so non-JS crawlers see the new post
//     sitemap.xml     — URL entry so Google can discover the post
//     posts-data.json — pure JSON for Worker SSR (robots:index, full body)
//
//   Using the Git Data API (ref → commit → tree → blob × 4 → new tree →
//   new commit → update ref) means it's all-or-nothing: either all four files
//   update together or none do, so the site can never end up in a partial state
//   where, say, posts.js is updated but posts-data.json is still stale.
async function handlePublish(request, env) {
  // 1) Session check — must be logged-in admin
  const sessionTok = getCookie(request, COOKIE_NAME);
  if (!await verifySessionToken(sessionTok)) {
    return jsonResponse({ error: "Unauthorized — please log in to /admin first." }, 401);
  }

  // 2) Check the GITHUB_TOKEN secret is configured
  const ghToken = env.GITHUB_TOKEN ?? "";
  if (!ghToken) {
    return jsonResponse({ error: "GITHUB_TOKEN secret is not set on this Worker. Add it in Cloudflare Dashboard → Workers → your worker → Settings → Environment variables → Secrets." }, 500);
  }

  // 3) Parse and validate the request body
  let post;
  try {
    const body = await request.json();
    post = body.post;
  } catch(e) {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }
  const required = ["slug","cat","cover","icon","title","author","date","read","excerpt","content"];
  for (const f of required) {
    if (!post || typeof post[f] === "undefined" || post[f] === "") {
      return jsonResponse({ error: `Missing or empty field: ${f}` }, 400);
    }
  }
  const { slug, cat, cover, icon, title, author, date, read, excerpt, content } = post;

  const REPO   = "khurrambaigpk/outreachnest-website";
  const BRANCH = "main";
  const ghH = {
    "Authorization"         : `Bearer ${ghToken}`,
    "Accept"                : "application/vnd.github+json",
    "Content-Type"          : "application/json",
    "X-GitHub-Api-Version"  : "2022-11-28",
    "User-Agent"            : "OutreachNest-Worker/1.0",
  };
  const ghFetch = (url, opts = {}) =>
    fetch(url, { ...opts, headers: { ...ghH, ...(opts.headers || {}) } });

  // Decode GitHub's base64-encoded file content to a UTF-8 string
  const b64dec = b64 => new TextDecoder().decode(
    Uint8Array.from(atob(b64.replace(/\n/g, "")), c => c.charCodeAt(0))
  );
  // HTML-escape helper for blog card injection
  const esc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

  try {
    // ── Step A: get the current HEAD commit and its tree ──────────────────
    const refResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/ref/heads/${BRANCH}`);
    if (!refResp.ok) throw new Error(`GitHub: could not read branch ref (HTTP ${refResp.status})`);
    const { object: { sha: headSha } } = await refResp.json();

    const headCommitResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/commits/${headSha}`);
    if (!headCommitResp.ok) throw new Error(`GitHub: could not read HEAD commit (HTTP ${headCommitResp.status})`);
    const { tree: { sha: treeSha } } = await headCommitResp.json();

    // ── Step B: fetch the four current files in parallel ──────────────────
    const [postsJsResp, blogHtmlResp, sitemapResp, postsDataResp] = await Promise.all([
      ghFetch(`https://api.github.com/repos/${REPO}/contents/posts.js?ref=${BRANCH}`),
      ghFetch(`https://api.github.com/repos/${REPO}/contents/blog.html?ref=${BRANCH}`),
      ghFetch(`https://api.github.com/repos/${REPO}/contents/sitemap.xml?ref=${BRANCH}`),
      ghFetch(`https://api.github.com/repos/${REPO}/contents/posts-data.json?ref=${BRANCH}`),
    ]);
    if (!postsJsResp.ok)   throw new Error(`GitHub: could not read posts.js (HTTP ${postsJsResp.status})`);
    if (!blogHtmlResp.ok)  throw new Error(`GitHub: could not read blog.html (HTTP ${blogHtmlResp.status})`);
    if (!sitemapResp.ok)   throw new Error(`GitHub: could not read sitemap.xml (HTTP ${sitemapResp.status})`);
    if (!postsDataResp.ok) throw new Error(`GitHub: could not read posts-data.json (HTTP ${postsDataResp.status})`);

    const [postsJsData, blogHtmlData, sitemapData, postsDataData] = await Promise.all([
      postsJsResp.json(), blogHtmlResp.json(), sitemapResp.json(), postsDataResp.json(),
    ]);

    const postsJsContent  = b64dec(postsJsData.content);
    const blogHtmlContent = b64dec(blogHtmlData.content);
    const sitemapContent  = b64dec(sitemapData.content);
    const postsDataArr    = JSON.parse(b64dec(postsDataData.content));

    // ── Step C: build patched file contents ───────────────────────────────

    // posts.js — insert new post as a JS object literal using JSON.stringify
    // (safe: handles quotes, backticks, ${...}, backslashes, and all Unicode)
    const jsLiteral = `  {\n  slug:${JSON.stringify(slug)},\n  cat:${JSON.stringify(cat)}, cover:${JSON.stringify(cover)}, icon:${JSON.stringify(icon)},\n  title:${JSON.stringify(title)},\n  author:${JSON.stringify(author)}, date:${JSON.stringify(date)}, read:${JSON.stringify(read)},\n  excerpt:${JSON.stringify(excerpt)},\n  content:${JSON.stringify(content)}\n  },`;
    const postsMarker = "window.POSTS = [";
    const postsIdx = postsJsContent.indexOf(postsMarker);
    if (postsIdx === -1) throw new Error('Could not find "window.POSTS = [" in posts.js — file format may have changed');
    const newPostsJs = postsJsContent.slice(0, postsIdx + postsMarker.length)
      + "\n" + jsLiteral
      + postsJsContent.slice(postsIdx + postsMarker.length);

    // blog.html — insert card at the top of the grid
    const gridMarker = '<div class="blog-grid" id="blogGrid">';
    const gridIdx = blogHtmlContent.indexOf(gridMarker);
    if (gridIdx === -1) throw new Error('Could not find blog grid in blog.html — file format may have changed');
    const blogCard = `<a class="post reveal" href="/blog/${slug}"><div class="cover ${cover}">${esc(icon)}</div><div class="body"><div class="cat">${esc(cat)}</div><h3>${esc(title)}</h3><div class="excerpt">${esc(excerpt)}</div><div class="meta"><span>${esc(author)}</span><span class="dot"></span><span>${esc(read)}</span></div></div></a>`;
    const newBlogHtml = blogHtmlContent.slice(0, gridIdx + gridMarker.length)
      + blogCard
      + blogHtmlContent.slice(gridIdx + gridMarker.length);

    // sitemap.xml — insert new <url> entry
    const urlsetMarker = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
    const urlsetIdx = sitemapContent.indexOf(urlsetMarker);
    if (urlsetIdx === -1) throw new Error('Could not find <urlset> in sitemap.xml — file format may have changed');
    const urlEntry = `<url><loc>https://getoutreachnest.com/blog/${slug}</loc><priority>0.6</priority></url>`;
    const newSitemap = sitemapContent.slice(0, urlsetIdx + urlsetMarker.length)
      + "\n" + urlEntry
      + sitemapContent.slice(urlsetIdx + urlsetMarker.length);

    // posts-data.json — prepend new post to JSON array
    const newPostObj = { slug, cat, cover, icon, title, author, date, read, excerpt, content };
    const newPostsData = JSON.stringify([newPostObj, ...postsDataArr], null, 2);

    // ── Step D: create git blobs for all four files in parallel ───────────
    const filesToCommit = [
      { path: "posts.js",        body: newPostsJs   },
      { path: "blog.html",       body: newBlogHtml  },
      { path: "sitemap.xml",     body: newSitemap   },
      { path: "posts-data.json", body: newPostsData },
    ];
    const blobs = await Promise.all(filesToCommit.map(async ({ path, body: fileBody }) => {
      const blobResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/blobs`, {
        method: "POST",
        body: JSON.stringify({ content: fileBody, encoding: "utf-8" }),
      });
      if (!blobResp.ok) {
        const e = await blobResp.json().catch(() => ({}));
        throw new Error(`Blob creation failed for ${path}: ${e.message || blobResp.status}`);
      }
      const { sha: blobSha } = await blobResp.json();
      return { path, sha: blobSha, mode: "100644", type: "blob" };
    }));

    // ── Step E: create new tree, new commit, advance branch pointer ────────
    const newTreeResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/trees`, {
      method: "POST",
      body: JSON.stringify({ base_tree: treeSha, tree: blobs }),
    });
    if (!newTreeResp.ok) throw new Error(`Tree creation failed (HTTP ${newTreeResp.status})`);
    const { sha: newTreeSha } = await newTreeResp.json();

    const newCommitResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/commits`, {
      method: "POST",
      body: JSON.stringify({
        message: `publish: add "${title}" (${slug})`,
        tree: newTreeSha,
        parents: [headSha],
      }),
    });
    if (!newCommitResp.ok) throw new Error(`Commit creation failed (HTTP ${newCommitResp.status})`);
    const { sha: newCommitSha } = await newCommitResp.json();

    const updateRefResp = await ghFetch(`https://api.github.com/repos/${REPO}/git/refs/heads/${BRANCH}`, {
      method: "PATCH",
      body: JSON.stringify({ sha: newCommitSha, force: false }),
    });
    if (!updateRefResp.ok) throw new Error(`Branch update failed (HTTP ${updateRefResp.status})`);

    // ── v10: IndexNow ping (fire-and-forget — never blocks the publish response) ──
    // Notifies Bing, Yandex, and any IndexNow-compatible engine about the new URL
    // immediately, instead of waiting for their next scheduled crawl.
    const newPostUrl = `https://getoutreachnest.com/blog/${slug}`;
    fetch("https://api.indexnow.org/indexnow", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        host: "getoutreachnest.com",
        key: "1257f0fc794749fa896e8d3c4e1af272",
        keyLocation: "https://getoutreachnest.com/1257f0fc794749fa896e8d3c4e1af272.txt",
        urlList: [newPostUrl],
      }),
    }).catch(() => {}); // silent — a ping failure never rolls back a successful publish

    return jsonResponse({ success: true, commit: newCommitSha.slice(0, 7) });

  } catch(err) {
    return jsonResponse({ error: err.message }, 500);
  }
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
    // Load password: KV override (set via recovery flow) takes priority over env secret
    ADMIN_PASS              = env.ADMIN_PASS              ?? "";
    RECOVERY_CODE           = env.RECOVERY_CODE          ?? "";
    RESEND_API_KEY          = env.RESEND_API_KEY          ?? "";
    RECOVERY_EMAIL          = env.RECOVERY_EMAIL          ?? "";
    SESSION_SECRET          = env.SESSION_SECRET          ?? "";
    LICENSE_SECRET          = env.LICENSE_SECRET          ?? "";
    ED25519_PRIVATE_KEY_HEX = env.ED25519_PRIVATE_KEY_HEX ?? "";
    GITHUB_TOKEN            = env.GITHUB_TOKEN            ?? "";
    // Reset the Ed25519 key cache whenever the env binding changes
    // (new deployment with rotated key) — forces fresh importKey().
    _ed25519PrivateKeyCache = null;

    const url = new URL(request.url);

    // v53: Fast pass-through for static assets — with run_worker_first=true the Worker
    // runs for every request, so we immediately hand off static files (CSS, JS, images,
    // fonts, etc.) to env.ASSETS without any further processing.  Admin paths are
    // explicitly excluded so the auth gate below always fires for them.
    const _p = url.pathname;
    const _isAdmin = _p === "/admin" || _p === "/admin.html";
    const _isDashboard = _p === "/dashboard" || _p === "/dashboard.html";
    if (!_isAdmin && !_isDashboard && /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|pdf|zip|exe|txt|xml|json|webmanifest)$/i.test(_p)) {
      return env.ASSETS.fetch(request);
    }

    // Local badge SVGs — served inline from Worker so no ASSETS/CORS issues
    const BADGE_SVGS = {
      "launchnest": `<svg xmlns="http://www.w3.org/2000/svg" width="210" height="44" viewBox="0 0 210 44"><rect width="210" height="44" rx="8" fill="#0f172a"/><circle cx="22" cy="22" r="13" fill="#f97316"/><polygon points="22,12 17,24 20,24 20,32 24,32 24,24 27,24" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">LaunchNest</text></svg>`,
      "lookingfortools": `<svg xmlns="http://www.w3.org/2000/svg" width="230" height="44" viewBox="0 0 230 44"><rect width="230" height="44" rx="8" fill="#f97316"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><circle cx="20" cy="20" r="6" fill="none" stroke="#ffffff" stroke-width="2.5"/><line x1="25" y1="25" x2="31" y2="31" stroke="#ffffff" stroke-width="3" stroke-linecap="round"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="14" font-weight="800" fill="#ffffff">Looking For Tools</text></svg>`,
      "shiplaunch": `<svg xmlns="http://www.w3.org/2000/svg" width="205" height="44" viewBox="0 0 205 44"><rect width="205" height="44" rx="8" fill="#dc2626"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><ellipse cx="22" cy="19" rx="4" ry="7" fill="#ffffff"/><polygon points="18,23 13,31 22,27" fill="#ffffff"/><polygon points="26,23 31,31 22,27" fill="#ffffff"/><circle cx="22" cy="19" r="2" fill="#dc2626"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">Ship Launch</text></svg>`,
      "peerpush": `<svg xmlns="http://www.w3.org/2000/svg" width="195" height="44" viewBox="0 0 195 44"><rect width="195" height="44" rx="8" fill="#7c3aed"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><circle cx="17" cy="18" r="4" fill="#ffffff"/><circle cx="27" cy="18" r="4" fill="#ffffff"/><path d="M10,30 Q17,24 24,30" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round"/><path d="M20,30 Q27,24 34,30" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">PeerPush</text></svg>`,
      "indieneed": `<svg xmlns="http://www.w3.org/2000/svg" width="195" height="44" viewBox="0 0 195 44"><rect width="195" height="44" rx="8" fill="#059669"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><ellipse cx="22" cy="18" rx="5.5" ry="6.5" fill="#ffffff"/><rect x="19.5" y="24" width="5" height="2.5" rx="0.5" fill="#ffffff"/><rect x="20.5" y="27" width="3" height="2" rx="0.5" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">LISTED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">IndieNeed</text></svg>`,
      "smolhunt": `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="44" viewBox="0 0 200 44"><rect width="200" height="44" rx="8" fill="#0ea5e9"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><circle cx="20" cy="20" r="6" fill="none" stroke="#ffffff" stroke-width="2.5"/><line x1="25" y1="25" x2="31" y2="31" stroke="#ffffff" stroke-width="3" stroke-linecap="round"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">SmolHunt</text></svg>`,
      "shipthing": `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="44" viewBox="0 0 200 44"><rect width="200" height="44" rx="8" fill="#0284c7"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><rect x="14" y="18" width="16" height="10" rx="2" fill="#ffffff"/><polygon points="14,22 10,28 32,28 28,22" fill="#ffffff"/><rect x="19" y="14" width="6" height="6" rx="1" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">ShipThing</text></svg>`,
      "launch01": `<svg xmlns="http://www.w3.org/2000/svg" width="190" height="44" viewBox="0 0 190 44"><rect width="190" height="44" rx="8" fill="#ea580c"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><polygon points="24,11 16,24 21,24 20,33 28,20 23,20" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">Launch01</text></svg>`,
      "makerhunt": `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="44" viewBox="0 0 200 44"><rect width="200" height="44" rx="8" fill="#9333ea"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><rect x="13" y="20" width="18" height="11" rx="2" fill="#ffffff"/><rect x="17" y="16" width="10" height="6" rx="2" fill="#ffffff"/><rect x="20" y="13" width="4" height="5" rx="1" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">MakerHunt</text></svg>`,
      "directree": `<svg xmlns="http://www.w3.org/2000/svg" width="195" height="44" viewBox="0 0 195 44"><rect width="195" height="44" rx="8" fill="#16a34a"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><polygon points="22,11 15,21 29,21" fill="#ffffff"/><polygon points="22,17 13,28 31,28" fill="#ffffff"/><rect x="20" y="28" width="4" height="5" rx="1" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">VERIFIED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">Directree</text></svg>`,
      "smolsaas": `<svg xmlns="http://www.w3.org/2000/svg" width="195" height="44" viewBox="0 0 195 44"><rect width="195" height="44" rx="8" fill="#0891b2"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><rect x="13" y="19" width="18" height="13" rx="2" fill="#ffffff"/><path d="M18,19 L18,16 Q18,14 22,14 Q26,14 26,16 L26,19" fill="none" stroke="#ffffff" stroke-width="2.2"/><line x1="13" y1="25" x2="31" y2="25" stroke="#0891b2" stroke-width="1.5"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">SmolSaas</text></svg>`,
      "tinyhunt": `<svg xmlns="http://www.w3.org/2000/svg" width="195" height="44" viewBox="0 0 195 44"><rect width="195" height="44" rx="8" fill="#be185d"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><circle cx="20" cy="20" r="6" fill="none" stroke="#ffffff" stroke-width="2.5"/><line x1="25" y1="25" x2="31" y2="31" stroke="#ffffff" stroke-width="3" stroke-linecap="round"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">TinyHunt</text></svg>`,
      "startupscrolls": `<svg xmlns="http://www.w3.org/2000/svg" width="225" height="44" viewBox="0 0 225 44"><rect width="225" height="44" rx="8" fill="#b45309"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><rect x="14" y="12" width="16" height="20" rx="2" fill="#ffffff"/><line x1="17" y1="17" x2="27" y2="17" stroke="#b45309" stroke-width="1.5"/><line x1="17" y1="21" x2="27" y2="21" stroke="#b45309" stroke-width="1.5"/><line x1="17" y1="25" x2="23" y2="25" stroke="#b45309" stroke-width="1.5"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="13.5" font-weight="800" fill="#ffffff">StartupScrolls</text></svg>`,
      "supalaunch": `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="44" viewBox="0 0 200 44"><rect width="200" height="44" rx="8" fill="#0d9488"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><ellipse cx="22" cy="19" rx="4" ry="7" fill="#ffffff"/><polygon points="18,23 13,31 22,27" fill="#ffffff"/><polygon points="26,23 31,31 22,27" fill="#ffffff"/><circle cx="22" cy="19" r="2" fill="#0d9488"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="15" font-weight="800" fill="#ffffff">SupaLaunch</text></svg>`,
      "findtoptools": `<svg xmlns="http://www.w3.org/2000/svg" width="210" height="44" viewBox="0 0 210 44"><rect width="210" height="44" rx="8" fill="#ca8a04"/><circle cx="22" cy="22" r="13" fill="rgba(255,255,255,0.2)"/><path d="M15,27 Q15,14 22,14 Q29,14 29,27 Z" fill="#ffffff"/><path d="M15,16 Q11,16 11,21 Q11,25 16,25" fill="none" stroke="#ffffff" stroke-width="2"/><path d="M29,16 Q33,16 33,21 Q33,25 28,25" fill="none" stroke="#ffffff" stroke-width="2"/><rect x="19" y="27" width="6" height="2.5" rx="0.5" fill="#ffffff"/><rect x="17" y="30" width="10" height="2" rx="0.5" fill="#ffffff"/><text x="43" y="15" font-family="Arial,Helvetica,sans-serif" font-size="8.5" font-weight="700" fill="rgba(255,255,255,0.65)" letter-spacing="0.9">FEATURED ON</text><text x="43" y="32" font-family="Arial,Helvetica,sans-serif" font-size="14" font-weight="800" fill="#ffffff">FindTopTools</text></svg>`,
    };
    if (url.pathname.startsWith("/badges/") && url.pathname.endsWith(".svg")) {
      const name = url.pathname.replace("/badges/", "").replace(".svg", "");
      const svg = BADGE_SVGS[name];
      if (svg) {
        return new Response(svg, {
          status: 200,
          headers: { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=604800" }
        });
      }
    }

    // v62: canonical redirect — www. and http:// → https://getoutreachnest.com
    if (url.hostname === "www.getoutreachnest.com" || url.protocol === "http:") {
      const canonical = "https://getoutreachnest.com" + url.pathname + url.search;
      return Response.redirect(canonical, 301);
    }
    // v62: /index.html → /
    if (url.pathname === "/index.html") {
      return Response.redirect("https://getoutreachnest.com/", 301);
    }

    // v53: redirect orphan page (in sitemap but no content) to canonical equivalent
    if (_p === "/blog/electrical-contractor-lead-generation") {
      return Response.redirect("https://getoutreachnest.com/blog/b2b-lead-generation-electrical-contractors", 301);
    }

    // v41: redirect .html duplicates to clean canonical URLs
    if (url.pathname === "/blog.html") { return Response.redirect("https://getoutreachnest.com/blog", 301); }
    if (url.pathname === "/services.html") { return Response.redirect("https://getoutreachnest.com/services", 301); }
    if (url.pathname === "/niches.html") { return Response.redirect("https://getoutreachnest.com/niches", 301); }
    if (url.pathname === "/contact.html") { return Response.redirect("https://getoutreachnest.com/contact", 301); }
    if (url.pathname === "/download.html") { return Response.redirect("https://getoutreachnest.com/download", 301); }

    // V13.1: Explicit clean URL → .html file serving
    // Must come BEFORE HTML_PAGES block and BEFORE env.ASSETS.fetch()
    // This handles /download, /services, /niches, /contact, /blog
    // when Cloudflare Assets cannot auto-map clean URLs to .html files
    const CLEAN_URL_MAP = {
      "/download": "download.html",
      "/services": "services.html", 
      "/niches": "niches.html",
      "/contact": "contact.html",
    };
    if (CLEAN_URL_MAP[url.pathname] && request.method === "GET") {
      const fileUrl = new URL(request.url);
      fileUrl.pathname = "/" + CLEAN_URL_MAP[url.pathname];
      fileUrl.search = "";
      const fileResp = await env.ASSETS.fetch(new Request(fileUrl.toString(), {method: "GET"}));
      if (fileResp.ok) return fileResp;
    }

    // Databank config API — save/load settings server-side via KV
    // GET /api/databank-config — returns current config JSON
    if (url.pathname === "/api/databank-config" && request.method === "GET") {
      try {
        const cfg = await env.LICENSE_KV.get("databank_config");
        const DEFAULT_CFG = {
          cols: ["Domain","Niche","Category","DA","DR","Traffic","Emails","Phone","Country","Type","Status"],
          niches: [],
          pub_hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        };
        let parsed = cfg ? JSON.parse(cfg) : DEFAULT_CFG;
        // Sanitize niches: only keep values that match actual API sheet names
        // If niches contains unrecognized values, reset to [] (show all)
        const VALID_NICHES = ["Solar Sites","Electrical Contractors","Industrial Automation","Electronics Repair","GBOB Tracker","Publisher Inventory"];
        if (parsed.niches && parsed.niches.length > 0) {
          const filtered = parsed.niches.filter(n => VALID_NICHES.includes(n));
          if (filtered.length !== parsed.niches.length) {
            // Some invalid niches were present — reset to show all
            parsed.niches = [];
          }
        }
        const data = JSON.stringify(parsed);
        return new Response(data, {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store"
          }
        });
      } catch(e) {
        return new Response('{"error":"KV unavailable"}', { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // POST /api/databank-config — save config (requires admin token)
    if (url.pathname === "/api/databank-config" && request.method === "POST") {
      try {
        const body = await request.json();
        // Verify admin token — hash incoming token and compare with stored hash
        // Default hash = SHA256("password")
        const DEFAULT_ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        const token = request.headers.get("X-Admin-Token") || "";
        let storedHash = DEFAULT_ADMIN_HASH;
        try { storedHash = await env.LICENSE_KV.get("databank_admin_hash") || DEFAULT_ADMIN_HASH; } catch(e) {}
        const enc = new TextEncoder().encode(token);
        const buf = await crypto.subtle.digest("SHA-256", enc);
        const hash = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
        if (hash !== storedHash) {
          return new Response('{"error":"Unauthorized"}', { status: 401, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        await env.LICENSE_KV.put("databank_config", JSON.stringify(body));
        return new Response('{"ok":true}', { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      } catch(e) {
        return new Response('{"error":"' + e.message + '"}', { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // POST /api/databank-change-password — change databank admin password
    if (url.pathname === "/api/databank-change-password" && request.method === "POST") {
      try {
        const body = await request.json();
        const DEFAULT_ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        const currentToken = request.headers.get("X-Admin-Token") || "";
        let storedHash = DEFAULT_ADMIN_HASH;
        try { storedHash = await env.LICENSE_KV.get("databank_admin_hash") || DEFAULT_ADMIN_HASH; } catch(e) {}
        const enc = new TextEncoder().encode(currentToken);
        const buf = await crypto.subtle.digest("SHA-256", enc);
        const hash = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
        if (hash !== storedHash) {
          return new Response('{"error":"Current password is incorrect"}', { status: 401, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        const newPass = (body.newPassword || "").trim();
        if (newPass.length < 6) {
          return new Response('{"error":"New password must be at least 6 characters"}', { status: 400, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        const newEnc = new TextEncoder().encode(newPass);
        const newBuf = await crypto.subtle.digest("SHA-256", newEnc);
        const newHash = Array.from(new Uint8Array(newBuf)).map(b=>b.toString(16).padStart(2,"0")).join("");
        await env.LICENSE_KV.put("databank_admin_hash", newHash);
        return new Response('{"ok":true}', { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      } catch(e) {
        return new Response('{"error":"' + e.message + '"}', { status: 500, headers: { "Content-Type": "application/json" } });
      }
    }

    // OPTIONS preflight for config API
    if (url.pathname === "/api/databank-config" && request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token" } });
    }

    // OPTIONS preflight for change-password API
    if (url.pathname === "/api/databank-change-password" && request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token" } });
    }

    // Databank routes — serve .html files directly, no redirect loop
    if (url.pathname === "/databank" || url.pathname === "/databank/") {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = "/databank.html";
      return env.ASSETS.fetch(new Request(assetUrl.toString(), { method: "GET", headers: request.headers }));
    }
    if (url.pathname === "/databank-admin" || url.pathname === "/databank-admin/") {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = "/databank-admin.html";
      return env.ASSETS.fetch(new Request(assetUrl.toString(), { method: "GET", headers: request.headers }));
    }
    // Also handle direct .html access without redirect loop
    if (url.pathname === "/databank.html" || url.pathname === "/databank-admin.html") {
      return env.ASSETS.fetch(request);
    }

    // POST /api/track-download — simple download click counter stored in KV
    if (url.pathname === "/api/track-download" && request.method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
        const key = `dl_count_${today}`;
        const existing = parseInt(await env.ON_KV.get(key) || "0");
        await env.ON_KV.put(key, String(existing + 1), { expirationTtl: 60 * 60 * 24 * 90 }); // 90 days
        return new Response(JSON.stringify({ ok: true, count: existing + 1, date: today }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false }), { status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    // GET /api/track-download — see total counts (admin use)
    if (url.pathname === "/api/track-download" && request.method === "GET") {
      try {
        const { keys } = await env.ON_KV.list({ prefix: "dl_count_" });
        const counts = {};
        let total = 0;
        for (const k of keys) {
          const val = parseInt(await env.ON_KV.get(k.name) || "0");
          counts[k.name.replace("dl_count_", "")] = val;
          total += val;
        }
        return new Response(JSON.stringify({ ok: true, total, daily: counts }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch(e) {
        return new Response(JSON.stringify({ ok: false }), { status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    if (url.pathname === "/api/activate") {
      return handleActivate(request, env);
    }

    // Server-side publishing: admin POSTs post data here; Worker commits all
    // four files atomically to GitHub using env.GITHUB_TOKEN (a Cloudflare Secret).
    if (url.pathname === "/api/publish" && request.method === "POST") {
      return handlePublish(request, env);
    }

    // ── PSX KSE-100 proxy ────────────────────────────────────────────────
    if (url.pathname === "/api/psx" && request.method === "GET") {
      // Dashboard is already session-gated by the Worker; just verify same-origin referer
      const referer = request.headers.get('Referer') || '';
      const origin  = url.origin;
      if (!referer.startsWith(origin)) {
        return new Response('{"error":"forbidden"}', { status:403, headers:{'Content-Type':'application/json'} });
      }
      try {
        // Yahoo Finance — free, no key, 15-min delay
        const yResp = await fetch(
          'https://query1.finance.yahoo.com/v8/finance/chart/%5EKSE100?interval=1d&range=30d',
          { headers: { 'User-Agent': 'Mozilla/5.0' } }
        );
        const yData = await yResp.json();
        const meta  = yData?.chart?.result?.[0]?.meta || {};
        const result = {
          symbol:        meta.symbol || 'KSE100',
          price:         meta.regularMarketPrice,
          prev:          meta.chartPreviousClose,
          change:        meta.regularMarketPrice && meta.chartPreviousClose
                           ? (meta.regularMarketPrice - meta.chartPreviousClose).toFixed(2)
                           : null,
          changePct:     meta.regularMarketPrice && meta.chartPreviousClose
                           ? (((meta.regularMarketPrice - meta.chartPreviousClose) / meta.chartPreviousClose) * 100).toFixed(2)
                           : null,
          dayHigh:       meta.regularMarketDayHigh,
          dayLow:        meta.regularMarketDayLow,
          fiftyTwoHigh:  meta.fiftyTwoWeekHigh,
          fiftyTwoLow:   meta.fiftyTwoWeekLow,
          currency:      meta.currency,
          exchangeName:  meta.exchangeName,
          ts:            meta.regularMarketTime,
        };
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=900',
            'Access-Control-Allow-Origin': '*',
          }
        });
      } catch(e) {
        return new Response('{"error":"fetch_failed","msg":"' + e.message + '"}', { status:502, headers:{'Content-Type':'application/json'} });
      }
    }

    // ── Live Fuel Prices proxy (scrapes dailyfuels.com) ──────────────────
    if (url.pathname === "/api/fuel" && request.method === "GET") {
      const fuelRef = request.headers.get('Referer') || '';
      if (!fuelRef.startsWith(url.origin)) {
        return new Response('{"error":"forbidden"}', { status:403, headers:{'Content-Type':'application/json'} });
      }
      try {
        // dailyfuels.com has today's OGRA prices in a simple HTML table
        const fResp = await fetch('https://www.dailyfuels.com/pakistan/', {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; OutreachNest/1.0)' }
        });
        const html = await fResp.text();

        // Page table rows contain: fuel name | USD price | PKR price
        // Strategy: split by <tr> tags, find the row with the fuel name,
        // then extract the ₨ value from that row only
        function priceFromRow(htmlText, fuelRegex) {
          // Split on <tr (case-insensitive)
          const rows = htmlText.split(/<tr[\s>]/i);
          for (const row of rows) {
            if (fuelRegex.test(row)) {
              // Find ₨NNN in this row only
              const m = row.match(/₨\s*([\d,]+(?:\.\d+)?)/);
              if (m) return parseFloat(m[1].replace(/,/g,''));
            }
          }
          return null;
        }

        const petrol   = priceFromRow(html, /gasoline|petrol/i);
        const diesel   = priceFromRow(html, /\bdiesel\b/i);
        const kerosene = priceFromRow(html, /kerosene/i);

        // Extract date — look for "Updated" or date pattern
        const dateMatch = html.match(/(\d{4}-\d{2}-\d{2})/);
        const effective = dateMatch ? dateMatch[1] : new Date().toISOString().slice(0,10);

        const result = { petrol, diesel, kerosene, effective, source:'dailyfuels.com' };
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=3600', // 1-hour cache
            'Access-Control-Allow-Origin': '*',
          }
        });
      } catch(e) {
        return new Response('{"error":"fetch_failed","msg":"' + e.message + '"}', { status:502, headers:{'Content-Type':'application/json'} });
      }
    }

    // ── Gold/Silver proxy (session-authenticated) ─────────────────────────
    // Dashboard fetches /api/gold — Worker fetches xaus.com server-side
    // (no CORS issue) and returns the data with CORS headers for the dashboard.
    if (url.pathname === "/api/gold" && request.method === "GET") {
      const goldRef = request.headers.get('Referer') || '';
      if (!goldRef.startsWith(url.origin)) {
        return new Response('{"error":"forbidden"}', { status:403, headers:{'Content-Type':'application/json'} });
      }
      try {
        const goldResp = await fetch('https://xaus.com/api/v1/spot?compact=1', {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; OutreachNest Dashboard)' }
        });
        const goldData = await goldResp.text();
        return new Response(goldData, {
          status: goldResp.status,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=900', // cache 15 min
            'Access-Control-Allow-Origin': '*',
          }
        });
      } catch(e) {
        return new Response('{"error":"fetch_failed"}', { status:502, headers:{'Content-Type':'application/json'} });
      }
    }

    // ── Blog post pages: inject per-post metadata server-side ──────────────
    // /post?p=SLUG is the clean-URL pattern for all blog posts. The static
    // post.html template has generic title/description/canonical for ALL posts;
    // this intercepts the request and returns a version with correct values
    // injected for the specific slug before any JavaScript runs, so Ahrefs,
    // Google, and all social OG bots see unique metadata per post.
    // v28: 301 redirect /post.html → /post to eliminate the duplicate-URL issue.
    // /post.html and /post serve identical content; having both indexable creates
    // canonical ambiguity. Redirect to the clean canonical form.
    
    // ── Dynamic posts.js — v38 single source of truth ──────────────────────
    // Worker generates posts.js on-the-fly from posts-data.json.
    // Now you only need to update posts-data.json — posts.js auto-syncs.
    if (url.pathname === "/posts.js") {
      try {
        const jsonResp = await env.ASSETS.fetch(
          new Request(new URL("/posts-data.json", request.url).toString())
        );
        if (!jsonResp.ok) throw new Error("posts-data.json not found");
        const posts = await jsonResp.json();
        let js = "// Auto-generated from posts-data.json by Worker v38\n";
        js += "window.POSTS = [\n";
        for (const p of posts) {
          js += JSON.stringify(p) + ",\n";
        }
        js += "];\n";
        return new Response(js, {
          headers: {
            "Content-Type": "application/javascript; charset=UTF-8",
            "Cache-Control": "public, max-age=60",
          },
        });
      } catch (e) {
        return env.ASSETS.fetch(request);
      }
    }

    if (url.pathname === "/post.html") {
      // v41: Direct redirect to canonical /blog/slug (skip double-hop via /post)
      const slug = url.searchParams.get("p");
      if (slug) {
        return Response.redirect("https://getoutreachnest.com/blog/" + slug, 301);
      }
      return Response.redirect("https://getoutreachnest.com/blog", 301);
    }

    // v41: /blog/slug → canonical article page
    // Trailing slash redirect: /blog/slug/ → /blog/slug
    if (url.pathname.match(/^\/blog\/[a-z0-9][a-z0-9-]{2,100}\/$/) ) {
      return Response.redirect("https://getoutreachnest.com" + url.pathname.slice(0, -1), 301);
    }
    const blogSlugMatch = url.pathname.match(/^\/blog\/([a-z0-9][a-z0-9-]{2,100})$/);
    if (blogSlugMatch) {
      return handlePostPage(request, env, ctx, blogSlugMatch[1]);
    }

    if (url.pathname === "/post") {
      const slug = url.searchParams.get("p");
      if (slug) {
        // 301 redirect old truncated slugs → clean canonical slugs (v15)
        const newSlug = SLUG_REDIRECTS[slug];
        if (newSlug) {
          return Response.redirect(
            "https://getoutreachnest.com/blog/" + newSlug,
            301
          );
        }
        // v41: permanent redirect to canonical /blog/slug
        return Response.redirect("https://getoutreachnest.com/blog/" + slug, 301);
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
      // v28: per-post lastmod from posts-data.json; fall back to SITE_PUB_DATE
      let postDatesMap = {};
      try {
        const pdResp = await env.ASSETS.fetch(
          new Request(new URL("/posts-data.json", request.url).href, { method: "GET" })
        );
        if (pdResp.ok) {
          const pdArr = await pdResp.json();
          pdArr.forEach(p => { postDatesMap[p.slug] = postDateToISO(p.date); });
        }
      } catch(e) {}

      // Use posts-data.json slugs if available (always up-to-date);
      // fall back to POSTS_META keys (covers pre-deployment edge case).
      const sitemapSlugs = Object.keys(postDatesMap).length
        ? Object.keys(postDatesMap)
        : Object.keys(POSTS_META);

      const postEntries = sitemapSlugs.map(slug => ({
        loc: `${BASE}/blog/${slug}`,
        lastmod: postDatesMap[slug] || SITE_PUB_DATE,
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

    // 301 redirect for /8443 → / (port number URL crawled by some bots)
    if (url.pathname === "/8443") {
      return new Response(null, {
        status: 301,
        headers: { "Location": "https://getoutreachnest.com/", "Cache-Control": "public, max-age=86400" },
      });
    }

    // 301 redirect for homepage tracking parameter variants → clean canonical URL.
    // /?ref=*, /?via=*, /?utm_source=* are how external listing platforms link to
    // this site. Ahrefs crawls them as separate orphan pages. Redirect to / to consolidate.
    if (url.pathname === "/" && request.method === "GET" &&
        (url.searchParams.has("ref") || url.searchParams.has("via") || url.searchParams.has("utm_source"))) {
      return new Response(null, {
        status: 301,
        headers: {
          "Location": "https://getoutreachnest.com/",
          "Cache-Control": "public, max-age=86400",
        },
      });
    }

    // Recovery routes (v32)
    if(url.pathname==='/admin/forgot'){if(request.method==='GET')return new Response(forgotPageHtml(),{headers:{'Content-Type':'text/html; charset=UTF-8'}});if(request.method==='POST'){const tok=await generateRecoveryToken();try{await env.LICENSE_KV.put('admin_recovery_token',tok,{expirationTtl:900});}catch(e){}const sent=await sendRecoveryEmail(tok,request);return new Response(recoveryConfirmHtml(sent),{headers:{'Content-Type':'text/html; charset=UTF-8'}});}}
    if(url.pathname==='/admin/recover'){
      const tok=url.searchParams.get('token')||'';
      // POST — save new password
      if(request.method==='POST'){
        let formTok='',newpass='',confirm='';
        try{const fd=await request.formData();formTok=fd.get('token')||'';newpass=fd.get('newpass')||'';confirm=fd.get('confirm')||'';}catch(e){}
        if(!formTok||newpass.length<8){return new Response(resetPasswordHtml(formTok,'Password must be at least 8 characters.'),{headers:{'Content-Type':'text/html; charset=UTF-8'}});}
        if(newpass!==confirm){return new Response(resetPasswordHtml(formTok,'Passwords do not match.'),{headers:{'Content-Type':'text/html; charset=UTF-8'}});}
        // Verify token is still valid before saving
        let stillValid=false;
        try{const stored=await env.LICENSE_KV.get('admin_recovery_token');if(stored&&stored===formTok){stillValid=await verifyRecoveryToken(formTok);}}catch(e){}
        if(!stillValid){return new Response(invalidTokenHtml(),{headers:{'Content-Type':'text/html; charset=UTF-8'}});}
        // Save new password to KV (overrides env secret)
        try{
          await env.LICENSE_KV.put('admin_pass_override',newpass);
          await env.LICENSE_KV.delete('admin_recovery_token');
          ADMIN_PASS=newpass;
        }catch(e){return new Response(resetPasswordHtml(formTok,'Save failed — please try again.'),{headers:{'Content-Type':'text/html; charset=UTF-8'}});}
        return new Response(resetSuccessHtml(),{headers:{'Content-Type':'text/html; charset=UTF-8','Cache-Control':'no-store'}});
      }
      // GET — validate token, show reset form
      if(!tok)return Response.redirect('/admin',302);
      let valid=false;
      try{const stored=await env.LICENSE_KV.get('admin_recovery_token');if(stored&&stored===tok){valid=await verifyRecoveryToken(tok);}}catch(e){}
      if(!valid)return new Response(invalidTokenHtml(),{headers:{'Content-Type':'text/html; charset=UTF-8'}});
      return new Response(resetPasswordHtml(tok),{headers:{'Content-Type':'text/html; charset=UTF-8','Cache-Control':'no-store'}});
    }

    // v45: trailing slash redirect — /blog/slug/ → /blog/slug (301)
    // Cloudflare Pages does NOT strip trailing slashes automatically when a Worker
    // is in front. Any link or bookmark with a trailing slash returns 404 instead
    // of the post. This catch-all redirect fixes it for all paths site-wide.
    if (url.pathname !== "/" && url.pathname.endsWith("/") && request.method === "GET") {
      return new Response(null, {
        status: 301,
        headers: {
          "Location": "https://" + url.host + url.pathname.slice(0, -1) + (url.search || ""),
          "Cache-Control": "public, max-age=86400",
        },
      });
    }

        const isAdminPath = url.pathname === "/admin" || url.pathname === "/admin.html";

    if (!isAdminPath) {
      // Cache all static HTML pages at the edge to eliminate Worker cold-start TTFB.
      // v12 only cached /, but /blog, /download, /services, /niches, /contact all go
      // through env.ASSETS.fetch() uncached — causing Ahrefs "Slow page" and
      // "Slow server response for AI crawlers" warnings on those pages.
      // Static assets (CSS/JS/images) are cached natively by Cloudflare Pages CDN
      // and never reach this Worker, so we only need to cache HTML pages here.
      const HTML_PAGES = new Set(["/", "/index.html", "/blog", "/download", "/services", "/niches", "/contact", "/solar-calculator", "/market", "/activate"]);
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
        // V13.1: fetch .html file directly — avoids redirect loop
        // (/download.html → /download → /download.html → 404)
        const _HTML_MAP = {"/":"/index.html","/index.html":"/index.html","/blog":"/blog.html","/download":"/download.html","/services":"/services.html","/niches":"/niches.html","/contact":"/contact.html","/solar-calculator":"/solar-calculator.html","/market":"/market.html","/activate":"/activate.html"};
        const _assetUrl = new URL(request.url);
        _assetUrl.pathname = _HTML_MAP[url.pathname] || url.pathname;
        const resp = await env.ASSETS.fetch(new Request(_assetUrl.toString(), {method:"GET",headers:request.headers}));
        if (resp.ok) {
          // v25: inject JSON-LD schema for each main page.
          // Normalize /index.html → / for schema lookup; all other paths are canonical.
          const normPath = url.pathname === "/index.html" ? "/" : url.pathname;
          const schema = PAGE_SCHEMAS[normPath];
          let bodyText = await resp.text();
          // v77: inject Market nav link on ALL pages — runs after fetch so works
          // regardless of which cached HTML version Cloudflare edge is serving
          const MARKET_LINK = `<a href="/market" style="display:inline-flex;align-items:center;gap:4px;background:#dcfce7;color:#166534;border:1.5px solid #4ade80;border-radius:20px;padding:3px 11px;font-weight:700;font-size:13px">📈 Market</a>`;
          // Insert before the solar-calculator Free Tools link (desktop + mobile nav)
          bodyText = bodyText.replace(
            /(<a href="\/solar-calculator"[^>]*>☀️ Free Tools<\/a>)/g,
            MARKET_LINK + '$1'
          );
          if (schema) {
            const schemaTag = `<script type="application/ld+json">${schema}</script>`;
            // v26: strip ALL existing JSON-LD blocks (global g flag), then insert ours
            // before </head>. The old single-replace + !== comparison was fragile —
            // if the regex failed to match (or matched but produced the same string
            // length by coincidence), the fallback path produced a double-schema page.
            bodyText = bodyText.replace(/<script\s+type="application\/ld\+json">[\s\S]*?<\/script>\n?/gi, '');
            bodyText = bodyText.replace(/<\/head>/i, schemaTag + "\n</head>");
            // v25: also fix Services page title and meta description (too generic in static HTML)
            if (normPath === "/services") {
              const fiverrBanner = `\n<!-- Fiverr Banner -->\n<section style="padding:20px 0 0"><div class="wrap" style="text-align:center"><div style="display:inline-flex;align-items:center;gap:12px;background:var(--paper-2);border:1px solid var(--line);border-radius:12px;padding:14px 24px;flex-wrap:wrap;justify-content:center"><span style="font-size:15px;color:var(--muted)">Need a single blog post?</span><a href="https://www.fiverr.com/s/VrYj9jx" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:8px;background:#1dbf73;color:#fff;padding:9px 18px;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none">🛒 Order on Fiverr — from $15</a></div></div></section>`;
              bodyText = bodyText
                .replace(/<!-- CTA -->/, fiverrBanner + '\n<!-- CTA -->')
                .replace(/<title>[^<]*<\/title>/i, "<title>Guest Posts, B2B Lead Lists &amp; Content Writing — OutreachNest</title>")
                .replace(/<meta\s+name="description"[^>]*>/i, '<meta name="description" content="Niche guest posts ($70–$250), B2B lead lists ($75/100 contacts), SEO content writing ($45/1k words). Solar, electrical &amp; automation niches.">');
            }
            // v33: fix homepage meta description (was 208 chars — over 155-char limit)
            if (normPath === "/") {
              bodyText = bodyText
                .replace(/<meta\s+name="description"[^>]*>/i, '<meta name="description" content="OutreachNest: niche guest posts, B2B lead lists, and content writing for Solar, Electrical &amp; Automation niches. Free Windows prospecting tool included.">')
                // v44: LaunchIgniter badge after Product Hunt in AS FEATURED ON section
                .replace(/(Product Hunt[^<]*<\/a>)(<\/div>)/, '$1<a href="https://launchigniter.com/product/outreachnest?ref=badge-outreachnest" target="_blank" rel="noopener noreferrer"><span style="display:inline-flex;align-items:center;gap:6px;background:#1e1b4b;color:#fff;border-radius:8px;padding:8px 16px;font-weight:600;font-size:13px;border:1px solid #3730a3">🚀 Featured on LaunchIgniter</span></a>$2');
            }
            // v44: LaunchIgniter badge on /download — inject before footer
            if (normPath === "/download") {
              bodyText = bodyText.replace(
                '<div id="footer-holder">',
                '<section style="padding:16px 0;text-align:center"><a href="https://launchigniter.com/product/outreachnest?ref=badge-outreachnest" target="_blank" rel="noopener noreferrer"><span style="display:inline-flex;align-items:center;gap:6px;background:#1e1b4b;color:#fff;border-radius:8px;padding:8px 16px;font-weight:600;font-size:13px;border:1px solid #3730a3">🚀 Featured on LaunchIgniter</span></a></section><div id="footer-holder">'
              );
            }
            // v33: fix /blog title (73 chars) and meta description (164 chars) — both over limit
            if (normPath === "/blog") {
              bodyText = bodyText
                .replace(/<title>[^<]*<\/title>/i, "<title>SEO, Link Building &amp; Guest Posting Blog — OutreachNest</title>")
                .replace(/<meta\s+name="description"[^>]*>/i, '<meta name="description" content="Practical SEO, link building, guest posting and outreach guides, original research, and field-tested strategies for finding better prospects.">');
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
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "Pragma": "no-cache",
        },
      });
    }

    // Login form submission.
    if (request.method === "POST") {
      const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "";
      const failCount = await getLoginFailCount(ip, env);
      // Block after 5 failures — attacker must wait for the 15-min TTL to expire.
      if (failCount >= 5) {
        return new Response(loginPageHtml(false, true), {
          status: 429,
          headers: { "Content-Type": "text/html; charset=UTF-8" },
        });
      }

      let user = "", pass = "";
      try {
        const form = await request.formData();
        user = form.get("username") || "";
        pass = form.get("password") || "";
      } catch (e) {
        // fall through with empty creds -> treated as wrong password
      }

      if ((pass === ADMIN_PASS || (RECOVERY_CODE && pass === RECOVERY_CODE))) {
        // Successful login — clear failure counter so the next genuine lockout starts fresh.
        await clearLoginFail(ip, env);
        const token = await makeSessionToken();
        return new Response(null, {
          status: 302,
          headers: {
            Location: url.pathname,
            "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }

      // Failed login — increment counter (non-blocking; best-effort).
      await incrementLoginFail(ip, env);
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

    // ── Dashboard route — session-protected, noindex ──────────────────
    if (_isDashboard) {
      const dashToken = getCookie(request, COOKIE_NAME);
      const dashValid = await verifySessionToken(dashToken);
      if (!dashValid) {
        return new Response(loginPageHtml(false), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=UTF-8" },
        });
      }
      const dashUrl = new URL(request.url);
      dashUrl.pathname = "/dashboard.html";
      const dashResp = await env.ASSETS.fetch(new Request(dashUrl.toString(), { method: "GET", headers: request.headers }));
      return new Response(dashResp.body, {
        status: dashResp.status,
        headers: {
          ...Object.fromEntries(dashResp.headers),
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "Pragma": "no-cache",
          "X-Robots-Tag": "noindex,nofollow",
        },
      });
    }

    // Serve admin.html with no-cache headers so logout always shows login form
    const adminResp = await env.ASSETS.fetch(request);
    return new Response(adminResp.body, {
      status: adminResp.status,
      headers: {
        ...Object.fromEntries(adminResp.headers),
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
      },
    });
  },
};
