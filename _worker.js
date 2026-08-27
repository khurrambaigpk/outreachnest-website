// Cloudflare Worker entry point — runs on Cloudflare's edge, source never sent to visitors.
// wrangler.toml's `run_worker_first = ["/admin", "/admin.html"]` makes THIS script run for those
// two paths before Cloudflare's normal static-file serving kicks in; every other page on the site
// bypasses this file entirely and is served exactly as before, unchanged.
//
// This replaces the earlier attempt at functions/_middleware.js, which only works for the
// separate "Cloudflare Pages" product — this site deploys as a Worker with a static-assets
// binding instead, which needs this different file + a wrangler.toml `main` entry to run any
// custom code at all. functions/_middleware.js can be deleted later; it is inert either way.
//
// To change the password later: edit ADMIN_USER / ADMIN_PASS below, keep this in sync with
// admin.html's own ADMIN_PASS constant if you want both layers to match, then re-upload this
// file the same way as any other website file.

const ADMIN_USER = "mariyam";
const ADMIN_PASS = "Nest2026!Falcon91";

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="OutreachNest Admin", charset="UTF-8"',
      "Content-Type": "text/plain; charset=UTF-8",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/admin" || url.pathname === "/admin.html") {
      const authHeader = request.headers.get("Authorization") || "";
      let ok = false;
      if (authHeader.startsWith("Basic ")) {
        try {
          const decoded = atob(authHeader.slice(6));
          const sep = decoded.indexOf(":");
          const user = sep === -1 ? decoded : decoded.slice(0, sep);
          const pass = sep === -1 ? "" : decoded.slice(sep + 1);
          ok = user === ADMIN_USER && pass === ADMIN_PASS;
        } catch (e) {
          ok = false;
        }
      }
      if (!ok) {
        return unauthorized();
      }
    }

    // Every other request (and an authenticated /admin request) is served normally.
    return env.ASSETS.fetch(request);
  },
};
