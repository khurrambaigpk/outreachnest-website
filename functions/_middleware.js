// Cloudflare Pages Function — runs on Cloudflare's edge server, never sent to the browser.
// Gates the admin Blog Editor with real HTTP Basic Auth *before* the page (and its
// client-side password check) is ever served, so the password can't be read via
// "View Source" the way it could before this file existed.
//
// To change the password later: edit ADMIN_USER / ADMIN_PASS below, keep this file's
// value in sync with admin.html's ADMIN_PASS constant if you want both layers to match,
// then re-upload this file the same way as any other website file.

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

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  if (url.pathname === "/admin" || url.pathname === "/admin.html") {
    const authHeader = request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Basic ")) {
      return unauthorized();
    }
    let decoded = "";
    try {
      decoded = atob(authHeader.slice(6));
    } catch (e) {
      return unauthorized();
    }
    const sep = decoded.indexOf(":");
    const user = sep === -1 ? decoded : decoded.slice(0, sep);
    const pass = sep === -1 ? "" : decoded.slice(sep + 1);
    if (user !== ADMIN_USER || pass !== ADMIN_PASS) {
      return unauthorized();
    }
  }

  return next();
}
