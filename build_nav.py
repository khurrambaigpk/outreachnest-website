#!/usr/bin/env python3
"""
OutreachNest — Nav Builder
==========================
Sirf YE file edit karo nav change karne ke liye, phir run karo:
  python3 build_nav.py

Ye script automatically:
  1. Sab HTML pages mein nav inject karti hai
  2. _worker.js mein CACHE_VERSION bump karti hai (Workers cache auto-clear)
"""

import re

# ═══════════════════════════════════════════════════════
#  NAV LINKS — yahan add/remove/change karo
# ═══════════════════════════════════════════════════════

PLAIN_LINKS = [
    ('/',           'Home'),
    ('/services',   'Services'),
    ('/niches',     'Niches'),
    ('/download',   'Download'),
    ('/blog',       'Blog'),
]

BADGE_LINKS = [
    ('/marketplace', '🛒 Marketplace', '#d1fae5', '#065f46', '#10b981'),
    ('/market',      '📈 Market',      '#1e3a5f', '#60a5fa', '#3b82f6'),
    ('/solar-calculator', '☀️ Free Tools', '#fef3c7', '#92400e', '#f59e0b'),
]

# ═══════════════════════════════════════════════════════
#  PAGES — yahan naya page add karo
# ═══════════════════════════════════════════════════════

PAGES = [
    ('index.html',            '/'),
    ('services.html',         '/services'),
    ('niches.html',           '/niches'),
    ('blog.html',             '/blog'),
    ('download.html',         '/download'),
    ('contact.html',          '/contact'),
    ('marketplace.html',      '/marketplace'),
    ('market.html',           '/market'),
    ('post.html',             '/blog'),
    ('solar-calculator.html', '/solar-calculator'),
]

# ═══════════════════════════════════════════════════════
#  BUILD — yahan mat chheyna
# ═══════════════════════════════════════════════════════

BADGE_STYLE = 'display:inline-flex;align-items:center;gap:3px;border-radius:20px;padding:4px 10px;font-weight:700;font-size:12.5px;text-decoration:none;white-space:nowrap;line-height:1;'

def make_nav(current_path):
    def active(href):
        if href == '/':
            return current_path == '/'
        return current_path == href or current_path.startswith(href + '/')

    desktop_plain = ''.join(
        f'<a href="{href}" class="{"active" if active(href) else ""}">{label}</a>'
        for href, label in PLAIN_LINKS
    )
    desktop_badges = ''.join(
        f'<a href="{href}" style="{BADGE_STYLE}background:{bg};color:{fg};border:1.5px solid {border};"'
        f'{" class=\"active\"" if active(href) else ""}>{label}</a>'
        for href, label, bg, fg, border in BADGE_LINKS
    )
    mobile_plain = ''.join(
        f'<a href="{href}" class="{"active" if active(href) else ""}">{label}</a>'
        for href, label in PLAIN_LINKS
    )
    mobile_badges = ''.join(
        f'<a href="{href}" class="{"active" if active(href) else ""}">{label}</a>'
        for href, label, bg, fg, border in BADGE_LINKS
    )

    return (
        '<div id="nav-holder"><nav>'
        '<div class="wrap nav-inner">'
        '<a href="/" class="logo"><span class="logo-mark"></span>OutreachNest</a>'
        f'<div class="nav-links">{desktop_plain}{desktop_badges}</div>'
        '<a href="/contact" class="nav-cta">Get in touch</a>'
        '<button class="menu-btn" id="menu-btn" aria-label="Menu"><span></span><span></span><span></span></button>'
        '</div>'
        f'<div class="mobile-menu" id="mobile-menu">{mobile_plain}{mobile_badges}'
        '<a href="/contact" class="m-cta">Get in touch</a></div>'
        f'<div class="nav-badges-row">{desktop_badges}</div>'
        '</nav></div>'
    )

def inject_nav(filename, current_path):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    new_nav = make_nav(current_path)

    updated = re.sub(
        r'<div id="nav-holder">.*?</nav>\s*</div>',
        new_nav,
        content,
        flags=re.DOTALL
    )
    # old nav.js format
    updated = re.sub(
        r'<div id="nav-holder"></div><script src="/nav\.js[^"]*"></script>',
        new_nav,
        updated,
        flags=re.DOTALL
    )

    if updated == content:
        # Either nav-holder not found, or nav was already identical
        if '<div id="nav-holder">' not in content:
            print(f'  ⚠️  {filename}: nav-holder not found — skipped')
        else:
            print(f'  ✓   {filename}: already up to date')
        return

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(updated)
    print(f'  ✅  {filename}')

def bump_cache_version():
    """_worker.js mein CACHE_VERSION auto-increment karo taake Workers cache clear ho."""
    worker_file = '_worker.js'
    with open(worker_file, 'r', encoding='utf-8') as f:
        content = f.read()

    match = re.search(r'const CACHE_VERSION = "v(\d+)"', content)
    if not match:
        print('  ⚠️  _worker.js: CACHE_VERSION not found — skipped')
        return

    old_v = int(match.group(1))
    new_v = old_v + 1
    updated = re.sub(
        r'const CACHE_VERSION = "v\d+"(;[^\n]*)?',
        f'const CACHE_VERSION = "v{new_v}"; // nav update',
        content,
        count=1
    )

    with open(worker_file, 'w', encoding='utf-8') as f:
        f.write(updated)
    print(f'  ✅  _worker.js: CACHE_VERSION v{old_v} → v{new_v} (Workers cache cleared)')

if __name__ == '__main__':
    print('\n1. Nav inject kar raha hoon sab pages mein...')
    for filename, path in PAGES:
        try:
            inject_nav(filename, path)
        except FileNotFoundError:
            print(f'  —   {filename}: file not found, skipped')

    print('\n2. Workers cache bust kar raha hoon...')
    bump_cache_version()

    print('\nDone! Ab sirf git add -A && git commit && git push karo.\n')
