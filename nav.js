/* OutreachNest — Shared Navbar
   Edit ONLY this file to change nav on all pages.
   Auto-sets active class based on current URL path.
*/
(function(){
  var path = window.location.pathname.replace(/\/$/, '') || '/';

  var links = [
    { href: '/',                label: 'Home' },
    { href: '/services',        label: 'Services' },
    { href: '/niches',          label: 'Niches' },
    { href: '/download',        label: 'Download' },
    { href: '/blog',            label: 'Blog' },
  ];

  var badgeLinks = [
    { href: '/marketplace', label: '🛒 Marketplace', style: 'background:#d1fae5;color:#065f46;border:1.5px solid #10b981;' },
    { href: '/market',      label: '📈 Market',      style: 'background:#1e3a5f;color:#60a5fa;border:1.5px solid #3b82f6;' },
    { href: '/solar-calculator', label: '☀️ Free Tools', style: 'background:#fef3c7;color:#92400e;border:1.5px solid #f59e0b;' },
  ];

  var badgeStyle = 'display:inline-flex;align-items:center;gap:4px;border-radius:20px;padding:3px 11px;font-weight:700;font-size:13px;text-decoration:none;';

  function isActive(href) {
    if (href === '/') return path === '/';
    return path === href || path.startsWith(href + '/');
  }

  // Desktop nav links
  var desktopLinks = links.map(function(l){
    return '<a href="' + l.href + '" class="' + (isActive(l.href) ? 'active' : '') + '">' + l.label + '</a>';
  }).join('');

  // Desktop badge links
  var desktopBadges = badgeLinks.map(function(l){
    var active = isActive(l.href) ? ' class="active"' : '';
    return '<a href="' + l.href + '" style="' + badgeStyle + l.style + '"' + active + '>' + l.label + '</a>';
  }).join('');

  // Mobile menu links
  var mobileLinks = links.map(function(l){
    return '<a href="' + l.href + '" class="' + (isActive(l.href) ? 'active' : '') + '">' + l.label + '</a>';
  }).join('');

  var mobileBadges = badgeLinks.map(function(l){
    var active = isActive(l.href) ? ' active' : '';
    return '<a href="' + l.href + '" class="' + active.trim() + '">' + l.label + '</a>';
  }).join('');

  var html =
    '<nav>' +
      '<div class="wrap nav-inner">' +
        '<a href="/" class="logo"><span class="logo-mark"></span>OutreachNest</a>' +
        '<div class="nav-links">' + desktopLinks + desktopBadges + '</div>' +
        '<a href="/contact" class="nav-cta">Get in touch</a>' +
        '<button class="menu-btn" id="menu-btn" aria-label="Menu"><span></span><span></span><span></span></button>' +
      '</div>' +
      '<div class="mobile-menu" id="mobile-menu">' + mobileLinks + mobileBadges + '<a href="/contact" class="m-cta">Get in touch</a></div>' +
      '<div class="nav-badges-row">' + desktopBadges + '</div>' +
    '</nav>';

  var holder = document.getElementById('nav-holder');
  if (holder) holder.innerHTML = html;

  // Mobile menu toggle
  document.addEventListener('DOMContentLoaded', function(){
    var btn = document.getElementById('menu-btn');
    var menu = document.getElementById('mobile-menu');
    if (btn && menu) {
      btn.addEventListener('click', function(){
        menu.classList.toggle('open');
        btn.classList.toggle('open');
      });
    }
  });
})();
