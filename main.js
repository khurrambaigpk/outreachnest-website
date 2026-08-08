// ===== SITE CONFIG — change here, updates everywhere =====
const EMAIL     = "queries@getoutreachnest.com";
const WHATSAPP  = "923006321406";   // international format, no +
const ADDRESS   = "Wapda Town Phase-2, Multan, Pakistan";
const DOWNLOAD_URL = "https://github.com/user-attachments/files/30851900/Setup_OutreachNestFinder_V12.19.7.zip";

// Prices — change here to update all pages
const PRICES = {
  trial:    { label: "Free Trial",  price: "FREE",  dur: "1 Day",    day: 1  },
  monthly:  { label: "Monthly",     price: "$15",   dur: "30 Days",  days: 30 },
  halfyear: { label: "6-Month",     price: "$29",   dur: "180 Days", days: 180},
  annual:   { label: "Annual",      price: "$49",   dur: "365 Days", days: 365},
};

// Payment details
const PAYMENT = {
  bank:     "Allied Bank",
  iban:     "PK48ABPA0010101916170010",
  account:  "10650010101916170010",
  branch:   "1065",
  jazzcash: "03317319333",
  name:     "Mariyam Riaz",
};

function buildNav(active){
  const links = [
    {href:"index.html",    label:"Home",     key:"home"},
    {href:"services.html", label:"Services", key:"services"},
    {href:"niches.html",   label:"Niches",   key:"niches"},
    {href:"download.html", label:"Download", key:"download"},
    {href:"blog.html",     label:"Blog",     key:"blog"},
  ];
  const items  = links.map(l=>`<a href="${l.href}" class="${active===l.key?'active':''}">${l.label}</a>`).join("");
  const mItems = links.map(l=>`<a href="${l.href}" class="${active===l.key?'active':''}">${l.label}</a>`).join("");
  return `<nav><div class="wrap nav-inner">
    <a href="index.html" class="logo"><span class="logo-mark"></span>OutreachNest</a>
    <div class="nav-links">${items}<a href="contact.html" class="nav-cta">Get in touch</a></div>
    <button class="menu-btn" id="menu-btn" aria-label="Menu"><span></span><span></span><span></span></button>
  </div>
  <div class="mobile-menu" id="mobile-menu">${mItems}<a href="contact.html" class="m-cta">Get in touch</a></div></nav>`;
}

function buildFooter(){
  return `<footer><div class="wrap">
    <div class="foot-grid">
      <div class="foot-col foot-about">
        <a href="index.html" class="logo"><span class="logo-mark"></span>OutreachNest</a>
        <p>Quality guest posts, verified leads, and content for solar, electrical, automation and electronics brands.</p>
        <div class="foot-social" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
          <a href="https://wa.me/${WHATSAPP}" target="_blank" style="display:inline-flex;align-items:center;gap:6px;background:#25d366;color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">💬 WhatsApp</a>
          <a href="mailto:${EMAIL}" style="display:inline-flex;align-items:center;gap:6px;background:var(--leaf-soft);color:var(--leaf-deep);padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">✉️ Email</a>
        </div>
      </div>
      <div class="foot-col"><h4>Services</h4>
        <a href="services.html">Guest posts</a>
        <a href="services.html">Lead lists</a>
        <a href="services.html">Content writing</a>
        <a href="download.html">Download Finder</a>
      </div>
      <div class="foot-col"><h4>Company</h4>
        <a href="niches.html">Niches</a>
        <a href="blog.html">Blog</a>
        <a href="contact.html">Contact</a>
      </div>
      <div class="foot-col"><h4>Contact</h4>
        <a href="mailto:${EMAIL}">${EMAIL}</a>
        <a href="https://wa.me/${WHATSAPP}" target="_blank">+${WHATSAPP}</a>
        <p style="font-size:13px;color:var(--muted);margin-top:8px;line-height:1.5">${ADDRESS}</p>
      </div>
    </div>
    <div class="foot-bottom">
      <p>© 2026 OutreachNest. All rights reserved.</p>
      <p>Real outreach for technical niches.</p>
    </div>
  </div></footer>`;
}

function injectShared(active){
  const nh = document.getElementById('nav-holder');
  const fh = document.getElementById('footer-holder');
  if(nh) nh.innerHTML = buildNav(active);
  if(fh) fh.innerHTML = buildFooter();
  document.querySelectorAll('[data-email]').forEach(el=>{
    el.textContent = EMAIL;
    if(el.tagName==='A') el.href = "mailto:"+EMAIL;
  });
  document.querySelectorAll('[data-whatsapp]').forEach(el=>{
    el.textContent = "+"+WHATSAPP;
    if(el.tagName==='A') el.href = "https://wa.me/"+WHATSAPP;
  });
  document.querySelectorAll('[data-download]').forEach(el=>{
    if(el.tagName==='A') el.href = DOWNLOAD_URL;
  });
  document.querySelectorAll('[data-price]').forEach(el=>{
    const key = el.getAttribute('data-price');
    const field = el.getAttribute('data-field') || 'price';
    if(PRICES[key]) el.textContent = PRICES[key][field] || '';
  });
}

function observe(){
  const io=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target);}});},{threshold:.12});
  document.querySelectorAll('.reveal:not(.in)').forEach(el=>io.observe(el));
}

window.addEventListener('DOMContentLoaded', ()=>{
  injectShared(window.PAGE_KEY || '');
  observe();
  const btn = document.getElementById('menu-btn');
  const menu = document.getElementById('mobile-menu');
  if(btn && menu){
    btn.addEventListener('click', ()=>{
      btn.classList.toggle('open');
      menu.classList.toggle('open');
    });
  }
});
