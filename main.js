// ===== SITE CONFIG — change here, updates everywhere =====
const EMAIL = "queries@getoutreachnest.com";
const WHATSAPP = "923006321406"; // international format, no +
const ADDRESS = "Multan, Punjab Pakistan";
const DOWNLOAD_URL = "https://github.com/khurrambaigpk/Outreachnest-releases/releases/latest/download/Setup_OutreachNestFinder.exe";

// Prices — change here to update all pages
const PRICES = {
  trial: { label: "Free Trial", price: "FREE", dur: "7 Days", days: 7 },
  monthly: { label: "Monthly", price: "$15", dur: "30 Days", days: 30 },
  halfyear: { label: "6-Month", price: "$29", dur: "180 Days", days: 180},
  annual: { label: "Annual", price: "$49", dur: "365 Days", days: 365},
};

// Payment details
const PAYMENT = {
  bank: "Allied Bank",
  iban: "PK48ABPA0010101916170010",
  account: "10650010101916170010",
  branch: "1065",
  jazzcash: "03317319333",
  name: "Mariyam Riaz",
};

function buildFooter(){
  return `<footer><div class="wrap">
  <div class="foot-grid">
  <div class="foot-col foot-about">
  <a href="/" class="logo"><span class="logo-mark"></span>OutreachNest</a>
  <p>Quality guest posts, verified leads, and content for solar, electrical, automation and electronics brands.</p>
  <div class="foot-social" style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
  <a href="mailto:${EMAIL}" style="display:inline-flex;align-items:center;gap:6px;background:var(--leaf-soft);color:var(--leaf-deep);padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">✉️ Email</a>
  <a href="https://wa.me/${WHATSAPP}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#25d366;color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">💬 WhatsApp</a>
  <a href="https://facebook.com/OutreachNestFinder" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#1877F2;color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">📘 Facebook</a>
  <a href="https://x.com/MariyamRiagclo" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#000000;color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">🐦 Twitter/X</a>
  <a href="https://www.linkedin.com/in/mariyam-riaz-1b93a8431" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#0A66C2;color:#fff;padding:7px 14px;border-radius:8px;font-size:13px;font-weight:600">💼 LinkedIn</a>
  </div>
  </div>
  <div class="foot-col"><h4>Services</h4>
  <a href="/services">Guest posts</a>
  <a href="/services">Lead lists</a>
  <a href="/services">Content writing</a>
  <a href="/download">Download Finder</a>
  </div>
  <div class="foot-col"><h4>Company</h4>
  <a href="/niches">Niches</a>
  <a href="/blog">Blog</a>
  <a href="/contact">Contact</a>
  </div>
  <div class="foot-col"><h4>Contact</h4>
  <a href="mailto:${EMAIL}">${EMAIL}</a>
  <a href="https://wa.me/${WHATSAPP}" target="_blank" rel="noopener noreferrer">+${WHATSAPP}</a>
  <p style="font-size:13px;color:var(--muted);margin-top:8px;line-height:1.5">${ADDRESS}</p>
  </div>
  </div>
  <div class="foot-bottom">
  <p>© 2026 OutreachNest. All rights reserved.</p>
  <p>Real outreach for technical niches.</p>
  </div>
  </div></footer>`;
}

// Nav baked by build_nav.py — do NOT inject here
function injectShared(){
  const fh = document.getElementById('footer-holder');
  if(fh) fh.innerHTML = buildFooter();
  document.querySelectorAll('[data-email]').forEach(el=>{
    if(!el.children.length && !el.textContent.trim()) el.textContent = EMAIL;
    if(el.tagName==='A') el.href = "mailto:"+EMAIL;
  });
  document.querySelectorAll('[data-whatsapp]').forEach(el=>{
    if(!el.children.length && !el.textContent.trim()) el.textContent = "+"+WHATSAPP;
    if(el.tagName==='A') el.href = "https://wa.me/"+WHATSAPP;
  });
  document.querySelectorAll('[data-download]').forEach(el=>{
    if(el.tagName==='A') el.href = DOWNLOAD_URL;
    el.addEventListener('click', function(){
      try {
        if(window.ahrefs) window.ahrefs.track('download_click', { version: 'V13.1', type: 'free_trial' });
      } catch(e){}
      try {
        fetch('/api/track-download', { method: 'POST', keepalive: true,
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ event: 'download_click', version: 'V13.1', ts: Date.now() })
        }).catch(()=>{});
      } catch(e){}
    });
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
  injectShared();
  observe();
  const btn = document.getElementById('menu-btn');
  const menu = document.getElementById('mobile-menu');
  if(btn && menu){
    const badges = document.querySelector('.nav-badges-row');
    btn.addEventListener('click', ()=>{
      const isOpen = btn.classList.toggle('open');
      menu.classList.toggle('open');
      if(badges){ badges.style.display = isOpen ? 'none' : 'flex'; }
    });
  }
});
