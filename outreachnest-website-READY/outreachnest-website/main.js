// ===== Shared nav + footer injected on every page =====
const EMAIL = "queries@getoutreachnest.com"; // <-- change here once, updates everywhere

function buildNav(active){
  const links = [
    {href:"index.html", label:"Home", key:"home"},
    {href:"services.html", label:"Services", key:"services"},
    {href:"niches.html", label:"Niches", key:"niches"},
    {href:"blog.html", label:"Blog", key:"blog"},
  ];
  const items = links.map(l=>`<a href="${l.href}" class="${active===l.key?'active':''}">${l.label}</a>`).join("");
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
      </div>
      <div class="foot-col"><h4>Services</h4>
        <a href="services.html">Guest posts</a><a href="services.html">Lead lists</a><a href="services.html">Content writing</a></div>
      <div class="foot-col"><h4>Company</h4>
        <a href="niches.html">Niches</a><a href="blog.html">Blog</a><a href="contact.html">Contact</a></div>
      <div class="foot-col"><h4>Contact</h4>
        <a href="mailto:${EMAIL}">${EMAIL}</a></div>
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
  // fill any email placeholders
  document.querySelectorAll('[data-email]').forEach(el=>{
    el.textContent = EMAIL;
    if(el.tagName==='A') el.href = "mailto:"+EMAIL;
  });
}

// scroll reveal
function observe(){
  const io=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target);}});},{threshold:.12});
  document.querySelectorAll('.reveal:not(.in)').forEach(el=>io.observe(el));
}

window.addEventListener('DOMContentLoaded', ()=>{
  injectShared(window.PAGE_KEY || '');
  observe();
  // mobile menu toggle
  const btn = document.getElementById('menu-btn');
  const menu = document.getElementById('mobile-menu');
  if(btn && menu){
    btn.addEventListener('click', ()=>{
      btn.classList.toggle('open');
      menu.classList.toggle('open');
    });
  }
});
