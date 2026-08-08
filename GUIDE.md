# OutreachNest Website — Simple Guide

## Aapki website mein kya kya hai

- **index.html** — Home page
- **services.html** — Services page
- **niches.html** — Niches page
- **blog.html** — Blog list page
- **post.html** — Individual blog article page (khud kaam karta hai)
- **contact.html** — Contact page (form + email)
- **admin.html** — 📝 Blog Editor (naya blog banane ke liye — bina coding)
- **posts.js** — Yahan saare blogs store hote hain
- **style.css** — Design
- **main.js** — Shared nav/footer + email setting

---

## ✉️ Email badalna hai?

- **main.js** file kholo
- Sabse upar line hai: `const EMAIL = "queries@getoutreachnest.com";`
- Bas email badal do, save karo. Poori website mein update ho jayega.

---

## 📝 Naya blog kaise add karein (bina coding)

**Sabse aasan tareeqa:**

1. Browser mein **admin.html** file kholo (double-click)
2. Form bharo — title, category, summary, aur content (sections add karke)
3. **"Generate blog code"** dabao
4. Jo code aaye, uska **"Copy code"** dabao
5. **posts.js** file kholo
6. `window.POSTS = [` line ke **bilkul baad** paste karo
7. Save karo
8. Website dobara host pe upload karo (ya Netlify pe folder drag karo)

Bas! Naya blog live ho jayega.

---

## 🌐 Website LIVE kaise karein (Netlify — free)

1. **netlify.com** pe jao, free account banao
2. **"Add new site" → "Deploy manually"**
3. Poora website folder (saari files) **drag-drop** karo
4. Live ho jayegi — ek temporary link milega
5. Phir **"Domain settings"** mein apna domain `getoutreachnest.com` connect karo
6. Netlify jo DNS records de, woh Namecheap pe lagao (jaise pehle MX/SPF lagaye)

---

## Zaroori baat

- `admin.html` ko internet pe upload **mat** karna zaroori nahi — yeh sirf tumhare computer pe blog banane ke liye hai. Chaho to upload na karo, sirf apne paas rakho.
- Har blog **original** likhna — kisi aur ki website se copy mat karna (plagiarism issue banta hai).
