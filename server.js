const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const https = require("https");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "nguyentanhuyvip10thanhngannek";
const SESSION_SECRET = process.env.SESSION_SECRET || "hft_session_secret_safe";
const STORE_PATH = path.join(__dirname, "keys.json");
const LOGO_PATH = path.join(__dirname, "logo.png");

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_REPO = process.env.GITHUB_REPO || "";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const GITHUB_DATA_PATH = process.env.GITHUB_DATA_PATH || "keys.json";
const PUBLIC_GITHUB_REPO = process.env.PUBLIC_GITHUB_REPO || GITHUB_REPO || "quocloy83-cpu/test";
const PUBLIC_GITHUB_BRANCH = process.env.PUBLIC_GITHUB_BRANCH || GITHUB_BRANCH || "main";
const PUBLIC_GITHUB_DATA_PATH = process.env.PUBLIC_GITHUB_DATA_PATH || GITHUB_DATA_PATH || "keys.json";

const FF_ANDROID_PACKAGE = process.env.FF_ANDROID_PACKAGE || "com.dts.freefireth";
const FFMAX_ANDROID_PACKAGE = process.env.FFMAX_ANDROID_PACKAGE || "com.dts.freefiremax";
const FF_IOS_SCHEME = process.env.FF_IOS_SCHEME || "freefire://";
const FFMAX_IOS_SCHEME = process.env.FFMAX_IOS_SCHEME || "freefiremax://";
const FF_IOS_APPID = process.env.FF_IOS_APPID || "1300146617";
const FFMAX_IOS_APPID = process.env.FFMAX_IOS_APPID || "1480516829";

const CONTACTS = {
  facebook: "https://www.facebook.com/share/1JHonUUaCA/?mibextid=wwXIfr",
  zalo: "https://zalo.me/0818249250",
  tiktok: "https://www.tiktok.com/@huyftsupport?_r=1&_t=ZS-94olc9q74ba"
};

const DEFAULT_FEATURES = [
  "AimLock",
  "Fix Rung",
  "Nhẹ Tâm",
  "Bám Mũ",
  "Tâm Bám"
];

const rateMap = new Map();
let memoryStore = null;
let publicStoreCache = { at: 0, data: null };

app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use((req, res, next) => {
  const ip = ((req.headers["x-forwarded-for"] || "").toString().split(",")[0] || req.socket.remoteAddress || "unknown").trim();
  const now = Date.now();
  const windowMs = 12_000;
  const limit = 80;
  const arr = (rateMap.get(ip) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  rateMap.set(ip, arr);
  if (arr.length > limit) return res.status(429).json({ ok: false, msg: "Thao tác quá nhanh" });
  next();
});

function isAdmin(req) {
  return (req.query.admin || "") === ADMIN_PASSWORD;
}

function loadLocalStore() {
  try {
    if (!fs.existsSync(STORE_PATH)) return {};
    const raw = fs.readFileSync(STORE_PATH, "utf8") || "{}";
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveLocalStore(store) {
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), "utf8");
}

memoryStore = loadLocalStore();

function normalizeKeyItem(item) {
  if (!item || typeof item !== "object") return null;
  const now = Date.now();
  const devices = Array.isArray(item.devices) ? item.devices.filter(Boolean) : [];
  const totalDevices = Math.max(devices.length, Number(item.totalDevices || item.maxDevices || item.limit || 1));
  let usesLeft = Number(item.usesLeft);
  if (!Number.isFinite(usesLeft)) {
    if (Number.isFinite(Number(item.uses))) usesLeft = Number(item.uses);
    else usesLeft = Math.max(0, totalDevices - devices.length);
  }
  const out = {
    devices,
    totalDevices,
    usesLeft: Math.max(0, usesLeft),
    createdAt: Number(item.createdAt || now),
    expireAt: Number(item.expireAt || 0),
    note: String(item.note || ""),
    source: String(item.source || "admin")
  };
  return out;
}

function normalizeStore(store) {
  const fixed = {};
  for (const [key, value] of Object.entries(store || {})) {
    const norm = normalizeKeyItem(value);
    if (norm) fixed[String(key).trim()] = norm;
  }
  return fixed;
}

memoryStore = normalizeStore(memoryStore);
saveLocalStore(memoryStore);

function genKey() {
  const a = Math.random().toString(36).slice(2, 6).toUpperCase();
  const b = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `ATH-${a}-${b}`;
}

function signText(text) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(text).digest("hex");
}

function createSessionToken(key, device, expireAt) {
  const issuedAt = Date.now();
  const payload = `${key}|${device}|${expireAt}|${issuedAt}`;
  const sig = signText(payload);
  return Buffer.from(`${payload}|${sig}`, "utf8").toString("base64url");
}

function verifySessionToken(token) {
  try {
    const raw = Buffer.from(token, "base64url").toString("utf8");
    const parts = raw.split("|");
    if (parts.length !== 5) return null;
    const [key, device, expireAt, issuedAt, sig] = parts;
    const payload = `${key}|${device}|${expireAt}|${issuedAt}`;
    if (sig !== signText(payload)) return null;
    return { key, device, expireAt: Number(expireAt), issuedAt: Number(issuedAt) };
  } catch {
    return null;
  }
}

function githubRequest(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.github.com",
        path: apiPath,
        method,
        headers: {
          "User-Agent": "hft-panel",
          ...(GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {}),
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          ...(body ? { "Content-Type": "application/json" } : {})
        }
      },
      (res) => {
        let data = "";
        res.on("data", (d) => (data += d));
        res.on("end", () => {
          let parsed;
          try { parsed = JSON.parse(data || "{}"); } catch { parsed = data; }
          const ok = res.statusCode >= 200 && res.statusCode < 300;
          if (!ok) {
            const err = new Error((parsed && parsed.message) || `GitHub ${res.statusCode}`);
            err.statusCode = res.statusCode;
            err.payload = parsed;
            return reject(err);
          }
          resolve(parsed);
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function rawGithubGet(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "hft-panel" } }, (res) => {
        let data = "";
        res.on("data", (d) => (data += d));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) return resolve(data);
          const err = new Error(`Raw GitHub ${res.statusCode}`);
          err.statusCode = res.statusCode;
          reject(err);
        });
      })
      .on("error", reject);
  });
}

function hasGithubWrite() {
  return Boolean(GITHUB_TOKEN && GITHUB_REPO && GITHUB_DATA_PATH);
}

async function readGithubStore() {
  const apiPath = `/repos/${encodeURIComponent(GITHUB_REPO).replace(/%2F/g, "/")}/contents/${encodeURIComponent(GITHUB_DATA_PATH).replace(/%2F/g, "/")}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
  try {
    const file = await githubRequest("GET", apiPath);
    const content = Buffer.from(file.content || "", "base64").toString("utf8") || "{}";
    const parsed = JSON.parse(content);
    return { store: normalizeStore(parsed), sha: file.sha || null };
  } catch (err) {
    if (err.statusCode === 404) {
      return { store: {}, sha: null };
    }
    throw err;
  }
}

async function writeGithubStore(store) {
  if (!hasGithubWrite()) throw new Error("github_write_not_configured");
  const current = await readGithubStore();
  const payload = {
    message: `Update keys ${new Date().toISOString()}`,
    content: Buffer.from(JSON.stringify(normalizeStore(store), null, 2), "utf8").toString("base64"),
    branch: GITHUB_BRANCH
  };
  if (current.sha) payload.sha = current.sha;
  const apiPath = `/repos/${encodeURIComponent(GITHUB_REPO).replace(/%2F/g, "/")}/contents/${encodeURIComponent(GITHUB_DATA_PATH).replace(/%2F/g, "/")}`;
  await githubRequest("PUT", apiPath, payload);
}

async function readPublicGithubStore() {
  const now = Date.now();
  if (publicStoreCache.data && now - publicStoreCache.at < 7000) return publicStoreCache.data;
  if (!PUBLIC_GITHUB_REPO) return null;
  const rawUrl = `https://raw.githubusercontent.com/${PUBLIC_GITHUB_REPO}/${PUBLIC_GITHUB_BRANCH}/${PUBLIC_GITHUB_DATA_PATH}`;
  try {
    const text = await rawGithubGet(rawUrl);
    const parsed = normalizeStore(JSON.parse(text || "{}"));
    publicStoreCache = { at: now, data: parsed };
    return parsed;
  } catch {
    return null;
  }
}

async function readStore() {
  if (hasGithubWrite()) {
    try {
      const gh = await readGithubStore();
      memoryStore = normalizeStore(gh.store || {});
      saveLocalStore(memoryStore);
      return { store: memoryStore, mode: "github" };
    } catch {
      // fallback further below
    }
  }
  const publicStore = await readPublicGithubStore();
  if (publicStore && Object.keys(publicStore).length) {
    return { store: publicStore, mode: "github-public" };
  }
  memoryStore = normalizeStore(loadLocalStore());
  return { store: memoryStore, mode: "local" };
}

async function persistStore(store) {
  const fixed = normalizeStore(store);
  memoryStore = fixed;
  saveLocalStore(fixed);
  if (hasGithubWrite()) {
    await writeGithubStore(fixed);
    publicStoreCache = { at: Date.now(), data: fixed };
    return "github";
  }
  return "local";
}

function formatVNTime(ms) {
  return new Date(ms).toLocaleString("vi-VN");
}

function msToViDuration(ms) {
  if (ms <= 0) return "0 phút";
  const totalMinutes = Math.floor(ms / 60000);
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;
  const parts = [];
  if (days) parts.push(`${days} ngày`);
  if (hours) parts.push(`${hours} giờ`);
  if (minutes || !parts.length) parts.push(`${minutes} phút`);
  return parts.join(" ");
}

function renderLogo(size = 82, radius = 24) {
  if (fs.existsSync(LOGO_PATH)) {
    return `<img src="/logo.png" alt="logo" style="width:${size}px;height:${size}px;object-fit:cover;border-radius:${radius}px;display:block">`;
  }
  return `<div style="width:${size}px;height:${size}px;border-radius:${radius}px;background:linear-gradient(135deg,#9a6dff,#ff6ac5);display:grid;place-items:center;font-size:${Math.round(size*0.34)}px;font-weight:700">HFT</div>`;
}

function appStyles() {
  return `
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Alata&display=swap');
    *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
    html{-webkit-text-size-adjust:100%}
    :root{
      --bg1:#06040c;--bg2:#12081d;--bg3:#1a0d28;
      --violet:#a977ff;--violet2:#cf8fff;--pink:#ff6dc5;--gold:#ffd36a;
      --text:#f7f2ff;--muted:#c8badc;--line:rgba(255,255,255,.08);
      --glass:rgba(255,255,255,.06);--glass2:rgba(255,255,255,.04);
      --ok:#9cffc8;--warn:#ffd883;--danger:#ff86ac;
      --shadow:0 22px 70px rgba(0,0,0,.45), 0 0 0 1px rgba(255,255,255,.06) inset;
    }
    body{
      margin:0;min-height:100vh;font-family:'Alata',system-ui,sans-serif;color:var(--text);overflow-x:hidden;
      background:
        radial-gradient(circle at 12% 12%, rgba(169,119,255,.22), transparent 18%),
        radial-gradient(circle at 88% 16%, rgba(255,109,197,.18), transparent 18%),
        radial-gradient(circle at 50% 100%, rgba(255,211,106,.08), transparent 26%),
        linear-gradient(145deg,var(--bg1),var(--bg2) 48%,var(--bg3));
    }
    body::before{content:'';position:fixed;inset:-30%;pointer-events:none;opacity:.18;background:
      radial-gradient(circle, rgba(255,255,255,.045) 1px, transparent 1.4px);
      background-size:16px 16px;animation:starMove 26s linear infinite}
    body::after{content:'';position:fixed;inset:0;pointer-events:none;background:
      linear-gradient(transparent, rgba(255,255,255,.02), transparent);
      background-size:100% 4px;opacity:.25;animation:scanMove 12s linear infinite}
    @keyframes starMove{from{transform:translateY(0)}to{transform:translateY(80px)}}
    @keyframes scanMove{from{transform:translateY(-100%)}to{transform:translateY(100%)}}
    @keyframes pulseGlow{0%,100%{box-shadow:0 0 0 rgba(0,0,0,0),0 10px 28px rgba(169,119,255,.18)}50%{box-shadow:0 0 32px rgba(255,109,197,.16),0 18px 36px rgba(169,119,255,.22)}}
    @keyframes floatY{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
    @keyframes spin{to{transform:rotate(360deg)}}
    @keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
    .page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px}
    .shell{width:min(960px,100%);position:relative;animation:fadeUp .55s ease}
    .shell::before,.shell::after{content:'';position:absolute;inset:-2px;border-radius:34px;pointer-events:none}
    .shell::before{background:linear-gradient(135deg,rgba(169,119,255,.35),rgba(255,109,197,.14),rgba(255,211,106,.20));filter:blur(18px);opacity:.45}
    .card{position:relative;backdrop-filter:blur(16px);background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.04));border:1px solid rgba(255,255,255,.08);border-radius:32px;box-shadow:var(--shadow);overflow:hidden}
    .card::before{content:'';position:absolute;inset:0;background:linear-gradient(120deg, rgba(255,255,255,.08), transparent 18%, transparent 82%, rgba(255,255,255,.04));pointer-events:none}
    .inner{padding:28px}
    .hero{display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center;padding:8px 0 20px}
    .logoWrap{position:relative;display:grid;place-items:center;width:108px;height:108px;border-radius:28px;background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.03));border:1px solid rgba(255,255,255,.08);animation:floatY 4.2s ease-in-out infinite,pulseGlow 3.8s ease-in-out infinite}
    .logoWrap::after{content:'';position:absolute;inset:-9px;border-radius:34px;border:1px solid rgba(255,211,106,.18)}
    h1,h2,h3,p{margin:0}
    .title{font-size:clamp(26px,4vw,42px);letter-spacing:.4px}
    .sub{color:var(--muted);font-size:14px;max-width:680px;line-height:1.65}
    .line{height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.12),transparent);margin:18px 0}
    .form{display:grid;gap:14px}
    .field{position:relative}
    .input,.select,.btn,.chip,.toggle,.gameBtn{font-family:'Alata',system-ui,sans-serif}
    .input,.select{width:100%;border-radius:18px;border:1px solid rgba(255,255,255,.10);padding:16px 16px;background:rgba(255,255,255,.045);color:var(--text);outline:none;transition:.22s ease}
    .input::placeholder{color:#c8b6df}
    .input:focus,.select:focus{border-color:rgba(255,211,106,.46);box-shadow:0 0 0 4px rgba(255,211,106,.08)}
    .btn{border:none;outline:none;cursor:pointer;color:#160d1f;padding:15px 18px;border-radius:18px;font-size:15px;background:linear-gradient(135deg,var(--gold),#ffb64c);font-weight:700;box-shadow:0 10px 24px rgba(255,184,76,.24);transition:.2s ease}
    .btn:active{transform:translateY(1px) scale(.995)}
    .btn.ghost{background:rgba(255,255,255,.06);color:var(--text);box-shadow:none;border:1px solid rgba(255,255,255,.10)}
    .btn.violet{background:linear-gradient(135deg,var(--violet),var(--pink));color:#fff;box-shadow:0 10px 24px rgba(169,119,255,.24)}
    .btn.row{display:flex;align-items:center;justify-content:center;gap:10px}
    .muted{color:var(--muted)}
    .small{font-size:13px}
    .loginGrid{display:grid;grid-template-columns:1.15fr .85fr;gap:18px}
    .panelGrid{display:grid;grid-template-columns:1fr 320px;gap:18px}
    .section{padding:18px;border-radius:24px;background:linear-gradient(180deg,rgba(255,255,255,.045),rgba(255,255,255,.03));border:1px solid rgba(255,255,255,.07)}
    .chips{display:flex;flex-wrap:wrap;gap:10px}
    .chip{padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.09);color:var(--muted);font-size:13px}
    .statusDot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;background:#6fffb3;box-shadow:0 0 14px rgba(111,255,179,.7)}
    .toggleList{display:grid;gap:12px}
    .toggleItem{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 16px;border-radius:20px;background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.07)}
    .toggleMeta{display:flex;flex-direction:column;gap:4px}
    .toggleMeta strong{font-size:15px}
    .toggleMeta span{font-size:12px;color:var(--muted)}
    .toggle{position:relative;width:68px;height:38px;border-radius:999px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.10);cursor:pointer;transition:.24s ease}
    .toggle::before{content:'';position:absolute;top:4px;left:4px;width:28px;height:28px;border-radius:50%;background:#fff;box-shadow:0 6px 16px rgba(0,0,0,.22);transition:.24s ease}
    .toggle.active{background:linear-gradient(135deg,var(--violet),var(--pink));box-shadow:0 0 0 4px rgba(169,119,255,.12)}
    .toggle.active::before{left:34px;background:#fff8e3}
    .console{height:240px;border-radius:20px;background:#08070e;border:1px solid rgba(255,255,255,.08);padding:14px;overflow:auto;font-family:ui-monospace,SFMono-Regular,monospace;font-size:12px;line-height:1.6;color:#bfe5ff;box-shadow:inset 0 0 0 1px rgba(255,255,255,.03)}
    .console .ok{color:var(--ok)} .console .warn{color:var(--warn)} .console .err{color:var(--danger)}
    .gameWrap{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .gameBtn{position:relative;display:flex;align-items:center;justify-content:center;gap:10px;padding:16px;border-radius:18px;border:1px solid rgba(255,255,255,.08);background:linear-gradient(135deg,rgba(169,119,255,.18),rgba(255,109,197,.14));color:#fff;cursor:pointer;overflow:hidden}
    .gameBtn::after{content:'';position:absolute;inset:-40%;background:linear-gradient(120deg,transparent,rgba(255,255,255,.16),transparent);transform:translateX(-120%);transition:transform .7s ease}
    .gameBtn:active::after,.gameBtn:hover::after{transform:translateX(120%)}
    .statBox{padding:16px;border-radius:18px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.07)}
    .adminTable{width:100%;border-collapse:collapse;font-size:13px}
    .adminTable th,.adminTable td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left}
    .adminTable th{color:#dbc9ef;font-weight:600}
    .loading{position:fixed;inset:0;display:grid;place-items:center;background:radial-gradient(circle at center, rgba(24,10,40,.92), rgba(3,2,8,.98));z-index:9999;transition:opacity .55s ease, visibility .55s ease}
    .loading.hide{opacity:0;visibility:hidden}
    .loadingCard{display:flex;flex-direction:column;align-items:center;gap:18px}
    .ring{width:120px;height:120px;border-radius:50%;position:relative;display:grid;place-items:center}
    .ring::before,.ring::after{content:'';position:absolute;inset:0;border-radius:50%}
    .ring::before{border:2px solid rgba(255,255,255,.08)}
    .ring::after{border-top:3px solid var(--gold);border-right:3px solid var(--pink);animation:spin 1.1s linear infinite}
    .contactBar{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}
    .contact{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.08);color:#fff;text-decoration:none;font-size:13px}
    .badge{padding:6px 10px;border-radius:999px;background:rgba(255,211,106,.12);color:#ffe7aa;font-size:12px;border:1px solid rgba(255,211,106,.18)}
    .topRow{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
    .keyStatus{padding:14px 16px;border-radius:18px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08)}
    .empty{padding:20px;text-align:center;color:var(--muted)}
    @media (max-width: 860px){.loginGrid,.panelGrid{grid-template-columns:1fr}.gameWrap{grid-template-columns:1fr}.shell{width:100%}}
  </style>`;
}

function loadingOverlay() {
  return `
  <div class="loading" id="loadingScreen">
    <div class="loadingCard">
      <div class="ring"><div class="logoWrap" style="animation:none;width:90px;height:90px">${renderLogo(74, 22)}</div></div>
      <div style="text-align:center">
        <h2 style="margin:0 0 6px">AimTrickHead</h2>
        <div class="muted small">Đang nạp giao diện VIP...</div>
      </div>
    </div>
  </div>`;
}

function commonScript() {
  return `
  <script>
    const $ = (s) => document.querySelector(s);
    const $$ = (s) => Array.from(document.querySelectorAll(s));
    window.addEventListener('load', () => setTimeout(() => $('#loadingScreen')?.classList.add('hide'), 900));
    function copyText(t){navigator.clipboard?.writeText(t||'');}
    function addConsoleLine(text, cls=''){ const c=$('#console'); if(!c) return; const div=document.createElement('div'); if(cls) div.className=cls; div.textContent='> '+text; c.appendChild(div); c.scrollTop=c.scrollHeight; }
    function simulateTask(name){
      addConsoleLine('Khởi chạy module '+name+' ...','warn');
      setTimeout(()=>addConsoleLine('Inject params: '+name+' OK','');, 260);
      setTimeout(()=>addConsoleLine('Sync profile: '+name+' ổn định','');, 520);
      setTimeout(()=>addConsoleLine(name+' hoạt động', 'ok'), 880);
    }
    function bindToggles(){
      $$('.toggle').forEach(el=>{
        el.addEventListener('click',()=>{
          el.classList.toggle('active');
          const name=el.dataset.name||'Module';
          simulateTask(name + (el.classList.contains('active') ? ' ON' : ' OFF'));
        });
      });
    }
    function isAndroid(){return /Android/i.test(navigator.userAgent)}
    function isIOS(){return /iPhone|iPad|iPod/i.test(navigator.userAgent)}
    function openGame(cfg){
      let hidden=false, left=false;
      const markHidden=()=>{hidden=true};
      const markLeave=()=>{left=true};
      document.addEventListener('visibilitychange', markHidden, {once:true});
      window.addEventListener('pagehide', markLeave, {once:true});
      window.addEventListener('blur', markHidden, {once:true});
      if(isAndroid()){
        window.location.href = 'intent://#Intent;package=' + cfg.android + ';end';
      }else if(isIOS()){
        window.location.href = cfg.ios;
      }else{
        window.location.href = cfg.web;
        return;
      }
      setTimeout(()=>{
        if(!hidden && !left && document.visibilityState === 'visible'){
          window.location.href = cfg.store;
        }
      }, 1800);
    }
    function openFF(){ openGame({ android: '${FF_ANDROID_PACKAGE}', ios: '${FF_IOS_SCHEME}', store: 'https://apps.apple.com/app/id${FF_IOS_APPID}', web: 'https://ff.garena.com/vn/' }); }
    function openFFMax(){ openGame({ android: '${FFMAX_ANDROID_PACKAGE}', ios: '${FFMAX_IOS_SCHEME}', store: 'https://apps.apple.com/app/id${FFMAX_IOS_APPID}', web: 'https://ff.garena.com/vn/' }); }
    bindToggles();
  </script>`;
}

function loginPage(message = "") {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AimTrickHead Login</title>${appStyles()}</head><body>${loadingOverlay()}<div class="page"><div class="shell"><div class="card"><div class="inner"><div class="hero"><div class="logoWrap">${renderLogo(82,24)}</div><span class="badge">SERVER KEY • VIP PANEL</span><h1 class="title">AimTrickHead</h1><p class="sub">Đăng nhập bằng key để mở panel. Hỗ trợ thêm key thủ công trong <b>keys.json</b> trên GitHub và key tạo từ admin nếu bạn có cấu hình GitHub ghi dữ liệu.</p></div><div class="loginGrid"><div class="section"><div class="topRow"><h3>Đăng nhập</h3><span class="small muted"><span class="statusDot"></span>${hasGithubWrite() ? 'Cloud mode hoạt động' : 'Manual/GitHub public mode'}</span></div><div class="line"></div><form class="form" method="post" action="/login"><input class="input" type="text" name="key" placeholder="Nhập key của bạn" autocomplete="off" required><input class="input" type="text" name="device" placeholder="Mã thiết bị hoặc tên máy" autocomplete="off" required><button class="btn violet" type="submit">Vào Panel</button>${message ? `<div class="small" style="color:var(--danger)">${message}</div>` : ''}</form><div class="line"></div><div class="contactBar"><a class="contact" href="${CONTACTS.facebook}" target="_blank">Facebook</a><a class="contact" href="${CONTACTS.zalo}" target="_blank">Zalo</a><a class="contact" href="${CONTACTS.tiktok}" target="_blank">TikTok</a></div></div><div class="section"><h3>Điểm nổi bật</h3><div class="line"></div><div class="chips"><span class="chip">UI động</span><span class="chip">Font Alata</span><span class="chip">FF / FF MAX</span><span class="chip">Tâm Bám mới</span><span class="chip">Key thủ công GitHub</span></div><div class="line"></div><div class="console" id="console"><div class="ok">> Hệ thống sẵn sàng.</div><div>> Chờ xác thực key...</div></div></div></div></div></div></div></div>${commonScript()}<script>setTimeout(()=>addConsoleLine('Quét trạng thái server key ...','warn'),500);setTimeout(()=>addConsoleLine('Nếu key nằm trên GitHub, panel sẽ nhận sau khi đồng bộ.','ok'),980);</script></body></html>`;
}

function adminPage(msg = "") {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Key</title>${appStyles()}</head><body>${loadingOverlay()}<div class="page"><div class="shell"><div class="card"><div class="inner"><div class="hero"><div class="logoWrap">${renderLogo(82,24)}</div><span class="badge">ADMIN CREATE KEY</span><h1 class="title">Bảng Điều Khiển Key</h1><p class="sub">Giữ hệ thống tạo key như cũ. Khi có <b>GITHUB_TOKEN</b>, key tạo từ admin sẽ lưu bền. Khi không có, bạn vẫn có thể thêm key thủ công trong <b>keys.json</b> trên GitHub public để dùng đăng nhập.</p></div><div class="panelGrid"><div class="section"><div class="topRow"><h3>Tạo Key</h3><span class="small muted">Mode: ${hasGithubWrite() ? 'Ghi GitHub' : 'Local + đọc GitHub public'}</span></div><div class="line"></div><div class="form"><input class="input" id="adminKey" type="password" placeholder="Nhập admin password"><input class="input" id="customKey" type="text" placeholder="Tên key tùy chỉnh hoặc bỏ trống để random"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><input class="input" id="maxDevices" type="number" min="1" value="1" placeholder="Số thiết bị"><input class="input" id="days" type="number" min="0" value="30" placeholder="Số ngày"></div><button class="btn violet row" onclick="taoKey()">Tạo Key</button>${msg ? `<div class="small" style="color:var(--danger)">${msg}</div>` : ''}<div class="small muted">Không có env GitHub thì key tạo từ admin chỉ lưu local. Key thêm tay trong <b>keys.json</b> trên GitHub public vẫn đọc được.</div></div><div class="line"></div><div class="topRow"><h3>Danh sách key</h3><button class="btn ghost" onclick="taiDanhSach()">Tải lại</button></div><div id="keyList" class="empty">Đang tải danh sách...</div></div><div class="section"><h3>Nhật ký</h3><div class="line"></div><div class="console" id="console"><div>> Chờ thao tác admin...</div></div><div class="line"></div><div class="small muted">Route admin: /admin • Route panel: /panel</div></div></div></div></div></div></div>${commonScript()}<script>
    async function taoKey(){
      const admin = $('#adminKey').value.trim();
      const customKey = $('#customKey').value.trim();
      const maxDevices = Number($('#maxDevices').value || 1);
      const days = Number($('#days').value || 0);
      if(!admin){ alert('Nhập admin password'); return; }
      addConsoleLine('Gửi yêu cầu tạo key...','warn');
      try{
        const res = await fetch('/api/create?admin='+encodeURIComponent(admin), { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ customKey, totalDevices:maxDevices, days }) });
        const data = await res.json();
        if(!res.ok){ addConsoleLine(data.msg || data.error || 'Không tạo được key','err'); return alert(data.msg || data.error || 'Không tạo được key'); }
        addConsoleLine('Tạo key thành công: '+data.key,'ok');
        alert('Tạo key thành công: '+data.key + (data.mode ? ' ('+data.mode+')' : ''));
        $('#customKey').value='';
        taiDanhSach();
      }catch(e){ addConsoleLine('Lỗi kết nối server','err'); alert('Lỗi kết nối server'); }
    }
    async function taiDanhSach(){
      addConsoleLine('Đồng bộ danh sách key...');
      try{
        const admin = $('#adminKey').value.trim();
        const res = await fetch('/api/list?admin='+encodeURIComponent(admin));
        const data = await res.json();
        if(!res.ok) throw new Error(data.msg || 'Không tải được');
        const rows = data.items || [];
        if(!rows.length){ $('#keyList').innerHTML='<div class="empty">Chưa có key nào.</div>'; return; }
        $('#keyList').innerHTML = '<div style="overflow:auto"><table class="adminTable"><thead><tr><th>Key</th><th>Thiết bị</th><th>Ngày hết hạn</th><th>Nguồn</th><th></th></tr></thead><tbody>' + rows.map(function(it){ return '<tr><td>' + it.key + '</td><td>' + it.devices + '/' + it.totalDevices + '</td><td>' + it.expireText + '</td><td>' + it.source + '</td><td><button class="btn ghost" style="padding:8px 12px;border-radius:12px" onclick="xoaKey(\'' + it.key + '\')">Xóa</button></td></tr>'; }).join('') + '</tbody></table></div>';
        addConsoleLine('Danh sách key đã tải xong.','ok');
      }catch(e){ $('#keyList').innerHTML='<div class="empty">Không tải được danh sách key.</div>'; addConsoleLine('Không tải được danh sách key','err'); }
    }
    async function xoaKey(key){
      const admin = $('#adminKey').value.trim();
      if(!confirm('Xóa key '+key+' ?')) return;
      try{
        const res = await fetch('/api/delete?admin='+encodeURIComponent(admin), { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ key }) });
        const data = await res.json();
        if(!res.ok) throw new Error(data.msg || 'Xóa thất bại');
        addConsoleLine('Đã xóa key: '+key,'ok');
        taiDanhSach();
      }catch(e){ alert(e.message || 'Xóa thất bại'); addConsoleLine('Xóa key thất bại','err'); }
    }
    setTimeout(taiDanhSach, 1200);
  </script></body></html>`;
}

function panelPage(session, item, mode) {
  const expireText = item.expireAt ? formatVNTime(item.expireAt) : "Vĩnh viễn";
  const leftMs = item.expireAt ? Math.max(0, item.expireAt - Date.now()) : 0;
  const remain = item.expireAt ? msToViDuration(leftMs) : "Không giới hạn";
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Panel</title>${appStyles()}</head><body>${loadingOverlay()}<div class="page"><div class="shell"><div class="card"><div class="inner"><div class="hero"><div class="logoWrap">${renderLogo(84,24)}</div><span class="badge">PANEL VIP • ${mode.toUpperCase()}</span><h1 class="title">AimTrickHead Panel</h1><p class="sub">Giữ màu chủ đạo, logo cũ và nâng cấp giao diện mượt hơn. Bật chức năng sẽ hiện log chạy code. Có thể vào game ngay bằng nút riêng.</p></div><div class="panelGrid"><div class="section"><div class="topRow"><h3>Chức năng chính</h3><span class="small muted">Key: ${session.key}</span></div><div class="line"></div><div class="toggleList">${DEFAULT_FEATURES.map((name) => `<div class="toggleItem"><div class="toggleMeta"><strong>${name}</strong><span>Tinh chỉnh theo profile hiện tại</span></div><button class="toggle" data-name="${name}"></button></div>`).join('')}</div><div class="line"></div><div class="topRow"><h3>Vào Game</h3><span class="small muted">Android / iPhone</span></div><div class="gameWrap" style="margin-top:12px"><button class="gameBtn" onclick="openFF()">Mở Free Fire</button><button class="gameBtn" onclick="openFFMax()">Mở FF MAX</button></div><div class="line"></div><div class="topRow"><h3>Console</h3><button class="btn ghost" onclick="copyText(document.getElementById('console').innerText)">Copy log</button></div><div class="console" id="console"><div>> Kết nối session thành công.</div><div class="ok">> Thiết bị hợp lệ: ${session.device}</div></div></div><div class="section"><div class="topRow"><h3>Trạng thái key</h3><span class="small muted"><span class="statusDot"></span>Online</span></div><div class="line"></div><div class="statBox"><div class="small muted">Ngày hết hạn</div><div>${expireText}</div></div><div style="height:12px"></div><div class="statBox"><div class="small muted">Thời gian còn lại</div><div>${remain}</div></div><div style="height:12px"></div><div class="statBox"><div class="small muted">Thiết bị đã dùng</div><div>${item.devices.length}/${item.totalDevices}</div></div><div style="height:12px"></div><div class="statBox"><div class="small muted">Nguồn dữ liệu</div><div>${mode}</div></div><div class="line"></div><div class="form"><a class="btn ghost row" href="${CONTACTS.facebook}" target="_blank">Facebook</a><a class="btn ghost row" href="${CONTACTS.zalo}" target="_blank">Zalo</a><a class="btn ghost row" href="${CONTACTS.tiktok}" target="_blank">TikTok</a><a class="btn violet row" href="/logout">Đăng xuất</a></div></div></div></div></div></div></div>${commonScript()}<script>setTimeout(()=>addConsoleLine('Nạp profile key...','warn'),450);setTimeout(()=>addConsoleLine('Module tối ưu đã sẵn sàng.','ok'),900);</script></body></html>`;
}

app.get(["/", "/login"], (req, res) => res.send(loginPage()));
app.get("/admin", (req, res) => res.send(adminPage()));

app.post("/login", async (req, res) => {
  try {
    const key = String(req.body.key || "").trim();
    const device = String(req.body.device || "").trim();
    if (!key || !device) return res.send(loginPage("Thiếu key hoặc thiết bị"));
    const { store, mode } = await readStore();
    const item = normalizeKeyItem(store[key]);
    if (!item) return res.send(loginPage("Key không hợp lệ"));
    if (item.expireAt && Date.now() > item.expireAt) return res.send(loginPage("Key đã hết hạn"));
    if (!item.devices.includes(device)) {
      if (item.devices.length >= item.totalDevices) return res.send(loginPage("Key đã hết lượt thiết bị"));
      item.devices.push(device);
      item.usesLeft = Math.max(0, item.totalDevices - item.devices.length);
      store[key] = item;
      if (mode !== "github-public") await persistStore(store);
    }
    const token = createSessionToken(key, device, item.expireAt || 0);
    res.cookie?.("session", token, { httpOnly: false, sameSite: "Lax" });
    res.setHeader("Set-Cookie", `session=${token}; Path=/; SameSite=Lax`);
    res.redirect("/panel");
  } catch {
    res.send(loginPage("Lỗi đăng nhập"));
  }
});

app.get("/panel", async (req, res) => {
  const cookie = String(req.headers.cookie || "");
  const token = cookie.split(";").map((v) => v.trim()).find((v) => v.startsWith("session="));
  if (!token) return res.redirect("/");
  const session = verifySessionToken(token.slice(8));
  if (!session) return res.redirect("/");
  const { store, mode } = await readStore();
  const item = normalizeKeyItem(store[session.key]);
  if (!item || !item.devices.includes(session.device)) return res.redirect("/");
  if (item.expireAt && Date.now() > item.expireAt) return res.redirect("/");
  res.send(panelPage(session, item, mode));
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", "session=; Path=/; Max-Age=0; SameSite=Lax");
  res.redirect("/");
});

app.get("/api/health", async (req, res) => {
  const { store, mode } = await readStore();
  res.json({ ok: true, mode, count: Object.keys(store || {}).length });
});
app.get("/healthz", async (req, res) => {
  const { store, mode } = await readStore();
  res.json({ ok: true, mode, count: Object.keys(store || {}).length });
});

app.post("/api/create", async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok: false, msg: "Sai admin key" });
  try {
    const { store } = await readStore();
    const customKey = String(req.body.customKey || "").trim();
    const key = customKey || genKey();
    if (store[key]) return res.status(400).json({ ok: false, msg: "Key đã tồn tại" });
    const totalDevices = Math.max(1, Number(req.body.totalDevices || 1));
    const days = Math.max(0, Number(req.body.days || 0));
    const createdAt = Date.now();
    const expireAt = days ? createdAt + days * 86400000 : 0;
    store[key] = normalizeKeyItem({ devices: [], totalDevices, usesLeft: totalDevices, createdAt, expireAt, source: "admin" });
    const mode = await persistStore(store);
    return res.json({ ok: true, key, mode });
  } catch (err) {
    return res.status(500).json({ ok: false, msg: hasGithubWrite() ? "Không lưu được key" : "Đã tạo local, cần GitHub env để giữ key admin lâu dài" });
  }
});

app.post("/api/check", async (req, res) => {
  try {
    const key = String(req.body.key || "").trim();
    const { store, mode } = await readStore();
    const item = normalizeKeyItem(store[key]);
    if (!item) return res.status(404).json({ ok: false, msg: "Không tìm thấy key" });
    return res.json({ ok: true, mode, key, totalDevices: item.totalDevices, devices: item.devices.length, expireAt: item.expireAt, expireText: item.expireAt ? formatVNTime(item.expireAt) : "Vĩnh viễn" });
  } catch {
    return res.status(500).json({ ok: false, msg: "Lỗi kiểm tra key" });
  }
});

app.get("/api/list", async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok: false, msg: "Sai admin key" });
  const { store, mode } = await readStore();
  const items = Object.entries(store).map(([key, raw]) => {
    const item = normalizeKeyItem(raw);
    return {
      key,
      devices: item.devices.length,
      totalDevices: item.totalDevices,
      expireText: item.expireAt ? formatVNTime(item.expireAt) : "Vĩnh viễn",
      source: item.source || mode
    };
  }).sort((a,b)=>a.key.localeCompare(b.key));
  res.json({ ok: true, mode, items });
});

app.post("/api/delete", async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ ok: false, msg: "Sai admin key" });
  try {
    const key = String(req.body.key || "").trim();
    const { store } = await readStore();
    delete store[key];
    const mode = await persistStore(store);
    res.json({ ok: true, mode });
  } catch {
    res.status(500).json({ ok: false, msg: "Xóa key thất bại" });
  }
});

app.get("/api/status", async (req, res) => {
  try {
    const cookie = String(req.headers.cookie || "");
    const token = cookie.split(";").map((v) => v.trim()).find((v) => v.startsWith("session="));
    if (!token) return res.status(401).json({ ok: false });
    const session = verifySessionToken(token.slice(8));
    if (!session) return res.status(401).json({ ok: false });
    const { store, mode } = await readStore();
    const item = normalizeKeyItem(store[session.key]);
    if (!item) return res.status(404).json({ ok: false });
    res.json({ ok: true, mode, key: session.key, device: session.device, devices: item.devices.length, totalDevices: item.totalDevices, expireText: item.expireAt ? formatVNTime(item.expireAt) : "Vĩnh viễn" });
  } catch {
    res.status(500).json({ ok: false });
  }
});

app.listen(PORT, () => {
  console.log(`HFT panel running on ${PORT}`);
});
