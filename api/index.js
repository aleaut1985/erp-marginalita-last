// TLuxy Business Manager v5.21.1 - Fix salvataggio KV con scadenza · v5.21: Accesso con Face ID (passkey) · v5.20: Nome app + icona bianco/nero · v5.19: Icona app Home (T. oro) + manifest · v5.18: Box Oggi (incasso + margine) in cima, card canali compatte espandibili · v5.17: Miinto anche giorno su giorno · v5.16: Pannello canali (Miinto, TLuxy fonti, Winkelstraat, Bradery private sale) · v5.15.1: Dashboard senza cache browser · v5.15: Controllo margini DUOMO nell'ERP · v5.14: Alert canali lenti (banner + /api/alerts) · v5.13: Restyle grafico mobile-first (Bodoni Moda + Jost) · v5.12: Nuova commissione Miinto 21,5% dal 01/11/2026 + The Bradery anticipo 90/10 (regole con data di validità)

import * as crypto from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'autore-luxit.myshopify.com';
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || '';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || '';

// ============ AUTH CONFIG (MAGIC LINK) ============
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'T. Luxy ERP <onboarding@resend.dev>';
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const AUTH_SECRET = process.env.AUTH_SECRET || (RESEND_API_KEY + '_tluxy_erp_secret_salt_2026');
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://erp-marginalita-last.vercel.app';
const AUTH_COOKIE_NAME = 'tluxy_erp_session';
// v5.21: accesso con passkey (Face ID / Touch ID). Attivo se PASSKEY_AUTH=1; PASSKEY_SETUP_CODE serve per registrare un dispositivo senza essere già dentro.
// v5.22: accesso con utente e password (ERP_USER + ERP_PASS_HASH = 'salt:scrypt'); ha priorità sulla passkey.
const ERP_USER = (process.env.ERP_USER || '').trim().toLowerCase();
const ERP_PASS_HASH = (process.env.ERP_PASS_HASH || '').trim();
const PASSWORD_AUTH = !!(ERP_USER && ERP_PASS_HASH.includes(':'));
const PASSKEY_AUTH = !PASSWORD_AUTH && process.env.PASSKEY_AUTH === '1';
const PASSKEY_SETUP_CODE = (process.env.PASSKEY_SETUP_CODE || '').trim();
const AUTH_SESSION_DAYS = (PASSKEY_AUTH || PASSWORD_AUTH) ? 30 : 7;
const MAGIC_LINK_MINUTES = 15;
const MAGIC_LINK_RATE_LIMIT = 3; // max 3 magic link/ora per email
const AUTH_ENABLED = PASSWORD_AUTH || PASSKEY_AUTH || !!(RESEND_API_KEY && ALLOWED_EMAILS.length > 0);

function hmacSign(payload) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('hex');
}

function createSessionToken(email) {
  const expiresAt = Date.now() + (AUTH_SESSION_DAYS * 24 * 60 * 60 * 1000);
  // email base64 per evitare caratteri problematici nel cookie
  const emailB64 = Buffer.from(email).toString('base64url');
  const payload = `v1.${expiresAt}.${emailB64}`;
  const sig = hmacSign(payload);
  return `${payload}.${sig}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return null;
  const expiresAt = parseInt(parts[1], 10);
  if (isNaN(expiresAt) || expiresAt < Date.now()) return null;
  const expectedSig = hmacSign(`v1.${parts[1]}.${parts[2]}`);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(parts[3]))) return null;
    const email = Buffer.from(parts[2], 'base64url').toString('utf8');
    return { email, expiresAt };
  } catch (e) { return null; }
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k] = v.join('=');
  });
  return cookies;
}

function getAuthenticatedUser(req) {
  if (!AUTH_ENABLED) return { email: 'auth-disabled' };
  const cookies = parseCookies(req.headers.cookie || '');
  return verifySessionToken(cookies[AUTH_COOKIE_NAME]);
}

function setAuthCookie(res, email) {
  const token = createSessionToken(email);
  const maxAge = AUTH_SESSION_DAYS * 24 * 60 * 60;
  res.setHeader('Set-Cookie', `${AUTH_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

// Genera token sicuro per magic link (32 byte random = ~43 char url-safe)
function generateMagicLinkToken() {
  return crypto.randomBytes(32).toString('base64url');
}

// Invia email via Resend API
async function sendMagicLinkEmail(email, magicLink) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY mancante');
  const html = `<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif; max-width:560px; margin:40px auto; padding:40px 32px; background:#F5F1E8; border-radius:16px; color:#1A1A1A;">
  <div style="background:#FFFFFF; padding:40px 36px; border-radius:14px; box-shadow:0 8px 24px rgba(0,0,0,0.06);">
    <div style="font-size:1.35rem; font-weight:800; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px;">T. <span style="color:#C9A961;">Luxy</span> · ERP</div>
    <div style="font-size:0.72rem; color:#8E8E8E; text-transform:uppercase; letter-spacing:0.15em; font-weight:600; margin-bottom:32px;">Marginality Dashboard</div>
    <h1 style="font-size:1.1rem; margin:0 0 18px 0;">🔐 Il tuo link di accesso</h1>
    <p style="font-size:0.92rem; line-height:1.6; color:#444; margin-bottom:28px;">Clicca il bottone qui sotto per accedere alla dashboard. Il link è valido per <strong>${MAGIC_LINK_MINUTES} minuti</strong> e può essere usato una sola volta.</p>
    <div style="text-align:center; margin:32px 0;">
      <a href="${magicLink}" style="display:inline-block; background:#1A1A1A; color:#FFFFFF; text-decoration:none; padding:14px 32px; border-radius:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; font-size:0.88rem;">Entra nella Dashboard</a>
    </div>
    <p style="font-size:0.78rem; color:#8E8E8E; line-height:1.5; margin-top:32px; padding-top:20px; border-top:1px solid #F0EBDF;">Se non hai richiesto tu questo link, ignora semplicemente questa email — nessun accesso sarà concesso.<br><br>Link diretto (se il bottone non funziona):<br><span style="word-break:break-all; color:#666; font-size:0.72rem;">${magicLink}</span></p>
  </div>
  <div style="text-align:center; font-size:0.7rem; color:#8E8E8E; margin-top:20px; letter-spacing:0.04em;">T. Luxy ERP · Business Intelligence</div>
  </body></html>`;
  const text = `T. LUXY ERP - Accesso Dashboard\n\nClicca il link per accedere (valido ${MAGIC_LINK_MINUTES} minuti):\n${magicLink}\n\nSe non hai richiesto tu questo link, ignora questa email.`;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: MAIL_FROM,
      to: [email],
      subject: 'Il tuo link di accesso T. Luxy ERP',
      html,
      text
    })
  });
  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Resend API error ${res.status}: ${errorBody}`);
  }
  return await res.json();
}


// ============ LOGIN UTENTE + PASSWORD (v5.22) ============
const tentativiLogin = new Map(); // per istanza: ip -> { n, t }
function passwordOk(user, pass) {
  try {
    const u1 = Buffer.from(String(user || '').trim().toLowerCase()), u2 = Buffer.from(ERP_USER);
    const userOk = u1.length === u2.length && crypto.timingSafeEqual(u1, u2);
    const [salt, hash] = ERP_PASS_HASH.split(':');
    const calc = crypto.scryptSync(String(pass || ''), Buffer.from(salt, 'hex'), 64, { N: 16384, r: 8, p: 1 });
    const passOk = crypto.timingSafeEqual(calc, Buffer.from(hash, 'hex'));
    return userOk && passOk;
  } catch (e) { return false; }
}
function passwordLoginPage(errore) {
  return `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>TLuxy Business Manager</title>
<link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="manifest" href="/manifest.webmanifest">
<meta name="apple-mobile-web-app-title" content="TLuxy Business Manager"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black"><meta name="theme-color" content="#111111">
<link href="https://fonts.googleapis.com/css2?family=Bodoni+Moda:opsz,wght@6..96,500&family=Jost:wght@400;500&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Jost', -apple-system, sans-serif; background: #111; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .wrap { width: 100%; max-width: 360px; text-align: center; }
  .logo { font-family: 'Bodoni Moda', Georgia, serif; font-size: 4.2rem; line-height: 1; }
  .sub { letter-spacing: 0.35em; font-size: 0.8rem; opacity: .8; margin: 10px 0 6px; padding-left: .35em; }
  .app { font-size: 0.8rem; opacity: .55; margin-bottom: 40px; }
  input { width: 100%; padding: 15px 16px; border-radius: 12px; border: 1px solid rgba(255,255,255,.3); background: transparent; color: #fff; font-family: inherit; font-size: 1rem; margin-bottom: 12px; }
  input::placeholder { color: rgba(255,255,255,.45); }
  button { width: 100%; padding: 16px; border-radius: 14px; border: none; background: #fff; color: #111; font-family: inherit; font-size: 1rem; font-weight: 500; cursor: pointer; margin-top: 4px; }
  .err { margin-top: 16px; font-size: .85rem; color: #ff8a8a; }
</style></head><body><div class="wrap">
  <div class="logo">T.</div><div class="sub">LUXY</div><div class="app">Business Manager</div>
  <form method="POST" action="/login">
    <input name="user" type="text" autocomplete="username" autocapitalize="none" autocorrect="off" placeholder="Utente" required>
    <input name="password" type="password" autocomplete="current-password" placeholder="Password" required>
    <button type="submit">Entra</button>
  </form>
  ${errore ? '<div class="err">' + errore + '</div>' : ''}
</div></body></html>`;
}

// ============ PASSKEY (FACE ID) — v5.21 ============
function rpFromReq(req) {
  const hostPort = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  return { rpID: hostPort.split(':')[0], origin: `${proto}://${hostPort}` };
}
async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let body = '';
  await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
  try { return JSON.parse(body || '{}'); } catch (e) { return {}; }
}
async function getPasskeys() { try { return JSON.parse((await kvGet('passkeys_v1')) || '[]'); } catch (e) { return []; } }
async function savePasskeys(list) { return kvSetBody('passkeys_v1', JSON.stringify(list)); }
function codiceOk(code) {
  if (!PASSKEY_SETUP_CODE || !code) return false;
  const a = Buffer.from(String(code).trim()), b = Buffer.from(PASSKEY_SETUP_CODE);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function salvaChallenge(res, challenge) {
  const id = crypto.randomBytes(16).toString('hex');
  const ok = await kvSetEx('pk_chal_' + id, 300, challenge);
  res.setHeader('Set-Cookie', `pk_chal=${id}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`);
  return ok;
}
async function leggiChallenge(req) {
  const id = parseCookies(req.headers.cookie || '').pk_chal;
  if (!id || !/^[a-f0-9]{32}$/.test(id)) return null;
  const c = await kvGet('pk_chal_' + id);
  await kvDel('pk_chal_' + id);
  return c;
}

function passkeyLoginPage(haPasskey) {
  return `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>TLuxy Business Manager</title>
<link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="manifest" href="/manifest.webmanifest">
<meta name="apple-mobile-web-app-title" content="TLuxy Business Manager"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black"><meta name="theme-color" content="#111111">
<link href="https://fonts.googleapis.com/css2?family=Bodoni+Moda:opsz,wght@6..96,500&family=Jost:wght@400;500&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Jost', -apple-system, sans-serif; background: #111; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .wrap { width: 100%; max-width: 360px; text-align: center; }
  .logo { font-family: 'Bodoni Moda', Georgia, serif; font-size: 4.2rem; line-height: 1; }
  .sub { letter-spacing: 0.35em; font-size: 0.8rem; opacity: .8; margin: 10px 0 6px; padding-left: .35em; }
  .app { font-size: 0.8rem; opacity: .55; margin-bottom: 48px; }
  button { width: 100%; padding: 16px; border-radius: 14px; border: none; background: #fff; color: #111; font-family: inherit; font-size: 1rem; font-weight: 500; cursor: pointer; }
  button.sec { background: transparent; color: #fff; border: 1px solid rgba(255,255,255,.3); margin-top: 12px; font-size: .9rem; }
  input { width: 100%; padding: 14px; border-radius: 12px; border: 1px solid rgba(255,255,255,.3); background: transparent; color: #fff; font-family: inherit; font-size: 1rem; text-align: center; letter-spacing: .2em; margin-bottom: 12px; }
  .msg { margin-top: 18px; font-size: .85rem; min-height: 1.2em; opacity: .85; }
  .msg.err { color: #ff8a8a; opacity: 1; }
  #setup { display: none; margin-top: 28px; }
</style></head><body><div class="wrap">
  <div class="logo">T.</div><div class="sub">LUXY</div><div class="app">Business Manager</div>
  <button id="btnLogin">Accedi con Face ID</button>
  <button class="sec" id="btnShowSetup">Registra questo dispositivo</button>
  <div id="setup"><input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="Codice di attivazione"><button id="btnRegister">Attiva Face ID</button></div>
  <div class="msg" id="msg"></div>
</div>
<script src="https://unpkg.com/@simplewebauthn/browser@13.3.0/dist/bundle/index.umd.min.js"></script>
<script>
var W = window.SimpleWebAuthnBrowser, msg = document.getElementById('msg');
function say(t, err) { msg.textContent = t; msg.className = 'msg' + (err ? ' err' : ''); }
async function post(u, b) { var r = await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}), credentials: 'same-origin' }); return r.json(); }
async function login() {
  try {
    say('');
    var o = await post('/api/passkey/login-options');
    if (!o.success) return say(o.error || 'Errore', true);
    var a = await W.startAuthentication({ optionsJSON: o.options });
    var v = await post('/api/passkey/login-verify', { response: a });
    if (v.success) { say('Accesso riuscito'); location.href = '/'; } else say(v.error || 'Accesso non riuscito', true);
  } catch (e) { say(e && e.name === 'NotAllowedError' ? 'Accesso annullato' : (e.message || 'Errore'), true); }
}
async function register() {
  try {
    say('');
    var o = await post('/api/passkey/register-options', { setup_code: document.getElementById('code').value });
    if (!o.success) return say(o.error || 'Codice non valido', true);
    if (o.fallback) { say(o.messaggio); setTimeout(function () { location.href = '/'; }, 1200); return; }
    var a = await W.startRegistration({ optionsJSON: o.options });
    var v = await post('/api/passkey/register-verify', { response: a, nome: navigator.platform || 'dispositivo' });
    if (v.success) { say('Face ID attivato'); location.href = '/'; } else say(v.error || 'Registrazione non riuscita', true);
  } catch (e) { say(e && e.name === 'NotAllowedError' ? 'Operazione annullata' : (e.message || 'Errore'), true); }
}
document.getElementById('btnLogin').onclick = login;
document.getElementById('btnRegister').onclick = register;
document.getElementById('btnShowSetup').onclick = function () { document.getElementById('setup').style.display = 'block'; this.style.display = 'none'; };
${haPasskey ? '' : "document.getElementById('btnShowSetup').click(); document.getElementById('btnLogin').style.display='none';"}
</script></body></html>`;
}

// Pagine HTML di login/conferma/errore
function loginHTMLPage(message, isError) {
  const msgBlock = message ? `<div class="${isError ? 'error' : 'info'} show">${message}</div>` : '';
  return `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>T. Luxy ERP · Accesso</title><link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png"><link rel="manifest" href="/manifest.webmanifest"><meta name="apple-mobile-web-app-title" content="TLuxy Business Manager"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #F5F1E8 0%, #ECE5D3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; color: #1A1A1A; }
  .card { background: #FFFFFF; padding: 48px 40px; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.08), 0 2px 8px rgba(0,0,0,0.04); max-width: 440px; width: 100%; border: 1px solid rgba(0,0,0,0.03); }
  .logo { font-size: 1.5rem; font-weight: 800; letter-spacing: 0.08em; margin-bottom: 8px; text-transform: uppercase; }
  .logo-accent { color: #C9A961; }
  .subtitle { font-size: 0.75rem; color: #8E8E8E; text-transform: uppercase; letter-spacing: 0.15em; margin-bottom: 36px; font-weight: 600; }
  h1 { font-size: 1.15rem; margin-bottom: 12px; font-weight: 700; color: #1A1A1A; }
  p.intro { font-size: 0.88rem; color: #555; margin-bottom: 28px; line-height: 1.55; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: #555; margin-bottom: 8px; font-weight: 700; }
  .field input { width: 100%; padding: 14px 16px; border: 1.5px solid #E5E0D3; border-radius: 10px; font-size: 1rem; font-family: inherit; background: #FAFAF7; transition: all 0.2s; }
  .field input:focus { outline: none; border-color: #C9A961; background: #FFFFFF; box-shadow: 0 0 0 3px rgba(201,169,97,0.1); }
  .btn { width: 100%; padding: 14px 20px; background: #1A1A1A; color: #FFFFFF; border: none; border-radius: 10px; font-size: 0.9rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer; transition: all 0.2s; margin-top: 8px; font-family: inherit; }
  .btn:hover { background: #333; transform: translateY(-1px); }
  .btn:disabled { background: #BBB; cursor: not-allowed; transform: none; }
  .error { background: #FCEEEE; color: #BF4747; padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 20px; border-left: 3px solid #BF4747; display: none; }
  .info { background: #E6F4EE; color: #006b4a; padding: 14px 18px; border-radius: 8px; font-size: 0.88rem; margin-bottom: 20px; border-left: 3px solid #008060; display: none; line-height: 1.5; }
  .error.show, .info.show { display: block; }
  .footer { margin-top: 28px; padding-top: 20px; border-top: 1px solid #F0EBDF; font-size: 0.72rem; color: #8E8E8E; text-align: center; letter-spacing: 0.04em; }
</style></head>
<body>
  <div class="card">
    <div class="logo">T. <span class="logo-accent">Luxy</span> · ERP</div>
    <div class="subtitle">Marginality Dashboard</div>
    <h1>🔐 Accesso riservato</h1>
    <p class="intro">Inserisci la tua email autorizzata. Riceverai un link sicuro per entrare. Valido ${MAGIC_LINK_MINUTES} minuti.</p>
    ${msgBlock}
    <form id="loginForm" action="/api/request-magic-link" method="POST">
      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" autocomplete="email" autofocus required placeholder="nome@azienda.com">
      </div>
      <button type="submit" class="btn" id="submitBtn">Invia magic link</button>
    </form>
    <div class="footer">Business Intelligence · Autenticazione protetta</div>
  </div>
<script>
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const btn = document.getElementById('submitBtn');
  btn.disabled = true; btn.textContent = 'Invio in corso...';
  try {
    const res = await fetch('/api/request-magic-link', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email}) });
    const data = await res.json();
    // Sempre successo percepito (anti-enumeration): mostriamo lo stesso messaggio
    window.location.href = '/login?sent=1';
  } catch(e) {
    btn.disabled = false; btn.textContent = 'Invia magic link';
    alert('Errore di rete, riprova');
  }
});
</script>
</body></html>`;
}

// ============ KV ENV DETECTION ============
// Vercel può creare env vars con nomi diversi a seconda della versione integrazione:
// - KV_REST_API_URL + KV_REST_API_TOKEN (vecchio Vercel KV)
// - UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN (Upstash diretto)
// - KV_REDIS_URL (nuovo Upstash marketplace — formato rediss://default:TOKEN@HOST:PORT)
// Questo codice prova tutti e 3 i formati automaticamente.
function detectKvCredentials() {
  if (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
    return { url: process.env.KV_REST_API_URL, token: process.env.KV_REST_API_TOKEN, source: 'kv_rest' };
  }
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    return { url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN, source: 'upstash_rest' };
  }
  const redisUrl = process.env.KV_REDIS_URL || process.env.REDIS_URL;
  if (redisUrl) {
    try {
      const u = new URL(redisUrl);
      const token = u.password || u.username;
      const host = u.hostname;
      if (host && token) {
        return { url: `https://${host}`, token, source: 'parsed_from_redis_url' };
      }
    } catch (e) {}
  }
  return null;
}
const KV_CREDENTIALS = detectKvCredentials();
const KV_REST_API_URL = KV_CREDENTIALS ? KV_CREDENTIALS.url : '';
const KV_REST_API_TOKEN = KV_CREDENTIALS ? KV_CREDENTIALS.token : '';
const KV_SOURCE = KV_CREDENTIALS ? KV_CREDENTIALS.source : null;
const KV_ENABLED = !!(KV_REST_API_URL && KV_REST_API_TOKEN);

const SHOPIFY_FEE_PERCENT = 0.0015;
const SHOPIFY_FEE_FIXED = 0;

// ============ KV STORAGE (Upstash Redis via Vercel KV) ============
// Cache persistente dei costi: sopravvive all'archiviazione dei prodotti su Shopify.
async function kvGet(key) {
  if (!KV_ENABLED) return null;
  try {
    const res = await fetch(`${KV_REST_API_URL}/get/${encodeURIComponent(key)}`, {
      headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.result; // string or null
  } catch (e) { return null; }
}
async function kvSet(key, value) {
  if (!KV_ENABLED) return false;
  try {
    const res = await fetch(`${KV_REST_API_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}`, {
      headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` }
    });
    return res.ok;
  } catch (e) { return false; }
}
// kvSetBody: set con valore nel body (per valori grandi, Upstash REST POST /set/{key})
async function kvSetBody(key, value) {
  if (!KV_ENABLED) return false;
  try {
    const res = await fetch(KV_REST_API_URL, { method: 'POST', headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify(['SET', key, String(value)]) });
    return res.ok;
  } catch (e) { return false; }
}
// kvSetEx: set con TTL (seconds)
async function kvSetEx(key, ttlSec, value) {
  if (!KV_ENABLED) return false;
  const auth = { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` };
  try {
    const r1 = await fetch(KV_REST_API_URL.replace(/\/$/, ''), { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify(['SET', key, String(value), 'EX', String(ttlSec)]) });
    if (r1.ok) return true;
    console.log('[kv] setex POST fallito', r1.status, (await r1.text()).slice(0, 200));
  } catch (e) { console.log('[kv] setex POST errore', e.message); }
  try {
    const r2 = await fetch(`${KV_REST_API_URL.replace(/\/$/, '')}/set/${encodeURIComponent(key)}/${encodeURIComponent(String(value))}/EX/${ttlSec}`, { headers: auth });
    if (!r2.ok) console.log('[kv] setex GET fallito', r2.status, (await r2.text()).slice(0, 200));
    return r2.ok;
  } catch (e) { console.log('[kv] setex GET errore', e.message); return false; }
}
// kvDel: elimina chiave
async function kvDel(key) {
  if (!KV_ENABLED) return false;
  try {
    const res = await fetch(`${KV_REST_API_URL}/del/${encodeURIComponent(key)}`, {
      headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` }
    });
    return res.ok;
  } catch (e) { return false; }
}
async function kvMGet(keys) {
  if (!KV_ENABLED || keys.length === 0) return {};
  try {
    // MGET accetta array di keys
    const url = `${KV_REST_API_URL}/mget/${keys.map(k => encodeURIComponent(k)).join('/')}`;
    const res = await fetch(url, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
    if (!res.ok) return {};
    const data = await res.json();
    const results = {};
    (data.result || []).forEach((val, idx) => { if (val !== null) results[keys[idx]] = val; });
    return results;
  } catch (e) { return {}; }
}
async function kvMSet(pairs) {
  if (!KV_ENABLED || Object.keys(pairs).length === 0) return false;
  try {
    // Facciamo più SET in parallelo (Upstash non ha MSET in REST)
    const concurrency = 5;
    const entries = Object.entries(pairs);
    for (let i = 0; i < entries.length; i += concurrency) {
      const batch = entries.slice(i, i + concurrency);
      await Promise.all(batch.map(([k, v]) => kvSet(k, v)));
    }
    return true;
  } catch (e) { return false; }
}

// Riconosce prodotti DUO dallo SKU (DUO- all'inizio)
function isDuoSku(sku) {
  return !!(sku && typeof sku === 'string' && /^DUO-/i.test(sku.trim()));
}

// ============ CURRENCY HELPERS ============
// Tassi di cambio fallback (aggiornare periodicamente). Usati SOLO se Shopify non fornisce shop_money
// (caso estremamente raro: ordini molto vecchi pre-multi-currency).
const SHOP_CURRENCY = 'EUR';
const FALLBACK_RATES_TO_EUR = {
  EUR: 1.0,
  USD: 0.92,
  GBP: 1.17,
  SEK: 0.087,
  NOK: 0.086,
  DKK: 0.134,
  CHF: 1.05,
  PLN: 0.23,
  CZK: 0.041,
  HUF: 0.0026,
  JPY: 0.0061,
  CAD: 0.67,
  AUD: 0.61,
  SGD: 0.68,
  HKD: 0.118,
  RON: 0.20
};

// Converte un prezzo in EUR. Prova nell'ordine:
//   1) money_set.shop_money (già convertito da Shopify al cambio del giorno — il più accurato)
//   2) calcolo manuale con tasso fallback
//   3) prezzo originale se già in EUR
function toEurAmount(moneySet, fallbackAmount, fallbackCurrency) {
  // moneySet = esempio ordine.total_price_set (o line_item.price_set)
  if (moneySet && moneySet.shop_money && moneySet.shop_money.amount !== undefined) {
    const amt = parseFloat(moneySet.shop_money.amount);
    if (!isNaN(amt) && (moneySet.shop_money.currency_code === SHOP_CURRENCY || !moneySet.shop_money.currency_code)) {
      return amt;
    }
  }
  // Fallback: conversione manuale
  const amt = parseFloat(fallbackAmount);
  if (isNaN(amt)) return 0;
  const cur = (fallbackCurrency || SHOP_CURRENCY).toUpperCase();
  if (cur === SHOP_CURRENCY) return amt;
  const rate = FALLBACK_RATES_TO_EUR[cur];
  if (rate) return amt * rate;
  return amt; // ultima spiaggia: ritorna così com'è
}

// Estrae info valuta di un ordine
function getOrderCurrencyInfo(ordine) {
  const originalCurrency = ordine.currency || SHOP_CURRENCY;
  const isForeign = originalCurrency !== SHOP_CURRENCY;
  const eurTotal = toEurAmount(ordine.total_price_set, ordine.total_price, originalCurrency);
  const originalTotal = parseFloat(ordine.total_price) || 0;
  const exchangeRate = isForeign && originalTotal > 0 ? eurTotal / originalTotal : 1;
  return { originalCurrency, isForeign, eurTotal, originalTotal, exchangeRate };
}

// Estrae info refund di un ordine (Shopify espone array refunds nel JSON ordine)
// Restituisce: importo totale rimborsato (in EUR), articoli rimborsati, status, ecc.
function getOrderRefundInfo(ordine) {
  const refunds = ordine.refunds || [];
  if (refunds.length === 0) {
    return { hasRefund: false, isFullRefund: false, isPartialRefund: false, totalRefundedEur: 0, refundedQuantity: 0, refundedLineItems: [], refundCount: 0 };
  }
  const ordCurrency = ordine.currency || SHOP_CURRENCY;
  let totalRefundedEur = 0;
  let refundedQuantity = 0;
  const refundedLineItems = [];
  
  refunds.forEach(refund => {
    // 1) Importo monetario rimborsato (transactions di tipo 'refund')
    (refund.transactions || []).forEach(tx => {
      if (tx.kind === 'refund' && (tx.status === 'success' || !tx.status)) {
        const amt = toEurAmount(tx.amount_set, tx.amount, tx.currency || ordCurrency);
        totalRefundedEur += amt;
      }
    });
    
    // 2) Quali line_items sono stati rimborsati (per quantità)
    (refund.refund_line_items || []).forEach(rli => {
      const qty = parseInt(rli.quantity) || 0;
      refundedQuantity += qty;
      // line_item_id punta al line_item originale dell'ordine
      const subtotalEur = toEurAmount(rli.subtotal_set, rli.subtotal, ordCurrency);
      const totalTaxEur = toEurAmount(rli.total_tax_set, rli.total_tax, ordCurrency);
      refundedLineItems.push({
        line_item_id: rli.line_item_id,
        quantity: qty,
        subtotal_eur: subtotalEur,
        total_tax_eur: totalTaxEur
      });
    });
  });
  
  // Determina se è full refund: confronto con prezzo totale dell'ordine
  const orderTotalEur = toEurAmount(ordine.total_price_set, ordine.total_price, ordCurrency);
  const totalQty = (ordine.line_items || []).reduce((s, li) => s + (parseInt(li.quantity) || 0), 0);
  const isFullRefund = totalRefundedEur > 0 && Math.abs(totalRefundedEur - orderTotalEur) < 0.5; // tolleranza 50 cent
  const isPartialRefund = totalRefundedEur > 0 && !isFullRefund;
  
  return {
    hasRefund: totalRefundedEur > 0,
    isFullRefund,
    isPartialRefund,
    totalRefundedEur,
    refundedQuantity,
    totalQuantity: totalQty,
    refundedLineItems,
    refundCount: refunds.length
  };
}

// ============ PAYMENT FORECAST ============
// Dato un ordine + config MP, calcola quando arriverà il pagamento (o più pagamenti se split).
// Ritorna array di { data: Date, importo_eur: number, nota: string, parte: number }
function calcolaPagamentiPrevisti(dataOrdine, policy, nettoIncassato) {
  if (!policy || nettoIncassato <= 0) return [];
  const orderDate = new Date(dataOrdine);
  if (isNaN(orderDate.getTime())) return [];
  
  const result = [];
  
  switch (policy.type) {
    case 'immediate': {
      result.push({ data: orderDate, importo_eur: nettoIncassato, nota: 'Accredito immediato', parte: 1 });
      break;
    }
    case 'fixed_days': {
      const d = new Date(orderDate);
      d.setDate(d.getDate() + (policy.days_offset || 0));
      result.push({ data: d, importo_eur: nettoIncassato, nota: `Ordine + ${policy.days_offset}gg`, parte: 1 });
      break;
    }
    case 'weekly': {
      // Stima: ordine + N giorni, poi arrotondato al lunedì successivo
      const d = new Date(orderDate);
      d.setDate(d.getDate() + (policy.days_offset || 21));
      const dayOfWeek = d.getDay(); // 0 = domenica, 1 = lunedì
      const daysToMonday = dayOfWeek === 0 ? 1 : (dayOfWeek === 1 ? 0 : (8 - dayOfWeek));
      d.setDate(d.getDate() + daysToMonday);
      result.push({ data: d, importo_eur: nettoIncassato, nota: `Settimanale (~${policy.days_offset}gg)`, parte: 1 });
      break;
    }
    case 'monthly_decade': {
      // Ordini del mese M pagati il giorno X (es. 10) del mese M + month_offset
      const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (policy.month_offset || 2), policy.payout_day || 10);
      result.push({ data: target, importo_eur: nettoIncassato, nota: `Prima decade mese+${policy.month_offset}`, parte: 1 });
      break;
    }
    case 'monthly_mid': {
      const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (policy.month_offset || 2), policy.payout_day || 15);
      result.push({ data: target, importo_eur: nettoIncassato, nota: `Prima metà mese+${policy.month_offset}`, parte: 1 });
      break;
    }
    case 'split': {
      (policy.parts || []).forEach((part, idx) => {
        const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (part.month_offset || 1), part.payout_day || 10);
        const importoParte = nettoIncassato * (part.pct / 100);
        result.push({ data: target, importo_eur: importoParte, nota: `${part.pct}% (mese+${part.month_offset})`, parte: idx + 1 });
      });
      break;
    }
    case 'prepaid_balance': {
      // Non genera pagamento futuro, scala dal wallet
      result.push({ data: orderDate, importo_eur: 0, nota: 'Wallet (scalato da credito)', parte: 1, is_wallet: true });
      break;
    }
    default: {
      // Fallback: usa data ordine + 30gg
      const d = new Date(orderDate);
      d.setDate(d.getDate() + 30);
      result.push({ data: d, importo_eur: nettoIncassato, nota: 'Policy sconosciuta (+30gg)', parte: 1 });
    }
  }
  
  return result;
}

// Helper: formatta data in YYYY-MM-DD
function fmtDateISO(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${dd}`;
}

// Helper: chiave mese YYYY-MM
function fmtMonthKey(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

let cachedToken = null;
let tokenExpiry = null;

async function getShopifyAccessToken() {
  if (cachedToken && tokenExpiry && Date.now() < tokenExpiry) return cachedToken;
  if (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET) throw new Error('Missing credentials');
  const body = new URLSearchParams();
  body.append('client_id', SHOPIFY_CLIENT_ID);
  body.append('client_secret', SHOPIFY_CLIENT_SECRET);
  body.append('grant_type', 'client_credentials');
  const response = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  if (!response.ok) { const errText = await response.text(); throw new Error(`HTTP ${response.status}: ${errText}`); }
  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
  return cachedToken;
}

// Payment policies (da Excel TL_REGOLE_MARKET_PLACE + istruzioni utente):
//   type: 'monthly_decade' → ordini del mese M pagati il giorno X del mese M+offset
//   type: 'monthly_mid' → prima metà del mese (~giorno 15)
//   type: 'split' → % al giorno X1, % al giorno X2 dopo data ordine
//   type: 'fixed_days' → data_ordine + N giorni
//   type: 'weekly' → payout settimanale (stima: data_ordine + N giorni)
//   type: 'immediate' → data_ordine (accreditato ~subito)
//   type: 'prepaid_balance' → sistema wallet (Balardi: inserisci ricariche, scali)
const MARKETPLACE_CONFIGS = {
  'SECRET_SALES': { nome: 'Secret Sales', sconto_percentuale: 0, fee_principale: 20, fee_secondaria: 0, fee_fissa_trasporto: 2, fee_fissa_packaging: 2, pagamento: 'Prima metà mese+2', payment_policy: { type: 'monthly_mid', month_offset: 2, payout_day: 15 } },
  'FASHION_TAMERS': { nome: 'Fashion Tamers', sconto_percentuale: 0, fee_principale: 32, fee_secondaria: 0, fee_accessoria: 2, fee_fissa_trasporto: 15, fee_fissa_packaging: 6, pagamento: 'Prima metà mese+2', payment_policy: { type: 'monthly_mid', month_offset: 2, payout_day: 15 } },
  'INTRA_MIRROR': { nome: 'Intra Mirror', sconto_percentuale: 15, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'BALARDI': { nome: 'Balardi', sconto_percentuale: 35, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Prepagato (wallet)', payment_policy: { type: 'prepaid_balance' } },
  // v5.12: anticipo Bradery portato da 80% a 90% (accordo con facturation@thebradery.com, 22/09/2026) - ordini fino al 31/08/2026 restano 80/20
  'THE_BRADERY': { nome: 'The Bradery', sconto_percentuale: 5, fee_principale: 17, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 2, pagamento: 'Split 90/10 (mese+1 / mese+2)', payment_policy: { type: 'split', parts: [{ pct: 90, month_offset: 1, payout_day: 10 }, { pct: 10, month_offset: 2, payout_day: 10 }] },
    storico: [{ fino_al: '2026-08-31', pagamento: 'Split 80/20 (mese+1 / mese+2)', payment_policy: { type: 'split', parts: [{ pct: 80, month_offset: 1, payout_day: 10 }, { pct: 20, month_offset: 2, payout_day: 10 }] } }] },
  'BOUTIQUE_MALL': { nome: 'Boutique Mall', sconto_percentuale: 33.3, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'ARCHIVIST': { nome: 'Archivist', sconto_percentuale: 0, fee_principale: 22, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  // v5.12: dal 01/11/2026 commissione unica Miinto 21,5% (include transaction fee), calcolata sul netto resi (email Miinto 28/10/2026).
  // La Campaign Contribution Fee resta separata (su lordo) e non è modellata qui. Ordini fino al 31/10/2026: 17,75% + 2,25%.
  'MIINTO': { nome: 'Miinto', sconto_percentuale: 0, fee_principale: 21.5, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 },
    nota_regole: 'Commissione unica 21,5% dal 01/11/2026 (prima 17,75% + 2,25%)',
    storico: [{ fino_al: '2026-10-31', fee_principale: 17.75, fee_secondaria: 2.25 }] },
  'WINKELSTRAAT': { nome: 'Winkelstraat', sconto_percentuale: 0, fee_principale: 17, fee_secondaria: 0, fee_accessoria: 9, fee_fissa_trasporto: 15, fee_fissa_packaging: 0, pagamento: 'Settimanale (~21gg)', payment_policy: { type: 'weekly', days_offset: 21 } },
  'ITALIST': { nome: 'Italist', sconto_percentuale: 20, fee_principale: 25.5, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 4, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'JAMMY_DUDE': { nome: 'Jammy Dude', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: '10gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 10 } },
  'POIZON': { nome: 'Poizon', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Immediato', payment_policy: { type: 'immediate' } },
  'BRANDSGATEWAY': { nome: 'Brandsgateway', sconto_percentuale: 13, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 0, pagamento: '45gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 45 } },
  'TLUXY_SITE': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato (Shopify +2gg)', payment_policy: { type: 'fixed_days', days_offset: 2 } },
  'MARK_FOYS': { nome: 'Mark Foy', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Prepagato immediato', payment_policy: { type: 'immediate' } },
  'GIGLIO': { nome: 'GIGLIO.COM', sconto_percentuale: 0, fee_principale: 30, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'TBD (prepagato per ora)', payment_policy: { type: 'immediate' } }
};

// Normalizza source_name per matching più robusto: lowercase + spazi→trattini
function normalizeSourceName(name) {
  return (name || '').toLowerCase().trim().replace(/\s+/g, '-');
}

const SOURCE_NAME_MAP = {
  'web': 'TLUXY_SITE', 'pos': 'TLUXY_SITE', 'shopify_draft_order': 'TLUXY_SITE', 'shopify-draft-order': 'TLUXY_SITE',
  'miinto': 'MIINTO', 'miinto-app': 'MIINTO',
  'secret-sales': 'SECRET_SALES', 'secretsales': 'SECRET_SALES',
  'fashion-tamers': 'FASHION_TAMERS', 'fashiontamers': 'FASHION_TAMERS',
  'intra-mirror': 'INTRA_MIRROR', 'intramirror': 'INTRA_MIRROR',
  'balardi': 'BALARDI',
  'the-bradery': 'THE_BRADERY', 'thebradery': 'THE_BRADERY', 'bradery': 'THE_BRADERY',
  'my-moon-store': 'THE_BRADERY', 'mymoonstore': 'THE_BRADERY', 'my-moon-store-syncio-order': 'THE_BRADERY', '1615469': 'THE_BRADERY',
  'boutique-mall': 'BOUTIQUE_MALL', 'boutiquemall': 'BOUTIQUE_MALL',
  'archivist': 'ARCHIVIST', 'winkelstraat': 'WINKELSTRAAT',
  'italist': 'ITALIST', 'italist-app': 'ITALIST',
  'syncio-order': 'JAMMY_DUDE', 'jammydude21': 'JAMMY_DUDE', 'jammy-dude': 'JAMMY_DUDE', 'jammydude': 'JAMMY_DUDE',
  'poizon': 'POIZON', '217504907265': 'POIZON',
  '223431819265': 'BALARDI'
};

const IVA_PER_PAESE = {
  'IT': 22, 'FR': 20, 'DE': 19, 'ES': 21, 'NL': 21, 'BE': 21, 'AT': 20, 'IE': 23,
  'PL': 23, 'SE': 25, 'DK': 25, 'FI': 25.5, 'PT': 23, 'GR': 24, 'CZ': 21, 'SK': 23,
  'HU': 27, 'RO': 19, 'BG': 20, 'HR': 25, 'SI': 22, 'EE': 22, 'LV': 21, 'LT': 21,
  'LU': 17, 'MT': 18, 'CY': 19,
  'GB': 20,
  'NO': 0, 'CH': 0, 'US': 0, 'CA': 0, 'AU': 0, 'JP': 0, 'CN': 0, 'AE': 0, 'SA': 0,
  'BR': 0, 'MX': 0, 'TR': 0, 'RU': 0, 'IN': 0, 'KR': 0, 'SG': 0, 'HK': 0, 'ZA': 0
};

function getIvaPerPaese(countryCode) {
  if (!countryCode) return 22;
  return IVA_PER_PAESE[countryCode.toUpperCase()] ?? 0;
}

function isWinkelstraatOrder(ordine) {
  // Controllo multi-criterio in OR
  const email = (ordine.email || ordine.customer?.email || '').toLowerCase();
  if (email.includes('@winkelstraat.nl')) return 'email';
  
  const tags = (ordine.tags || '').toLowerCase();
  if (tags.includes('winkelstraat')) return 'tag';
  
  // source_name può contenere "copernicus" per import automatici
  const sourceName = (ordine.source_name || '').toLowerCase();
  if (sourceName.includes('copernicus') || sourceName.includes('winkelstraat')) return 'source_name';
  
  // Note ordine e note attributes
  const note = (ordine.note || '').toLowerCase();
  if (note.includes('winkelstraat') || note.includes('copernicus')) return 'note';
  
  const noteAttrs = (ordine.note_attributes || []).map(a => ((a.name || '') + ' ' + (a.value || '')).toLowerCase()).join(' ');
  if (noteAttrs.includes('winkelstraat') || noteAttrs.includes('copernicus')) return 'note_attributes';
  
  // Shipping address: address1, address2, name, company
  const ship = ordine.shipping_address || {};
  const shipFields = [ship.address1, ship.address2, ship.name, ship.company, ship.first_name, ship.last_name].filter(Boolean).map(s => s.toLowerCase()).join(' ');
  if (shipFields.includes('winkelstraat')) return 'shipping_address';
  
  return null;
}

// v5.12: regole marketplace con data di validità. Ogni voce di `storico` ({ fino_al: 'YYYY-MM-DD', ...override })
// si applica agli ordini con data (fuso Roma) <= fino_al. Si sceglie la voce con fino_al più vicino.
function getConfigPerData(mpKey, dataOrdine) {
  const base = MARKETPLACE_CONFIGS[mpKey];
  if (!base || !Array.isArray(base.storico) || !dataOrdine) return base;
  const d = new Date(dataOrdine);
  if (isNaN(d.getTime())) return base;
  const giorno = getRomeDateString(d);
  const valide = base.storico.filter(v => v && v.fino_al && giorno <= v.fino_al).sort((a, b) => a.fino_al.localeCompare(b.fino_al));
  if (valide.length === 0) return base;
  const { fino_al, ...override } = valide[0];
  return { ...base, ...override, regola_storica_fino_al: fino_al };
}

function riconosciMarketplace(ordine) {
  const r = riconosciMarketplaceBase(ordine);
  return { key: r.key, config: getConfigPerData(r.key, ordine.created_at) || r.config };
}

function riconosciMarketplaceBase(ordine) {
  const rawSource = (ordine.source_name || '').trim();
  const sourceName = normalizeSourceName(rawSource);
  const tags = (ordine.tags || '').toLowerCase();
  const email = (ordine.email || ordine.customer?.email || '').toLowerCase();
  
  // PRIORITÀ 1: tag specifici che hanno precedenza sul source_name
  // Brandsgateway è un dropship fornitore, arriva con source=web ma va classificato come BRANDSGATEWAY
  if (tags.includes('brandsgateway')) {
    return { key: 'BRANDSGATEWAY', config: MARKETPLACE_CONFIGS.BRANDSGATEWAY };
  }
  
  // PRIORITÀ 2: Winkelstraat via Copernicus (import da external) - multi-criterio
  const wsMatch = isWinkelstraatOrder(ordine);
  if (wsMatch) {
    return { key: 'WINKELSTRAAT', config: MARKETPLACE_CONFIGS.WINKELSTRAAT };
  }
  
  // PRIORITÀ 3: Mark Foy's Department Store (condivide source 1615469 con The Bradery)
  // Detection via tag "mark foy" oppure email non-bradery con source 1615469
  if (tags.includes('mark foy') || tags.includes("mark foy's")) {
    return { key: 'MARK_FOYS', config: MARKETPLACE_CONFIGS.MARK_FOYS };
  }
  // Caso sub: source 1615469 MA email non è di thebradery → Mark Foy's
  if (rawSource === '1615469' && email && !email.includes('thebradery')) {
    return { key: 'MARK_FOYS', config: MARKETPLACE_CONFIGS.MARK_FOYS };
  }
  
  // PRIORITÀ 4: Giglio.com - detection via shipping/billing company name
  // Customer ha sempre ragione sociale "Giglio.com S.p.a." 
  const shipCompany = (ordine.shipping_address?.company || '').toLowerCase();
  const billCompany = (ordine.billing_address?.company || '').toLowerCase();
  const custFirstName = (ordine.customer?.first_name || '').toLowerCase();
  const custLastName = (ordine.customer?.last_name || '').toLowerCase();
  const custDefaultCompany = (ordine.customer?.default_address?.company || '').toLowerCase();
  if (
    shipCompany.includes('giglio') ||
    billCompany.includes('giglio') ||
    custDefaultCompany.includes('giglio') ||
    custFirstName.includes('giglio') ||
    custLastName.includes('giglio')
  ) {
    return { key: 'GIGLIO', config: MARKETPLACE_CONFIGS.GIGLIO };
  }
  
  // Match diretto normalizzato su source_name
  if (SOURCE_NAME_MAP[sourceName]) return { key: SOURCE_NAME_MAP[sourceName], config: MARKETPLACE_CONFIGS[SOURCE_NAME_MAP[sourceName]] };
  
  // Poizon detection: source numerico + email customer "poizon"
  const isNumericSource = /^\d+$/.test(rawSource);
  if (isNumericSource && email.includes('poizon')) {
    return { key: 'POIZON', config: MARKETPLACE_CONFIGS.POIZON };
  }
  
  // Partial match su source_name
  for (const [pattern, mpKey] of Object.entries(SOURCE_NAME_MAP)) {
    if (sourceName.includes(pattern) || pattern.includes(sourceName)) return { key: mpKey, config: MARKETPLACE_CONFIGS[mpKey] };
  }
  
  // Match su tags
  for (const [pattern, mpKey] of Object.entries(SOURCE_NAME_MAP)) {
    if (tags.includes(pattern)) return { key: mpKey, config: MARKETPLACE_CONFIGS[mpKey] };
  }
  
  const defaultKey = process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE';
  return { key: defaultKey, config: MARKETPLACE_CONFIGS[defaultKey] };
}

function hasJDTag(productTagsString) {
  if (!productTagsString) return false;
  const tags = productTagsString.split(',').map(t => t.trim());
  const regex = /(^|[\s,\-_])JD([\s,\-_]|$)/i;
  return tags.some(tag => regex.test(tag));
}

async function fetchProductsTags(productIds, cache = {}) {
  const toFetch = productIds.filter(id => id && !(id in cache));
  if (toFetch.length === 0) return cache;
  const token = await getShopifyAccessToken();
  const chunks = [];
  for (let i = 0; i < toFetch.length; i += 100) chunks.push(toFetch.slice(i, i + 100));
  for (const chunk of chunks) {
    try {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?ids=${chunk.join(',')}&fields=id,tags`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      if (!response.ok) continue;
      const data = await response.json();
      (data.products || []).forEach(p => { cache[p.id] = p.tags || ''; });
      chunk.forEach(id => { if (!(id in cache)) cache[id] = ''; });
    } catch (e) {
      chunk.forEach(id => { if (!(id in cache)) cache[id] = ''; });
    }
  }
  return cache;
}

async function applyJDFilter(ordini) {
  const jdOrders = ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE');
  if (jdOrders.length === 0) return ordini;
  const productIdsSet = new Set();
  jdOrders.forEach(o => (o.line_items || []).forEach(item => { if (item.product_id) productIdsSet.add(item.product_id); }));
  const tagsCache = await fetchProductsTags([...productIdsSet]);
  return ordini.map(o => {
    if (riconosciMarketplace(o).key !== 'JAMMY_DUDE') return o;
    const filteredItems = (o.line_items || []).filter(item => hasJDTag(tagsCache[item.product_id]));
    return { ...o, line_items: filteredItems, _jd_excluded: filteredItems.length === 0 };
  }).filter(o => !o._jd_excluded);
}

// ============ CONTROLLO MARGINI DUOMO (v5.15) ============
// Catalogo DUOMO attivo letto con una bulk operation Shopify (asincrona) e analizzato con le regole del controllo mattutino.
const DUO_RULES = {
  iva: 1.22,
  soglia_mp: 0.07,
  miinto_sped: 16.5,
  miinto_campagna_pct: 0.035,
  // dal 01/11/2026 commissione unica 21,5% sul prezzo senza IVA (include transaction fee); prima 21,66% senza IVA + 2,25% con IVA
  miintoFee(prezzoLordo, giornoISO) {
    const netto = prezzoLordo / 1.22;
    if (giornoISO >= '2026-11-01') return netto * 0.215;
    return netto * 0.2166 + prezzoLordo * 0.0225;
  },
  campagneMiinto: [['2026-10-25','2026-11-01'],['2026-11-08','2026-11-09'],['2026-11-15','2026-11-17'],['2026-11-22','2026-11-30'],['2026-12-26','2026-12-30']]
};
function isCampagnaMiinto(giornoISO) { return DUO_RULES.campagneMiinto.some(([a, b]) => giornoISO >= a && giornoISO <= b); }

async function shopifyGraphQL(query, variables = {}) {
  const token = await getShopifyAccessToken();
  const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/graphql.json`, { method: 'POST', headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ query, variables }) });
  if (!r.ok) throw new Error(`Shopify GraphQL HTTP ${r.status}`);
  const j = await r.json();
  if (j.errors) throw new Error('Shopify GraphQL: ' + JSON.stringify(j.errors).slice(0, 300));
  return j.data;
}

const DUO_BULK_QUERY = `{ products(query: "tag:'TLX_PRODUCT:DUO' AND status:active") { edges { node { id handle title vendor productType tags metafield(namespace: "custom", key: "prezzo_miinto") { value } variants { edges { node { id sku price compareAtPrice inventoryQuantity inventoryItem { unitCost { amount } } } } } } } } }`;

function analizzaCatalogoDuo(jsonl, giornoISO) {
  const prodotti = new Map();
  for (const line of jsonl.split('\n')) {
    if (!line.trim()) continue;
    const o = JSON.parse(line);
    if (o.__parentId) { const p = prodotti.get(o.__parentId); if (p) p.varianti.push(o); }
    else prodotti.set(o.id, { ...o, varianti: [] });
  }
  const campagna = isCampagnaMiinto(giornoISO);
  const out = { prodotti_attivi: prodotti.size, senza_costo: 0, sito_negativi: [], sito_extra_sconto_negativi: [], miinto_sotto_soglia: [], miinto_prezzo_fuori_regola: [] };
  for (const p of prodotti.values()) {
    const prezzi = p.varianti.map(v => parseFloat(v.price)).filter(x => x > 0);
    const rrps = p.varianti.map(v => parseFloat(v.compareAtPrice)).filter(x => x > 0);
    const costi = p.varianti.map(v => parseFloat(v.inventoryItem?.unitCost?.amount)).filter(x => x > 0);
    if (!prezzi.length || !costi.length) { out.senza_costo++; continue; }
    const prezzo = Math.min(...prezzi), costo = Math.max(...costi), rrp = rrps.length ? Math.max(...rrps) : prezzo;
    const tags = (p.tags || []).map(t => String(t).toLowerCase());
    const stock = p.varianti.reduce((s, v) => s + Math.max(0, v.inventoryQuantity || 0), 0);
    const base = { handle: p.handle, titolo: p.title, brand: p.vendor, categoria: p.productType, stock, costo: Math.round(costo * 100) / 100, rrp };
    const netto = prezzo / DUO_RULES.iva;
    const margSito = netto - costo;
    if (margSito < 0) out.sito_negativi.push({ ...base, prezzo, margine: Math.round(margSito), margine_pct: Math.round(margSito / netto * 1000) / 10 });
    const extra = tags.includes('discount_20') ? 0.20 : tags.includes('discount_15') ? 0.15 : tags.includes('discount_10') ? 0.10 : 0;
    if (extra) {
      const nettoEx = prezzo * (1 - extra) / DUO_RULES.iva; const m = nettoEx - costo;
      if (m < 0) out.sito_extra_sconto_negativi.push({ ...base, prezzo: Math.round(prezzo * (1 - extra) * 100) / 100, sconto_extra: extra * 100, margine: Math.round(m), margine_pct: Math.round(m / nettoEx * 1000) / 10 });
    }
    if (tags.includes('miinto meta price set')) {
      const pm = parseFloat(p.metafield?.value) || rrp;
      const nettoM = pm / DUO_RULES.iva;
      const fee = DUO_RULES.miintoFee(pm, giornoISO) + (campagna ? pm * DUO_RULES.miinto_campagna_pct : 0);
      const m = nettoM - fee - DUO_RULES.miinto_sped - costo;
      const mp = m / nettoM;
      if (mp < DUO_RULES.soglia_mp) out.miinto_sotto_soglia.push({ ...base, prezzo_miinto: pm, margine: Math.round(m), margine_pct: Math.round(mp * 1000) / 10 });
      const atteso = campagna ? Math.round(rrp * 1.0599) : rrp;
      if (Math.abs(pm - atteso) > 1) out.miinto_prezzo_fuori_regola.push({ ...base, prezzo_miinto: pm, atteso });
    }
  }
  const byM = (a, b) => a.margine - b.margine;
  out.sito_negativi.sort(byM); out.sito_extra_sconto_negativi.sort(byM); out.miinto_sotto_soglia.sort(byM);
  return { generato_il: new Date().toISOString(), giorno: giornoISO, campagna_miinto_oggi: campagna, regole: { iva: '22%', miinto: giornoISO >= '2026-11-01' ? 'commissione unica 21,5% + sped. 16,50€' : '21,66% + 2,25% + sped. 16,50€', soglia_marketplace: '7%' }, ...out };
}

// ============ PANNELLO CANALI (v5.16) ============
// Ordine: Miinto (sett/sett) → TLuxy diretto (giorno/giorno + fonti) → Winkelstraat (sett/sett) → The Bradery (private sale vs precedente) → altri.
function fonteOrdineSito(o) {
  const land = String(o.landing_site || '').toLowerCase();
  const ref = String(o.referring_site || '').toLowerCase();
  const q = (k) => { const m = land.match(new RegExp('[?&]' + k + '=([^&#]*)')); return m ? decodeURIComponent(m[1]) : ''; };
  const src = q('utm_source'), med = q('utm_medium');
  if (land.includes('gclid=') || land.includes('gbraid=') || land.includes('wbraid=') || (/google/.test(src) && /cpc|ppc|paid/.test(med))) return 'Google Ads';
  if (land.includes('fbclid=') || /facebook|instagram|^fb$|^ig$|meta/.test(src) || /facebook\.|instagram\./.test(ref)) return 'Meta (IG/FB)';
  if (/omnisend|klaviyo|newsletter|email/.test(src) || med === 'email') return 'Email';
  if (/whatsapp|textyess/.test(src) || /whatsapp/.test(ref)) return 'WhatsApp';
  if (/google\./.test(ref) || /bing\.|yahoo\.|duckduckgo/.test(ref)) return 'Ricerca organica';
  if (src) return 'Altro: ' + src;
  if (!ref) return 'Diretto';
  try { return 'Altro: ' + new URL(ref).hostname.replace(/^www\./, ''); } catch (e) { return 'Altro'; }
}

function calcolaPannelloCanali(ordini) {
  const D = 86400000, now = Date.now();
  const romaOggi = getRomeDateString();
  const inizioOggi = romeDateTimeToUTC(romaOggi, '00:00:00').getTime();
  const righe = [];
  for (const o of ordini) {
    if (o.cancelled_at) continue;
    const t = new Date(o.created_at).getTime(); if (isNaN(t)) continue;
    const ref = getOrderRefundInfo(o); if (ref.isFullRefund) continue;
    const mp = riconosciMarketplace(o);
    const cur = getOrderCurrencyInfo(o);
    righe.push({ t, key: mp.key, nome: (mp.config && mp.config.nome) || mp.key, eur: Math.max(0, (cur.eurTotal || 0) - (ref.totalRefundedEur || 0)), o });
  }
  const somma = (arr) => ({ ordini: arr.length, fatturato: Math.round(arr.reduce((s, r) => s + r.eur, 0)) });
  const varPct = (a, b) => b > 0 ? Math.round((a - b) / b * 100) : (a > 0 ? null : 0);
  const finestra = (key, da, a) => somma(righe.filter(r => r.key === key && r.t >= da && r.t < a));
  const settimana = (key) => {
    const cur = finestra(key, now - 7 * D, now), prev = finestra(key, now - 14 * D, now - 7 * D);
    return { corrente: cur, precedente: prev, variazione_pct: varPct(cur.fatturato, prev.fatturato) };
  };
  const alerts = [];
  const sezioni = [];

  // 1) Miinto — settimana su settimana
  const mi = settimana('MIINTO');
  const miStato = mi.precedente.ordini >= 3 && mi.corrente.ordini === 0 ? 'critico' : (mi.variazione_pct !== null && mi.variazione_pct <= -40 && mi.precedente.ordini >= 3 ? 'attenzione' : 'ok');
  if (miStato !== 'ok') alerts.push({ livello: miStato, nome: 'Miinto', messaggio: `ultimi 7 giorni €${mi.corrente.fatturato} (${mi.corrente.ordini} ordini) contro €${mi.precedente.fatturato} (${mi.precedente.ordini}) della settimana prima` });
  const giorno = (key) => {
    const rr = righe.filter(r => r.key === key);
    const oggi = somma(rr.filter(r => r.t >= inizioOggi)), ieriStessaOra = somma(rr.filter(r => r.t >= inizioOggi - D && r.t < now - D));
    const ieri = somma(rr.filter(r => r.t >= inizioOggi - D && r.t < inizioOggi)), altroIeri = somma(rr.filter(r => r.t >= inizioOggi - 2 * D && r.t < inizioOggi - D));
    return { oggi, ieri_stessa_ora: ieriStessaOra, variazione_oggi_pct: varPct(oggi.fatturato, ieriStessaOra.fatturato), ieri, altro_ieri: altroIeri, variazione_ieri_pct: varPct(ieri.fatturato, altroIeri.fatturato) };
  };
  sezioni.push({ key: 'MIINTO', nome: 'Miinto', confronto: 'Giorno su giorno e settimana su settimana', stato: miStato, ...mi, giorno: giorno('MIINTO') });

  // 2) TLuxy diretto — giorno su giorno + fonti
  const sito = righe.filter(r => r.key === 'TLUXY_SITE');
  const oggi = somma(sito.filter(r => r.t >= inizioOggi));
  const ieriStessaOra = somma(sito.filter(r => r.t >= inizioOggi - D && r.t < now - D));
  const ieri = somma(sito.filter(r => r.t >= inizioOggi - D && r.t < inizioOggi));
  const altroIeri = somma(sito.filter(r => r.t >= inizioOggi - 2 * D && r.t < inizioOggi - D));
  const fonti7 = {};
  sito.filter(r => r.t >= now - 7 * D).forEach(r => { const f = fonteOrdineSito(r.o); fonti7[f] = fonti7[f] || { fonte: f, ordini: 0, fatturato: 0 }; fonti7[f].ordini++; fonti7[f].fatturato += r.eur; });
  const fontiOggi = {};
  sito.filter(r => r.t >= inizioOggi).forEach(r => { const f = fonteOrdineSito(r.o); fontiOggi[f] = (fontiOggi[f] || 0) + 1; });
  sezioni.push({ key: 'TLUXY_SITE', nome: 'TLuxy diretto', confronto: 'Oggi vs ieri alla stessa ora', stato: 'info',
    oggi, ieri_stessa_ora: ieriStessaOra, variazione_pct: varPct(oggi.fatturato, ieriStessaOra.fatturato), ieri, altro_ieri: altroIeri, variazione_ieri_pct: varPct(ieri.fatturato, altroIeri.fatturato),
    settimana: settimana('TLUXY_SITE'),
    fonti_7gg: Object.values(fonti7).map(f => ({ ...f, fatturato: Math.round(f.fatturato) })).sort((a, b) => b.fatturato - a.fatturato),
    fonti_oggi: fontiOggi });

  // 3) Winkelstraat — settimana su settimana
  const wk = settimana('WINKELSTRAAT');
  const wkStato = wk.precedente.ordini >= 3 && wk.corrente.ordini === 0 ? 'critico' : (wk.variazione_pct !== null && wk.variazione_pct <= -40 && wk.precedente.ordini >= 3 ? 'attenzione' : 'ok');
  if (wkStato !== 'ok') alerts.push({ livello: wkStato, nome: 'Winkelstraat', messaggio: `ultimi 7 giorni €${wk.corrente.fatturato} (${wk.corrente.ordini} ordini) contro €${wk.precedente.fatturato} (${wk.precedente.ordini})` });
  sezioni.push({ key: 'WINKELSTRAAT', nome: 'Winkelstraat', confronto: 'Ultimi 7 giorni vs 7 precedenti', stato: wkStato, ...wk, giorno: giorno('WINKELSTRAAT') });

  // 4) The Bradery — private sale vs private sale (una vendita = ordini senza pause > 4 giorni)
  const br = righe.filter(r => r.key === 'THE_BRADERY').sort((a, b) => a.t - b.t);
  const vendite = [];
  for (const r of br) { const v = vendite[vendite.length - 1]; if (!v || r.t - v.fine > 4 * D) vendite.push({ inizio: r.t, fine: r.t, righe: [r] }); else { v.fine = r.t; v.righe.push(r); } }
  const descr = (v) => v ? { dal: new Date(v.inizio).toISOString(), al: new Date(v.fine).toISOString(), giorni: Math.max(1, Math.ceil((v.fine - v.inizio) / D) + 1), ...somma(v.righe) } : null;
  const ultima = vendite[vendite.length - 1], precedente = vendite[vendite.length - 2];
  const inCorso = !!(ultima && now - ultima.fine < 3 * D);
  let brStato = 'ok', brConfronto = null;
  if (inCorso && precedente) {
    const giorniTrascorsi = Math.max(1, Math.ceil((now - ultima.inizio) / D));
    const precStessiGiorni = somma(precedente.righe.filter(r => r.t < precedente.inizio + giorniTrascorsi * D));
    brConfronto = { giorni: giorniTrascorsi, corrente: somma(ultima.righe), precedente_stessi_giorni: precStessiGiorni, variazione_pct: varPct(somma(ultima.righe).fatturato, precStessiGiorni.fatturato) };
    if (brConfronto.variazione_pct !== null && brConfronto.variazione_pct <= -30) { brStato = 'attenzione'; alerts.push({ livello: 'attenzione', nome: 'The Bradery', messaggio: `private sale in corso: primi ${giorniTrascorsi} giorni €${brConfronto.corrente.fatturato} contro €${precStessiGiorni.fatturato} della vendita precedente negli stessi giorni` }); }
  }
  sezioni.push({ key: 'THE_BRADERY', nome: 'The Bradery', confronto: 'Private sale vs private sale precedente', stato: inCorso ? brStato : 'pausa', in_corso: inCorso, ultima_vendita: descr(ultima), vendita_precedente: descr(precedente), confronto_in_corso: brConfronto, giorno: giorno('THE_BRADERY') });

  // 5) Altri canali — sett/sett, compatti
  const principali = new Set(['MIINTO', 'TLUXY_SITE', 'WINKELSTRAAT', 'THE_BRADERY']);
  const altriKeys = [...new Set(righe.filter(r => !principali.has(r.key) && r.t >= now - 28 * D).map(r => r.key))];
  const altri = altriKeys.map(k => { const w = settimana(k); const nome = (MARKETPLACE_CONFIGS[k] && MARKETPLACE_CONFIGS[k].nome) || k; return { key: k, nome, ...w }; })
    .sort((a, b) => (b.corrente.fatturato + b.precedente.fatturato) - (a.corrente.fatturato + a.precedente.fatturato));
  return { generato_il: new Date().toISOString(), alerts, sezioni, altri };
}

// ============ ALERT CANALI LENTI (v5.14) ============
// Confronta gli ultimi `giorni` giorni con la media settimanale delle 4 settimane precedenti, per marketplace.
// Esclude ordini cancellati e rimborsati totalmente. Considera "attivo" un canale con almeno `minOrdiniSett` ordini/settimana di media.
function calcolaAlertCanali(ordini, opts = {}) {
  const giorni = opts.giorni || 7;
  const settimaneBase = opts.settimaneBase || 4;
  const soglia = opts.soglia ?? 0.5;            // calo minimo per alert (0.5 = -50%)
  const minOrdiniSett = opts.minOrdiniSett ?? 1.5;
  const now = Date.now();
  const msGiorno = 86400000;
  const inizioRecente = now - giorni * msGiorno;
  const inizioBase = inizioRecente - settimaneBase * 7 * msGiorno;
  const canali = {};
  for (const o of ordini) {
    if (o.cancelled_at) continue;
    const t = new Date(o.created_at).getTime();
    if (isNaN(t) || t < inizioBase) continue;
    const ref = getOrderRefundInfo(o);
    if (ref.isFullRefund) continue;
    const mp = riconosciMarketplace(o);
    const cur = getOrderCurrencyInfo(o);
    const valore = Math.max(0, (cur.eurTotal || 0) - (ref.totalRefundedEur || 0));
    const c = canali[mp.key] || (canali[mp.key] = { key: mp.key, nome: (mp.config && mp.config.nome) || mp.key, ordini_recenti: 0, fatturato_recente: 0, ordini_base: 0, fatturato_base: 0, ultimo_ordine: null });
    if (t >= inizioRecente) { c.ordini_recenti++; c.fatturato_recente += valore; }
    else { c.ordini_base++; c.fatturato_base += valore; }
    if (!c.ultimo_ordine || t > new Date(c.ultimo_ordine).getTime()) c.ultimo_ordine = o.created_at;
  }
  const alerts = [];
  const riepilogo = Object.values(canali).map(c => {
    const mediaOrd = c.ordini_base / settimaneBase * (giorni / 7);
    const mediaFat = c.fatturato_base / settimaneBase * (giorni / 7);
    const giorniUltimo = c.ultimo_ordine ? Math.floor((now - new Date(c.ultimo_ordine).getTime()) / msGiorno) : null;
    const variazione = mediaFat > 0 ? (c.fatturato_recente - mediaFat) / mediaFat : null;
    const attivo = mediaOrd >= minOrdiniSett * (giorni / 7);
    const r = { ...c, fatturato_recente: Math.round(c.fatturato_recente), fatturato_base: Math.round(c.fatturato_base), media_ordini: Math.round(mediaOrd * 10) / 10, media_fatturato: Math.round(mediaFat), variazione_pct: variazione === null ? null : Math.round(variazione * 100), giorni_da_ultimo_ordine: giorniUltimo, attivo, stato: 'ok' };
    if (attivo && c.ordini_recenti === 0) {
      r.stato = 'fermo';
      alerts.push({ livello: 'critico', key: c.key, nome: c.nome, messaggio: `Nessun ordine da ${giorniUltimo ?? giorni} giorni (di solito ~${Math.round(mediaOrd)} ordini ogni ${giorni} giorni)` });
    } else if (attivo && variazione !== null && variazione <= -soglia && c.ordini_recenti < mediaOrd) {
      r.stato = 'in_calo';
      alerts.push({ livello: 'attenzione', key: c.key, nome: c.nome, messaggio: `Vendite ${Math.round(variazione * 100)}% rispetto alla media: €${Math.round(c.fatturato_recente).toLocaleString('it-IT')} contro ~€${Math.round(mediaFat).toLocaleString('it-IT')} (${c.ordini_recenti} ordini contro ~${Math.round(mediaOrd)})` });
    }
    return r;
  }).sort((a, b) => b.media_fatturato - a.media_fatturato);
  alerts.sort((a, b) => (a.livello === 'critico' ? 0 : 1) - (b.livello === 'critico' ? 0 : 1));
  return { generato_il: new Date().toISOString(), finestra_giorni: giorni, settimane_confronto: settimaneBase, soglia_calo_pct: Math.round(soglia * 100), alerts, canali: riepilogo };
}

async function processOrders(ordini) {
  const jdOrdersOriginalIds = new Set(ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE').map(o => o.id));
  const filtered = await applyJDFilter(ordini);
  return filtered.map(o => {
    if (jdOrdersOriginalIds.has(o.id)) {
      const newTotal = (o.line_items || []).reduce((sum, item) => sum + (parseFloat(item.price) || 0) * (parseInt(item.quantity) || 0), 0);
      return { ...o, total_price: String(newTotal.toFixed(2)), total_tax: '0.00' };
    }
    return o;
  });
}

// ============ COSTO REALE (v4.3 - strategia products/{id}.json con logging) ============
// Strategia: per ogni product_id unico, 1 chiamata a /products/{id}.json che ritorna
// tutte le varianti del prodotto con i loro inventory_item_id. Poi batch /inventory_items.json
// Aggiunge logging dettagliato delle chiamate fallite.
// v5.27: costi e immagini via GraphQL (100 varianti per chiamata) — molto più veloce del REST prodotto-per-prodotto
const MEM_VARIANT_IMG = new Map();
async function infoVariantiGraphQL(variantIds) {
  const out = {};
  const ids = [...new Set(variantIds.filter(Boolean).map(String))];
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    try {
      const d = await shopifyGraphQL('query($ids:[ID!]!){ nodes(ids:$ids){ ... on ProductVariant { id inventoryItem { unitCost { amount } } image { url } product { featuredImage { url } } } } }', { ids: chunk.map(v => 'gid://shopify/ProductVariant/' + v) });
      (d.nodes || []).forEach(n => {
        if (!n || !n.id) return;
        const vid = n.id.split('/').pop();
        const c = n.inventoryItem && n.inventoryItem.unitCost ? parseFloat(n.inventoryItem.unitCost.amount) : null;
        const img = (n.image && n.image.url) || (n.product && n.product.featuredImage && n.product.featuredImage.url) || null;
        out[vid] = { costo: (c !== null && !isNaN(c)) ? c : null, immagine: img };
        if (img) MEM_VARIANT_IMG.set(vid, img);
      });
    } catch (e) { console.log('[gql costi] errore', e.message); }
  }
  return out;
}
const MEM_VARIANT_COST = new Map(); // cache in memoria (istanza calda) — utile se il KV non risponde
async function fetchVariantCosts(variantIds, orderProductIds = []) {
  const stats = { products_tentati: 0, products_ok: 0, products_falliti: [], variants_mappati: 0, inventory_tentati: 0, inventory_ok: 0, inventory_falliti: [], kv_hit: 0, kv_miss: 0, kv_new_saved: 0 };
  if (variantIds.length === 0) return { costs: {}, stats };
  
  const uniqueVariantIds = [...new Set(variantIds.filter(Boolean))];
  const costsFromKV = {};
  
  // STEP 0: PROVO A LEGGERE DAL KV (cache persistente) PRIMA di chiamare Shopify
  if (KV_ENABLED) {
    const kvKeys = uniqueVariantIds.map(v => `variant_cost_${v}`);
    const kvResults = await kvMGet(kvKeys);
    uniqueVariantIds.forEach(v => {
      const key = `variant_cost_${v}`;
      if (kvResults[key] !== undefined) {
        const parsed = parseFloat(kvResults[key]);
        if (!isNaN(parsed)) { costsFromKV[v] = parsed; stats.kv_hit++; }
        else stats.kv_miss++;
      } else stats.kv_miss++;
    });
  }
  
  uniqueVariantIds.forEach(v => { if (!(v in costsFromKV) && MEM_VARIANT_COST.has(v)) costsFromKV[v] = MEM_VARIANT_COST.get(v); });
  // Solo variant_id che NON abbiamo già nel KV vanno chiamati su Shopify
  const variantsToFetch = uniqueVariantIds.filter(v => !(v in costsFromKV));
  const uniqueProductIds = [...new Set(orderProductIds.filter(Boolean))];
  const variantToInventoryItem = {};
  
  // Se tutti i variant sono in cache, skip le chiamate Shopify
  if (variantsToFetch.length === 0) {
    return { costs: costsFromKV, stats };
  }
  // v5.27: prima GraphQL (veloce); il REST resta solo per le varianti non trovate
  {
    const gq = await infoVariantiGraphQL(variantsToFetch);
    const nuovi = {};
    Object.entries(gq).forEach(([vid, info]) => { if (info.costo !== null) { costsFromKV[vid] = info.costo; MEM_VARIANT_COST.set(vid, info.costo); nuovi['variant_cost_' + vid] = String(info.costo); } });
    if (KV_ENABLED && Object.keys(nuovi).length) { try { await kvMSet(nuovi); } catch (e) {} }
    const ancora = variantsToFetch.filter(v => !(v in costsFromKV));
    if (ancora.length === 0) {
      uniqueVariantIds.forEach(v => { if (!(v in costsFromKV)) costsFromKV[v] = null; });
      return { costs: costsFromKV, stats };
    }
    variantsToFetch.length = 0; ancora.forEach(v => variantsToFetch.push(v));
  }
  
  const token = await getShopifyAccessToken();
  
  // STEP 1: per ogni product_id, chiamo /products/{id}.json (funziona sempre)
  async function fetchProductWithRetry(pid, attempt = 0) {
    stats.products_tentati++;
    try {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products/${pid}.json?fields=id,variants`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      if (response.status === 429 || response.status >= 500) {
        if (attempt < 4) {
          const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
          await new Promise(r => setTimeout(r, wait));
          return fetchProductWithRetry(pid, attempt + 1);
        }
        stats.products_falliti.push({ product_id: pid, status: response.status, reason: 'max_retries' });
        return;
      }
      if (!response.ok) {
        stats.products_falliti.push({ product_id: pid, status: response.status, reason: 'http_error' });
        return;
      }
      const data = await response.json();
      stats.products_ok++;
      (data.product?.variants || []).forEach(v => {
        if (v.id && v.inventory_item_id) {
          variantToInventoryItem[v.id] = v.inventory_item_id;
          stats.variants_mappati++;
        }
      });
    } catch (e) {
      if (attempt < 3) {
        await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
        return fetchProductWithRetry(pid, attempt + 1);
      }
      stats.products_falliti.push({ product_id: pid, status: 'exception', reason: e.message });
    }
  }
  
  const concurrency = 3;
  for (let i = 0; i < uniqueProductIds.length; i += concurrency) {
    const batch = uniqueProductIds.slice(i, i + concurrency);
    await Promise.all(batch.map(p => fetchProductWithRetry(p)));
  }
  
  // STEP 1b: per variant non trovate tramite product, fallback a /variants/{id}.json
  const missing = uniqueVariantIds.filter(vid => !(vid in variantToInventoryItem));
  if (missing.length > 0) {
    async function fetchVariantSingle(vid, attempt = 0) {
      try {
        const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/variants/${vid}.json?fields=id,inventory_item_id`;
        const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
        if (response.status === 429 || response.status >= 500) {
          if (attempt < 4) {
            const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
            await new Promise(r => setTimeout(r, wait));
            return fetchVariantSingle(vid, attempt + 1);
          }
          return;
        }
        if (!response.ok) return;
        const data = await response.json();
        if (data.variant && data.variant.inventory_item_id) {
          variantToInventoryItem[vid] = data.variant.inventory_item_id;
          stats.variants_mappati++;
        }
      } catch (e) {
        if (attempt < 3) {
          await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
          return fetchVariantSingle(vid, attempt + 1);
        }
      }
    }
    for (let i = 0; i < missing.length; i += concurrency) {
      const batch = missing.slice(i, i + concurrency);
      await Promise.all(batch.map(v => fetchVariantSingle(v)));
    }
  }
  
  // STEP 2: batch /inventory_items.json?ids= (questo endpoint supporta ids multipli)
  const inventoryIds = [...new Set(Object.values(variantToInventoryItem).filter(Boolean))];
  const inventoryToCost = {};
  const invChunks = [];
  for (let i = 0; i < inventoryIds.length; i += 50) invChunks.push(inventoryIds.slice(i, i + 50)); // chunk 50 invece di 100 per sicurezza
  
  async function fetchInvWithRetry(chunk, attempt = 0) {
    stats.inventory_tentati++;
    try {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${chunk.join(',')}`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      if (response.status === 429 || response.status >= 500) {
        if (attempt < 4) {
          const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
          await new Promise(r => setTimeout(r, wait));
          return fetchInvWithRetry(chunk, attempt + 1);
        }
        stats.inventory_falliti.push({ chunk_size: chunk.length, status: response.status, reason: 'max_retries' });
        return;
      }
      if (!response.ok) {
        stats.inventory_falliti.push({ chunk_size: chunk.length, status: response.status, reason: 'http_error' });
        return;
      }
      const data = await response.json();
      stats.inventory_ok++;
      (data.inventory_items || []).forEach(item => {
        const costValue = item.cost;
        inventoryToCost[item.id] = (costValue !== null && costValue !== undefined && costValue !== '' && !isNaN(parseFloat(costValue))) ? parseFloat(costValue) : null;
      });
    } catch (e) {
      if (attempt < 3) {
        await new Promise(r => setTimeout(r, 600 * (attempt + 1)));
        return fetchInvWithRetry(chunk, attempt + 1);
      }
      stats.inventory_falliti.push({ chunk_size: chunk.length, status: 'exception', reason: e.message });
    }
  }
  
  for (const chunk of invChunks) {
    await fetchInvWithRetry(chunk);
  }
  
  // Map finale + salvataggio KV dei NUOVI costi letti
  const newCostsFromShopify = {};
  Object.entries(variantToInventoryItem).forEach(([variantId, invId]) => {
    const cost = invId && inventoryToCost[invId] !== undefined ? inventoryToCost[invId] : null;
    if (cost !== null && cost !== undefined) newCostsFromShopify[variantId] = cost;
  });
  
  // SALVA i nuovi costi su KV per il futuro (anche se il prodotto sarà cancellato)
  if (KV_ENABLED && Object.keys(newCostsFromShopify).length > 0) {
    const kvPairs = {};
    Object.entries(newCostsFromShopify).forEach(([vid, cost]) => {
      kvPairs[`variant_cost_${vid}`] = String(cost);
    });
    await kvMSet(kvPairs);
    stats.kv_new_saved = Object.keys(kvPairs).length;
  }
  
  // Merge: costi da KV (già persistenti) + costi nuovi letti da Shopify
  const costs = { ...costsFromKV, ...newCostsFromShopify };
  Object.entries(costs).forEach(([v, c]) => { if (c !== null && c !== undefined) MEM_VARIANT_COST.set(v, c); });
  // Aggiungo null per i variant che Shopify non ha restituito e che non erano in KV
  uniqueVariantIds.forEach(v => { if (!(v in costs)) costs[v] = null; });
  
  return { costs, stats };
}

function calcolaCostoOrdine(ordine, variantCosts, duoUserCosts = {}) {
  let costo_totale = 0;
  const errori = [];
  for (const item of (ordine.line_items || [])) {
    const quantity = parseInt(item.quantity) || 0;
    let costUnit = item.variant_id ? variantCosts[item.variant_id] : null;
    // Fallback: per prodotti DUO, usa il costo inserito manualmente dall'utente nel simulatore
    if ((costUnit === null || costUnit === undefined) && isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) {
      costUnit = duoUserCosts[item.variant_id];
    }
    if (costUnit === null || costUnit === undefined) {
      errori.push({ title: item.title, sku: item.sku || '', variant_id: item.variant_id, is_duo: isDuoSku(item.sku) });
      continue;
    }
    costo_totale += costUnit * quantity;
  }
  return { costo: costo_totale, errori };
}

function calcolaFeesShopify(prezzo_netto, mpKey) {
  if (mpKey !== 'TLUXY_SITE') return 0;
  return prezzo_netto * SHOPIFY_FEE_PERCENT + SHOPIFY_FEE_FIXED;
}

function calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce, spedizione, mp, mpKey) {
  const prezzo_netto_iva = prezzo_lordo - iva_scorporata;
  const prezzo_netto_marketplace = prezzo_netto_iva * (1 - mp.sconto_percentuale / 100);
  const fees_shopify = calcolaFeesShopify(prezzo_netto_marketplace, mpKey);
  const fee_principale = prezzo_netto_marketplace * (mp.fee_principale / 100);
  const fee_secondaria = prezzo_netto_marketplace * ((mp.fee_secondaria || 0) / 100);
  const fee_accessoria = prezzo_netto_marketplace * ((mp.fee_accessoria || 0) / 100);
  const fees_marketplace = fee_principale + fee_secondaria + fee_accessoria + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine_netto = prezzo_netto_marketplace - fees_shopify - fees_marketplace - costo_merce - spedizione;
  const margine_percentuale = prezzo_lordo > 0 ? (margine_netto / prezzo_lordo * 100) : 0;
  const costi_totali = costo_merce + spedizione + fees_shopify + fees_marketplace + iva_scorporata;
  return { prezzo_lordo_iva_inclusa: prezzo_lordo, iva_scorporata, prezzo_netto_iva, prezzo_netto_marketplace, fees_shopify, fees_marketplace, costo_merce, spedizione, costi_totali, margine_netto, margine_percentuale: parseFloat(margine_percentuale.toFixed(2)) };
}

// ============ FUSO ORARIO EUROPE/ROME REALE ============
// Ottiene la data di oggi in formato YYYY-MM-DD secondo il fuso di Roma
function getRomeDateString(date = new Date()) {
  // Usa Intl per ottenere data reale a Roma (gestisce automaticamente DST)
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Rome',
    year: 'numeric', month: '2-digit', day: '2-digit'
  });
  return formatter.format(date); // es. "2026-04-20"
}

// Ottiene offset in minuti di Roma per una data specifica (gestisce DST)
function getRomeOffset(date) {
  const romeStr = date.toLocaleString('en-US', { timeZone: 'Europe/Rome' });
  const utcStr = date.toLocaleString('en-US', { timeZone: 'UTC' });
  const rome = new Date(romeStr);
  const utc = new Date(utcStr);
  return (rome - utc) / 60000; // minuti
}

// Converte una data Rome (YYYY-MM-DD HH:mm:ss) in Date UTC
function romeDateTimeToUTC(dateStr, timeStr = '00:00:00') {
  // Creiamo una data ipotetica locale e calcoliamo l'offset Roma per quel momento
  const testDate = new Date(dateStr + 'T' + timeStr + 'Z');
  const offsetMin = getRomeOffset(testDate);
  // Invertiamo: se Roma è UTC+2, dobbiamo sottrarre 2 ore per ottenere l'UTC
  return new Date(testDate.getTime() - offsetMin * 60000);
}

function getDateRange(periodo, dateFromCustom, dateToCustom) {
  let dateFrom, dateTo;
  if (dateFromCustom && dateToCustom) {
    dateFrom = romeDateTimeToUTC(dateFromCustom, '00:00:00');
    dateTo = romeDateTimeToUTC(dateToCustom, '23:59:59');
    return { dateFrom, dateTo };
  }
  
  const romeToday = getRomeDateString(); // es. "2026-04-20"
  const now = new Date();
  
  switch(periodo) {
    case 'today':
      dateFrom = romeDateTimeToUTC(romeToday, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      break;
    case 'yesterday': {
      // Calcola data di ieri a Roma
      const yesterdayRome = new Date(now.getTime() - 24*60*60*1000);
      const yesterdayStr = getRomeDateString(yesterdayRome);
      dateFrom = romeDateTimeToUTC(yesterdayStr, '00:00:00');
      dateTo = romeDateTimeToUTC(yesterdayStr, '23:59:59');
      break;
    }
    case 'week': {
      const weekAgo = new Date(now.getTime() - 7*24*60*60*1000);
      const weekAgoStr = getRomeDateString(weekAgo);
      dateFrom = romeDateTimeToUTC(weekAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      break;
    }
    case 'month': {
      const monthAgo = new Date(now.getTime() - 30*24*60*60*1000);
      const monthAgoStr = getRomeDateString(monthAgo);
      dateFrom = romeDateTimeToUTC(monthAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      break;
    }
    case 'quarter': {
      const qAgo = new Date(now.getTime() - 90*24*60*60*1000);
      const qAgoStr = getRomeDateString(qAgo);
      dateFrom = romeDateTimeToUTC(qAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      break;
    }
    case 'year': {
      const yAgo = new Date(now.getTime() - 365*24*60*60*1000);
      const yAgoStr = getRomeDateString(yAgo);
      dateFrom = romeDateTimeToUTC(yAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      break;
    }
    default:
      dateFrom = romeDateTimeToUTC(romeToday, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
  }
  return { dateFrom, dateTo };
}

async function getShopifyOrders(periodo = 'today', dateFromCustom = null, dateToCustom = null) {
  const token = await getShopifyAccessToken();
  const { dateFrom, dateTo } = getDateRange(periodo, dateFromCustom, dateToCustom);
  let allOrders = [];
  let url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&created_at_min=${dateFrom.toISOString()}&created_at_max=${dateTo.toISOString()}&limit=250`;
  let pageCount = 0;
  const maxPages = 20;
  while (url && pageCount < maxPages) {
    const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    allOrders = allOrders.concat(data.orders || []);
    const linkHeader = response.headers.get('link') || response.headers.get('Link');
    url = null;
    if (linkHeader) { const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/); if (nextMatch) url = nextMatch[1]; }
    pageCount++;
  }
  return allOrders;
}

function calcolaBestSellers(ordini, top = 20, variantCosts = {}) {
  const prodotti = {};
  ordini.forEach(ordine => {
    const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
    const ivaPerc = getIvaPerPaese(country);
    const ordCurrency = ordine.currency || SHOP_CURRENCY;
    (ordine.line_items || []).forEach(item => {
      const productId = item.product_id || item.variant_id || item.title;
      // PREZZO IN EUR (da price_set.shop_money quando disponibile)
      const prezzo_unit_lordo = toEurAmount(item.price_set, item.price, ordCurrency);
      const quantity = parseInt(item.quantity) || 0;
      const prezzo_unit_netto = prezzo_unit_lordo / (1 + ivaPerc / 100);
      const costo_unit_reale = item.variant_id && variantCosts[item.variant_id] != null ? variantCosts[item.variant_id] : 0;
      const fatturato_lordo = prezzo_unit_lordo * quantity;
      const fatturato_netto = prezzo_unit_netto * quantity;
      const costo_tot = costo_unit_reale * quantity;
      const ricavo_stimato = fatturato_netto - costo_tot;
      if (!prodotti[productId]) {
        prodotti[productId] = { product_id: item.product_id, variant_id: item.variant_id, titolo: item.title, variante: item.variant_title || '', sku: item.sku || '', vendor: item.vendor || '', prezzo_unit_lordo, prezzo_unit_netto, costo_unit: costo_unit_reale, quantita_venduta: 0, fatturato_lordo: 0, fatturato_netto: 0, ricavo_stimato: 0, immagine: null };
      }
      prodotti[productId].quantita_venduta += quantity;
      prodotti[productId].fatturato_lordo += fatturato_lordo;
      prodotti[productId].fatturato_netto += fatturato_netto;
      prodotti[productId].ricavo_stimato += ricavo_stimato;
    });
  });
  return Object.values(prodotti).sort((a, b) => b.fatturato_lordo - a.fatturato_lordo).slice(0, top);
}

// v5.27: Best seller per modello (colori raggruppati), per brand e per canale
function calcolaBestSellersModelli(ordini, variantCosts = {}) {
  const modelli = {}, brand = {}, canaliTot = {};
  let tot = { pezzi: 0, fatturato: 0, netto: 0, ncc: 0, costo: 0, ordini: 0, senza_costo: 0 };
  ordini.forEach(ordine => {
    if (ordine.cancelled_at) return;
    tot.ordini++;
    const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
    const ivaPerc = getIvaPerPaese(country);
    const ordCurrency = ordine.currency || SHOP_CURRENCY;
    const mp = riconosciMarketplace(ordine);
    const chKey = mp.key, chNome = (mp.config && mp.config.nome) || mp.key;
    (ordine.line_items || []).forEach(item => {
      const q = parseInt(item.quantity) || 0; if (!q) return;
      const mfP = chKey === 'MARK_FOYS' ? mfPrezzoRiga(item, ordine, variantCosts) : null;
      const lordo = mfP !== null ? mfP * q : toEurAmount(item.price_set, item.price, ordCurrency) * q;
      const netto = mfP !== null ? lordo : lordo / (1 + ivaPerc / 100);
      const cu = item.variant_id && variantCosts[item.variant_id] != null ? variantCosts[item.variant_id] : null;
      const costo = cu !== null ? cu * q : 0;
      const ncc = cu !== null ? netto : 0;
      const vend = (item.vendor || '').trim() || 'Altro';
      const vendKey = vend.toUpperCase();
      const titolo = (item.title || '').trim();
      const key = vendKey + '|' + titolo.toUpperCase().replace(/\s+/g, ' ');
      if (!modelli[key]) modelli[key] = { titolo, brand: vend, pezzi: 0, fatturato: 0, netto: 0, costo: 0, senza_costo: 0, ncc: 0, varianti: {}, canali: {}, variant_id: item.variant_id, immagine: null };
      const m = modelli[key];
      m.pezzi += q; m.fatturato += lordo; m.netto += netto; m.ncc += ncc; m.costo += costo; if (cu === null) m.senza_costo += q;
      const vt = item.variant_title || '—'; m.varianti[vt] = (m.varianti[vt] || 0) + q;
      if (!m.canali[chKey]) m.canali[chKey] = { nome: chNome, pezzi: 0, fatturato: 0 };
      m.canali[chKey].pezzi += q; m.canali[chKey].fatturato += lordo;
      if (!brand[vendKey]) brand[vendKey] = { brand: vend, pezzi: 0, fatturato: 0, netto: 0, ncc: 0, costo: 0, sito: 0 };
      const b = brand[vendKey]; b.pezzi += q; b.fatturato += lordo; b.netto += netto; b.ncc += ncc; b.costo += costo; if (chKey === 'TLUXY_SITE') b.sito += lordo;
      if (!canaliTot[chKey]) canaliTot[chKey] = { key: chKey, nome: chNome, pezzi: 0, fatturato: 0 };
      canaliTot[chKey].pezzi += q; canaliTot[chKey].fatturato += lordo;
      tot.pezzi += q; tot.fatturato += lordo; tot.netto += netto; tot.ncc += ncc; tot.costo += costo; if (cu === null) tot.senza_costo += q;
    });
  });
  const r0 = n => Math.round(n);
  const marg = x => x.ncc > 0 ? Math.round((x.ncc - x.costo) / x.ncc * 1000) / 10 : 0;
  const lista = Object.values(modelli).map(m => ({ titolo: m.titolo, brand: m.brand, pezzi: m.pezzi, fatturato: r0(m.fatturato), ricavo: r0(m.ncc - m.costo), margine_pct: marg(m), prezzo_medio: m.pezzi ? r0(m.fatturato / m.pezzi) : 0, senza_costo: m.senza_costo, variant_id: m.variant_id,
    varianti: Object.entries(m.varianti).sort((a, b) => b[1] - a[1]).map(([nome, pezzi]) => ({ nome, pezzi })),
    canali: Object.entries(m.canali).map(([k, c]) => ({ key: k, nome: c.nome, pezzi: c.pezzi, fatturato: r0(c.fatturato) })).sort((a, b) => b.fatturato - a.fatturato) }))
    .sort((a, b) => b.fatturato - a.fatturato);
  return {
    totali: { ordini: tot.ordini, pezzi: tot.pezzi, fatturato: r0(tot.fatturato), ricavo: r0(tot.ncc - tot.costo), margine_pct: marg(tot), pezzi_senza_costo: tot.senza_costo, modelli: lista.length },
    brand: Object.values(brand).map(b => ({ brand: b.brand, pezzi: b.pezzi, fatturato: r0(b.fatturato), ricavo: r0(b.ncc - b.costo), margine_pct: marg(b), quota_pct: tot.fatturato ? Math.round(b.fatturato / tot.fatturato * 1000) / 10 : 0, sito: r0(b.sito) })).sort((a, b) => b.fatturato - a.fatturato).slice(0, 15),
    canali: Object.values(canaliTot).map(c => ({ ...c, fatturato: r0(c.fatturato) })).sort((a, b) => b.fatturato - a.fatturato),
    modelli: lista.slice(0, 40)
  };
}

async function arricchisciConImmagini(prodotti) {
  if (prodotti.length === 0) return prodotti;
  try {
    const token = await getShopifyAccessToken();
    const productIds = prodotti.map(p => p.product_id).filter(Boolean).join(',');
    if (!productIds) return prodotti;
    const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?ids=${productIds}&fields=id,image,images`, { headers: { 'X-Shopify-Access-Token': token } });
    if (!response.ok) return prodotti;
    const data = await response.json();
    const imageMap = {};
    (data.products || []).forEach(p => { imageMap[p.id] = p.image?.src || (p.images?.[0]?.src) || null; });
    return prodotti.map(p => ({ ...p, immagine: imageMap[p.product_id] || null }));
  } catch (e) { return prodotti; }
}



// ============ v5.29 MARK FOY'S: incasso = prezzo B2B (EUR, senza IVA, nessuna commissione) ============
// Fonte 1: metafield prodotto custom.mark_foy_price. Fonte 2: scheda LISTINO del foglio "MARK FOY'S ORDERS" (Umberto).
// Fonte 3: prodotti DUOMO → costo × 1,15. Margine = incasso − costo merce.
const MF_LISTINO_SKU = {
  'BAG YS 2 SD FW26 17078': 1380, 'BAG YS 2 SD SS25 14035': 1150, 'BAG YS 2 SD FW25 16805': 1380, 'BAG YS 2 BC FW25 16804': 345,
  'BAG YS 2 SD FW26 17079': 1265, 'BAG YS 2 SD FW25 16798': 1265, 'BAG YS 2 SD SS25 12791': 1265, 'BAG YS 2 SD FW25 16799': 1265,
  'BAG YS 2 SD FW25 16801': 1035, 'BAG YS 2 SD FW25 16797': 1035, 'BAG YS 2 SD FW25 16800': 1035, 'BAG YS 2 TH FW25 17276': 1380,
  'BAG YS 2 TH FW25 17275': 1380, 'BAG YS 2 TH FW25 17274': 1380, 'BAG YS 2 TH FW25 16807': 1380, 'BAG YS 2 SD FW24 12192': 805,
  'BAG YS 2 SD FW24 12200': 1150, 'BAG YS 2 SD SS24 12450': 920, 'BAG YS 2 SD FW24 12449': 977.5, 'BAG YS 2 SD FW25 16808': 920,
  'BAG YS 2 SD FW24 12197': 920, 'BAG YS 2 SD SS25 13702': 1380, 'BAG YS 2 SD FW25 16596': 632.5, 'BAG YS 2 SD FW25 14741': 632.5,
  'BAG YS 2 SD SS25 14714': 920, 'BAG YS 2 SD FW25 16806': 920, 'BAG YS 2 SD SS25 13823': 920, 'BAG YS 2 SD FW24 12199': 747.5,
  'BAG YS 2 SD SS25 13704': 1265, 'BAG YS 2 SD FW24 12193': 1265
};
function mfPrezzoListino(item, dataOrdine) {
  const sku = String(item.sku || '').toUpperCase().trim();
  for (const ref in MF_LISTINO_SKU) { if (sku === ref || sku.startsWith(ref + ' ')) return MF_LISTINO_SKU[ref]; }
  const t = String(item.title || '').toUpperCase();
  if (t.includes('JACQUEMUS')) {
    if (t.includes('CHIQUITO')) return t.includes('HOMME') ? 260 : 310;
    if (t.includes('LONG BAMBINO') || (t.includes('BAMBINO') && t.includes('LONG'))) return 330;
    if (t.includes('GRAND BAMBINO')) { const g = String(dataOrdine || '').slice(0, 10); return (g >= '2026-08-15' && g <= '2026-09-15') ? 285 : 325; }
    if (t.includes('BAMBINO')) return 260;
  }
  return null;
}
const MEM_MF_PRICE = new Map();
async function caricaPrezziMarkFoy(ordini) {
  const pids = new Set();
  ordini.forEach(o => { if (riconosciMarketplace(o).key === 'MARK_FOYS') (o.line_items || []).forEach(li => { if (li.product_id && !MEM_MF_PRICE.has(String(li.product_id))) pids.add(String(li.product_id)); }); });
  const ids = [...pids];
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    try {
      const d = await shopifyGraphQL('query($ids:[ID!]!){ nodes(ids:$ids){ ... on Product { id metafield(namespace:"custom", key:"mark_foy_price"){ value } } } }', { ids: chunk.map(p => 'gid://shopify/Product/' + p) });
      const trovati = new Set();
      (d.nodes || []).forEach(n => { if (!n || !n.id) return; const pid = n.id.split('/').pop(); trovati.add(pid); const v = n.metafield ? parseFloat(String(n.metafield.value).replace(',', '.')) : NaN; MEM_MF_PRICE.set(pid, isNaN(v) ? null : v); });
      chunk.forEach(p => { if (!trovati.has(p)) MEM_MF_PRICE.set(p, null); }); // prodotto cancellato
    } catch (e) { console.log('[markfoy] metafield errore', e.message); }
  }
}
function mfPrezzoRiga(item, ordine, variantCosts = {}) {
  let p = item.product_id ? MEM_MF_PRICE.get(String(item.product_id)) : null;
  if (p === null || p === undefined) p = mfPrezzoListino(item, ordine.created_at);
  if ((p === null || p === undefined) && isDuoSku(item.sku) && item.variant_id && variantCosts[item.variant_id] != null) p = Math.round(variantCosts[item.variant_id] * 1.15 * 100) / 100;
  return (p === null || p === undefined) ? null : p;
}
// Incasso e costo di un ordine Mark Foy, riga per riga, al netto delle quantità rese
function calcolaMarkFoyOrdine(ordine, variantCosts = {}, duoUserCosts = {}) {
  const resiPerRiga = {};
  (ordine.refunds || []).forEach(r => (r.refund_line_items || []).forEach(rli => { resiPerRiga[rli.line_item_id] = (resiPerRiga[rli.line_item_id] || 0) + (parseInt(rli.quantity) || 0); }));
  let incasso = 0, costo = 0; const mancanti = [], fonti = { metafield: 0, listino: 0, duomo: 0 }; const righe = [];
  for (const item of (ordine.line_items || [])) {
    const q = Math.max(0, (parseInt(item.quantity) || 0) - (resiPerRiga[item.id] || 0));
    let cu = item.variant_id ? variantCosts[item.variant_id] : null;
    if ((cu === null || cu === undefined) && isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) cu = duoUserCosts[item.variant_id];
    let prezzo = item.product_id ? MEM_MF_PRICE.get(String(item.product_id)) : null, fonte = 'metafield';
    if (prezzo === null || prezzo === undefined) { prezzo = mfPrezzoListino(item, ordine.created_at); fonte = 'listino'; }
    if ((prezzo === null || prezzo === undefined) && isDuoSku(item.sku) && cu !== null && cu !== undefined) { prezzo = Math.round(cu * 1.15 * 100) / 100; fonte = 'duomo'; }
    if (prezzo === null || prezzo === undefined) { mancanti.push({ title: item.title, sku: item.sku || '', product_id: item.product_id, motivo: 'prezzo Mark Foy mancante' }); continue; }
    if (cu === null || cu === undefined) { mancanti.push({ title: item.title, sku: item.sku || '', variant_id: item.variant_id, is_duo: isDuoSku(item.sku) }); continue; }
    fonti[fonte] += q; incasso += prezzo * q; costo += cu * q;
    righe.push({ title: item.title, sku: item.sku || '', quantita: q, prezzo_mf: prezzo, costo_unit: cu, fonte });
  }
  return { incasso, costo, margine: incasso - costo, mancanti, fonti, righe };
}


// ============ v5.30 NOTIFICA ORDINI DUOMO (webhook Shopify orders/create) ============
const NTFY_TOPIC = process.env.NTFY_TOPIC || '';
const DUO_NOTIFY_EMAIL = process.env.DUO_NOTIFY_EMAIL || '';
const ERP_PUBLIC_URL = process.env.ERP_PUBLIC_URL || 'https://erp-marginalita-last.vercel.app';
const WEBHOOK_PATH = '/api/webhooks/orders-create';
const notificatiDuo = new Set();
async function margineOrdineSingolo(ordineRaw) {
  const [ordine] = await processOrders([ordineRaw]);
  const vids = [], pids = [];
  (ordine.line_items || []).forEach(li => { if (li.variant_id) vids.push(li.variant_id); if (li.product_id) pids.push(li.product_id); });
  const variantCosts = (await fetchVariantCosts(vids, pids)).costs;
  const duoUserCosts = {};
  if (KV_ENABLED) { try { const dv = (ordine.line_items || []).filter(li => li.variant_id && isDuoSku(li.sku)).map(li => li.variant_id); if (dv.length) { const r = await kvMGet(dv.map(v => 'duo_user_cost_' + v)); dv.forEach(v => { const x = parseFloat(r['duo_user_cost_' + v]); if (!isNaN(x)) duoUserCosts[v] = x; }); } } catch (e) {} }
  await caricaPrezziMarkFoy([ordine]);
  const mp = riconosciMarketplace(ordine);
  if (mp.key === 'MARK_FOYS') { const m = calcolaMarkFoyOrdine(ordine, variantCosts, duoUserCosts); return { mp: mp.config.nome, incasso: m.incasso, margine: m.margine, pct: m.incasso > 0 ? m.margine / m.incasso * 100 : 0, mancanti: m.mancanti.length }; }
  const { costo, errori } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
  const cur = getOrderCurrencyInfo(ordine);
  const lordo = cur.eurTotal;
  const sped = (ordine.shipping_lines || []).reduce((s2, l) => s2 + toEurAmount(l.price_set, l.price, cur.originalCurrency), 0);
  const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
  const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(country);
  const tax = toEurAmount(ordine.total_tax_set, ordine.total_tax, cur.originalCurrency);
  const iva = tax > 0 ? tax : (lordo - lordo / (1 + ivaPerc / 100));
  const ris = calcolaMarginalita(lordo, iva, costo, sped, mp.config, mp.key);
  return { mp: mp.config.nome, incasso: lordo, margine: ris.margine_netto, pct: lordo > 0 ? ris.margine_netto / lordo * 100 : 0, mancanti: errori.length };
}
async function inviaNotificaDuo(ordine, m) {
  const eur = n => '€' + Math.round(n || 0).toLocaleString('it-IT');
  const haDuo = (ordine.line_items || []).some(li => isDuoSku(li.sku));
  const titolo = eur(m.incasso) + ' · margine ' + eur(m.margine) + ' (' + Math.round(m.pct) + '%) · ' + m.mp + (haDuo ? ' · DUOMO' : '') + (m.mancanti ? ' · costo mancante' : '');
  const testo = '#' + ordine.order_number + '\n' + (ordine.line_items || []).map(li => '• ' + li.title + (li.variant_title ? ' – ' + li.variant_title : '') + ' ×' + li.quantity + (isDuoSku(li.sku) ? ' (DUOMO)' : '')).join('\n');
  const esiti = [];
  if (NTFY_TOPIC) {
    try { const r = await fetch('https://ntfy.sh/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ topic: NTFY_TOPIC, title: titolo, message: testo, tags: [m.margine < 0 ? 'red_circle' : (haDuo ? 'large_orange_diamond' : 'shopping_bags')], priority: (m.margine < 0 || haDuo) ? 4 : 3, click: ERP_PUBLIC_URL }) }); esiti.push('ntfy ' + r.status); } catch (e) { esiti.push('ntfy errore ' + e.message); }
  }
  if (RESEND_API_KEY && DUO_NOTIFY_EMAIL) {
    try { const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: MAIL_FROM, to: [DUO_NOTIFY_EMAIL], subject: titolo, text: testo + '\n\n' + ERP_PUBLIC_URL }) }); esiti.push('email ' + r.status); } catch (e) { esiti.push('email errore ' + e.message); }
  }
  console.log('[duo-notifica]', titolo, esiti.join(', '));
  return { titolo, esiti };
}
async function assicuraWebhookOrdini() {
  const token = await getShopifyAccessToken();
  const address = ERP_PUBLIC_URL + WEBHOOK_PATH;
  const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/webhooks.json?topic=orders/create`, { headers: { 'X-Shopify-Access-Token': token } });
  const j = await r.json();
  const esistente = (j.webhooks || []).find(w => w.address === address);
  if (esistente) return { gia_presente: true, id: esistente.id };
  const c = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/webhooks.json`, { method: 'POST', headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ webhook: { topic: 'orders/create', address, format: 'json' } }) });
  const cj = await c.json();
  return { creato: c.ok, status: c.status, risposta: cj };
}


// ============ v5.33 RICERCHE: Miinto SS27 Buying Guidelines (maggio-giugno 2026) ============
// Fonte: email di Lethicia Miranda (Miinto) del 19/06/2026 — file Drive "Miinto SS27 Buying Journey_May26", "SS27_CategoryInsights_Bags", "SS27_CategoryInsights_Shoes".
// yoy = crescita GMV su Miinto anno su anno. null = segno non leggibile nel PDF (estrazione testo perde il "−").
const MIINTO_SS27 = {
  fonte: { titolo: 'Miinto SS27 Buying Guidelines', data: '19/06/2026', periodo_dati: 'nov 2025 – mag 2026 (Miinto BI)', link: {
    guida: 'https://drive.google.com/file/d/1Mljbx5sUx44Yc6ZCBgUC81K3AQo8TGzR/view', borse: 'https://drive.google.com/file/d/1dpS2O3x1TJBWE3pdB6rQpyiIe38GUHWy/view', scarpe: 'https://drive.google.com/file/d/1wVyoh-JXHISC7lBVad896GcVENTGtXlX/view',
    brand: 'https://drive.google.com/drive/u/0/folders/1HbCKV7FzN1ctoZ6Y8RVMkcMF37y0Vr-3', categorie: 'https://drive.google.com/drive/u/0/folders/1O8QZ9vgox0-hLBZsg9i9V7gXcQNwd2Y7', mercati: 'https://drive.google.com/drive/u/0/folders/1KCjNrwQUGaCabu11Qr25c8SWX4M4DqOU', emergenti: 'https://drive.google.com/file/d/1G8pSVStflnrZRtdJxaH7GOLRtsnpgjyl/view' } },
  sintesi: [
    'Borse: 12% del GMV Miinto, +11% anno su anno, prezzo medio €430, sconto medio 19%, conversione 0,9%.',
    'Saint Laurent borse +170% (Polonia +330%, Scandinavia +250%): raddoppiare la profondità su Lou Camera, Envelope, Cassandra, Le 5 à 7.',
    'Jacquemus è il brand borse n.1 (9,8% del GMV): Le Grand Bambino nero/marrone/beige da tenere sempre disponibile per 12 mesi.',
    'Nuovi brand in forte crescita: Totême +878%, DeMellier +655%, Yuzefi +1841%, Ganni +103%, Gucci +74%, Prada +71%, Balenciaga +66%.',
    'In calo su Miinto: Marc Jacobs, Mulberry, Celine, Dolce & Gabbana (ridurre gli acquisti).',
    'Forme: mini bag −47% e tracolle −19%; in crescita secchiello +76%, pochette +42%, tote +5%. Spostare il 10% del budget su borse a spalla, secchiello e tote strutturate.',
    'Colori: nero 43%, marrone 24%, beige 13% = 80% del GMV borse donna. Nuovi: cognac, castagna, latte; accento bordeaux.',
    'Materiali: pelle 82%; in crescita scamosciato e pelle intrecciata/rafia.',
    'Scarpe: 28% del GMV (categoria n.1), prezzo medio €227. Volume: UGG, Golden Goose, Autry. Crescita: Louboutin +169%, Prada +142%, Red Wing +374%, Timberland +101%, Gucci uomo +138%, Dior uomo +115%.',
    'Mercati: Polonia e USA vogliono icone di lusso (mai fuori stock su Saint Laurent, Jacquemus, Gucci, Balenciaga); Italia/Francia/Spagna preferiscono artigianato e brand italiani (Zanellato, Gianni Chiarini).',
    'Regola di acquisto: 70% modelli già provati, 30% novità SS27.'
  ],
  brand: [
    { brand: 'Jacquemus', cat: 'Borse', quota: 9.8, prezzo: 613, sconto: 92, yoy: null, nota: 'n.1 borse; Le Grand Bambino nero n.1 per GMV e pezzi', modelli: ['Le Grand Bambino nero · €652 · sell-through 61%', 'The Large Bambino nero · €612'] },
    { brand: 'Saint Laurent', cat: 'Borse', quota: 9.2, prezzo: 1939, sconto: 65, yoy: 170, nota: 'Lou Camera, Envelope, Cassandra; sell-through 100% su più modelli', modelli: ['Envelope Medium nero · €2.376 · sell-through 100%', 'Le 5 à 7 Supple Small nero · €2.817'] },
    { brand: 'Marc Jacobs', cat: 'Borse', quota: 4.9, prezzo: 258, sconto: 90, yoy: -48, nota: 'tote in tela, volume ma in calo', modelli: ['The Medium Tote nero · €170', 'The Leather Mini Bag nero · €167'] },
    { brand: 'Mulberry', cat: 'Borse', quota: 3.3, prezzo: 1083, sconto: 49, yoy: -29, nota: 'ridurre', modelli: ['Lily'] },
    { brand: 'Chloé', cat: 'Borse', quota: 2.9, prezzo: 1067, sconto: 75, yoy: null, nota: 'core in Germania/Olanda', modelli: ['Marcie Mini · €1.450'] },
    { brand: 'Gucci', cat: 'Borse', quota: 2.9, prezzo: 1440, sconto: 73, yoy: 74, nota: 'Dionysus ricerche +400%', modelli: ['Dionysus (ricerche +400%)'] },
    { brand: 'Ganni', cat: 'Borse', quota: 2.8, prezzo: 342, sconto: 61, yoy: 103, nota: 'Bou Bag', modelli: ['Suede Bou Bag · €475', 'Mini Bou Bag · €345'] },
    { brand: 'Coach', cat: 'Borse', quota: 2.6, prezzo: 405, sconto: 35, yoy: 40, nota: 'Tabby', modelli: ['Tabby Shoulder · €495', 'Field Tote 22 · €425'] },
    { brand: 'Balenciaga', cat: 'Borse', quota: 2.6, prezzo: 2150, sconto: 58, yoy: 66, nota: '' },
    { brand: 'Isabel Marant', cat: 'Borse', quota: 2.3, prezzo: 371, sconto: 75, yoy: 40, nota: '', modelli: ['Oscan Soft Zip · €850', 'Bahia · €550'] },
    { brand: 'Tory Burch', cat: 'Borse', quota: 2.0, prezzo: 428, sconto: 87, yoy: null, nota: '', modelli: ['Ella Patent Tote · €345'] },
    { brand: 'Celine', cat: 'Borse', quota: 1.7, prezzo: 2114, sconto: 50, yoy: -19, nota: 'ridurre acquisti; Triomphe resta desiderata in Polonia', modelli: ['Triomphe (la più desiderata in Polonia)', 'Luggage (ricerche +245%)'] },
    { brand: 'Burberry', cat: 'Borse', quota: 1.6, prezzo: 861, sconto: 90, yoy: null, nota: '', modelli: ['Borsa a spalla check beige · €815 · sell-through 100%'] },
    { brand: 'Valentino Garavani', cat: 'Borse', quota: 1.6, prezzo: 1398, sconto: 81, yoy: null, nota: '' },
    { brand: 'Toteme', cat: 'Borse', quota: 1.5, prezzo: 840, sconto: 71, yoy: 878, nota: 'T-Lock: nuovo eroe quiet luxury', modelli: ['T-Lock Top-Handle · €890'] },
    { brand: 'Dragon Diffusion', cat: 'Borse', quota: 1.5, prezzo: 386, sconto: 47, yoy: 55, nota: 'intrecciato, Sud Europa', modelli: ['Santa Croce Small · €432', 'Half Moon Tote · €495'] },
    { brand: 'Dolce & Gabbana', cat: 'Borse', quota: 1.4, prezzo: 1254, sconto: 79, yoy: -17, nota: 'ridurre' },
    { brand: 'Prada', cat: 'Borse', quota: 1.2, prezzo: 1709, sconto: 66, yoy: 71, nota: 'Re-Edition', modelli: ['Re-Edition 2005'] },
    { brand: 'Fendi', cat: 'Borse', quota: 1.2, prezzo: 1680, sconto: 54, yoy: null, nota: 'Baguette e Spy in forte domanda nel resale', modelli: ['Baguette', 'Spy'] },
    { brand: "Tod's", cat: 'Borse', quota: 1.1, prezzo: 1309, sconto: 83, yoy: null, nota: '' },
    { brand: 'Michael Kors', cat: 'Borse', quota: 1.1, prezzo: 210, sconto: 88, yoy: 31, nota: '', modelli: ['Parker Crossbody · €375'] },
    { brand: 'Yuzefi', cat: 'Borse', quota: 1.0, prezzo: 596, sconto: 39, yoy: 1841, nota: 'Fortune Cookie Hobo', modelli: ['Fortune Cookie Hobo · €449'] },
    { brand: 'DeMellier', cat: 'Borse', quota: 1.0, prezzo: 559, sconto: 56, yoy: 655, nota: 'New York Tote, Alexandria', modelli: ['New York Tote · €560', 'Mini Alexandria · €375'] },
    { brand: 'Acne Studios', cat: 'Borse', quota: 0.8, prezzo: 1288, sconto: 42, yoy: 51, nota: 'Musubi', modelli: ['Musubi Tote in pelle · €1.500'] },
    { brand: 'Diesel', cat: 'Borse', quota: null, prezzo: 450, sconto: null, yoy: 161, nota: 'volume driver', modelli: ['Camera Bag · €450'] },
    { brand: 'Bottega Veneta', cat: 'Borse', quota: null, prezzo: null, sconto: null, yoy: null, nota: 'intrecciato: icona SS27 artigianale; Veneta Hobo ricerche +146%', modelli: ['Intrecciato Cabat / Andiamo · €3.800', 'Veneta Hobo (ricerche +146%)'] },
    { brand: 'Miu Miu', cat: 'Borse', quota: null, prezzo: null, sconto: null, yoy: null, nota: 'Aventure (intrecciato) tra i riferimenti SS27', modelli: ['Aventure · €2.500'] },
    { brand: 'UGG', cat: 'Scarpe', quota: 8.7, prezzo: 162, sconto: 13, yoy: null, nota: 'Tasman/Tazz: pantofole +101% donna, +120% uomo', modelli: ['Tasman II / Tazz II · €150', 'Classic Ultra Mini · €168'] },
    { brand: 'Golden Goose', cat: 'Scarpe', quota: 8.6, prezzo: 486, sconto: 9, yoy: 21, nota: 'Super-Star; uomo 6,5% +19%', modelli: ['Super-Star bianca · €520', 'Ball Star bianca · €488'] },
    { brand: 'Autry', cat: 'Scarpe', quota: 4.7, prezzo: 168, sconto: 16, yoy: 32, nota: 'Medalist; n.1 uomo 7,5%', modelli: ['Medalist Low · €195'] },
    { brand: 'Hogan', cat: 'Scarpe', quota: 3.7, prezzo: 348, sconto: 20, yoy: null, nota: 'core Centro Europa', modelli: ['H461'] },
    { brand: 'Moon Boot', cat: 'Scarpe', quota: 3.2, prezzo: 194, sconto: 17, yoy: 38, nota: '', modelli: ['Icon Nylon nero · €182', 'Icon Low nero · €160'] },
    { brand: 'Philippe Model', cat: 'Scarpe', quota: 5.6, prezzo: 218, sconto: 30, yoy: 46, nota: 'uomo: PRSX n.1', modelli: ['PRSX Basic bianca · €306', 'PRSX Tennis blu · €209'] },
    { brand: 'Premiata', cat: 'Scarpe', quota: 1.8, prezzo: 232, sconto: 15, yoy: null, nota: '', modelli: ['Belle · €280', 'Lus · €290'] },
    { brand: 'Christian Louboutin', cat: 'Scarpe', quota: 1.2, prezzo: 726, sconto: 8, yoy: 169, nota: 'Kate 100; Polonia +349%', modelli: ['Kate 100 nera · €741'] },
    { brand: 'Inuikii', cat: 'Scarpe', quota: 1.1, prezzo: 223, sconto: 23, yoy: 130, nota: '', modelli: ['Classic Low suede · €285'] },
    { brand: 'ALOHAS', cat: 'Scarpe', quota: 1.0, prezzo: 166, sconto: 9, yoy: 71, nota: '', modelli: ['Cassidy Mule · €195'] },
    { brand: 'Prada', cat: 'Scarpe', quota: 0.8, prezzo: 803, sconto: 18, yoy: 142, nota: '' },
    { brand: 'Gucci', cat: 'Scarpe', quota: 1.9, prezzo: 608, sconto: 29, yoy: 138, nota: 'uomo', modelli: ['Mocassino (Polonia)'] },
    { brand: 'Dior', cat: 'Scarpe', quota: 1.0, prezzo: 812, sconto: 24, yoy: 115, nota: 'uomo; B22', modelli: ['B22'] },
    { brand: 'Red Wing Shoes', cat: 'Scarpe', quota: 1.3, prezzo: 307, sconto: 18, yoy: 374, nota: 'uomo, Iron Ranger', modelli: ['Iron Ranger · €380'] },
    { brand: 'Timberland', cat: 'Scarpe', quota: 1.2, prezzo: 167, sconto: 20, yoy: 101, nota: 'uomo, 6-Inch', modelli: ['Premium 6-Inch marrone · €210'] },
    { brand: 'Santoni', cat: 'Scarpe', quota: 2.6, prezzo: 552, sconto: 20, yoy: 30, nota: 'uomo', modelli: ['Carlo suede loafer · €890'] },
    { brand: 'Maison Margiela', cat: 'Scarpe', quota: 1.2, prezzo: 607, sconto: 9, yoy: 36, nota: 'uomo, Replica/Tabi', modelli: ['Replica', 'Tabi'] },
    { brand: 'Axel Arigato', cat: 'Scarpe', quota: 3.4, prezzo: 238, sconto: 10, yoy: -55, nota: 'ridurre', modelli: ['Clean 90 · €230'] },
    { brand: 'Off White', cat: 'Scarpe', quota: 2.0, prezzo: 407, sconto: 16, yoy: -39, nota: 'ridurre' },
    { brand: 'Stuart Weitzman', cat: 'Scarpe', quota: 0.8, prezzo: 344, sconto: 34, yoy: -40, nota: 'ridurre', modelli: ['Nudistia · €425'] },
    { brand: 'Salomon', cat: 'Scarpe', quota: null, prezzo: 160, sconto: null, yoy: null, nota: 'XT-6: trail sneaker, forte in UK/USA', modelli: ['XT-6 · €160'] },
    { brand: 'New Balance', cat: 'Scarpe', quota: 2.1, prezzo: 152, sconto: 15, yoy: null, nota: '550/327, 1906R', modelli: ['1906R · €175', '550 / 327'] }
  ],
  borse_forme: [
    { forma: 'Borse a mano', quota: 33.1, prezzo: 540, yoy: null }, { forma: 'Borse a spalla', quota: 28.9, prezzo: 523, yoy: null },
    { forma: 'Tote', quota: 16.5, prezzo: 342, yoy: 5 }, { forma: 'Tracolle', quota: 13.4, prezzo: 471, yoy: -19 },
    { forma: 'Pochette', quota: 3.0, prezzo: 246, yoy: 42 }, { forma: 'Secchiello', quota: 2.5, prezzo: 511, yoy: 76 }, { forma: 'Mini bag', quota: 0.8, prezzo: 419, yoy: -47 }
  ],
  modelli_top: ['Jacquemus Le Grand Bambino nero (n.1 GMV e pezzi)', 'Jacquemus Le Bambino nero e beige', 'Saint Laurent Envelope Medium nero (sell-through 100%)', 'Saint Laurent Le 5 à 7 Supple Small nero', 'Saint Laurent Le 37 secchiello nero', 'Saint Laurent Monogram Grain de Poudre', 'Burberry borsa check beige', 'Golden Goose Super-Star bianca', 'Christian Louboutin Kate 100 nera', 'UGG Tasman / Tazz / Classic Ultra Mini'],
  emergenti: ['Polène (borse, in forte crescita in FR/NL/UK/ES)', 'Totême', 'DeMellier', 'Yuzefi', 'Ganni', 'Strathberry', 'A.P.C. accessori', 'Salomon', 'On Running', 'New Balance']
};
let CACHE_RICERCHE = null;
function normBrand(v) { return String(v || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }

// ============ ICONE APP (v5.19) ============
const ICON_PNG = {
  '180': 'iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAIAAACyr5FlAAAMpUlEQVR42u2dbWgcRRjHd2d3b+/23nKmhqupsS029Q0DVoVKi9iIoBgE5RSEok1BiPihvlSwVk2pmFQhaqkWRQgWQdSUNlSTYglG9DBJMYVSW1tIe/bSJibmLneX293bVz8MHCEv1whN3L38fx+b43rs/HbmmWeemWEjkQgDwFwQPAIAOQDkAJADQA4AOQDkAJADQA4AOQDkAAByAMgBIAeAHAByAMgBIAeAHAByAMgBAOQAkANADgA5AOQAkANADgA5AOQAywbeyT+O4zi3P1/bti3LghzXGcuycrmc618+npckybZtyHF9YFnWNE2/379582aWZRf4gi6kAQghC5Hymj9vgb+KYZh0On369Gme593oh0Pl0HV91apVx44dc3vP8csvv9TX14dCIchxPTFNU1EUURRt257xptKBnBBSDEr++eef8fFxWZZVVZ2zGSzL8vv9dXV1hJDZX0i/k2XZVCr1xx9/zPmi27bN87zP5wsGg9Fo1O/303/XdZ1l2dl9kmmaHMfJsrzwbgZy/If+gxAyZ1uapikIAsMwPT09J06cGBwcTCQSY2NjpmnOOb4QQmRZrqur6+/vn08O0zQJISdPnnzssceCwaBpmvMNKJIk3XTTTevWrdu4cWNDQ8Ott95aVGGGTPT3Y7aydME/ncX09fXt2bOnt7e3UCgIguDxeARBmG92QwixLEsUxYUEJTzPe73eOeWgaJp24cKFM2fOfPfdd/v27du2bdtrr71WWVk52w/kOZbaDIZhmpubH3744Z6eHr/fv2LFimAw6PF4imFpCRYe25aAEOLz+SoqKm688cZCodDa2rpp06be3l6O40ooBTkW1wzK9u3b9+zZI4piOBy2LMswDMuyljLcoxGPaZqGYRBCqqqqLl++3NDQ0NnZWWZ+uEYOGoHu2rWrvb29qqqKDvNOUFbXdUmSWJZ9/vnnBwcHOY5zb9bLlXJYlsVx3PHjx9va2lasWGEYhqNmhqZper1eRVFefPHFfD4/fQSEHEsxc1FVdffu3XSS6cBHbxhGOBzu7+8/ePAgjX8hxxK9lyzLfvvtt6dOnQoEAo597oZhBIPBTz/9dHx8nOO4Mug8XCAHIcQ0zUOHDgmC4OQnbtu21+tNJBKHDx92SEi0LOQ4d+7c77//LkmSw5+4ZVmCIBw5cqQ8lpSJ80NRhmF6enoymQzP886fb0uSdOrUqaGhIef/WtfLQdPP8XjcFaM4XX+ZmJjo6+tDQLoU5HK5s2fP0hU4tzzW/v5+yLEU+fKrV6+OjIx4PB63yMHz/Pnz5zFbWQo5rly5IssyXU1l3JCvEwQhmUyWQTbMBXJcunSJ1kww7ikNTKfTo6OjkGPRSSQSNA/GuGSBkOf5TCaTTCYhxyI+ZSrE6OioW8YUZlqyf2xsDDHH4j5lhmGy2azr6qlYlk2n05Bj0SsnMpmMu3oOyuTkpDPXCMukhtTn89E8h+t6Dtu2s9ksy7K0RA1yXP/dCUNDQ4QQNw4rhJBkMjk6OnrlyhVUn1/nVIHH40kmk5s3b7ZtW9M0URRdVCFhmmYwGOzu7u7t7dU0TZIkl5Z38E7umWVZXuA2NWdu2qMji3t3J7hgI7VLYzqWZenCrHtjUt4VexEY126xx1QWMDi8BUAOACAHgBwAcgDIASAHgBwAcgDIASAHgBwAcgAAOQDkAJADQA4AOQDkAJADQA4AOQDkAAByAMgBIAeAHAByAMgBIAeAHAByAMgBAOQATFndZe9S6JmC9EBSeiyzK44LgxxLoYWiKKqq0rsfeJ73+Xwej8f510dCDmZRj8pUVVVV1fXr12/YsGHNmjWFQuHChQsDAwNXr14Nh8MOv54YciyiGblcrqamprm5+fHHHw+FQsU/DQ8Pf/HFF21tbSzLCoLgWD8QkC6iGXV1dSdOnHj22WdDoZBlWYZhmKZpWdaqVauam5s7Ojq8Xq+TL6GCHIsSZ2iaVlVV9fXXX99yyy26rtu2TQjheZ7jODqU6Lr+yCOPHDhwQNM0yLGc0gOE5HK5nTt3rl27Vtd1QRBmND8hRBAEwzBisdgTTzyRyWSceX015FiUbuPmm29+5plnbNsu0eosy9q23djYyPO8M2e2kGNRLnhbv359VVVV6SsTaObjrrvuqqysdGbkATkW5TKNaDRKk13X/HwkEgmHw87MeWAquyh+yLK8wJ6gUCgUCgVn3snCl1MYWOJPlAUmNEvfN1j6Wj/btj0eD70omQYT81lCv2R4eDiVStGbWSDHYqEoimEYc7YETWDT+8NLYxiGrutTU1Pz9fO2bXu93hIhpGVZPp/v7Nmzv/7660MPPWSa5nwxqWVZPM93dnZOTk5WVlY6cGThy2aYr62tjUQicz5iQoiqquvWrSsues12yLIslmXD4fCGDRtCodB8TcVx3MWLF9PpdOkphm3bra2tDz74IP3m2Z2WYRg8zyeTyc8//zwQCDgzScpGIpHyyCt0dXXV19cvwX+3bdu2L7/8svS7znFcKpXauXNna2srVYFl2eKqLL3SPJ/PNzQ0xOPxEi6i52CuS7r64sWL1dXVc76mzPW7tpIQMjk5ec0QwTTNSCTS1taWzWbfe++9ioqKGR84c+ZMU1PTwMCAY80ok56j2B7XTCVdcwaxkGQUx3ELnIkQQjKZTG1t7VNPPXXPPffU1tYqinL+/Pmff/75yJEj2Ww2GAw6eeG+fORwbJemKIosy4Ig0Atm8/m8bdvBYFAQBIeXdECOpYiXOY6zLItGnXTy4opiMCTBmCW4QNQwjOnDHwqMAYPqcwA5AOQAAHIAyAEgB4AcAHIAyAEgB4AcAHIwy2OpjJlW/FGs4Jqz0nh6bQct93LF2RvLS45rLoLPPjVlvjpynudN09R1nba3YRi05HO6B7TUj+5vK8pkmqamaXRDLORgHFJdHAgEvvnmmzfeeENV1dkNw3FcPp/fsmXLTz/9dP/99yuKQj9z8ODB/fv3T19DJ4TIshyLxeLxeCwWUxRFUZT77ruvt7f39ddfL256psbccMMNHR0dH330Ed0nrWlaNBo9duxYS0vL9DV6yPE/jwIcx9XW1lZXV5fYMRAOh++4447ppd5r1qxZvXr1jL7E4/F0d3fbtv3KK6/QLY2vvvpqTU3N0aNH6dE89GOiKF66dCkej2/durW+vn5qakrX9cbGxo0bN/7www+Kojhzb/RyHFZs21YURdM0puSeFFmWp/cTdLfZjO8RRTGZTL7zzjtr166NxWKPPvroli1b3n///d9++83v9xfFsm3b5/MdOHDg9OnTL7/8Msuyt99++3PPPXfo0KGuri6HF4cyy3DHW+m63+mntk2PH5lZhcoVFRXd3d2HDx9uamqSZbmvr6+9vZ0ewDKjj0mlUh988EF7e3ssFrv33nsty9q/f78gCAhImfIuDN63b5+qqpFI5N13383lcoIgzBizTNMMhULff/99V1fX22+//eSTT37yySfnzp2jhcSQw92RbIk/GYaxcuVKSZJ4no9Go/M1Nj2m58MPPxRFMZFItLe3O3b72nKXg9Z5U+abTBZPYJovdGVZVtf1UCi0d+/ey5cvDwwMvPXWWzU1NXPOgyzLEkVxaGgok8n89ddfY2NjszsYyOEINE3L5/PpdDqVSs04BIFl2cnJSY7jVq9erarq33//HQwGV65cmU6nNU2b3uqEkKmpqaamprvvvrulpWXv3r3RaHTHjh2qqs5nG014UCnLxozyCUgJIaZp3nnnnbt376anwJ48ebKrq8vn89ENIz6fb3Bw8M8//6Qzi5GRkaeffrq6urqlpYVuoZ5+CuCmTZt27Nhx9OjReDyu6/pXX33V2Nj4448/Hj9+fM6DVmzbFgShzMwoq9nK6OhoNBrdunUrnW4wDNPZ2SlJUrHxJiYmXnrppebm5l27dvE8Pz4+/uabb3Z0dAQCgWJ7G4YhSdILL7wwMjLy8ccfW5YlCMJnn332wAMPbN++fWBgQFXV2RLYtj0xMZHNZh17LuCy3vHGsqzX6y1uGaJp0xlpSpr99Hg8t912myRJiURieHg4EAjMHiP8fj89eZgmskzTFEXR6/UqijLf4V20i1JVtZz8KJ/tkDPWTeY8rI1OLhRFoVkKURTnHCNM0ySEFHsIqpplWSW2UNPkaXksqZShHDOarcTwT5uwxOlNs5dh51uYXfgHEHMw//s6+wL7mP/6Vdf88jLTAhlSADkA5ACQA0AOADkA5ACQA0AOADkA5AAAcgDIASAHgBwAcgDIASAHgBwAcgDIAQDkAJADQA4AOQDkAJADQA4AOQDkAJADAMgBIAeAHABygCXkXzqH4prB8jhPAAAAAElFTkSuQmCC',
  '192': 'iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAIAAADdvvtQAAANnUlEQVR42u2da0wcVRvHZ87Mzix7YVnATaFdU2iqJBXTYprYkrRATEwN0RjSVBOaYsRGjY0ajZfEorYmxpgKFCOJEk1jMMYPRppAKVJNKbbaeKFULjZSLkIVAwLL7s7szOzM++G8nfDCsqWmgZ15/78PDRmmu7PMb5/znDPPOYf1+/0MAP8Wgj8BgEAAAgEIBCAQABAIQCAAgQAEAgACAQgEIBCAQABAIACBAAQCEAgACAQgEIBAAAIBCAQABAIQCEAgAIEAgEAAAgEIBCAQABAIQCCQcvCWuEqWZe33pzcMAwKtEvF4XNd1W0V+QgghEGiVvqlut9vhcNhJIEVRJEmyQWRNdYE4jguFQu+9915FRUU8Huc4LolnhmHQQMUuYBX8NqGhJfn7aprG8/wnn3zy/PPPZ2dna5oGgVYjAqWnp9spArlcLuRAq5oDGYaRMALRqMPzPMMw4+PjPT09ly9f7uvrm5qaUlVVVdWEKbmu6xzHNTU1bdq0Sdf1hOkIfbtffvnl4MGDHo9nuSTM4XAIgnDbbbdt2bKlsLBw69atubm5NNLQaJQwAsXjcfTCVrUXlrBJoveeEHLhwoX6+vqurq7p6WlVVTmOS9KEmQLRLCTJaSzLhsPhn376yeVyLXfLzaZT13VBELKysu67777nnntu27Zt5hUm/CwQaO3DEsdx09PTr7/++okTJyRJ8ng8Xq+XEEJbh+XaCFOglfSDOI4TRdHtdifpBlIb6MtGIpHm5uaTJ08+8cQTNTU1NHTZo8NlK4GoAb29vfv37+/t7c3MzHQ6nfp1bhjPdF1fYQwwo8sKxxE4jsvMzNQ07d133+3u7m5ubs7Ly7OxQ8Si9hBCBgYGysvLf/vtt0AgQDOkVEhLDcOgHatAIHDx4sXy8vLx8XFCiM3GsSwsELUkFApVVlZOTk76fL6EmfKao6pqVlbW4ODg448/TpWyR7fLDgIRQt58882ff/45IyMjNe0xHcrOzu7o6KitrbVrECJWbLwuXbr00Ucf+f3+VLbH7LT7fL5jx46Njo7a0iFL5kB1dXXRaJSO/aR+vBQE4e+//25oaGBZ1n6tGLFc+Pnjjz/a29s9Ho9VxuLi8bjH4/nyyy+npqY4jrOZQxYTiGGY9vb2yclJQRCscicMwxBFcWxsrLOz0/wUEGhtSiAYhuno6LDo97i1tZWxXW2TlQRyOBwzMzM9PT1paWnW+h4bhuF0On/88cdwOGyzuhSLJdEDAwPXrl1zOBzWikC6rouiOD4+3t/fjwi0lvz666+yLFvxsQAhRJKkvr4+9MLWktHR0ZU/xmJSrKBA1/Xff/8dAq0lIyMjPM9bMYOmA+ijo6N2qqi3Xjfe0gI5HI6xsbHUHz23oUDUmJmZmampKUsLND4+Pj8/D4HW7Al8NBq1bmENIUSW5bm5OTRha0M0Go3FYtYViGVZRVFCoRAi0BpkP7quh8Nh2oe3aBPGsqyqqqFQaOX1jRDolg3j0loIiw4CmU1YLBZTFIUQIooig5ro1bGH5/n+/v6enp7z589bNPyYTZhhGD/88EN2dvaVK1cs2htY/KH8fj9jkXlhDMPckhogc1bG2bNnt2zZknxeWHd3d1lZWXp6+q1qdGh5K8uySWbZIgLd6qu87o0NvrL0QZ5tist4rISyJp8F3XgAIBCAQAACAQgEIBAAEAhAIACBAAQCAAIBCAQgEIBAAEAgAIEABAIQCAAIBCAQgEAAAgEIBAAEAhAIQCAAgQCAQAACAQgEIBAAEAhAIACBAAQCAAIBCAQgEIBAAPD4EzBrt/MB3bmBrhnNsixdQt9aS0hDoLWB47hYLBaJRHiepxuvxGIxTdPcbrcoivF4HAKBZNv2zM3NBYPB6urq4uLi/Px8wzCGhobOnTt38uTJiYkJn89nlf2gINAa2BMKhQ4ePFhTUxMIBMzjRUVFe/fuffXVVw8fPnzixAmrOIQkerXtmZ2dPXLkyPvvvx8IBOLxeDwep/vP0Z9zcnKamppqampmZ2ctsZ0PBFrVvCcUCj366KOvvPIK9YbjOI7jCCGEEPozNenw4cP79u2bm5tLfYcg0Or1uTRN8/l8R48epds9JdykjBBCd4J66623fD4f3VwMAgGGEDI/P79nz56NGzcut8WdeaZhGHl5eXv27AmHwykehCAQs5o7hd1zzz3mwA+TdJNherKmaSzLQiDw39ASDAbpgOFKmrwNGzZwHJfi44oQaFWRZXnlJyuKous6IhBgzF18R0ZGVrLfJZVmeHgY3fi17PXckNV8KcMwBEE4c+ZM8gx64b7SZ86cEUUxxYcTebumq6qqLvdFN7f9Xkl6YRiGoiiKoiR/PuVwOJJrpOu6x+Pp7u7++uuv77//fk3TltvCnP7q9OnT3d3dXq83xQWyxr7xN5WoRqPRoqKid95554Z+3H333S6Xi47KJFSHZdlQKHT58mWe55O8GsuyTz311NWrV0VRTH6aoijr16/v6uoKBAKqqvI8v/CtDcPQNM3hcPz111+7d+++du2aIAgpnkTzthyvCwQCxcXFt+QFMzMzd+/efcPT6KCf0+lMcr8Nw3A6ncPDw3v37m1ubt6wYQM9SGMMHUJ0OBzDw8P79+8fHR31er2p/1jebhGIZVlVVXNyckpLS1cSrm6Yvpg3ODnt7e0zMzPJAxVz/YHG3Nxcfn7+a6+9Vl5enpGRYf7qn3/+aWlpOXr06MTERHp6uiWKOuwmkOnQ/Pz8ar5penr6SuwxHZJlWZblzZs3FxQU3HnnnYZhDAwMDA4ODg0NuVwuC5UE2VAg6tAqPwGIx+M3lazQ4CdJkqIoqqqyLEsry5xOp7WKEu0pkLWqWmkzSttKa9WzoqBs7YcbLFS9ipFoAIEABAIQCAAIBCAQgEAAAgEIBAAEAhAIQCAAgRh7POX+FwVly5WYLXxsvtyRJC+S5GSrw6WlpdnvU2maFovFkt8zwzBisRitrmeu173TeVuL5KO1zLFYzCwzooWzsiwbhrGoNl7XdUmSFh5nWTYejy86CIFSF13Xs7KygsFgLBZTFGW5gnlBEDZu3CiKYiQSIYTouu5yufLy8mhZvvm/6O3PyckJBoO6rkejUZ7nNU3z+/15eXmCIMzPz5vC6brudrs3bdq08HjCg2jCUncJlUgkUllZ+c0332zdulWSpKU3jBASi8WCwWBbW9sLL7wgSRLHcZIkFRYWfvvtt1VVVQuXNGBZVpblO+64o62trbGxURRFTdMEQWhsbDx16lRBQYEsy9Q289/a2trW1tbbb79dlmWO4xRFOXLkSGdnZ2FhYcLrgUBMChZqrXDO16LTlh6h87lOnz792WeflZSUVFRUzM3N7du3r6SkpLm5+dSpUx6Ph1bdG4ZBZ+TU1dWtW7euurpa1/VIJLJr166KioqWlpbW1laPx2P1CjL0wv4Noig2NDRcvXq1qqqqqKjoscceGxoaOn78OF0fk1lQGe3z+dra2lpaWh555JFt27YpivLMM8+Ew+H6+vqbmg4LgWyVVDmdzpGRkfr6+vz8/IaGhmAweOzYsbGxMVoDv3Rae11dHcMwBw4ceOihh8rKypqamnp7e91ut1WWzmRQE83c6kkXPp/v888/Ly0tfeCBB7766qsvvvgi4dQtmjL39PQ0NTVVVVUVFxf39/d//PHHLpfLfvYgAt3EwJKu66IoejwehmFcLleSSce6rqelpX344YcjIyPr1q1raGj4888/U3+SMgRKMKBnsjT5MCfT0N/SheWSL1D35JNP3nvvvR0dHWVlZQcOHAiFQglnnxmGIYrixMTE4OCgoijff/996i+yAYESIEmSLMvhcDgcDtPJe+YNJoRIkqSqanZ2tqqqsVhMlmW/3y8IQjgcXmQSISQcDm/fvv3pp5/+7rvvDh061NfXd+jQoYKCgmg0mrBbbhgGx3F02NDhcNgy9thZIF3XVVUtKCjYuXPnzp07d+3alZuba643SEcRaYQoKSmprKzMyMjYvn17dXW1LMuXLl1aeMvpQCLHcS+99BLP8x988MHk5GRjY2MgEHj22WeTLCJD53zd7IxVJNEpgdvt9nq9b7zxhiAIdNT45Zdfrq2t9fv9NO2lw81vv/12XV3d8ePHp6en3W43y7J1dXUXLlxY2F2iE5BffPHFhx9+uKGhoaurKzs7u7W1taOjo7q6+uLFi59++qk5FLRIII/Hk5mZmbxxtHx2aMvVOe66666CggJFUcx409vbe+XKlYWZLCEkEomsX7/+wQcf3Lx58+zsbGdn5/nz551O56I1eziOKy0tTU9PP3v27OTkpNPplCQpPz9/x44dExMT586dW7qsAr2MHTt25ObmdnR0pP5qvRDof26eJEn02acpQVpa2tLVnwghiqJIkkTX9uY4LmEsYRhmfn4+Ho97vV6e5+kadYqiRCIRh8Ph8XgSBhiWZSORiKqqXq/XZo8v7L+4wtJu13LrFpj9L+rQcn0lGj8Wvgh9Mk+3uUh+GTZ7dvF/kQOtvM+8wuUNlp5Dl6O7VZeBXhhgUJEIAAQCEAhAIACBAIBAAAIBCAQgEAAQCEAgAIEABAIAAgEIBCAQgEAAAgEAgQAEAhAIQCAAIBCAQAACAQgEAAQCEAhAIACBAIBAAAIBCAQgEIBAAEAgAIGAJfkPCkYxqmHsClcAAAAASUVORK5CYII=',
  '512': 'iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAIAAAB7GkOtAAAVBUlEQVR42u3de3yVBf3A8WdzXCQxZgheQCUn8FJnlqghxMpArQTyleHISeNaSilI+apAehWBe23KNSBugglBKimaYKRiykBpKwwBF4yNMXQ0cOMyxwZjvz94eX5HbgK777zff/EcHvaw79nO5zzPc85zomJjYwMAIk+0EQAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAACAEAkijGCBioxMXHGjBnmwGnKysrq2rWrOWAPAAABABAAAAQAgMBJYOqpI0eO1If/xsGDB0tLS0tKSkpLSz/++OOPP/64ev9jcXFxbdu2renvIj09vXq/YLNmzVp84txzz23ZsmWd31OVlZV+axCAxrLvFl0He2979uzZGGbz5s3l5eU1usWpU6cmJSXV9PfVp0+fmn58vPjii6/5xNVXX33VVVc1adKkNu+7qKgovzUIAGcmPz9/zZo1q1evXr16dW5uroGcnQ8//PDDDz989dVXQ7sIN954Y/fu3bt3737DDTc0a9bMiBAAgnpyCKikpGT27NlLlizZsmVLoz9wUfuHR8rKyo429WgMEhISfvazn3Xp0sUhIJwEpi4PAR04cGDSpEnx8fHjxo2r20f/oLYOXNTt4ZGysrKVK1fedttt3/ve9zIzMx0CQgComyd0v//976+77rpx48YVFxc34m+zfj47XrVqVa9eve69995t27b5CUcAqL0ndJmZmV27dh07dmw9eeiPnD2AY6xYsaJr166PPfZYWVmZn3MEgJpVVFT00EMP9erVKysryzTqg0OHDqWlpXXr1u2tt94yDQSAmrJp06Zu3bo9/fTTRlHfbNu2rW/fvikpKc7fIgBUv+XLl/fq1augoMAo6q3U1NSkpKSDBw8aBQJAtXn88ceTkpJKS0uNop5bsWLF7bffXlhYaBQIANXgt7/97YQJE8yhodiwYcMdd9xRr87PIwA0SE8//fTkyZPNoWHJycnp169fTV97AwEgaNzHE0aMGGEODVFGRsbgwYPryXUAEQAamNzc3EGDBnlVScP18ssvT5o0yRwQAIIzvXxQcnKytxc1dCkpKRs3bjQHBIAz8MQTT/znP/8xh4auoqJi0KBBTgYgAASn/4av1NRUc2gctmzZ8pvf/MYcEIDA5aBPx9ChQysqKgLXvAsayaWSZ86cmZGR4XLQCIDLQX+GpUuXbt68OXDNu6BRXSr517/+tctBIwAEpz5kPG7cOHNofNauXRv6iDEQAE5g8eLFeXl55tAoOROAABCc4sLCKSkp5tBYbdy4cenSpeaAAHACL7zwwgcffGAOjZj3hSEABCe77I8hBI39Bb4190nCCAAN1Y4dO1avXm0Ojd6CBQsMAQHgU5566ilDiATPPvtsSUmJOSAAfOpxwRAiQXl5+bJly8wBASAIHRresWOHOUSIF1980RAQAILQdYMNIXKsWrXKp3siAAShD3w3hCCS3vCxYsUKc0AACAoKCt59911ziCgvvfSSISAABK+99pohROCd7tMiEQCCd955xxAizYEDBzZt2mQOCECke/vttw0hiMjrgxoCAhDRPvroo61bt5pDBFqzZo0hIACB4z9EoDfffNMQEIDA8R8iUFFR0bZt28wBAYhc7733niFErPXr1xsCAhC5PAeMZNnZ2YaAAAQR+wnALgEUyZz/RwAiV25urncD2QMAAQgc/yHSbNmyxRAQgAiVk5NjCJFs//79e/bsMQcEwB4AgdMAIAD2AAicBgABsAeAAIAABI3tNaD2ABAABCAS7dixw2tAcQ4AAQgc/0EAQACCyPkkSEOgvLy8qKjIHBCAyLJ3715DIAgCAUAABIAIVVxcbAgIgF97/CSAANgDIHAICARAAPCTgAAYgR1/7AEgADR4+/btMwQ8FUAA7PhjDwAEwPM+/CSAADRilZWVJSUl5oA9AATA7zyBg4EgAH7n8WwAjhVjBA3Url270tPTg8b+aeCVlZWNZiu1HIBjfjzy8vL81iAAjcSqVatWrVrV6L/NqKio2tlKI2vAwYMHe/fu7deEwCEgAAQAAAEAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAgM8SYwQQsW699da4uLgOn2jfvv3u3buzs7NzcnJycnK2bt2anp6+b98+gxIAoJG4/PLLhwwZ0r9//wsuuOCYv2rXrl27du0SEhKOLh48ePD555+fP39+RkaGuQUOAQEN17e+9a3nn3/+3//+9/Dhw49/9D9e8+bN+/fvv3LlyjfffDM5OdkABQBoeJo2bTp79uxFixaFnt2fkWuvvXbixImvvPJKmzZtDFMAgAbj0ksvff311+++++4qfp2bbrpp9erVt9xyi5EKANAAJCQkpKenX3311dXy1Vq3br1s2bKRI0cabOAkMFCfdenSZenSpdHR1flU75xzznn00UdbtGgxfvx4E7YHANRHF1544cKFC6v30T/k4Ycf/sY3vmHIAgDUO1FRUQsXLqy5c7ZRUVFPPvlku3btjFoAgPplzJgxN954Y41u4vOf//zixYubNm1q2gIA1Bfx8fG1c572mmuu+fnPf27gAgDUF/fff3+tbWvQoEF2AgQAqBdatWpV9Zf8n77Y2Nh+/foZuwAAdW/IkCExMbX6Cu8HHnjA2AUAqGPnnHPOkCFDanmjnTt3/upXv2r4AgDUpWuvvbZOLtfTs2dPwxcAoC516NChTrZ7xRVXGL4AAHWprh6I6yo8CABQxw/EAiAAQIQGoFWrVueff775CwBQZ9q2bVtXm77kkkvMXwCAOvO///0vAjeNAABBXl5enWy3rKzso48+Mn8BACIuANnZ2YYvAEBd2r59e0RtFwEA6ngPQAAEAKhjGRkZRUVFtb/d1157zfAFAKhL5eXlTz31VC1vNDc3VwAEAKh7M2fOPHz4cG1ucdq0acYuAEDdKywsXLZsWa1tbv/+/UuWLDF2AQDqhenTp9fatubMmVNaWmrmAgDUC+vXr09LS6uFDW3atCk1NdXAG6io2NhYU+DsDB06tE+fPjW6ibi4uFq4uE16enpNb6J37961fwc999xzt956a819/aKioh49euzcudPvQgMVYwSctSuvvLJbt26N4Buphe/i3HPPrf3jJIMGDVqzZk0NXaPtyJEjSUlJHv0Dh4CAemjfvn333nvvoUOHauKL/+53v1u7dq0hCwBQT7377rt9+/at3su0HT58eMyYMZMnTzZeAQDqtbfffrtHjx7r16+vlq+2a9euO+64Y8aMGQYrAEAD8MEHH9x+++1//vOfq/h11q1b171793/9619GGngVENCw3HnnnT/+8Y9vueWWM/2HW7dunTlz5vz5881QAIAGrFOnTsOGDbvnnntatGhx6jUrKiqWL18+d+7ct956y9wEAGgkYmJi4uLiOnXq1LFjx06dOnXq1KlDhw4FBQVZWVlZWVnvv/9+VlbWf//7X+/yFQAAAieBARAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABABAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQBAAAAQAAAEAAABAEAAABAAAAQAAAEAQAAAEAAABAAAAQAQAAAEAAABAEAAABAAABqBGCPg7CQmJj788MOhxZSUlL/85S/Vu4m+ffuOHj06tDhlypRFixadYv2JEyd27949tPj9739/+/btZ7rR/v37jxw5MvyWcePGvfTSSydbPy0tLSEhIbRYVlaWnJycnZ19+lvs0KHDwoULmzRpErplzJgxK1euPPW/6tq165QpU0KLFRUVAwYM2LJli59M7AHAWVq8eHFWVlb4LT/60Y9iYk78VOkrX/lK+KN/EAR/+tOfzujRPwiCnJycZ599NvyWYcOGRUd/xu/mgw8+GL64bNkyj/4IAFTV+PHjjxw5Elps06bNfffdd8I1w/eBgiDIy8ubM2fOWWxx1qxZhYWFocXLLrvs7rvvPsX6d91115VXXhla3Ldv3x/+8Ad3HAIAVfX+++8fczjrvvvui42NPWa17373ux07dgwtVlZWPvbYY4cPHz6LLZaWls6aNSv8loEDBzZt2vSEK8fExAwePDj8lnnz5hUXF7vjEACoBtOnT9+zZ09o8bzzzhsyZEj4Ck2bNh06dGj4LcuXL8/MzDzrLb744oubNm0KLX7hC19ITk4+4ZoDBgxo06ZNaDE3N3fx4sXuMgQAqkdJSckTTzwRfPqMdPv27UOLgwcPvvDCC0OLxcXFkyZNquJG09LSwg89JSYmHr/b0bJly6SkpPBbHn/8cfcXAgDV6dVXX127dm34U/7hw4cf/XPr1q3vueee8JWnTZu2b9++Km5x48aNy5cvD9/tOGYnIwiCYcOGnXfeeaHF119/fd26de4sBACqWWpqallZWWjx61//enx8fBAEDz74YIsWLUK3r1+//hSvEz0jU6dOPXDgQGixT58+l1xySWjxoosuuuuuu4Kwl5xWfbcDAQBOYOfOnX/84x///7clOnrEiBEdO3a87bbbwh+Fx48fX11bLC4ufvLJJ8N3Ox544IHQ4vDhw8PPDC9atGjXrl3uJgQAasT8+fNzcnJCi/Hx8WlpaeEv0l+wYMFZvN3sFBYuXJibmxta7NmzZ+fOnYMg6Ny5c69evUK3FxQUhKcCBACq2eHDh1NTUysrK0O3XHzxxaE/Z2dnz5s3r9o3Gn5eNzo6+ic/+cnRp//h4Zk+fXp5ebk7CAGAGpSZmXnCCzMcOXJkwoQJNbHFdevWvfHGG6HFm266KSkp6eabbw7Czjr87W9/c9cgAFDjJk+evH///uC4V+5v2LChhrY4derU8PPP4Rd+qKioSEtLc6cgAFAb9uzZE/4CzaPO7qoPpyk/P3/JkiUn/CuX/UEAoPa0adPm29/+9jE3HvPe4Go3Z86cgoKCY2502R8EAGrVI4880rJly+C4q1UffVtADSkvL58xY8YxN86dO9dlfxAAqCXf/OY3e/TocYJfnujoX/7ylzW66VdeeWX37t1B2HsOTnZcCAQAqtn5558/atSoIOxVoRkZGaHFuLi4gQMHBjX8OtQT/hkEgMYs/NX3QRCc7FNZwp+SB59+mWbV/w8jRoxo3bp1aPG5556bMGFC+AvwBw4ceOmll7qzEAAIqveSnOGL4e/AOqGLLroo+PRlFar4H7j55pu/853vhBaLiopmz56dn58f/mkBzZs3f+SRR9xZCABUp6KiovDFdu3anXr98Ms1V1RUHP/K/TPSpEmTX/3qV1FRUUHY564cvVLb7Nmz9+7dG4R9PG/Pnj3dXwgAVJvNmzeHH8b50pe+1LZt25OtfOedd4Z/rvrWrVuruPWf/vSn4fscOTk5zzzzzNE/HzhwYMGCBeErjxo16nOf+5y7DAGA6lFaWvree++FFps1a3aygy2tWrW6//77w2/55z//WZVNx8fH9+vXL/yWiRMnBp/+7Pi8vLwg7AO8RowY4S6jYYkxAqrFFVdckZCQcIoVtm/fHn6Ry9P017/+9brrrgstfu1rX5s1a9bYsWPDL4PcpUuXsWPHhn8+15EjR6p4gf7Ro0eHn1J+44033nnnneDTZ5inTZsWfkmG3r171+jFIUAAqKcSExMTExNPscK8efOO+dzz0/HCCy/079+/Q4cOoVu+/OUvL1u2bO/evbt3727atOkFF1xw/Fu0Xn755fBrOJ+pIUOGfPGLXwzCXn0/derU41f7xz/+sX79+uuvvz78bQE/+MEP/DAQOAQE1WLUqFHHfOxJdHR0bGzsVVdddfnllx//6J+ZmZmSknLWm2vfvv0Pf/jD8FueeeaZ/Pz8E648bdq08LMUcXFxNX19CBAAIkh+fv6gQYPS09M/c82KiopFixY99NBDhw4dOuvNPfroo82aNQstFhYWzp0792Qrb9iw4e9//3v4LQMGDPC2AAQAqk1hYeHIkSNHjx69c+fOk62TkZGRnJw8ZcqUqnxMSr9+/UKHdIJPrshWWlp6in8yffr08Os2N2/e/Be/+IW7jAYhKjY21hRoME9YoqOvv/76G2644bLLLmvduvWhQ4cKCwuzs7PXrl1blYP+IAAAOAQEgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAIAgAAAIAAACAAAAgCAAAAgAAAIAAACAIAAACAAAAgAAAIAgAAAIAAACAAAAgBAdfg/gAhBLBmiYkAAAAAASUVORK5CYII='
};
const WEB_MANIFEST = JSON.stringify({ name: 'TLuxy Business Manager', short_name: 'TLuxy Business Manager', start_url: '/', display: 'standalone', background_color: '#111111', theme_color: '#111111', icons: [{ src: '/icon-192.png', sizes: '192x192', type: 'image/png' }, { src: '/icon-512.png', sizes: '512x512', type: 'image/png' }] });

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#F4F1EB">
<link rel="apple-touch-icon" href="/apple-touch-icon.png"><link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png"><link rel="manifest" href="/manifest.webmanifest"><meta name="apple-mobile-web-app-title" content="TLuxy Business Manager"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bodoni+Moda:opsz,wght@6..96,500;6..96,600&family=Jost:wght@400;500;600&display=swap" rel="stylesheet">
<title>TLuxy Business Manager</title>
<style>
  :root {
    --green-primary: #008060; --green-dark: #004C3F; --green-light: #E8F4F0;
    --gold: #C9A961; --gold-light: #F4ECD8;
    --beige: #F4F1EB; --cream: #FAFAF7;
    --black: #1A1A1A; --gray-900: #2D2D2D; --gray-700: #5C5C5C; --gray-500: #8E8E8E;
    --gray-300: #D4D4D4; --gray-200: #E8E8E8; --gray-100: #F2F2F0;
    --white: #FFFFFF; --red: #BF4747; --red-light: #FCEEEE;
    --shadow-sm: 0 1px 2px rgba(26,26,26,0.04);
    --shadow-md: 0 4px 12px rgba(26,26,26,0.06);
    --shadow-lg: 0 12px 32px rgba(26,26,26,0.08);
    --radius-sm: 8px; --radius-md: 12px; --radius-lg: 20px;
    --font-main: 'Century Gothic', 'CenturyGothic', 'AppleGothic', Futura, 'Trebuchet MS', sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: var(--font-main); background: var(--beige); min-height: 100vh; color: var(--black); -webkit-font-smoothing: antialiased; line-height: 1.5; letter-spacing: 0.01em; }
  .container { max-width: 1440px; margin: 0 auto; padding: 24px; }
  .header { background: var(--white); border-radius: var(--radius-lg); padding: 32px 40px; margin-bottom: 24px; box-shadow: var(--shadow-md); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px; border: 1px solid var(--gray-100); }
  .header-left { display: flex; align-items: center; gap: 28px; }
  .logo { font-family: var(--font-main); font-weight: 700; font-size: 2.6rem; color: var(--black); letter-spacing: 0.02em; line-height: 1; text-transform: uppercase; }
  .logo .dot { color: var(--gold); }
  .header-divider { width: 1px; height: 52px; background: var(--gray-200); }
  .header-info h1 { font-size: 1.05rem; font-weight: 700; color: var(--gray-900); margin-bottom: 3px; text-transform: uppercase; letter-spacing: 0.05em; }
  .header-info p { font-size: 0.8rem; color: var(--gray-500); letter-spacing: 0.03em; }
  .header-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .status-pill { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; background: var(--green-light); color: var(--green-dark); border-radius: 50px; font-size: 0.75rem; font-weight: 700; border: 1px solid rgba(0,128,96,0.15); letter-spacing: 0.05em; text-transform: uppercase; }
  .status-dot { width: 7px; height: 7px; background: var(--green-primary); border-radius: 50%; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .tabs-wrap { background: var(--white); border-radius: var(--radius-lg); padding: 8px; margin-bottom: 24px; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-100); }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tab { flex: 1; min-width: 130px; padding: 14px 20px; border: none; background: transparent; border-radius: var(--radius-md); cursor: pointer; font-family: var(--font-main); font-weight: 700; font-size: 0.82rem; color: var(--gray-700); transition: all 0.25s ease; letter-spacing: 0.06em; text-transform: uppercase; }
  .tab:hover { background: var(--gray-100); color: var(--black); }
  .tab.active { background: var(--black); color: var(--white); }
  .tab-content { display: none; animation: fade 0.4s ease; }
  .tab-content.active { display: block; }
  @keyframes fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  .section { background: var(--white); border-radius: var(--radius-lg); padding: 36px; margin-bottom: 24px; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-100); }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; flex-wrap: wrap; gap: 16px; }
  .section-title { font-family: var(--font-main); font-size: 1.6rem; font-weight: 700; color: var(--black); letter-spacing: 0.02em; text-transform: uppercase; }
  .section-subtitle { font-size: 0.85rem; color: var(--gray-500); margin-top: 6px; letter-spacing: 0.02em; }
  .info-box { background: var(--green-light); border-left: 3px solid var(--green-primary); padding: 14px 20px; border-radius: var(--radius-sm); margin-bottom: 24px; font-size: 0.85rem; color: var(--green-dark); }
  .warn-box { background: var(--gold-light); border-left: 3px solid var(--gold); padding: 14px 20px; border-radius: var(--radius-sm); margin-bottom: 24px; font-size: 0.85rem; color: #6B5320; }
  .error-box { background: var(--red-light); border-left: 3px solid var(--red); padding: 16px 20px; border-radius: var(--radius-sm); margin: 24px 0; font-size: 0.85rem; color: var(--red); }
  .error-box strong { display: block; margin-bottom: 8px; font-size: 0.95rem; }
  .error-list { max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 0.8rem; background: var(--white); padding: 12px; border-radius: 6px; margin-top: 10px; }
  .error-list div { padding: 4px 0; border-bottom: 1px solid var(--red-light); }
  .error-list div:last-child { border-bottom: none; }
  .filter-bar { display: flex; align-items: center; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
  .period-selector { display: flex; gap: 6px; background: var(--gray-100); padding: 6px; border-radius: 50px; flex-wrap: wrap; }
  .period-btn { padding: 10px 22px; border: none; background: transparent; border-radius: 50px; cursor: pointer; font-family: var(--font-main); font-weight: 700; font-size: 0.78rem; color: var(--gray-700); transition: all 0.2s ease; letter-spacing: 0.06em; text-transform: uppercase; }
  .period-btn:hover { color: var(--black); }
  .period-btn.active { background: var(--white); color: var(--black); box-shadow: var(--shadow-sm); }
  .custom-range { display: flex; align-items: center; gap: 8px; background: var(--white); border: 1.5px solid var(--gray-200); border-radius: 50px; padding: 6px 8px 6px 18px; }
  .custom-range label { font-size: 0.72rem; font-weight: 700; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.06em; }
  .custom-range input[type="date"] { border: none; background: transparent; font-family: var(--font-main); font-size: 0.85rem; color: var(--black); padding: 6px 8px; cursor: pointer; }
  .custom-range input[type="date"]:focus { outline: none; }
  .custom-range .apply-btn { background: var(--black); color: var(--white); border: none; padding: 8px 18px; border-radius: 50px; font-family: var(--font-main); font-size: 0.72rem; font-weight: 700; cursor: pointer; text-transform: uppercase; letter-spacing: 0.06em; transition: background 0.2s; }
  .custom-range .apply-btn:hover { background: var(--green-dark); }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .kpi { background: var(--white); border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 24px; transition: all 0.25s ease; position: relative; overflow: hidden; }
  .kpi:hover { border-color: var(--gray-300); transform: translateY(-2px); box-shadow: var(--shadow-md); }
  .kpi.primary { background: var(--black); color: var(--white); border-color: var(--black); }
  .kpi.primary .kpi-label { color: rgba(255,255,255,0.7); }
  .kpi.primary .kpi-sub { color: rgba(255,255,255,0.5); }
  .kpi.green { background: var(--green-primary); color: var(--white); border-color: var(--green-primary); }
  .kpi.green .kpi-label { color: rgba(255,255,255,0.85); }
  .kpi.green .kpi-sub { color: rgba(255,255,255,0.65); }
  .kpi.gold { background: var(--gold-light); border-color: var(--gold); }
  .kpi-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; color: var(--gray-500); margin-bottom: 14px; }
  .kpi-value { font-family: var(--font-main); font-size: 1.9rem; font-weight: 700; line-height: 1.1; margin-bottom: 6px; letter-spacing: 0.01em; }
  .kpi-sub { font-size: 0.74rem; color: var(--gray-500); letter-spacing: 0.04em; }
  .breakdown-section { margin-top: 8px; }
  .breakdown-title { font-size: 0.95rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--black); margin-bottom: 12px; }
  .breakdown-sub { font-size: 0.8rem; color: var(--gray-500); margin-bottom: 16px; }
  .breakdown-table-wrap { overflow-x: auto; border-radius: var(--radius-md); border: 1px solid var(--gray-200); }
  .breakdown-table { width: 100%; border-collapse: collapse; background: var(--white); }
  .breakdown-table thead { background: var(--black); color: var(--white); }
  .breakdown-table th { padding: 14px 14px; text-align: left; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; white-space: nowrap; }
  .breakdown-table th.num, .breakdown-table td.num { text-align: right; }
  .breakdown-table td { padding: 14px 14px; border-bottom: 1px solid var(--gray-100); font-size: 0.88rem; color: var(--gray-900); }
  .breakdown-table tbody tr { transition: background 0.15s ease; }
  .breakdown-table tbody tr:hover { background: var(--cream); }
  .breakdown-table tfoot td { background: var(--gray-100); font-weight: 700; padding: 16px 14px; border-top: 2px solid var(--black); border-bottom: none; font-size: 0.9rem; }
  .mp-badge { display: inline-block; padding: 4px 10px; border-radius: 50px; font-size: 0.7rem; font-weight: 700; color: var(--white); letter-spacing: 0.02em; }
  .mp-row:hover { background: var(--green-light) !important; }
  .toggle-arrow { display: inline-block; font-size: 0.7rem; color: var(--gray-500); margin-right: 4px; font-family: monospace; width: 12px; }
  .detail-table { width: 100%; border-collapse: collapse; background: var(--white); border-radius: var(--radius-sm); overflow: hidden; box-shadow: inset 0 0 0 1px var(--gray-200); }
  .detail-table thead { background: var(--gray-100); }
  .detail-table th { padding: 10px 12px; text-align: left; font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; color: var(--gray-700); white-space: nowrap; border-bottom: 1.5px solid var(--gray-200); }
  .detail-table th.num, .detail-table td.num { text-align: right; }
  .detail-table td { padding: 12px; border-bottom: 1px solid var(--gray-100); font-size: 0.82rem; color: var(--gray-900); vertical-align: top; }
  .detail-table tbody tr:last-child td { border-bottom: none; }
  .detail-table tbody tr:hover { background: var(--cream); }
  .duo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 18px; margin-top: 16px; }
  .duo-card { background: var(--white); border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); overflow: hidden; transition: border-color 0.2s; }
  .duo-card:hover { border-color: var(--gold); }
  .duo-img { width: 100%; height: 180px; background: var(--gray-100); display: flex; align-items: center; justify-content: center; overflow: hidden; }
  .duo-img img { width: 100%; height: 100%; object-fit: cover; }
  .duo-body { padding: 16px; }
  .duo-title { font-weight: 700; font-size: 0.92rem; color: var(--black); margin-bottom: 4px; line-height: 1.3; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; text-transform: uppercase; letter-spacing: 0.02em; }
  .duo-meta { font-size: 0.7rem; color: var(--gray-500); margin-bottom: 8px; font-family: monospace; }
  .duo-listino { font-size: 0.82rem; color: var(--gray-700); margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px dotted var(--gray-200); }
  .duo-input-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .duo-input-row label { flex: 0 0 110px; font-size: 0.7rem; color: var(--gray-700); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
  .duo-input-row input, .duo-input-row select { flex: 1; padding: 7px 10px; border: 1px solid var(--gray-200); border-radius: 6px; font-size: 0.85rem; font-family: var(--font-main); background: var(--white); }
  .duo-input-row input:focus, .duo-input-row select:focus { outline: none; border-color: var(--green-primary); }
  .duo-result { margin-top: 12px; padding: 12px; border-radius: 8px; background: var(--gray-100); font-size: 0.82rem; }
  .duo-result.duo-pos { background: var(--green-light); border-left: 3px solid var(--green-primary); }
  .duo-result.duo-neg { background: var(--red-light); border-left: 3px solid var(--red); }
  .duo-main-result { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px dotted var(--gray-200); }
  .duo-result-label { font-size: 0.65rem; font-weight: 700; color: var(--gray-700); text-transform: uppercase; letter-spacing: 0.08em; }
  .duo-breakeven { font-size: 0.78rem; color: var(--gray-700); line-height: 1.7; }
  .margin-pos { color: var(--green-dark); font-weight: 700; }
  .margin-neg { color: var(--red); font-weight: 700; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; }
  .form-group { display: flex; flex-direction: column; gap: 8px; }
  .form-group label { font-weight: 700; color: var(--black); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; }
  .form-group input, .form-group select { padding: 13px 16px; border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); font-size: 0.95rem; font-family: var(--font-main); background: var(--white); color: var(--black); transition: all 0.2s ease; }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--green-primary); box-shadow: 0 0 0 3px rgba(0,128,96,0.1); }
  .btn-primary { background: var(--black); color: var(--white); border: none; padding: 16px 32px; border-radius: var(--radius-md); font-size: 0.85rem; font-family: var(--font-main); font-weight: 700; cursor: pointer; width: 100%; margin-top: 20px; transition: all 0.2s ease; letter-spacing: 0.08em; text-transform: uppercase; }
  .btn-primary:hover { background: var(--green-dark); transform: translateY(-1px); box-shadow: var(--shadow-md); }
  .results { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-top: 28px; }
  .result-card { background: var(--gray-100); border-radius: var(--radius-md); padding: 18px; border: 1.5px solid transparent; transition: all 0.2s ease; }
  .result-card.positive { background: var(--green-light); border-color: var(--green-primary); }
  .result-card.negative { background: var(--red-light); border-color: var(--red); }
  .result-label { font-size: 0.68rem; color: var(--gray-500); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 8px; }
  .result-value { font-family: var(--font-main); font-size: 1.25rem; font-weight: 700; color: var(--black); letter-spacing: 0.01em; }
  .mp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
  .mp-card { background: var(--white); border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); padding: 24px; cursor: pointer; transition: all 0.25s ease; }
  .mp-card:hover { border-color: var(--green-primary); transform: translateY(-3px); box-shadow: var(--shadow-md); }
  .mp-name { font-family: var(--font-main); font-size: 1.1rem; font-weight: 700; color: var(--black); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .mp-pay { font-size: 0.7rem; color: var(--gray-500); margin-bottom: 14px; letter-spacing: 0.04em; }
  .mp-fees { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem; color: var(--gray-700); }
  .mp-fees strong { color: var(--gray-500); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 2px; font-weight: 700; }
  .bs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; }
  .bs-card { background: var(--white); border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); overflow: hidden; transition: all 0.25s ease; position: relative; }
  .bs-card:hover { border-color: var(--gold); transform: translateY(-4px); box-shadow: var(--shadow-lg); }
  .bs-rank { position: absolute; top: 14px; left: 14px; background: var(--black); color: var(--white); width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.95rem; z-index: 2; box-shadow: 0 4px 12px rgba(26,26,26,0.3); }
  .bs-rank.top3 { background: var(--gold); color: var(--black); }
  .bs-image { width: 100%; height: 220px; background: var(--gray-100); display: flex; align-items: center; justify-content: center; overflow: hidden; }
  .bs-image img { width: 100%; height: 100%; object-fit: cover; }
  .bs-image-placeholder { color: var(--gray-300); font-size: 3rem; }
  .bs-body { padding: 20px; }
  .bs-title { font-family: var(--font-main); font-weight: 700; color: var(--black); font-size: 1rem; margin-bottom: 4px; line-height: 1.3; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; letter-spacing: 0.01em; text-transform: uppercase; }
  .bs-variant { font-size: 0.74rem; color: var(--gray-500); margin-bottom: 14px; letter-spacing: 0.03em; }
  .bs-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .bs-stat { padding: 10px 12px; background: var(--gray-100); border-radius: var(--radius-sm); }
  .bs-stat-label { font-size: 0.6rem; color: var(--gray-500); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 4px; }
  .bs-stat-value { font-weight: 700; color: var(--black); font-size: 0.9rem; }
  .bs-stat.fatturato { background: var(--gold-light); }
  .bs-stat.ricavo { background: var(--green-light); color: var(--green-dark); }
  .bs-stat.ricavo .bs-stat-value { color: var(--green-dark); }
  .bs2 { display: block; }
  .bs2-kpi { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin-bottom: 18px; }
  .bs2-kpi > div { background: var(--gray-100); border-radius: 12px; padding: 10px 12px; }
  .bs2-kpi span { display: block; font-size: 0.64rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--gray-500); }
  .bs2-kpi b { font-size: 1.05rem; font-weight: 600; white-space: nowrap; } .bs2-kpi small { font-size: 0.72rem; color: var(--gray-500); font-weight: 400; }
  .bs2-sec { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--gray-700); margin: 6px 0 8px; font-weight: 600; }
  .bs2-brands { margin-bottom: 18px; }
  .bs2-brand { display: grid; grid-template-columns: minmax(0,1.4fr) minmax(0,1fr) 72px 64px; gap: 8px; align-items: center; padding: 7px 0; font-size: 0.82rem; border-top: 1px solid var(--gray-100); }
  .bs2-brand small { display: block; font-size: 0.66rem; color: var(--gray-500); font-weight: 400; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bs2-brand.bs2-bhead { border-top: none; padding: 0 0 2px; font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--gray-500); } .bs2-bhead span:not(:first-child) { text-align: right; }
  .bs2-bn b { font-weight: 500; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bs2-bm, .bs2-bs { text-align: right; } .bs2-bs { font-weight: 500; }
  .bs2-bn { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bs2-bar { height: 8px; background: var(--gray-100); border-radius: 4px; overflow: hidden; } .bs2-bar i { display: block; height: 100%; background: var(--black); border-radius: 4px; }
  .bs2-bv { text-align: right; white-space: nowrap; font-weight: 500; } .bs2-bv small { color: var(--gray-500); font-weight: 400; font-size: 0.68rem; }
  .bs2-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
  .bs2-chips { display: flex; gap: 6px; } .bs2-chip { border: 1px solid var(--gray-200); background: #fff; border-radius: 999px; padding: 5px 12px; font-size: 0.74rem; cursor: pointer; font-family: inherit; } .bs2-chip.on { background: var(--black); color: #fff; border-color: var(--black); }
  .bs2-row { border-top: 1px solid var(--gray-100); } .bs2-row > summary { list-style: none; cursor: pointer; display: grid; grid-template-columns: 26px 52px minmax(0,1fr) auto; gap: 10px; align-items: center; padding: 8px 0; } .bs2-row > summary::-webkit-details-marker { display: none; }
  .bs2-rank { font-size: 0.78rem; font-weight: 600; color: var(--gray-500); text-align: center; } .bs2-rank.top { color: var(--black); }
  .bs2-img { width: 52px; height: 52px; border-radius: 8px; background: var(--gray-100); overflow: hidden; display: flex; align-items: center; justify-content: center; color: var(--gray-300); } .bs2-img img { width: 100%; height: 100%; object-fit: cover; }
  .bs2-info { min-width: 0; display: flex; flex-direction: column; } .bs2-t { font-size: 0.86rem; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; } .bs2-s { font-size: 0.72rem; color: var(--gray-500); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bs2-num { text-align: right; display: flex; flex-direction: column; align-items: flex-end; gap: 2px; } .bs2-num b { font-size: 0.9rem; font-weight: 600; white-space: nowrap; }
  .bs2-m { font-size: 0.66rem; padding: 1px 7px; border-radius: 999px; background: var(--gray-100); } .bs2-m.ok { background: var(--green-light); color: var(--green-dark); } .bs2-m.mid { background: #FFF4D6; color: #8B6914; } .bs2-m.low { background: #FDECEC; color: #B42318; }
  .bs2-det { padding: 0 0 10px 88px; font-size: 0.78rem; color: var(--gray-700); display: grid; gap: 4px; } .bs2-l { font-size: 0.64rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--gray-500); margin-right: 4px; }
  .bs2-ch { display: inline-block; background: var(--gray-100); border-radius: 6px; padding: 1px 6px; margin: 0 4px 2px 0; font-size: 0.72rem; }
  @media (max-width: 640px) { .bs2-kpi { grid-template-columns: repeat(2, minmax(0,1fr)); } .bs2-brand { grid-template-columns: minmax(0,1.3fr) minmax(0,1fr) 62px 52px; gap: 6px; } .bs2-det { padding-left: 0; } }
  .ric-src { font-size: 0.74rem; color: var(--gray-500); margin-bottom: 12px; } .ric-src a { color: var(--gray-700); }
  .ric-list { margin: 0 0 16px 18px; padding: 0; font-size: 0.84rem; line-height: 1.5; } .ric-list li { margin-bottom: 4px; }
  .ric-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; margin-bottom: 18px; }
  .ric-card { border-radius: 12px; padding: 12px 14px; font-size: 0.84rem; } .ric-card.ok { background: var(--green-light); } .ric-card.low { background: #FDECEC; }
  .ric-card b { display: block; } .ric-card > span { display: block; font-size: 0.72rem; color: var(--gray-500); margin-bottom: 6px; } .ric-card small { color: var(--gray-500); }
  .ric-table { margin-bottom: 8px; }
  .ric-row { display: grid; grid-template-columns: minmax(0,1.6fr) minmax(0,0.8fr) 70px minmax(0,1fr) 88px; gap: 8px; align-items: center; padding: 7px 0; border-top: 1px solid var(--gray-100); font-size: 0.82rem; }
  .ric-row.ric-3 { grid-template-columns: minmax(0,1.4fr) minmax(0,1fr) 70px; }
  .ric-row small { display: block; font-size: 0.66rem; color: var(--gray-500); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .ric-row b { font-weight: 500; } .ric-row > span:not(:first-child) { text-align: right; }
  .ric-h { border-top: none; font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--gray-500); }
  .ric-na { font-size: 0.66rem; color: var(--gray-300); }
  .ric-exp > summary { list-style: none; cursor: pointer; } .ric-exp > summary::-webkit-details-marker { display: none; }
  .ric-exp[open] > summary { background: var(--gray-100); }
  .ric-det { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 16px; padding: 8px 4px 12px; font-size: 0.8rem; background: var(--gray-100); border-radius: 0 0 10px 10px; margin-bottom: 4px; }
  .ric-det .bs2-l { display: block; margin-bottom: 3px; }
  .ric-it { display: grid; grid-template-columns: 44px minmax(0,1fr); gap: 8px; align-items: center; margin-bottom: 6px; } .ric-it small { display: block; font-size: 0.68rem; color: var(--gray-500); }
  .ric-img { width: 44px; height: 44px; border-radius: 6px; background: #fff; overflow: hidden; display: flex; align-items: center; justify-content: center; color: var(--gray-300); } .ric-img img { width: 100%; height: 100%; object-fit: cover; } .ric-nota { grid-column: 1 / -1; font-size: 0.74rem; color: var(--gray-500); }
  @media (max-width: 640px) { .ric-det { grid-template-columns: 1fr; } } .ric-tags { margin-bottom: 8px; }
  @media (max-width: 640px) { .ric-row { grid-template-columns: minmax(0,1.3fr) 62px minmax(0,1fr) 78px; } .ric-row > span:nth-child(2) { display: none; } .ric-row.ric-3 { grid-template-columns: minmax(0,1.2fr) minmax(0,1fr) 62px; } .ric-row.ric-3 > span:nth-child(2) { display: block; } }
  .bs-empty { text-align: center; padding: 80px 20px; color: var(--gray-500); font-style: italic; grid-column: 1 / -1; }
  .confronto-form { background: var(--cream); padding: 24px; border-radius: var(--radius-md); margin-bottom: 24px; border: 1px solid var(--gray-200); }
  .table-wrap { overflow-x: auto; border-radius: var(--radius-md); border: 1px solid var(--gray-200); }
  .compare-table { width: 100%; border-collapse: collapse; background: var(--white); }
  .compare-table thead { background: var(--black); color: var(--white); }
  .compare-table th { padding: 16px 14px; text-align: left; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; white-space: nowrap; }
  .compare-table td { padding: 16px 14px; border-bottom: 1px solid var(--gray-100); font-size: 0.88rem; color: var(--gray-900); }
  .compare-table tbody tr:hover { background: var(--cream); }
  .compare-table tr.best { background: var(--green-light); }
  .compare-table tr.best td:first-child { border-left: 3px solid var(--green-primary); font-weight: 700; }
  .compare-table tr.worst { background: var(--red-light); }
  .compare-table tr.worst td:first-child { border-left: 3px solid var(--red); }
  .mp-pill { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.62rem; font-weight: 700; margin-left: 8px; letter-spacing: 0.08em; text-transform: uppercase; }
  .mp-pill.win { background: var(--green-primary); color: var(--white); }
  .mp-pill.lose { background: var(--red); color: var(--white); }
  .num-pos { color: var(--green-dark); font-weight: 700; }
  .num-neg { color: var(--red); font-weight: 700; }
  .compare-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 24px; }
  .summary-card { padding: 22px; border-radius: var(--radius-md); border: 1.5px solid; }
  .summary-card.best-mp { background: var(--green-light); border-color: var(--green-primary); }
  .summary-card.worst-mp { background: var(--red-light); border-color: var(--red); }
  .summary-card.info { background: var(--gold-light); border-color: var(--gold); }
  .summary-label { font-size: 0.68rem; color: var(--gray-700); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 8px; }
  .summary-value { font-family: var(--font-main); font-size: 1.2rem; font-weight: 700; color: var(--black); letter-spacing: 0.02em; text-transform: uppercase; }
  .summary-detail { margin-top: 6px; font-size: 0.82rem; color: var(--gray-700); }
  .alerts-banner:empty { display: none; }
  .alerts-banner { background: var(--white); border: 1px solid #ECE6DA; border-radius: var(--radius-lg); padding: 16px 20px; margin-bottom: 16px; }
  .alerts-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px; }
  .alerts-title { font-family: 'Bodoni Moda', Georgia, serif; font-size: 1.15rem; font-weight: 500; }
  .alerts-refresh { background: transparent; border: 1px solid var(--gray-200); border-radius: 999px; padding: 5px 12px; font-family: var(--font-main); font-size: 0.7rem; cursor: pointer; color: var(--gray-700); }
  .alert-item { display: flex; gap: 10px; align-items: flex-start; padding: 10px 0; border-top: 1px solid var(--gray-100); font-size: 0.85rem; line-height: 1.45; }
  .alert-item:first-of-type { border-top: none; }
  .alert-dot { flex: 0 0 8px; height: 8px; border-radius: 50%; margin-top: 6px; }
  .alert-item.critico .alert-dot { background: var(--red); }
  .alert-item.attenzione .alert-dot { background: var(--gold); }
  .alert-item strong { font-weight: 600; }
  .alerts-ok { font-size: 0.82rem; color: var(--green-dark); }
  .alerts-meta { font-size: 0.7rem; color: var(--gray-500); margin-top: 6px; }
  .ch-card { border: 1px solid #ECE6DA; border-radius: 14px; padding: 12px 14px; margin-top: 10px; }
  .ch-card.critico { border-color: var(--red); } .ch-card.attenzione { border-color: var(--gold); }
  .ch-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
  .ch-name { font-family: 'Bodoni Moda', Georgia, serif; font-size: 1.05rem; font-weight: 500; }
  .ch-sub { font-size: 0.68rem; color: var(--gray-500); }
  .ch-row { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr) 66px; gap: 8px 12px; align-items: end; padding: 6px 0; border-top: 1px solid var(--gray-100); }
  .ch-row:first-of-type { border-top: none; }
  .ch-lab { font-size: 0.66rem; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.05em; }
  .ch-val { font-size: 1rem; font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: clip; } .ch-val small { font-size: 0.66rem; color: var(--gray-500); font-weight: 400; } .ch-val.muted { color: var(--gray-700); }
  .ch-pill { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 0.72rem; font-weight: 500; background: var(--gray-100); color: var(--gray-700); white-space: nowrap; }
  .ch-row > div:last-child { text-align: right; }
  .ch-pill.up { background: var(--green-light); color: var(--green-dark); } .ch-pill.down { background: var(--red-light); color: var(--red); }
  .ch-note { font-size: 0.82rem; color: var(--gray-700); line-height: 1.5; }
  .src-row { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, 1fr) auto; gap: 8px; align-items: center; padding: 5px 0; font-size: 0.78rem; }
  .src-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .src-bar { height: 6px; background: var(--gray-100); border-radius: 3px; overflow: hidden; } .src-bar i { display: block; height: 100%; background: var(--gold); border-radius: 3px; }
  .src-num { white-space: nowrap; color: var(--gray-700); font-size: 0.74rem; }
  .ch-altri { margin-top: 10px; font-size: 0.82rem; } .ch-altri summary { cursor: pointer; color: var(--gray-700); padding: 6px 0; }
  .ch-altri .src-row { grid-template-columns: minmax(0, 1fr) auto auto; }
  .mp-badge { white-space: nowrap; }
  .breakdown-table td:first-child { white-space: nowrap; }
  .kpi-more { margin: -18px 0 24px; border: 1px solid var(--gray-200, #e8e2d6); border-radius: 14px; background: #fff; }
  .kpi-more > summary { list-style: none; cursor: pointer; display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 12px 16px; font-size: 0.8rem; color: var(--gray-700); letter-spacing: 0.02em; }
  .kpi-more > summary::-webkit-details-marker, .fx-det > summary::-webkit-details-marker { display: none; }
  .kpi-more > summary::before { content: '+'; font-weight: 600; margin-right: 2px; } .kpi-more[open] > summary::before { content: '−'; }
  .kpi-more > summary span:first-child { flex: 1; }
  .kpi-more-val { font-weight: 600; color: #00704a; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .kpi-more[open] > summary { border-bottom: 1px solid var(--gray-200, #e8e2d6); }
  .kpi-more .kpi-grid { padding: 12px; margin-bottom: 0; }
  .fx-det { background: #FFF8E6; border-left: 3px solid #E8C77A; border-radius: 8px; margin-bottom: 12px; font-size: 0.78rem; color: #6B4E0E; }
  .fx-det > summary { list-style: none; cursor: pointer; padding: 7px 12px; } .fx-det > summary::before { content: '+ '; } .fx-det[open] > summary::before { content: '− '; }
  .fx-det .fx-body { padding: 0 12px 8px; }
  .ch-det { margin-top: 4px; } .ch-det summary { cursor: pointer; font-size: 0.74rem; color: var(--gray-500); padding: 4px 0; list-style: none; } .ch-det summary::before { content: '+ '; } .ch-det[open] summary::before { content: '− '; }
  .ch-card { padding: 10px 14px; } .ch-head { margin-bottom: 2px; }
  .oggi-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 6px; }
  .oggi-kpi { border-radius: 14px; padding: 14px; border: 1px solid #ECE6DA; }
  .oggi-kpi.dark { background: #1A1A1A; color: #fff; border-color: #1A1A1A; } .oggi-kpi.dark .ch-lab, .oggi-kpi.dark .oggi-sub { color: rgba(255,255,255,0.65); }
  .oggi-kpi.pos { background: var(--green-light); border-color: rgba(0,128,96,0.25); } .oggi-kpi.pos .oggi-val { color: var(--green-dark); }
  .oggi-kpi.neg { background: var(--red-light); border-color: var(--red); } .oggi-kpi.neg .oggi-val { color: var(--red); }
  .oggi-val { font-size: 1.55rem; font-weight: 500; margin-top: 4px; white-space: nowrap; }
  .oggi-sub { font-size: 0.72rem; color: var(--gray-500); margin-top: 2px; }
  .oggi-ieri { font-size: 0.76rem; color: var(--gray-700); margin-top: 10px; }
  .mese-strip { border: 1px solid #ECE6DA; border-radius: 12px; padding: 6px 12px; margin: 4px 0 10px; }
  .mese-row { display: grid; grid-template-columns: minmax(0, 1fr) 78px 82px 48px; gap: 8px; align-items: center; padding: 5px 0; font-size: 0.78rem; border-top: 1px solid var(--gray-100); }
  .mese-row:first-child, .mese-row.mese-head + .mese-row { border-top: none; }
  .mese-head { font-size: 0.6rem; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.06em; padding-bottom: 0; }
  .mese-nome { color: var(--gray-700); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-transform: capitalize; }
  .mese-num { font-weight: 500; white-space: nowrap; text-align: right; } .mese-head span { text-align: right; } .mese-num.pos { color: var(--green-dark); } .mese-num small { font-size: 0.62rem; color: var(--gray-500); font-weight: 400; display: block; line-height: 1; } .mese-row .ch-pill { font-size: 0.66rem; padding: 2px 7px; }
  /* ===== v5.13 restyle: tipografia sito (Bodoni Moda + Jost), oro come accento, mobile-first ===== */
  :root { --font-main: 'Jost', -apple-system, 'Segoe UI', Roboto, sans-serif; --font-display: 'Bodoni Moda', 'Didot', Georgia, serif; --gold: #B8935A; --gold-light: #F6EFE2; }
  body { font-weight: 400; letter-spacing: 0; }
  .logo { font-family: var(--font-display); font-weight: 500; letter-spacing: 0.06em; }
  .section-title, .header-info h1 { font-family: var(--font-display); font-weight: 500; text-transform: none; letter-spacing: 0.01em; }
  .header-info h1 { font-size: 1.15rem; }
  .kpi-value, .result-value, .summary-value { font-family: var(--font-main); font-weight: 500; letter-spacing: -0.01em; }
  .tab, .period-btn, .btn-primary, .status-pill, .kpi-label, .form-group label, .breakdown-title { font-weight: 500; }
  .tab.active { background: var(--black); }
  .tab:hover:not(.active) { background: var(--gold-light); }
  .section, .header, .tabs-wrap { box-shadow: none; border: 1px solid #ECE6DA; }
  .kpi { border-color: #ECE6DA; }
  .kpi:hover { transform: none; box-shadow: none; border-color: var(--gold); }
  .kpi.gold { background: var(--gold-light); border-color: var(--gold); }
  .breakdown-table thead, .compare-table thead { background: #1A1A1A; }
  .tabs::-webkit-scrollbar, .period-selector::-webkit-scrollbar { display: none; }
  @media (max-width: 768px) {
    .container { padding: 12px; }
    .header { padding: 12px 14px; border-radius: 14px; margin-bottom: 10px; flex-wrap: nowrap; gap: 10px; }
    .header-left { gap: 10px; min-width: 0; }
    .logo { font-size: 1.45rem; white-space: nowrap; }
    .header-divider { display: none; }
    .header-info h1 { font-size: 0.85rem; margin-bottom: 0; white-space: nowrap; }
    .header-info { min-width: 0; }
    .header-info p { display: block; font-size: 0.68rem; letter-spacing: 0.08em; margin-top: 1px; opacity: 0.75; }
    .header-info p .hide-m { display: none; }
    .header-info h1 { overflow: hidden; text-overflow: ellipsis; }
    .header-right { gap: 6px; flex-wrap: nowrap; }
    .status-pill { padding: 5px 10px; font-size: 0.64rem; }
    #logoutBtn { margin-left: 0 !important; padding: 6px 10px !important; font-size: 0.64rem !important; }
    .tabs-wrap { position: sticky; top: 0; z-index: 20; padding: 6px; border-radius: 14px; margin-bottom: 12px; background: rgba(255,255,255,0.96); -webkit-backdrop-filter: blur(8px); backdrop-filter: blur(8px); }
    .tabs { flex-direction: row; flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; -webkit-overflow-scrolling: touch; gap: 6px; scroll-snap-type: x proximity; }
    .tab { flex: 0 0 auto; min-width: 0; padding: 9px 15px; border-radius: 999px; font-size: 0.72rem; letter-spacing: 0.04em; scroll-snap-align: start; white-space: nowrap; }
    .section { padding: 18px 16px; border-radius: 14px; margin-bottom: 12px; }
    .section-header { margin-bottom: 16px; gap: 10px; }
    .section-title { font-size: 1.45rem; }
    .section-subtitle { font-size: 0.78rem; }
    .info-box, .warn-box { padding: 10px 12px; font-size: 0.78rem; margin-bottom: 14px; }
    .filter-bar { flex-direction: column; align-items: stretch; gap: 10px; margin-bottom: 16px; }
    .period-selector { flex-wrap: nowrap; overflow-x: auto; scrollbar-width: none; }
    .period-btn { flex: 0 0 auto; padding: 8px 14px; font-size: 0.7rem; }
    .period-selector { max-width: 100%; }
    .custom-range { flex-wrap: wrap; border-radius: 14px; max-width: 100%; padding: 8px 10px; gap: 4px; }
    .custom-range input[type="date"] { flex: 1 1 110px; min-width: 0; font-size: 0.8rem; padding: 4px; }
    .custom-range .apply-btn { flex: 1 0 100%; padding: 9px; }
    .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 18px; }
    .kpi-more { margin: -8px 0 18px; } .kpi-more .kpi-grid { padding: 10px; }
    .kpi { padding: 14px; }
    .kpi-label { font-size: 0.62rem; margin-bottom: 8px; }
    .kpi-value { font-size: 1.3rem; word-break: break-word; }
    .kpi-sub { font-size: 0.66rem; }
    .breakdown-table th, .breakdown-table td, .compare-table th, .compare-table td { padding: 10px 8px; font-size: 0.78rem; }
    .breakdown-table th:first-child, .breakdown-table td:first-child { position: sticky; left: 0; background: inherit; z-index: 1; }
    .breakdown-table tbody td:first-child { background: var(--white); }
    .breakdown-table thead th:first-child { background: #1A1A1A; }
    .breakdown-table .mp-badge { font-size: 0.64rem; padding: 3px 8px; max-width: 110px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
    .breakdown-table .toggle-arrow { width: 10px; margin-right: 0; }
    .breakdown-table td:first-child, .breakdown-table th:first-child { box-shadow: 1px 0 0 var(--gray-200); }
    .results, .mp-grid, .duo-grid, .form-grid { grid-template-columns: 1fr; }
    .results { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .btn-primary { padding: 14px 20px; }
  }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-left">
      <div class="logo">T<span class="dot">.</span> LUXY</div>
      <div class="header-divider"></div>
      <div class="header-info">
        <h1>Business Manager</h1>
        <p><span class="hide-m">Business Intelligence Dashboard · </span>v5.35</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill"><div class="status-dot"></div>Live</div>
      <button id="logoutBtn" style="background:transparent; border:1px solid rgba(0,0,0,0.15); padding:8px 14px; border-radius:50px; cursor:pointer; font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:var(--gray-700); margin-left:12px; font-family:var(--font-main); transition:all 0.2s;" onmouseover="this.style.background='var(--gray-100)'" onmouseout="this.style.background='transparent'">Esci</button>
    </div>
  </div>
  <div class="tabs-wrap">
    <div class="tabs">
      <button class="tab active" data-tab="analytics">Analytics</button>
      <button class="tab" data-tab="bestsellers">Best Seller</button>
      <button class="tab" data-tab="ricerche">Ricerche</button>
      <button class="tab" data-tab="compare">Confronto MP</button>
      <button class="tab" data-tab="calculator">Calcolatore</button>
      <button class="tab" data-tab="marketplaces">Marketplace</button>
      <button class="tab" data-tab="duo">Simulatore DUO</button>
      <button class="tab" data-tab="forecast">💰 Previsioni Incassi</button>
      <button class="tab" data-tab="inventory">📦 Inventario</button>
      <button class="tab" data-tab="chat">💬 Assistente AI</button>
    </div>
  </div>
  <div id="analytics-tab" class="tab-content active">
    <div id="oggi-box" class="alerts-banner"></div>
    <div id="alerts-banner" class="alerts-banner"></div>
    <div id="duo-alerts" class="alerts-banner"></div>
    <div class="section">
      <div class="section-header"><div><div class="section-title">Performance</div><div class="section-subtitle">Analisi vendite e marginalità in tempo reale</div></div></div>
      <div class="info-box">Fuso orario Europa/Roma reale. Costo merce letto da Shopify. Ordini senza "Cost per item" segnalati sotto.</div>
      <div class="filter-bar">
        <div class="period-selector" data-analytics-periods>
          <button class="period-btn active" data-period="today">Oggi</button>
          <button class="period-btn" data-period="yesterday">Ieri</button>
          <button class="period-btn" data-period="week">Settimana</button>
          <button class="period-btn" data-period="month">Mese</button>
          <button class="period-btn" data-period="quarter">Trimestre</button>
          <button class="period-btn" data-period="year">Anno</button>
        </div>
        <div class="custom-range"><label>Da</label><input type="date" id="date-from"><label>A</label><input type="date" id="date-to"><button class="apply-btn" id="analytics-apply">Applica</button></div>
      </div>
      <div class="kpi-grid">
        <div class="kpi primary"><div class="kpi-label">Lordo IVA inclusa</div><div class="kpi-value" id="lordo">—</div><div class="kpi-sub" id="ordini-count">— ordini</div></div>
        <div class="kpi"><div class="kpi-label">IVA Scorporata</div><div class="kpi-value" id="iva">—</div><div class="kpi-sub">Da versare</div></div>
      </div>
      <details class="kpi-more"><summary><span>Costi e margine</span><span class="kpi-more-val" id="kpi-more-val"></span></summary>
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-label">Costi Totali</div><div class="kpi-value" id="costi">—</div><div class="kpi-split" id="costi-split" style="margin-top:8px; padding-top:8px; border-top:1px solid rgba(0,0,0,0.08); font-size:0.78rem; line-height:1.5;"><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Merce</span><span id="costi-merce" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Fees + sped.</span><span id="costi-fees" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div></div></div>
        <div class="kpi green"><div class="kpi-label">Margine Netto</div><div class="kpi-value" id="netto">—</div><div class="kpi-sub">Profitto reale</div></div>
        <div class="kpi gold"><div class="kpi-label">Margine %</div><div class="kpi-value" id="margine">—</div><div class="kpi-sub">Su lordo</div></div>
      </div>
      </details>
      <div id="refunds-panel"></div>
      <div id="foreign-currency-panel"></div>
      <div id="errors-panel"></div>
      <div class="breakdown-section">
        <div class="breakdown-title">Breakdown per Marketplace</div>
        <div class="breakdown-sub">Clicca su un marketplace per vedere il dettaglio di tutti gli ordini</div>
        <div class="breakdown-table-wrap">
          <table class="breakdown-table">
            <thead><tr><th>Marketplace</th><th class="num">Ordini</th><th class="num">Fatturato</th><th class="num">IVA</th><th class="num">Costo Merce</th><th class="num">Margine Netto</th><th class="num">Margine %</th></tr></thead>
            <tbody id="breakdown-body"><tr><td colspan="7" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;">Caricamento breakdown...</td></tr></tbody>
            <tfoot id="breakdown-foot"></tfoot>
          </table>
        </div>
      </div>
    </div>
  </div>
  <div id="bestsellers-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Best Seller</div><div class="section-subtitle">Brand e modelli più venduti, con margine e quota sul sito</div></div></div>
      
      <div class="filter-bar">
        <div class="period-selector" data-bs-periods>
          <button class="period-btn" data-period="today">Oggi</button>
          <button class="period-btn" data-period="week">Settimana</button>
          <button class="period-btn active" data-period="month">Mese</button>
          <button class="period-btn" data-period="quarter">Trimestre</button>
          <button class="period-btn" data-period="year">Anno</button>
        </div>
        <div class="custom-range"><label>Da</label><input type="date" id="bs-date-from"><label>A</label><input type="date" id="bs-date-to"><button class="apply-btn" id="bs-apply">Applica</button></div>
      </div>
      <div id="bs-content" class="bs-grid"><div class="bs-empty">Caricamento prodotti...</div></div>
    </div>
  </div>
  <div id="ricerche-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Ricerche</div><div class="section-subtitle">Miinto SS27 Buying Guidelines incrociate con le vendite e il catalogo TLuxy</div></div></div>
      <div id="ric-content"><div class="bs-empty">Apri la scheda per caricare l'analisi.</div></div>
    </div>
  </div>
  <div id="compare-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Confronto Marketplace</div><div class="section-subtitle">Margine effettivo a parità di condizioni</div></div></div>
      <div class="info-box">Modifica i valori per confronto in tempo reale.</div>
      <div class="confronto-form">
        <div class="form-grid">
          <div class="form-group"><label>Prezzo IVA inclusa (€)</label><input type="number" id="c-prezzo" value="100" step="0.01"></div>
          <div class="form-group"><label>Paese / IVA</label><select id="c-iva">
            <option value="22">🇮🇹 Italia (22%)</option><option value="20">🇫🇷 Francia (20%)</option><option value="19">🇩🇪 Germania (19%)</option><option value="21">🇪🇸 Spagna (21%)</option><option value="21">🇳🇱 Olanda (21%)</option><option value="21">🇧🇪 Belgio (21%)</option><option value="20">🇦🇹 Austria (20%)</option><option value="23">🇮🇪 Irlanda (23%)</option><option value="23">🇵🇱 Polonia (23%)</option><option value="25">🇸🇪 Svezia (25%)</option><option value="25">🇩🇰 Danimarca (25%)</option><option value="20">🇬🇧 Regno Unito (20%)</option><option value="0">🇺🇸 USA / Extra-UE (0%)</option>
          </select></div>
          <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="c-costo" value="45" step="0.01"></div>
          <div class="form-group"><label>Spedizione (€)</label><input type="number" id="c-spedizione" value="5" step="0.01"></div>
        </div>
      </div>
      <div class="table-wrap"><table class="compare-table" id="compare-table"><thead><tr><th>Marketplace</th><th>Sconto</th><th>Prezzo Netto</th><th>Fees Shopify</th><th>Fees MP</th><th>Margine €</th><th>Margine %</th><th>Esito</th></tr></thead><tbody id="compare-body"></tbody></table></div>
      <div class="compare-summary" id="compare-summary"></div>
    </div>
  </div>
  <div id="calculator-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Calcolatore</div><div class="section-subtitle">Simulatore marginalità singolo marketplace</div></div></div>
      <div class="info-box">Inserisci prezzo IVA inclusa e aliquota IVA del paese.</div>
      <div style="background:var(--cream); border:1.5px solid var(--gold); border-radius:var(--radius-md); padding:18px 22px; margin-bottom:20px;">
        <div style="font-size:0.85rem; font-weight:700; color:var(--gray-900); text-transform:uppercase; letter-spacing:0.06em; margin-bottom:12px;">🧮 Scorciatoia Retail (opzionale)</div>
        <div style="font-size:0.8rem; color:var(--gray-700); margin-bottom:14px;">Compila Retail + Sconti per calcolare automaticamente Prezzo IVA inclusa e Costo Merce. Lascia vuoto per inserire manualmente.</div>
        <div class="form-grid" style="grid-template-columns:repeat(3, 1fr);">
          <div class="form-group"><label>Retail RRP (€)</label><input type="number" id="calc-retail" placeholder="es. 500" step="0.01" min="0"></div>
          <div class="form-group"><label>Sconto Vendita (%)</label><input type="number" id="calc-sconto-vendita" placeholder="es. 10" step="0.1" min="0" max="100"></div>
          <div class="form-group"><label>Sconto Costo (%)</label><input type="number" id="calc-sconto-costo" placeholder="es. 50" step="0.1" min="0" max="100"></div>
        </div>
        <div id="calc-retail-summary" style="margin-top:12px; padding:10px 14px; background:var(--green-light); border-left:3px solid var(--green-primary); border-radius:6px; font-size:0.85rem; color:var(--green-dark); display:none;"></div>
      </div>
      <div class="form-grid">
        <div class="form-group"><label>Prezzo IVA inclusa (€)</label><input type="number" id="prezzo" value="100" step="0.01"></div>
        <div class="form-group"><label>Paese / IVA</label><select id="iva-select">
          <option value="22">🇮🇹 Italia (22%)</option><option value="20">🇫🇷 Francia (20%)</option><option value="19">🇩🇪 Germania (19%)</option><option value="21">🇪🇸 Spagna (21%)</option><option value="21">🇳🇱 Olanda (21%)</option><option value="21">🇧🇪 Belgio (21%)</option><option value="20">🇦🇹 Austria (20%)</option><option value="23">🇮🇪 Irlanda (23%)</option><option value="23">🇵🇱 Polonia (23%)</option><option value="25">🇸🇪 Svezia (25%)</option><option value="25">🇩🇰 Danimarca (25%)</option><option value="20">🇬🇧 Regno Unito (20%)</option><option value="0">🇺🇸 USA / Extra-UE (0%)</option>
        </select></div>
        <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="costo" value="45" step="0.01"></div>
        <div class="form-group"><label>Spedizione (€)</label><input type="number" id="spedizione" value="5" step="0.01"></div>
        <div class="form-group"><label>Marketplace</label><select id="mp-select"></select></div>
      </div>
      <button class="btn-primary" id="calcola-btn">Calcola Marginalità</button>
      <div class="results" id="results" style="display:none;">
        <div class="result-card"><div class="result-label">Lordo IVA incl.</div><div class="result-value" id="r-lordo">-</div></div>
        <div class="result-card"><div class="result-label">IVA Scorporata</div><div class="result-value" id="r-iva">-</div></div>
        <div class="result-card"><div class="result-label">Netto IVA</div><div class="result-value" id="r-netto-iva">-</div></div>
        <div class="result-card"><div class="result-label">Netto Marketplace</div><div class="result-value" id="r-netto">-</div></div>
        <div class="result-card"><div class="result-label">Fees Shopify</div><div class="result-value" id="r-shopify">-</div></div>
        <div class="result-card"><div class="result-label">Fees Marketplace</div><div class="result-value" id="r-mp">-</div></div>
        <div class="result-card" id="r-margine-card"><div class="result-label">Margine Netto</div><div class="result-value" id="r-margine">-</div></div>
        <div class="result-card"><div class="result-label">Margine %</div><div class="result-value" id="r-perc">-</div></div>
        <div class="result-card" id="r-redd-card"><div class="result-label">Esito</div><div class="result-value" id="r-redd">-</div></div>
      </div>
    </div>
    
    <!-- ============ EXCEL BATCH CALCULATOR (v5.10) ============ -->
    <div class="section" style="margin-top:24px;">
      <div class="section-header">
        <div>
          <div class="section-title">📊 Calcolo batch da Excel</div>
          <div class="section-subtitle">Carica un file Excel/CSV con prodotti · calcolo margine su tutti i 16 marketplace · supporta sconto% fornitore</div>
        </div>
      </div>
      <div class="info-box">
        <strong>Obbligatorie</strong>: <code>SKU</code>, <code>Retail</code> (o Listino), e <code>Costo</code> O <code>Sconto%</code>. <strong>Opzionali</strong>: <code>Titolo</code>, <code>Stock</code>, <code>Listino</code> (di vendita), <code>IVA</code>.<br>
        <strong>Esempio</strong>: Retail €500 con Sconto% 50 → Costo €250 calcolato automaticamente. Puoi anche caricare direttamente Retail + Costo.
      </div>
      <div class="filter-bar" style="gap:12px;">
        <label class="apply-btn" style="background:var(--green-primary); cursor:pointer; padding:10px 18px;">
          <i style="display:inline-block; transform:scale(1.2); margin-right:4px;">📤</i> Carica Excel/CSV
          <input type="file" id="batch-file" accept=".xlsx,.xls,.csv" style="display:none;">
        </label>
        <button id="batch-template-btn" class="apply-btn" style="background:var(--gray-700); padding:10px 18px;">
          <i style="display:inline-block; transform:scale(1.2); margin-right:4px;">📥</i> Scarica template
        </button>
        <div style="margin-left:auto; display:flex; gap:10px; align-items:center;">
          <label style="font-size:0.72rem; color:var(--gray-700); font-weight:700; text-transform:uppercase; letter-spacing:0.06em;">IVA default</label>
          <select id="batch-iva-default" style="padding:8px 12px; border:1.5px solid var(--gray-200); border-radius:8px; font-size:0.85rem; font-family:inherit;">
            <option value="22" selected>🇮🇹 Italia 22%</option>
            <option value="20">🇫🇷🇬🇧🇦🇹 20%</option>
            <option value="19">🇩🇪 Germania 19%</option>
            <option value="21">🇪🇸🇳🇱🇧🇪 21%</option>
            <option value="23">🇵🇱🇮🇪🇵🇹 23%</option>
            <option value="25">🇸🇪🇩🇰 25%</option>
            <option value="0">🌍 Extra-UE 0%</option>
          </select>
        </div>
      </div>
      <div id="batch-status" style="font-size:0.85rem; color:var(--gray-700); margin:10px 0;"></div>
      <div id="batch-content"></div>
    </div>
  </div>
  <div id="marketplaces-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Portfolio Marketplace</div><div class="section-subtitle">Configurazioni canali</div></div></div>
      <div class="warn-box">Riconoscimento via <code>source_name</code>. Verifica con <code>/api/debug-orders</code>.</div>
      <div class="mp-grid" id="mp-grid"></div>
    </div>
  </div>
  <div id="duo-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Simulatore DUO</div>
          <div class="section-subtitle">Prodotti dropship (fungi da marketplace) — calcola a quale prezzo ti conviene vendere</div>
        </div>
      </div>
      <div id="duo-kv-status" class="warn-box">Caricamento stato KV...</div>
      <div class="filter-bar" style="gap:12px;">
        <button class="apply-btn" id="duo-reload" style="background:var(--black);">🔄 Ricarica prodotti</button>
        <label class="apply-btn" style="background:var(--green-primary); cursor:pointer;">📤 Import costi CSV
          <input type="file" id="duo-csv-file" accept=".csv" style="display:none;">
        </label>
        <span id="duo-import-status" style="font-size:0.85rem; color:var(--gray-700);"></span>
        <div style="margin-left:auto; display:flex; gap:8px; align-items:center;">
          <label style="font-size:0.78rem; color:var(--gray-700); font-weight:700; text-transform:uppercase;">Cerca</label>
          <input type="text" id="duo-search" placeholder="Titolo / SKU..." style="padding:8px 14px; border:1.5px solid var(--gray-200); border-radius:50px; font-size:0.85rem; min-width:220px;">
        </div>
      </div>
      <div class="info-box" style="margin-top:12px;">
        <strong>Come funziona</strong>: clicca "Ricarica prodotti" per vedere tutti i DUO attivi. Inserisci il costo fornitore e il prezzo vendita, scegli il marketplace → ti mostro il margine reale. Puoi anche importare tutti i costi in blocco da un file CSV con colonne <code>variant_id,cost</code> (o <code>sku,cost</code>).
      </div>
      <div id="duo-content">
        <div class="bs-empty">Clicca "Ricarica prodotti" per caricare i DUO da Shopify.</div>
      </div>
    </div>
  </div>
  <div id="forecast-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Previsioni Incassi</div>
          <div class="section-subtitle">Scadenziario bonifici MP · cache aggiornata 1 volta al giorno</div>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="apply-btn" id="forecast-reload" style="background:var(--gray-700);" title="Ricarica dalla cache (veloce)">Mostra</button>
          <button class="apply-btn" id="forecast-refresh" style="background:var(--black);" title="Rifà tutti i calcoli (lento)">🔄 Aggiorna ora</button>
        </div>
      </div>
      <div id="forecast-content">
        <div class="bs-empty">Clicca "Ricalcola" per generare le previsioni.</div>
      </div>
    </div>
  </div>
  <div id="inventory-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Snapshot inventario</div>
          <div class="section-subtitle">Pezzi attivi con stock > 0 · categoria × gender · cache 24h</div>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="apply-btn" id="inventory-reload" style="background:var(--gray-700);" title="Carica dalla cache">Mostra</button>
          <button class="apply-btn" id="inventory-refresh" style="background:var(--black);" title="Rifà fetch da Shopify (lento)">🔄 Aggiorna ora</button>
        </div>
      </div>
      <div style="margin:12px 0 16px; display:inline-flex; gap:0; background:var(--gray-100); border-radius:8px; padding:3px;" id="inventory-filter-group">
        <button class="inv-filter active" data-filter="tutto" style="border:none; background:var(--white); color:var(--black); padding:6px 14px; font-size:0.82rem; font-weight:600; border-radius:6px; cursor:pointer;">Tutti</button>
        <button class="inv-filter" data-filter="own" style="border:none; background:transparent; color:var(--gray-700); padding:6px 14px; font-size:0.82rem; font-weight:400; border-radius:6px; cursor:pointer;">Solo mio stock</button>
        <button class="inv-filter" data-filter="duo" style="border:none; background:transparent; color:var(--gray-700); padding:6px 14px; font-size:0.82rem; font-weight:400; border-radius:6px; cursor:pointer;">Solo DUO</button>
      </div>
      <div id="inventory-content">
        <div class="bs-empty">Clicca "Mostra" o "Aggiorna ora" per caricare lo snapshot.</div>
      </div>
    </div>
  </div>
  <div id="chat-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">💬 Assistente AI</div>
          <div class="section-subtitle">Chiedi qualsiasi cosa sui tuoi dati: KPI, ordini, marketplace, suggerimenti</div>
        </div>
        <button id="chat-clear" class="apply-btn" style="background:var(--gray-700); padding:6px 12px; font-size:0.78rem;">🗑️ Pulisci</button>
      </div>
      <div id="chat-status-bar" class="warn-box" style="margin-bottom:12px;">Verifica configurazione...</div>
      <div id="chat-messages" style="background:var(--cream); border:1px solid var(--gray-200); border-radius:12px; padding:18px; min-height:380px; max-height:600px; overflow-y:auto; margin-bottom:14px;">
        <div style="text-align:center; color:var(--gray-500); padding:40px 20px;">
          <div style="font-size:2.5rem; margin-bottom:14px;">💬</div>
          <div style="font-size:0.95rem; margin-bottom:18px;">Ciao Alessio, sono il tuo assistente. Posso aiutarti con:</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; max-width:520px; margin:0 auto;">
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">📊 Quanto ho fatturato questo mese?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">🏆 Qual è il MP più redditizio?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">⚠️ Quanti ordini hanno costi mancanti?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">↩️ Mostrami i resi recenti</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">💰 Quanto incasserò il prossimo mese?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">📦 Stato inventario per categoria?</button>
          </div>
        </div>
      </div>
      <div style="display:flex; gap:8px;">
        <input type="text" id="chat-input" placeholder="Scrivi una domanda..." style="flex:1; padding:14px 18px; border:1.5px solid var(--gray-200); border-radius:50px; font-size:0.95rem; font-family:inherit;">
        <button id="chat-send" class="apply-btn" style="background:var(--black); padding:0 24px; font-size:0.85rem; white-space:nowrap;">Invia →</button>
      </div>
    </div>
  </div>
</div>
<script>
const MARKETPLACES = ${JSON.stringify(MARKETPLACE_CONFIGS)};
const MP_COLORS = { TLUXY_SITE:'#1A1A1A', THE_BRADERY:'#C9A961', MIINTO:'#008060', BALARDI:'#BF4747', ITALIST:'#2D2D2D', JAMMY_DUDE:'#8E4FBF', SECRET_SALES:'#6B5320', FASHION_TAMERS:'#5C5C5C', INTRA_MIRROR:'#B89550', ARCHIVIST:'#004C3F', BOUTIQUE_MALL:'#E8573A', WINKELSTRAAT:'#479CCF', POIZON:'#D4397A', BRANDSGATEWAY:'#4A7FBC', MARK_FOYS:'#2E5F8F', GIGLIO:'#7B4F8A' };

function setActiveButton(selector, btn) { document.querySelectorAll(selector).forEach(b => b.classList.remove('active')); if (btn) btn.classList.add('active'); }
async function fetchNoCache(url) { const sep = url.includes('?') ? '&' : '?'; const res = await fetch(url + sep + '_=' + Date.now(), { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } }); return res.json(); }

function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  const tabBtn = document.querySelector('.tab[data-tab="' + name + '"]'); if (tabBtn) tabBtn.classList.add('active');
  if (name === 'compare' && !document.getElementById('compare-body').children.length) confronta();
  if (name === 'ricerche' && !RIC_DATA) caricaRicerche(false);
  if (name === 'bestsellers') { const bsContent = document.getElementById('bs-content'); if (bsContent.querySelector('.bs-empty')) { const activeBtn = document.querySelector('[data-bs-periods] .period-btn.active') || document.querySelector('[data-bs-periods] .period-btn[data-period="month"]'); loadBestSellers(activeBtn ? activeBtn.dataset.period : 'month', activeBtn); } }
}

function renderErrors(ordiniConErrori) {
  const panel = document.getElementById('errors-panel');
  if (!ordiniConErrori || ordiniConErrori.length === 0) { panel.innerHTML = ''; return; }
  const rows = ordiniConErrori.slice(0, 50).map(o => {
    const prods = o.prodotti_senza_costo.map(p => '&nbsp;&nbsp;&nbsp;• ' + (p.title || 'Senza titolo') + (p.sku ? ' [SKU: ' + p.sku + ']' : '')).join('<br>');
    const origPrice = o.currency && o.currency !== 'EUR' ? o.currency + ' ' + o.total_price + ' → €' + (o.total_price_eur || 0).toFixed(2) : '€' + o.total_price;
    return '<div><strong>Ordine #' + (o.order_number || o.name || o.id) + '</strong> (' + o.marketplace + ', ' + origPrice + ')<br>' + prods + '</div>';
  }).join('');
  const moreMsg = ordiniConErrori.length > 50 ? '<div style="margin-top:8px; font-style:italic;">... e altri ' + (ordiniConErrori.length - 50) + ' ordini</div>' : '';
  panel.innerHTML = '<div class="error-box"><strong>⚠ ' + ordiniConErrori.length + ' ordini esclusi: prodotti senza "Cost per item" su Shopify</strong>Aggiungi il costo su Shopify → Prodotti → Inventario.<div class="error-list">' + rows + moreMsg + '</div></div>';
}

function renderForeignCurrency(ordiniEstero) {
  const panel = document.getElementById('foreign-currency-panel');
  if (!panel) return;
  if (!ordiniEstero || ordiniEstero.length === 0) { panel.innerHTML = ''; return; }
  // Raggruppa per valuta
  const byCurrency = {};
  ordiniEstero.forEach(o => {
    if (!byCurrency[o.currency]) byCurrency[o.currency] = { count: 0, total_orig: 0, total_eur: 0, rates: [] };
    byCurrency[o.currency].count++;
    byCurrency[o.currency].total_orig += o.total_original;
    byCurrency[o.currency].total_eur += o.total_eur;
    byCurrency[o.currency].rates.push(o.exchange_rate);
  });
  const summary = Object.entries(byCurrency).map(([cur, info]) => {
    const avgRate = info.rates.reduce((a, b) => a + b, 0) / info.rates.length;
    return '<div style="padding:6px 0; border-bottom:1px dotted #E8C77A;"><strong>' + cur + '</strong>: ' + info.count + ' ordini · ' + cur + ' ' + info.total_orig.toFixed(2) + ' → <strong>€' + info.total_eur.toFixed(2) + '</strong> (cambio medio ~' + avgRate.toFixed(4) + ')</div>';
  }).join('');
  panel.innerHTML = '<details class="fx-det"><summary>💱 ' + ordiniEstero.length + ' ordin' + (ordiniEstero.length > 1 ? 'i' : 'e') + ' in valuta estera · ' + Object.keys(byCurrency).join(', ') + '</summary><div class="fx-body">Convertit' + (ordiniEstero.length > 1 ? 'i' : 'o') + ' in EUR al cambio storico Shopify' + summary + '</div></details>';
}

function renderRefunds(resi) {
  const panel = document.getElementById('refunds-panel');
  if (!panel) return;
  if (!resi || resi.totale_count === 0) { panel.innerHTML = ''; return; }
  // Riepilogo
  const dettagliRecenti = (resi.dettaglio || []).slice(0, 8).map(r => {
    const dataFmt = r.created_at ? new Date(r.created_at).toLocaleDateString('it-IT', {day:'2-digit', month:'2-digit'}) : '—';
    const tipoBadge = r.tipo === 'totale' ? '<span style="background:#FCEEEE; color:#BF4747; padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">TOTALE</span>' : '<span style="background:#FFE4D6; color:#8B4F14; padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">PARZIALE</span>';
    return '<div style="padding:4px 0; border-bottom:1px dotted #E89A5A;"><strong>' + (r.name || '#' + r.order_number) + '</strong>' + tipoBadge + ' · ' + dataFmt + ' · ' + r.marketplace + ' · <strong>€' + r.importo_rimborsato_eur.toFixed(2) + '</strong> rimborsati' + (r.tipo === 'parziale' ? ' (' + r.quantita_rimborsata + '/' + r.quantita_totale + ' articoli)' : '') + '</div>';
  }).join('');
  const moreMsg = (resi.dettaglio || []).length > 8 ? '<div style="margin-top:6px; font-style:italic; font-size:0.78rem; color:#8B4F14;">... e altri ' + ((resi.dettaglio || []).length - 8) + ' resi</div>' : '';
  panel.innerHTML = '<div style="background:#FFE4D6; border-left:4px solid #E89A5A; border-radius:8px; padding:14px 18px; margin-bottom:16px;">' +
    '<div style="font-weight:700; color:#8B4F14; margin-bottom:10px; font-size:0.95rem;">↩️ ' + resi.totale_count + ' resi nel periodo · €' + resi.importo_totale_eur.toFixed(2) + ' rimborsati (' + resi.percentuale_su_lordo.toFixed(1) + '% del fatturato lordo)</div>' +
    '<div style="font-size:0.78rem; color:#6B3D14; margin-bottom:8px;">📊 ' + resi.totali_count + ' totali · ' + resi.parziali_count + ' parziali · ' + resi.articoli_resi_qty + ' articoli rimborsati</div>' +
    '<div style="font-size:0.82rem; color:#6B3D14; line-height:1.6; margin-top:10px;"><strong style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em;">Resi recenti:</strong><br>' + dettagliRecenti + moreMsg + '</div>' +
  '</div>';
}

function renderBreakdown(breakdown) {
  const body = document.getElementById('breakdown-body'); const foot = document.getElementById('breakdown-foot');
  if (!breakdown || Object.keys(breakdown).length === 0) { body.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;">Nessun ordine.</td></tr>'; foot.innerHTML = ''; return; }
  const arr = Object.entries(breakdown).map(([key, v]) => ({ key, ...v })); arr.sort((a, b) => b.fatturato - a.fatturato);
  let totOrdini = 0, totFatt = 0, totIva = 0, totCosti = 0, totMargine = 0;
  body.innerHTML = arr.map(r => {
    totOrdini += r.ordini; totFatt += r.fatturato; totIva += (r.iva || 0); totCosti += (r.costo_merce || 0); totMargine += r.margine;
    const marginePerc = r.fatturato > 0 ? (r.margine / r.fatturato * 100) : 0;
    const marginCls = r.margine >= 0 ? 'margin-pos' : 'margin-neg';
    const color = MP_COLORS[r.key] || '#8E8E8E';
    // Riga principale cliccabile + riga dettagli nascosta
    const mainRow = '<tr class="mp-row" data-mp-key="' + r.key + '" style="cursor:pointer"><td><span class="toggle-arrow" id="arrow-' + r.key + '">▶</span>&nbsp;<span class="mp-badge" style="background:' + color + '">' + r.nome + '</span></td><td class="num">' + r.ordini + '</td><td class="num">€' + Math.round(r.fatturato).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.iva || 0).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.costo_merce || 0).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">€' + Math.round(r.margine).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">' + marginePerc.toFixed(1) + '%</td></tr>';
    // Dettaglio ordini (nascosto default)
    const detailRow = '<tr class="mp-detail" id="detail-' + r.key + '" style="display:none;"><td colspan="7" style="padding:0; background:var(--cream);"><div style="padding:16px;"><table class="detail-table"><thead><tr><th>Ordine</th><th>Data</th><th>Paese</th><th>Articoli</th><th class="num">Fatturato</th><th class="num">IVA</th><th class="num">Costo</th><th class="num">Fees MP</th><th class="num">Margine €</th><th class="num">%</th></tr></thead><tbody>' + 
      (r.dettaglio_ordini || []).map(o => {
        const dataFmt = o.created_at ? new Date(o.created_at).toLocaleDateString('it-IT', {day:'2-digit', month:'2-digit', year:'2-digit'}) : '—';
        const orderNumFmt = o.name || ('#' + o.order_number);
        const articoli = (o.articoli || []).map(a => {
          // Margine netto unitario = allocato proporzionalmente sul fatturato del singolo articolo
          const totFatturatoOrdine = (o.articoli || []).reduce((s, x) => s + (x.prezzo_unit * x.quantity), 0);
          const fattArticolo = a.prezzo_unit * a.quantity;
          const quotaFatt = totFatturatoOrdine > 0 ? fattArticolo / totFatturatoOrdine : 0;
          const margineNettoArticolo = o.margine_netto * quotaFatt;
          const margineNettoUnit = a.quantity > 0 ? margineNettoArticolo / a.quantity : 0;
          const badgeStyle = margineNettoUnit >= 0
            ? 'display:inline-block; background:var(--green-light); color:var(--green-dark); border:1px solid rgba(0,128,96,0.3); padding:2px 9px; border-radius:6px; font-weight:700; font-size:0.78rem;'
            : 'display:inline-block; background:var(--red-light); color:var(--red); border:1px solid rgba(191,71,71,0.3); padding:2px 9px; border-radius:6px; font-weight:700; font-size:0.78rem;';
          const segno = margineNettoUnit >= 0 ? '+' : '';
          return '<div style="padding:4px 0; border-bottom:1px dotted var(--gray-200);"><strong style="font-size:0.82rem;">' + a.title + '</strong><br><span style="font-size:0.72rem; color:var(--gray-500);">SKU: ' + a.sku + ' · qty ' + a.quantity + '</span><br><span style="font-size:0.75rem;">Prezzo: <strong>€' + a.prezzo_unit.toFixed(2) + '</strong> · Costo: <strong>€' + a.cost_unit.toFixed(2) + '</strong> · <span style="' + badgeStyle + '" title="Margine netto per unità (dopo IVA, fees, spedizione)">Netto ' + segno + '€' + margineNettoUnit.toFixed(2) + '</span></span></div>';
        }).join('');
        const marginCls2 = o.margine_netto >= 0 ? 'margin-pos' : 'margin-neg';
        const currencyBadge = o.is_foreign_currency ? '<span style="display:inline-block; background:#FFF4D6; color:#8B6914; padding:2px 7px; border-radius:10px; font-size:0.68rem; font-weight:700; margin-left:6px; border:1px solid #E8C77A;" title="Ordine in ' + o.currency + ' convertito in EUR al cambio del giorno (' + o.exchange_rate.toFixed(4) + ')">💱 ' + o.currency + ' ' + (o.total_original || 0).toFixed(0) + '</span>' : '';
        const refundBadge = o.refund_status === 'partial' ? '<span style="display:inline-block; background:#FFE4D6; color:#8B4F14; padding:2px 7px; border-radius:10px; font-size:0.68rem; font-weight:700; margin-left:6px; border:1px solid #E89A5A;" title="Reso parziale: ' + (o.refund_quantity || 0) + '/' + (o.refund_total_quantity || 0) + ' articoli, €' + (o.refund_amount_eur || 0).toFixed(2) + ' rimborsati">↩️ RESO PARZIALE €' + (o.refund_amount_eur || 0).toFixed(0) + '</span>' : '';
        return '<tr><td><strong>' + orderNumFmt + '</strong>' + currencyBadge + refundBadge + '</td><td>' + dataFmt + '</td><td>' + (o.country || '—') + '</td><td style="max-width:340px;">' + articoli + '</td><td class="num">€' + o.fatturato.toFixed(2) + '</td><td class="num">€' + o.iva.toFixed(2) + '</td><td class="num">€' + o.costo_merce.toFixed(2) + '</td><td class="num">€' + o.fees_marketplace.toFixed(2) + '</td><td class="num ' + marginCls2 + '">€' + o.margine_netto.toFixed(2) + '</td><td class="num ' + marginCls2 + '">' + o.margine_percentuale.toFixed(1) + '%</td></tr>';
      }).join('') +
      '</tbody></table></div></td></tr>';
    return mainRow + detailRow;
  }).join('');
  // Toggle handler via event delegation
  document.querySelectorAll('.mp-row').forEach(row => {
    row.addEventListener('click', () => {
      const key = row.dataset.mpKey;
      const detail = document.getElementById('detail-' + key);
      const arrow = document.getElementById('arrow-' + key);
      if (detail && arrow) {
        const isOpen = detail.style.display !== 'none';
        detail.style.display = isOpen ? 'none' : 'table-row';
        arrow.textContent = isOpen ? '▶' : '▼';
      }
    });
  });
  const totMargPerc = totFatt > 0 ? (totMargine / totFatt * 100) : 0;
  foot.innerHTML = '<tr><td>TOTALE</td><td class="num">' + totOrdini + '</td><td class="num">€' + Math.round(totFatt).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totIva).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totCosti).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totMargine).toLocaleString('it-IT') + '</td><td class="num">' + totMargPerc.toFixed(1) + '%</td></tr>';
}

async function fetchAnalytics(url) {
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '...'; });
  document.getElementById('ordini-count').textContent = 'Caricamento (leggo costi reali)...';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;">Caricamento...</td></tr>';
  document.getElementById('breakdown-foot').innerHTML = ''; document.getElementById('errors-panel').innerHTML = '';
  try {
    const data = await fetchNoCache(url);
    if (data.success) {
      document.getElementById('lordo').textContent = '€' + Math.round(data.lordo_iva_inclusa).toLocaleString('it-IT');
      document.getElementById('iva').textContent = '€' + Math.round(data.iva_totale).toLocaleString('it-IT');
      document.getElementById('costi').textContent = '€' + Math.round(data.costi_totali).toLocaleString('it-IT');
      // Split Merce / Fees+sped.
      const merce = data.costi_merce_totali || 0;
      const fees = data.costi_fees_totali || 0;
      document.getElementById('costi-merce').textContent = '€' + Math.round(merce).toLocaleString('it-IT');
      document.getElementById('costi-fees').textContent = '€' + Math.round(fees).toLocaleString('it-IT');
      document.getElementById('netto').textContent = '€' + Math.round(data.margine_netto).toLocaleString('it-IT');
      document.getElementById('margine').textContent = data.margine_percentuale.toFixed(1) + '%';
      var kmv = document.getElementById('kpi-more-val'); if (kmv) kmv.textContent = '€' + Math.round(data.margine_netto).toLocaleString('it-IT') + ' · ' + data.margine_percentuale.toFixed(1) + '%';
      const countLabel = data.ordini_con_errori_count > 0 ? data.ordini_totali + ' validi (' + data.ordini_con_errori_count + ' esclusi)' : data.ordini_totali + ' ordini';
      document.getElementById('ordini-count').textContent = countLabel;
      renderBreakdown(data.breakdown_marketplace);
      renderErrors(data.ordini_con_errori || []);
      renderForeignCurrency(data.ordini_valuta_estera || []);
      renderRefunds(data.resi || null);
      return true;
    }
  } catch(e) { console.error(e); }
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '—'; });
  document.getElementById('ordini-count').textContent = 'Errore caricamento';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--red);">Errore.</td></tr>';
  return false;
}

async function setPeriod(p, btn) { setActiveButton('[data-analytics-periods] .period-btn', btn); await fetchAnalytics('/api/analytics?periodo=' + p); }
async function applyCustomRange() {
  const from = document.getElementById('date-from').value; const to = document.getElementById('date-to').value;
  if (!from || !to) { alert('Seleziona date'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-analytics-periods] .period-btn', null); await fetchAnalytics('/api/analytics?from=' + from + '&to=' + to);
}
async function loadBestSellers(p, btn) {
  setActiveButton('[data-bs-periods] .period-btn', btn);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty">Caricamento prodotti...</div>';
  try { const data = await fetchNoCache('/api/bestsellers?periodo=' + p); if (data.success && data.modelli && data.modelli.length > 0) { renderBestSellers2(data); return; } cont.innerHTML = '<div class="bs-empty">' + (data.success ? 'Nessun prodotto venduto nel periodo.' : 'Errore: ' + (data.error || '')) + '</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
async function applyBsCustomRange() {
  const from = document.getElementById('bs-date-from').value; const to = document.getElementById('bs-date-to').value;
  if (!from || !to) { alert('Seleziona date'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-bs-periods] .period-btn', null);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty">Caricamento...</div>';
  try { const data = await fetchNoCache('/api/bestsellers?from=' + from + '&to=' + to); if (data.success && data.modelli && data.modelli.length > 0) { renderBestSellers2(data); return; } cont.innerHTML = '<div class="bs-empty">' + (data.success ? 'Nessun prodotto venduto nel periodo.' : 'Errore: ' + (data.error || '')) + '</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
var BS_DATA = null, BS_FILTRO = 'tutti';
function bsEsc(t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function bsEur(n) { return '€' + Math.round(n || 0).toLocaleString('it-IT'); }
function bsMargCls(m) { return m >= 30 ? 'ok' : (m >= 15 ? 'mid' : 'low'); }
function bsFiltro(f) { BS_FILTRO = f; renderBestSellers2(BS_DATA); }
function renderBestSellers2(d) {
  BS_DATA = d;
  var cont = document.getElementById('bs-content');
  cont.className = 'bs2';
  var t = d.totali;
  var modelli = d.modelli.map(function (m) {
    if (BS_FILTRO === 'tutti') return m;
    var sel = m.canali.filter(function (c) { return BS_FILTRO === 'sito' ? c.key === 'TLUXY_SITE' : c.key !== 'TLUXY_SITE'; });
    if (!sel.length) return null;
    var f = sel.reduce(function (s, c) { return s + c.fatturato; }, 0), q = sel.reduce(function (s, c) { return s + c.pezzi; }, 0);
    return Object.assign({}, m, { fatturato: f, pezzi: q, ricavo: m.fatturato ? Math.round(m.ricavo * f / m.fatturato) : 0 });
  }).filter(Boolean).sort(function (a, b) { return b.fatturato - a.fatturato; });
  var maxB = d.brand.length ? d.brand[0].fatturato : 1;
  var sitoTot = (d.canali.filter(function (c) { return c.key === 'TLUXY_SITE'; })[0] || { fatturato: 0 }).fatturato;
  var html = '<div class="bs2-kpi"><div><span>Fatturato</span><b>' + bsEur(t.fatturato) + '</b></div><div><span>Pezzi</span><b>' + t.pezzi + '</b></div><div><span>Margine merce</span><b>' + bsEur(t.ricavo) + ' <small>' + t.margine_pct + '%</small></b></div><div><span>Di cui sito</span><b>' + bsEur(sitoTot) + ' <small>' + (t.fatturato ? Math.round(sitoTot / t.fatturato * 100) : 0) + '%</small></b></div></div>';
  html += '<div class="bs2-sec">Brand</div><div class="bs2-brands"><div class="bs2-brand bs2-bhead"><span>Brand</span><span>Fatturato</span><span>Margine</span><span>Sul sito</span></div>' + d.brand.slice(0, 10).map(function (b) {
    var sitoPct = b.fatturato ? Math.round(b.sito / b.fatturato * 100) : 0;
    return '<div class="bs2-brand"><span class="bs2-bn"><b>' + bsEsc(b.brand) + '</b><small>' + b.pezzi + ' pz · media ' + bsEur(b.pezzi ? b.fatturato / b.pezzi : 0) + '</small></span><span class="bs2-bv">' + bsEur(b.fatturato) + '<small>' + b.quota_pct + '% del totale</small></span><span class="bs2-bm"><span class="bs2-m ' + bsMargCls(b.margine_pct) + '">' + b.margine_pct + '%</span><small>' + bsEur(b.ricavo) + '</small></span><span class="bs2-bs">' + sitoPct + '%<small>' + bsEur(b.sito) + '</small></span></div>';
  }).join('') + '</div>';
  html += '<div class="bs2-head"><div class="bs2-sec" style="margin:0">Modelli più venduti</div><div class="bs2-chips">' + [['tutti', 'Tutti'], ['sito', 'Sito'], ['mp', 'Marketplace']].map(function (c) { return '<button class="bs2-chip' + (BS_FILTRO === c[0] ? ' on' : '') + '" data-f="' + c[0] + '" onclick="bsFiltro(this.dataset.f)">' + c[1] + '</button>'; }).join('') + '</div></div>';
  html += '<div class="bs2-list">' + (modelli.length ? modelli.slice(0, 30).map(function (m, i) {
    var img = m.immagine ? '<img src="' + bsEsc(m.immagine) + '&width=160" loading="lazy" alt="">' : '<span>◇</span>';
    var colori = m.varianti.slice(0, 4).map(function (v) { return bsEsc(v.nome.split(' / ')[0]) + (v.pezzi > 1 ? ' ×' + v.pezzi : ''); }).join(', ') + (m.varianti.length > 4 ? '…' : '');
    var canali = m.canali.map(function (c) { return '<span class="bs2-ch">' + bsEsc(c.nome) + ' ' + c.pezzi + ' · ' + bsEur(c.fatturato) + '</span>'; }).join('');
    return '<details class="bs2-row"><summary><span class="bs2-rank' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span><span class="bs2-img">' + img + '</span><span class="bs2-info"><span class="bs2-t">' + bsEsc(m.titolo) + '</span><span class="bs2-s">' + bsEsc(m.brand) + ' · ' + m.pezzi + ' pz · media ' + bsEur(m.prezzo_medio) + '</span></span><span class="bs2-num"><b>' + bsEur(m.fatturato) + '</b><span class="bs2-m ' + bsMargCls(m.margine_pct) + '">' + (m.senza_costo === m.pezzi ? 'costo ?' : m.margine_pct + '%') + '</span></span></summary>'
      + '<div class="bs2-det"><div><span class="bs2-l">Colori</span> ' + colori + '</div><div><span class="bs2-l">Canali</span> ' + canali + '</div><div><span class="bs2-l">Margine merce</span> ' + bsEur(m.ricavo) + (m.senza_costo ? ' <small>(' + m.senza_costo + ' pz senza costo in Shopify)</small>' : '') + '</div></div></details>';
  }).join('') : '<div class="bs-empty">Nessun modello per questo filtro.</div>') + '</div>';
  html += '<div class="alerts-meta" style="margin-top:10px">Margine merce = prezzo senza IVA − costo merce, solo sui pezzi con costo in Shopify (fees marketplace e spedizione escluse). ' + (t.pezzi_senza_costo ? t.pezzi_senza_costo + ' pezzi senza costo. ' : '') + t.ordini + ' ordini, ' + t.modelli + ' modelli venduti.</div>';
  cont.innerHTML = html;
}
function renderBestSellers(prodotti) {
  const cont = document.getElementById('bs-content');
  if (!prodotti || prodotti.length === 0) { cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; return; }
  cont.innerHTML = prodotti.map((p, i) => {
    const rank = p.rank || (i + 1); const rankClass = rank <= 3 ? 'top3' : '';
    const img = p.immagine ? '<img src="' + p.immagine + '" alt="' + p.titolo + '" loading="lazy">' : '<div class="bs-image-placeholder">◇</div>';
    return '<div class="bs-card"><div class="bs-rank ' + rankClass + '">' + rank + '</div><div class="bs-image">' + img + '</div><div class="bs-body"><div class="bs-title">' + p.titolo + '</div><div class="bs-variant">' + (p.variante || '') + (p.sku ? ' · ' + p.sku : '') + '</div><div class="bs-stats"><div class="bs-stat"><div class="bs-stat-label">Prezzo</div><div class="bs-stat-value">€' + p.prezzo_unit_lordo.toFixed(2) + '</div></div><div class="bs-stat"><div class="bs-stat-label">Pezzi</div><div class="bs-stat-value">' + p.quantita_venduta + '</div></div><div class="bs-stat fatturato"><div class="bs-stat-label">Fatturato</div><div class="bs-stat-value">€' + Math.round(p.fatturato_lordo).toLocaleString('it-IT') + '</div></div><div class="bs-stat ricavo"><div class="bs-stat-label">Ricavo</div><div class="bs-stat-value">€' + Math.round(p.ricavo_stimato).toLocaleString('it-IT') + '</div></div></div></div></div>';
  }).join('');
}
function confronta() {
  const prezzoLordo = parseFloat(document.getElementById('c-prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('c-iva').value) || 0;
  const costo = parseFloat(document.getElementById('c-costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('c-spedizione').value) || 0;
  const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100);
  const risultati = Object.entries(MARKETPLACES).map(([key, mp]) => {
    const prezzoNetto = prezzoNettoIva * (1 - mp.sconto_percentuale / 100);
    const feesShop = key === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
    const feeP = prezzoNetto * (mp.fee_principale / 100); const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100); const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
    const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
    const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
    const margineP = prezzoLordo > 0 ? (margine / prezzoLordo * 100) : 0;
    return { key, nome: mp.nome, sconto: mp.sconto_percentuale, prezzoNetto, feesShop, feesMp, margine, margineP };
  });
  risultati.sort((a, b) => b.margine - a.margine);
  const best = risultati[0]; const worst = risultati[risultati.length - 1];
  document.getElementById('compare-body').innerHTML = risultati.map((r, i) => {
    let cls = '', pill = '';
    if (i === 0) { cls = 'best'; pill = '<span class="mp-pill win">Top</span>'; }
    if (i === risultati.length - 1) { cls = 'worst'; pill = '<span class="mp-pill lose">Last</span>'; }
    const numCls = r.margine >= 0 ? 'num-pos' : 'num-neg';
    const esito = r.margine >= 0 ? '✓' : '✕';
    return '<tr class="' + cls + '"><td><strong>' + r.nome + '</strong>' + pill + '</td><td>' + r.sconto + '%</td><td>€' + r.prezzoNetto.toFixed(2) + '</td><td>€' + r.feesShop.toFixed(2) + '</td><td>€' + r.feesMp.toFixed(2) + '</td><td class="' + numCls + '">€' + r.margine.toFixed(2) + '</td><td class="' + numCls + '">' + r.margineP.toFixed(1) + '%</td><td style="font-size:1.1rem; font-weight:700; color:' + (r.margine >= 0 ? 'var(--green-primary)' : 'var(--red)') + '">' + esito + '</td></tr>';
  }).join('');
  const redditizi = risultati.filter(r => r.margine > 0).length; const inPerdita = risultati.filter(r => r.margine <= 0).length;
  document.getElementById('compare-summary').innerHTML = '<div class="summary-card best-mp"><div class="summary-label">Migliore</div><div class="summary-value">' + best.nome + '</div><div class="summary-detail">€' + best.margine.toFixed(2) + ' (' + best.margineP.toFixed(1) + '%)</div></div><div class="summary-card worst-mp"><div class="summary-label">Peggiore</div><div class="summary-value">' + worst.nome + '</div><div class="summary-detail">€' + worst.margine.toFixed(2) + ' (' + worst.margineP.toFixed(1) + '%)</div></div><div class="summary-card info"><div class="summary-label">Redditizi</div><div class="summary-value">' + redditizi + ' su ' + risultati.length + '</div><div class="summary-detail">' + inPerdita + ' in perdita</div></div>';
}
function calcola() {
  const prezzoLordo = parseFloat(document.getElementById('prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('iva-select').value) || 0;
  const costo = parseFloat(document.getElementById('costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('spedizione').value) || 0;
  const mpKey = document.getElementById('mp-select').value;
  const mp = MARKETPLACES[mpKey];
  const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100); const ivaScorporata = prezzoLordo - prezzoNettoIva;
  const prezzoNetto = prezzoNettoIva * (1 - mp.sconto_percentuale / 100);
  const feesShop = mpKey === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
  const feeP = prezzoNetto * (mp.fee_principale / 100); const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100); const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
  const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
  const margineP = prezzoLordo > 0 ? (margine / prezzoLordo * 100) : 0;
  document.getElementById('results').style.display = 'grid';
  document.getElementById('r-lordo').textContent = '€' + prezzoLordo.toFixed(2);
  document.getElementById('r-iva').textContent = '€' + ivaScorporata.toFixed(2);
  document.getElementById('r-netto-iva').textContent = '€' + prezzoNettoIva.toFixed(2);
  document.getElementById('r-netto').textContent = '€' + prezzoNetto.toFixed(2);
  document.getElementById('r-shopify').textContent = '€' + feesShop.toFixed(2);
  document.getElementById('r-mp').textContent = '€' + feesMp.toFixed(2);
  document.getElementById('r-margine').textContent = '€' + margine.toFixed(2);
  document.getElementById('r-perc').textContent = margineP.toFixed(1) + '%';
  const mc = document.getElementById('r-margine-card'); const rc = document.getElementById('r-redd-card'); const re = document.getElementById('r-redd');
  if (margine > 0) { mc.className = 'result-card positive'; rc.className = 'result-card positive'; re.textContent = '✓ Redditizio'; }
  else { mc.className = 'result-card negative'; rc.className = 'result-card negative'; re.textContent = '✕ In Perdita'; }
}
function loadMarketplaces() {
  const select = document.getElementById('mp-select'); const grid = document.getElementById('mp-grid');
  Object.entries(MARKETPLACES).forEach(([key, mp]) => {
    const opt = document.createElement('option'); opt.value = key; opt.textContent = mp.nome; select.appendChild(opt);
    const card = document.createElement('div'); card.className = 'mp-card';
    card.addEventListener('click', () => { select.value = key; showTab('calculator'); calcola(); });
    card.innerHTML = '<div class="mp-name">' + mp.nome + '</div><div class="mp-pay">Pagamento: ' + (mp.pagamento || 'N/D') + '</div>' + (mp.nota_regole ? '<div class="mp-pay" style="color:#8B6914;">' + mp.nota_regole + '</div>' : '') + '<div class="mp-fees"><div><strong>Sconto</strong>' + mp.sconto_percentuale + '%</div><div><strong>Fee Princ.</strong>' + mp.fee_principale + '%</div><div><strong>Fee Sec.</strong>' + (mp.fee_secondaria || 0) + '%</div><div><strong>Trasporto</strong>€' + (mp.fee_fissa_trasporto || 0) + '</div><div><strong>Packaging</strong>€' + (mp.fee_fissa_packaging || 0) + '</div>' + (mp.fee_accessoria ? '<div><strong>Fee Acc.</strong>' + mp.fee_accessoria + '%</div>' : '') + '</div>';
    grid.appendChild(card);
  });
}

// ============ SIMULATORE DUO ============
let duoProducts = [];
function calcolaMargineDUO(prezzoLordo, costo, mpKey, ivaPerc) {
  if (!prezzoLordo || !mpKey) return null;
  const mp = MARKETPLACES[mpKey]; if (!mp) return null;
  const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100);
  const ivaScorp = prezzoLordo - prezzoNettoIva;
  const prezzoNetto = prezzoNettoIva * (1 - mp.sconto_percentuale / 100);
  const feesShop = mpKey === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
  const feeP = prezzoNetto * (mp.fee_principale / 100);
  const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100);
  const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
  const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine = prezzoNetto - feesShop - feesMp - costo;
  const marginePerc = prezzoLordo > 0 ? (margine / prezzoLordo * 100) : 0;
  return { margine, marginePerc, prezzoNetto, ivaScorp, feesShop, feesMp };
}

// Calcola il prezzo minimo (IVA inclusa) per raggiungere un margine target
function prezzoMinimoPerMargine(costo, mpKey, ivaPerc, margineTargetPerc) {
  const mp = MARKETPLACES[mpKey]; if (!mp) return null;
  const totalPercFee = (mp.fee_principale + (mp.fee_secondaria || 0) + (mp.fee_accessoria || 0) + (mpKey === 'TLUXY_SITE' ? 0.15 : 0)) / 100;
  const scontoPerc = mp.sconto_percentuale / 100;
  const feeFissa = (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  // Formula: prezzoNetto(1-totalPercFee) - costo - feeFissa = margineTarget
  // prezzoNetto = prezzoLordo/(1+iva) * (1-scontoPerc)
  // prezzoLordo = X. Risolvo per X.
  // margine = X/(1+iva)*(1-sconto)*(1-totalFee) - costo - feeFissa
  // margineTarget = margineTargetPerc/100 * X
  // X/(1+iva)*(1-sconto)*(1-totalFee) - costo - feeFissa = margineTargetPerc/100 * X
  // X * [(1-sconto)*(1-totalFee)/(1+iva) - margineTargetPerc/100] = costo + feeFissa
  const coef = (1 - scontoPerc) * (1 - totalPercFee) / (1 + ivaPerc / 100) - margineTargetPerc / 100;
  if (coef <= 0) return Infinity; // impossibile raggiungere quel margine
  return (costo + feeFissa) / coef;
}

async function loadDuoProducts() {
  const cont = document.getElementById('duo-content');
  cont.innerHTML = '<div class="bs-empty">Caricamento prodotti DUO da Shopify...</div>';
  try {
    const data = await fetchNoCache('/api/duo-products');
    if (!data.success) { cont.innerHTML = '<div class="bs-empty">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    duoProducts = data.prodotti || [];
    renderDuoProducts(duoProducts);
  } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}

function renderDuoProducts(products) {
  const cont = document.getElementById('duo-content');
  if (!products || products.length === 0) { cont.innerHTML = '<div class="bs-empty">Nessun prodotto DUO trovato (SKU che inizia con "DUO-").</div>'; return; }
  const mpOptions = Object.entries(MARKETPLACES).map(([k, v]) => '<option value="' + k + '">' + v.nome + '</option>').join('');
  cont.innerHTML = '<div class="duo-grid">' + products.map(p => {
    // Placeholder compatto con iniziale + sfondo colorato (no immagini)
    const initial = (p.title || 'D').charAt(0).toUpperCase();
    const hue = ((p.variant_id || 0) % 360);
    const costoSaved = p.costo_fornitore !== null && p.costo_fornitore !== undefined ? p.costo_fornitore : '';
    const costBadge = p.costo_fornitore !== null 
      ? '<span style="display:inline-block; background:#E6F4EE; color:var(--green-dark); padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">Cost Shopify</span>'
      : '<span style="display:inline-block; background:#FCEEEE; color:var(--red); padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">Cost mancante</span>';
    return '<div class="duo-card" data-vid="' + p.variant_id + '">' +
      '<div class="duo-body" style="padding:14px;">' +
        '<div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">' +
          '<div style="width:36px; height:36px; border-radius:8px; background:hsl(' + hue + ', 35%, 88%); color:hsl(' + hue + ', 45%, 30%); display:flex; align-items:center; justify-content:center; font-weight:700; font-size:0.95rem; flex-shrink:0;">' + initial + '</div>' +
          '<div style="flex:1; min-width:0;">' +
            '<div class="duo-title" style="font-size:0.88rem; font-weight:600; line-height:1.3;">' + p.title + '</div>' +
            '<div class="duo-meta" style="font-size:0.72rem; color:var(--gray-500);">SKU: ' + p.sku + ' · Stock: ' + p.inventory_quantity + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="duo-listino" style="font-size:0.82rem; margin-bottom:8px;">Listino: <strong>€' + p.prezzo_listino.toFixed(2) + '</strong>' + (p.compare_at_price > 0 ? ' <span style="text-decoration:line-through; color:var(--gray-500); margin-left:4px;">€' + p.compare_at_price.toFixed(2) + '</span>' : '') + costBadge + '</div>' +
        '<div class="duo-input-row"><label>Costo €</label><input type="number" class="duo-cost" value="' + costoSaved + '" step="0.01" min="0" data-vid="' + p.variant_id + '"></div>' +
        '<div class="duo-input-row"><label>Marketplace</label><select class="duo-mp" data-vid="' + p.variant_id + '"><option value="">— scegli —</option>' + mpOptions + '</select></div>' +
        '<div class="duo-input-row"><label>IVA %</label><select class="duo-iva" data-vid="' + p.variant_id + '"><option value="22">IT (22%)</option><option value="20">FR/UK/AT (20%)</option><option value="19">DE (19%)</option><option value="21">ES/NL/BE (21%)</option><option value="23">PL/IE/PT (23%)</option><option value="25">SE/DK (25%)</option><option value="0">Extra-UE (0%)</option></select></div>' +
        '<div class="duo-input-row"><label>Prezzo test €</label><input type="number" class="duo-prezzo-test" value="' + p.prezzo_listino.toFixed(2) + '" step="0.01" data-vid="' + p.variant_id + '"></div>' +
        '<div class="duo-result" id="duo-res-' + p.variant_id + '">—</div>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
  
  // Listeners: solo calcolo locale, NO salvataggio KV (semplice)
  cont.querySelectorAll('.duo-cost, .duo-mp, .duo-iva, .duo-prezzo-test').forEach(el => {
    el.addEventListener('input', e => updateDuoCard(e.target.dataset.vid));
    el.addEventListener('change', e => updateDuoCard(e.target.dataset.vid));
  });
  
  // Auto-update tutti i prodotti con costo noto (triggera calcolo margine immediato)
  setTimeout(() => {
    cont.querySelectorAll('.duo-card').forEach(card => {
      const vid = card.dataset.vid;
      if (vid) updateDuoCard(vid);
    });
  }, 50);
}

function updateDuoCard(vid) {
  const card = document.querySelector('.duo-card[data-vid="' + vid + '"]'); if (!card) return;
  const costo = parseFloat(card.querySelector('.duo-cost').value) || 0;
  const mpKey = card.querySelector('.duo-mp').value;
  const iva = parseFloat(card.querySelector('.duo-iva').value);
  const prezzo = parseFloat(card.querySelector('.duo-prezzo-test').value) || 0;
  const resDiv = card.querySelector('.duo-result');
  if (!costo || !mpKey || !prezzo) { resDiv.innerHTML = '<span style="color:var(--gray-500); font-style:italic;">Compila costo, marketplace e prezzo per vedere il margine</span>'; resDiv.className = 'duo-result'; return; }
  const r = calcolaMargineDUO(prezzo, costo, mpKey, iva);
  if (!r) { resDiv.innerHTML = 'Errore calcolo'; return; }
  const prezzoBE = prezzoMinimoPerMargine(costo, mpKey, iva, 0);
  const prezzo20 = prezzoMinimoPerMargine(costo, mpKey, iva, 20);
  const prezzo30 = prezzoMinimoPerMargine(costo, mpKey, iva, 30);
  const marginCls = r.margine >= 0 ? 'margin-pos' : 'margin-neg';
  resDiv.className = 'duo-result ' + (r.margine >= 0 ? 'duo-pos' : 'duo-neg');
  resDiv.innerHTML = '<div class="duo-main-result"><span class="duo-result-label">MARGINE</span><span class="' + marginCls + '" style="font-size:1.3rem; font-weight:700;">€' + r.margine.toFixed(2) + '</span><span class="' + marginCls + '">' + r.marginePerc.toFixed(1) + '%</span></div>' +
    '<div class="duo-breakeven"><strong>Break-even</strong>: €' + (isFinite(prezzoBE) ? prezzoBE.toFixed(2) : '—') + '<br><strong>Per 20% margine</strong>: €' + (isFinite(prezzo20) ? prezzo20.toFixed(2) : '—') + '<br><strong>Per 30% margine</strong>: €' + (isFinite(prezzo30) ? prezzo30.toFixed(2) : '—') + '</div>';
}

function filterDuoProducts() {
  const q = (document.getElementById('duo-search').value || '').toLowerCase().trim();
  if (!q) { renderDuoProducts(duoProducts); return; }
  const filtered = duoProducts.filter(p => p.title.toLowerCase().includes(q) || p.sku.toLowerCase().includes(q));
  renderDuoProducts(filtered);
}

async function checkKvStatus() {
  const el = document.getElementById('duo-kv-status');
  try {
    const data = await fetchNoCache('/api/kv-status');
    if (data.kv_enabled) {
      el.className = 'info-box';
      el.style.cssText = 'background:var(--green-light); border-left-color:var(--green-primary); color:var(--green-dark);';
      el.innerHTML = '✅ <strong>DB persistente attivo</strong>: i costi vengono salvati permanentemente (non si perdono se i prodotti vengono archiviati).';
    } else {
      el.className = 'warn-box';
      el.innerHTML = '⚠️ <strong>DB persistente NON configurato</strong>. Vai su Vercel → Storage → Create KV Database. Senza KV il simulatore non può salvare i costi.';
    }
  } catch(e) { el.innerHTML = '❌ Errore verifica KV: ' + e.message; }
}

function parseCSV(text) {
  const lines = text.split(/\\r?\\n/).filter(l => l.trim());
  if (lines.length === 0) return { costs: {}, err: 'File vuoto' };
  const header = lines[0].split(/[,;]/).map(h => h.trim().toLowerCase().replace(/^"|"$/g, ''));
  const vidIdx = header.findIndex(h => h === 'variant_id' || h === 'variantid');
  const skuIdx = header.findIndex(h => h === 'sku');
  const costIdx = header.findIndex(h => h === 'cost' || h === 'costo' || h === 'costo_fornitore');
  if (costIdx < 0) return { costs: {}, err: 'Colonna "cost" non trovata nel CSV' };
  if (vidIdx < 0 && skuIdx < 0) return { costs: {}, err: 'Devi avere colonna "variant_id" o "sku"' };
  const costs = {}; const skippedSkus = [];
  for (let i = 1; i < lines.length; i++) {
    const parts = lines[i].split(/[,;]/).map(p => p.trim().replace(/^"|"$/g, ''));
    const cost = parseFloat(parts[costIdx]);
    if (isNaN(cost)) continue;
    let vid = null;
    if (vidIdx >= 0 && parts[vidIdx]) vid = parts[vidIdx];
    else if (skuIdx >= 0 && parts[skuIdx]) {
      const sku = parts[skuIdx];
      const match = duoProducts.find(p => p.sku === sku);
      if (match) vid = String(match.variant_id); else { skippedSkus.push(sku); continue; }
    }
    if (vid) costs[vid] = cost;
  }
  return { costs, skippedSkus };
}

async function handleCsvImport(file) {
  const status = document.getElementById('duo-import-status');
  status.textContent = '📄 Lettura CSV...';
  try {
    const text = await file.text();
    const { costs, err, skippedSkus } = parseCSV(text);
    if (err) { status.textContent = '❌ ' + err; status.style.color = 'var(--red)'; return; }
    const n = Object.keys(costs).length;
    if (n === 0) { status.textContent = '❌ Nessun costo valido nel CSV'; status.style.color = 'var(--red)'; return; }
    status.textContent = '💾 Salvataggio ' + n + ' costi...';
    const res = await fetch('/api/duo-costs-import', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({costs}) });
    const data = await res.json();
    if (data.success) {
      let msg = '✅ Salvati ' + data.salvati + ' costi';
      if (skippedSkus && skippedSkus.length) msg += ' (' + skippedSkus.length + ' SKU sconosciuti skippati)';
      status.textContent = msg; status.style.color = 'var(--green-dark)';
      setTimeout(loadDuoProducts, 500);
    } else { status.textContent = '❌ ' + data.error; status.style.color = 'var(--red)'; }
  } catch(e) { status.textContent = '❌ ' + e.message; status.style.color = 'var(--red)'; }
}

// ============ PREVISIONI INCASSI ============
let forecastData = null;

function fmtEur(n) { return '€' + Math.round(n).toLocaleString('it-IT'); }
function fmtEur2(n) { return '€' + (n || 0).toFixed(2); }
function fmtDateIT(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr + 'T00:00:00');
  return d.toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' });
}
function fmtMonthIT(monthKey) {
  if (!monthKey) return '—';
  const [y, m] = monthKey.split('-');
  const d = new Date(parseInt(y), parseInt(m) - 1, 1);
  return d.toLocaleDateString('it-IT', { month: 'long', year: 'numeric' });
}

async function loadForecast(forceRefresh) {
  const cont = document.getElementById('forecast-content');
  cont.innerHTML = '<div class="bs-empty">' + (forceRefresh ? '🔄 Ricalcolo in corso (legge 120gg ordini da Shopify, ~10-30 sec)...' : 'Caricamento previsioni...') + '</div>';
  try {
    const url = forceRefresh ? '/api/forecast?refresh=1' : '/api/forecast';
    const data = await fetchNoCache(url);
    if (!data.success) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    forecastData = data;
    renderForecast(data);
  } catch(e) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + e.message + '</div>'; }
}

function renderForecast(data) {
  const cont = document.getElementById('forecast-content');
  const kpi = data.kpi;
  const bg = data.balardi_wallet;
  const todayStr = new Date().toISOString().split('T')[0];
  
  // Banner cache status
  let cacheInfoHtml = '';
  if (data.from_cache) {
    const age = data.cache_age_hours || 0;
    const ageLabel = age < 1 ? Math.round(age * 60) + ' min fa' : age.toFixed(1) + ' ore fa';
    cacheInfoHtml = '<div style="background:#E8F0F5; border-left:3px solid #4A7FBC; border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:#1A4A78; display:flex; justify-content:space-between; align-items:center;">' +
      '<span>⚡ Dati dalla cache · ultimo aggiornamento ' + ageLabel + ' · scade tra ' + (data.cache_expires_in_hours || 0).toFixed(1) + ' ore</span>' +
    '</div>';
  } else if (data.cached_to_kv) {
    cacheInfoHtml = '<div style="background:#E6F4EE; border-left:3px solid var(--green-primary); border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:var(--green-dark);">' +
      '✅ Dati appena calcolati e salvati in cache (valida 24h)' +
    '</div>';
  }
  
  // KPI cards: solo mese corrente, mese prossimo, totale 2 mesi
  const totale2mesi = (kpi.incasso_mese_corrente.importo || 0) + (kpi.incasso_mese_prossimo.importo || 0);
  const count2mesi = (kpi.incasso_mese_corrente.ordini || 0) + (kpi.incasso_mese_prossimo.ordini || 0);
  const kpiHtml = '<div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; margin-bottom:24px;">' +
    '<div style="background:linear-gradient(135deg, #E6F4EE 0%, #C8E8D6 100%); padding:18px 22px; border-radius:12px; border-left:4px solid var(--green-primary);">' +
      '<div style="font-size:0.7rem; color:var(--green-dark); text-transform:uppercase; letter-spacing:0.08em; font-weight:700; margin-bottom:6px;">' + fmtMonthIT(kpi.incasso_mese_corrente.mese) + ' (corrente)</div>' +
      '<div style="font-size:1.5rem; font-weight:800; color:var(--black);">' + fmtEur(kpi.incasso_mese_corrente.importo) + '</div>' +
      '<div style="font-size:0.75rem; color:var(--gray-700); margin-top:2px;">' + kpi.incasso_mese_corrente.ordini + ' pagamenti</div>' +
    '</div>' +
    '<div style="background:linear-gradient(135deg, #FFF4D6 0%, #FFE8A8 100%); padding:18px 22px; border-radius:12px; border-left:4px solid #C9A961;">' +
      '<div style="font-size:0.7rem; color:#8B6914; text-transform:uppercase; letter-spacing:0.08em; font-weight:700; margin-bottom:6px;">' + fmtMonthIT(kpi.incasso_mese_prossimo.mese) + ' (prossimo)</div>' +
      '<div style="font-size:1.5rem; font-weight:800; color:var(--black);">' + fmtEur(kpi.incasso_mese_prossimo.importo) + '</div>' +
      '<div style="font-size:0.75rem; color:var(--gray-700); margin-top:2px;">' + kpi.incasso_mese_prossimo.ordini + ' pagamenti</div>' +
    '</div>' +
    '<div style="background:linear-gradient(135deg, #F0EBDF 0%, #E5DDC8 100%); padding:18px 22px; border-radius:12px; border-left:4px solid var(--gray-700);">' +
      '<div style="font-size:0.7rem; color:var(--gray-700); text-transform:uppercase; letter-spacing:0.08em; font-weight:700; margin-bottom:6px;">Totale 2 mesi</div>' +
      '<div style="font-size:1.5rem; font-weight:800; color:var(--black);">' + fmtEur(totale2mesi) + '</div>' +
      '<div style="font-size:0.75rem; color:var(--gray-700); margin-top:2px;">' + count2mesi + ' pagamenti</div>' +
    '</div>' +
  '</div>';
  
  // Card per marketplace con scadenziari aggregati
  // Raggruppo i pagamenti per MP per mese
  const breakdownMP = data.breakdown_marketplace || [];
  const meseCorrente = kpi.incasso_mese_corrente.mese;
  const meseProssimo = kpi.incasso_mese_prossimo.mese;
  
  // Raggruppa pagamenti per MP e poi per mese
  const mpAggregato = {};
  breakdownMP.forEach(mp => {
    // Da pagamenti[] ricostruisco raggruppamento per mese
    const perMese = {};
    (mp.pagamenti || []).forEach(p => {
      const monthKey = p.data.substring(0, 7);
      if (!perMese[monthKey]) perMese[monthKey] = { importo: 0, count: 0, note: new Set() };
      perMese[monthKey].importo += p.importo_eur;
      perMese[monthKey].count++;
      if (p.nota) perMese[monthKey].note.add(p.nota);
    });
    mpAggregato[mp.nome] = {
      ...mp,
      scadenze: Object.entries(perMese).map(([mese, info]) => ({
        mese, importo: info.importo, count: info.count, note: [...info.note].join(' · ')
      })).sort((a, b) => a.mese.localeCompare(b.mese))
    };
  });
  
  // Filtra scadenze: solo mese corrente in avanti
  const mpVisibili = Object.values(mpAggregato).filter(mp => {
    const future = mp.scadenze.filter(s => s.mese >= meseCorrente);
    mp.scadenzeFuture = future;
    return future.length > 0;
  });
  
  // Ordina per: prima MP con pagamenti nel mese corrente, poi per totale futuro
  mpVisibili.sort((a, b) => {
    const aNow = a.scadenzeFuture.some(s => s.mese === meseCorrente) ? 1 : 0;
    const bNow = b.scadenzeFuture.some(s => s.mese === meseCorrente) ? 1 : 0;
    if (aNow !== bNow) return bNow - aNow;
    const aTot = a.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
    const bTot = b.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
    return bTot - aTot;
  });
  
  const MP_BADGE_COLORS = { Miinto:'#008060', 'The Bradery':'#C9A961', Brandsgateway:'#4A7FBC', Winkelstraat:'#479CCF', 'Secret Sales':'#6B5320', Italist:'#2D2D2D', Archivist:'#004C3F', 'Intra Mirror':'#B89550', 'Fashion Tamers':'#5C5C5C', 'Boutique Mall':'#E8573A', 'Jammy Dude':'#8E4FBF', 'T. Luxy (proprio)':'#1A1A1A', Poizon:'#D4397A' };
  
  const cardsHtml = '<div style="margin-bottom:12px; font-size:1rem; font-weight:700; color:var(--black);">Scadenziario per marketplace</div>' +
    '<div style="display:flex; flex-direction:column; gap:10px; margin-bottom:24px;">' +
    (mpVisibili.length > 0 ? mpVisibili.map(mp => {
      const color = MP_BADGE_COLORS[mp.nome] || '#8E8E8E';
      const totaleFuturo = mp.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
      const scadenzeHtml = mp.scadenzeFuture.map(sc => {
        const isCorrente = sc.mese === meseCorrente;
        const isProssimo = sc.mese === meseProssimo;
        const mensileLabel = isCorrente ? ' (corrente)' : (isProssimo ? ' (prossimo)' : '');
        const color2 = isCorrente ? 'var(--green-dark)' : (isProssimo ? '#8B6914' : 'var(--gray-700)');
        return '<div style="display:flex; justify-content:space-between; align-items:baseline; padding:5px 0; font-size:0.88rem;">' +
          '<span style="color:' + color2 + ';"><strong style="text-transform:capitalize;">' + fmtMonthIT(sc.mese) + '</strong>' + mensileLabel + ' · ' + sc.count + ' ord.' + (sc.note ? ' <span style="color:var(--gray-500); font-size:0.78rem;">(' + sc.note + ')</span>' : '') + '</span>' +
          '<span style="font-weight:700; font-variant-numeric:tabular-nums;">' + fmtEur(sc.importo) + '</span>' +
        '</div>';
      }).join('');
      return '<div style="background:var(--white); border:1px solid var(--gray-200); border-radius:12px; padding:14px 18px;">' +
        '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; padding-bottom:10px; border-bottom:1px solid var(--gray-100);">' +
          '<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">' +
            '<span class="mp-badge" style="background:' + color + '; font-size:0.8rem;">' + mp.nome + '</span>' +
            '<span style="font-size:0.78rem; color:var(--gray-700); font-style:italic;">' + (mp.pagamento_desc || '') + '</span>' +
          '</div>' +
          '<div style="font-size:1.05rem; font-weight:800;">Totale <span style="color:var(--black);">' + fmtEur(totaleFuturo) + '</span></div>' +
        '</div>' +
        scadenzeHtml +
      '</div>';
    }).join('') : '<div style="text-align:center; padding:24px; color:var(--gray-500); font-style:italic;">Nessun pagamento previsto nei prossimi 2 mesi.</div>') +
    '</div>';
  
  // Balardi — pannello compatto in basso
  const residuo = bg.credito_residuo;
  const percConsumo = bg.credito_ricaricato > 0 ? (bg.credito_consumato / bg.credito_ricaricato * 100) : 0;
  const residuoClass = residuo > 300 ? 'var(--green-primary)' : (residuo > 0 ? '#C9A961' : 'var(--red)');
  const residuoLabel = residuo < 300 && residuo >= 0 ? ' ⚠️ Ricarica presto' : (residuo < 0 ? ' 🔴 Credito esaurito' : '');
  const ricaricheHtml = (bg.ricariche || []).slice().reverse().slice(0, 5).map(r => 
    '<div style="padding:5px 0; border-bottom:1px dotted var(--gray-200); font-size:0.8rem; display:flex; justify-content:space-between;">' +
      '<span>' + fmtDateIT(r.data_ricarica) + (r.nota ? ' · <span style="color:var(--gray-500);">' + r.nota + '</span>' : '') + '</span>' +
      '<span><strong>+' + fmtEur2(r.importo) + '</strong> <button onclick="deleteRicarica(' + r.id + ')" style="background:none; border:none; color:var(--red); cursor:pointer; font-size:0.75rem; margin-left:6px;" title="Elimina">✕</button></span>' +
    '</div>'
  ).join('');
  const balardiHtml = '<div style="background:var(--gray-100); border-radius:12px; padding:14px 18px;">' +
    '<div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">' +
      '<div>' +
        '<div style="font-size:0.7rem; color:var(--gray-700); text-transform:uppercase; letter-spacing:0.08em; font-weight:700; margin-bottom:4px;">💳 Balardi · credito prepagato</div>' +
        '<div style="font-size:0.92rem;">Residuo <strong style="color:' + residuoClass + ';">' + fmtEur2(residuo) + '</strong>' + residuoLabel + ' · ricaricato ' + fmtEur2(bg.credito_ricaricato) + ' · consumato ' + fmtEur2(bg.credito_consumato) + ' (' + percConsumo.toFixed(0) + '%)</div>' +
      '</div>' +
      '<div style="display:flex; gap:6px; align-items:center;">' +
        '<input type="number" id="balardi-new-importo" placeholder="€ importo" step="0.01" style="padding:6px 10px; border:1px solid var(--gray-200); border-radius:6px; width:100px; font-size:0.85rem;">' +
        '<input type="text" id="balardi-new-nota" placeholder="Nota" style="padding:6px 10px; border:1px solid var(--gray-200); border-radius:6px; width:120px; font-size:0.85rem;">' +
        '<button id="balardi-ricarica-btn" class="apply-btn" style="background:var(--green-primary); padding:6px 12px; font-size:0.82rem;">+ Ricarica</button>' +
      '</div>' +
    '</div>' +
    (ricaricheHtml ? '<details style="margin-top:8px;"><summary style="cursor:pointer; font-size:0.78rem; color:var(--gray-700); font-weight:600;">Ultime ricariche (' + (bg.ricariche || []).length + ')</summary><div style="margin-top:6px;">' + ricaricheHtml + '</div></details>' : '') +
  '</div>';
  
  cont.innerHTML = cacheInfoHtml + kpiHtml + cardsHtml + balardiHtml;
  
  // Handler ricarica Balardi
  const ricBtn = document.getElementById('balardi-ricarica-btn');
  if (ricBtn) {
    ricBtn.addEventListener('click', async () => {
      const importo = parseFloat(document.getElementById('balardi-new-importo').value);
      const nota = document.getElementById('balardi-new-nota').value;
      if (isNaN(importo) || importo <= 0) { alert('Inserisci un importo valido'); return; }
      ricBtn.disabled = true; ricBtn.textContent = '...';
      try {
        const res = await fetch('/api/balardi-ricarica', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ importo, nota }) });
        const r = await res.json();
        if (r.success) { loadForecast(); } else { alert('Errore: ' + (r.error || 'sconosciuto')); ricBtn.disabled = false; ricBtn.textContent = '+ Ricarica'; }
      } catch(e) { alert('Errore: ' + e.message); ricBtn.disabled = false; ricBtn.textContent = '+ Ricarica'; }
    });
  }
}

async function deleteRicarica(id) {
  if (!confirm('Eliminare questa ricarica?')) return;
  try {
    const res = await fetch('/api/balardi-ricarica-delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id }) });
    const r = await res.json();
    if (r.success) loadForecast();
    else alert('Errore: ' + (r.error || 'sconosciuto'));
  } catch(e) { alert('Errore: ' + e.message); }
}

// ============ INVENTORY SNAPSHOT ============
let inventoryData = null;
let inventoryFilter = 'tutto';

async function loadInventory(forceRefresh) {
  const cont = document.getElementById('inventory-content');
  cont.innerHTML = '<div class="bs-empty">' + (forceRefresh ? '🔄 Fetch catalogo da Shopify in corso (20-60 secondi)...' : 'Caricamento snapshot...') + '</div>';
  try {
    const url = forceRefresh ? '/api/inventory?refresh=1' : '/api/inventory';
    const data = await fetchNoCache(url);
    if (!data.success) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    inventoryData = data;
    renderInventory();
  } catch(e) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + e.message + '</div>'; }
}

function renderInventory() {
  if (!inventoryData) return;
  const d = inventoryData;
  const cont = document.getElementById('inventory-content');
  const snap = d.snapshot[inventoryFilter];
  
  // Header info
  let subtitle = '';
  if (inventoryFilter === 'tutto') subtitle = d.totale_prodotti_attivi_con_stock + ' prodotti · ' + d.totale_pezzi.toLocaleString('it-IT') + ' pezzi (di cui ' + d.duo_prodotti + ' DUO)';
  else if (inventoryFilter === 'own') subtitle = d.own_prodotti + ' prodotti · ' + d.own_pezzi.toLocaleString('it-IT') + ' pezzi (esclusi ' + d.duo_prodotti + ' DUO)';
  else subtitle = d.duo_prodotti + ' prodotti DUO · ' + d.duo_pezzi.toLocaleString('it-IT') + ' pezzi';
  
  // Banner cache
  let cacheHtml = '';
  if (d.dalla_cache_discovery && d.cached_at) {
    const age = Math.round((Date.now() - new Date(d.cached_at).getTime()) / 3600000 * 10) / 10;
    cacheHtml = '<div style="background:#E8F0F5; border-left:3px solid #4A7FBC; border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:#1A4A78;">⚡ Dati dalla cache · aggiornati ' + age + ' ore fa</div>';
  } else {
    cacheHtml = '<div style="background:#E6F4EE; border-left:3px solid var(--green-primary); border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:var(--green-dark);">✅ Dati appena scaricati da Shopify e salvati in cache (24h)</div>';
  }
  
  // Tabella categoria × gender
  const CATEGORIE = [
    { key: 'bag', nome: 'Bag' },
    { key: 'shoes', nome: 'Shoes' },
    { key: 'accessori', nome: 'Accessori' },
    { key: 'clothing', nome: 'Clothing' }
  ];
  
  function fmtCell(p, pz) {
    return '<td class="num" style="font-variant-numeric:tabular-nums;"><span style="color:var(--gray-500);">' + p.toLocaleString('it-IT') + '</span> · <strong>' + pz.toLocaleString('it-IT') + '</strong></td>';
  }
  
  let rows = '';
  let totDonnaP = 0, totDonnaPz = 0, totUomoP = 0, totUomoPz = 0, totUniP = 0, totUniPz = 0;
  CATEGORIE.forEach(cat => {
    const c = snap[cat.key];
    const rowP = c.donna.prodotti + c.uomo.prodotti + c.unisex.prodotti;
    const rowPz = c.donna.pezzi + c.uomo.pezzi + c.unisex.pezzi;
    totDonnaP += c.donna.prodotti; totDonnaPz += c.donna.pezzi;
    totUomoP += c.uomo.prodotti; totUomoPz += c.uomo.pezzi;
    totUniP += c.unisex.prodotti; totUniPz += c.unisex.pezzi;
    rows += '<tr>' +
      '<td style="font-weight:600;">' + cat.nome + '</td>' +
      fmtCell(c.donna.prodotti, c.donna.pezzi) +
      fmtCell(c.uomo.prodotti, c.uomo.pezzi) +
      fmtCell(c.unisex.prodotti, c.unisex.pezzi) +
      '<td class="num" style="font-variant-numeric:tabular-nums; background:var(--gray-100);"><span style="color:var(--gray-500);">' + rowP.toLocaleString('it-IT') + '</span> · <strong style="font-size:1.05rem;">' + rowPz.toLocaleString('it-IT') + '</strong></td>' +
    '</tr>';
  });
  const totRowP = totDonnaP + totUomoP + totUniP;
  const totRowPz = totDonnaPz + totUomoPz + totUniPz;
  rows += '<tr style="background:var(--gray-100); font-weight:700;">' +
    '<td>Totale</td>' +
    fmtCell(totDonnaP, totDonnaPz) +
    fmtCell(totUomoP, totUomoPz) +
    fmtCell(totUniP, totUniPz) +
    '<td class="num" style="font-variant-numeric:tabular-nums; background:var(--gray-200);"><span style="color:var(--gray-500);">' + totRowP.toLocaleString('it-IT') + '</span> · <strong style="font-size:1.1rem;">' + totRowPz.toLocaleString('it-IT') + '</strong></td>' +
  '</tr>';
  
  const tableHtml = '<div style="background:var(--white); border:1px solid var(--gray-200); border-radius:12px; padding:14px 18px; margin-bottom:16px;">' +
    '<div style="font-size:0.82rem; color:var(--gray-700); margin-bottom:10px;">' + subtitle + '</div>' +
    '<table class="breakdown-table" style="width:100%;">' +
      '<thead><tr>' +
        '<th style="width:120px;">Categoria</th>' +
        '<th class="num">Donna <span style="font-weight:400; font-size:0.72rem; color:var(--gray-500);">prod · pezzi</span></th>' +
        '<th class="num">Uomo <span style="font-weight:400; font-size:0.72rem; color:var(--gray-500);">prod · pezzi</span></th>' +
        '<th class="num">Unisex <span style="font-weight:400; font-size:0.72rem; color:var(--gray-500);">prod · pezzi</span></th>' +
        '<th class="num" style="background:var(--gray-100);">Totale <span style="font-weight:400; font-size:0.72rem; color:var(--gray-500);">prod · pezzi</span></th>' +
      '</tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
    '</table>' +
  '</div>';
  
  // Non classificati
  let orfaniHtml = '';
  const nc = d.non_classificati;
  if (nc && nc.prodotti > 0) {
    const orfaniTop = (nc.product_types_orfani || []).slice(0, 10).map(o => 
      '<div style="padding:4px 0; font-size:0.82rem;"><strong>' + o.product_type + '</strong> · ' + o.count + ' prodotti</div>'
    ).join('');
    const sampleHtml = (nc.sample_orfani || []).slice(0, 5).map(s => 
      '<div style="padding:4px 0; font-size:0.78rem; color:var(--gray-700); border-bottom:1px dotted var(--gray-200);"><strong>' + s.title + '</strong><br><span style="color:var(--gray-500);">product_type: "' + (s.product_type || '(vuoto)') + '" · stock: ' + s.stock + '</span></div>'
    ).join('');
    orfaniHtml = '<div style="background:#FFF4D6; border-left:4px solid #E8C77A; border-radius:8px; padding:14px 18px; margin-bottom:16px;">' +
      '<div style="font-weight:700; color:#8B6914; margin-bottom:8px; font-size:0.92rem;">⚠️ ' + nc.prodotti + ' prodotti non classificati (' + nc.pezzi.toLocaleString('it-IT') + ' pezzi)</div>' +
      '<div style="font-size:0.8rem; color:#6B4E0E; margin-bottom:10px;">Product types orfani più frequenti — dimmeli nella chat per aggiungerli alla classificazione:</div>' +
      '<div style="margin-bottom:10px;">' + orfaniTop + '</div>' +
      '<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:0.78rem; color:#6B4E0E; font-weight:600;">📋 Esempi di prodotti orfani</summary><div style="margin-top:8px;">' + sampleHtml + '</div></details>' +
    '</div>';
  }
  
  cont.innerHTML = cacheHtml + orfaniHtml + tableHtml;
}

// ============ EXCEL BATCH CALCULATOR (v5.10) ============
// Caricamento dinamico SheetJS (CDN) per leggere/scrivere XLSX
let SHEETJS_LOADED = false;
async function loadSheetJS() {
  if (SHEETJS_LOADED || (typeof XLSX !== 'undefined')) { SHEETJS_LOADED = true; return true; }
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
    script.onload = () => { SHEETJS_LOADED = true; resolve(true); };
    script.onerror = () => reject(new Error('Caricamento SheetJS fallito'));
    document.head.appendChild(script);
  });
}

let batchProducts = []; // {sku, titolo, stock, costo, listino, iva, calcoli: [{mp, margine, ...}]}
let batchExpanded = null; // sku attualmente espanso

function batchNormalizeHeader(h) {
  return String(h || '').trim().toLowerCase().replace(/[\s_\-]+/g, '');
}
function batchFindCol(headers, candidates) {
  for (const c of candidates) {
    const idx = headers.findIndex(h => batchNormalizeHeader(h) === batchNormalizeHeader(c));
    if (idx >= 0) return idx;
  }
  return -1;
}

async function handleBatchFile(file) {
  const status = document.getElementById('batch-status');
  status.textContent = '⏳ Caricamento libreria Excel...';
  status.style.color = 'var(--gray-700)';
  try {
    await loadSheetJS();
    status.textContent = '📄 Lettura file...';
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(buf, { type: 'array' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    if (!ws) { status.textContent = '❌ Nessun foglio trovato nel file'; status.style.color = 'var(--red)'; return; }
    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
    if (rows.length < 2) { status.textContent = "❌ Il file ha solo l'intestazione, manca dati"; status.style.color = 'var(--red)'; return; }
    
    const headers = rows[0];
    const skuIdx = batchFindCol(headers, ['sku', 'codice', 'codiceprodotto']);
    // Retail RRP = prezzo di vendita pieno (può essere il listino se non c'è sconto vendita)
    const retailIdx = batchFindCol(headers, ['retail', 'rrp', 'retailprice', 'prezzoretail', 'prezzopieno']);
    // Sconto% fornitore (opzionale)
    const scontoIdx = batchFindCol(headers, ['sconto', 'sconto%', 'scontofornitore', 'discountfornitore', 'discount%', 'scontoacquisto']);
    // Costo (opzionale, calcolato da sconto se manca)
    const costoIdx = batchFindCol(headers, ['costo', 'cost', 'costofornitore', 'costoacquisto', 'costopzunit']);
    // Listino di vendita (opzionale, default = retail)
    const listinoIdx = batchFindCol(headers, ['listino', 'prezzovendita', 'prezzo', 'price', 'prezzolistino', 'sellprice']);
    const titoloIdx = batchFindCol(headers, ['titolo', 'title', 'nome', 'description', 'descrizione', 'product']);
    const stockIdx = batchFindCol(headers, ['stock', 'inventario', 'quantity', 'qty', 'disponibilita', 'pezzi']);
    const ivaIdx = batchFindCol(headers, ['iva', 'vat', 'tax']);
    
    if (skuIdx < 0) { status.textContent = '❌ Colonna SKU non trovata'; status.style.color = 'var(--red)'; return; }
    if (retailIdx < 0 && listinoIdx < 0) { status.textContent = '❌ Manca colonna Retail (o Listino)'; status.style.color = 'var(--red)'; return; }
    if (costoIdx < 0 && scontoIdx < 0) { status.textContent = '❌ Manca colonna Costo (o Sconto% fornitore)'; status.style.color = 'var(--red)'; return; }
    
    const ivaDefault = parseFloat(document.getElementById('batch-iva-default').value) || 22;
    const products = [];
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (!row || row.every(c => c === '' || c === null || c === undefined)) continue;
      const sku = String(row[skuIdx] || '').trim();
      if (!sku) continue;
      // Retail (se manca, usa listino)
      let retail = retailIdx >= 0 ? parseFloat(row[retailIdx]) : NaN;
      let listino = listinoIdx >= 0 ? parseFloat(row[listinoIdx]) : NaN;
      // Fallback: se manca uno, usa l'altro
      if (isNaN(retail) && !isNaN(listino)) retail = listino;
      if (isNaN(listino) && !isNaN(retail)) listino = retail;
      if (isNaN(retail) || retail <= 0) continue;
      // Sconto% e costo
      const scontoForn = scontoIdx >= 0 ? parseFloat(row[scontoIdx]) : NaN;
      let costo = costoIdx >= 0 ? parseFloat(row[costoIdx]) : NaN;
      // Se costo manca ma c'è sconto%, calcola da retail
      if (isNaN(costo) && !isNaN(scontoForn) && scontoForn >= 0 && scontoForn <= 100) {
        costo = retail * (1 - scontoForn / 100);
      }
      if (isNaN(costo) || costo < 0) continue;
      // Sconto% effettivo (calcolato dal costo)
      const scontoEffettivo = retail > 0 ? ((retail - costo) / retail * 100) : 0;
      const titolo = titoloIdx >= 0 ? String(row[titoloIdx] || '').trim() : '';
      const stock = stockIdx >= 0 ? (parseInt(row[stockIdx]) || 0) : null;
      let iva = ivaDefault;
      if (ivaIdx >= 0) {
        const ivaCol = parseFloat(row[ivaIdx]);
        if (!isNaN(ivaCol) && ivaCol >= 0 && ivaCol <= 30) iva = ivaCol;
      }
      products.push({ sku, titolo, stock, retail, scontoForn: scontoEffettivo, costo, listino, iva });
    }
    
    if (products.length === 0) {
      status.textContent = '❌ Nessuna riga valida (controlla SKU + Retail + Costo/Sconto%)';
      status.style.color = 'var(--red)';
      return;
    }
    
    // Calcola margini per ogni prodotto su tutti i MP
    products.forEach(p => {
      p.calcoli = Object.entries(MARKETPLACES).map(([key, mp]) => {
        const r = batchCalcMargine(p.listino, p.costo, key, p.iva, p.retail);
        return { mp_key: key, mp_nome: mp.nome, ...r };
      }).sort((a, b) => b.margine - a.margine);
    });
    
    batchProducts = products;
    status.textContent = '✅ Caricati ' + products.length + ' prodotti';
    status.style.color = 'var(--green-dark)';
    renderBatch();
  } catch (e) {
    status.textContent = '❌ Errore: ' + e.message;
    status.style.color = 'var(--red)';
    console.error(e);
  }
}

function batchCalcMargine(listino, costo, mpKey, iva, retail) {
  const mp = MARKETPLACES[mpKey];
  if (!mp) return null;
  const nettoIva = listino / (1 + iva / 100);
  const dopoSconto = nettoIva * (1 - mp.sconto_percentuale / 100);
  const feeShop = mpKey === 'TLUXY_SITE' ? dopoSconto * 0.0015 : 0;
  const feeP = dopoSconto * (mp.fee_principale / 100);
  const feeS = dopoSconto * ((mp.fee_secondaria || 0) / 100);
  const feeA = dopoSconto * ((mp.fee_accessoria || 0) / 100);
  const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine = dopoSconto - feeShop - feesMp - costo;
  const marginePerc = listino > 0 ? (margine / listino * 100) : 0;
  // Break-even, prezzo per 20%, prezzo per 30% (formula: stesso meccanismo di prezzoMinimoPerMargine)
  function prezzoMin(targetPerc) {
    const totalPercFee = (mp.fee_principale + (mp.fee_secondaria || 0) + (mp.fee_accessoria || 0) + (mpKey === 'TLUXY_SITE' ? 0.15 : 0)) / 100;
    const scontoP = mp.sconto_percentuale / 100;
    const feeFissa = (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
    const coef = (1 - scontoP) * (1 - totalPercFee) / (1 + iva / 100) - targetPerc / 100;
    if (coef <= 0) return null;
    return (costo + feeFissa) / coef;
  }
  // Margine se vendo a retail pieno
  let margineRetail = null, margineRetailPerc = null;
  if (retail && retail > 0 && retail !== listino) {
    const r = batchCalcMargine(retail, costo, mpKey, iva, null);
    margineRetail = r ? r.margine : null;
    margineRetailPerc = r ? r.marginePerc : null;
  }
  // Sconto massimo accettabile dal retail per fare 20% margine
  // Se per fare 20% serve prezzo X, allora sconto max = (retail - X) / retail * 100
  let scontoMax20 = null;
  if (retail && retail > 0) {
    const p20 = prezzoMin(20);
    if (p20 !== null && p20 > 0) {
      scontoMax20 = ((retail - p20) / retail) * 100;
      // Se negativo significa che NON puoi scontare (devi vendere SOPRA retail)
      if (scontoMax20 < 0) scontoMax20 = null; // impossibile
    }
  }
  return {
    margine, marginePerc, dopoSconto, feesMp, feeShop,
    breakEven: prezzoMin(0),
    prezzo20: prezzoMin(20),
    prezzo30: prezzoMin(30),
    margineRetail, margineRetailPerc,
    scontoMax20
  };
}

function renderBatch() {
  const cont = document.getElementById('batch-content');
  if (!batchProducts.length) { cont.innerHTML = ''; return; }
  
  // Riepilogo: quanti prodotti redditizi, quale MP è il migliore in media
  const sopra20 = batchProducts.filter(p => p.calcoli[0].marginePerc >= 20).length;
  const sopra10 = batchProducts.filter(p => p.calcoli[0].marginePerc >= 10).length;
  const sotto = batchProducts.length - sopra10;
  
  // Migliore MP in media (top scelto più spesso)
  const topCounts = {};
  batchProducts.forEach(p => {
    const top = p.calcoli[0].mp_nome;
    topCounts[top] = (topCounts[top] || 0) + 1;
  });
  const mpVincente = Object.entries(topCounts).sort((a, b) => b[1] - a[1])[0];
  
  const summary = '<div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:12px; margin-bottom:20px;">' +
    '<div style="background:var(--green-light); border-left:3px solid var(--green-primary); padding:14px; border-radius:8px;">' +
      '<div style="font-size:0.7rem; color:var(--green-dark); text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">Margine ≥ 20%</div>' +
      '<div style="font-size:1.4rem; font-weight:800; margin-top:4px;">' + sopra20 + '</div>' +
      '<div style="font-size:0.75rem; color:var(--green-dark);">su ' + batchProducts.length + ' prodotti</div>' +
    '</div>' +
    '<div style="background:var(--gold-light); border-left:3px solid var(--gold); padding:14px; border-radius:8px;">' +
      '<div style="font-size:0.7rem; color:#8B6914; text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">Margine 10-20%</div>' +
      '<div style="font-size:1.4rem; font-weight:800; margin-top:4px;">' + (sopra10 - sopra20) + '</div>' +
      '<div style="font-size:0.75rem; color:#8B6914;">accettabile</div>' +
    '</div>' +
    '<div style="background:var(--red-light); border-left:3px solid var(--red); padding:14px; border-radius:8px;">' +
      '<div style="font-size:0.7rem; color:var(--red); text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">Sotto 10%</div>' +
      '<div style="font-size:1.4rem; font-weight:800; margin-top:4px;">' + sotto + '</div>' +
      '<div style="font-size:0.75rem; color:var(--red);">da rivedere</div>' +
    '</div>' +
    '<div style="background:var(--gray-100); border-left:3px solid var(--gray-700); padding:14px; border-radius:8px;">' +
      '<div style="font-size:0.7rem; color:var(--gray-700); text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">MP più spesso #1</div>' +
      '<div style="font-size:1.05rem; font-weight:800; margin-top:4px;">' + (mpVincente ? mpVincente[0] : '—') + '</div>' +
      '<div style="font-size:0.75rem; color:var(--gray-700);">' + (mpVincente ? mpVincente[1] + ' volte top' : '') + '</div>' +
    '</div>' +
  '</div>';
  
  // Bottone Esporta
  const exportBtn = '<div style="display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap;">' +
    '<button id="batch-export-btn" class="apply-btn" style="background:var(--green-primary); padding:10px 18px;">📥 Esporta Excel completo (16 MP × tutti i prodotti)</button>' +
    '<button id="batch-clear-btn" class="apply-btn" style="background:var(--gray-700); padding:10px 18px;">🗑️ Pulisci</button>' +
  '</div>';
  
  // Tabella compatta
  const tableHtml = '<div class="table-wrap" style="margin-top:8px;">' +
    '<table class="breakdown-table" style="font-size:0.85rem;">' +
      '<thead><tr>' +
        '<th>SKU</th>' +
        '<th>Titolo</th>' +
        (batchProducts.some(p => p.stock !== null) ? '<th class="num">Stock</th>' : '') +
        '<th class="num">Retail</th>' +
        '<th class="num">Sc.%</th>' +
        '<th class="num">Costo</th>' +
        '<th class="num">Listino</th>' +
        '<th class="num">IVA</th>' +
        '<th>Top 3 MP</th>' +
        '<th></th>' +
      '</tr></thead>' +
      '<tbody>' +
      batchProducts.map((p, idx) => {
        const top3 = p.calcoli.slice(0, 3);
        const top3Html = top3.map(c => {
          const cls = c.margine >= 0 ? 'margin-pos' : 'margin-neg';
          const segno = c.margine >= 0 ? '+' : '';
          return '<span style="display:inline-block; background:var(--gray-100); padding:2px 8px; border-radius:6px; font-size:0.75rem; margin:1px 2px;"><strong>' + c.mp_nome + '</strong> · <span class="' + cls + '">' + segno + '€' + c.margine.toFixed(0) + '</span> <span style="color:var(--gray-700);">(' + c.marginePerc.toFixed(1) + '%)</span></span>';
        }).join(' ');
        const isExpanded = batchExpanded === p.sku;
        const sameRetailListino = Math.abs(p.retail - p.listino) < 0.5;
        const mainRow = '<tr style="cursor:pointer;" data-batch-sku="' + p.sku + '">' +
          '<td><strong style="font-family:monospace; font-size:0.8rem;">' + p.sku + '</strong></td>' +
          '<td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' + (p.titolo || '—') + '</td>' +
          (batchProducts.some(pp => pp.stock !== null) ? '<td class="num">' + (p.stock !== null ? p.stock : '—') + '</td>' : '') +
          '<td class="num">€' + p.retail.toFixed(2) + '</td>' +
          '<td class="num" style="color:var(--green-dark); font-weight:600;">-' + p.scontoForn.toFixed(0) + '%</td>' +
          '<td class="num">€' + p.costo.toFixed(2) + '</td>' +
          '<td class="num">' + (sameRetailListino ? '<span style="color:var(--gray-500);">=retail</span>' : '€' + p.listino.toFixed(2)) + '</td>' +
          '<td class="num">' + p.iva + '%</td>' +
          '<td>' + top3Html + '</td>' +
          '<td class="num"><span style="color:var(--gray-500); font-size:0.75rem;">' + (isExpanded ? '▼' : '▶') + '</span></td>' +
        '</tr>';
        let detailRow = '';
        if (isExpanded) {
          const colspan = batchProducts.some(pp => pp.stock !== null) ? '10' : '9';
          const detTable = '<tr><td colspan="' + colspan + '" style="padding:0; background:var(--cream);">' +
            '<div style="padding:14px;">' +
            '<div style="margin-bottom:8px; font-size:0.78rem; color:var(--gray-700);"><strong>Retail di riferimento: €' + p.retail.toFixed(2) + '</strong> · sconto fornitore -' + p.scontoForn.toFixed(1) + '% (costo €' + p.costo.toFixed(2) + ')</div>' +
            '<table class="detail-table" style="font-size:0.78rem;">' +
              '<thead><tr><th>Marketplace</th><th class="num">Prezzo netto MP</th><th class="num">Fees MP</th><th class="num">Margine €</th><th class="num">Margine %</th><th class="num">Break-even</th><th class="num">Per 20%</th><th class="num">Per 30%</th><th class="num" title="Sconto massimo che puoi fare dal retail e ancora avere 20% margine">Sc.Max 20%</th></tr></thead>' +
              '<tbody>' +
              p.calcoli.map((c, ci) => {
                const cls = c.margine >= 0 ? 'margin-pos' : 'margin-neg';
                const isTop = ci < 3;
                const bg = isTop ? 'background:rgba(0,128,96,0.06);' : '';
                const segno = c.margine >= 0 ? '+' : '';
                const medal = isTop ? ' 🏆' : '';
                // Sconto max formattato
                let scMaxFmt = '—';
                if (c.scontoMax20 !== null && c.scontoMax20 !== undefined) {
                  if (c.scontoMax20 < 0) scMaxFmt = '<span style="color:var(--red);" title="Impossibile fare 20%: devi vendere sopra retail">impossibile</span>';
                  else scMaxFmt = '<span style="color:var(--green-dark); font-weight:600;">-' + c.scontoMax20.toFixed(1) + '%</span>';
                }
                return '<tr style="' + bg + '">' +
                  '<td><strong>' + c.mp_nome + medal + '</strong></td>' +
                  '<td class="num">€' + c.dopoSconto.toFixed(2) + '</td>' +
                  '<td class="num">€' + c.feesMp.toFixed(2) + '</td>' +
                  '<td class="num ' + cls + '">' + segno + '€' + c.margine.toFixed(2) + '</td>' +
                  '<td class="num ' + cls + '">' + c.marginePerc.toFixed(1) + '%</td>' +
                  '<td class="num" style="color:var(--gray-700);">' + (c.breakEven ? '€' + c.breakEven.toFixed(0) : '—') + '</td>' +
                  '<td class="num" style="color:var(--gray-700);">' + (c.prezzo20 ? '€' + c.prezzo20.toFixed(0) : '—') + '</td>' +
                  '<td class="num" style="color:var(--gray-700);">' + (c.prezzo30 ? '€' + c.prezzo30.toFixed(0) : '—') + '</td>' +
                  '<td class="num">' + scMaxFmt + '</td>' +
                '</tr>';
              }).join('') +
              '</tbody></table></div></td></tr>';
          detailRow = detTable;
        }
        return mainRow + detailRow;
      }).join('') +
      '</tbody></table></div>';
  
  cont.innerHTML = summary + exportBtn + tableHtml;
  
  // Click handlers
  cont.querySelectorAll('tr[data-batch-sku]').forEach(tr => {
    tr.addEventListener('click', () => {
      const sku = tr.dataset.batchSku;
      batchExpanded = batchExpanded === sku ? null : sku;
      renderBatch();
    });
  });
  document.getElementById('batch-export-btn').addEventListener('click', exportBatchExcel);
  document.getElementById('batch-clear-btn').addEventListener('click', () => {
    if (!confirm('Pulire tutti i prodotti caricati?')) return;
    batchProducts = []; batchExpanded = null;
    document.getElementById('batch-status').textContent = '';
    document.getElementById('batch-file').value = '';
    renderBatch();
  });
}

function exportBatchExcel() {
  if (!batchProducts.length) return;
  loadSheetJS().then(() => {
    const wb = XLSX.utils.book_new();
    
    // Foglio 1: riepilogo per prodotto (top MP per ognuno)
    const summaryRows = [
      ['SKU', 'Titolo', 'Stock', 'Retail RRP', 'Sconto% fornitore', 'Costo', 'Listino vendita', 'IVA %', 'Top MP', 'Margine €', 'Margine %', 'Break-even', 'Sconto Max -20% margine']
    ];
    batchProducts.forEach(p => {
      const top = p.calcoli[0];
      summaryRows.push([
        p.sku, p.titolo || '', p.stock !== null ? p.stock : '',
        p.retail, parseFloat(p.scontoForn.toFixed(2)),
        p.costo, p.listino, p.iva,
        top.mp_nome, parseFloat(top.margine.toFixed(2)), parseFloat(top.marginePerc.toFixed(2)),
        top.breakEven ? parseFloat(top.breakEven.toFixed(2)) : '',
        top.scontoMax20 !== null && top.scontoMax20 !== undefined && top.scontoMax20 >= 0 ? parseFloat(top.scontoMax20.toFixed(2)) : 'N/D'
      ]);
    });
    const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
    XLSX.utils.book_append_sheet(wb, wsSummary, 'Riepilogo');
    
    // Foglio 2: Dettaglio (riga per ogni MP × prodotto, vista lunga)
    const detRows = [
      ['SKU', 'Titolo', 'Stock', 'Retail RRP', 'Sconto% fornitore', 'Costo', 'Listino vendita', 'IVA %', 'Marketplace', 'Prezzo netto MP', 'Fees MP', 'Margine €', 'Margine %', 'Break-even', 'Prezzo per 20%', 'Prezzo per 30%', 'Sconto Max -20% margine']
    ];
    batchProducts.forEach(p => {
      p.calcoli.forEach(c => {
        detRows.push([
          p.sku, p.titolo || '', p.stock !== null ? p.stock : '',
          p.retail, parseFloat(p.scontoForn.toFixed(2)),
          p.costo, p.listino, p.iva,
          c.mp_nome,
          parseFloat(c.dopoSconto.toFixed(2)),
          parseFloat(c.feesMp.toFixed(2)),
          parseFloat(c.margine.toFixed(2)),
          parseFloat(c.marginePerc.toFixed(2)),
          c.breakEven ? parseFloat(c.breakEven.toFixed(2)) : '',
          c.prezzo20 ? parseFloat(c.prezzo20.toFixed(2)) : '',
          c.prezzo30 ? parseFloat(c.prezzo30.toFixed(2)) : '',
          c.scontoMax20 !== null && c.scontoMax20 !== undefined && c.scontoMax20 >= 0 ? parseFloat(c.scontoMax20.toFixed(2)) : 'N/D'
        ]);
      });
    });
    const wsDet = XLSX.utils.aoa_to_sheet(detRows);
    XLSX.utils.book_append_sheet(wb, wsDet, 'Dettaglio per MP');
    
    // Foglio 3: matrice pivot (SKU in righe × MP in colonne, valori = margine €)
    const mpKeys = Object.keys(MARKETPLACES);
    const pivotHeader = ['SKU', 'Titolo', 'Listino'].concat(mpKeys.map(k => MARKETPLACES[k].nome + ' €'));
    const pivotRows = [pivotHeader];
    batchProducts.forEach(p => {
      const row = [p.sku, p.titolo || '', p.listino];
      mpKeys.forEach(k => {
        const c = p.calcoli.find(x => x.mp_key === k);
        row.push(c ? parseFloat(c.margine.toFixed(2)) : '');
      });
      pivotRows.push(row);
    });
    const wsPivot = XLSX.utils.aoa_to_sheet(pivotRows);
    XLSX.utils.book_append_sheet(wb, wsPivot, 'Matrice margini €');
    
    // Foglio 4: matrice pivot %
    const pivotHeaderPerc = ['SKU', 'Titolo', 'Listino'].concat(mpKeys.map(k => MARKETPLACES[k].nome + ' %'));
    const pivotRowsPerc = [pivotHeaderPerc];
    batchProducts.forEach(p => {
      const row = [p.sku, p.titolo || '', p.listino];
      mpKeys.forEach(k => {
        const c = p.calcoli.find(x => x.mp_key === k);
        row.push(c ? parseFloat(c.marginePerc.toFixed(2)) : '');
      });
      pivotRowsPerc.push(row);
    });
    const wsPivotPerc = XLSX.utils.aoa_to_sheet(pivotRowsPerc);
    XLSX.utils.book_append_sheet(wb, wsPivotPerc, 'Matrice margini %');
    
    const date = new Date().toISOString().split('T')[0];
    XLSX.writeFile(wb, 'tluxy_calcolo_batch_' + date + '.xlsx');
  }).catch(e => alert('Errore export: ' + e.message));
}

function downloadBatchTemplate() {
  loadSheetJS().then(() => {
    const data = [
      ['SKU', 'Titolo', 'Stock', 'Retail', 'Sconto%', 'Costo', 'Listino', 'IVA'],
      ['ESEMPIO-001', 'Borsa esempio (sconto 50%)', 5, 590, 50, '', 590, 22],
      ['ESEMPIO-002', 'Sneakers (costo diretto)', 3, 380, '', 152, 380, 22],
      ['ESEMPIO-003', 'Borsa scontata in vendita', 2, 1200, 55, '', 1080, 22],
      ['ESEMPIO-004', 'Solo retail e sconto', 1, 800, 60, '', '', 22]
    ];
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(data);
    // Set column widths per leggibilità
    ws['!cols'] = [{wch:18}, {wch:32}, {wch:8}, {wch:10}, {wch:10}, {wch:10}, {wch:12}, {wch:6}];
    XLSX.utils.book_append_sheet(wb, ws, 'Prodotti');
    
    // Aggiungo un foglio "Istruzioni" per chiarezza
    const istr = [
      ['ISTRUZIONI USO TEMPLATE'],
      [''],
      ['COLONNE OBBLIGATORIE:'],
      ['• SKU - codice prodotto'],
      ['• Retail (o Listino) - prezzo retail pieno RRP'],
      ['• Costo OPPURE Sconto% - almeno una delle due'],
      [''],
      ['COLONNE OPZIONALI:'],
      ['• Titolo - nome prodotto'],
      ['• Stock - pezzi disponibili'],
      ['• Listino - prezzo di vendita effettivo (default = Retail)'],
      ['• IVA - aliquota IVA (default = 22%)'],
      [''],
      ['LOGICA CALCOLO COSTO:'],
      ['• Se compili "Sconto%", il costo è calcolato: Retail × (1 - Sconto%/100)'],
      ['• Se compili "Costo", uso quel valore direttamente'],
      ['• Se compili entrambi, prevale "Costo"'],
      [''],
      ['ESEMPI:'],
      ['• Retail 500€ + Sconto% 50 = Costo 250€'],
      ['• Retail 380€ + Costo 152€ = Sconto effettivo 60%'],
      [''],
      ['NOMI COLONNE ACCETTATI (case-insensitive):'],
      ['• SKU: sku, codice, codice prodotto'],
      ['• Retail: retail, rrp, retail price, prezzo retail, prezzo pieno'],
      ['• Sconto%: sconto, sconto%, sconto fornitore, discount%'],
      ['• Costo: costo, cost, costo fornitore, costo acquisto'],
      ['• Listino: listino, prezzo vendita, prezzo, price, sell price']
    ];
    const wsIstr = XLSX.utils.aoa_to_sheet(istr);
    wsIstr['!cols'] = [{wch:70}];
    XLSX.utils.book_append_sheet(wb, wsIstr, 'Istruzioni');
    
    XLSX.writeFile(wb, 'tluxy_template_calcolo_batch.xlsx');
  }).catch(e => alert('Errore: ' + e.message));
}

// ============ CHAT AI ASSISTANT (v5.10) ============
let chatHistory = []; // {role, content}
let chatBusy = false;

async function checkChatStatus() {
  const bar = document.getElementById('chat-status-bar');
  if (!bar) return;
  try {
    const data = await fetchNoCache('/api/chat-status');
    if (data.enabled) {
      bar.className = 'info-box';
      bar.style.cssText = 'background:var(--green-light); border-left-color:var(--green-primary); color:var(--green-dark);';
      bar.innerHTML = '✅ <strong>Assistente attivo</strong> · usa modello ' + (data.model || 'Claude') + ' · costo stimato per messaggio: ' + (data.cost_per_msg || '€0.01-0.05');
    } else {
      bar.className = 'warn-box';
      bar.innerHTML = '⚠️ <strong>Assistente non configurato</strong>. Per attivarlo: Vercel → Settings → Environment Variables → aggiungi <code>ANTHROPIC_API_KEY</code> con la tua chiave da console.anthropic.com';
    }
  } catch(e) {
    bar.innerHTML = '❌ Errore verifica stato: ' + e.message;
  }
}

function chatRender() {
  const container = document.getElementById('chat-messages');
  if (!container) return;
  if (chatHistory.length === 0) return; // mostra suggested
  container.innerHTML = chatHistory.map(msg => {
    const isUser = msg.role === 'user';
    const align = isUser ? 'flex-end' : 'flex-start';
    const bg = isUser ? 'var(--black)' : 'var(--white)';
    const color = isUser ? 'var(--white)' : 'var(--black)';
    const border = isUser ? 'none' : '1px solid var(--gray-200)';
    const radius = isUser ? '14px 14px 4px 14px' : '14px 14px 14px 4px';
    // Markdown molto basico: doppio asterisco per bold, newline per a-capo
    let content = String(msg.content || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    content = content.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
    content = content.replace(/\\n/g, '<br>');
    return '<div style="display:flex; justify-content:' + align + '; margin-bottom:12px;">' +
      '<div style="max-width:80%; padding:11px 16px; background:' + bg + '; color:' + color + '; border:' + border + '; border-radius:' + radius + '; font-size:0.92rem; line-height:1.5; white-space:pre-wrap; overflow-wrap:break-word;">' + content + '</div>' +
    '</div>';
  }).join('');
  if (chatBusy) {
    container.innerHTML += '<div style="display:flex; justify-content:flex-start; margin-bottom:12px;">' +
      '<div style="padding:11px 16px; background:var(--white); border:1px solid var(--gray-200); border-radius:14px 14px 14px 4px; font-size:0.9rem; color:var(--gray-700);">' +
      '<span style="display:inline-block; animation:pulse 1.4s infinite;">●</span><span style="display:inline-block; animation:pulse 1.4s infinite 0.2s; margin:0 4px;">●</span><span style="display:inline-block; animation:pulse 1.4s infinite 0.4s;">●</span></div></div>';
  }
  container.scrollTop = container.scrollHeight;
}

async function chatSend(message) {
  if (!message || chatBusy) return;
  chatHistory.push({ role: 'user', content: message });
  chatBusy = true;
  chatRender();
  document.getElementById('chat-input').value = '';
  
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: chatHistory })
    });
    const data = await res.json();
    chatBusy = false;
    if (data.success) {
      chatHistory.push({ role: 'assistant', content: data.reply });
    } else {
      chatHistory.push({ role: 'assistant', content: '❌ Errore: ' + (data.error || 'sconosciuto') });
    }
    chatRender();
  } catch(e) {
    chatBusy = false;
    chatHistory.push({ role: 'assistant', content: '❌ Errore di rete: ' + e.message });
    chatRender();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadMarketplaces();
  const today = new Date(); const monthAgo = new Date(); monthAgo.setMonth(monthAgo.getMonth() - 1);
  const fmt = d => d.toISOString().split('T')[0];
  ['date-from', 'bs-date-from'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(monthAgo); });
  ['date-to', 'bs-date-to'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(today); });
  document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => {
    showTab(btn.dataset.tab);
    if (btn.dataset.tab === 'duo') { checkKvStatus(); /* on-demand: niente auto-load, clicca Ricarica */ }
    if (btn.dataset.tab === 'forecast') { if (!forecastData) loadForecast(); }
    if (btn.dataset.tab === 'inventory') { if (!inventoryData) loadInventory(false); }
    if (btn.dataset.tab === 'chat') { checkChatStatus(); }
  }));
  document.querySelectorAll('[data-analytics-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => setPeriod(btn.dataset.period, btn)));
  document.querySelectorAll('[data-bs-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => loadBestSellers(btn.dataset.period, btn)));
  document.getElementById('analytics-apply').addEventListener('click', applyCustomRange);
  document.getElementById('bs-apply').addEventListener('click', applyBsCustomRange);
  ['c-prezzo', 'c-iva', 'c-costo', 'c-spedizione'].forEach(id => { const el = document.getElementById(id); if (el) { el.addEventListener('input', confronta); if (el.tagName === 'SELECT') el.addEventListener('change', confronta); } });
  document.getElementById('calcola-btn').addEventListener('click', calcola);
  // Batch Excel listeners
  const batchFile = document.getElementById('batch-file');
  if (batchFile) batchFile.addEventListener('change', e => { if (e.target.files[0]) handleBatchFile(e.target.files[0]); });
  const batchTplBtn = document.getElementById('batch-template-btn');
  if (batchTplBtn) batchTplBtn.addEventListener('click', downloadBatchTemplate);
  const batchIvaSel = document.getElementById('batch-iva-default');
  if (batchIvaSel) batchIvaSel.addEventListener('change', () => {
    // Ricalcola usando nuova IVA come default
    if (batchProducts.length > 0) {
      const newIva = parseFloat(batchIvaSel.value) || 22;
      batchProducts.forEach(p => {
        p.iva = newIva;
        p.calcoli = Object.entries(MARKETPLACES).map(([key, mp]) => {
          const r = batchCalcMargine(p.listino, p.costo, key, p.iva, p.retail);
          return { mp_key: key, mp_nome: mp.nome, ...r };
        }).sort((a, b) => b.margine - a.margine);
      });
      renderBatch();
    }
  });
  // DUO listeners
  document.getElementById('duo-reload').addEventListener('click', loadDuoProducts);
  const fcBtn = document.getElementById('forecast-reload');
  if (fcBtn) fcBtn.addEventListener('click', () => loadForecast(false));
  const fcRefresh = document.getElementById('forecast-refresh');
  if (fcRefresh) fcRefresh.addEventListener('click', () => {
    if (confirm('Ricalcolare tutte le previsioni? Richiede 10-30 secondi.')) loadForecast(true);
  });
  
  // Inventory listeners
  const invBtn = document.getElementById('inventory-reload');
  if (invBtn) invBtn.addEventListener('click', () => loadInventory(false));
  const invRefresh = document.getElementById('inventory-refresh');
  if (invRefresh) invRefresh.addEventListener('click', () => {
    if (confirm('Scaricare di nuovo tutto il catalogo da Shopify? Richiede 20-60 secondi.')) loadInventory(true);
  });
  document.querySelectorAll('.inv-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.inv-filter').forEach(b => {
        b.classList.remove('active');
        b.style.background = 'transparent';
        b.style.color = 'var(--gray-700)';
        b.style.fontWeight = '400';
      });
      btn.classList.add('active');
      btn.style.background = 'var(--white)';
      btn.style.color = 'var(--black)';
      btn.style.fontWeight = '600';
      inventoryFilter = btn.dataset.filter;
      if (inventoryData) renderInventory();
    });
  });
  document.getElementById('duo-csv-file').addEventListener('change', e => { if (e.target.files[0]) handleCsvImport(e.target.files[0]); });
  document.getElementById('duo-search').addEventListener('input', filterDuoProducts);
  // Chat AI listeners
  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send');
  const chatClearBtn = document.getElementById('chat-clear');
  if (chatSendBtn) chatSendBtn.addEventListener('click', () => {
    const v = (chatInput.value || '').trim();
    if (v) chatSend(v);
  });
  if (chatInput) chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const v = (chatInput.value || '').trim();
      if (v) chatSend(v);
    }
  });
  if (chatClearBtn) chatClearBtn.addEventListener('click', () => {
    chatHistory = [];
    chatBusy = false;
    chatRender();
    // Mostra schermata vuota con suggerimenti
    document.getElementById('chat-messages').innerHTML = document.getElementById('chat-messages').innerHTML; // forza re-render iniziale
    location.hash = '#chat-tab'; setTimeout(() => location.hash = '', 100); // reset visivo
  });
  // Bottoni suggested in chat
  document.querySelectorAll('.chat-suggest').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.textContent.replace(/^[^a-zA-Z0-9]+\s*/, '').trim();
      chatSend(text);
    });
  });
  // Logout handler
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (!confirm('Vuoi uscire dalla dashboard?')) return;
      try { await fetch('/api/logout', { method: 'POST' }); } catch(_) {}
      window.location.href = '/login';
    });
  }
  // Scorciatoia Retail nel Calcolatore: monodirezionale (retail+sconti → prezzo+costo)
  function calcUpdateFromRetail() {
    try {
      var retailEl = document.getElementById('calc-retail');
      var scVendEl = document.getElementById('calc-sconto-vendita');
      var scCostEl = document.getElementById('calc-sconto-costo');
      var summary = document.getElementById('calc-retail-summary');
      if (!retailEl || !scVendEl || !scCostEl || !summary) return;
      var retail = parseFloat(retailEl.value);
      if (isNaN(retail) || retail <= 0) { summary.style.display = 'none'; return; }
      var scVend = parseFloat(scVendEl.value); if (isNaN(scVend)) scVend = 0;
      var scCost = parseFloat(scCostEl.value); if (isNaN(scCost)) scCost = 0;
      var prezzo = retail * (1 - scVend / 100);
      var costo = retail * (1 - scCost / 100);
      var prezzoEl = document.getElementById('prezzo');
      var costoEl = document.getElementById('costo');
      if (prezzoEl) prezzoEl.value = prezzo.toFixed(2);
      if (costoEl) costoEl.value = costo.toFixed(2);
      summary.style.display = 'block';
      summary.innerHTML = 'Vendo a <strong>€' + prezzo.toFixed(2) + '</strong> (-' + scVend.toFixed(1) + '%) · compro a <strong>€' + costo.toFixed(2) + '</strong> (-' + scCost.toFixed(1) + '%)';
      if (typeof calcola === 'function') calcola();
    } catch(e) { console.error('calcUpdateFromRetail:', e); }
  }
  ['calc-retail', 'calc-sconto-vendita', 'calc-sconto-costo'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('input', calcUpdateFromRetail);
  });
  setTimeout(() => { calcola(); confronta(); const todayBtn = document.querySelector('[data-analytics-periods] .period-btn[data-period="today"]'); setPeriod('today', todayBtn); }, 300);
});

// ===== v5.14 Alert canali lenti =====
function escAlert(t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function eur0(n) { return '€' + Math.round(n || 0).toLocaleString('it-IT'); }
function pillVar(v) { if (v === null || v === undefined) return '<span class="ch-pill">nuovo</span>'; var cls = v > 0 ? 'up' : (v < 0 ? 'down' : ''); return '<span class="ch-pill ' + cls + '">' + (v > 0 ? '+' : '') + v + '%</span>'; }
function rigaConfronto(etA, a, etB, b, v) { return '<div class="ch-row"><div><div class="ch-lab">' + etA + '</div><div class="ch-val">' + eur0(a.fatturato) + ' <small>' + a.ordini + ' ord.</small></div></div><div><div class="ch-lab">' + etB + '</div><div class="ch-val muted">' + eur0(b.fatturato) + ' <small>' + b.ordini + ' ord.</small></div></div><div>' + pillVar(v) + '</div></div>'; }
function dataBreve(iso) { return new Date(iso).toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit' }); }
function caricaAlertCanali(refresh) {
  var box = document.getElementById('alerts-banner');
  if (!box) return;
  if (refresh) box.innerHTML = '<div class="alerts-meta">Aggiorno i canali…</div>';
  fetch('/api/alerts' + (refresh ? '?refresh=1' : '')).then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success || !d.sezioni) { box.innerHTML = ''; return; }
    var ora = new Date(d.generato_il).toLocaleString('it-IT', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    var html = '<div class="alerts-head"><div class="alerts-title">Canali di vendita</div><button class="alerts-refresh" onclick="caricaAlertCanali(true)">Aggiorna</button></div>';
    if (d.alerts.length) html += d.alerts.map(function (a) { return '<div class="alert-item ' + escAlert(a.livello) + '"><span class="alert-dot"></span><div><strong>' + escAlert(a.nome) + '</strong> · ' + escAlert(a.messaggio) + '</div></div>'; }).join('');
    d.sezioni.forEach(function (s) {
      var main = '', det = '';
      if (s.key === 'THE_BRADERY') {
        if (s.in_corso && s.confronto_in_corso) main = rigaConfronto('Vendita in corso (' + s.confronto_in_corso.giorni + ' gg)', s.confronto_in_corso.corrente, 'Precedente, stessi gg', s.confronto_in_corso.precedente_stessi_giorni, s.confronto_in_corso.variazione_pct);
        else if (s.ultima_vendita) main = '<div class="ch-note">Nessuna private sale in corso · ultima ' + dataBreve(s.ultima_vendita.dal) + '–' + dataBreve(s.ultima_vendita.al) + ' · ' + eur0(s.ultima_vendita.fatturato) + '</div>';
        else main = '<div class="ch-note">Nessuna private sale negli ultimi 100 giorni.</div>';
        if (s.giorno && (s.giorno.oggi.ordini || s.giorno.ieri_stessa_ora.ordini)) main = rigaConfronto('Oggi finora', s.giorno.oggi, 'Ieri stessa ora', s.giorno.ieri_stessa_ora, s.giorno.variazione_oggi_pct) + main;
        if (s.ultima_vendita) det = '<div class="ch-note">Ultima: ' + dataBreve(s.ultima_vendita.dal) + '–' + dataBreve(s.ultima_vendita.al) + ' · ' + eur0(s.ultima_vendita.fatturato) + ' (' + s.ultima_vendita.ordini + ' ordini)' + (s.vendita_precedente ? '<br>Precedente: ' + dataBreve(s.vendita_precedente.dal) + '–' + dataBreve(s.vendita_precedente.al) + ' · ' + eur0(s.vendita_precedente.fatturato) + ' (' + s.vendita_precedente.ordini + ' ordini)' : '') + '</div>';
      } else if (s.key === 'TLUXY_SITE') {
        main = rigaConfronto('Oggi finora', s.oggi, 'Ieri stessa ora', s.ieri_stessa_ora, s.variazione_pct) + rigaConfronto('Ultimi 7 giorni', s.settimana.corrente, '7 precedenti', s.settimana.precedente, s.settimana.variazione_pct);
        det = rigaConfronto('Ieri', s.ieri, 'L’altro ieri', s.altro_ieri, s.variazione_ieri_pct);
        if (s.fonti_7gg && s.fonti_7gg.length) {
          var maxF = Math.max.apply(null, s.fonti_7gg.map(function (f) { return f.fatturato; })) || 1;
          det += '<div class="ch-lab" style="margin-top:10px">Da dove arrivano gli ordini (7 giorni)</div>' + s.fonti_7gg.map(function (f) { return '<div class="src-row"><span class="src-name">' + escAlert(f.fonte) + '</span><span class="src-bar"><i style="width:' + Math.max(4, Math.round(f.fatturato / maxF * 100)) + '%"></i></span><span class="src-num">' + f.ordini + ' · ' + eur0(f.fatturato) + '</span></div>'; }).join('');
        }
      } else {
        main = (s.giorno ? rigaConfronto('Oggi finora', s.giorno.oggi, 'Ieri stessa ora', s.giorno.ieri_stessa_ora, s.giorno.variazione_oggi_pct) : '') + rigaConfronto('Ultimi 7 giorni', s.corrente, '7 precedenti', s.precedente, s.variazione_pct);
        if (s.giorno) det = rigaConfronto('Ieri', s.giorno.ieri, 'L’altro ieri', s.giorno.altro_ieri, s.giorno.variazione_ieri_pct);
      }
      html += '<div class="ch-card ' + escAlert(s.stato) + '"><div class="ch-head"><span class="ch-name">' + escAlert(s.nome) + '</span></div>' + main
        + (det ? '<details class="ch-det"><summary>' + (s.key === 'TLUXY_SITE' ? 'Ieri e fonti ordini' : (s.key === 'THE_BRADERY' ? 'Dettaglio vendite' : 'Ieri vs l’altro ieri')) + '</summary>' + det + '</details>' : '') + '</div>';
    });
    if (d.altri && d.altri.length) {
      html += '<details class="ch-altri"><summary>Altri canali (' + d.altri.length + ')</summary>' + d.altri.map(function (a) { return '<div class="src-row"><span class="src-name">' + escAlert(a.nome) + '</span><span class="src-num">' + eur0(a.corrente.fatturato) + ' vs ' + eur0(a.precedente.fatturato) + '</span>' + pillVar(a.variazione_pct) + '</div>'; }).join('') + '</details>';
    }
    box.innerHTML = html + '<div class="alerts-meta">Aggiornato ' + ora + '</div>';
  }).catch(function () { box.innerHTML = ''; });
}
setTimeout(function () { caricaAlertCanali(false); }, 400);

// ===== v5.15 Controllo margini DUOMO =====
var duoPollN = 0;
function duoRiga(x, extra) { return '<div class="alert-item critico"><span class="alert-dot"></span><div><strong>' + escAlert(x.brand) + '</strong> · ' + escAlert(x.titolo) + '<br><span style="color:var(--gray-500);font-size:0.78rem;">' + extra + ' · costo €' + Math.round(x.costo) + ' · stock ' + x.stock + '</span></div></div>'; }
function duoSezione(titolo, arr, fmt) { if (!arr || !arr.length) return ''; return '<div class="breakdown-title" style="margin:14px 0 4px;font-size:0.78rem;">' + titolo + ' (' + arr.length + ')</div>' + arr.slice(0, 10).map(function (x) { return duoRiga(x, fmt(x)); }).join('') + (arr.length > 10 ? '<div class="alerts-meta">…e altri ' + (arr.length - 10) + '</div>' : ''); }
function caricaDuoAlerts(refresh) {
  var box = document.getElementById('duo-alerts'); if (!box) return;
  var head = '<div class="alerts-head"><div class="alerts-title">Margini DUOMO</div><button class="alerts-refresh" onclick="duoPollN=0;caricaDuoAlerts(true)">Aggiorna</button></div>';
  if (refresh) box.innerHTML = head + '<div class="alerts-meta">Leggo il catalogo DUOMO da Shopify…</div>';
  fetch('/api/duo-alerts' + (refresh ? '?refresh=1' : '')).then(function (r) { return r.json(); }).then(function (d) {
    if (d.status === 'running' || d.status === 'busy') {
      box.innerHTML = head + '<div class="alerts-meta">' + (d.status === 'busy' ? 'Shopify è occupato con un altro export, riprovo…' : 'Analisi del catalogo in corso' + (d.oggetti ? ' (' + d.oggetti + ' righe lette)' : '') + '…') + '</div>';
      if (duoPollN++ < 40) setTimeout(function () { caricaDuoAlerts(false); }, 6000);
      return;
    }
    if (!d.success) { box.innerHTML = head + '<div class="alerts-meta">Controllo non disponibile: ' + escAlert(d.error || '') + '</div>'; return; }
    var tot = d.sito_negativi.length + d.sito_extra_sconto_negativi.length + d.miinto_sotto_soglia.length + d.miinto_prezzo_fuori_regola.length;
    var ora = new Date(d.generato_il).toLocaleString('it-IT', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    var sint = '<div class="' + (tot ? 'alerts-meta' : 'alerts-ok') + '" style="font-size:0.82rem;color:' + (tot ? 'var(--gray-900)' : '') + '">' + d.prodotti_attivi + ' prodotti DUOMO attivi · ' + (tot ? (d.sito_negativi.length + ' in perdita sul sito, ' + d.sito_extra_sconto_negativi.length + ' in perdita con extra sconto, ' + d.miinto_sotto_soglia.length + ' Miinto sotto 7%, ' + d.miinto_prezzo_fuori_regola.length + ' prezzo Miinto fuori regola') : 'nessun problema di margine') + (d.campagna_miinto_oggi ? ' · <strong>oggi campagna Miinto</strong> (prezzo RRP +6%)' : '') + '</div>';
    var body = duoSezione('In perdita sul sito', d.sito_negativi, function (x) { return 'vendita €' + x.prezzo + ' · margine €' + x.margine + ' (' + x.margine_pct + '%)'; })
      + duoSezione('In perdita con extra sconto', d.sito_extra_sconto_negativi, function (x) { return '-' + x.sconto_extra + '% → €' + x.prezzo + ' · margine €' + x.margine; })
      + duoSezione('Miinto sotto soglia 7%', d.miinto_sotto_soglia, function (x) { return 'Miinto €' + x.prezzo_miinto + ' · margine €' + x.margine + ' (' + x.margine_pct + '%)'; })
      + duoSezione('Prezzo Miinto fuori regola', d.miinto_prezzo_fuori_regola, function (x) { return 'ora €' + x.prezzo_miinto + ' · atteso €' + x.atteso; });
    box.innerHTML = head + sint + body + '<div id="duo-ieri"></div><div class="alerts-meta">Regole: IVA ' + d.regole.iva + ', Miinto ' + d.regole.miinto + ', soglia ' + d.regole.soglia_marketplace + ' · aggiornato ' + ora + '</div>';
    caricaOrdiniIeriInPerdita();
  }).catch(function () { box.innerHTML = head + '<div class="alerts-meta">Controllo non disponibile.</div>'; });
}
function caricaOrdiniIeriInPerdita() {
  var el = document.getElementById('duo-ieri'); if (!el) return;
  fetch('/api/analytics?periodo=yesterday').then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success) return;
    var righe = []; var bm = d.breakdown_marketplace || {};
    Object.keys(bm).forEach(function (k) { (bm[k].dettaglio_ordini || []).forEach(function (o) { if (o.margine_netto < 0 && !o.is_foreign_currency) righe.push({ mp: bm[k].nome, o: o }); }); });
    var head = '<div class="breakdown-title" style="margin:14px 0 4px;font-size:0.78rem;">Ordini di ieri in perdita (' + righe.length + ')</div>';
    if (!righe.length) { el.innerHTML = head + '<div class="alerts-ok">Nessun ordine in perdita ieri · margine netto totale €' + Math.round(d.margine_netto || 0).toLocaleString('it-IT') + '</div>'; return; }
    el.innerHTML = head + righe.map(function (x) { return '<div class="alert-item critico"><span class="alert-dot"></span><div><strong>' + escAlert(x.o.name || ('#' + x.o.order_number)) + '</strong> · ' + escAlert(x.mp) + ' · venduto €' + Math.round(x.o.fatturato) + ' · margine €' + Math.round(x.o.margine_netto) + '<br><span style="color:var(--gray-500);font-size:0.78rem;">' + escAlert((x.o.articoli || []).map(function (a) { return a.title; }).join(', ')) + '</span></div></div>'; }).join('');
  }).catch(function () {});
}
setTimeout(function () { caricaDuoAlerts(false); }, 700);

// ===== v5.18 Incassi e margine di oggi in cima =====
function caricaOggiBox() {
  var box = document.getElementById('oggi-box'); if (!box) return;
  box.innerHTML = '<div class="alerts-meta">Calcolo incassi e margine di oggi…</div>';
  Promise.all([fetch('/api/analytics?periodo=today').then(function (r) { return r.json(); }), fetch('/api/analytics?periodo=yesterday').then(function (r) { return r.json(); }).catch(function () { return null; })]).then(function (res) {
    var d = res[0], y = res[1];
    if (!d || !d.success) { box.innerHTML = ''; return; }
    var mp = d.margine_percentuale || 0;
    var ieri = (y && y.success) ? '<div class="oggi-ieri">Ieri: ' + eur0(y.lordo_iva_inclusa) + ' incassati · margine ' + eur0(y.margine_netto) + ' (' + (y.margine_percentuale || 0).toFixed(1) + '%) · ' + (y.ordini_totali || 0) + ' ordini</div>' : '';
    box.innerHTML = '<div class="alerts-head"><div class="alerts-title">Oggi</div><button class="alerts-refresh" onclick="caricaOggiBox()">Aggiorna</button></div>'
      + '<div id="mese-strip" class="mese-strip"><span class="ch-lab">Calcolo il mese…</span></div>'
      + '<div class="oggi-grid"><div class="oggi-kpi dark"><div class="ch-lab">Incassato</div><div class="oggi-val">' + eur0(d.lordo_iva_inclusa) + '</div><div class="oggi-sub">' + (d.ordini_totali || 0) + ' ordini · IVA inclusa</div></div>'
      + '<div class="oggi-kpi ' + (d.margine_netto < 0 ? 'neg' : 'pos') + '"><div class="ch-lab">Margine netto</div><div class="oggi-val">' + eur0(d.margine_netto) + '</div><div class="oggi-sub">' + mp.toFixed(1) + '% sul lordo</div></div></div>' + ieri;
    caricaMeseStrip();
  }).catch(function () { box.innerHTML = ''; });
}
function ymd(d) { return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
function caricaMeseStrip() {
  var el = document.getElementById('mese-strip'); if (!el) return;
  var oggi = new Date(), g = oggi.getDate();
  var inizio = new Date(oggi.getFullYear(), oggi.getMonth(), 1);
  var inizioPrec = new Date(oggi.getFullYear(), oggi.getMonth() - 1, 1);
  var ultimoPrec = new Date(oggi.getFullYear(), oggi.getMonth(), 0).getDate();
  var finePrec = new Date(oggi.getFullYear(), oggi.getMonth() - 1, Math.min(g, ultimoPrec));
  var mesi = ['Gen','Feb','Mar','Apr','Mag','Giu','Lug','Ago','Set','Ott','Nov','Dic'];
  function get(da, a) {
    var ctl = window.AbortController ? new AbortController() : null;
    var t = setTimeout(function () { if (ctl) ctl.abort(); }, 120000);
    return fetch('/api/analytics?from=' + ymd(da) + '&to=' + ymd(a), ctl ? { signal: ctl.signal } : {}).then(function (r) { clearTimeout(t); return r.json(); }).catch(function () { clearTimeout(t); return null; });
  }
  var nonDisp = '<span class="ch-lab">Totale mese non disponibile · <a href="#" onclick="caricaMeseStrip();return false;">riprova</a></span>';
  get(inizio, oggi).then(function (c) {
    if (!c || !c.success) { el.innerHTML = nonDisp; return null; }
    el.innerHTML = '<span class="ch-lab">' + mesi[oggi.getMonth()] + ' 1–' + g + ': ' + eur0(c.lordo_iva_inclusa) + ' · margine ' + eur0(c.margine_netto) + ' — calcolo mese scorso…</span>';
    return get(inizioPrec, finePrec).then(function (p) { return [c, p]; });
  }).then(function (r) {
    if (!r) return;
    var c = r[0], p = r[1];
    function riga(nome, x, conf) {
      var v = (conf && conf.success && conf.lordo_iva_inclusa > 0) ? Math.round((x.lordo_iva_inclusa - conf.lordo_iva_inclusa) / conf.lordo_iva_inclusa * 100) : null;
      return '<div class="mese-row"><span class="mese-nome">' + nome + '</span><span class="mese-num">' + eur0(x.lordo_iva_inclusa) + '</span><span class="mese-num pos">' + eur0(x.margine_netto) + ' <small>' + (x.margine_percentuale || 0).toFixed(1) + '%</small></span>' + (conf ? pillVar(v) : '<span></span>') + '</div>';
    }
    el.innerHTML = '<div class="mese-row mese-head"><span></span><span>Incassato</span><span>Margine</span><span></span></div>'
      + riga(mesi[oggi.getMonth()] + ' 1–' + g, c, p)
      + ((p && p.success) ? riga(mesi[inizioPrec.getMonth()] + ' 1–' + finePrec.getDate(), p, null) : '');
  }).catch(function () { el.innerHTML = nonDisp; });
}

// ===== v5.33 Ricerche: Miinto SS27 =====
var RIC_DATA = null, RIC_FILTRO = 'tutti';
function ricYoy(v) { if (v === null || v === undefined) return '<span class="ric-na">n.d.</span>'; return '<span class="bs2-m ' + (v >= 40 ? 'ok' : (v < 0 ? 'low' : 'mid')) + '">' + (v > 0 ? '+' : '') + v + '%</span>'; }
var RIC_SEGNALI = { opportunita: ['Opportunità', 'ok'], rafforza: ['Rafforza', 'ok'], tieni: ['Tieni', 'mid'], neutro: ['—', ''], 'in calo': ['In calo', 'low'], attenzione: ['Attenzione', 'low'] };
function ricItem(foto, testo, sotto) { return '<div class="ric-it"><span class="ric-img">' + (foto ? '<img src="' + bsEsc(foto) + (foto.indexOf('?') > -1 ? '&' : '?') + 'width=120" loading="lazy" alt="">' : '◇') + '</span><span>' + testo + (sotto ? '<small>' + sotto + '</small>' : '') + '</span></div>'; }
function ricFiltro(f) { RIC_FILTRO = f; renderRicerche(RIC_DATA); }
function caricaRicerche(refresh) {
  var el = document.getElementById('ric-content');
  el.innerHTML = '<div class="bs-empty">Incrocio i dati Miinto con 180 giorni di ordini e il catalogo TLuxy…</div>';
  fetch('/api/ricerche-miinto' + (refresh ? '?refresh=1' : '')).then(function (r) { return r.json(); }).then(function (d) {
    if (!d.success) { el.innerHTML = '<div class="bs-empty">Errore: ' + bsEsc(d.error || '') + '</div>'; return; }
    RIC_DATA = d; renderRicerche(d);
  }).catch(function (e) { el.innerHTML = '<div class="bs-empty">Errore: ' + bsEsc(e.message) + '</div>'; });
}
function renderRicerche(d) {
  var el = document.getElementById('ric-content');
  var f = d.fonte.link;
  var html = '<div class="ric-src">Fonte: ' + bsEsc(d.fonte.titolo) + ' (' + bsEsc(d.fonte.data) + ', dati ' + bsEsc(d.fonte.periodo_dati) + ') · <a href="' + f.guida + '" target="_blank">Guida</a> · <a href="' + f.borse + '" target="_blank">Borse</a> · <a href="' + f.scarpe + '" target="_blank">Scarpe</a> · <a href="' + f.brand + '" target="_blank">Brand</a> · <a href="' + f.mercati + '" target="_blank">Mercati</a></div>';
  html += '<div class="bs2-sec">In sintesi</div><ul class="ric-list">' + d.sintesi.map(function (x) { return '<li>' + bsEsc(x) + '</li>'; }).join('') + '</ul>';
  var opp = d.brand.filter(function (b) { return b.segnale === 'opportunita'; });
  var att = d.brand.filter(function (b) { return b.segnale === 'attenzione'; });
  if (opp.length || att.length) {
    html += '<div class="ric-cards">' + (opp.length ? '<div class="ric-card ok"><b>Opportunità</b><span>Crescono su Miinto ma da noi quasi assenti</span>' + opp.map(function (b) { return '<div>' + bsEsc(b.brand) + ' <small>' + b.cat + ' · ' + (b.yoy > 0 ? '+' : '') + b.yoy + '% · ' + b.tluxy_attivi + ' attivi</small></div>'; }).join('') + '</div>' : '')
      + (att.length ? '<div class="ric-card low"><b>Attenzione</b><span>In calo su Miinto e tanti prodotti da noi</span>' + att.map(function (b) { return '<div>' + bsEsc(b.brand) + ' <small>' + b.cat + ' · ' + b.yoy + '% · ' + b.tluxy_attivi + ' attivi</small></div>'; }).join('') + '</div>' : '') + '</div>';
  }
  html += '<div class="bs2-head"><div class="bs2-sec" style="margin:0">Brand: Miinto vs TLuxy</div><div class="bs2-chips">' + [['tutti', 'Tutti'], ['Borse', 'Borse'], ['Scarpe', 'Scarpe']].map(function (c) { return '<button class="bs2-chip' + (RIC_FILTRO === c[0] ? ' on' : '') + '" data-f="' + c[0] + '" onclick="ricFiltro(this.dataset.f)">' + c[1] + '</button>'; }).join('') + '</div></div>';
  var rows = d.brand.filter(function (b) { return RIC_FILTRO === 'tutti' || b.cat === RIC_FILTRO; });
  html += '<div class="ric-table"><div class="ric-row ric-h"><span>Brand</span><span>Miinto</span><span>Crescita</span><span>TLuxy 180 gg</span><span>Segnale</span></div>' + rows.map(function (b) {
    var sg = RIC_SEGNALI[b.segnale] || ['—', ''];
    var det = '<div class="ric-det"><div><span class="bs2-l">Più venduti su Miinto</span>' + ((b.modelli && b.modelli.length) ? b.modelli.slice(0, 2).map(function (m, i) { return ricItem((b.modelli_foto || [])[i], (i + 1) + '. ' + bsEsc(m), (b.modelli_foto || [])[i] ? 'foto dal nostro catalogo' : ''); }).join('') : '<div class="ric-na">non indicati nel report</div>') + '</div>'
      + '<div><span class="bs2-l">Più venduti da noi (180 gg)</span>' + ((b.tluxy_top && b.tluxy_top.length) ? b.tluxy_top.map(function (m, i) { return ricItem(m.foto, (i + 1) + '. ' + bsEsc(m.titolo) + (m.colore ? ' – ' + bsEsc(m.colore) : ''), m.pezzi + ' pz · ' + bsEur(m.fatturato)); }).join('') : '<div class="ric-na">nessuna vendita</div>') + '</div>'
      + (b.nota ? '<div class="ric-nota">' + bsEsc(b.nota) + '</div>' : '') + '</div>';
    return '<details class="ric-exp"><summary class="ric-row"><span><b>' + bsEsc(b.brand) + '</b><small>' + b.cat + (b.nota ? ' · ' + bsEsc(b.nota) : '') + '</small></span><span>' + (b.quota !== null ? b.quota + '%' : '—') + '<small>' + (b.prezzo ? 'medio ' + bsEur(b.prezzo) : '') + '</small></span><span>' + ricYoy(b.yoy) + '</span><span>' + bsEur(b.tluxy_fatturato_180g) + '<small>' + b.tluxy_pezzi_180g + ' pz · ' + b.tluxy_attivi + ' attivi</small></span><span>' + (sg[1] ? '<span class="bs2-m ' + sg[1] + '">' + sg[0] + '</span>' : sg[0]) + '</span></summary>' + det + '</details>';
  }).join('') + '</div>';
  html += '<div class="bs2-sec" style="margin-top:16px">Forme delle borse (donna)</div><div class="ric-table">' + d.borse_forme.map(function (x) { return '<div class="ric-row ric-3"><span><b>' + bsEsc(x.forma) + '</b></span><span>' + x.quota + '% <small>medio ' + bsEur(x.prezzo) + '</small></span><span>' + ricYoy(x.yoy) + '</span></div>'; }).join('') + '</div>';
  html += '<div class="bs2-sec" style="margin-top:16px">Modelli più venduti su Miinto</div><ul class="ric-list">' + d.modelli_top.map(function (x) { return '<li>' + bsEsc(x) + '</li>'; }).join('') + '</ul>';
  html += '<div class="bs2-sec">Brand emergenti da valutare</div><div class="ric-tags">' + d.emergenti.map(function (x) { return '<span class="bs2-ch">' + bsEsc(x) + '</span>'; }).join('') + '</div>';
  html += '<div class="alerts-meta" style="margin-top:12px">Tocca un brand per vedere i 2 modelli più venduti su Miinto e da noi. Quota e crescita = GMV su Miinto. "n.d." = segno della crescita non leggibile nel PDF. TLuxy = vendite su tutti i canali negli ultimi 180 giorni e prodotti attivi su Shopify. Analizzati ' + d.ordini_analizzati + ' ordini · <a href="#" onclick="caricaRicerche(true);return false;">aggiorna</a></div>';
  el.innerHTML = html;
}
setTimeout(caricaOggiBox, 200);
setTimeout(function () { fetch('/api/setup-webhooks').catch(function () {}); }, 4000);
</script>
</body>
</html>`;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const path = req.url.split('?')[0];
  const query = new URLSearchParams(req.url.split('?')[1] || '');
  // Icone e manifest pubblici (servono alla schermata Home anche senza login)
  const iconMap = { '/apple-touch-icon.png': '180', '/apple-touch-icon-precomposed.png': '180', '/icon-192.png': '192', '/icon-512.png': '512', '/favicon.ico': '192', '/favicon.png': '192' };
  if (req.method === 'GET' && iconMap[path]) {
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.status(200).send(Buffer.from(ICON_PNG[iconMap[path]], 'base64'));
  }
  if (req.method === 'GET' && path === '/manifest.webmanifest') {
    res.setHeader('Content-Type', 'application/manifest+json');
    return res.status(200).send(WEB_MANIFEST);
  }

  try {
    // ============ WEBHOOK SHOPIFY (pubblico, verificato con HMAC) ============
    if (req.method === 'POST' && path === WEBHOOK_PATH) {
      let raw = ''; await new Promise((resolve, reject) => { req.on('data', c => raw += c); req.on('end', resolve); req.on('error', reject); });
      const hmac = req.headers['x-shopify-hmac-sha256'] || '';
      const atteso = crypto.createHmac('sha256', SHOPIFY_CLIENT_SECRET).update(raw, 'utf8').digest('base64');
      const ok = hmac && atteso.length === String(hmac).length && crypto.timingSafeEqual(Buffer.from(atteso), Buffer.from(String(hmac)));
      if (!ok) { console.log('[webhook] HMAC non valido'); return res.status(401).json({ ok: false }); }
      try {
        const ordine = JSON.parse(raw);
        if (!notificatiDuo.has(ordine.id)) {
          notificatiDuo.add(ordine.id);
          const m = await margineOrdineSingolo(ordine);
          await inviaNotificaDuo(ordine, m);
        }
      } catch (e) { console.log('[webhook] errore', e.message); }
      return res.status(200).json({ ok: true });
    }

    // ============ LOGIN UTENTE + PASSWORD (v5.22) ============
    if (PASSWORD_AUTH && path === '/login') {
      res.setHeader('Cache-Control', 'no-store');
      if (req.method === 'GET') { res.setHeader('Content-Type', 'text/html'); return res.status(200).send(passwordLoginPage(query.get('expired') === '1' ? null : null)); }
      if (req.method === 'POST') {
        const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'x';
        const t = tentativiLogin.get(ip) || { n: 0, t: Date.now() };
        if (Date.now() - t.t > 15 * 60000) { t.n = 0; t.t = Date.now(); }
        let user = '', pass = '';
        if (req.body && typeof req.body === 'object') { user = req.body.user; pass = req.body.password; }
        else {
          let raw = ''; await new Promise((resolve, reject) => { req.on('data', c => raw += c); req.on('end', resolve); req.on('error', reject); });
          const f = new URLSearchParams(raw); user = f.get('user'); pass = f.get('password');
        }
        res.setHeader('Content-Type', 'text/html');
        if (t.n >= 8) return res.status(429).send(passwordLoginPage('Troppi tentativi, riprova tra 15 minuti'));
        await new Promise(r => setTimeout(r, 300));
        if (!passwordOk(user, pass)) { t.n++; tentativiLogin.set(ip, t); return res.status(401).send(passwordLoginPage('Utente o password non corretti')); }
        tentativiLogin.delete(ip);
        setAuthCookie(res, 'utente:' + ERP_USER);
        res.writeHead(303, { Location: '/' });
        return res.end();
      }
    }

    // ============ PASSKEY ENDPOINTS (v5.21) ============
    if (PASSKEY_AUTH && req.method === 'GET' && path === '/login') {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Cache-Control', 'no-store');
      const pks = await getPasskeys();
      return res.status(200).send(passkeyLoginPage(pks.length > 0));
    }
    if (PASSKEY_AUTH && req.method === 'POST' && path.startsWith('/api/passkey/')) {
      try {
        if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurato' });
        const { rpID, origin } = rpFromReq(req);
        const data = await readJsonBody(req);
        const pks = await getPasskeys();
        if (path === '/api/passkey/login-options') {
          if (!pks.length) return res.json({ success: false, error: 'Nessun dispositivo registrato: usa il codice di attivazione' });
          const options = await generateAuthenticationOptions({ rpID, userVerification: 'required', allowCredentials: pks.map(p => ({ id: p.id, transports: p.transports })) });
          await salvaChallenge(res, options.challenge);
          return res.json({ success: true, options });
        }
        if (path === '/api/passkey/login-verify') {
          const challenge = await leggiChallenge(req);
          const cred = pks.find(p => p.id === data.response?.id);
          if (!challenge || !cred) return res.json({ success: false, error: 'Sessione scaduta o dispositivo non riconosciuto, riprova' });
          const v = await verifyAuthenticationResponse({ response: data.response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true, credential: { id: cred.id, publicKey: Buffer.from(cred.publicKey, 'base64url'), counter: cred.counter || 0, transports: cred.transports } });
          if (!v.verified) return res.json({ success: false, error: 'Verifica non riuscita' });
          cred.counter = v.authenticationInfo.newCounter; cred.ultimo_accesso = new Date().toISOString();
          await savePasskeys(pks);
          setAuthCookie(res, 'passkey:' + (cred.nome || 'dispositivo'));
          return res.json({ success: true });
        }
        if (path === '/api/passkey/register-options') {
          const loggato = getAuthenticatedUser(req);
          if (!loggato && !codiceOk(data.setup_code)) return res.json({ success: false, error: 'Codice di attivazione non valido' });
          const options = await generateRegistrationOptions({ rpName: 'TLuxy Business Manager', rpID, userName: 'TLuxy', userDisplayName: 'TLuxy Business Manager', userID: new TextEncoder().encode('tluxy-owner'), attestationType: 'none', excludeCredentials: pks.map(p => ({ id: p.id, transports: p.transports })), authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' } });
          const ok1 = await salvaChallenge(res, options.challenge);
          const ok2 = await kvSetEx('pk_reg_ok_' + options.challenge, 300, '1');
          console.log('[passkey] register-options', JSON.stringify({ ok1, ok2, rpID, origin }));
          if (!ok1 || !ok2) {
            // Database non raggiungibile: con il codice valido si entra comunque (sessione 30 giorni), Face ID si attiva quando il DB torna online
            setAuthCookie(res, 'codice-attivazione');
            return res.json({ success: true, fallback: true, messaggio: 'Database non disponibile: accesso con codice. Face ID si attiverà quando il database torna online.' });
          }
          return res.json({ success: true, options });
        }
        if (path === '/api/passkey/register-verify') {
          const cookieId = parseCookies(req.headers.cookie || '').pk_chal;
          const challenge = await leggiChallenge(req);
          const regOk = challenge ? await kvGet('pk_reg_ok_' + challenge) : null;
          console.log('[passkey] register-verify', JSON.stringify({ cookie: !!cookieId, challenge: !!challenge, regOk: !!regOk, rpID, origin }));
          if (!challenge || !regOk) return res.json({ success: false, error: 'Sessione scaduta, riprova (' + (cookieId ? 'c1' : 'c0') + (challenge ? 'k1' : 'k0') + (regOk ? 'r1' : 'r0') + ')' });
          const v = await verifyRegistrationResponse({ response: data.response, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
          if (!v.verified || !v.registrationInfo) return res.json({ success: false, error: 'Registrazione non verificata' });
          const c = v.registrationInfo.credential;
          const nome = String(data.nome || 'dispositivo').slice(0, 40) + ' ' + new Date().toISOString().slice(0, 10);
          pks.push({ id: c.id, publicKey: Buffer.from(c.publicKey).toString('base64url'), counter: c.counter || 0, transports: c.transports || data.response?.response?.transports || [], nome, creato: new Date().toISOString() });
          await savePasskeys(pks);
          setAuthCookie(res, 'passkey:' + nome);
          return res.json({ success: true });
        }
        return res.status(404).json({ success: false, error: 'Endpoint passkey sconosciuto' });
      } catch (error) {
        console.log('[passkey] errore', path, error.message);
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    // ============ AUTH ENDPOINTS (MAGIC LINK) ============
    // Pagina login: GET /login (pubblica, sempre accessibile)
    if (req.method === 'GET' && path === '/login') {
      res.setHeader('Content-Type', 'text/html');
      const sent = query.get('sent');
      const err = query.get('err');
      const expired = query.get('expired');
      let msg = null, isErr = false;
      if (sent === '1') msg = "✉️ Se l'email è autorizzata, riceverai il magic link a breve. Controlla la posta (anche spam).";
      else if (err === 'invalid') { msg = 'Link non valido o già usato. Richiedine uno nuovo.'; isErr = true; }
      else if (err === 'rate') { msg = "Troppi tentativi. Riprova tra un'ora."; isErr = true; }
      else if (err === 'config') { msg = "Sistema auth non configurato. Contatta l'amministratore."; isErr = true; }
      else if (expired === '1') { msg = 'Sessione scaduta, rifai login.'; isErr = true; }
      return res.status(200).send(loginHTMLPage(msg, isErr));
    }
    
    // Request magic link: POST /api/request-magic-link { email }
    if (req.method === 'POST' && path === '/api/request-magic-link') {
      if (!AUTH_ENABLED) return res.status(503).json({ success: false, error: 'Auth non configurato (RESEND_API_KEY o ALLOWED_EMAILS mancanti)' });
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurato — necessario per magic link' });
      try {
        let body = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const email = (data.email || '').trim().toLowerCase();
        // Validazione base email
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return res.status(200).json({ success: true }); // no info leak
        }
        // Check whitelist (silente per evitare enumeration)
        if (!ALLOWED_EMAILS.includes(email)) {
          // Ritorna comunque success: true per non dare info su quali email sono autorizzate
          return res.status(200).json({ success: true });
        }
        // Rate limiting via KV
        const rateLimitKey = `auth_rate_${email}`;
        const currentCount = await kvGet(rateLimitKey);
        if (currentCount && parseInt(currentCount, 10) >= MAGIC_LINK_RATE_LIMIT) {
          return res.status(200).json({ success: true }); // no leak
        }
        // Genera token magic link
        const token = generateMagicLinkToken();
        const tokenKey = `magic_token_${token}`;
        const expiresAt = Date.now() + (MAGIC_LINK_MINUTES * 60 * 1000);
        // Salva in KV con payload email + expiresAt
        await kvSet(tokenKey, JSON.stringify({ email, expiresAt }));
        // Imposta TTL via EXPIRE (Upstash supporta via URL path)
        try {
          await fetch(`${KV_REST_API_URL}/expire/${encodeURIComponent(tokenKey)}/${MAGIC_LINK_MINUTES * 60}`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
        } catch (_) {}
        // Rate limit counter increment (TTL 1h)
        try {
          const newCount = currentCount ? parseInt(currentCount, 10) + 1 : 1;
          await kvSet(rateLimitKey, String(newCount));
          await fetch(`${KV_REST_API_URL}/expire/${encodeURIComponent(rateLimitKey)}/3600`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
        } catch (_) {}
        // Costruisci magic link e invia email
        const magicLink = `${DASHBOARD_URL}/api/verify-magic-link?token=${token}`;
        try {
          await sendMagicLinkEmail(email, magicLink);
        } catch (sendErr) {
          console.error('Send email error:', sendErr.message);
          // Non leakare info sull'errore all'utente
        }
        return res.status(200).json({ success: true });
      } catch (error) {
        console.error('Magic link request error:', error.message);
        return res.status(200).json({ success: true }); // no leak
      }
    }
    
    // Verify magic link: GET /api/verify-magic-link?token=XXX (click dal link email)
    if (req.method === 'GET' && path === '/api/verify-magic-link') {
      if (!AUTH_ENABLED) return res.redirect(302, '/login?err=config');
      const token = query.get('token');
      if (!token) return res.redirect(302, '/login?err=invalid');
      try {
        const tokenKey = `magic_token_${token}`;
        const raw = await kvGet(tokenKey);
        if (!raw) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          return res.end();
        }
        let payload;
        try { payload = JSON.parse(raw); } catch (e) { 
          res.writeHead(302, { Location: '/login?err=invalid' });
          return res.end();
        }
        if (!payload.email || !payload.expiresAt || payload.expiresAt < Date.now()) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          return res.end();
        }
        // Cancella token (single-use)
        try { await fetch(`${KV_REST_API_URL}/del/${encodeURIComponent(tokenKey)}`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } }); } catch (_) {}
        // Verifica che email sia ancora autorizzata (la whitelist può essere cambiata)
        if (!ALLOWED_EMAILS.includes(payload.email)) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          return res.end();
        }
        // Setta cookie sessione e redirect alla dashboard
        setAuthCookie(res, payload.email);
        res.writeHead(302, { Location: '/' });
        return res.end();
      } catch (error) {
        console.error('Verify magic link error:', error.message);
        res.writeHead(302, { Location: '/login?err=invalid' });
        return res.end();
      }
    }
    
    // Logout: cancella cookie e redirect login
    if (req.method === 'POST' && path === '/api/logout') {
      clearAuthCookie(res);
      return res.status(200).json({ success: true });
    }
    if (req.method === 'GET' && path === '/logout') {
      clearAuthCookie(res);
      res.writeHead(302, { Location: '/login' });
      return res.end();
    }

    // ============ AUTH GATE ============
    // Tutti gli altri endpoint richiedono autenticazione (se abilitata)
    const authUser = getAuthenticatedUser(req);
    if (AUTH_ENABLED && !authUser) {
      if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
        res.writeHead(302, { Location: '/login?expired=1' });
        return res.end();
      }
      return res.status(401).json({ success: false, error: 'Non autorizzato. Effettua il login.', auth_required: true });
    }

    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      return res.json({ sistema: 'TLuxy Business Manager v5.35', status: 'LIVE', store: SHOPIFY_STORE, credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET), auth_enabled: AUTH_ENABLED, auth_type: 'magic_link_resend', kv_enabled: KV_ENABLED, kv_source: KV_SOURCE, anthropic_configured: !!process.env.ANTHROPIC_API_KEY, user_email: authUser?.email || null, funzionalita: ['🧾 Controllo margini DUOMO (/api/duo-alerts)', '🔔 Alert canali lenti (/api/alerts)', '📅 Regole MP con data di validità (Miinto 21,5% dal 01/11/2026, Bradery 90/10)', '🧮 Scorciatoia Retail+Sconti nel Calcolatore', '📊 Excel batch con Retail + Sconto% fornitore', '💡 Sconto Max accettabile per 20% margine', '💬 Chat AI assistant (Claude Haiku 4.5)', 'GIGLIO.COM marketplace', 'Mark Foy: incasso = prezzo B2B (metafield mark_foy_price → listino → DUOMO costo×1,15)', 'Split costi KPI (Merce + Fees)', 'Simulatore DUO on-demand', 'Snapshot Inventario', 'Cache KV 24h', 'Previsioni Incassi', 'Balardi wallet', 'Gestione resi/refund', 'Conversione valuta automatica'], marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length });
    }

    if (req.method === 'GET' && path === '/api/analytics') {
      const periodo = query.get('periodo') || 'today';
      const from = query.get('from'); const to = query.get('to');
      try {
        let ordini = await getShopifyOrders(periodo, from, to);
        ordini = await processOrders(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => { 
          if (item.variant_id) variantIds.add(item.variant_id);
          if (item.product_id) productIds.add(item.product_id);
        }));
        const fetchResult = await fetchVariantCosts([...variantIds], [...productIds]);
        const variantCosts = fetchResult.costs;
        const fetchStats = fetchResult.stats;
        await caricaPrezziMarkFoy(ordini);
        
        // Carica costi DUO salvati manualmente dall'utente (per gli ordini dove Shopify ha perso il cost)
        const duoUserCosts = {};
        if (KV_ENABLED) {
          const duoSkuVariantIds = [];
          ordini.forEach(o => (o.line_items || []).forEach(item => {
            if (item.variant_id && isDuoSku(item.sku)) duoSkuVariantIds.push(item.variant_id);
          }));
          const uniqueDuoVids = [...new Set(duoSkuVariantIds)];
          if (uniqueDuoVids.length > 0) {
            const duoKeys = uniqueDuoVids.map(v => `duo_user_cost_${v}`);
            const duoResults = await kvMGet(duoKeys);
            uniqueDuoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              if (duoResults[key] !== undefined) {
                const parsed = parseFloat(duoResults[key]);
                if (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        
        let lordo_iva_inclusa = 0, iva_totale = 0, costi_totali = 0, margine_netto = 0;
        // Split costi per KPI "merce" vs "fees + spedizione + packaging"
        let costi_merce_totali = 0, costi_fees_totali = 0;
        // Aggregati refund (separati per analisi)
        let resi_totale_eur = 0, resi_count = 0, resi_full_count = 0, resi_partial_count = 0;
        let resi_articoli_qty = 0;
        const breakdown_marketplace = {};
        const ordini_con_errori = [];
        const ordini_valuta_estera = [];
        const ordini_con_resi = []; // dettaglio resi per visualizzazione
        ordini.forEach(ordine => {
          const mp = riconosciMarketplace(ordine);
          const mfCalc = mp.key === 'MARK_FOYS' ? calcolaMarkFoyOrdine(ordine, variantCosts, duoUserCosts) : null;
          const { costo: costo_merce, errori } = mfCalc ? { costo: mfCalc.costo, errori: mfCalc.mancanti } : calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
          const currencyInfo = getOrderCurrencyInfo(ordine);
          const refundInfo = getOrderRefundInfo(ordine);
          if (errori.length > 0) {
            ordini_con_errori.push({ id: ordine.id, order_number: ordine.order_number, name: ordine.name, total_price: ordine.total_price, total_price_eur: currencyInfo.eurTotal, currency: currencyInfo.originalCurrency, marketplace: mp.config.nome, prodotti_senza_costo: errori });
            return;
          }
          // PREZZO LORDO IN EUR (al netto refund)
          const prezzo_lordo_originale = currencyInfo.eurTotal;
          const prezzo_lordo = Math.max(0, prezzo_lordo_originale - refundInfo.totalRefundedEur); // sottrae i refund
          const spedizione = (ordine.shipping_lines || []).reduce((sum, line) => sum + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency), 0);
          const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
          const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(country);
          const shopifyTaxEur = toEurAmount(ordine.total_tax_set, ordine.total_tax, currencyInfo.originalCurrency);
          const iva_scorporata = shopifyTaxEur > 0 ? shopifyTaxEur : (prezzo_lordo - prezzo_lordo / (1 + ivaPerc / 100));
          
          // Costo merce: se reso totale → 0 (la merce torna a magazzino), se reso parziale → proporzionale
          let costo_merce_effettivo = costo_merce;
          if (refundInfo.isFullRefund) {
            costo_merce_effettivo = 0;
          } else if (mfCalc) {
            costo_merce_effettivo = mfCalc.costo; // già al netto delle righe rese
          } else if (refundInfo.isPartialRefund && refundInfo.totalQuantity > 0) {
            // Sottrai costo della quantità rimborsata (proporzionale)
            const ratioReso = refundInfo.refundedQuantity / refundInfo.totalQuantity;
            costo_merce_effettivo = costo_merce * (1 - ratioReso);
          }
          
          const ris = mfCalc
            ? { prezzo_lordo_iva_inclusa: mfCalc.incasso, iva_scorporata: 0, prezzo_netto_iva: mfCalc.incasso, prezzo_netto_marketplace: mfCalc.incasso, fees_shopify: 0, fees_marketplace: 0, costo_merce: mfCalc.costo, spedizione: 0, costi_totali: mfCalc.costo, margine_netto: mfCalc.margine, margine_percentuale: mfCalc.incasso > 0 ? parseFloat((mfCalc.margine / mfCalc.incasso * 100).toFixed(2)) : 0 }
            : calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce_effettivo, spedizione, mp.config, mp.key);
          
          // Se reso totale → conta come 0 fatturato/margine (ma traccialo a parte)
          if (refundInfo.isFullRefund) {
            // Non sommare nulla ai KPI principali, registra solo come reso
            resi_totale_eur += refundInfo.totalRefundedEur;
            resi_count++;
            resi_full_count++;
            resi_articoli_qty += refundInfo.refundedQuantity;
            ordini_con_resi.push({
              order_number: ordine.order_number,
              name: ordine.name,
              created_at: ordine.created_at,
              marketplace: mp.config.nome,
              tipo: 'totale',
              importo_originale_eur: prezzo_lordo_originale,
              importo_rimborsato_eur: refundInfo.totalRefundedEur,
              quantita_rimborsata: refundInfo.refundedQuantity,
              quantita_totale: refundInfo.totalQuantity
            });
            return; // skip aggiunta breakdown
          }
          
          if (refundInfo.isPartialRefund) {
            resi_totale_eur += refundInfo.totalRefundedEur;
            resi_count++;
            resi_partial_count++;
            resi_articoli_qty += refundInfo.refundedQuantity;
            ordini_con_resi.push({
              order_number: ordine.order_number,
              name: ordine.name,
              created_at: ordine.created_at,
              marketplace: mp.config.nome,
              tipo: 'parziale',
              importo_originale_eur: prezzo_lordo_originale,
              importo_rimborsato_eur: refundInfo.totalRefundedEur,
              quantita_rimborsata: refundInfo.refundedQuantity,
              quantita_totale: refundInfo.totalQuantity
            });
          }
          
          lordo_iva_inclusa += ris.prezzo_lordo_iva_inclusa;
          iva_totale += ris.iva_scorporata;
          costi_totali += ris.costi_totali;
          // Split: merce da una parte; fees + spedizione + packaging dall'altra
          // (costo_fees = fees_shopify + fees_marketplace + spedizione — packaging è incluso in fees_marketplace)
          costi_merce_totali += costo_merce_effettivo;
          costi_fees_totali += (ris.fees_shopify || 0) + (ris.fees_marketplace || 0) + (mfCalc ? 0 : (spedizione || 0));
          margine_netto += ris.margine_netto;
          
          if (currencyInfo.isForeign && !mfCalc) {
            ordini_valuta_estera.push({
              order_number: ordine.order_number,
              name: ordine.name,
              currency: currencyInfo.originalCurrency,
              total_original: currencyInfo.originalTotal,
              total_eur: currencyInfo.eurTotal,
              exchange_rate: currencyInfo.exchangeRate,
              marketplace: mp.config.nome
            });
          }
          
          if (!breakdown_marketplace[mp.key]) breakdown_marketplace[mp.key] = { nome: mp.config.nome, ordini: 0, fatturato: 0, iva: 0, costo_merce: 0, margine: 0, resi_count: 0, resi_eur: 0, dettaglio_ordini: [] };
          breakdown_marketplace[mp.key].ordini += 1;
          breakdown_marketplace[mp.key].fatturato += ris.prezzo_lordo_iva_inclusa;
          breakdown_marketplace[mp.key].iva += ris.iva_scorporata;
          breakdown_marketplace[mp.key].costo_merce += costo_merce_effettivo;
          breakdown_marketplace[mp.key].margine += ris.margine_netto;
          if (refundInfo.hasRefund) {
            breakdown_marketplace[mp.key].resi_count += 1;
            breakdown_marketplace[mp.key].resi_eur += refundInfo.totalRefundedEur;
          }
          breakdown_marketplace[mp.key].dettaglio_ordini.push({
            order_number: ordine.order_number,
            name: ordine.name,
            created_at: ordine.created_at,
            country,
            fatturato: ris.prezzo_lordo_iva_inclusa,
            iva: ris.iva_scorporata,
            costo_merce: costo_merce_effettivo,
            fees_marketplace: ris.fees_marketplace,
            fees_shopify: ris.fees_shopify,
            spedizione: mfCalc ? 0 : spedizione,
            margine_netto: ris.margine_netto,
            mark_foy: mfCalc ? { fonti: mfCalc.fonti, righe: mfCalc.righe } : undefined,
            margine_percentuale: ris.margine_percentuale,
            currency: currencyInfo.originalCurrency,
            is_foreign_currency: currencyInfo.isForeign && !mfCalc,
            total_original: currencyInfo.originalTotal,
            exchange_rate: currencyInfo.exchangeRate,
            // Info refund
            refund_status: refundInfo.isFullRefund ? 'full' : (refundInfo.isPartialRefund ? 'partial' : 'none'),
            refund_amount_eur: refundInfo.totalRefundedEur,
            refund_quantity: refundInfo.refundedQuantity,
            refund_total_quantity: refundInfo.totalQuantity,
            articoli: (ordine.line_items || []).map(item => ({
              title: item.title,
              sku: item.sku || '',
              quantity: parseInt(item.quantity) || 0,
              prezzo_unit: (function() { if (mfCalc) { const r = mfCalc.righe.find(x => x.title === item.title && x.sku === (item.sku || '')); if (r) return r.prezzo_mf; } return toEurAmount(item.price_set, item.price, currencyInfo.originalCurrency); })(),
              cost_unit: (function() {
                if (item.variant_id && variantCosts[item.variant_id] !== null && variantCosts[item.variant_id] !== undefined) return variantCosts[item.variant_id];
                if (isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) return duoUserCosts[item.variant_id];
                return 0;
              })()
            }))
          });
        });
        const ordini_validi = ordini.length - ordini_con_errori.length - resi_full_count;
        const margine_percentuale = lordo_iva_inclusa > 0 ? (margine_netto / lordo_iva_inclusa * 100) : 0;
        // Ordina i resi più recenti prima
        ordini_con_resi.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        return res.json({
          success: true,
          periodo: from && to ? `${from} → ${to}` : periodo,
          ordini_totali: ordini_validi,
          ordini_con_errori_count: ordini_con_errori.length,
          ordini_con_errori,
          lordo_iva_inclusa,
          iva_totale,
          costi_totali,
          costi_merce_totali,
          costi_fees_totali,
          margine_netto,
          margine_percentuale,
          // Sezione resi
          resi: {
            totale_count: resi_count,
            totali_count: resi_full_count,
            parziali_count: resi_partial_count,
            articoli_resi_qty: resi_articoli_qty,
            importo_totale_eur: resi_totale_eur,
            percentuale_su_lordo: lordo_iva_inclusa > 0 ? (resi_totale_eur / (lordo_iva_inclusa + resi_totale_eur) * 100) : 0,
            dettaglio: ordini_con_resi.slice(0, 100)
          },
          breakdown_marketplace,
          ordini_valuta_estera,
          fetch_stats: fetchStats,
          ultima_sincronizzazione: new Date().toISOString()
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    if (req.method === 'GET' && path === '/api/setup-webhooks') {
      try { return res.json({ success: true, ntfy: !!NTFY_TOPIC, email: !!(RESEND_API_KEY && DUO_NOTIFY_EMAIL), webhook: await assicuraWebhookOrdini() }); }
      catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }
    if (req.method === 'GET' && path === '/api/test-notifica-duo') {
      try {
        const token = await getShopifyAccessToken();
        const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&limit=100&order=created_at+desc`, { headers: { 'X-Shopify-Access-Token': token } });
        const j = await r.json();
        const o = (j.orders || [])[0];
        if (!o) return res.json({ success: false, error: 'Nessun ordine trovato' });
        const m = await margineOrdineSingolo(o);
        return res.json({ success: true, prova: true, ...(await inviaNotificaDuo(o, m)) });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    if (req.method === 'GET' && path === '/api/ricerche-miinto') {
      try {
        if (CACHE_RICERCHE && CACHE_RICERCHE.v === 3 && Date.now() - CACHE_RICERCHE.t < 3600000 && query.get('refresh') !== '1') return res.json(CACHE_RICERCHE.d);
        const brands = [...new Set(MIINTO_SS27.brand.map(b => b.brand))];
        // Prodotti attivi su Shopify per brand
        const attivi = {};
        for (let i = 0; i < brands.length; i += 25) {
          const chunk = brands.slice(i, i + 25);
          const q = '{ ' + chunk.map((b, k) => 'b' + k + ': productsCount(query: ' + JSON.stringify("status:active AND vendor:'" + b.replace(/'/g, "\\'") + "'") + ') { count }').join(' ') + ' }';
          try { const d = await shopifyGraphQL(q); chunk.forEach((b, k) => { attivi[normBrand(b)] = d['b' + k] ? d['b' + k].count : 0; }); } catch (e) { console.log('[ricerche] count errore', e.message); }
        }
        // Vendite TLuxy ultimi 180 giorni per brand
        const oggi = new Date(); const da = new Date(oggi.getTime() - 180 * 86400000);
        const ymdS = d => d.toISOString().slice(0, 10);
        const ordini = await getShopifyOrders('custom', ymdS(da), ymdS(oggi));
        const vend = {}, modTL = {};
        ordini.forEach(o => { if (o.cancelled_at) return; const cur = o.currency || SHOP_CURRENCY; const mp = riconosciMarketplace(o).key; (o.line_items || []).forEach(li => { const k = normBrand(li.vendor); if (!k) return; const q = parseInt(li.quantity) || 0; if (!vend[k]) vend[k] = { pezzi: 0, fatturato: 0, sito: 0 }; const eur = toEurAmount(li.price_set, li.price, cur) * q; vend[k].pezzi += q; vend[k].fatturato += eur; if (mp === 'TLUXY_SITE') vend[k].sito += eur;
          const t = String(li.title || '').trim(); const col = String(li.variant_title || '').split(' / ')[0].trim(); const kk = t + '|' + col; if (!modTL[k]) modTL[k] = {}; if (!modTL[k][kk]) modTL[k][kk] = { titolo: t, colore: col, variant_id: li.variant_id, pezzi: 0, fatturato: 0 }; modTL[k][kk].pezzi += q; modTL[k][kk].fatturato += eur; }); });
        // Foto: modelli TLuxy (variante venduta) + modelli Miinto cercati nel nostro catalogo
        const topPerBrand = {};
        Object.keys(modTL).forEach(k => { topPerBrand[k] = Object.values(modTL[k]).sort((x, y) => y.fatturato - x.fatturato).slice(0, 2); });
        const vidsFoto = [];
        MIINTO_SS27.brand.forEach(b => (topPerBrand[normBrand(b.brand)] || []).forEach(m => { if (m.variant_id && !MEM_VARIANT_IMG.has(String(m.variant_id))) vidsFoto.push(m.variant_id); }));
        if (vidsFoto.length) await infoVariantiGraphQL(vidsFoto);
        const ricMiinto = [];
        MIINTO_SS27.brand.forEach(b => (b.modelli || []).slice(0, 2).forEach(m => {
          const kw = m.split(' · ')[0].replace(/\(.*?\)/g, '').replace(/\b(nero|nera|bianca|bianco|beige|marrone|blu|in pelle)\b/gi, '').replace(/[\/]/g, ' ').replace(/\s+/g, ' ').trim();
          if (kw) ricMiinto.push({ key: b.brand + '|' + m, q: 'vendor:"' + b.brand.replace(/"/g, '') + '" ' + kw.replace(/"/g, '') });
        }));
        const fotoMiinto = {};
        for (let i = 0; i < ricMiinto.length; i += 20) {
          const chunk = ricMiinto.slice(i, i + 20);
          const gq = '{ ' + chunk.map((r, j) => 'm' + j + ': products(first: 1, sortKey: RELEVANCE, query: ' + JSON.stringify(r.q) + ') { nodes { featuredImage { url } } }').join(' ') + ' }';
          try { const d = await shopifyGraphQL(gq); chunk.forEach((r, j) => { const n = d['m' + j] && d['m' + j].nodes && d['m' + j].nodes[0]; if (n && n.featuredImage) fotoMiinto[r.key] = n.featuredImage.url; }); } catch (e) { console.log('[ricerche] foto errore', e.message); }
        }
        const righe = MIINTO_SS27.brand.map(b => {
          const k = normBrand(b.brand), v = vend[k] || { pezzi: 0, fatturato: 0, sito: 0 }, a = attivi[k] || 0;
          let segnale = 'neutro';
          if (b.yoy !== null && b.yoy < 0) segnale = a > 30 ? 'attenzione' : 'in calo';
          else if (b.yoy !== null && b.yoy >= 40) segnale = (a < 10 && v.pezzi < 5) ? 'opportunita' : 'rafforza';
          else if (v.pezzi >= 5) segnale = 'tieni';
          const tluxy_top = (topPerBrand[k] || []).map(x => ({ titolo: x.titolo, colore: x.colore, pezzi: x.pezzi, fatturato: Math.round(x.fatturato), foto: x.variant_id ? (MEM_VARIANT_IMG.get(String(x.variant_id)) || null) : null }));
          const modelli_foto = (b.modelli || []).slice(0, 2).map(m => fotoMiinto[b.brand + '|' + m] || null);
          return { ...b, tluxy_top, modelli_foto, tluxy_attivi: a, tluxy_pezzi_180g: v.pezzi, tluxy_fatturato_180g: Math.round(v.fatturato), tluxy_sito_180g: Math.round(v.sito), segnale };
        });
        const out = { success: true, generato_il: new Date().toISOString(), ordini_analizzati: ordini.length, fonte: MIINTO_SS27.fonte, sintesi: MIINTO_SS27.sintesi, brand: righe, borse_forme: MIINTO_SS27.borse_forme, modelli_top: MIINTO_SS27.modelli_top, emergenti: MIINTO_SS27.emergenti };
        CACHE_RICERCHE = { v: 3, t: Date.now(), d: out };
        return res.json(out);
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    if (req.method === 'GET' && path === '/api/bestsellers') {
      const periodo = query.get('periodo') || 'month';
      const from = query.get('from'); const to = query.get('to');
      try {
        let ordini = await getShopifyOrders(periodo, from, to);
        ordini = await processOrders(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => { 
          if (item.variant_id) variantIds.add(item.variant_id);
          if (item.product_id) productIds.add(item.product_id);
        }));
        const variantCosts = (await fetchVariantCosts([...variantIds], [...productIds])).costs;
        await caricaPrezziMarkFoy(ordini);
        const bs = calcolaBestSellersModelli(ordini, variantCosts);
        const senzaImg = bs.modelli.filter(m => m.variant_id && !MEM_VARIANT_IMG.has(String(m.variant_id))).map(m => m.variant_id);
        if (senzaImg.length) await infoVariantiGraphQL(senzaImg);
        bs.modelli.forEach(m => { m.immagine = m.variant_id ? (MEM_VARIANT_IMG.get(String(m.variant_id)) || null) : null; });
        return res.json({ success: true, versione: 2, periodo: from && to ? `${from} → ${to}` : periodo, ...bs });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    if (req.method === 'GET' && path === '/api/debug-costs') {
      try {
        const periodo = query.get('periodo') || 'yesterday';
        const ordini = await getShopifyOrders(periodo);
        const processati = await processOrders(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        processati.forEach(o => (o.line_items || []).forEach(item => { 
          if (item.variant_id) variantIds.add(item.variant_id);
          if (item.product_id) productIds.add(item.product_id);
        }));
        const fetchResult = await fetchVariantCosts([...variantIds], [...productIds]);
        const variantCosts = fetchResult.costs;
        // Costi DUO manuali
        const duoUserCosts = {};
        if (KV_ENABLED) {
          const duoSkuVariantIds = [];
          processati.forEach(o => (o.line_items || []).forEach(item => {
            if (item.variant_id && isDuoSku(item.sku)) duoSkuVariantIds.push(item.variant_id);
          }));
          const uniqueDuoVids = [...new Set(duoSkuVariantIds)];
          if (uniqueDuoVids.length > 0) {
            const duoKeys = uniqueDuoVids.map(v => `duo_user_cost_${v}`);
            const duoResults = await kvMGet(duoKeys);
            uniqueDuoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              if (duoResults[key] !== undefined) {
                const parsed = parseFloat(duoResults[key]);
                if (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        const debug = processati.map(o => {
          const { costo, errori } = calcolaCostoOrdine(o, variantCosts, duoUserCosts);
          return {
            order_number: o.order_number, name: o.name, created_at: o.created_at,
            total_price: o.total_price, country: o.shipping_address?.country_code || o.billing_address?.country_code,
            marketplace: riconosciMarketplace(o).config.nome, costo_merce_reale: costo.toFixed(2),
            line_items: (o.line_items || []).map(item => {
              let cost_per_unit = 'MANCANTE';
              let cost_source = null;
              if (item.variant_id && variantCosts[item.variant_id] !== null && variantCosts[item.variant_id] !== undefined) {
                cost_per_unit = variantCosts[item.variant_id]; cost_source = 'shopify';
              } else if (isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) {
                cost_per_unit = duoUserCosts[item.variant_id]; cost_source = 'duo_manual';
              }
              return { title: item.title, sku: item.sku, variant_id: item.variant_id, quantity: item.quantity, price: item.price, cost_per_unit, cost_source };
            }),
            errori
          };
        });
        return res.json({ success: true, periodo, fetch_stats: fetchResult.stats, kv_enabled: KV_ENABLED, duo_costs_loaded: Object.keys(duoUserCosts).length, ordini: debug });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    if (req.method === 'GET' && path === '/api/debug-orders') {
      try {
        const ordini = await getShopifyOrders('month');
        const debug = ordini.slice(0, 50).map(o => {
          const country = o.shipping_address?.country_code || o.billing_address?.country_code;
          return { order_number: o.order_number, name: o.name, created_at: o.created_at, source_name: o.source_name, email: o.email, tags: o.tags, total_price: o.total_price, total_tax_shopify: o.total_tax, country, iva_paese: getIvaPerPaese(country) + '%', marketplace: riconosciMarketplace(o).config.nome, num_line_items: (o.line_items || []).length };
        });
        return res.json({ success: true, ordini_totali: ordini.length, primi_50: debug });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    if (req.method === 'GET' && path === '/api/debug-jd') {
      try {
        const periodo = query.get('periodo') || 'month';
        const ordini = await getShopifyOrders(periodo);
        const jdOrders = ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE');
        const productIds = new Set();
        jdOrders.forEach(o => (o.line_items || []).forEach(item => { if (item.product_id) productIds.add(item.product_id); }));
        const tagsCache = await fetchProductsTags([...productIds]);
        const breakdown = jdOrders.map(o => ({ order_number: o.order_number, source_name: o.source_name, total_price: o.total_price, country: o.shipping_address?.country_code || o.billing_address?.country_code, line_items: (o.line_items || []).map(item => ({ product_id: item.product_id, title: item.title, sku: item.sku, price: item.price, quantity: item.quantity, product_tags: tagsCache[item.product_id] || '', ha_tag_JD: hasJDTag(tagsCache[item.product_id]) })) }));
        const inclusi = breakdown.filter(o => o.line_items.some(i => i.ha_tag_JD)).length;
        return res.json({ success: true, periodo, totale_ordini_jammy_dude: jdOrders.length, ordini_inclusi_dopo_filtro: inclusi, ordini_esclusi_dopo_filtro: breakdown.length - inclusi, dettaglio_ordini: breakdown });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // DIAGNOSTIC: traccia chiamate Shopify per singolo variant_id
    // ============ SIMULATORE DUO ============
    // Lista tutti i prodotti DUO attivi (SKU che inizia con DUO-) con info utili per simulazione
    if (req.method === 'GET' && path === '/api/duo-products') {
      try {
        const token = await getShopifyAccessToken();
        const products = [];
        // NB: aggiungiamo inventory_item_id per poter recuperare i cost in batch dopo
        let url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&status=active&fields=id,title,variants`;
        let pageCount = 0;
        const maxPages = 30;
        while (url && pageCount < maxPages) {
          const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          if (!response.ok) break;
          const data = await response.json();
          (data.products || []).forEach(p => {
            (p.variants || []).forEach(v => {
              if (isDuoSku(v.sku)) {
                products.push({
                  product_id: p.id,
                  variant_id: v.id,
                  inventory_item_id: v.inventory_item_id, // serve per fetch cost batch
                  title: p.title,
                  variant_title: v.title,
                  sku: v.sku,
                  prezzo_listino: parseFloat(v.price) || 0,
                  compare_at_price: parseFloat(v.compare_at_price) || 0,
                  inventory_quantity: v.inventory_quantity || 0
                });
              }
            });
          });
          const linkHeader = response.headers.get('link') || response.headers.get('Link');
          url = null;
          if (linkHeader) { const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/); if (nextMatch) url = nextMatch[1]; }
          pageCount++;
        }
        
        // ============ FETCH COSTI DA SHOPIFY IN BATCH ============
        // Shopify espone il cost via /inventory_items.json?ids=1,2,3 (max 100 per chiamata)
        const inventoryItemIds = products.map(p => p.inventory_item_id).filter(Boolean);
        const costsByItemId = {};
        const BATCH_SIZE = 100;
        for (let i = 0; i < inventoryItemIds.length; i += BATCH_SIZE) {
          const batch = inventoryItemIds.slice(i, i + BATCH_SIZE);
          const batchUrl = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${batch.join(',')}&limit=${BATCH_SIZE}`;
          try {
            const r = await fetch(batchUrl, { headers: { 'X-Shopify-Access-Token': token } });
            if (!r.ok) continue;
            const data = await r.json();
            (data.inventory_items || []).forEach(item => {
              const c = parseFloat(item.cost);
              if (!isNaN(c)) costsByItemId[item.id] = c;
            });
          } catch (e) { /* continua con batch successivo */ }
        }
        
        // Applica cost Shopify a ciascun prodotto (senza KV, come richiesto)
        const enriched = products.map(p => ({
          product_id: p.product_id,
          variant_id: p.variant_id,
          title: p.title,
          variant_title: p.variant_title,
          sku: p.sku,
          prezzo_listino: p.prezzo_listino,
          compare_at_price: p.compare_at_price,
          inventory_quantity: p.inventory_quantity,
          costo_fornitore: costsByItemId[p.inventory_item_id] !== undefined ? costsByItemId[p.inventory_item_id] : null,
          costo_source: costsByItemId[p.inventory_item_id] !== undefined ? 'shopify' : 'missing'
        }));
        
        // Ordina: prima quelli con costo, poi per titolo
        enriched.sort((a, b) => {
          if ((a.costo_fornitore !== null) !== (b.costo_fornitore !== null)) return a.costo_fornitore !== null ? -1 : 1;
          return a.title.localeCompare(b.title);
        });
        
        const withCost = enriched.filter(p => p.costo_fornitore !== null).length;
        return res.json({
          success: true,
          totale: enriched.length,
          con_costo_shopify: withCost,
          senza_costo: enriched.length - withCost,
          prodotti: enriched
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Import costi DUO da CSV (payload JSON: {costs: {variant_id: cost}})
    if (req.method === 'POST' && path === '/api/duo-costs-import') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV storage non configurato. Abilita Vercel KV.' });
      try {
        let body = '';
        await new Promise((resolve, reject) => {
          req.on('data', chunk => body += chunk);
          req.on('end', resolve);
          req.on('error', reject);
        });
        const data = JSON.parse(body);
        const costs = data.costs || {};
        const pairs = {};
        let count = 0;
        Object.entries(costs).forEach(([vid, cost]) => {
          const parsed = parseFloat(cost);
          if (vid && !isNaN(parsed) && parsed >= 0) {
            pairs[`duo_user_cost_${vid}`] = String(parsed);
            count++;
          }
        });
        if (count === 0) return res.json({ success: false, error: 'Nessun costo valido nel CSV' });
        await kvMSet(pairs);
        return res.json({ success: true, salvati: count });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Save singolo costo DUO (per editing inline dal browser)
    if (req.method === 'POST' && path === '/api/duo-cost-set') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV storage non configurato' });
      try {
        let body = '';
        await new Promise((resolve, reject) => {
          req.on('data', chunk => body += chunk);
          req.on('end', resolve);
          req.on('error', reject);
        });
        const data = JSON.parse(body);
        const vid = data.variant_id;
        const cost = parseFloat(data.cost);
        if (!vid || isNaN(cost) || cost < 0) return res.json({ success: false, error: 'Dati invalidi' });
        await kvSet(`duo_user_cost_${vid}`, String(cost));
        return res.json({ success: true });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Health check KV
    // Debug Winkelstraat: mostra ordini riconosciuti come WINKELSTRAAT e il motivo
    // ============ FORECAST INCASSI ============
    // Calcola pagamenti previsti per il mese corrente + mese prossimo (default)
    // Cache KV 24h come /api/inventory-discovery. ?refresh=1 per forzare ricalcolo
    if (req.method === 'GET' && path === '/api/duo-alerts') {
      try {
        if (!KV_ENABLED) return res.json({ success: false, error: 'KV non configurato' });
        const refresh = query.get('refresh') === '1';
        const CACHE = 'duo_alerts_cache', OPKEY = 'duo_alerts_bulk_id';
        if (!refresh) {
          const c = await kvGet(CACHE);
          if (c) { const obj = JSON.parse(c); if (Date.now() - new Date(obj.generato_il).getTime() < 12 * 3600 * 1000) return res.json({ success: true, status: 'ready', cached: true, ...obj }); }
        }
        const mioOp = await kvGet(OPKEY);
        const d = await shopifyGraphQL('{ currentBulkOperation { id status url errorCode objectCount } }');
        const cur = d.currentBulkOperation;
        if (mioOp && cur && cur.id === mioOp) {
          if (cur.status === 'RUNNING' || cur.status === 'CREATED') return res.json({ success: true, status: 'running', oggetti: cur.objectCount });
          if (cur.status === 'COMPLETED') {
            const giorno = getRomeDateString();
            const testo = cur.url ? await (await fetch(cur.url)).text() : '';
            const risultato = analizzaCatalogoDuo(testo, giorno);
            ['sito_negativi', 'sito_extra_sconto_negativi', 'miinto_sotto_soglia', 'miinto_prezzo_fuori_regola'].forEach(k => { risultato[k + '_count'] = risultato[k].length; });
            await kvSetBody(CACHE, JSON.stringify(risultato));
            await kvDel(OPKEY);
            return res.json({ success: true, status: 'ready', cached: false, ...risultato });
          }
          await kvDel(OPKEY);
          return res.json({ success: false, status: 'error', error: 'Bulk operation ' + cur.status + (cur.errorCode ? ' ' + cur.errorCode : '') });
        }
        if (cur && (cur.status === 'RUNNING' || cur.status === 'CREATED')) return res.json({ success: true, status: 'busy', messaggio: 'Shopify sta già eseguendo un altro export, riprovo tra poco' });
        const st = await shopifyGraphQL('mutation($q: String!) { bulkOperationRunQuery(query: $q) { bulkOperation { id status } userErrors { field message } } }', { q: DUO_BULK_QUERY });
        const errs = st.bulkOperationRunQuery.userErrors || [];
        if (errs.length) return res.json({ success: false, status: 'error', error: errs.map(e => e.message).join('; ') });
        await kvSetEx(OPKEY, 3600, st.bulkOperationRunQuery.bulkOperation.id);
        return res.json({ success: true, status: 'running' });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    if (req.method === 'GET' && path === '/api/alerts') {
      try {
        const refresh = query.get('refresh') === '1';
        const cacheKey = 'pannello_canali_v526';
        if (!refresh && KV_ENABLED) {
          try { const c = await kvGet(cacheKey); if (c) { const obj = JSON.parse(c); if (Date.now() - new Date(obj.generato_il).getTime() < 15 * 60000) return res.json({ success: true, cached: true, ...obj }); } } catch (e) {}
        }
        const oggi = getRomeDateString();
        const da = getRomeDateString(new Date(Date.now() - 100 * 86400000));
        let ordini = await getShopifyOrders('custom', da, oggi);
        ordini = await processOrders(ordini);
        const risultato = calcolaPannelloCanali(ordini);
        if (KV_ENABLED) { try { await kvSetBody(cacheKey, JSON.stringify(risultato)); } catch (e) {} }
        return res.json({ success: true, cached: false, ...risultato });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    if (req.method === 'GET' && path === '/api/forecast') {
      try {
        const forceRefresh = query.get('refresh') === '1';
        const FORECAST_CACHE_KEY = 'forecast_cache_v529';
        const FORECAST_META_KEY = 'forecast_cache_meta_v529';
        const FORECAST_TTL_HOURS = 24;
        
        // 1) Prova cache KV (se non force refresh)
        if (!forceRefresh && KV_ENABLED) {
          try {
            const meta = await kvGet(FORECAST_META_KEY);
            if (meta) {
              const metaObj = JSON.parse(meta);
              const ageMs = Date.now() - (metaObj.generated_at || 0);
              const ageHours = ageMs / (1000 * 60 * 60);
              if (ageHours < FORECAST_TTL_HOURS) {
                const cached = await kvGet(FORECAST_CACHE_KEY);
                if (cached) {
                  const cachedObj = JSON.parse(cached);
                  // RICALCOLA SOLO il Balardi wallet (rapido, legge solo le ricariche da KV)
                  // per averlo sempre aggiornato anche se si aggiunge una ricarica oggi
                  try {
                    const rawRic = await kvGet('balardi_wallet_ricariche');
                    if (rawRic) {
                      const ricariche = JSON.parse(rawRic);
                      const totRicaricato = (ricariche || []).reduce((s, r) => s + parseFloat(r.importo || 0), 0);
                      cachedObj.balardi_wallet = cachedObj.balardi_wallet || { consumo_periodo: { importo_eur: 0 } };
                      cachedObj.balardi_wallet.credito_ricaricato = totRicaricato;
                      cachedObj.balardi_wallet.credito_residuo = totRicaricato - (cachedObj.balardi_wallet.credito_consumato || 0);
                      cachedObj.balardi_wallet.ricariche = ricariche;
                    }
                  } catch(e) { /* ignore */ }
                  cachedObj.from_cache = true;
                  cachedObj.cache_age_hours = Math.round(ageHours * 10) / 10;
                  cachedObj.cache_generated_at = new Date(metaObj.generated_at).toISOString();
                  cachedObj.cache_expires_in_hours = Math.round((FORECAST_TTL_HOURS - ageHours) * 10) / 10;
                  return res.json(cachedObj);
                }
              }
            }
          } catch (e) { /* ignore cache errors, fetch fresh */ }
        }
        
        // Periodo di LOOKUP ordini: ultimi 120 giorni (per coprire pagamenti futuri dei MP mensili)
        const daysBack = parseInt(query.get('days_back') || '120', 10);
        const monthsAhead = parseInt(query.get('months_ahead') || '2', 10);
        const dateTo = new Date();
        const dateFrom = new Date();
        dateFrom.setDate(dateFrom.getDate() - daysBack);
        
        // Fetch ordini custom range
        let ordini = await getShopifyOrders(null, fmtDateISO(dateFrom), fmtDateISO(dateTo));
        ordini = await processOrders(ordini);
        
        // Fetch costi (per calcolare netto incassato)
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => { 
          if (item.variant_id) variantIds.add(item.variant_id);
          if (item.product_id) productIds.add(item.product_id);
        }));
        const { costs: variantCosts } = await fetchVariantCosts([...variantIds], [...productIds]);
        await caricaPrezziMarkFoy(ordini);
        
        // Carica costi DUO user
        const duoUserCosts = {};
        if (KV_ENABLED) {
          const duoVids = [];
          ordini.forEach(o => (o.line_items || []).forEach(item => {
            if (item.variant_id && isDuoSku(item.sku)) duoVids.push(item.variant_id);
          }));
          const uniq = [...new Set(duoVids)];
          if (uniq.length > 0) {
            const keys = uniq.map(v => `duo_user_cost_${v}`);
            const results = await kvMGet(keys);
            uniq.forEach(v => {
              const key = `duo_user_cost_${v}`;
              if (results[key] !== undefined) {
                const parsed = parseFloat(results[key]);
                if (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        
        // Calcola forecast per ogni ordine
        const paymentsByDate = {}; // YYYY-MM-DD → array pagamenti
        const paymentsByMP = {};   // MP_KEY → aggregato
        const paymentsByMonth = {}; // YYYY-MM → aggregato
        const balardiConsumo = { count: 0, importo_eur: 0, ordini: [] };
        let ordiniForecast = 0;
        let ordiniSkipped = 0;
        
        ordini.forEach(ordine => {
          const mp = riconosciMarketplace(ordine);
          const policy = mp.config.payment_policy;
          if (!policy) { ordiniSkipped++; return; }
          
          const refundInfo = getOrderRefundInfo(ordine);
          if (refundInfo.isFullRefund) { ordiniSkipped++; return; } // no forecast su resi totali
          
          const currencyInfo = getOrderCurrencyInfo(ordine);
          const prezzoLordoOriginale = currencyInfo.eurTotal;
          const prezzoLordo = Math.max(0, prezzoLordoOriginale - refundInfo.totalRefundedEur);
          
          // Calcola costo merce (fallback cost DUO)
          const { costo: costoMerce } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
          let costoMerceEffettivo = costoMerce;
          if (refundInfo.isPartialRefund && refundInfo.totalQuantity > 0) {
            const ratio = refundInfo.refundedQuantity / refundInfo.totalQuantity;
            costoMerceEffettivo = costoMerce * (1 - ratio);
          }
          
          // Spedizione EUR
          const spedizione = (ordine.shipping_lines || []).reduce((s, line) => s + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency), 0);
          
          // Calcola netto per il venditore (prezzo_netto - fees - sped - packaging, MA netto merce rimane)
          // Il "netto da incassare dal MP" = prezzo_lordo - sconto - fee_mp - fee_accessoria (NON include costo merce: quello è tuo)
          const cfg = mp.config;
          const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
          const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(country);
          const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100);
          const prezzoDopoSconto = prezzoNettoIva * (1 - (cfg.sconto_percentuale || 0) / 100);
          const feesMP = prezzoDopoSconto * ((cfg.fee_principale || 0) / 100)
                       + prezzoDopoSconto * ((cfg.fee_secondaria || 0) / 100)
                       + prezzoDopoSconto * ((cfg.fee_accessoria || 0) / 100);
          const nettoFromMP = mp.key === 'MARK_FOYS' ? calcolaMarkFoyOrdine(ordine, variantCosts, duoUserCosts).incasso : Math.max(0, prezzoDopoSconto - feesMP - (cfg.fee_fissa_trasporto === 'GLS' ? 15 : (cfg.fee_fissa_trasporto || 0)) - (cfg.fee_fissa_packaging || 0));
          
          const pagamenti = calcolaPagamentiPrevisti(ordine.created_at, policy, nettoFromMP);
          if (pagamenti.length === 0) { ordiniSkipped++; return; }
          ordiniForecast++;
          
          // Se è Balardi, traccia come consumo wallet (non genera incasso)
          if (policy.type === 'prepaid_balance') {
            balardiConsumo.count++;
            balardiConsumo.importo_eur += nettoFromMP;
            balardiConsumo.ordini.push({
              order_number: ordine.order_number,
              name: ordine.name,
              created_at: ordine.created_at,
              importo_consumato: nettoFromMP,
              prezzo_lordo: prezzoLordo
            });
            return;
          }
          
          pagamenti.forEach(pg => {
            const dateKey = fmtDateISO(pg.data);
            const monthKey = fmtMonthKey(pg.data);
            if (!paymentsByDate[dateKey]) paymentsByDate[dateKey] = [];
            paymentsByDate[dateKey].push({
              order_number: ordine.order_number,
              name: ordine.name,
              created_at: ordine.created_at,
              marketplace: mp.config.nome,
              mp_key: mp.key,
              importo_eur: pg.importo_eur,
              nota: pg.nota,
              parte: pg.parte
            });
            if (!paymentsByMP[mp.key]) paymentsByMP[mp.key] = { nome: mp.config.nome, pagamento_desc: mp.config.pagamento, ordini: 0, importo_totale: 0, prossimo_bonifico: null, pagamenti: [] };
            paymentsByMP[mp.key].ordini++;
            paymentsByMP[mp.key].importo_totale += pg.importo_eur;
            paymentsByMP[mp.key].pagamenti.push({ data: dateKey, order_number: ordine.order_number, importo_eur: pg.importo_eur, nota: pg.nota });
            if (!paymentsByMonth[monthKey]) paymentsByMonth[monthKey] = { mese: monthKey, importo_totale: 0, ordini_count: 0, per_mp: {} };
            paymentsByMonth[monthKey].importo_totale += pg.importo_eur;
            paymentsByMonth[monthKey].ordini_count++;
            if (!paymentsByMonth[monthKey].per_mp[mp.key]) paymentsByMonth[monthKey].per_mp[mp.key] = { nome: mp.config.nome, importo: 0, count: 0 };
            paymentsByMonth[monthKey].per_mp[mp.key].importo += pg.importo_eur;
            paymentsByMonth[monthKey].per_mp[mp.key].count++;
          });
        });
        
        // Determina prossimo bonifico per ogni MP (data minima >= oggi)
        const todayStr = fmtDateISO(new Date());
        Object.keys(paymentsByMP).forEach(k => {
          const futuri = paymentsByMP[k].pagamenti.filter(p => p.data >= todayStr).sort((a, b) => a.data.localeCompare(b.data));
          paymentsByMP[k].prossimo_bonifico = futuri.length > 0 ? { data: futuri[0].data, importo_parziale: futuri.filter(f => f.data === futuri[0].data).reduce((s, f) => s + f.importo_eur, 0) } : null;
        });
        
        // Mesi correnti e futuri
        const oggi = new Date();
        const meseCorrente = fmtMonthKey(oggi);
        const meseProssimo = fmtMonthKey(new Date(oggi.getFullYear(), oggi.getMonth() + 1, 1));
        const mesiSecondoProssimo = fmtMonthKey(new Date(oggi.getFullYear(), oggi.getMonth() + 2, 1));
        
        const incassoMeseCorrente = paymentsByMonth[meseCorrente] || { importo_totale: 0, ordini_count: 0 };
        const incassoMeseProssimo = paymentsByMonth[meseProssimo] || { importo_totale: 0, ordini_count: 0 };
        const incassoMeseSecondoProssimo = paymentsByMonth[mesiSecondoProssimo] || { importo_totale: 0, ordini_count: 0 };
        
        // Pending totale (da oggi in avanti)
        let pendingTotale = 0, pendingCount = 0;
        Object.entries(paymentsByDate).forEach(([date, arr]) => {
          if (date >= todayStr) { arr.forEach(p => { pendingTotale += p.importo_eur; pendingCount++; }); }
        });
        
        // Balardi wallet: leggi ricariche da KV
        let balardiWallet = { credito_ricaricato: 0, credito_consumato: balardiConsumo.importo_eur, credito_residuo: -balardiConsumo.importo_eur, ricariche: [], consumo_periodo: balardiConsumo };
        if (KV_ENABLED) {
          try {
            const raw = await kvGet('balardi_wallet_ricariche');
            if (raw) {
              const ricariche = JSON.parse(raw);
              const totRicaricato = (ricariche || []).reduce((s, r) => s + parseFloat(r.importo || 0), 0);
              balardiWallet.credito_ricaricato = totRicaricato;
              balardiWallet.credito_residuo = totRicaricato - balardiConsumo.importo_eur;
              balardiWallet.ricariche = ricariche;
            }
          } catch (e) {}
        }
        
        // Ordina breakdown MP per prossimo bonifico
        const breakdownMP = Object.values(paymentsByMP).sort((a, b) => {
          if (!a.prossimo_bonifico) return 1;
          if (!b.prossimo_bonifico) return -1;
          return a.prossimo_bonifico.data.localeCompare(b.prossimo_bonifico.data);
        });
        
        const forecastResult = {
          success: true,
          periodo_analisi: { from: fmtDateISO(dateFrom), to: fmtDateISO(dateTo), days_back: daysBack },
          ordini_analizzati: ordini.length,
          ordini_con_forecast: ordiniForecast,
          ordini_skipped: ordiniSkipped,
          kpi: {
            incasso_mese_corrente: { mese: meseCorrente, importo: incassoMeseCorrente.importo_totale, ordini: incassoMeseCorrente.ordini_count },
            incasso_mese_prossimo: { mese: meseProssimo, importo: incassoMeseProssimo.importo_totale, ordini: incassoMeseProssimo.ordini_count },
            incasso_mese_dopo: { mese: mesiSecondoProssimo, importo: incassoMeseSecondoProssimo.importo_totale, ordini: incassoMeseSecondoProssimo.ordini_count },
            pending_totale: pendingTotale,
            pending_count: pendingCount
          },
          breakdown_marketplace: breakdownMP,
          timeline_mensile: Object.values(paymentsByMonth).sort((a, b) => a.mese.localeCompare(b.mese)),
          balardi_wallet: balardiWallet,
          from_cache: false,
          ultima_sincronizzazione: new Date().toISOString()
        };
        
        // Salva in cache KV (24h)
        if (KV_ENABLED) {
          try {
            await kvSet(FORECAST_CACHE_KEY, JSON.stringify(forecastResult));
            await kvSet(FORECAST_META_KEY, JSON.stringify({ generated_at: Date.now(), ordini_count: ordini.length }));
            forecastResult.cached_to_kv = true;
            forecastResult.cache_valid_for_hours = FORECAST_TTL_HOURS;
          } catch (e) { forecastResult.cache_error = e.message; }
        }
        
        return res.json(forecastResult);
      } catch (error) { return res.status(500).json({ success: false, error: error.message, stack: error.stack }); }
    }
    
    // Balardi wallet: aggiungi ricarica
    if (req.method === 'POST' && path === '/api/balardi-ricarica') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurato' });
      try {
        let body = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const importo = parseFloat(data.importo);
        const nota = (data.nota || '').substring(0, 200);
        const data_ricarica = data.data_ricarica || fmtDateISO(new Date());
        if (isNaN(importo) || importo <= 0) return res.status(400).json({ success: false, error: 'Importo non valido' });
        const raw = await kvGet('balardi_wallet_ricariche');
        const ricariche = raw ? JSON.parse(raw) : [];
        ricariche.push({ id: Date.now(), data_ricarica, importo, nota, creato: new Date().toISOString() });
        await kvSet('balardi_wallet_ricariche', JSON.stringify(ricariche));
        return res.json({ success: true, ricariche });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }
    
    // Balardi wallet: rimuovi ricarica
    if (req.method === 'POST' && path === '/api/balardi-ricarica-delete') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurato' });
      try {
        let body = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const id = parseInt(data.id);
        if (isNaN(id)) return res.status(400).json({ success: false, error: 'ID non valido' });
        const raw = await kvGet('balardi_wallet_ricariche');
        const ricariche = raw ? JSON.parse(raw) : [];
        const filtered = ricariche.filter(r => r.id !== id);
        await kvSet('balardi_wallet_ricariche', JSON.stringify(filtered));
        return res.json({ success: true, ricariche: filtered });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    // ============ INVENTORY DISCOVERY (temporaneo per v5.9) ============
    // Analizza i prodotti Shopify per capire come sono classificati product_type + tags
    // INVENTORY DISCOVERY: analizza TUTTO il catalogo con paginazione cursor + cache 24h
    if (req.method === 'GET' && path === '/api/inventory-discovery') {
      try {
        const forceRefresh = query.get('refresh') === '1';
        const cacheKey = 'inventory_discovery_cache_v1';
        const CACHE_TTL_SEC = 24 * 60 * 60; // 24 ore
        
        // Prova cache prima (se KV disponibile e non forced)
        if (!forceRefresh && KV_ENABLED) {
          try {
            const cached = await kvGet(cacheKey);
            if (cached) {
              const data = JSON.parse(cached);
              const ageMin = Math.floor((Date.now() - new Date(data.generated_at).getTime()) / 60000);
              data.dalla_cache = true;
              data.cache_age_minutes = ageMin;
              data.cache_age_human = ageMin < 60 ? `${ageMin} minuti fa` : `${Math.floor(ageMin / 60)} ore fa`;
              return res.json(data);
            }
          } catch (e) { /* procedi col fetch */ }
        }
        
        // Fetch completo con paginazione cursor-based
        const token = await getShopifyAccessToken();
        const fields = 'id,title,handle,product_type,vendor,tags,status,published_at,variants';
        let allProducts = [];
        let pageInfo = null;
        let pagesDone = 0;
        const MAX_PAGES = 60; // safety: 60 × 250 = 15.000 prodotti
        
        while (pagesDone < MAX_PAGES) {
          let url;
          if (pageInfo) {
            url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&page_info=${encodeURIComponent(pageInfo)}`;
          } else {
            url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?status=active&limit=250&fields=${fields}`;
          }
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } });
          if (!r.ok) {
            const t = await r.text();
            return res.status(500).json({ success: false, error: `Shopify page ${pagesDone + 1} ${r.status}: ${t.substring(0, 200)}`, pages_done: pagesDone, partial_products: allProducts.length });
          }
          const data = await r.json();
          const batch = data.products || [];
          allProducts = allProducts.concat(batch);
          pagesDone++;
          
          // Parse Link header per cursor paginazione
          const linkHeader = r.headers.get('Link') || r.headers.get('link');
          pageInfo = null;
          if (linkHeader) {
            const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
            if (nextMatch) {
              try {
                const nextUrl = new URL(nextMatch[1]);
                pageInfo = nextUrl.searchParams.get('page_info');
              } catch (e) { pageInfo = null; }
            }
          }
          
          if (!pageInfo || batch.length < 250) break;
        }
        
        // Analizza l'intero catalogo
        const productTypes = {};
        const vendors = {};
        const tagsAll = {};
        let prodottiAttivi = 0;
        let prodottiConStock = 0;
        let prodottiZeroStock = 0;
        let totalePezzi = 0;
        let totaleVarianti = 0;
        let duoProdotti = 0;
        let duoPezzi = 0;
        const sampleProducts = [];
        
        allProducts.forEach(p => {
          if (p.status !== 'active') return;
          prodottiAttivi++;
          const pt = (p.product_type || '(vuoto)').trim();
          productTypes[pt] = (productTypes[pt] || 0) + 1;
          const v = (p.vendor || '(vuoto)').trim();
          vendors[v] = (vendors[v] || 0) + 1;
          (p.tags || '').split(',').map(t => t.trim()).filter(t => t).forEach(tag => {
            tagsAll[tag] = (tagsAll[tag] || 0) + 1;
          });
          const variants = p.variants || [];
          const qty = variants.reduce((s, v) => s + Math.max(0, parseInt(v.inventory_quantity) || 0), 0);
          totalePezzi += qty;
          totaleVarianti += variants.length;
          if (qty > 0) prodottiConStock++; else prodottiZeroStock++;
          
          // Detect DUO: tag TLX_PRODUCT:DUO oppure SKU pattern
          const tagsLower = (p.tags || '').toLowerCase();
          const hasDuoTag = tagsLower.includes('tlx_product:duo') || /(^|,)\s*duo(\s*,|$)/.test(tagsLower);
          const firstSku = variants[0] ? (variants[0].sku || '') : '';
          const isDuo = hasDuoTag || (firstSku && isDuoSku(firstSku));
          if (isDuo) { duoProdotti++; duoPezzi += qty; }
          
          if (sampleProducts.length < 10) {
            sampleProducts.push({
              id: p.id, title: (p.title || '').substring(0, 60), handle: p.handle,
              product_type: p.product_type, vendor: p.vendor, tags: p.tags,
              stock: qty, varianti: variants.length,
              prima_variante_sku: firstSku, is_duo: isDuo
            });
          }
        });
        
        const sortByCount = obj => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ valore: k, count: v }));
        
        const result = {
          success: true,
          generated_at: new Date().toISOString(),
          dalla_cache: false,
          cache_age_minutes: 0,
          cache_age_human: 'appena generato',
          ttl_hours: 24,
          pagine_scaricate: pagesDone,
          prodotti_totali_scaricati: allProducts.length,
          prodotti_attivi: prodottiAttivi,
          prodotti_con_stock: prodottiConStock,
          prodotti_zero_stock: prodottiZeroStock,
          totale_varianti: totaleVarianti,
          totale_pezzi: totalePezzi,
          duo_prodotti: duoProdotti,
          duo_pezzi: duoPezzi,
          own_prodotti: prodottiAttivi - duoProdotti,
          own_pezzi: totalePezzi - duoPezzi,
          product_types_distinti: Object.keys(productTypes).length,
          product_types: sortByCount(productTypes),
          vendors_distinti: Object.keys(vendors).length,
          vendors: sortByCount(vendors).slice(0, 50),
          tags_distinti: Object.keys(tagsAll).length,
          tags_top_80: sortByCount(tagsAll).slice(0, 80),
          sample_prodotti: sampleProducts
        };
        
        // Salva in cache 24h
        if (KV_ENABLED) {
          try { 
            await kvSetEx(cacheKey, CACHE_TTL_SEC, JSON.stringify(result)); 
          } catch (e) { /* cache best-effort, continua */ }
        }
        
        return res.json(result);
      } catch (e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }
    
    // Reset cache inventory discovery (per forzare refresh)
    if (req.method === 'POST' && path === '/api/inventory-discovery-reset') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurato' });
      try {
        await kvDel('inventory_discovery_cache_v1');
        return res.json({ success: true, message: 'Cache resettata. Prossima chiamata farà fetch fresco.' });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    // ============ INVENTORY SNAPSHOT ============
    // Snapshot categorizzato (bag/shoes/accessori/clothing × donna/uomo/unisex)
    // Usa la stessa cache discovery (raw products già scaricati)
    if (req.method === 'GET' && path === '/api/inventory') {
      try {
        const forceRefresh = query.get('refresh') === '1';
        const cacheKey = 'inventory_discovery_cache_v1';
        let discoveryData = null;
        
        // Prova a prendere dalla cache discovery (che contiene già i products raw)
        if (!forceRefresh && KV_ENABLED) {
          try {
            const cached = await kvGet(cacheKey);
            if (cached) {
              discoveryData = JSON.parse(cached);
            }
          } catch (e) { /* ignore */ }
        }
        
        // Se niente cache, chiama lo stesso endpoint discovery per popolarla
        // (ma noi abbiamo bisogno di più dati: product_type + tags + stock per ogni prodotto, non solo aggregati)
        // Scarichiamo da zero con gli stessi parametri
        if (!discoveryData || !discoveryData._raw_products) {
          // Full fetch: scarica tutti i prodotti
          const token = await getShopifyAccessToken();
          const allProducts = [];
          let nextPageInfo = null;
          let pagesDone = 0;
          const MAX_PAGES = 60;
          
          while (pagesDone < MAX_PAGES) {
            let url;
            if (nextPageInfo) {
              url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&page_info=${encodeURIComponent(nextPageInfo)}`;
            } else {
              url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?status=active&limit=250&fields=id,title,handle,product_type,vendor,tags,status,variants`;
            }
            const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } });
            if (!r.ok) { const t = await r.text(); return res.status(500).json({ success: false, error: `Shopify ${r.status}: ${t.substring(0, 300)}` }); }
            const data = await r.json();
            const batch = data.products || [];
            allProducts.push(...batch);
            pagesDone++;
            const linkHeader = r.headers.get('link') || r.headers.get('Link') || '';
            const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
            if (nextMatch && batch.length === 250) {
              const piMatch = nextMatch[1].match(/page_info=([^&>]+)/);
              if (piMatch) nextPageInfo = decodeURIComponent(piMatch[1]);
              else break;
            } else break;
          }
          
          discoveryData = { _raw_products: allProducts, pagine_scaricate: pagesDone, generated_at: Date.now() };
          if (KV_ENABLED) {
            try {
              // Salva cache per riuso (24h). Salviamo i raw products per il categorizer
              const cacheable = { ...discoveryData, cached_at: new Date().toISOString() };
              await kvSetEx(cacheKey, 86400, JSON.stringify(cacheable));
            } catch (e) { /* ignore */ }
          }
        }
        
        const products = discoveryData._raw_products || [];
        
        // ============ CATEGORIZER ============
        // Parole chiave per categoria (priorità: più specifica vince)
        // Match case-insensitive su: product_type, tags, title
        const CATEGORIE = {
          bag: { 
            label: 'Bag',
            keywords: ['bag', 'handbag', 'shoulder', 'crossbody', 'tote', 'clutch', 'pochette', 'borsa', 'borse', 'zaino', 'backpack', 'sacca', 'shopper', 'hobo', 'bauletto', 'marsupio', 'belt bag']
          },
          shoes: {
            label: 'Shoes',
            keywords: ['shoe', 'shoes', 'sneaker', 'sneakers', 'boot', 'boots', 'stivale', 'stivali', 'decolleté', 'décolleté', 'sandalo', 'sandali', 'sandal', 'mocassino', 'loafer', 'heel', 'heels', 'tacco', 'ballerina', 'flat', 'scarpa', 'scarpe', 'espadrilla', 'stringata', 'ankle boot', 'slipper']
          },
          accessori: {
            label: 'Accessori',
            keywords: ['accessor', 'cintura', 'cinture', 'belt', 'portafoglio', 'portafogli', 'wallet', 'cappello', 'hat', 'cap', 'occhiali', 'sunglasses', 'eyewear', 'bijoux', 'jewel', 'gioiello', 'collana', 'necklace', 'bracciale', 'bracelet', 'anello', 'ring', 'orecchino', 'earring', 'sciarpa', 'scarf', 'foulard', 'guanti', 'gloves', 'cravatta', 'tie', 'papillon', 'card holder', 'porta carte', 'key', 'chiave']
          },
          clothing: {
            label: 'Clothing',
            keywords: ['jacket', 'giacca', 'coat', 'cappotto', 'parka', 'piumino', 'blazer', 'giubbotto', 'bomber', 'shirt', 'camicia', 't-shirt', 'tshirt', 'polo', 'maglia', 'sweater', 'felpa', 'hoodie', 'sweatshirt', 'maglione', 'cardigan', 'pant', 'pants', 'pantalone', 'pantaloni', 'jeans', 'leggings', 'shorts', 'bermuda', 'skirt', 'gonna', 'dress', 'abito', 'vestito', 'top', 'tank', 'body', 'bodysuit', 'tuta', 'jumpsuit', 'blouse', 'camicetta', 'knit', 'intimo', 'underwear', 'costume', 'swimsuit', 'bikini', 'trench', 'gilet', 'vest', 'pigiama', 'pajama']
          }
        };
        
        // Keyword gender (con regex word-boundary per evitare match errato "man" dentro "woman")
        const KW_WOMAN = ['woman', 'women', 'ladies', 'donna', 'donne', 'female', 'femme', 'mujer', 'femminile'];
        const KW_MAN = ['man', 'men', 'uomo', 'uomini', 'male', 'homme', 'hombre', 'maschile'];
        const KW_UNISEX = ['unisex', 'bambino', 'bambini', 'kid', 'kids', 'child', 'children', 'junior', 'baby'];
        
        function wordMatch(text, kw) {
          // Matcher case-insensitive con word boundary: non matcha "man" dentro "woman"
          const re = new RegExp('(^|[^a-zàèéìòù])' + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^a-zàèéìòù]|$)', 'i');
          return re.test(text);
        }
        
        function detectCategoria(searchText) {
          if (!searchText) return null;
          // Check più specifico per primo (ordine categorie è già dal più specifico)
          for (const [key, cfg] of Object.entries(CATEGORIE)) {
            for (const kw of cfg.keywords) {
              if (wordMatch(searchText, kw)) return key;
            }
          }
          return null;
        }
        
        function detectGender(searchText) {
          if (!searchText) return null;
          // Priorità: woman PRIMA di man (altrimenti "woman bags" matcha "man")
          // Word boundary evita match di substring
          // 1) Woman check (con word boundary)
          const isW = KW_WOMAN.some(kw => wordMatch(searchText, kw));
          if (isW) return 'donna'; // se c'è woman/donna, è donna (anche se appare anche man da qualche parte)
          // 2) Man check
          const isM = KW_MAN.some(kw => wordMatch(searchText, kw));
          if (isM) return 'uomo';
          // 3) Unisex/kids check
          for (const kw of KW_UNISEX) if (wordMatch(searchText, kw)) return 'unisex';
          return null;
        }
        
        function isDuoProduct(product) {
          // DUO: se lo SKU della prima variante matcha il pattern isDuoSku
          const firstVariantSku = (product.variants && product.variants[0]) ? product.variants[0].sku : null;
          if (firstVariantSku && isDuoSku(firstVariantSku)) return true;
          // Oppure se ha un tag DUO esplicito
          const tags = (product.tags || '').toLowerCase();
          if (tags.includes('tlx_product:duo') || tags.includes('duo')) return true;
          return false;
        }
        
        // ============ CLASSIFICAZIONE ============
        const snapshot = {
          tutto: { bag: {}, shoes: {}, accessori: {}, clothing: {} },
          own:   { bag: {}, shoes: {}, accessori: {}, clothing: {} },
          duo:   { bag: {}, shoes: {}, accessori: {}, clothing: {} }
        };
        
        // Inizializza struttura
        for (const group of ['tutto', 'own', 'duo']) {
          for (const cat of ['bag', 'shoes', 'accessori', 'clothing']) {
            snapshot[group][cat] = {
              donna: { prodotti: 0, pezzi: 0 },
              uomo: { prodotti: 0, pezzi: 0 },
              unisex: { prodotti: 0, pezzi: 0 }
            };
          }
        }
        
        const nonClassificati = { prodotti: 0, pezzi: 0, product_types_orfani: {}, sample_orfani: [] };
        let totPezzi = 0, totProdotti = 0, totDuoProdotti = 0, totDuoPezzi = 0;
        
        products.forEach(p => {
          if (p.status !== 'active') return;
          
          const qty = (p.variants || []).reduce((s, v) => s + Math.max(0, parseInt(v.inventory_quantity) || 0), 0);
          if (qty <= 0) return; // Esclude qty = 0 (come da requisito utente)
          
          totProdotti++;
          totPezzi += qty;
          
          const isDuo = isDuoProduct(p);
          if (isDuo) { totDuoProdotti++; totDuoPezzi += qty; }
          
          // Cerca categoria e gender in product_type + tags + title
          const searchText = [p.product_type || '', p.tags || '', p.title || ''].join(' ');
          const cat = detectCategoria(searchText);
          const gender = detectGender(searchText) || 'unisex'; // fallback unisex
          
          if (!cat) {
            nonClassificati.prodotti++;
            nonClassificati.pezzi += qty;
            const pt = (p.product_type || '(vuoto)').trim();
            nonClassificati.product_types_orfani[pt] = (nonClassificati.product_types_orfani[pt] || 0) + 1;
            if (nonClassificati.sample_orfani.length < 10) {
              nonClassificati.sample_orfani.push({ id: p.id, title: p.title, product_type: p.product_type, tags: p.tags, stock: qty });
            }
            return;
          }
          
          // Aggrega in tutto/own/duo
          snapshot.tutto[cat][gender].prodotti++;
          snapshot.tutto[cat][gender].pezzi += qty;
          
          if (isDuo) {
            snapshot.duo[cat][gender].prodotti++;
            snapshot.duo[cat][gender].pezzi += qty;
          } else {
            snapshot.own[cat][gender].prodotti++;
            snapshot.own[cat][gender].pezzi += qty;
          }
        });
        
        // Converti sample orfani in array ordinato
        nonClassificati.product_types_orfani = Object.entries(nonClassificati.product_types_orfani)
          .sort((a, b) => b[1] - a[1])
          .map(([pt, count]) => ({ product_type: pt, count }));
        
        return res.json({
          success: true,
          generated_at: new Date().toISOString(),
          dalla_cache_discovery: !forceRefresh && discoveryData && discoveryData.cached_at ? true : false,
          cached_at: discoveryData?.cached_at || null,
          totale_prodotti_attivi_con_stock: totProdotti,
          totale_pezzi: totPezzi,
          duo_prodotti: totDuoProdotti,
          duo_pezzi: totDuoPezzi,
          own_prodotti: totProdotti - totDuoProdotti,
          own_pezzi: totPezzi - totDuoPezzi,
          snapshot,
          non_classificati: nonClassificati
        });
      } catch (e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }

    if (req.method === 'GET' && path === '/api/debug-winkelstraat') {
      try {
        const periodo = query.get('periodo') || 'month';
        const ordini = await getShopifyOrders(periodo);
        const winkelstraatOrders = [];
        const fallbackDefaultOrders = []; // ordini che non hanno matchato e finiscono in TLUXY_SITE (candidati mancati?)
        ordini.forEach(o => {
          const match = isWinkelstraatOrder(o);
          const mp = riconosciMarketplace(o);
          const email = (o.email || o.customer?.email || '').toLowerCase();
          const ship = o.shipping_address || {};
          const info = {
            order_number: o.order_number,
            name: o.name,
            created_at: o.created_at,
            source_name: o.source_name,
            email,
            tags: o.tags,
            note: o.note,
            shipping_address1: ship.address1,
            shipping_company: ship.company,
            shipping_name: [ship.first_name, ship.last_name].filter(Boolean).join(' '),
            marketplace_assegnato: mp.config.nome,
            winkelstraat_match: match // null oppure il campo che ha matchato
          };
          if (match) winkelstraatOrders.push(info);
          else if (mp.key === 'TLUXY_SITE') fallbackDefaultOrders.push(info);
        });
        return res.json({
          success: true,
          periodo,
          totale_ordini: ordini.length,
          winkelstraat_riconosciuti: winkelstraatOrders.length,
          ordini_winkelstraat: winkelstraatOrders,
          ordini_tluxy_site_campione: fallbackDefaultOrders.slice(0, 20) // per capire se qualcuno è sfuggito
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Auth diagnostic
    if (req.method === 'GET' && path === '/api/auth-status') {
      return res.json({
        auth_enabled: AUTH_ENABLED,
        auth_type: 'magic_link_resend',
        resend_configured: !!RESEND_API_KEY,
        mail_from: MAIL_FROM,
        allowed_emails_count: ALLOWED_EMAILS.length,
        session_days: AUTH_SESSION_DAYS,
        magic_link_minutes: MAGIC_LINK_MINUTES,
        authenticated: !!authUser,
        user_email: authUser?.email || null
      });
    }

    if (req.method === 'GET' && path === '/api/kv-status') {
      const envVarsDetected = {
        KV_REST_API_URL: !!process.env.KV_REST_API_URL,
        KV_REST_API_TOKEN: !!process.env.KV_REST_API_TOKEN,
        UPSTASH_REDIS_REST_URL: !!process.env.UPSTASH_REDIS_REST_URL,
        UPSTASH_REDIS_REST_TOKEN: !!process.env.UPSTASH_REDIS_REST_TOKEN,
        KV_REDIS_URL: !!process.env.KV_REDIS_URL,
        REDIS_URL: !!process.env.REDIS_URL
      };
      if (!KV_ENABLED) {
        return res.json({
          kv_enabled: false,
          kv_source: null,
          env_vars_detected: envVarsDetected,
          message: 'Nessuna credenziale KV trovata. Verifica che Vercel abbia creato le env vars.'
        });
      }
      try {
        const testKey = '__kv_test__';
        const testVal = String(Date.now());
        const writeOk = await kvSet(testKey, testVal);
        const read = await kvGet(testKey);
        return res.json({
          kv_enabled: true,
          kv_source: KV_SOURCE,
          kv_url_host: KV_REST_API_URL.replace(/^https?:\/\//, '').split('/')[0],
          env_vars_detected: envVarsDetected,
          write_ok: !!writeOk,
          read_ok: read === testVal,
          read_value: read
        });
      } catch (error) { return res.json({ kv_enabled: true, kv_source: KV_SOURCE, error: error.message }); }
    }

    // Diagnostica: verifica perché un ordine specifico potrebbe mancare dall'analytics
    // Usa: /api/debug-order?name=13027   oppure   /api/debug-order?id=5783212343468
    if (req.method === 'GET' && path === '/api/debug-order') {
      try {
        const orderName = query.get('name');
        const orderId = query.get('id');
        if (!orderName && !orderId) return res.status(400).json({ success: false, error: 'Passa ?name=13027 oppure ?id=5783212343468' });
        const token = await getShopifyAccessToken();
        const diag = { checks: {}, warnings: [], orderFound: null };
        
        // Step 1: cerca l'ordine su Shopify (by name o by id)
        let ordine = null;
        if (orderId) {
          const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders/${orderId}.json`;
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          diag.checks.fetch_by_id = { url, status: r.status };
          if (r.ok) { const d = await r.json(); ordine = d.order; }
        } else {
          // Cerca by name (serve scorrere gli ordini recenti)
          const cleaned = String(orderName).replace('#', '').trim();
          const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&name=%23${cleaned}&limit=10`;
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          diag.checks.fetch_by_name = { url, status: r.status };
          if (r.ok) {
            const d = await r.json();
            ordine = (d.orders || []).find(o => String(o.order_number) === cleaned || o.name === '#' + cleaned || o.name === cleaned);
            if (!ordine && (d.orders || []).length > 0) ordine = d.orders[0];
          }
        }
        
        if (!ordine) {
          diag.checks.exists_on_shopify = false;
          diag.warnings.push('Ordine NON trovato su Shopify. Controlla il numero esatto.');
          return res.json({ success: true, diagnostica: diag });
        }
        
        diag.checks.exists_on_shopify = true;
        diag.orderFound = {
          id: ordine.id,
          order_number: ordine.order_number,
          name: ordine.name,
          created_at: ordine.created_at,
          updated_at: ordine.updated_at,
          financial_status: ordine.financial_status,
          fulfillment_status: ordine.fulfillment_status,
          cancelled_at: ordine.cancelled_at,
          total_price: ordine.total_price,
          currency: ordine.currency,
          source_name: ordine.source_name,
          tags: ordine.tags,
          customer_email: ordine.customer?.email,
          shipping_country: ordine.shipping_address?.country_code,
          line_items_count: (ordine.line_items || []).length,
          refunds_count: (ordine.refunds || []).length
        };
        
        // Step 2: verifica status (cancellato?)
        if (ordine.cancelled_at) diag.warnings.push('Ordine CANCELLATO il ' + ordine.cancelled_at);
        
        // Step 3: verifica periodo "month" (che probabilmente è quello selezionato in dashboard)
        const now = new Date();
        const romeOffset = new Date().toLocaleString('en-US', { timeZone: 'Europe/Rome' });
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0);
        const createdAt = new Date(ordine.created_at);
        const inMeseCorrente = createdAt >= monthStart;
        diag.checks.created_at = ordine.created_at;
        diag.checks.mese_corrente_start = monthStart.toISOString();
        diag.checks.dentro_mese_corrente = inMeseCorrente;
        if (!inMeseCorrente) diag.warnings.push('Ordine NON dentro il mese corrente (periodo=month). Created ' + ordine.created_at);
        
        // Step 4: verifica marketplace
        const mp = riconosciMarketplace(ordine);
        diag.checks.marketplace_riconosciuto = { key: mp.key, nome: mp.config.nome };
        if (mp.key === 'TLUXY_SITE' && ordine.source_name && !['web', 'pos', 'shopify_draft_order'].includes(ordine.source_name)) {
          diag.warnings.push('⚠️ Marketplace defaultato a TLUXY_SITE ma source_name è "' + ordine.source_name + '". Controllare mapping.');
        }
        
        // Step 5: verifica refund (totale?)
        const refundInfo = getOrderRefundInfo(ordine);
        diag.checks.refund_info = refundInfo;
        if (refundInfo.isFullRefund) diag.warnings.push('Ordine con REFUND TOTALE → escluso dai conteggi analytics.');
        
        // Step 6: verifica costi merce (errori?)
        const variantIds = [...new Set((ordine.line_items || []).map(li => li.variant_id).filter(Boolean))];
        const productIds = [...new Set((ordine.line_items || []).map(li => li.product_id).filter(Boolean))];
        const { costs: variantCosts } = await fetchVariantCosts(variantIds, productIds);
        const duoUserCosts = {};
        if (KV_ENABLED) {
          const duoVids = (ordine.line_items || []).filter(li => isDuoSku(li.sku)).map(li => li.variant_id).filter(Boolean);
          if (duoVids.length) {
            const keys = duoVids.map(v => `duo_user_cost_${v}`);
            const results = await kvMGet(keys);
            duoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              if (results[key] !== undefined) {
                const parsed = parseFloat(results[key]);
                if (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        const { costo, errori } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
        diag.checks.costo_totale_calcolato = costo;
        diag.checks.errori_costi = errori;
        if (errori.length > 0) diag.warnings.push('⚠️ Errori costi: ' + errori.length + ' varianti senza costo → ordine va in "Ordini con errori"');
        
        // Step 7: verifica che fetchShopifyOrders lo includerebbe (periodo=month)
        const ordiniPeriodo = await getShopifyOrders('month');
        const trovatoNelPeriodo = (ordiniPeriodo || []).some(o => String(o.id) === String(ordine.id));
        diag.checks.trovato_in_getShopifyOrders_month = trovatoNelPeriodo;
        diag.checks.totale_ordini_fetchati_mese = (ordiniPeriodo || []).length;
        if (!trovatoNelPeriodo) diag.warnings.push('❌ CRITICO: getShopifyOrders(month) NON include questo ordine. Controllare filtri created_at_min/max.');
        
        // Riepilogo finale
        diag.verdict = errori.length > 0 ? 'ESCLUSO per costi mancanti (visibile in "Ordini con errori")'
          : (refundInfo.isFullRefund ? 'ESCLUSO per refund totale'
          : (!trovatoNelPeriodo ? 'NON FETCHATO nel periodo selezionato'
          : (ordine.cancelled_at ? 'CANCELLATO' : 'DOVREBBE ESSERE INCLUSO nei conteggi')));
        
        return res.json({ success: true, diagnostica: diag });
      } catch (error) { return res.status(500).json({ success: false, error: error.message, stack: error.stack }); }
    }

    if (req.method === 'GET' && path === '/api/debug-single-cost') {
      try {
        const variantId = query.get('variant_id') || '47254190325972';
        const token = await getShopifyAccessToken();
        const v1url = `https://${SHOPIFY_STORE}/admin/api/2024-01/variants/${variantId}.json`;
        const v1res = await fetch(v1url, { headers: { 'X-Shopify-Access-Token': token } });
        const v1body = await v1res.text();
        let inventoryItemId = null, v1parsed = null;
        try { v1parsed = JSON.parse(v1body); inventoryItemId = v1parsed?.variant?.inventory_item_id; } catch(e) {}
        let step2 = null;
        if (inventoryItemId) {
          const i1url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items/${inventoryItemId}.json`;
          const i1res = await fetch(i1url, { headers: { 'X-Shopify-Access-Token': token } });
          const i1body = await i1res.text();
          let i1parsed = null; try { i1parsed = JSON.parse(i1body); } catch(e) {}
          step2 = { url: i1url, status: i1res.status, response: i1parsed || i1body.substring(0, 500) };
        }
        let step3 = null;
        if (inventoryItemId) {
          const i2url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${inventoryItemId}`;
          const i2res = await fetch(i2url, { headers: { 'X-Shopify-Access-Token': token } });
          const i2body = await i2res.text();
          let i2parsed = null; try { i2parsed = JSON.parse(i2body); } catch(e) {}
          step3 = { url: i2url, status: i2res.status, response: i2parsed || i2body.substring(0, 500) };
        }
        return res.json({
          success: true,
          variant_id_testato: variantId,
          step1_variant: { url: v1url, status: v1res.status, response: v1parsed || v1body.substring(0, 500) },
          inventory_item_id_estratto: inventoryItemId,
          step2_inventory_item_singolo: step2,
          step3_inventory_items_con_ids: step3
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    if (req.method === 'GET' && path === '/api/test-shopify') {
      try {
        const token = await getShopifyAccessToken();
        const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/shop.json`, { headers: { 'X-Shopify-Access-Token': token } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        return res.json({ success: true, shop_name: data.shop.name, message: 'Shopify connesso' });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // ============ CHAT AI ASSISTANT (v5.10) ============
    if (req.method === 'GET' && path === '/api/chat-status') {
      const apiKey = process.env.ANTHROPIC_API_KEY || '';
      return res.json({
        enabled: !!apiKey,
        configured: !!apiKey,
        model: 'claude-haiku-4-5',
        cost_per_msg: '€0.005-0.02 per messaggio',
        configure_hint: apiKey ? null : 'Aggiungi env var ANTHROPIC_API_KEY su Vercel (chiave da console.anthropic.com)'
      });
    }
    
    if (req.method === 'POST' && path === '/api/chat') {
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ success: false, error: 'ANTHROPIC_API_KEY non configurato. Aggiungi su Vercel → Settings → Environment Variables.' });
      try {
        let body = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const userMessages = data.messages || [];
        if (userMessages.length === 0) return res.status(400).json({ success: false, error: 'Nessun messaggio' });
        
        // System prompt: dice a Claude che è l'assistente del tuo ERP
        const systemPrompt = `Sei l'assistente AI di T. Luxy ERP, una dashboard di Business Intelligence per un negozio luxury off-price gestito da Alessio. Hai accesso a strumenti per leggere dati Shopify in tempo reale: ordini, marginalità, marketplace, inventario, previsioni incassi.

Marketplace gestiti: Miinto, The Bradery, Italist, Secret Sales, Fashion Tamers, Intra Mirror, Balardi, Boutique Mall, Archivist, Winkelstraat, Jammy Dude, Poizon, Brandsgateway, T. Luxy sito proprio, Mark Foy, GIGLIO.COM.

Regole:
- Rispondi sempre in italiano
- Quando ti chiedono dati specifici (fatturato, ordini, ecc.), usa i tool per leggere i dati REALI, non inventarli
- Sii conciso: rispondi al punto, evita preamboli
- Usa formatting markdown leggero (**bold** per evidenziare numeri chiave)
- Se non puoi rispondere a una domanda, dillo onestamente
- Per il contesto: oggi è ${new Date().toLocaleDateString('it-IT')}, fuso orario Europa/Roma`;
        
        // Tool definitions: gli endpoint del nostro ERP esposti come strumenti per Claude
        const tools = [
          {
            name: 'get_analytics',
            description: 'Ottieni analytics completi (fatturato, IVA, margine, breakdown per marketplace, errori) per un periodo. Utilizzalo per domande su KPI, fatturato, marginalità, MP migliori/peggiori.',
            input_schema: {
              type: 'object',
              properties: {
                periodo: { type: 'string', enum: ['today', 'yesterday', 'week', 'month', 'quarter', 'year'], description: 'Periodo di analisi' }
              },
              required: ['periodo']
            }
          },
          {
            name: 'get_bestsellers',
            description: 'Ottieni i top 20 prodotti più venduti per fatturato in un periodo.',
            input_schema: {
              type: 'object',
              properties: {
                periodo: { type: 'string', enum: ['today', 'week', 'month', 'quarter', 'year'] }
              },
              required: ['periodo']
            }
          },
          {
            name: 'get_forecast',
            description: 'Ottieni le previsioni di incasso (bonifici futuri da marketplace) per i prossimi 2 mesi, con scadenziario per MP.',
            input_schema: { type: 'object', properties: {} }
          },
          {
            name: 'get_inventory',
            description: "Ottieni snapshot dell'inventario corrente: prodotti per categoria (bag/shoes/accessori/clothing) × gender.",
            input_schema: { type: 'object', properties: {} }
          },
          {
            name: 'get_ricerche_miinto',
            description: 'Ricerche di mercato: Miinto SS27 Buying Guidelines (brand in crescita/calo su Miinto, forme, colori, modelli top, brand emergenti) incrociate con vendite TLuxy 180 giorni e prodotti attivi per brand. Usalo per domande su cosa comprare, trend, brand da spingere o ridurre.',
            input_schema: { type: 'object', properties: {} }
          },
          {
            name: 'get_marketplaces_config',
            description: 'Ottieni la configurazione dei marketplace (commissioni, sconti, modalità pagamento).',
            input_schema: { type: 'object', properties: {} }
          }
        ];
        
        // Funzione che esegue un tool e restituisce il risultato
        async function executeTool(toolName, toolInput) {
          const baseUrl = `https://${req.headers.host || 'erp-marginalita-last.vercel.app'}`;
          const cookie = req.headers.cookie || '';
          const headers = cookie ? { 'Cookie': cookie } : {};
          try {
            let url;
            switch (toolName) {
              case 'get_analytics':
                url = `${baseUrl}/api/analytics?periodo=${encodeURIComponent(toolInput.periodo)}`;
                break;
              case 'get_bestsellers':
                url = `${baseUrl}/api/bestsellers?periodo=${encodeURIComponent(toolInput.periodo)}`;
                break;
              case 'get_forecast':
                url = `${baseUrl}/api/forecast`;
                break;
              case 'get_inventory':
                url = `${baseUrl}/api/inventory`;
                break;
              case 'get_marketplaces_config':
                url = `${baseUrl}/api/marketplaces`;
                break;
              case 'get_ricerche_miinto':
                url = `${baseUrl}/api/ricerche-miinto`;
                break;
              default:
                return { error: 'Tool sconosciuto: ' + toolName };
            }
            const r = await fetch(url, { headers });
            const d = await r.json();
            // Comprime l'output per non saturare il context (rimuove campi inutili)
            if (toolName === 'get_analytics' && d.success) {
              return {
                periodo: d.periodo,
                ordini_totali: d.ordini_totali,
                lordo_iva_inclusa: Math.round(d.lordo_iva_inclusa),
                iva_totale: Math.round(d.iva_totale),
                costi_merce: Math.round(d.costi_merce_totali || 0),
                costi_fees: Math.round(d.costi_fees_totali || 0),
                margine_netto: Math.round(d.margine_netto),
                margine_percentuale: parseFloat(d.margine_percentuale.toFixed(2)),
                errori_count: d.ordini_con_errori_count,
                resi: d.resi ? { count: d.resi.totale_count, importo: Math.round(d.resi.importo_totale_eur) } : null,
                breakdown_mp: Object.values(d.breakdown_marketplace || {}).map(mp => ({
                  nome: mp.nome,
                  ordini: mp.ordini,
                  fatturato: Math.round(mp.fatturato),
                  margine: Math.round(mp.margine),
                  margine_perc: mp.fatturato > 0 ? parseFloat((mp.margine / mp.fatturato * 100).toFixed(2)) : 0
                }))
              };
            }
            if (toolName === 'get_bestsellers' && d.success) {
              return { totali: d.totali, brand: (d.brand || []).slice(0, 10), modelli: (d.modelli || []).slice(0, 15).map(m => ({ titolo: m.titolo, brand: m.brand, pezzi: m.pezzi, fatturato: m.fatturato, margine_pct: m.margine_pct, canali: m.canali.map(c => c.nome + ' ' + c.pezzi).join(', ') })) };
            }
            if (toolName === 'get_forecast' && d.success) {
              return {
                kpi: d.kpi,
                breakdown: (d.breakdown_marketplace || []).slice(0, 10).map(mp => ({
                  nome: mp.nome,
                  prossimo_bonifico: mp.prossimo_bonifico,
                  importo_totale: Math.round(mp.importo_totale)
                })),
                balardi_residuo: d.balardi_wallet ? Math.round(d.balardi_wallet.credito_residuo * 100) / 100 : null
              };
            }
            if (toolName === 'get_inventory' && d.success) {
              return {
                totale_prodotti: d.totale_prodotti_attivi_con_stock,
                totale_pezzi: d.totale_pezzi,
                duo: { prodotti: d.duo_prodotti, pezzi: d.duo_pezzi },
                own: { prodotti: d.own_prodotti, pezzi: d.own_pezzi },
                snapshot: d.snapshot.tutto,
                non_classificati: d.non_classificati ? { prodotti: d.non_classificati.prodotti, pezzi: d.non_classificati.pezzi } : null
              };
            }
            if (toolName === 'get_marketplaces_config') {
              return { marketplace: Object.entries(d.marketplace_disponibili || {}).map(([k, mp]) => ({ key: k, nome: mp.nome, sconto: mp.sconto_percentuale, fee_principale: mp.fee_principale, fee_secondaria: mp.fee_secondaria || 0, sped: mp.fee_fissa_trasporto, pack: mp.fee_fissa_packaging, pagamento: mp.pagamento })) };
            }
            return d;
          } catch(e) { return { error: e.message }; }
        }
        
        // Chiama Claude API con loop tool calling (max 10 iterazioni)
        const claudeMessages = userMessages.map(m => ({ role: m.role, content: m.content }));
        let finalReply = '';
        let iteration = 0;
        const MAX_ITERATIONS = 8;
        
        while (iteration < MAX_ITERATIONS) {
          iteration++;
          const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': apiKey,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
              model: 'claude-haiku-4-5-20251001',
              max_tokens: 2048,
              system: systemPrompt,
              tools,
              messages: claudeMessages
            })
          });
          
          if (!claudeRes.ok) {
            const errBody = await claudeRes.text();
            return res.status(500).json({ success: false, error: `Claude API error ${claudeRes.status}: ${errBody.substring(0, 300)}` });
          }
          
          const claudeData = await claudeRes.json();
          
          // Aggiunge la risposta dell'assistente all'history
          claudeMessages.push({ role: 'assistant', content: claudeData.content });
          
          // Se è un tool_use, esegui e itera
          const toolUses = (claudeData.content || []).filter(b => b.type === 'tool_use');
          if (toolUses.length > 0 && claudeData.stop_reason === 'tool_use') {
            const toolResults = [];
            for (const toolUse of toolUses) {
              const result = await executeTool(toolUse.name, toolUse.input);
              toolResults.push({
                type: 'tool_result',
                tool_use_id: toolUse.id,
                content: JSON.stringify(result).substring(0, 8000) // limit context
              });
            }
            claudeMessages.push({ role: 'user', content: toolResults });
            continue;
          }
          
          // Altrimenti raccogli risposta testuale finale
          const textBlocks = (claudeData.content || []).filter(b => b.type === 'text');
          finalReply = textBlocks.map(b => b.text).join('\n');
          break;
        }
        
        if (!finalReply) finalReply = '⚠️ Non sono riuscito a completare la richiesta dopo ' + MAX_ITERATIONS + ' iterazioni.';
        
        return res.json({ success: true, reply: finalReply, iterations: iteration });
      } catch(e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }
    
    if (req.method === 'GET' && path === '/api/marketplaces') {
      return res.json({ marketplace_disponibili: MARKETPLACE_CONFIGS, source_name_map: SOURCE_NAME_MAP, iva_per_paese: IVA_PER_PAESE });
    }

    return res.status(404).json({ error: 'Endpoint non trovato' });
  } catch (error) { return res.status(500).json({ error: 'Errore interno', dettagli: error.message }); }
}
