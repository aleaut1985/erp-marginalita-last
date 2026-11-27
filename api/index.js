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
const DASHBOARD_URL = (process.env.DASHBOARD_URL || 'https://erp-marginalita-last.vercel.app').trim();
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
// v5.72: spesa pubblicitaria giornaliera (Google Ads + Meta) caricata ogni notte da Claude: KV ads:giorno:YYYY-MM-DD
async function adsPeriodo(da, a) {
  const giorni = []; for (let d = new Date(da + 'T12:00:00Z'); d.toISOString().slice(0, 10) <= a; d = new Date(d.getTime() + 86400000)) giorni.push(d.toISOString().slice(0, 10));
  const vals = {}; for (let i = 0; i < giorni.length; i += 90) Object.assign(vals, await kvMGet(giorni.slice(i, i + 90).map(g => 'ads:giorno:' + g)));
  const canali = {}; let totale = 0, mancanti = [];
  giorni.forEach(g => {
    let v = vals['ads:giorno:' + g]; if (!v) { mancanti.push(g); return; }
    try { v = typeof v === 'string' ? JSON.parse(v) : v; } catch (e) { mancanti.push(g); return; }
    ['google', 'meta'].forEach(c => {
      const x = v[c]; if (!x) return;
      if (!canali[c]) canali[c] = { totale: 0, campagne: {} };
      canali[c].totale += +x.totale || 0; totale += +x.totale || 0;
      (x.campagne || []).forEach(k => { const n = String(k.nome || '—'); const t = canali[c].campagne[n] || (canali[c].campagne[n] = { spesa: 0, tipo: k.tipo || '' }); t.spesa += +k.spesa || 0; });
    });
  });
  Object.values(canali).forEach(c => { c.campagne = Object.entries(c.campagne).map(([nome, v]) => ({ nome, spesa: Math.round(v.spesa * 100) / 100, tipo: v.tipo })).sort((x, y) => y.spesa - x.spesa); c.totale = Math.round(c.totale * 100) / 100; });
  return { da, a, giorni: giorni.length, caricati: giorni.length - mancanti.length, mancanti, totale: Math.round(totale * 100) / 100, canali };
}
// v5.70: utenti aggiuntivi (es. Floriana) salvati in KV come { email: 'salt:hash' }; li gestisce solo l'amministratore da /utenti
const UTENTI_KEY = 'erp:utenti:v1';
async function utentiExtra() { try { const v = await kvGet(UTENTI_KEY); const o = v ? JSON.parse(v) : {}; return o && typeof o === 'object' ? o : {}; } catch (e) { return {}; } }
function hashPassword(pass) { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + crypto.scryptSync(String(pass), salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex'); }
function hashOk(pass, stored) { try { const [salt, hash] = String(stored).split(':'); const calc = crypto.scryptSync(String(pass || ''), Buffer.from(salt, 'hex'), 64, { N: 16384, r: 8, p: 1 }); return crypto.timingSafeEqual(calc, Buffer.from(hash, 'hex')); } catch (e) { return false; } }
function isAdmin(u) { return !!u && (u.email === 'utente:' + ERP_USER || u.email === 'auth-disabled'); }
function utentiPage(lista, msg) {
  const esc = t => String(t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const righe = lista.length ? lista.map(e => `<li><span>${esc(e)}</span><form method="post" action="/utenti" onsubmit="return confirm('Tolgo l’accesso a ${esc(e)}?')"><input type="hidden" name="azione" value="rimuovi"><input type="hidden" name="email" value="${esc(e)}"><button class="rm">Togli accesso</button></form></li>`).join('') : '<li class="vuoto">Nessun altro utente</li>';
  return `<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Utenti · TLuxy Business Manager</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F6F4EF;color:#1b1b1b;margin:0;padding:24px 16px}main{max-width:460px;margin:0 auto;background:#fff;border-radius:14px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.06)}h1{font-size:1.2rem;margin:0 0 4px}p{color:#666;font-size:.88rem;margin:0 0 18px}ul{list-style:none;padding:0;margin:0 0 22px}li{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #eee;font-size:.92rem}li.vuoto{color:#999}label{display:block;font-size:.8rem;font-weight:600;margin:12px 0 4px}input[type=email],input[type=password]{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:1rem}button{font:inherit;cursor:pointer;border-radius:8px}button.add{margin-top:16px;width:100%;padding:11px;background:#111;color:#fff;border:0;font-weight:600}button.rm{padding:5px 10px;background:#fff;border:1px solid #c0392b;color:#c0392b;font-size:.8rem}.msg{background:#EEF4EF;color:#2F5A3A;padding:10px;border-radius:8px;font-size:.88rem;margin-bottom:14px}a{color:#555;font-size:.85rem}</style></head><body><main>
<h1>Chi può entrare nell’ERP</h1><p>Tu sei l’amministratore. Gli utenti qui sotto vedono tutto l’ERP ma non possono gestire gli accessi.</p>
${msg ? `<div class="msg">${esc(msg)}</div>` : ''}<ul>${righe}</ul>
<form method="post" action="/utenti"><input type="hidden" name="azione" value="aggiungi"><label>Email (sarà il nome utente)</label><input type="email" name="email" required autocomplete="off"><label>Password (almeno 10 caratteri)</label><input type="password" name="password" required minlength="10" autocomplete="new-password"><button class="add">Aggiungi utente</button></form>
<p style="margin-top:18px"><a href="/">← Torna all’ERP</a></p></main></body></html>`;
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
  .field input { width: 100%; padding: 14px 16px; border: 1.5px solid #E5E0D3; border-radius: 10px; font-size: 1rem; font-family: inherit; background: #FAFAF7; transition: border-color 200ms cubic-bezier(0.23, 1, 0.32, 1), box-shadow 200ms cubic-bezier(0.23, 1, 0.32, 1), background-color 200ms cubic-bezier(0.23, 1, 0.32, 1); }
  .field input:focus { outline: none; border-color: #C9A961; background: #FFFFFF; box-shadow: 0 0 0 3px rgba(201,169,97,0.1); }
  .btn { width: 100%; padding: 14px 20px; background: #1A1A1A; color: #FFFFFF; border: none; border-radius: 10px; font-size: 0.9rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer; transition: background-color 200ms cubic-bezier(0.23, 1, 0.32, 1), transform 160ms cubic-bezier(0.23, 1, 0.32, 1); margin-top: 8px; font-family: inherit; }
  .btn:hover { background: #333; }
  .btn:disabled { background: #BBB; cursor: not-allowed; transform: none; }
  .error { background: #FCEEEE; color: #BF4747; padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 20px; border-left: 3px solid #BF4747; display: none; }
  .info { background: #E6F4EE; color: #006b4a; padding: 14px 18px; border-radius: 8px; font-size: 0.88rem; margin-bottom: 20px; border-left: 3px solid #008060; display: none; line-height: 1.5; }
  .error.show, .info.show { display: block; }
  .footer { margin-top: 28px; padding-top: 20px; border-top: 1px solid #F0EBDF; font-size: 0.72rem; color: #8E8E8E; text-align: center; letter-spacing: 0.04em; }
  @media (hover: hover) and (pointer: fine) { .btn:hover { transform: translateY(-1px); } }
  .btn:active:not(:disabled) { transform: scale(0.97); }
  @media (prefers-reduced-motion: reduce) { .btn:hover, .btn:active:not(:disabled) { transform: none; } }
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
  // v5.76: nuovo database Upstash collegato con prefisso ERPDB (il vecchio KV è stato archiviato)
  const eu = process.env.ERPDB_KV_REST_API_URL || process.env.ERPDB_REST_API_URL, et = process.env.ERPDB_KV_REST_API_TOKEN || process.env.ERPDB_REST_API_TOKEN;
  if (eu && et) return { url: eu.trim(), token: et.trim(), source: 'erpdb_rest' };
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

// v5.58: Mantova Moda (canale di approvvigionamento via Atelier/Zucchetti): SKU AMM-…, tag TLX_PRODUCT:AMM, metafield tluxy.supplier=mantovamoda
function isMMSku(sku) {
  return !!(sku && typeof sku === 'string' && /^AMM-/i.test(sku.trim()));
}
async function atelierReady(nome, oidIn, dry) {
  const b = { oid: oidIn }; const dbg = [];
  const oid = String(b.oid || '').replace(/[^0-9]/g, '');
  const CAMPI = 'id name tags lineItems(first:50){ edges { node { sku } } }';
  let o = null;
  if (oid) { const q1 = await shopifyGraphQL('query($id:ID!){ order(id:$id){ ' + CAMPI + ' } }', { id: 'gid://shopify/Order/' + oid }); o = q1?.order || null; if (q1?.errors) dbg.push(q1.errors[0]?.message); }
  if (!o) {
    // fallback per nome: i nomi marketplace (#miinto-xxxx-…) non si trovano con name:"…", si cerca senza # e si confronta esatto
    const pulito = nome.replace(/^#/, '');
    for (const qq of ['name:' + JSON.stringify(nome), 'name:' + JSON.stringify(pulito), JSON.stringify(pulito)]) {
      const q = await shopifyGraphQL('query($q:String!){ orders(first:10, query:$q, sortKey:CREATED_AT, reverse:true){ edges { node { ' + CAMPI + ' } } } }', { q: qq });
      if (q?.errors) dbg.push(q.errors[0]?.message); dbg.push(qq + ' → ' + (q?.orders?.edges || []).map(e => e.node.name).join('|'));
      o = (q?.orders?.edges || []).map(e => e.node).find(n => n.name === nome || n.name.replace(/^#/, '') === pulito) || null;
      if (o) break;
    }
  }
  if (!o) return ({ success: false, error: 'Ordine ' + nome + ' non trovato', dbg });
  const mm = (o.lineItems?.edges || []).some(e => isMMSku(e.node.sku));
  if (!mm) return ({ success: false, error: 'Nessun articolo Mantova Moda (AMM-) in questo ordine' });
  if ((o.tags || []).some(t => String(t).toUpperCase() === 'ATELIER READY')) return ({ success: true, gia: true });
  if (dry) return ({ success: true, dry: true, ordine: o.name, tags: o.tags, skus: (o.lineItems?.edges || []).map(e => e.node.sku) });
  const r = await shopifyGraphQL('mutation($id:ID!,$t:[String!]!){ tagsAdd(id:$id, tags:$t){ userErrors { message } } }', { id: o.id, t: ['ATELIER READY'] });
  const err = r?.errors?.[0]?.message || r?.tagsAdd?.userErrors?.[0]?.message;
  if (err) return ({ success: false, error: /access|scope|denied/i.test(err) ? 'Manca il permesso write_orders sull\'app ERP' : err });
  return ({ success: true });
}
function fornitoreSku(sku) { return isMMSku(sku) ? 'MANTOVA MODA' : (isDuoSku(sku) ? 'DUOMO' : ''); }

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
    case 'monthly_end': {
      // Ordini del mese M fatturati a fine mese, pagati a fine mese M + month_offset (es. Giglio 30DFFM)
      const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (policy.month_offset || 1) + 1, 0);
      result.push({ data: target, importo_eur: nettoIncassato, nota: `Fine mese+${policy.month_offset || 1}`, parte: 1 });
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
  'BALARDI': { nome: 'Balardi', sconto_percentuale: 35, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Prepagato (wallet)', payment_policy: { type: 'prepaid_balance' }, iva_esente: true, prezzo_ordine_netto: true, nota_regole: 'Paga il prezzo di vendita TLuxy −35%, senza IVA; il prezzo ordine Shopify è già l\'incasso. Spedizione rimborsata a parte (copre il corriere).' },
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
  'LOVE_THE_SALES': { nome: 'Love The Sales', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Da contratto (da verificare)', payment_policy: { type: 'fixed_days', days_offset: 30 }, nota_regole: 'Commissione a scaglioni sullo sconto del prodotto (prezzo vs prezzo pieno): 0–30% → 19%, 31–40% → 17%, 41–50% → 15%, 51–60% → 12%, 61–70% → 10%, 71–100% → 5%. Ordini resi: 7%. Spedizione a carico TLuxy (stima 12 €). Condizioni dalle email di negoziazione.' },
  'LUOSOPHY': { nome: 'Luosophy', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 1, pagamento: 'Paga direttamente (immediato)', payment_policy: { type: 'fixed_days', days_offset: 2 }, iva_esente: true, prezzo_ordine_netto: true, nota_regole: 'Rivenditrice USA (Yinghan Wang): ordina sul sito con un suo codice sconto e paga direttamente; l\'importo dell\'ordine è già il netto incassato. Spedizione a suo carico.' },
  'TLUXY_SITE': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato (Shopify +2gg)', payment_policy: { type: 'fixed_days', days_offset: 2 } },
  'MARK_FOYS': { nome: 'Mark Foy', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Prepagato immediato', payment_policy: { type: 'immediate' } },
  'REFLAUNT': { nome: 'Reflaunt', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: '14gg reso + report + fattura (~30gg)', payment_policy: { type: 'fixed_days', days_offset: 30 },
    nota_regole: 'Dropship: l\'ordine arriva su Shopify al payout (metafield custom.reflaunt_payout) = incasso, senza IVA né commissioni; etichetta di spedizione fornita da Reflaunt' },
  // v5.47: contratto Giglio 29/10/2024 — sconto base 31% sul prezzo finale senza IVA + 2,5% per pagamento 30DFFM = 33,5%;
  // commissione attuale 34,5% (confermata nov 2026, fatture Giglio); contributo spedizione €3,60 (applicato per ordine); penali KPI mensili NON incluse (arrivano dal rendiconto Giglio)
  // v5.63: ABOUT YOU (app Shopify "About You", source_name "ayou", tag ayou, ordini ds-xxxx). Commissione a scaglioni di prezzo
  // (struttura dal 01/07/2026: fascia minima <35€, fasce intermedie fino a 100€) — percentuali ESATTE da confermare dal Seller Center › Legal.
  'ABOUT_YOU': { nome: 'About You', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 1.15, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5, pagamento: 'Mensile: 5° giorno lavorativo del mese dopo (SCAYLE Payments)', payment_policy: { type: 'monthly_decade', month_offset: 1, payout_day: 7 }, nota_regole: 'Commissione a scaglioni per categoria e prezzo (tabella Seller Center nov 2026: >100€ uomo 22%, borse/accessori 19%, scarpe 19%, donna 18%), calcolata riga per riga. SCAYLE Payments 1,15% sul lordo (contratto 22/06/2026). Payout 5° giorno lavorativo del mese dopo; trattenuta garanzia resi 60gg / chargeback 180gg. Reso prepagato a nostro carico.' },
  'GIGLIO': { nome: 'GIGLIO.COM', sconto_percentuale: 0, fee_principale: 34.5, fee_secondaria: 0, fee_fissa_trasporto: 3.6, fee_fissa_packaging: 0, pagamento: '30gg data fattura fine mese (fine mese+1)', payment_policy: { type: 'monthly_end', month_offset: 1 }, nota_regole: 'Commissione 34,5% (confermata da Alessio nov 2026) sul prezzo pagato dal cliente senza IVA. Contributo spedizione €3,60 a pezzo. Penali KPI (no-stock/ritardi) a parte, dal rendiconto mensile.' }
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
  'ayou': 'ABOUT_YOU', 'about-you': 'ABOUT_YOU', 'aboutyou': 'ABOUT_YOU', '426640277505': 'ABOUT_YOU',
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

// v5.66: commissione About You per categoria × fascia di prezzo unitario (IVA incl.) — tabella Seller Center nov 2026 (fonte wortfilter.de 23/11/2026)
const ABOUT_YOU_TIERS = {            // <35, 35–50, 50–100, >100
  uomo:      [6, 14, 18, 22],
  donna:     [4, 5, 13, 18],
  accessori: [6, 16, 18, 19],
  scarpe:    [4, 8, 16, 19]
};
function aboutYouCategoria(item) {
  const sku = String(item.sku || '').toUpperCase(), t = String(item.title || '').toLowerCase(), v = String(item.vendor || '').toLowerCase();
  if (/^BAG/.test(sku) || /\b(bag|borsa|wallet|portafoglio|belt|cintura|scarf|sciarpa|hat|cappello|jewel|sunglass|occhiali)/.test(t)) return 'accessori';
  if (/\b(sneaker|shoe|scarp|boot|stivale|loafer|mocassino|sandal|mule|pump|décolleté|decollete)/.test(t)) return 'scarpe';
  if (v.includes('autore')) return 'uomo';
  if (/\b(women|woman|donna|dress|abito donna|skirt|gonna)/.test(t)) return 'donna';
  return 'uomo'; // prudenziale: fascia più cara
}
function aboutYouFeePct(ordine) {
  let lordo = 0, fee = 0;
  for (const it of (ordine.line_items || [])) {
    const q = parseInt(it.quantity) || 0, pu = parseFloat(it.price) || 0;
    if (!q || !pu) continue;
    const tr = ABOUT_YOU_TIERS[aboutYouCategoria(it)];
    const pct = pu < 35 ? tr[0] : pu < 50 ? tr[1] : pu < 100 ? tr[2] : tr[3];
    lordo += pu * q; fee += pu * q * pct / 100;
  }
  return lordo > 0 ? Math.round(fee / lordo * 10000) / 100 : null;
}

// v5.78: Love The Sales — commissione a scaglioni in base allo sconto (prezzo venduto vs prezzo pieno compare-at della variante)
const VARIANT_CMP = {};
async function caricaCmpLoveTheSales(ordini) {
  const ids = [...new Set((ordini || []).filter(o => riconosciMarketplaceBase(o).key === 'LOVE_THE_SALES').flatMap(o => (o.line_items || []).map(li => li.variant_id)).filter(v => v && !VARIANT_CMP[v]))];
  for (let i = 0; i < ids.length; i += 100) {
    try {
      const d = await shopifyGraphQL('query($ids:[ID!]!){ nodes(ids:$ids){ ... on ProductVariant { id compareAtPrice } } }', { ids: ids.slice(i, i + 100).map(v => 'gid://shopify/ProductVariant/' + v) });
      (d?.data?.nodes || []).forEach(n => { if (n && n.compareAtPrice) VARIANT_CMP[String(n.id).split('/').pop()] = parseFloat(n.compareAtPrice); });
    } catch (e) { console.log('[lts cmp]', e.message); }
  }
}
function loveTheSalesPct(sconto) { return sconto <= 30 ? 19 : sconto <= 40 ? 17 : sconto <= 50 ? 15 : sconto <= 60 ? 12 : sconto <= 70 ? 10 : 5; }
function loveTheSalesFeePct(ordine) {
  let lordo = 0, fee = 0, noti = 0;
  for (const it of (ordine.line_items || [])) {
    const q = parseInt(it.quantity) || 0, pu = parseFloat(it.price) || 0; if (!q || !pu) continue;
    const cmp = VARIANT_CMP[it.variant_id] || 0;
    const sconto = cmp > pu ? (1 - pu / cmp) * 100 : 0; if (cmp > pu) noti++;
    lordo += pu * q; fee += pu * q * loveTheSalesPct(sconto) / 100;
  }
  return lordo > 0 && noti ? Math.round(fee / lordo * 10000) / 100 : null;
}
function riconosciMarketplace(ordine) {
  const r = riconosciMarketplaceBase(ordine);
  let config = getConfigPerData(r.key, ordine.created_at) || r.config;
  if (r.key === 'ABOUT_YOU') { const p = aboutYouFeePct(ordine); if (p !== null) config = { ...config, fee_principale: p }; }
  if (r.key === 'LOVE_THE_SALES') { const p = loveTheSalesFeePct(ordine); if (p !== null) config = { ...config, fee_principale: p }; }
  return { key: r.key, config };
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
  
  // PRIORITÀ 1b: Reflaunt (dropship) — app "Reflaunt T-Luxy App", tag ordine REFLAUNT, email admin@reflaunt.com
  if (rawSource === '253898227713' || /(^|,\s*)reflaunt(\s*,|$)/.test(tags) || email === 'admin@reflaunt.com') {
    return { key: 'REFLAUNT', config: MARKETPLACE_CONFIGS.REFLAUNT };
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
  // Ordini Syncio arrivati da Jammy Dude (tag "jammydude21 syncio-order"): stesso source 1615469, ma sono Jammy Dude, non Mark Foy's
  if (/jammy\s*-?dude/.test(tags)) {
    return { key: 'JAMMY_DUDE', config: MARKETPLACE_CONFIGS.JAMMY_DUDE };
  }
  // Caso sub: source 1615469 MA email non è di thebradery → Mark Foy's
  if (rawSource === '1615469' && email && !email.includes('thebradery')) {
    return { key: 'MARK_FOYS', config: MARKETPLACE_CONFIGS.MARK_FOYS };
  }
  
  // PRIORITÀ 3a: Love The Sales (app "T.Luxy: LovetheSales", source "Love The Sales")
  if (rawSource === '252655108097' || /love\s*the\s*sales/i.test(rawSource) || tags.includes('love the sales')) {
    return { key: 'LOVE_THE_SALES', config: MARKETPLACE_CONFIGS.LOVE_THE_SALES };
  }
  // PRIORITÀ 3b: Luosophy (rivenditrice USA, ordina sul sito con codice sconto dedicato)
  const discLuo = (ordine.discount_codes || []).some(d => /luo/i.test(String(d.code || '')));
  const nomiLuo = [ordine.customer?.first_name, ordine.customer?.last_name, ordine.shipping_address?.company, ordine.billing_address?.company, ordine.shipping_address?.name, ordine.billing_address?.name].join(' ').toLowerCase();
  if (discLuo || tags.includes('luosophy') || /luosophy|luoluowyh/.test(email) || nomiLuo.includes('luosophy') || nomiLuo.includes('yinghan')) {
    return { key: 'LUOSOPHY', config: MARKETPLACE_CONFIGS.LUOSOPHY };
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

// v5.59: visite e conversione del sito (ShopifyQL, serve lo scope read_reports sull'app Shopify)
const trafficoCache = new Map();
async function trafficoSito(da, a) {
  const key = da + '|' + a; const c = trafficoCache.get(key);
  if (c && Date.now() - c.t < 10 * 60 * 1000) return c.v;
  const token = await getShopifyAccessToken();
  const q = `FROM sessions SHOW sessions, sessions_that_completed_checkout TIMESERIES day SINCE ${da} UNTIL ${a}`;
  const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2025-10/graphql.json`, { method: 'POST', headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'query($q:String!){ shopifyqlQuery(query:$q){ tableData { columns { name } rows } parseErrors } }', variables: { q } }) });
  const j = await r.json();
  if (j.errors) throw new Error(JSON.stringify(j.errors).slice(0, 300));
  const res = j.data && j.data.shopifyqlQuery;
  if (!res || !res.tableData) throw new Error('ShopifyQL: ' + ((res && res.parseErrors || []).join('; ') || 'nessun dato'));
  const rows = (res.tableData.rows || []).map(x => Array.isArray(x) ? { day: x[0], sessions: x[1], sessions_that_completed_checkout: x[2] } : x);
  const giorni = rows.map(x => ({ d: String(x.day || '').slice(0, 10), s: parseInt(x.sessions) || 0, o: parseInt(x.sessions_that_completed_checkout) || 0 })).filter(x => x.d).sort((x, y) => x.d < y.d ? -1 : 1);
  const sess = giorni.reduce((t, x) => t + x.s, 0), ok = giorni.reduce((t, x) => t + x.o, 0);
  const v = { sessioni: sess, checkout: ok, conversione: sess ? ok / sess * 100 : 0, giorni };
  trafficoCache.set(key, { t: Date.now(), v });
  return v;
}

// v5.60: da dove arrivano le visite (fonte + sito di provenienza)
async function trafficoFonti(da, a) {
  const key = 'f|' + da + '|' + a; const c = trafficoCache.get(key);
  if (c && Date.now() - c.t < 10 * 60 * 1000) return c.v;
  const token = await getShopifyAccessToken();
  const q = `FROM sessions SHOW sessions, sessions_that_completed_checkout GROUP BY referrer_source, referrer_name SINCE ${da} UNTIL ${a} ORDER BY sessions DESC LIMIT 40`;
  const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2025-10/graphql.json`, { method: 'POST', headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'query($q:String!){ shopifyqlQuery(query:$q){ tableData { columns { name } rows } parseErrors } }', variables: { q } }) });
  const j = await r.json();
  if (j.errors) throw new Error(JSON.stringify(j.errors).slice(0, 300));
  const res = j.data && j.data.shopifyqlQuery;
  if (!res || !res.tableData) throw new Error('ShopifyQL: ' + ((res && res.parseErrors || []).join('; ') || 'nessun dato'));
  const v = (res.tableData.rows || []).map(x => Array.isArray(x) ? { referrer_source: x[0], referrer_name: x[1], sessions: x[2], sessions_that_completed_checkout: x[3] } : x)
    .map(x => ({ fonte: String(x.referrer_source || '').toLowerCase(), nome: String(x.referrer_name || ''), s: parseInt(x.sessions) || 0, o: parseInt(x.sessions_that_completed_checkout) || 0 }))
    .filter(x => x.s > 0);
  trafficoCache.set(key, { t: Date.now(), v });
  return v;
}

// v5.61: iscritti newsletter da Omnisend (API statistics: max 55 chiamate/giorno → cache 1h in KV)
async function omnisendIscritti() {
  const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
  if (!KEY) throw new Error('NO_KEY');
  const ck = 'omni_iscritti_v3';
  const cached = await kvGet(ck);
  if (cached) { try { return JSON.parse(cached); } catch (_) {} }
  const oggi = getRomeDateString();
  const piu1 = getRomeDateString(new Date(Date.now() + 86400000));
  const d59 = getRomeDateString(new Date(Date.now() - 58 * 86400000)); // max 60 giorni con granularità day
  const m = new Date(); const da12 = `${m.getFullYear() - 1}-${String(m.getMonth() + 2 > 12 ? 1 : m.getMonth() + 2).padStart(2, '0')}-01`;
  const off = getRomeOffset(new Date()) === 120 ? '+02:00' : '+01:00';
  const body = { queries: [
    { alias: 'giorni', metrics: [{ name: 'subscribedEmail' }, { name: 'unsubscribedEmail' }], dimensions: [{ name: 'timestamp', granularity: 'day' }], dateRange: { from: d59 + 'T00:00:00' + off, to: piu1 + 'T00:00:00' + off } },
    { alias: 'mesi', metrics: [{ name: 'subscribedEmail' }, { name: 'unsubscribedEmail' }], dimensions: [{ name: 'timestamp', granularity: 'month' }], dateRange: { from: (m.getMonth() === 11 ? `${m.getFullYear()}-01-01` : da12) + 'T00:00:00' + off, to: piu1 + 'T00:00:00' + off } }
  ] };
  let r = await fetch('https://api.omnisend.com/api/analytics/statistics', { method: 'POST', headers: { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify(body) });
  if (r.status === 401) r = await fetch('https://api.omnisend.com/api/analytics/statistics', { method: 'POST', headers: { 'X-API-KEY': KEY, 'Omnisend-Version': '2026-03-15', 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify(body) });
  if (r.status === 401) console.log('[newsletter-iscritti] chiave rifiutata, lunghezza', KEY.length, 'formato', /^[0-9a-f]{24}-[A-Za-z0-9]+$/.test(KEY) ? 'ok' : 'anomalo');
  if (!r.ok) throw new Error('Omnisend HTTP ' + r.status + ' ' + (await r.text()).slice(0, 200));
  const j = await r.json();
  const pick = a => ((j.statistics || []).find(x => x.alias === a) || { rows: [] }).rows.map(x => ({ d: String(x.timestamp).slice(0, 10), i: x.subscribedEmail || 0, u: x.unsubscribedEmail || 0 }));
  const v = { giorni: pick('giorni'), mesi: pick('mesi'), oggi, agg: new Date().toISOString() };
  // v5.63: togli iscrizioni finte (email test… dei bot, iscritto+disiscritto entro 2 minuti)
  try {
    const f = await omnisendFinti(KEY, d59);
    const togli = (rows, key, len) => rows.forEach(g => { const x = f[key][g.d.slice(0, len)]; if (x) { g.i = Math.max(0, g.i - (x.i || 0)); g.u = Math.max(0, g.u - (x.u || 0)); } });
    togli(v.giorni, 'giorni', 10); togli(v.mesi, 'mesi', 7);
    v.finti = f.totale; v.finti_completo = f.completo;
  } catch (e) { console.log('[newsletter-finti]', e.message); }
  await kvSetEx(ck, 3600, JSON.stringify(v));
  return v;
}

// v5.63: contatti finti creati negli ultimi ~60 giorni, raggruppati per giorno/mese (ora di Roma)
const EMAIL_TEST_BOT = /^test[0-9a-f]{20,}@/i;
async function omnisendFinti(KEY, daGiorno) {
  const h = { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Accept': 'application/json' };
  const out = { giorni: {}, mesi: {}, totale: 0, completo: false };
  const add = (iso, campo) => {
    const d = getRomeDateString(new Date(iso));
    for (const [k, key] of [[d, 'giorni'], [d.slice(0, 7), 'mesi']]) { out[key][k] = out[key][k] || { i: 0, u: 0 }; out[key][k][campo]++; }
  };
  let after = '', pagine = 0; const t0 = Date.now();
  while (pagine < 60 && Date.now() - t0 < 25000) {
    const r = await fetch('https://api.omnisend.com/api/contacts?sort=createdAt&direction=desc&limit=250' + (after ? '&after=' + encodeURIComponent(after) : ''), { headers: h });
    if (!r.ok) throw new Error('Omnisend contacts HTTP ' + r.status);
    const j = await r.json(); pagine++;
    let fine = false;
    for (const c of (j.contacts || [])) {
      if (getRomeDateString(new Date(c.createdAt)) < daGiorno) { fine = true; break; }
      const st = (c.statuses || []).filter(s => s.channel === 'email');
      const sub = st.find(s => s.status === 'subscribed'), uns = st.find(s => s.status === 'unsubscribed');
      const rapido = sub && uns && Math.abs(new Date(uns.statusChangedAt) - new Date(sub.statusChangedAt)) <= 120000;
      if (!(EMAIL_TEST_BOT.test(c.email || '') || rapido)) continue;
      out.totale++;
      if (sub) add(sub.statusChangedAt, 'i');
      if (uns) add(uns.statusChangedAt, 'u');
    }
    const nx = j.paging && j.paging.cursors && j.paging.cursors.after;
    if (fine || !(j.paging && j.paging.hasMore) || !nx) { out.completo = true; break; }
    after = nx;
  }
  return out;
}

// v5.62: totale iscritti email (conteggio contatti "subscribed", cache 6h)
// v5.67: iscritti per form Omnisend (report per form nel periodo; elenco form in cache 6h, report 30 min)
const omniFormCache = new Map();
async function omnisendIscrittiPerForm(da, a) {
  const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
  if (!KEY) throw new Error('NO_KEY');
  const ck = 'f|' + da + '|' + a, hit = omniFormCache.get(ck);
  if (hit && Date.now() - hit.t < 30 * 60000) return hit.v;
  const h = { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Accept': 'application/json' };
  let forms = null;
  const cf = await kvGet('omni_forms_v1');
  if (cf) { try { forms = JSON.parse(cf); } catch (_) {} }
  if (!forms) {
    const r = await fetch('https://api.omnisend.com/api/forms?limit=100', { headers: h });
    if (!r.ok) throw new Error('Omnisend forms HTTP ' + r.status);
    const j = await r.json();
    forms = (j.forms || []).map(f => ({ id: f.id, nome: f.name, stato: f.status, tipo: f.displayType }));
    await kvSetEx('omni_forms_v1', 6 * 3600, JSON.stringify(forms));
  }
  const off = getRomeOffset(new Date()) === 120 ? '+02:00' : '+01:00';
  const righe = await Promise.all(forms.map(async f => {
    try {
      const u = 'https://api.omnisend.com/api/forms/' + f.id + '/report?createdAtFrom=' + encodeURIComponent(da + 'T00:00:00' + off) + '&createdAtTo=' + encodeURIComponent(a + 'T23:59:59' + off);
      const r = await fetch(u, { headers: h });
      if (!r.ok) return null;
      const st = (await r.json()).statistics || {};
      return { ...f, viste: st.views || 0, invii: st.submits || 0, iscritti: st.signups || 0 };
    } catch (_) { return null; }
  }));
  const v = righe.filter(x => x && (x.iscritti || x.viste)).sort((x, y) => y.iscritti - x.iscritti || y.viste - x.viste);
  omniFormCache.set(ck, { t: Date.now(), v });
  return v;
}

async function omnisendTotale() {
  const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
  if (!KEY) throw new Error('NO_KEY');
  const ck = 'omni_totale_v1';
  const cached = await kvGet(ck);
  if (cached) { try { return JSON.parse(cached); } catch (_) {} }
  const h = { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Accept': 'application/json' };
  let tot = 0, after = '', pagine = 0, completo = false;
  const t0 = Date.now();
  while (pagine < 400 && Date.now() - t0 < 45000) {
    const u = 'https://api.omnisend.com/api/contacts?status=subscribed&limit=250' + (after ? '&after=' + encodeURIComponent(after) : '');
    const r = await fetch(u, { headers: h });
    if (!r.ok) throw new Error('Omnisend contacts HTTP ' + r.status);
    const j = await r.json();
    tot += (j.contacts || []).length; pagine++;
    const nx = j.paging && j.paging.cursors && j.paging.cursors.after;
    if (!(j.paging && j.paging.hasMore) || !nx) { completo = true; break; }
    after = nx;
  }
  const v = { totale: tot, completo, agg: new Date().toISOString() };
  if (completo) await kvSetEx(ck, 6 * 3600, JSON.stringify(v));
  return v;
}


// ============ v5.64 AVVISO CALO PREZZO (tema: snippet tlx-price-alert → tag price-alert + pa-<handle>) ============
// Ogni mattina: per ogni contatto Omnisend con tag price-alert e ogni suo tag pa-<handle>, confronta il prezzo effettivo
// di oggi (taglia disponibile più economica, con la fascia Black Friday bf26-X nei giorni 27–30/11) con quello del giorno
// in cui l'abbiamo visto la prima volta (KV). Se è sceso di almeno 5% o 20 € e il prodotto è disponibile, manda a Omnisend
// l'evento "price dropped" (automazione "T.LUXY - Avviso prezzo sceso"). Una sola volta per contatto e prodotto.
// I prezzi non vengono MAI modificati: solo letti. PRICE_ALERT_LIVE=1 per inviare davvero; altrimenti simula.
const PA_PATH = '/api/cron/price-alerts';
const PA_BF = { da: '2026-11-27', a: '2026-11-30' };
const paEuro = n => { const r = Math.round(n * 100) / 100; const [i, d] = r.toFixed(2).split('.'); return '€' + i.replace(/\B(?=(\d{3})+(?!\d))/g, '.') + (d === '00' ? '' : ',' + d); };
function paTesti(lang, d) {
  const it = lang === 'it';
  const bf = d.bf;
  return {
    subject: bf ? (it ? `Black Friday: ${d.title} ora a ${paEuro(d.nuovo)}` : `Black Friday: ${d.title} now ${paEuro(d.nuovo)}`)
                : (it ? `Il prezzo è sceso: ${d.title}` : `Price drop: ${d.title}`),
    preheader: bf ? (it ? `−${d.pct}% applicato al checkout, fino al 30/11. Su tluxy.com` : `−${d.pct}% applied at checkout, until 30/11. On tluxy.com`)
                  : (it ? `Ora a ${paEuro(d.nuovo)} invece di ${paEuro(d.vecchio)}. Su tluxy.com` : `Now ${paEuro(d.nuovo)} instead of ${paEuro(d.vecchio)}. On tluxy.com`),
    eyebrow: it ? 'Il tuo avviso prezzo' : 'Your price alert',
    headline: bf ? (it ? `Ora con il Black Friday: −${d.pct}%.` : `Now with Black Friday: −${d.pct}%.`) : (it ? 'Buone notizie: il prezzo è sceso.' : 'Good news: the price has dropped.'),
    intro: bf ? (it ? 'Il pezzo che segui è nel Black Friday. Il lusso autentico, selezionato per te.' : 'The piece you follow is in our Black Friday. Authentic luxury, selected for you.')
              : (it ? 'Il pezzo che segui costa meno da oggi. Il lusso autentico, selezionato per te.' : 'The piece you follow costs less from today. Authentic luxury, selected for you.'),
    saving: bf ? (it ? `−${paEuro(d.vecchio - d.nuovo)} con il Black Friday` : `−${paEuro(d.vecchio - d.nuovo)} with Black Friday`) : (it ? `−${paEuro(d.vecchio - d.nuovo)} da quando lo segui` : `−${paEuro(d.vecchio - d.nuovo)} since you started following`),
    ref_line: bf ? (it ? `Prezzo retail ${paEuro(d.rrp)} · Prezzo più basso ultimi 30 gg ${paEuro(d.base)}` : `RRP ${paEuro(d.rrp)} · Lowest price in the last 30 days ${paEuro(d.base)}`) : '',
    cta: it ? 'Vedi il prodotto' : 'View the product',
    note: bf ? (it ? 'Sconto applicato automaticamente al checkout, fino al 30/11. Pezzi disponibili in quantità limitata.' : 'Discount applied automatically at checkout, until 30/11. Limited quantities available.')
             : (it ? "Pezzi disponibili in quantità limitata: il prezzo vale finché c'è disponibilità." : 'Limited quantities available: the price is valid while stock lasts.'),
    trust: it ? '✓ Autenticità garantita · Spedizione assicurata · Reso entro 14 giorni' : '✓ Guaranteed authentic · Insured shipping · Returns within 14 days',
    footer: it ? "Ricevi questa email perché hai attivato l'avviso prezzo su tluxy.com." : 'You are receiving this email because you set a price alert on tluxy.com.',
    unsub_label: it ? 'Disiscriviti' : 'Unsubscribe'
  };
}
async function paProdotto(handle, cache) {
  if (cache.has(handle)) return cache.get(handle);
  let v = null;
  try {
    const d = await shopifyGraphQL(`query($h:String!){ productByHandle(handle:$h){ title vendor handle status featuredImage{ url } variants(first:100){ nodes{ price compareAtPrice availableForSale } } collections(first:60){ nodes{ handle } } } }`, { h: handle });
    const p = d && d.productByHandle;
    if (p) {
      const disp = p.variants.nodes.filter(x => x.availableForSale);
      const top = disp.sort((a, b) => parseFloat(a.price) - parseFloat(b.price))[0] || null;
      let pct = 0;
      for (const c of p.collections.nodes) { const m = /^bf26-(5|10|15|20|25|30)$/.exec(c.handle); if (m) pct = Math.max(pct, +m[1]); }
      const oggi = getRomeDateString();
      const bfOn = oggi >= PA_BF.da && oggi <= PA_BF.a && pct > 0;
      const base = top ? parseFloat(top.price) : 0;
      const cmp = top && top.compareAtPrice ? parseFloat(top.compareAtPrice) : 0;
      v = { title: p.title, brand: p.vendor, handle: p.handle, attivo: p.status === 'ACTIVE', disponibile: !!top, img: p.featuredImage ? p.featuredImage.url : '',
            base, rrp: Math.max(base, cmp), pct: bfOn ? pct : 0, bf: bfOn, eff: bfOn ? Math.round(base * (100 - pct) / 100) : base };
    }
  } catch (e) { console.log('[price-alert] prodotto', handle, e.message); }
  cache.set(handle, v);
  return v;
}
async function paEsegui({ live, soloEmail, soloHandle, testBf }) {
  const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
  if (!KEY) throw new Error('NO_KEY');
  const h = { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Accept': 'application/json', 'Content-Type': 'application/json' };
  const contatti = []; let after = '';
  if (soloEmail && soloHandle) contatti.push({ email: soloEmail, tags: ['lang-it', 'pa-' + soloHandle], countryCode: 'IT' });
  for (let i = 0; i < 20 && !(soloEmail && soloHandle); i++) {
    const r = await fetch('https://api.omnisend.com/api/contacts?tag=price-alert&limit=250' + (after ? '&after=' + encodeURIComponent(after) : ''), { headers: h });
    if (!r.ok) throw new Error('Omnisend contacts HTTP ' + r.status);
    const j = await r.json(); contatti.push(...(j.contacts || []));
    const nx = j.paging && j.paging.cursors && j.paging.cursors.after;
    if (!(j.paging && j.paging.hasMore) || !nx) break; after = nx;
  }
  const cache = new Map(); const out = { contatti: contatti.length, coppie: 0, nuovi: 0, invii: [], saltati: 0, live };
  for (const c of contatti) {
    const email = String(c.email || '').toLowerCase();
    if (!email || EMAIL_TEST_BOT.test(email)) continue;
    if (soloEmail && email !== soloEmail.toLowerCase()) continue;
    const tags = (c.tags || []).map(t => String(t).toLowerCase());
    const lang = tags.includes('lang-it') || (!tags.some(t => t.startsWith('lang-')) && c.countryCode === 'IT') ? 'it' : 'en';
    for (const t of tags.filter(t => t.startsWith('pa-'))) {
      const handle = t.slice(3);
      if (soloHandle && handle !== soloHandle) continue;
      out.coppie++;
      const p = await paProdotto(handle, cache);
      if (!p || !p.attivo || !p.base) { out.saltati++; continue; }
      const k = 'pa:v1:' + email + ':' + handle;
      let st = null; try { st = JSON.parse(await kvGet(k) || 'null'); } catch (_) {}
      if (!st) {
        // prezzo di riferimento = prezzo pieno del sito (senza Black Friday). Chi si è iscritto prima del 27/11 riceve l'avviso BF.
        st = { base: p.base, at: new Date().toISOString(), sent: null }; await kvSet(k, JSON.stringify(st)); out.nuovi++;
        const primaBf = String(c.createdAt || '9999').slice(0, 10) < PA_BF.da;
        if (!soloEmail && !(p.bf && primaBf)) continue;
      }
      if (st.sent && !soloEmail) continue;
      const calo = st.base - p.eff;
      const soglia = Math.min(20, st.base * 0.05);
      const scatta = p.disponibile && calo > 0 && calo >= soglia;
      if (!scatta && !soloEmail) continue;
      let vecchio = soloEmail && !scatta ? p.base : st.base;
      let nuovo = p.eff, bfx = p.bf, pctx = p.pct;
      if (soloEmail && testBf > 0) { vecchio = p.base; nuovo = Math.round(p.base * (100 - testBf) / 100); bfx = true; pctx = testBf; }
      const d = { title: p.title, nuovo, vecchio, base: p.base, rrp: p.rrp, bf: bfx, pct: pctx };
      const url = 'https://tluxy.com' + (lang === 'it' ? '/it' : '') + '/products/' + handle + '?utm_source=omnisend&utm_medium=email&utm_campaign=avviso-prezzo';
      const props = { ...paTesti(lang, d), product_title: p.title, product_brand: p.brand, product_url: url, product_image: p.img, price_new: paEuro(nuovo), price_old: paEuro(vecchio), price_rrp: paEuro(p.rrp), lowest_30d: paEuro(p.base), is_black_friday: bfx, price_new_num: nuovo };
      const voce = { email, handle, vecchio, nuovo, bf: bfx, lang };
      if (live || soloEmail) {
        const r = await fetch('https://api.omnisend.com/api/events', { method: 'POST', headers: h, body: JSON.stringify({ eventName: 'price dropped', origin: 'api', eventVersion: '', contact: { email }, properties: props }) });
        voce.inviato = r.ok; voce.status = r.status;
        if (r.ok && !soloEmail) { st.sent = new Date().toISOString(); st.sentPrice = nuovo; await kvSet(k, JSON.stringify(st)); }
        if (!r.ok) voce.errore = (await r.text()).slice(0, 200);
      }
      out.invii.push(voce);
    }
  }
  return out;
}


// ============ v5.65 RICHIESTE AVVISO PREZZO → OFFERTA PERSONALE (codice 48h + email "Allegra" da concierge@tluxy.it) ============
// Il prezzo del prodotto NON viene mai toccato (i marketplace lo seguono): lo sconto è un codice Shopify personale,
// 1 utilizzo, solo su quel prodotto, valido 48 ore. L'email la manda Alessio dalla casella concierge (bottone "Scrivi").
const PA_MIN_MARGINE_EUR = 25, PA_MIN_MARGINE_PCT = 0.10, PA_FEE = 0.02, PA_IVA = 1.22;
function paMargine(prezzo, costo) { const netto = prezzo / PA_IVA; return netto - costo - prezzo * PA_FEE; }
function paPrezzoMinimo(prezzo, costo) {
  if (!costo) return null;
  for (let x = Math.floor(prezzo); x > 0; x--) {
    const m = paMargine(x, costo), soglia = Math.max(PA_MIN_MARGINE_EUR, PA_MIN_MARGINE_PCT * x / PA_IVA);
    if (m < soglia) return x + 1 <= prezzo ? x + 1 : null;
  }
  return 1;
}
async function paDettaglio(handle) {
  const d = await shopifyGraphQL(`query($h:String!){ productByHandle(handle:$h){ id title vendor handle status featuredImage{ url } variants(first:100){ nodes{ price compareAtPrice availableForSale inventoryItem{ unitCost{ amount } } } } } }`, { h: handle });
  const p = d && d.productByHandle; if (!p) return null;
  const disp = p.variants.nodes.filter(v => v.availableForSale).sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
  const v = disp[0] || p.variants.nodes[0];
  const prezzo = v ? parseFloat(v.price) : 0;
  const costo = v && v.inventoryItem && v.inventoryItem.unitCost ? parseFloat(v.inventoryItem.unitCost.amount) : 0;
  const minimo = paPrezzoMinimo(prezzo, costo);
  return { id: p.id, title: p.title, brand: p.vendor, handle: p.handle, attivo: p.status === 'ACTIVE', disponibile: disp.length > 0, img: p.featuredImage ? p.featuredImage.url : '',
           prezzo, costo, margine: costo ? Math.round(paMargine(prezzo, costo)) : null, prezzo_minimo: minimo, sconto_max_pct: minimo ? Math.max(0, Math.floor((1 - minimo / prezzo) * 100)) : null };
}
function paEmailAllegra(lang, o) {
  const it = lang === 'it';
  const scad = new Date(o.scade).toLocaleString(it ? 'it-IT' : 'en-GB', { timeZone: 'Europe/Rome', weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });
  const subject = it ? `Una proposta per lei: ${o.title}` : `A personal offer for you: ${o.title}`;
  const body = it
    ? `Buongiorno,\n\nho visto che segue ${o.title} su T.LUXY. Per lei ho riservato un prezzo speciale: ${paEuro(o.nuovo)} invece di ${paEuro(o.prezzo)}.\n\nLe basta inserire il codice ${o.code} al checkout. Il codice è personale ed è valido 48 ore, fino a ${scad}.\n\nEcco il link diretto:\n${o.url}\n\nResto a disposizione per qualsiasi domanda su taglia, condizioni o spedizione.\n\nUn caro saluto,\nAllegra\nPersonal Concierge · T.LUXY\nhttps://tluxy.com`
    : `Hello,\n\nI noticed you are following ${o.title} on T.LUXY. I have reserved a special price for you: ${paEuro(o.nuovo)} instead of ${paEuro(o.prezzo)}.\n\nJust enter the code ${o.code} at checkout. The code is personal and valid for 48 hours, until ${scad}.\n\nHere is the direct link:\n${o.url}\n\nI remain at your disposal for any question about size, condition or shipping.\n\nKind regards,\nAllegra\nPersonal Concierge · T.LUXY\nhttps://tluxy.com`;
  return { subject, body, mailto: 'mailto:' + encodeURIComponent(o.email) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body) };
}
async function paRichieste() {
  const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
  const h = { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Accept': 'application/json' };
  const contatti = []; let after = '';
  for (let i = 0; i < 10; i++) {
    const r = await fetch('https://api.omnisend.com/api/contacts?tag=price-alert&limit=250' + (after ? '&after=' + encodeURIComponent(after) : ''), { headers: h });
    if (!r.ok) throw new Error('Omnisend contacts HTTP ' + r.status);
    const j = await r.json(); contatti.push(...(j.contacts || []));
    const nx = j.paging && j.paging.cursors && j.paging.cursors.after;
    if (!(j.paging && j.paging.hasMore) || !nx) break; after = nx;
  }
  const prodotti = new Map(); const righe = [];
  for (const c of contatti) {
    const email = String(c.email || '').toLowerCase(); if (!email || EMAIL_TEST_BOT.test(email)) continue;
    const tags = (c.tags || []).map(t => String(t).toLowerCase());
    const lang = tags.includes('lang-it') || (!tags.some(t => t.startsWith('lang-')) && c.countryCode === 'IT') ? 'it' : 'en';
    const stato = (c.identifiers || []).find(x => x.type === 'email')?.channels?.email?.status || c.status;
    for (const t of tags.filter(t => t.startsWith('pa-'))) {
      const handle = t.slice(3);
      if (!prodotti.has(handle)) { try { prodotti.set(handle, await paDettaglio(handle)); } catch (e) { prodotti.set(handle, null); } }
      let offerta = null; try { offerta = JSON.parse(await kvGet('pa:offer:' + email + ':' + handle) || 'null'); } catch (_) {}
      righe.push({ email, nome: [c.firstName, c.lastName].filter(Boolean).join(' '), paese: c.countryCode || '', lang, stato, dal: c.createdAt, handle, prodotto: prodotti.get(handle), offerta });
    }
  }
  return righe;
}
// v5.68: PREZZO RISERVATO 24h — link personale (sconto Shopify invisibile, si applica da solo) + email automatica del Concierge via Omnisend (evento "price reserved")
function paTestiRiservato(lang, o) {
  const it = lang === 'it';
  const scad = new Date(o.scade).toLocaleString(it ? 'it-IT' : 'en-GB', { timeZone: 'Europe/Rome', weekday: 'long', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });
  return it ? {
    subject: `Variazione di prezzo: ${o.title}`, preheader: 'Un prezzo solo per te, valido 24 ore.',
    eyebrow: 'Solo per te · 24 ore', headline: 'Ti abbiamo riservato un prezzo',
    intro: `Ci avevi chiesto di avvisarti. Per le prossime 24 ore questo pezzo ha un prezzo pensato solo per te.`,
    expiry_line: `Il tuo prezzo è valido fino a ${scad}`, cta: 'Vedi il tuo prezzo',
    note: 'Nessun codice da inserire: aprendo il link il prezzo è già applicato. Il prezzo vale finché il pezzo è disponibile.',
    signature: 'Il tuo Personal Concierge T.LUXY', trust: 'Originale garantito · Spedizione assicurata · Reso facile',
    footer: 'Stai ricevendo questa email perché c’è stata una variazione di prezzo sull’articolo che segui.', unsub_label: "Annulla l'iscrizione"
  } : {
    subject: `Price change: ${o.title}`, preheader: 'A price just for you, valid for 24 hours.',
    eyebrow: 'Just for you · 24 hours', headline: "We've reserved a price for you",
    intro: `You asked us to let you know. For the next 24 hours this piece has a price set aside just for you.`,
    expiry_line: `Your price is valid until ${scad} (Italian time)`, cta: 'See your price',
    note: 'No code needed: open the link and your price is already applied. Valid while the piece is available.',
    signature: 'Your T.LUXY Personal Concierge', trust: 'Guaranteed authentic · Insured shipping · Easy returns',
    footer: 'You are receiving this email because there has been a price change on the item you are following.', unsub_label: 'Unsubscribe'
  };
}
async function paCreaOfferta({ email, handle, pct, prezzoFinale, lang }) {
  const p = await paDettaglio(handle);
  if (!p) throw new Error('Prodotto non trovato');
  if (!p.attivo || !p.disponibile) throw new Error('Prodotto non disponibile');
  let nuovo = prezzoFinale ? Math.round(prezzoFinale) : Math.round(p.prezzo * (100 - pct) / 100);
  if (!(nuovo > 0 && nuovo < p.prezzo)) throw new Error('Prezzo non valido');
  if (p.prezzo_minimo && nuovo < p.prezzo_minimo) throw new Error(`Sotto il margine minimo: il prezzo più basso consentito è ${paEuro(p.prezzo_minimo)}`);
  const sconto = Math.round((p.prezzo - nuovo) * 100) / 100;
  const code = 'RISERVATO-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const ora = new Date(), scade = new Date(ora.getTime() + 24 * 3600 * 1000);
  const d = await shopifyGraphQL(`mutation($b: DiscountCodeBasicInput!){ discountCodeBasicCreate(basicCodeDiscount: $b){ codeDiscountNode{ id } userErrors{ field message } } }`, { b: {
    title: `Prezzo riservato 24h – ${email} – ${p.title}`, code, startsAt: ora.toISOString(), endsAt: scade.toISOString(), usageLimit: 1, appliesOncePerCustomer: true,
    customerSelection: { all: true }, combinesWith: { orderDiscounts: false, productDiscounts: false, shippingDiscounts: true },
    customerGets: { value: { discountAmount: { amount: sconto, appliesOnEachItem: false } }, items: { products: { productsToAdd: [p.id] } } } } });
  const r = d.discountCodeBasicCreate;
  if (r.userErrors && r.userErrors.length) throw new Error('Shopify: ' + r.userErrors.map(e => e.message).join('; '));
  const pref = lang === 'it' ? '/it' : '';
  const dest = pref + '/products/' + handle + '?riservato=' + code + '&utm_source=concierge&utm_medium=email&utm_campaign=prezzo-riservato';
  const url = 'https://tluxy.com' + pref + '/discount/' + encodeURIComponent(code) + '?redirect=' + encodeURIComponent(dest);
  const o = { email, handle, title: p.title, brand: p.brand, prezzo: p.prezzo, nuovo, sconto, code, id: r.codeDiscountNode.id, creata: ora.toISOString(), scade: scade.toISOString(), url, lang };
  await kvSetEx('pa:res:' + code, 2 * 86400, JSON.stringify({ handle, prezzo: p.prezzo, nuovo, scade: o.scade }));
  // invio email del Concierge (automazione Omnisend "T.LUXY Concierge – Prezzo riservato 24h", evento "price reserved")
  try {
    const KEY = (process.env.OMNISEND_API_KEY || '').trim().replace(/^["']|["']$/g, '');
    const props = { ...paTestiRiservato(lang, o), product_title: p.title, product_brand: p.brand, product_url: url, product_image: p.img ? p.img + (p.img.includes('?') ? '&' : '?') + 'width=800' : '', price_new: paEuro(nuovo), price_old: paEuro(p.prezzo), saving: paEuro(sconto), handle, code, expires_at: o.scade };
    const er = await fetch('https://api.omnisend.com/api/events', { method: 'POST', headers: { 'Authorization': 'Omnisend-API-Key ' + KEY, 'Omnisend-Version': '2026-03-15', 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify({ eventName: 'price reserved', origin: 'api', eventVersion: '', contact: { email }, properties: props }) });
    o.email_inviata = er.ok; if (!er.ok) o.email_errore = 'Omnisend ' + er.status + ' ' + (await er.text()).slice(0, 160);
  } catch (e) { o.email_inviata = false; o.email_errore = e.message; }
  await kvSetEx('pa:offer:' + email + ':' + handle, 90 * 86400, JSON.stringify(o));
  return o;
}
async function paRiservatoPubblico(code) {
  const c = String(code || '').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 40);
  if (!/^RISERVATO-[0-9A-F]{8}$/.test(c)) return null;
  let v = null; try { v = JSON.parse(await kvGet('pa:res:' + c) || 'null'); } catch (_) {}
  if (!v || new Date(v.scade) <= new Date()) return null;
  return { handle: v.handle, prezzo: v.prezzo, nuovo: v.nuovo, scade: v.scade };
}


const PA_PAGE = `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Avvisi prezzo · TLuxy</title>
<style>
:root{--bg:#F3EEE7;--fg:#1a1a1a;--mut:#5c5249;--line:#d9d1c6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;background:var(--bg);padding:16px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;z-index:2}
h1{font:600 20px Georgia,serif;margin:0;letter-spacing:.02em}a.back{color:var(--fg);font-size:15px}
main{max-width:720px;margin:0 auto;padding:16px}.mut{color:var(--mut);font-size:14px}
.card{background:#fff;padding:16px;margin:0 0 14px;display:grid;grid-template-columns:84px 1fr;gap:14px}
.card img{width:84px;height:84px;object-fit:contain;background:#f6f3ef}
.t{font-weight:600}.row{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;align-items:center}
button,.btn{min-height:44px;padding:0 16px;border:1px solid #000;background:#fff;color:#000;font:600 14px inherit;letter-spacing:.04em;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}
button.pri,.btn.pri{background:#000;color:#fff}button:disabled{opacity:.35;cursor:not-allowed}
input{min-height:44px;width:110px;padding:0 10px;border:1px solid var(--line);font-size:16px}
.of{grid-column:1/-1;background:var(--bg);padding:14px;margin-top:4px}.of pre{white-space:pre-wrap;font:14px/1.5 inherit;margin:10px 0;background:#fff;padding:12px}
.code{font:700 18px ui-monospace,Menlo,monospace;letter-spacing:.04em}.err{color:#b23a2a;font-size:14px;margin-top:6px}
.badge{display:inline-block;font-size:12px;padding:2px 8px;border:1px solid var(--line);margin-left:6px}
</style></head><body><header><h1>Avvisi prezzo</h1><a class="back" href="/">← ERP</a></header><main><p class="mut">Clienti che hanno chiesto di essere avvisate se il prezzo scende. Il prezzo pubblico non cambia: riservi un prezzo solo per lei per 24 ore. Il Concierge le manda subito l'email con il link personale (il prezzo si applica da solo, nessun codice da inserire).</p><div id="l" class="mut">Carico…</div></main>
<script>
const eur=n=>'€'+Number(n).toLocaleString('it-IT',{maximumFractionDigits:2});
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function offertaHtml(o){const sc=new Date(o.scade);const att=sc>new Date();return '<div class="of"><div><b>Prezzo riservato</b> '+eur(o.nuovo)+' invece di '+eur(o.prezzo)+' · '+(att?'valido fino a ':'scaduto ')+sc.toLocaleString('it-IT',{weekday:'short',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'})+'</div><div class="mut" style="margin-top:6px">'+(o.email_inviata?'✓ Email del Concierge inviata a '+esc(o.email):(o.email_inviata===false?'⚠ Email non inviata: '+esc(o.email_errore||''):''))+'</div>'+(o.url?'<div class="row"><a class="btn" href="'+esc(o.url)+'" target="_blank" rel="noopener">Apri il link della cliente</a><button onclick="navigator.clipboard.writeText(this.dataset.t);this.textContent=&quot;Copiato ✓&quot;" data-t="'+esc(o.url)+'">Copia link</button></div>':'')+'</div>';}
async function carica(){const r=await fetch('/api/avvisi');const j=await r.json();const el=document.getElementById('l');
if(!j.success){el.textContent='Errore: '+(j.error||'');return}
if(!j.righe.length){el.innerHTML='Nessuna richiesta per ora. Ti arriva una notifica quando una cliente attiva l\\'avviso.';return}
el.innerHTML=j.righe.map((x,i)=>{const p=x.prodotto||{};const max=p.sconto_max_pct;const b=[5,10,15,20].map(v=>'<button '+(max!=null&&v>max?'disabled':'')+' onclick="offri('+i+','+v+')">−'+v+'%</button>').join('');
return '<div class="card" id="c'+i+'"><img src="'+esc(p.img)+'" alt=""><div><div class="t">'+esc(p.brand)+' · '+esc(p.title||x.handle)+'</div><div class="mut">'+esc(x.nome||'')+' '+esc(x.email)+' <span class="badge">'+esc(x.paese||x.lang)+'</span>'+(x.stato!=='subscribed'?'<span class="badge">'+esc(x.stato)+'</span>':'')+'</div><div class="mut">Prezzo '+eur(p.prezzo||0)+(p.margine!=null?' · margine '+eur(p.margine):'')+(max!=null?' · sconto max '+max+'% (min '+eur(p.prezzo_minimo)+')':' · costo mancante')+(p.disponibile===false?' · <b>esaurito</b>':'')+'</div><div class="row">'+b+'<input type="number" inputmode="decimal" placeholder="€ finale" id="p'+i+'"><button class="pri" onclick="offri('+i+',0)">Riserva prezzo 24h</button></div><div class="err" id="e'+i+'"></div></div>'+(x.offerta?offertaHtml(x.offerta):'')+'</div>'}).join('');window._r=j.righe}
async function offri(i,pct){const x=window._r[i];const pf=pct?0:parseFloat(document.getElementById('p'+i).value);const e=document.getElementById('e'+i);e.textContent='';
if(!pct&&!(pf>0)){e.textContent='Scegli una percentuale o scrivi il prezzo finale.';return}
if(!confirm('Riservo il prezzo per 24 ore a '+x.email+' ('+(pct?'−'+pct+'%':eur(pf))+') e il Concierge le manda subito l\\'email. Confermi?'))return;
const r=await fetch('/api/avvisi/offerta',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:x.email,handle:x.handle,pct,prezzoFinale:pf,lang:x.lang})});const j=await r.json();
if(!j.success){e.textContent=j.error||'Errore';return}const c=document.getElementById('c'+i);const old=c.querySelector('.of');if(old)old.remove();c.insertAdjacentHTML('beforeend',offertaHtml(j.offerta))}
carica();
</script></body></html>`;

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
  const meseADataSito = () => {
    const [yy, mm, dd] = romaOggi.split('-').map(Number);
    const inizioMese = romeDateTimeToUTC(`${yy}-${String(mm).padStart(2, '0')}-01`, '00:00:00').getTime();
    const py = mm === 1 ? yy - 1 : yy, pm = mm === 1 ? 12 : mm - 1;
    const giorniPrec = new Date(Date.UTC(py, pm, 0)).getUTCDate();
    const inizioPrec = romeDateTimeToUTC(`${py}-${String(pm).padStart(2, '0')}-01`, '00:00:00').getTime();
    const ddPrec = Math.min(dd, giorniPrec);
    const fineGiornoPrec = romeDateTimeToUTC(`${py}-${String(pm).padStart(2, '0')}-${String(ddPrec).padStart(2, '0')}`, '00:00:00').getTime() + (now - inizioOggi);
    const nomi = ['gennaio','febbraio','marzo','aprile','maggio','giugno','luglio','agosto','settembre','ottobre','novembre','dicembre'];
    const corrente = somma(sito.filter(r => r.t >= inizioMese && r.t < now));
    const precedente = somma(sito.filter(r => r.t >= inizioPrec && r.t < fineGiornoPrec));
    return { mese: nomi[mm - 1], mese_prec: nomi[pm - 1], corrente, precedente, variazione_pct: varPct(corrente.fatturato, precedente.fatturato) };
  };
  sezioni.push({ key: 'TLUXY_SITE', nome: 'TLuxy diretto', confronto: 'Oggi vs ieri alla stessa ora', stato: 'info',
    oggi, ieri_stessa_ora: ieriStessaOra, variazione_pct: varPct(oggi.fatturato, ieriStessaOra.fatturato), ieri, altro_ieri: altroIeri, variazione_ieri_pct: varPct(ieri.fatturato, altroIeri.fatturato),
    settimana: settimana('TLUXY_SITE'),
    mese: meseADataSito(),
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
  const tuttiAltri = altriKeys.map(k => { const w = settimana(k); const nome = (MARKETPLACE_CONFIGS[k] && MARKETPLACE_CONFIGS[k].nome) || k; return { key: k, nome, ...w }; });
  // v5.40: un canale "altro" oltre €2000 negli ultimi 7 giorni diventa una card grande
  const SOGLIA_CARD = 2000;
  tuttiAltri.filter(a => a.corrente.fatturato > SOGLIA_CARD).forEach(a => sezioni.push({ ...a, confronto: 'Ultimi 7 giorni vs 7 precedenti', stato: 'ok', giorno: giorno(a.key) }));
  const altri = tuttiAltri.filter(a => a.corrente.fatturato <= SOGLIA_CARD)
    .sort((a, b) => (b.corrente.fatturato - a.corrente.fatturato) || (b.precedente.fatturato - a.precedente.fatturato));
  // ordine card: per incasso ultimi 7 giorni, TLuxy diretto sempre seconda
  sezioni.forEach(x => { x.incasso_7gg = x.key === 'TLUXY_SITE' ? x.settimana.corrente.fatturato : (x.corrente ? x.corrente.fatturato : settimana(x.key).corrente.fatturato); });
  const sito7 = sezioni.find(x => x.key === 'TLUXY_SITE');
  const ordinate = sezioni.filter(x => x.key !== 'TLUXY_SITE').sort((a, b) => b.incasso_7gg - a.incasso_7gg);
  if (sito7) ordinate.splice(Math.min(1, ordinate.length), 0, sito7);
  return { generato_il: new Date().toISOString(), alerts, sezioni: ordinate, altri };
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
        if (v.id && parseFloat(v.compare_at_price) > 0) VARIANT_CMP[v.id] = parseFloat(v.compare_at_price);
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
  // v5.43: Balardi (iva_esente + prezzo_ordine_netto) → il prezzo dell'ordine Shopify è già l'incasso: niente IVA, niente sconto
  if (mp.iva_esente) iva_scorporata = 0;
  const prezzo_netto_iva = prezzo_lordo - iva_scorporata;
  const prezzo_netto_marketplace = prezzo_netto_iva * (1 - (mp.prezzo_ordine_netto ? 0 : mp.sconto_percentuale) / 100);
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
    const ivaPerc = (riconosciMarketplace(ordine).config || {}).iva_esente ? 0 : getIvaPerPaese(country);
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
// ============ VENDITE DUOMO (v5.42) ============
// Pezzi DUOMO venduti oggi / 7 / 30 giorni con margine netto dopo tutti i costi (stessa logica di Best Seller).
let CACHE_DUO_VENDITE = null;
function calcolaVenditeDuo(ordini, variantCosts) {
  const D = 86400000, now = Date.now();
  const inizioOggi = romeDateTimeToUTC(getRomeDateString(), '00:00:00').getTime();
  const fin = { oggi: inizioOggi, giorni7: now - 7 * D, giorni30: now - 30 * D };
  const out = {}; Object.keys(fin).forEach(k => { out[k] = { pezzi: 0, ordini: 0, fatturato: 0, margine: 0, lordo_con_costo: 0, senza_costo: 0 }; });
  for (const ordine of ordini) {
    if (ordine.cancelled_at || getOrderRefundInfo(ordine).isFullRefund) continue;
    const t = new Date(ordine.created_at).getTime(); if (isNaN(t) || t < fin.giorni30) continue;
    const items = ordine.line_items || [];
    if (!items.some(it => isDuoSku(it.sku))) continue;
    const ordCurrency = ordine.currency || SHOP_CURRENCY;
    const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
    const ivaPerc = getIvaPerPaese(country);
    const mp = riconosciMarketplace(ordine); const chKey = mp.key;
    const lineeLordo = items.map(it => toEurAmount(it.price_set, it.price, ordCurrency) * (parseInt(it.quantity) || 0));
    const sommaLinee = lineeLordo.reduce((a, b) => a + b, 0);
    let incassoNettoOrd = null;
    if (chKey !== 'MARK_FOYS' && mp.config && sommaLinee > 0) {
      const curI = getOrderCurrencyInfo(ordine), refI = getOrderRefundInfo(ordine);
      const lordoOrd = Math.max(0, (curI.eurTotal || 0) - (refI.totalRefundedEur || 0));
      const sped = (ordine.shipping_lines || []).reduce((s2, l) => s2 + toEurAmount(l.price_set, l.price, curI.originalCurrency), 0);
      const tax = toEurAmount(ordine.total_tax_set, ordine.total_tax, curI.originalCurrency);
      const ivaO = chKey === 'POIZON' ? 22 : (chKey === 'REFLAUNT' ? 0 : ivaPerc);
      const ivaOrd = tax > 0 ? tax * (curI.eurTotal > 0 ? lordoOrd / curI.eurTotal : 1) : (lordoOrd - lordoOrd / (1 + ivaO / 100));
      incassoNettoOrd = calcolaMarginalita(lordoOrd, ivaOrd, 0, sped, mp.config, chKey).margine_netto;
    }
    const contati = new Set();
    items.forEach((item, idx) => {
      if (!isDuoSku(item.sku)) return;
      const q = parseInt(item.quantity) || 0; if (!q) return;
      const mfP = chKey === 'MARK_FOYS' ? mfPrezzoRiga(item, ordine, variantCosts) : null;
      const lordo = mfP !== null ? mfP * q : lineeLordo[idx];
      const netto = mfP !== null ? lordo : (incassoNettoOrd !== null ? incassoNettoOrd * (lineeLordo[idx] / sommaLinee) : lordo / (1 + ivaPerc / 100));
      const cu = item.variant_id && variantCosts[item.variant_id] != null ? variantCosts[item.variant_id] : null;
      Object.keys(fin).forEach(k => {
        if (t < fin[k]) return;
        const w = out[k]; w.pezzi += q; w.fatturato += lordo;
        if (!contati.has(k)) { w.ordini++; contati.add(k); }
        if (cu !== null) { w.margine += netto - cu * q; w.lordo_con_costo += lordo; } else w.senza_costo += q;
      });
    });
  }
  Object.values(out).forEach(w => { w.margine_pct = w.lordo_con_costo > 0 ? Math.round(w.margine / w.lordo_con_costo * 1000) / 10 : 0; w.fatturato = Math.round(w.fatturato); w.margine = Math.round(w.margine); delete w.lordo_con_costo; });
  return { generato_il: new Date().toISOString(), ...out };
}

function calcolaBestSellersModelli(ordini, variantCosts = {}) {
  const modelli = {}, brand = {}, canaliTot = {};
  let tot = { pezzi: 0, fatturato: 0, netto: 0, ncc: 0, lcc: 0, costo: 0, ordini: 0, senza_costo: 0 };
  ordini.forEach(ordine => {
    if (ordine.cancelled_at) return;
    if (getOrderRefundInfo(ordine).isFullRefund) return;
    tot.ordini++;
    const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
    const ivaPerc = getIvaPerPaese(country);
    const ordCurrency = ordine.currency || SHOP_CURRENCY;
    const mp = riconosciMarketplace(ordine);
    const chKey = mp.key, chNome = (mp.config && mp.config.nome) || mp.key;
    // v5.41: margine dopo TUTTI i costi. Per ordine: incasso reale (sconti e rimborsi parziali inclusi) meno IVA,
    // commissioni marketplace/Shopify e spedizione; il risultato è ripartito sulle righe in proporzione al prezzo.
    const lineeLordo = (ordine.line_items || []).map(it => toEurAmount(it.price_set, it.price, ordCurrency) * (parseInt(it.quantity) || 0));
    const sommaLinee = lineeLordo.reduce((a, b) => a + b, 0);
    let incassoNettoOrd = null;
    if (chKey !== 'MARK_FOYS' && mp.config && sommaLinee > 0) {
      const curI = getOrderCurrencyInfo(ordine), refI = getOrderRefundInfo(ordine);
      const lordoOrd = Math.max(0, (curI.eurTotal || 0) - (refI.totalRefundedEur || 0));
      const sped = (ordine.shipping_lines || []).reduce((s2, l) => s2 + toEurAmount(l.price_set, l.price, curI.originalCurrency), 0);
      const ivaO = chKey === 'POIZON' ? 22 : (chKey === 'REFLAUNT' ? 0 : ivaPerc);
      const tax = toEurAmount(ordine.total_tax_set, ordine.total_tax, curI.originalCurrency);
      const ivaOrd = tax > 0 ? tax * (curI.eurTotal > 0 ? lordoOrd / curI.eurTotal : 1) : (lordoOrd - lordoOrd / (1 + ivaO / 100));
      incassoNettoOrd = calcolaMarginalita(lordoOrd, ivaOrd, 0, sped, mp.config, chKey).margine_netto;
    }
    (ordine.line_items || []).forEach((item, idx) => {
      const q = parseInt(item.quantity) || 0; if (!q) return;
      const mfP = chKey === 'MARK_FOYS' ? mfPrezzoRiga(item, ordine, variantCosts) : null;
      const lordo = mfP !== null ? mfP * q : toEurAmount(item.price_set, item.price, ordCurrency) * q;
      const netto = mfP !== null ? lordo : (incassoNettoOrd !== null ? incassoNettoOrd * (lineeLordo[idx] / sommaLinee) : lordo / (1 + ivaPerc / 100));
      const cu = item.variant_id && variantCosts[item.variant_id] != null ? variantCosts[item.variant_id] : null;
      const costo = cu !== null ? cu * q : 0;
      const ncc = cu !== null ? netto : 0;
      const lcc = cu !== null ? lordo : 0;
      const vend = (item.vendor || '').trim() || 'Altro';
      const vendKey = vend.toUpperCase();
      const titolo = (item.title || '').trim();
      const key = vendKey + '|' + titolo.toUpperCase().replace(/\s+/g, ' ');
      if (!modelli[key]) modelli[key] = { titolo, brand: vend, pezzi: 0, fatturato: 0, netto: 0, costo: 0, senza_costo: 0, ncc: 0, lcc: 0, varianti: {}, canali: {}, variant_id: item.variant_id, immagine: null, sku: item.sku || '' };
      const m = modelli[key];
      m.pezzi += q; m.fatturato += lordo; m.netto += netto; m.ncc += ncc; m.lcc += lcc; m.costo += costo; if (cu === null) m.senza_costo += q;
      const vt = item.variant_title || '—'; m.varianti[vt] = (m.varianti[vt] || 0) + q;
      if (!m.canali[chKey]) m.canali[chKey] = { nome: chNome, pezzi: 0, fatturato: 0 };
      m.canali[chKey].pezzi += q; m.canali[chKey].fatturato += lordo;
      if (!brand[vendKey]) brand[vendKey] = { brand: vend, pezzi: 0, fatturato: 0, netto: 0, ncc: 0, lcc: 0, costo: 0, sito: 0 };
      const b = brand[vendKey]; b.pezzi += q; b.fatturato += lordo; b.netto += netto; b.ncc += ncc; b.lcc += lcc; b.costo += costo; if (chKey === 'TLUXY_SITE') b.sito += lordo;
      if (!canaliTot[chKey]) canaliTot[chKey] = { key: chKey, nome: chNome, pezzi: 0, fatturato: 0 };
      canaliTot[chKey].pezzi += q; canaliTot[chKey].fatturato += lordo;
      tot.pezzi += q; tot.fatturato += lordo; tot.netto += netto; tot.ncc += ncc; tot.lcc += lcc; tot.costo += costo; if (cu === null) tot.senza_costo += q;
    });
  });
  const r0 = n => Math.round(n);
  const marg = x => x.lcc > 0 ? Math.round((x.ncc - x.costo) / x.lcc * 1000) / 10 : 0; // % sul lordo, come in Analytics
  const lista = Object.values(modelli).map(m => ({ titolo: m.titolo, brand: m.brand, pezzi: m.pezzi, fatturato: r0(m.fatturato), ricavo: r0(m.ncc - m.costo), margine_pct: marg(m), prezzo_medio: m.pezzi ? r0(m.fatturato / m.pezzi) : 0, senza_costo: m.senza_costo, variant_id: m.variant_id, sku: m.sku,
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
  await caricaPrezziMarkFoy([ordine]); await caricaCmpLoveTheSales([ordine]);
  const mp = riconosciMarketplace(ordine);
  if (mp.key === 'MARK_FOYS') { const m = calcolaMarkFoyOrdine(ordine, variantCosts, duoUserCosts); return { mp: mp.config.nome, incasso: m.incasso, margine: m.margine, pct: m.incasso > 0 ? m.margine / m.incasso * 100 : 0, mancanti: m.mancanti.length }; }
  const { costo, errori } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
  const cur = getOrderCurrencyInfo(ordine);
  const lordo = cur.eurTotal;
  const sped = (ordine.shipping_lines || []).reduce((s2, l) => s2 + toEurAmount(l.price_set, l.price, cur.originalCurrency), 0);
  const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
  const ivaPerc = mp.key === 'POIZON' ? 22 : (mp.key === 'REFLAUNT' ? 0 : getIvaPerPaese(country));
  const tax = toEurAmount(ordine.total_tax_set, ordine.total_tax, cur.originalCurrency);
  const iva = tax > 0 ? tax : (lordo - lordo / (1 + ivaPerc / 100));
  const ris = calcolaMarginalita(lordo, iva, costo, sped, mp.config, mp.key);
  return { mp: mp.config.nome, incasso: lordo, margine: ris.margine_netto, pct: lordo > 0 ? ris.margine_netto / lordo * 100 : 0, mancanti: errori.length };
}
async function inviaNotificaDuo(ordine, m) {
  const eur = n => '€' + Math.round(n || 0).toLocaleString('it-IT');
  const haDuo = (ordine.line_items || []).some(li => isDuoSku(li.sku));
  const haMM = (ordine.line_items || []).some(li => isMMSku(li.sku));
  const titolo = (haMM ? '🟣 MANTOVA MODA · ' : '') + eur(m.incasso) + ' · margine ' + eur(m.margine) + ' (' + Math.round(m.pct) + '%) · ' + m.mp + (haDuo ? ' · DUOMO' : '') + (m.mancanti ? ' · costo mancante' : '');
  const testo = '#' + ordine.order_number + '\n' + (ordine.line_items || []).map(li => '• ' + li.title + (li.variant_title ? ' – ' + li.variant_title : '') + ' ×' + li.quantity + (fornitoreSku(li.sku) ? ' (' + fornitoreSku(li.sku) + (isMMSku(li.sku) ? ' · SKU ' + li.sku : '') + ')' : '')).join('\n') + (haMM ? '\n\nDa ordinare a Mantova Moda (spedizione a TLuxy con etichetta TLuxy).\n👉 Tocca qui e premi "Invia ad Atelier" per mettere il tag ATELIER READY.' : '');
  const esiti = [];
  if (NTFY_TOPIC) {
    try { const r = await fetch('https://ntfy.sh/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ topic: NTFY_TOPIC, title: titolo, message: testo, tags: [m.margine < 0 ? 'red_circle' : (haMM ? 'purple_circle' : (haDuo ? 'large_orange_diamond' : 'shopping_bags'))], priority: haMM ? 5 : ((m.margine < 0 || haDuo) ? 4 : 3), click: ERP_PUBLIC_URL + '/?ordine=' + encodeURIComponent(ordine.order_number) + '#ordini' }) }); esiti.push('ntfy ' + r.status); } catch (e) { esiti.push('ntfy errore ' + e.message); }
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

// ============ v5.57 GIGLIO → SHOPIFY: import automatico ordini (portale supplier.giglio.com) ============
// Legge gli ordini "waiting" della boutique TLuxy su api.giglio.com e crea in Shopify un ordine per ogni ordine Giglio
// (cliente Giglio.com S.p.a., tag = numero ordine Giglio come nell'inserimento manuale, nota GIGLIO / n° / data / DDT).
// Doppioni bloccati dal tag (anche per gli ordini già inseriti a mano) e da una lista in KV.
// Se l'articolo non ha giacenza in Shopify l'ordine NON viene creato e parte un avviso (possibile no-stock).
const GIGLIO_API = 'https://api.giglio.com';
const GIGLIO_USER = process.env.GIGLIO_USER || '';
const GIGLIO_PASSWORD = process.env.GIGLIO_PASSWORD || '';
const GIGLIO_BOUTIQUE = process.env.GIGLIO_BOUTIQUE || '524';
const GIGLIO_CUSTOMER_GID = process.env.GIGLIO_CUSTOMER_GID || 'gid://shopify/Customer/7784800747732';
const GIGLIO_SYNC_PATH = '/api/cron/giglio';
const GIGLIO_ESCLUSI = ['4518633', '4518634', '4522917', '4527782'];
const GIGLIO_KV_IMPORTATI = 'giglio_importati_v1';
const GIGLIO_KV_AVVISATI = 'giglio_avvisati_v1';
const GIGLIO_KV_LOCK = 'giglio_lock_v1';
const GIGLIO_KV_ULTIMO = 'giglio_ultimo_run_v1';

async function giglioLogin() {
  if (!GIGLIO_USER || !GIGLIO_PASSWORD) throw new Error('Credenziali Giglio mancanti (GIGLIO_USER / GIGLIO_PASSWORD su Vercel)');
  const r = await fetch(GIGLIO_API + '/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: JSON.stringify({ name: GIGLIO_USER, password: GIGLIO_PASSWORD }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.auth_token) throw new Error('Login Giglio fallito (HTTP ' + r.status + ')');
  return { 'giglio-auth-token': j.auth_token, 'giglio-refresh-token': j.refresh_token || '', 'Accept': 'application/json' };
}
async function giglioOrdini(headers, status, maxPagine = 10) {
  const out = [];
  for (let p = 1; p <= maxPagine; p++) {
    const r = await fetch(`${GIGLIO_API}/orders?status=${status}&page=${p}&boutique=${GIGLIO_BOUTIQUE}`, { headers });
    if (!r.ok) throw new Error('Giglio /orders ' + status + ' HTTP ' + r.status);
    const j = await r.json();
    out.push(...(j.data || []));
    if (!j.last_page || p >= j.last_page) break;
  }
  return out;
}
async function giglioTagGiaInShopify(ids) {
  const trovati = new Set();
  for (let i = 0; i < ids.length; i += 20) {
    const blocco = ids.slice(i, i + 20);
    const q = blocco.map(id => 'tag:' + id).join(' OR ');
    const d = await shopifyGraphQL(`query($q: String!) { orders(first: 100, query: $q) { edges { node { tags } } } }`, { q });
    (d.orders?.edges || []).forEach(e => (e.node.tags || []).forEach(t => { if (blocco.includes(String(t).trim())) trovati.add(String(t).trim()); }));
  }
  return trovati;
}
async function giglioVariante(barcode) {
  const d = await shopifyGraphQL(`query($q: String!) { productVariants(first: 2, query: $q) { edges { node { id sku title price inventoryQuantity product { title status } } } } }`, { q: 'barcode:' + barcode });
  return (d.productVariants?.edges || []).map(e => e.node);
}
function giglioDataIt(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('it-IT', { timeZone: 'Europe/Rome', day: '2-digit', month: '2-digit', year: 'numeric' }); }
function giglioSkuCorto(sku) { const m = String(sku || '').match(/(\d{4,5})\s+T_/); return m ? m[1] : String(sku || ''); }

async function giglioCreaOrdine(o, v) {
  const note = `GIGLIO\n${o.c_order_id} - ${giglioSkuCorto(v.sku)}\n${giglioDataIt(o.data)}\nDDT\n(import automatico ERP · ordine Giglio ${o.ordine})`;
  const c = await shopifyGraphQL(`mutation($input: DraftOrderInput!) { draftOrderCreate(input: $input) { draftOrder { id } userErrors { field message } } }`, {
    input: { customerId: GIGLIO_CUSTOMER_GID, lineItems: [{ variantId: v.id, quantity: Math.max(1, parseInt(o.quantita) || 1) }], tags: [String(o.c_order_id), 'GIGLIO', 'GIGLIO_AUTO'], note }
  });
  const ue = c.draftOrderCreate?.userErrors || [];
  if (ue.length || !c.draftOrderCreate?.draftOrder?.id) throw new Error('draftOrderCreate: ' + JSON.stringify(ue).slice(0, 200));
  const k = await shopifyGraphQL(`mutation($id: ID!) { draftOrderComplete(id: $id, paymentPending: false) { draftOrder { order { id name } } userErrors { field message } } }`, { id: c.draftOrderCreate.draftOrder.id });
  const ue2 = k.draftOrderComplete?.userErrors || [];
  if (ue2.length) throw new Error('draftOrderComplete: ' + JSON.stringify(ue2).slice(0, 200));
  return k.draftOrderComplete?.draftOrder?.order?.name || '(creato)';
}
async function giglioNotifica(titolo, testo, urgente) {
  if (!NTFY_TOPIC) return;
  try { await fetch('https://ntfy.sh/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ topic: NTFY_TOPIC, title: titolo, message: testo.slice(0, 3800), tags: [urgente ? 'warning' : 'package'], priority: urgente ? 4 : 3, click: ERP_PUBLIC_URL + '/#ordini' }) }); } catch (_) {}
}

async function giglioImporta({ dry = false } = {}) {
  const t0 = Date.now();
  const headers = await giglioLogin();
  const attesa = await giglioOrdini(headers, 'waiting');
  const importati = new Set(JSON.parse((await kvGet(GIGLIO_KV_IMPORTATI)) || '[]').map(String));
  const avvisati = new Set(JSON.parse((await kvGet(GIGLIO_KV_AVVISATI)) || '[]').map(String));
  const ids = [...new Set(attesa.map(o => String(o.c_order_id)))];
  // Ordini da NON importare (out of stock / basso margine, decisi da Alessio 23/11/2026)
  GIGLIO_ESCLUSI.forEach(id => importati.add(id));
  const candidati = ids.filter(id => !importati.has(id));
  const inShopify = candidati.length ? await giglioTagGiaInShopify(candidati) : new Set();
  inShopify.forEach(id => importati.add(id));
  const esito = { in_attesa: attesa.length, gia_in_shopify: ids.length - candidati.length + inShopify.size, creati: [], no_stock: [], barcode_sconosciuti: [], errori: [], dry };
  for (const o of attesa) {
    const id = String(o.c_order_id);
    if (importati.has(id)) continue;
    if (Date.now() - t0 > 45000) { esito.rimandati = (esito.rimandati || 0) + 1; continue; }
    const desc = `${id} · ${o.linea} ${o.categoria || ''} ${o.colore || ''} tg.${o.taglia} · barcode ${o.barcode}`;
    try {
      const varianti = await giglioVariante(o.barcode);
      if (varianti.length !== 1) { esito.barcode_sconosciuti.push(desc + (varianti.length > 1 ? ' (barcode su più varianti)' : '')); continue; }
      const v = varianti[0];
      const qta = Math.max(1, parseInt(o.quantita) || 1);
      if ((v.inventoryQuantity || 0) < qta) { esito.no_stock.push(desc + ` · ${v.sku} (giacenza ${v.inventoryQuantity})`); continue; }
      if (dry) { esito.creati.push(`${desc} → ${v.sku} (simulato)`); continue; }
      const nome = await giglioCreaOrdine(o, v);
      importati.add(id);
      esito.creati.push(`${nome} ← ${desc} → ${v.sku}`);
    } catch (e) { console.log('[giglio] errore ordine', desc, '·', e.message); esito.errori.push(desc + ' · ' + e.message); }
  }
  if (!dry) {
    await kvSetBody(GIGLIO_KV_IMPORTATI, JSON.stringify([...importati].slice(-3000)));
    const nuoviAvvisi = [...esito.no_stock, ...esito.barcode_sconosciuti, ...esito.errori].filter(x => !avvisati.has(x.split(' · ')[0]));
    if (esito.creati.length) await giglioNotifica(`Giglio: ${esito.creati.length} ordini importati in Shopify`, esito.creati.join('\n'), false);
    if (nuoviAvvisi.length) {
      await giglioNotifica(`Giglio: ${nuoviAvvisi.length} ordini da controllare`, nuoviAvvisi.map(x => '• ' + x).join('\n'), true);
      nuoviAvvisi.forEach(x => avvisati.add(x.split(' · ')[0]));
      await kvSetBody(GIGLIO_KV_AVVISATI, JSON.stringify([...avvisati].slice(-3000)));
    }
    await kvSetBody(GIGLIO_KV_ULTIMO, JSON.stringify({ quando: new Date().toISOString(), creati: esito.creati.length, no_stock: esito.no_stock.length, barcode_sconosciuti: esito.barcode_sconosciuti.length, errori: esito.errori.length }));
  }
  esito.durata_ms = Date.now() - t0;
  return esito;
}

// ============ v5.48 LORD & TAYLOR: tag LORDANDTAYLOR + metafield custom.lord_taylor_cost ============
// Regola: prodotti ATTIVI, esclusi DUOMO (tag TLX_PRODUCT:DUO) e DIFETTO (tag o titolo).
// lord_taylor_cost = prezzo scontato (variant price) × 0,76 arrotondato per eccesso all'euro (.00).
// Se le varianti hanno prezzi diversi il prodotto non viene toccato (caso anomalo da verificare a mano).
const LT_TAG = 'LORDANDTAYLOR';
const LT_WEBHOOK_PATH = '/api/webhooks/products-lt';
const LT_SYNC_PATH = '/api/cron/lord-taylor';
const LT_TOPICS = ['products/create', 'products/update', 'inventory_levels/update'];
const CRON_SECRET = process.env.CRON_SECRET || '';
const LT_FIELDS = `id title status tags totalInventory tracksInventory variants(first: 20) { edges { node { price } } } metafield(namespace: "custom", key: "lord_taylor_cost") { id value }`;

function ltCosto(prezzo) {
  const cent = Math.round(parseFloat(prezzo) * 100);
  return (Math.ceil((cent * 76) / 10000)).toFixed(2); // aritmetica intera: niente errori float (es. 25 × 0,76)
}
function ltEscluso(p) {
  const tags = (p.tags || []).map(t => String(t).toUpperCase());
  return tags.includes('TLX_PRODUCT:DUO') || tags.includes('DIFETTO') || /DIFETTO/i.test(p.title || '');
}
// Ritorna le operazioni necessarie per un prodotto (vuoto se già allineato: evita loop di webhook).
function ltAzioni(p) {
  const haTag = (p.tags || []).includes(LT_TAG);
  const mf = p.metafield;
  if (ltEscluso(p)) return { rimuoviTag: haTag, cancellaMf: !!mf, motivo: 'escluso' };
  if (p.status !== 'ACTIVE') return { motivo: 'non attivo' };
  // v5.49: senza disponibilità (inventario tracciato a zero) → via il tag, così L&T non riceve prodotti esauriti
  if (p.tracksInventory !== false && (p.totalInventory || 0) <= 0) return { rimuoviTag: haTag, motivo: 'esaurito' };
  const prezzi = [...new Set(p.variants.edges.map(e => parseFloat(e.node.price)).filter(x => x > 0))];
  if (prezzi.length !== 1) return { motivo: 'prezzi varianti diversi' };
  const valore = ltCosto(prezzi[0]);
  return { aggiungiTag: !haTag, valore: (!mf || parseFloat(mf.value) !== parseFloat(valore)) ? valore : null, motivo: 'incluso' };
}
async function ltApplica(prodotti) {
  const ops = [], mfs = [], esito = { tag_aggiunti: 0, tag_rimossi: 0, mf_scritti: 0, mf_cancellati: 0, saltati: {} };
  for (const p of prodotti) {
    const a = ltAzioni(p);
    if (!['incluso', 'escluso', 'esaurito'].includes(a.motivo)) esito.saltati[a.motivo] = (esito.saltati[a.motivo] || 0) + 1;
    if (a.aggiungiTag) { ops.push(`tagsAdd(id: ${JSON.stringify(p.id)}, tags: ["${LT_TAG}"]) { userErrors { message } }`); esito.tag_aggiunti++; }
    if (a.rimuoviTag) { ops.push(`tagsRemove(id: ${JSON.stringify(p.id)}, tags: ["${LT_TAG}"]) { userErrors { message } }`); esito.tag_rimossi++; }
    if (a.cancellaMf) { ops.push(`metafieldsDelete(metafields: [{ ownerId: ${JSON.stringify(p.id)}, namespace: "custom", key: "lord_taylor_cost" }]) { userErrors { message } }`); esito.mf_cancellati++; }
    if (a.valore) { mfs.push({ ownerId: p.id, namespace: 'custom', key: 'lord_taylor_cost', value: a.valore }); esito.mf_scritti++; }
  }
  for (let i = 0; i < ops.length; i += 50) {
    const blocco = ops.slice(i, i + 50).map((o, k) => `o${k}: ${o}`).join('\n');
    await shopifyGraphQL(`mutation { ${blocco} }`);
  }
  for (let i = 0; i < mfs.length; i += 25) {
    const d = await shopifyGraphQL(`mutation($m: [MetafieldsSetInput!]!) { metafieldsSet(metafields: $m) { userErrors { message } } }`, { m: mfs.slice(i, i + 25) });
    const err = d?.metafieldsSet?.userErrors || []; if (err.length) console.log('[lord-taylor] metafieldsSet', JSON.stringify(err).slice(0, 300));
  }
  return esito;
}
async function ltSincronizzaProdotto(gid) {
  const d = await shopifyGraphQL(`query($id: ID!) { product(id: $id) { ${LT_FIELDS} } }`, { id: gid });
  return d?.product ? ltApplica([d.product]) : null;
}
// Recupero: prodotti attivi senza tag (nuovi o persi) + prodotti esclusi che hanno ancora il tag.
async function ltSincronizzaTutto(budgetMs = 50000) {
  const t0 = Date.now(), tot = { tag_aggiunti: 0, tag_rimossi: 0, mf_scritti: 0, mf_cancellati: 0, saltati: {}, controllati: 0, completo: true };
  const ricerche = [`status:active AND inventory_total:>0 AND -tag:${LT_TAG} AND -tag:'TLX_PRODUCT:DUO' AND -tag:DIFETTO`, `tag:${LT_TAG} AND (tag:'TLX_PRODUCT:DUO' OR tag:DIFETTO)`, `tag:${LT_TAG} AND inventory_total:<=0`];
  for (const q of ricerche) {
    let after = null, giri = 0;
    while (true) {
      if (Date.now() - t0 > budgetMs) { tot.completo = false; return tot; }
      // Dopo le modifiche la ricerca non restituisce più i prodotti sistemati: si riparte sempre dall'inizio,
      // avanzando col cursore solo se nella pagina c'erano soltanto prodotti da saltare.
      const d = await shopifyGraphQL(`query($q: String!, $a: String) { products(first: 30, query: $q, after: $a) { pageInfo { hasNextPage endCursor } nodes { ${LT_FIELDS} } } }`, { q, a: after });
      const pag = d.products; tot.controllati += pag.nodes.length;
      const e = await ltApplica(pag.nodes);
      for (const k of ['tag_aggiunti', 'tag_rimossi', 'mf_scritti', 'mf_cancellati']) tot[k] += e[k];
      for (const [k, v] of Object.entries(e.saltati)) tot.saltati[k] = (tot.saltati[k] || 0) + v;
      const modificati = e.tag_aggiunti + e.tag_rimossi;
      if (!pag.pageInfo.hasNextPage) break;
      if (modificati === 0) after = pag.pageInfo.endCursor; // pagina di soli saltati: vai avanti
      if (++giri > 200) break;
      if (modificati > 0) await new Promise(r => setTimeout(r, 1500)); // lascia aggiornare l'indice di ricerca
    }
  }
  return tot;
}
async function assicuraWebhookLordTaylor() {
  const token = await getShopifyAccessToken();
  const address = ERP_PUBLIC_URL + LT_WEBHOOK_PATH, out = {};
  for (const topic of LT_TOPICS) {
    const r = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/webhooks.json?topic=${topic}`, { headers: { 'X-Shopify-Access-Token': token } });
    const j = await r.json();
    if ((j.webhooks || []).some(w => w.address === address)) { out[topic] = 'gia_presente'; continue; }
    const c = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/webhooks.json`, { method: 'POST', headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, body: JSON.stringify({ webhook: { topic, address, format: 'json' } }) });
    out[topic] = c.ok ? 'creato' : ('errore ' + c.status + ' ' + JSON.stringify(await c.json()).slice(0, 200));
  }
  return out;
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
    { brand: 'Jacquemus', cat: 'Borse', quota: 9.8, prezzo: 613, sconto: 92, yoy: null, nota: 'n.1 borse; Le Grand Bambino nero n.1 per GMV e pezzi', modelli: ['Le Grand Bambino nero · €652 · sell-through 61%', 'The Large Bambino nero · €612'], foto_web: 'https://cdn-images.farfetch-contents.com/29/88/45/90/29884590_59797248_600.jpg' },
    { brand: 'Saint Laurent', cat: 'Borse', quota: 9.2, prezzo: 1939, sconto: 65, yoy: 170, nota: 'Lou Camera, Envelope, Cassandra; sell-through 100% su più modelli', modelli: ['Envelope Medium nero · €2.376 · sell-through 100%', 'Le 5 à 7 Supple Small nero · €2.817'], foto_web: 'https://saint-laurent.dam.kering.com/m/d526dcba7c6d517/eCom-600185BOW911000_A.jpg?v=7' },
    { brand: 'Marc Jacobs', cat: 'Borse', quota: 4.9, prezzo: 258, sconto: 90, yoy: -48, nota: 'tote in tela, volume ma in calo', modelli: ['The Medium Tote nero · €170', 'The Leather Mini Bag nero · €167'], foto_web: 'https://cdn-images.farfetch-contents.com/17/98/09/40/17980940_53563817_1000.jpg' },
    { brand: 'Mulberry', cat: 'Borse', quota: 3.3, prezzo: 1083, sconto: 49, yoy: -29, nota: 'ridurre', modelli: ['Lily'], foto_web: 'https://images.mulberry.com/i/mulberrygroup/G_HH8733_552G110_7?$pdp-zoom-1024px$&img404=404&v=13' },
    { brand: 'Chloé', cat: 'Borse', quota: 2.9, prezzo: 1067, sconto: 75, yoy: null, nota: 'core in Germania/Olanda', modelli: ['Marcie Mini · €1.450'], foto_web: 'https://www.chloe.com/dw/image/v2/BLMX_PRD/on/demandware.static/-/Sites-chloe-master/default/dw6c8ca41d/images/all-images/CH26SP927R3526M/4r0fGKjHRdeGetiUEgsk8w_acc4ec81.jpeg?sw=600&sfrm=png&q=90' },
    { brand: 'Gucci', cat: 'Borse', quota: 2.9, prezzo: 1440, sconto: 73, yoy: 74, nota: 'Dionysus ricerche +400%', modelli: ['Dionysus (ricerche +400%)'], foto_web: 'https://media.gucci.com/style/DarkGray_Center_0_0_490x490/1778594440/876531_FAF7S_9642_003_100_0000_Light-dionysus-small-shoulder-bag.jpg' },
    { brand: 'Ganni', cat: 'Borse', quota: 2.8, prezzo: 342, sconto: 61, yoy: 103, nota: 'Bou Bag', modelli: ['Suede Bou Bag · €475', 'Mini Bou Bag · €345'], foto_web: 'https://ganni.kleecks-cdn.com/dw/image/v2/AAWT_PRD/on/demandware.static/-/Sites-ganni-master-catalogue/default/dw5f50e909/images/images/packshots/B2070016_979_1.jpg?sh=600' },
    { brand: 'Coach', cat: 'Borse', quota: 2.6, prezzo: 405, sconto: 35, yoy: 40, nota: 'Tabby', modelli: ['Tabby Shoulder · €495', 'Field Tote 22 · €425'], foto_web: 'https://coach.scene7.com/is/image/Coach/ccx04_b4mpl_a0' },
    { brand: 'Balenciaga', cat: 'Borse', quota: 2.6, prezzo: 2150, sconto: 58, yoy: 66, nota: '', modelli: ['Le Cagole (riferimento)'], foto_web: 'https://balenciaga.dam.kering.com/m/14b9682b34a160cf/Medium-6713091VG9Y1000_H.jpg?v=4' },
    { brand: 'Isabel Marant', cat: 'Borse', quota: 2.3, prezzo: 371, sconto: 75, yoy: 40, nota: '', modelli: ['Oscan Soft Zip · €850', 'Bahia · €550'], foto_web: 'https://www.net-a-porter.com/variants/images/1647597349483271/ou/w2000_q60.jpg' },
    { brand: 'Tory Burch', cat: 'Borse', quota: 2.0, prezzo: 428, sconto: 87, yoy: null, nota: '', modelli: ['Ella Patent Tote · €345'], foto_web: 'https://n.nordstrommedia.com/it/2d5ef11d-3ce3-4362-b4f3-ca780a943269.jpeg?w=780&h=1170&crop=pad' },
    { brand: 'Celine', cat: 'Borse', quota: 1.7, prezzo: 2114, sconto: 50, yoy: -19, nota: 'ridurre acquisti; Triomphe resta desiderata in Polonia', modelli: ['Triomphe (la più desiderata in Polonia)', 'Luggage (ricerche +245%)'], foto_web: 'https://www.celine.com/on/demandware.static/-/Sites-masterCatalog/default/dw36f0bdd8/images/large/187363BF4.38NO_1_SS24_W_V5.jpg' },
    { brand: 'Burberry', cat: 'Borse', quota: 1.6, prezzo: 861, sconto: 90, yoy: null, nota: '', modelli: ['Borsa a spalla check beige · €815 · sell-through 100%'], foto_web: 'https://assets.burberry.com/is/image/Burberryltd/B4579917-0A46-44D8-94C4-B9930E57CE82?$BBY_V3_SL_1$&wid=600&hei=600' },
    { brand: 'Valentino Garavani', cat: 'Borse', quota: 1.6, prezzo: 1398, sconto: 81, yoy: null, nota: '' },
    { brand: 'Toteme', cat: 'Borse', quota: 1.5, prezzo: 840, sconto: 71, yoy: 878, nota: 'T-Lock: nuovo eroe quiet luxury', modelli: ['T-Lock Top-Handle · €890'], foto_web: 'https://toteme.com/cdn/shop/files/TOTEME_SS23_BAGS_232-9103-612_T-LOCK_TOP_HANDLE_SOLID_BLACK_1_GB_2a033a90-0950-4b6a-ae3e-cfab7fd6b4dc.jpg?v=1731414043&width=600' },
    { brand: 'Dragon Diffusion', cat: 'Borse', quota: 1.5, prezzo: 386, sconto: 47, yoy: 55, nota: 'intrecciato, Sud Europa', modelli: ['Santa Croce Small · €432', 'Half Moon Tote · €495'], foto_web: 'https://dragondiffusion.com/cdn/shop/files/dragon-diffusion-leather-bag-handmade-santa-croce-small-black-1.webp?v=1721735908&width=600' },
    { brand: 'Dolce & Gabbana', cat: 'Borse', quota: 1.4, prezzo: 1254, sconto: 79, yoy: -17, nota: 'ridurre' },
    { brand: 'Prada', cat: 'Borse', quota: 1.2, prezzo: 1709, sconto: 66, yoy: 71, nota: 'Re-Edition', modelli: ['Re-Edition 2005'], foto_web: 'https://www.prada.com/content/dam/pradabkg_products/1/1BH/1BH204/R064F0002/1BH204_R064_F0002_V_V9L_SLO.jpg' },
    { brand: 'Fendi', cat: 'Borse', quota: 1.2, prezzo: 1680, sconto: 54, yoy: null, nota: 'Baguette e Spy in forte domanda nel resale', modelli: ['Baguette', 'Spy'], foto_web: 'https://static.fendi.com/dam/is/image/fendi/8BR600AT57F15ZW_01?wid=600&hei=600&hash=8d6719182feadb9918a823edf161af18-19f8e3f7857' },
    { brand: "Tod's", cat: 'Borse', quota: 1.1, prezzo: 1309, sconto: 83, yoy: null, nota: '' },
    { brand: 'Michael Kors', cat: 'Borse', quota: 1.1, prezzo: 210, sconto: 88, yoy: 31, nota: '', modelli: ['Parker Crossbody · €375'], foto_web: 'https://assets.michaelkors.com/transform/ECOM_Image_Large/e77b11b3-e8c2-44a0-8be2-f872d8ea5650/32H3G7PC3B-099-0160_1-tif' },
    { brand: 'Yuzefi', cat: 'Borse', quota: 1.0, prezzo: 596, sconto: 39, yoy: 1841, nota: 'Fortune Cookie Hobo', modelli: ['Fortune Cookie Hobo · €449'], foto_web: 'https://cdn-images.farfetch-contents.com/24/26/50/76/24265076_54308107_600.jpg' },
    { brand: 'DeMellier', cat: 'Borse', quota: 1.0, prezzo: 559, sconto: 56, yoy: 655, nota: 'New York Tote, Alexandria', modelli: ['New York Tote · €560', 'Mini Alexandria · €375'], foto_web: 'https://demellierlondon.com/cdn/shop/files/The-New-York-work-bag-black-small-grain-1.jpg?v=1763106744&width=600' },
    { brand: 'Acne Studios', cat: 'Borse', quota: 0.8, prezzo: 1288, sconto: 42, yoy: 51, nota: 'Musubi', modelli: ['Musubi Tote in pelle · €1.500'], foto_web: 'https://www.net-a-porter.com/variants/images/1647597343833467/ou/w2000_q60.jpg' },
    { brand: 'Diesel', cat: 'Borse', quota: null, prezzo: 450, sconto: null, yoy: 161, nota: 'volume driver', modelli: ['Camera Bag · €450'], foto_web: 'https://diesel.com/dw/image/v2/BBLG_PRD/on/demandware.static/-/Sites-diesel-master-catalog/default/dw946e356e/images/large/X10223_PR818_T8013_G.jpg?q=80' },
    { brand: 'Bottega Veneta', cat: 'Borse', quota: null, prezzo: null, sconto: null, yoy: null, nota: 'intrecciato: icona SS27 artigianale; Veneta Hobo ricerche +146%', modelli: ['Intrecciato Cabat / Andiamo · €3.800', 'Veneta Hobo (ricerche +146%)'], foto_web: 'https://www.net-a-porter.com/variants/images/1647597326482827/ou/w2000_q60.jpg' },
    { brand: 'Miu Miu', cat: 'Borse', quota: null, prezzo: null, sconto: null, yoy: null, nota: 'Aventure (intrecciato) tra i riferimenti SS27', modelli: ['Aventure · €2.500'], foto_web: 'https://www.miumiu.com/content/dam/miumiubkg_products/5/5BG/5BG291/2BBLF0NBL/5BG291_2BBL_F0NBL_V_OON_SLF.jpg' },
    { brand: 'UGG', cat: 'Scarpe', quota: 8.7, prezzo: 162, sconto: 13, yoy: null, nota: 'Tasman/Tazz: pantofole +101% donna, +120% uomo', modelli: ['Tasman II / Tazz II · €150', 'Classic Ultra Mini · €168'], foto_web: 'https://dms.deckers.com/ugg/image/upload/t_product-xlarge-wp/v1741285640/1174470-CHE_1.png?_s=RAABAB0' },
    { brand: 'Golden Goose', cat: 'Scarpe', quota: 8.6, prezzo: 486, sconto: 9, yoy: 21, nota: 'Super-Star; uomo 6,5% +19%', modelli: ['Super-Star bianca · €520', 'Ball Star bianca · €488'], foto_web: 'https://static2.goldengoose.com/public/Style/ECOMM/GWF00105.F003347-10220.jpg' },
    { brand: 'Autry', cat: 'Scarpe', quota: 4.7, prezzo: 168, sconto: 16, yoy: 32, nota: 'Medalist; n.1 uomo 7,5%', modelli: ['Medalist Low · €195'], foto_web: 'https://static.autry-usa.com/articoli/sneakers_medalist_low_in_pelle_bianca_848190_dettaglio_02_20260709112554.jpg' },
    { brand: 'Hogan', cat: 'Scarpe', quota: 3.7, prezzo: 348, sconto: 20, yoy: null, nota: 'core Centro Europa', modelli: ['H461'], foto_web: 'https://cdn.germainecollard.com/proxy/97260_1.JPG/' },
    { brand: 'Moon Boot', cat: 'Scarpe', quota: 3.2, prezzo: 194, sconto: 17, yoy: 38, nota: '', modelli: ['Icon Nylon nero · €182', 'Icon Low nero · €160'], foto_web: 'https://cdn-images.farfetch-contents.com/17/75/58/52/17755852_50575637_1000.jpg' },
    { brand: 'Philippe Model', cat: 'Scarpe', quota: 5.6, prezzo: 218, sconto: 30, yoy: 46, nota: 'uomo: PRSX n.1', modelli: ['PRSX Basic bianca · €306', 'PRSX Tennis blu · €209'], foto_web: 'https://cdn.shopify.com/s/files/1/0771/7204/8174/files/PRLU__1011_1.png?v=1699405441&width=600' },
    { brand: 'Premiata', cat: 'Scarpe', quota: 1.8, prezzo: 232, sconto: 15, yoy: null, nota: '', modelli: ['Belle · €280', 'Lus · €290'], foto_web: 'https://www.premiata.us/cdn/shop/files/BEL07813_4_0b9bfcce-7c8b-4b22-b710-17306a7a08e5.jpg?crop=center&height=750&v=1769168622&width=600' },
    { brand: 'Christian Louboutin', cat: 'Scarpe', quota: 1.2, prezzo: 726, sconto: 8, yoy: 169, nota: 'Kate 100; Polonia +349%', modelli: ['Kate 100 nera · €741'], foto_web: 'https://us.christianlouboutin.com/media/catalog/product/3/1/3191411bk01-3191411bk01-main_image-ecommerce-fw19_kate_100_patent.jpg' },
    { brand: 'Inuikii', cat: 'Scarpe', quota: 1.1, prezzo: 223, sconto: 23, yoy: 130, nota: '', modelli: ['Classic Low suede · €285'], foto_web: 'https://www.inuikii.com/cdn/shop/files/1001.001.0092.152_3.jpg?v=1787260530&width=600' },
    { brand: 'ALOHAS', cat: 'Scarpe', quota: 1.0, prezzo: 166, sconto: 9, yoy: 71, nota: '', modelli: ['Cassidy Mule · €195'], foto_web: 'https://images.urbndata.com/is/image/FreePeople/101193597_012_d/?$a15-pdp-detail-shot$&fit=constrain&qlt=80&wid=640' },
    { brand: 'Prada', cat: 'Scarpe', quota: 0.8, prezzo: 803, sconto: 18, yoy: 142, nota: '', modelli: ['Monolith loafer (riferimento)'], foto_web: 'https://www.prada.com/content/dam/pradabkg_products/1/1D6/1D649M/B4LF0002/1D649M_B4L_F0002_F_G055_SLR.jpg' },
    { brand: 'Gucci', cat: 'Scarpe', quota: 1.9, prezzo: 608, sconto: 29, yoy: 138, nota: 'uomo', modelli: ['Mocassino (Polonia)'], foto_web: 'https://media.gucci.com/style/DarkGray_Center_0_0_490x490/1702979103/307929_BLM00_1000_002_100_0000_Light-mens-horsebit-1953-loafer.jpg' },
    { brand: 'Dior', cat: 'Scarpe', quota: 1.0, prezzo: 812, sconto: 24, yoy: 115, nota: 'uomo; B22', modelli: ['B22'], foto_web: 'https://i.ebayimg.com/images/g/1l8AAeSwLDNqBZ6w/s-l1200.jpg' },
    { brand: 'Red Wing Shoes', cat: 'Scarpe', quota: 1.3, prezzo: 307, sconto: 18, yoy: 374, nota: 'uomo, Iron Ranger', modelli: ['Iron Ranger · €380'], foto_web: 'https://embed.widencdn.net/img/redwing/vhngyoup5h/1200x1200px/RW08111C_MUL_N1_0418.webp?keep=S&position=S&crop=no&color=F2F2F2' },
    { brand: 'Timberland', cat: 'Scarpe', quota: 1.2, prezzo: 167, sconto: 20, yoy: 101, nota: 'uomo, 6-Inch', modelli: ['Premium 6-Inch marrone · €210'], foto_web: 'https://assets.timberland.com/images/t_img/f_auto,h_600,e_sharpen:60,w_600/dpr_2.0/v1741199070/TB110061713-HERO/Mens-Timberland-Premium-6Inch-Waterproof-Boot-TBL-Wheat-Nubuck-HERO.png' },
    { brand: 'Santoni', cat: 'Scarpe', quota: 2.6, prezzo: 552, sconto: 20, yoy: 30, nota: 'uomo', modelli: ['Carlo suede loafer · €890'], foto_web: 'https://cdn-images.farfetch-contents.com/22/67/05/73/22670573_53534889_600.jpg' },
    { brand: 'Maison Margiela', cat: 'Scarpe', quota: 1.2, prezzo: 607, sconto: 9, yoy: 36, nota: 'uomo, Replica/Tabi', modelli: ['Replica', 'Tabi'], foto_web: 'https://www.mrporter.com/variants/images/1647597278218578/ou/w2000_q60.jpg' },
    { brand: 'Axel Arigato', cat: 'Scarpe', quota: 3.4, prezzo: 238, sconto: 10, yoy: -55, nota: 'ridurre', modelli: ['Clean 90 · €230'], foto_web: 'https://www.mrporter.com/variants/images/1647597336654577/ou/w2000_q60.jpg' },
    { brand: 'Off White', cat: 'Scarpe', quota: 2.0, prezzo: 407, sconto: 16, yoy: -39, nota: 'ridurre' },
    { brand: 'Stuart Weitzman', cat: 'Scarpe', quota: 0.8, prezzo: 344, sconto: 34, yoy: -40, nota: 'ridurre', modelli: ['Nudistia · €425'], foto_web: 'https://m.media-amazon.com/images/I/615xkhRHJtL._AC_UY900_.jpg' },
    { brand: 'Salomon', cat: 'Scarpe', quota: null, prezzo: 160, sconto: null, yoy: null, nota: 'XT-6: trail sneaker, forte in UK/USA', modelli: ['XT-6 · €160'], foto_web: 'https://cdn.dam.salomon.com/75c57008-3baf-486b-8538-b37900898a7d/L45416900/PNG-2000px-max-72dpi.png?width=600&fit=cover&optimize=medium&bg-color=f5f5f5&format=pjpg' },
    { brand: 'New Balance', cat: 'Scarpe', quota: 2.1, prezzo: 152, sconto: 15, yoy: null, nota: '550/327, 1906R', modelli: ['1906R · €175', '550 / 327'], foto_web: 'https://nb.scene7.com/is/image/NB/u1906567_nb_02_i?$pdpflexf2$&wid=440&hei=440' }
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
    --ease-out: cubic-bezier(0.23, 1, 0.32, 1); --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);
    --dur-press: 160ms; --dur-fast: 150ms; --dur-base: 200ms;
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
  .tab { flex: 1; min-width: 130px; padding: 14px 20px; border: none; background: transparent; border-radius: var(--radius-md); cursor: pointer; font-family: var(--font-main); font-weight: 700; font-size: 0.82rem; color: var(--gray-700); transition: background-color var(--dur-base) var(--ease-out), color var(--dur-base) var(--ease-out); letter-spacing: 0.06em; text-transform: uppercase; }
  .tab:hover { background: var(--gray-100); color: var(--black); }
  .tab.active { background: var(--black); color: var(--white); }
  .tab-content { display: none; animation: tab-fade var(--dur-fast) var(--ease-out); }
  .tab-content.active { display: block; }
  @keyframes fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes tab-fade { from { opacity: 0; } }
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
  .period-btn { padding: 10px 22px; border: none; background: transparent; border-radius: 50px; cursor: pointer; font-family: var(--font-main); font-weight: 700; font-size: 0.78rem; color: var(--gray-700); transition: background-color var(--dur-base) var(--ease-out), color var(--dur-base) var(--ease-out); letter-spacing: 0.06em; text-transform: uppercase; }
  .period-btn:hover { color: var(--black); }
  .period-btn.active { background: var(--white); color: var(--black); box-shadow: var(--shadow-sm); }
  .custom-range { display: flex; align-items: center; gap: 8px; background: var(--white); border: 1.5px solid var(--gray-200); border-radius: 50px; padding: 6px 8px 6px 18px; }
  .custom-range label { font-size: 0.72rem; font-weight: 700; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.06em; }
  .custom-range input[type="date"] { border: none; background: transparent; font-family: var(--font-main); font-size: 0.85rem; color: var(--black); padding: 6px 8px; cursor: pointer; }
  .custom-range input[type="date"]:focus { outline: none; }
  .custom-range .apply-btn { background: var(--black); color: var(--white); border: none; padding: 8px 18px; border-radius: 50px; font-family: var(--font-main); font-size: 0.72rem; font-weight: 700; cursor: pointer; text-transform: uppercase; letter-spacing: 0.06em; transition: background 0.2s; }
  .custom-range .apply-btn:hover { background: var(--green-dark); }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .kpi { background: var(--white); border: 1px solid var(--gray-200); border-radius: var(--radius-md); padding: 24px; transition: border-color var(--dur-base) var(--ease-out); position: relative; overflow: hidden; }
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
  .form-group input, .form-group select { padding: 13px 16px; border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); font-size: 0.95rem; font-family: var(--font-main); background: var(--white); color: var(--black); transition: border-color var(--dur-base) var(--ease-out), box-shadow var(--dur-base) var(--ease-out); }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--green-primary); box-shadow: 0 0 0 3px rgba(0,128,96,0.1); }
  .btn-primary { background: var(--black); color: var(--white); border: none; padding: 16px 32px; border-radius: var(--radius-md); font-size: 0.85rem; font-family: var(--font-main); font-weight: 700; cursor: pointer; width: 100%; margin-top: 20px; transition: background-color var(--dur-base) var(--ease-out), box-shadow var(--dur-base) var(--ease-out), transform var(--dur-press) var(--ease-out); letter-spacing: 0.08em; text-transform: uppercase; }
  .btn-primary:hover { background: var(--green-dark); }
  .results { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-top: 28px; }
  .result-card { background: var(--gray-100); border-radius: var(--radius-md); padding: 18px; border: 1.5px solid transparent; transition: background-color var(--dur-base) var(--ease-out), border-color var(--dur-base) var(--ease-out); }
  .result-card.positive { background: var(--green-light); border-color: var(--green-primary); }
  .result-card.negative { background: var(--red-light); border-color: var(--red); }
  .result-label { font-size: 0.68rem; color: var(--gray-500); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 8px; }
  .result-value { font-family: var(--font-main); font-size: 1.25rem; font-weight: 700; color: var(--black); letter-spacing: 0.01em; }
  .mp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
  .mp-card { background: var(--white); border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); padding: 24px; cursor: pointer; transition: border-color var(--dur-base) var(--ease-out), box-shadow var(--dur-base) var(--ease-out), transform var(--dur-base) var(--ease-out); }
  .mp-card:hover { border-color: var(--green-primary); }
  .mp-name { font-family: var(--font-main); font-size: 1.1rem; font-weight: 700; color: var(--black); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .mp-pay { font-size: 0.7rem; color: var(--gray-500); margin-bottom: 14px; letter-spacing: 0.04em; }
  .mp-fees { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem; color: var(--gray-700); }
  .mp-fees strong { color: var(--gray-500); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 2px; font-weight: 700; }
  .bs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; }
  .bs-card { background: var(--white); border: 1.5px solid var(--gray-200); border-radius: var(--radius-md); overflow: hidden; transition: border-color var(--dur-base) var(--ease-out), box-shadow var(--dur-base) var(--ease-out), transform var(--dur-base) var(--ease-out); position: relative; }
  .bs-card:hover { border-color: var(--gold); }
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
  .ric-forn { border: 1px solid var(--gray-200); border-radius: 12px; padding: 10px 12px 4px; margin-bottom: 10px; } .ric-forn-h { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 0.86rem; } .ric-forn .ric-it { font-size: 0.82rem; } .ric-forn .ric-it .bs2-m { margin-left: 4px; } .ric-forn .ric-img { background: var(--gray-100); }
  .ric-ta { width: 100%; box-sizing: border-box; font-family: inherit; font-size: 0.82rem; line-height: 1.5; padding: 12px; border: 1px solid var(--gray-200); border-radius: 12px; background: #fff; resize: vertical; margin-bottom: 8px; }
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
  .traffic { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 10px 0 4px; }
  .traffic .t-kpi { background: var(--white); border: 1px solid #ECE8DF; border-radius: 14px; padding: 12px 14px; }
  .traffic .t-val { font-size: 1.35rem; font-weight: 700; font-variant-numeric: tabular-nums; margin-top: 2px; }
  .traffic .t-sub { font-size: 0.72rem; color: var(--gray-500); margin-top: 2px; }
  .traffic .t-bars { grid-column: 1 / -1; display: flex; align-items: flex-end; gap: 3px; height: 54px; padding: 4px 2px 0; }
  .traffic .t-bar { flex: 1 1 0; min-width: 2px; background: #D9D3C7; border-radius: 3px 3px 0 0; position: relative; }
  .traffic .t-bar.last { background: var(--black); }
  .traffic .t-axis { grid-column: 1 / -1; display: flex; justify-content: space-between; font-size: 0.66rem; color: var(--gray-500); margin-top: -4px; }
  .traffic .t-kpi.t-click { cursor: pointer; } .traffic .t-kpi.t-click:hover { border-color: #CFC7B8; }
  .traffic .t-more { font-size: 0.7rem; color: var(--gray-500); margin-left: 4px; }
  .traffic .t-src { grid-column: 1 / -1; background: var(--white); border: 1px solid #ECE8DF; border-radius: 14px; padding: 6px 14px; }
  .traffic .t-src-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 4px 12px; align-items: center; padding: 8px 0; border-bottom: 1px solid #F1EEE8; font-variant-numeric: tabular-nums; }
  .traffic .t-src-row:last-child { border-bottom: 0; }
  .traffic .t-src-name { font-weight: 600; font-size: 0.86rem; min-width: 0; }
  .traffic .t-src-name small { display: block; font-weight: 400; color: var(--gray-500); font-size: 0.72rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .traffic .t-src-n { font-size: 0.86rem; text-align: right; }
  .traffic .t-src-c { font-size: 0.72rem; color: var(--gray-500); text-align: right; min-width: 64px; }
  .traffic .t-src-bar { grid-column: 1 / -1; height: 4px; background: #F1EEE8; border-radius: 2px; overflow: hidden; }
  .traffic .t-src-bar span { display: block; height: 100%; background: var(--black); }
  .traffic .t-nl { grid-column: 1 / -1; display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .traffic .t-nl .t-val { font-size: 1.15rem; }
  .traffic .t-nl .t-neg { font-size: 0.8rem; color: var(--gray-500); }
  .traffic .t-nl { flex-direction: column; align-items: stretch; gap: 6px; }
  .traffic .nl-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
  .traffic .nl-tot { font-size: 0.78rem; font-weight: 600; padding: 3px 10px; border-radius: 999px; background: #EEF4EF; color: #2F5A3A; white-space: nowrap; }
  .traffic .nl-main { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .traffic .nl-d { font-size: 0.78rem; font-weight: 600; color: var(--gray-500); }
  .traffic .nl-d.up { color: #1F7A3E; } .traffic .nl-d.down { color: #B3261E; }
  .traffic .nl-click { cursor: pointer; } .traffic .nl-click:focus-visible { outline: 2px solid #2F5A3A; outline-offset: 2px; }
  .traffic .nl-form { border-top: 1px solid var(--gray-200, #e5e5e5); margin-top: 6px; padding-top: 6px; display: flex; flex-direction: column; gap: 8px; }
  .traffic .nl-fr { display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: "n v" "b b" "s s"; gap: 2px 8px; }
  .traffic .nl-fn { grid-area: n; font-size: 0.85rem; font-weight: 600; min-width: 0; }
  .traffic .nl-fv { grid-area: v; font-weight: 600; font-variant-numeric: tabular-nums; }
  .traffic .nl-fb { grid-area: b; height: 6px; background: #EEF1EE; border-radius: 3px; overflow: hidden; }
  .traffic .nl-fb span { display: block; height: 100%; background: #2F5A3A; border-radius: 3px; } .traffic .nl-fb span.alt { background: #9AA59C; }
  .traffic .nl-fs { grid-area: s; font-size: 0.72rem; color: var(--gray-500); }
  .traffic .nl-off { font-size: 0.65rem; font-weight: 500; color: #8a6d1f; background: #F6EBDC; padding: 1px 6px; border-radius: 6px; }
  .traffic .nl-cmp { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-top: 4px; }
  .traffic .nl-c { border: 1px solid var(--gray-200, #e5e5e5); border-radius: 8px; padding: 6px 8px; min-width: 0; }
  .traffic .nl-ck { font-size: 0.7rem; color: var(--gray-500); text-transform: uppercase; letter-spacing: .04em; }
  .traffic .nl-cv { font-weight: 600; font-size: 0.95rem; }
  .traffic .nl-cs { font-size: 0.7rem; color: var(--gray-500); }
  @media (max-width: 520px) { .traffic .nl-cmp { grid-template-columns: 1fr; } }
  .traffic .t-err { grid-column: 1 / -1; font-size: 0.75rem; color: var(--gray-500); }
  .perf-grid { margin: 0 0 4px; } #perf-ieri { margin: 8px 0 12px; } #perf-ieri:empty { display: none; } .perf-range { margin-bottom: 14px; }
  .last-orders { margin: -12px 0 24px; border: 1px solid var(--gray-200, #e8e2d6); border-radius: 14px; background: #fff; overflow: hidden; }
  .lo-head { display: flex; justify-content: space-between; align-items: center; padding: 10px 16px; font-size: 0.8rem; color: var(--gray-700); letter-spacing: 0.02em; border-bottom: 1px solid var(--gray-200, #e8e2d6); }
  .lo-count { font-size: 0.72rem; color: var(--gray-500); }
  .lo-list { position: relative; max-height: 204px; overflow-y: auto; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; scroll-snap-type: y proximity; }
  .lo-row { display: grid; grid-template-columns: 1fr auto; gap: 2px 10px; padding: 9px 16px; border-bottom: 1px solid #f1ede5; scroll-snap-align: start; min-height: 68px; box-sizing: border-box; }
  .lo-row:last-child { border-bottom: 0; }
  .lo-flag { font-size: 1rem; line-height: 1; }
  .lo-top { display: flex; align-items: center; gap: 6px; font-size: 0.78rem; min-width: 0; }
  .lo-num { font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; flex-shrink: 1; }
  .lo-top > :not(.lo-num) { flex-shrink: 0; white-space: nowrap; }
  .lo-time { color: var(--gray-500); font-size: 0.72rem; }
  .lo-mp { display: inline-block; color: #fff; font-size: 0.62rem; font-weight: 600; padding: 2px 7px; border-radius: 10px; white-space: nowrap; }
  .lo-forn { display: inline-block; font-size: 0.6rem; font-weight: 700; letter-spacing: .04em; padding: 1px 5px; border-radius: 4px; margin-right: 5px; background: #ECE8DF; color: #5A5347; vertical-align: 1px; }
  .lo-forn-mm { background: #EDE4F7; color: #5B2E91; }
  .lo-atl { grid-column: 1 / -1; grid-row: 3; margin-top: 4px; font-size: 0.72rem; }
  .lo-atl-ok { color: #2F6B3A; font-weight: 600; }
  .lo-atl-btn { font: inherit; font-size: 0.72rem; font-weight: 600; padding: 4px 10px; border-radius: 6px; border: 1px solid #5B2E91; background: #fff; color: #5B2E91; cursor: pointer; }
  .lo-atl-btn:hover { background: #EDE4F7; } .lo-atl-btn:disabled { opacity: .6; cursor: default; }
  .lo-items { grid-column: 1; font-size: 0.74rem; color: var(--gray-700); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .lo-price { grid-column: 2; grid-row: 1; text-align: right; font-weight: 600; font-size: 0.82rem; font-variant-numeric: tabular-nums; }
  .lo-marg { grid-column: 2; grid-row: 2; text-align: right; font-size: 0.74rem; font-weight: 600; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .lo-row.lo-hit { background: #FFF6DC; transition: background .6s; }
  .lo-marg.pos { color: #00704a; } .lo-marg.neg { color: var(--red, #bf4747); }
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
    .breakdown-table .mp-badge { font-size: 0.7rem; padding: 3px 8px; max-width: 110px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
    .breakdown-table .toggle-arrow { width: 10px; margin-right: 0; }
    .breakdown-table td:first-child, .breakdown-table th:first-child { box-shadow: 1px 0 0 var(--gray-200); }
    .results, .mp-grid, .duo-grid, .form-grid { grid-template-columns: 1fr; }
    .results { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .btn-primary { padding: 14px 20px; }
  }

  /* v5.53 HIG Apple: contrasto (>= 4.5:1) e tap target (>= 44x44 pt) */
  :root { --gray-500: #6B6B6B; }
  .apply-btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 44px; background: var(--black); color: var(--white); border: none; padding: 10px 18px; border-radius: 50px; font-family: var(--font-main); font-size: 0.78rem; font-weight: 600; letter-spacing: 0.04em; cursor: pointer; transition: filter 0.2s; }
  .apply-btn:hover { filter: brightness(1.2); }
  .tab, .period-btn, .inv-filter, .alerts-refresh, #logoutBtn, summary { min-height: 44px; }
  .tab, .period-btn, .inv-filter { display: inline-flex; align-items: center; justify-content: center; }
  summary { display: flex; align-items: center; }
  .alerts-refresh { padding: 10px 16px; }
  .header-info p { opacity: 1; }
  .kpi-label, .ch-lab, .result-label { font-size: 0.72rem; }
  .lo-mp { font-size: 0.7rem; font-weight: 700; padding: 3px 8px; }
  @media (max-width: 768px) {
    .header-info p { opacity: 1; font-size: 0.72rem; }
    .tab { min-height: 44px; padding: 10px 16px; }
    .period-btn { min-height: 44px; padding: 10px 16px; }
    #logoutBtn { min-height: 44px !important; min-width: 44px; padding: 10px 14px !important; }
    input, select { min-height: 44px; font-size: 16px; }
    .custom-range .apply-btn { min-height: 44px; }
    .kpi-label { font-size: 0.72rem; }
    .form-grid { grid-template-columns: 1fr !important; }
    .form-group input, .form-group select { width: 100%; min-width: 0; box-sizing: border-box; }
  }
  /* v5.54 motion: hover solo con mouse */
  @media (hover: hover) and (pointer: fine) {
    .btn-primary:hover { transform: translateY(-1px); box-shadow: var(--shadow-md); }
    .mp-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); }
    .bs-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); }
  }
  /* v5.54 press feedback */
  .tab, .period-btn, .apply-btn { transition-property: background-color, color, filter, transform; transition-duration: var(--dur-base), var(--dur-base), var(--dur-base), var(--dur-press); transition-timing-function: var(--ease-out); }
  .tab:active, .period-btn:active, .btn-primary:active, .apply-btn:active { transform: scale(0.97); }
  .mp-card:active { transform: scale(0.98); }
  /* v5.54 riduci movimento */
  @media (prefers-reduced-motion: reduce) {
    .btn-primary:hover, .mp-card:hover, .bs-card:hover,
    .tab:active, .period-btn:active, .btn-primary:active, .apply-btn:active, .mp-card:active { transform: none; }
    html { scroll-behavior: auto; }
  }

  /* v5.55 calendario intervallo tipo Booking */
  .custom-range.rp-wrap { padding: 0; border: none; background: transparent; }
  .apply-btn[hidden] { display: none !important; }
  .custom-range.rp-wrap { display: block; }
  .rp-trigger { display: flex; align-items: center; gap: 10px; width: 100%; min-height: 48px; padding: 12px 18px; border: 1.5px solid var(--gray-200); border-radius: 50px; background: var(--white); font-family: var(--font-main); font-size: 0.9rem; font-weight: 600; color: var(--black); cursor: pointer; text-align: left; }
  .rp-trigger .rp-label { flex: 1; }
  .rp-trigger .rp-chev { color: var(--gray-500); font-size: 1.2rem; }
  .rp-trigger:active { transform: scale(0.98); }
  .rp-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.35); z-index: 1000; display: none; align-items: flex-end; justify-content: center; }
  .rp-overlay.open { display: flex; }
  .rp-sheet { background: var(--white); width: 100%; max-width: 480px; max-height: 88vh; border-radius: 22px 22px 0 0; display: flex; flex-direction: column; box-shadow: 0 -10px 40px rgba(0,0,0,0.15); animation: rp-up 220ms cubic-bezier(0.23,1,0.32,1); }
  @media (min-width: 769px) { .rp-overlay { align-items: center; } .rp-sheet { border-radius: 22px; } }
  @keyframes rp-up { from { transform: translateY(24px); opacity: 0; } }
  @media (prefers-reduced-motion: reduce) { .rp-sheet { animation: none; } }
  .rp-head { padding: 18px 20px 10px; border-bottom: 1px solid var(--gray-200); }
  .rp-title { display: flex; justify-content: space-between; align-items: center; }
  .rp-title b { font-family: var(--font-display); font-size: 1.35rem; font-weight: 500; }
  .rp-x { width: 44px; height: 44px; border: none; background: var(--gray-100); border-radius: 50%; font-size: 1.1rem; cursor: pointer; }
  .rp-sel { margin-top: 10px; display: flex; gap: 8px; align-items: center; font-size: 0.9rem; }
  .rp-sel span { flex: 1; padding: 10px 12px; border-radius: 12px; background: var(--gray-100); color: var(--gray-700); }
  .rp-sel span.on { background: #E8F4F0; color: var(--green-dark); font-weight: 700; box-shadow: inset 0 0 0 1.5px var(--green-primary); }
  .rp-chips { display: flex; gap: 8px; overflow-x: auto; padding: 12px 0 2px; scrollbar-width: none; }
  .rp-chips::-webkit-scrollbar { display: none; }
  .rp-chip { flex: 0 0 auto; min-height: 36px; padding: 8px 14px; border: 1.5px solid var(--gray-200); border-radius: 50px; background: var(--white); font-family: var(--font-main); font-size: 0.78rem; font-weight: 600; color: var(--black); cursor: pointer; white-space: nowrap; }
  .rp-dow { display: grid; grid-template-columns: repeat(7, 1fr); padding: 8px 14px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.06em; color: var(--gray-500); text-align: center; border-bottom: 1px solid var(--gray-200); }
  .rp-body { overflow-y: auto; padding: 0 14px 10px; -webkit-overflow-scrolling: touch; }
  .rp-month h4 { font-family: var(--font-main); font-size: 0.95rem; font-weight: 700; margin: 18px 6px 8px; text-transform: capitalize; }
  .rp-grid { display: grid; grid-template-columns: repeat(7, 1fr); row-gap: 4px; }
  .rp-d { position: relative; height: 46px; border: none; background: transparent; font-family: var(--font-main); font-size: 0.95rem; color: var(--black); cursor: pointer; padding: 0; }
  .rp-d span { position: relative; z-index: 1; display: inline-flex; width: 42px; height: 42px; align-items: center; justify-content: center; border-radius: 50%; }
  .rp-d.today span { box-shadow: inset 0 0 0 1.5px var(--gray-500); }
  .rp-d.in { background: #E8F4F0; }
  .rp-d.start, .rp-d.end { background: linear-gradient(90deg, transparent 50%, #E8F4F0 50%); }
  .rp-d.end { background: linear-gradient(90deg, #E8F4F0 50%, transparent 50%); }
  .rp-d.start.end { background: transparent; }
  .rp-d.start span, .rp-d.end span { background: var(--black); color: var(--white); font-weight: 700; }
  .rp-d:disabled { color: #C4C4C4; cursor: default; }
  .rp-d.empty { visibility: hidden; }
  .rp-foot { display: flex; gap: 10px; padding: 12px 20px calc(12px + env(safe-area-inset-bottom)); border-top: 1px solid var(--gray-200); }
  .rp-foot button { flex: 1; min-height: 50px; border-radius: 50px; font-family: var(--font-main); font-size: 0.85rem; font-weight: 700; letter-spacing: 0.04em; cursor: pointer; }
  .rp-reset { background: var(--white); border: 1.5px solid var(--gray-200); color: var(--black); }
  .rp-ok { background: var(--black); border: none; color: var(--white); }
  .rp-ok:disabled { opacity: 0.4; }
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
        <p><span class="hide-m">Business Intelligence Dashboard · </span>v5.61</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill"><div class="status-dot"></div>Live</div>
      <button id="logoutBtn" style="background:transparent; border:1px solid rgba(0,0,0,0.15); padding:8px 14px; border-radius:50px; cursor:pointer; font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:var(--gray-700); margin-left:12px; font-family:var(--font-main); transition:background-color 200ms cubic-bezier(0.23, 1, 0.32, 1);" onmouseover="this.style.background='var(--gray-100)'" onmouseout="this.style.background='transparent'">Esci</button>
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
    <div class="section">
      <div class="section-header"><div><div class="section-title">Incassi e margine</div><div class="section-subtitle">Tutti i canali · margine netto dopo IVA, commissioni, spedizione e costo merce</div></div></div>
      <div class="filter-bar">
        <div class="period-selector" data-analytics-periods>
          <button class="period-btn active" data-period="today">Oggi</button>
          <button class="period-btn" data-period="yesterday">Ieri</button>
          <button class="period-btn" data-period="week">Settimana</button>
          <button class="period-btn" data-period="month">Mese</button>
          <button class="period-btn" data-period="quarter">Trimestre</button>
          <button class="period-btn" data-period="year">Anno</button>
        </div>
      </div>
      <div class="oggi-grid perf-grid">
        <div class="oggi-kpi dark"><div class="ch-lab">Incassato</div><div class="oggi-val" id="lordo">—</div><div class="oggi-sub" id="ordini-count">— ordini</div></div>
        <div class="oggi-kpi pos" id="kpi-netto-box"><div class="ch-lab">Margine netto</div><div class="oggi-val" id="netto">—</div><div class="oggi-sub" id="margine-sub">—</div></div>
      </div>
      <div class="traffic" id="traffic-box" hidden></div>
      <div class="oggi-ieri" id="perf-ieri"></div>
      <details class="kpi-more"><summary><span>IVA e costi</span><span class="kpi-more-val" id="kpi-more-val" style="color:var(--gray-700)"></span></summary>
      <div class="kpi-grid">
        <div class="kpi"><div class="kpi-label">IVA scorporata</div><div class="kpi-value" id="iva">—</div><div class="kpi-sub">Da versare</div></div>
        <div class="kpi"><div class="kpi-label">Costi Totali</div><div class="kpi-value" id="costi">—</div><div class="kpi-split" id="costi-split" style="margin-top:8px; padding-top:8px; border-top:1px solid rgba(0,0,0,0.08); font-size:0.78rem; line-height:1.5;"><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Merce</span><span id="costi-merce" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Fees + sped.</span><span id="costi-fees" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div></div></div>
        <div class="kpi gold"><div class="kpi-label">Margine %</div><div class="kpi-value" id="margine">—</div><div class="kpi-sub">Su lordo</div></div>
      </div>
      </details>
      <div class="last-orders" id="last-orders" hidden><div class="lo-head"><span>Ordini</span><span class="lo-count" id="lo-count"></span></div><div class="lo-list" id="lo-list"></div></div>
      <div id="mese-strip" class="mese-strip"><span class="ch-lab">Calcolo il mese…</span></div>
      <div class="filter-bar perf-range">
        <div class="custom-range rp-wrap"><button type="button" class="rp-trigger" data-from="date-from" data-to="date-to" data-apply="analytics-apply"><span class="rp-ico">📅</span><span class="rp-label">Scegli le date</span><span class="rp-chev">›</span></button><input type="hidden" id="date-from"><input type="hidden" id="date-to"><button class="apply-btn" id="analytics-apply" hidden>Applica</button></div>
      </div>
      <div id="refunds-panel"></div>
      <div id="foreign-currency-panel"></div>
      <div id="errors-panel"></div>
      <div class="alerts-meta" style="margin:-6px 0 14px">Fuso orario Europa/Roma. Costo merce letto da Shopify; gli ordini senza "Cost per item" sono segnalati qui sopra.</div>
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
    <div id="alerts-banner" class="alerts-banner"></div>
    <div id="duo-vendite" class="alerts-banner"></div>
    <div id="duo-alerts" class="alerts-banner"></div>
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
        <div class="custom-range rp-wrap"><button type="button" class="rp-trigger" data-from="bs-date-from" data-to="bs-date-to" data-apply="bs-apply"><span class="rp-ico">📅</span><span class="rp-label">Scegli le date</span><span class="rp-chev">›</span></button><input type="hidden" id="bs-date-from"><input type="hidden" id="bs-date-to"><button class="apply-btn" id="bs-apply" hidden>Applica</button></div>
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
const MARKETPLACES = ${JSON.stringify(Object.fromEntries(Object.entries(MARKETPLACE_CONFIGS).filter(([k]) => k !== 'REFLAUNT')))};
function mpTextColor(hex){ var h=(hex||'#8E8E8E').replace('#',''); var c=[0,2,4].map(function(i){ var v=parseInt(h.substr(i,2),16)/255; return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4); }); var L=0.2126*c[0]+0.7152*c[1]+0.0722*c[2]; return (1.05/(L+0.05)) >= 4.5 ? '#FFFFFF' : '#1A1A1A'; }
const MP_COLORS = { REFLAUNT:'#6E8B74', TLUXY_SITE:'#1A1A1A', THE_BRADERY:'#C9A961', MIINTO:'#008060', BALARDI:'#BF4747', ITALIST:'#2D2D2D', JAMMY_DUDE:'#8E4FBF', SECRET_SALES:'#6B5320', FASHION_TAMERS:'#5C5C5C', INTRA_MIRROR:'#B89550', ARCHIVIST:'#004C3F', BOUTIQUE_MALL:'#E8573A', WINKELSTRAAT:'#479CCF', POIZON:'#D4397A', BRANDSGATEWAY:'#4A7FBC', MARK_FOYS:'#2E5F8F', GIGLIO:'#7B4F8A', ABOUT_YOU:'#E4572E', LUOSOPHY:'#B5651D', LOVE_THE_SALES:'#E8467C' };

function setActiveButton(selector, btn) { document.querySelectorAll(selector).forEach(b => b.classList.remove('active')); if (btn) btn.classList.add('active'); }
async function fetchNoCache(url) { const sep = url.includes('?') ? '&' : '?'; const res = await fetch(url + sep + '_=' + Date.now(), { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } }); return res.json(); }

function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  const tabBtn = document.querySelector('.tab[data-tab="' + name + '"]'); if (tabBtn) tabBtn.classList.add('active');
  if (name === 'compare' && !document.getElementById('compare-body').children.length) confronta();
  if (name === 'ricerche' && !RIC_DATA) caricaRicerche(false);
  if (name === 'bestsellers') { const bsContent = document.getElementById('bs-content'); if (bsContent.querySelector('.bs-empty') && !bsContent.querySelector('.bs-loading')) { const activeBtn = document.querySelector('[data-bs-periods] .period-btn.active') || document.querySelector('[data-bs-periods] .period-btn[data-period="month"]'); loadBestSellers(activeBtn ? activeBtn.dataset.period : 'month', activeBtn); } }
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

// v5.73: sigla fornitore (MM = Mantova Moda, DUO = Duomo) ovunque compaia un articolo
function fornChipSku(sku) { sku = String(sku || ''); return /^AMM-/i.test(sku) ? '<span class="lo-forn lo-forn-mm" title="Fornitore Mantova Moda">MM</span>' : (/^DUO-/i.test(sku) ? '<span class="lo-forn" title="Fornitore Duomo">DUO</span>' : ''); }
// v5.56.1: numero ordine corto (es. #miinto-b2ae…) per tenere le righe allineate
function loShortNum(n) { n = String(n || ''); return n.length > 14 ? n.slice(0, 13) + '…' : n; }
// v5.56: bandierina paese di spedizione nella lista ordini
function loFlag(cc) {
  cc = String(cc || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  var f = String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  return '<span class="lo-flag" title="' + cc + '" aria-label="Paese ' + cc + '">' + f + '</span>';
}
// v5.69: ordini Mantova Moda → bottone per il tag ATELIER READY (fa partire l'ordine su Atelier)
function loAtelierBtn(o) {
  var pronto = String(o.tags || '').split(',').some(function (t) { return t.trim().toUpperCase() === 'ATELIER READY'; });
  var n = String(o.name || ('#' + o.order_number)).replace(/[&<>"']/g, '');
  return pronto ? '<div class="lo-atl lo-atl-ok">✓ Inviato ad Atelier</div>'
    : '<div class="lo-atl"><button type="button" class="lo-atl-btn" data-name="' + n + '" data-oid="' + String(o.oid || '').replace(/[^0-9]/g, '') + '" onclick="loAtelierReady(this)">Invia ad Atelier (tag ATELIER READY)</button></div>';
}
function loAtelierReady(btn) {
  var nome = btn.getAttribute('data-name');
  if (!confirm('Aggiungo il tag ATELIER READY all’ordine ' + nome + '? Atelier lo prenderà in carico.')) return;
  btn.disabled = true; btn.textContent = 'Invio…';
  fetch('/api/ordine-atelier-ready', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: nome, oid: btn.getAttribute('data-oid') || '' }) })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.success) { btn.parentNode.className = 'lo-atl lo-atl-ok'; btn.parentNode.textContent = d.gia ? '✓ Era già inviato ad Atelier' : '✓ Inviato ad Atelier'; }
      else { btn.disabled = false; btn.textContent = 'Riprova'; alert(d.error || 'Errore'); }
    })
    .catch(function () { btn.disabled = false; btn.textContent = 'Riprova'; });
}
// v5.50: lista compatta degli ordini del periodo sotto "Costi e margine" (si vedono ~3 righe, poi si scorre)
function renderLastOrders(breakdown) {
  const box = document.getElementById('last-orders'); const list = document.getElementById('lo-list'); const cnt = document.getElementById('lo-count');
  if (!box || !list) return;
  const righe = [];
  Object.keys(breakdown || {}).forEach(function (k) { (breakdown[k].dettaglio_ordini || []).forEach(function (o) { righe.push({ k: k, nome: breakdown[k].nome, o: o }); }); });
  LAST_BD = breakdown || null; renderAds();
  if (!righe.length) { box.hidden = true; list.innerHTML = ''; return; }
  righe.sort(function (a, b) { return new Date(b.o.created_at || 0) - new Date(a.o.created_at || 0); });
  const oggi = new Date().toDateString();
  const esc = function (t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  list.innerHTML = righe.map(function (r) {
    const o = r.o; const d = o.created_at ? new Date(o.created_at) : null;
    const quando = d ? (d.toDateString() === oggi ? d.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })) : '';
    const art = (o.articoli || []).filter(function (a) { return a.quantity > 0; });
    const testo = art.length ? art.map(function (a) { return (a.quantity > 1 ? a.quantity + '× ' : '') + a.title; }).join(' · ') : '—';
    const fornChip = art.some(function (a) { return /^AMM-/i.test(a.sku || ''); }) ? '<span class="lo-forn lo-forn-mm" title="Fornitore Mantova Moda">MM</span>' : (art.some(function (a) { return /^DUO-/i.test(a.sku || ''); }) ? '<span class="lo-forn" title="Fornitore Duomo">DUO</span>' : '');
    const m = o.margine_netto || 0; const cls = m >= 0 ? 'pos' : 'neg';
    const reso = o.refund_status === 'partial' ? ' ↩️' : '';
    return '<div class="lo-row" data-ord="' + esc(String(o.order_number || '')) + '"><div class="lo-top"><span class="lo-num" title="' + esc(o.name || ('#' + o.order_number)) + '">' + esc(loShortNum(o.name || ('#' + o.order_number))) + '</span>' + loFlag(o.country) + '<span class="lo-mp" style="background:' + (MP_COLORS[r.k] || '#8E8E8E') + ';color:' + mpTextColor(MP_COLORS[r.k]) + '">' + esc(r.nome) + '</span><span class="lo-time">' + quando + reso + '</span></div>' +
      '<div class="lo-price">€' + Math.round(o.fatturato || 0).toLocaleString('it-IT') + '</div>' +
      '<div class="lo-items" title="' + esc(testo) + '">' + fornChip + esc(testo) + '</div>' +
      '<div class="lo-marg ' + cls + '">' + (m >= 0 ? '+' : '−') + '€' + Math.abs(Math.round(m)).toLocaleString('it-IT') + ' · ' + (o.margine_percentuale || 0).toFixed(1) + '%</div>' + (fornChip.indexOf('lo-forn-mm') > -1 ? loAtelierBtn(o) : '') + '</div>';
  }).join('');
  if (cnt) cnt.textContent = righe.length > 3 ? righe.length + ' · scorri per vederli tutti' : String(righe.length);
  list.scrollTop = 0; box.hidden = false;
  focusOrdineDaNotifica();
}
// v5.51: dalla notifica ntfy (?ordine=12345#ordini) si apre Analytics, si scorre al riquadro Ordini e si evidenzia l'ordine
var ORD_FOCUS_FATTO = false;
function focusOrdineDaNotifica() {
  if (ORD_FOCUS_FATTO) return;
  var qs = new URLSearchParams(location.search); var num = qs.get('ordine');
  if (!num && location.hash !== '#ordini') return;
  ORD_FOCUS_FATTO = true;
  var box = document.getElementById('last-orders'); if (!box) return;
  if (!document.getElementById('analytics-tab').classList.contains('active')) showTab('analytics');
  setTimeout(function () {
    box.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    if (!num) return;
    var row = document.querySelector('#lo-list .lo-row[data-ord="' + String(num).replace(/[^0-9A-Za-z_-]/g, '') + '"]');
    if (row) { var list = document.getElementById('lo-list'); list.scrollTop = row.offsetTop; row.classList.add('lo-hit'); setTimeout(function () { row.classList.remove('lo-hit'); }, 4000); }
  }, 250);
  try { history.replaceState(null, '', location.pathname); } catch (e) {}
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
    const mainRow = '<tr class="mp-row" data-mp-key="' + r.key + '" style="cursor:pointer"><td><span class="toggle-arrow" id="arrow-' + r.key + '">▶</span>&nbsp;<span class="mp-badge" style="background:' + color + ';color:' + mpTextColor(color) + '">' + r.nome + '</span></td><td class="num">' + r.ordini + '</td><td class="num">€' + Math.round(r.fatturato).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.iva || 0).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.costo_merce || 0).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">€' + Math.round(r.margine).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">' + marginePerc.toFixed(1) + '%</td></tr>';
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
          return '<div style="padding:4px 0; border-bottom:1px dotted var(--gray-200);">' + fornChipSku(a.sku) + '<strong style="font-size:0.82rem;">' + a.title + '</strong><br><span style="font-size:0.72rem; color:var(--gray-500);">SKU: ' + a.sku + ' · qty ' + a.quantity + '</span><br><span style="font-size:0.75rem;">Prezzo: <strong>€' + a.prezzo_unit.toFixed(2) + '</strong> · Costo: <strong>€' + a.cost_unit.toFixed(2) + '</strong> · <span style="' + badgeStyle + '" title="Margine netto per unità (dopo IVA, fees, spedizione)">Netto ' + segno + '€' + margineNettoUnit.toFixed(2) + '</span></span></div>';
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
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '...'; }); var msub = document.getElementById('margine-sub'); if (msub) msub.textContent = '…';
  document.getElementById('ordini-count').textContent = 'Caricamento (leggo costi reali)...';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;">Caricamento...</td></tr>';
  document.getElementById('breakdown-foot').innerHTML = ''; document.getElementById('errors-panel').innerHTML = ''; var loBox = document.getElementById('last-orders'); if (loBox) loBox.hidden = true;
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
      var kmv = document.getElementById('kpi-more-val'); if (kmv) kmv.textContent = 'IVA €' + Math.round(data.iva_totale).toLocaleString('it-IT') + ' · costi €' + Math.round(data.costi_totali).toLocaleString('it-IT');
      var msub = document.getElementById('margine-sub'); if (msub) msub.textContent = data.margine_percentuale.toFixed(1) + '% sul lordo';
      var nb = document.getElementById('kpi-netto-box'); if (nb) nb.className = 'oggi-kpi ' + (data.margine_netto < 0 ? 'neg' : 'pos');
      const countLabel = (data.ordini_con_errori_count > 0 ? data.ordini_totali + ' validi (' + data.ordini_con_errori_count + ' esclusi)' : data.ordini_totali + ' ordini') + ' · IVA inclusa';
      document.getElementById('ordini-count').textContent = countLabel;
      renderBreakdown(data.breakdown_marketplace);
      renderLastOrders(data.breakdown_marketplace);
      renderErrors(data.ordini_con_errori || []);
      renderForeignCurrency(data.ordini_valuta_estera || []);
      renderRefunds(data.resi || null);
      caricaTraffico(url.split('?')[1] || '');
      return true;
    }
  } catch(e) { console.error(e); }
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '—'; });
  document.getElementById('ordini-count').textContent = 'Errore caricamento';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--red);">Errore.</td></tr>';
  return false;
}

// v5.59: visite giornaliere e tasso di conversione del sito per il periodo scelto
function caricaTraffico(qs) {
  var box = document.getElementById('traffic-box'); if (!box) return;
  box.hidden = false; box.innerHTML = '<div class="t-err">Carico visite e conversione…</div>';
  fetch('/api/traffico?' + qs).then(function (r) { return r.json(); }).then(function (t) {
    if (!t || !t.success) {
      box.innerHTML = '<div class="t-err">Visite non disponibili' + (t && t.read_reports === false ? ': l’app Shopify dell’ERP non ha il permesso "Analytics" (read_reports).' : '.') + '</div>';
      return;
    }
    var gg = t.giorni || [], n = gg.length || 1, media = Math.round(t.sessioni / n);
    var it = function (v) { return Math.round(v).toLocaleString('it-IT'); };
    var html = '<div class="t-kpi t-click" role="button" tabindex="0" onclick="toggleFonti()" onkeydown="if(event.key===&quot;Enter&quot;)toggleFonti()"><div class="ch-lab">Visite sito <span class="t-more">· da dove ›</span></div><div class="t-val">' + it(t.sessioni) + '</div><div class="t-sub">' + (n > 1 ? 'media ' + it(media) + ' al giorno' : 'sessioni tluxy.com') + '</div></div>'
      + '<div class="t-kpi"><div class="ch-lab">Conversione</div><div class="t-val">' + t.conversione.toFixed(2).replace('.', ',') + '%</div><div class="t-sub">' + it(t.checkout) + ' acquisti sul sito</div></div>';
    if (gg.length > 1) {
      var max = Math.max.apply(null, gg.map(function (x) { return x.s; }).concat([1]));
      var fmt = function (d) { return d.slice(8, 10) + '/' + d.slice(5, 7); };
      html += '<div class="t-bars" aria-label="Visite giornaliere">' + gg.map(function (x, i) { return '<span class="t-bar' + (i === gg.length - 1 ? ' last' : '') + '" style="height:' + Math.max(4, Math.round(x.s / max * 100)) + '%" title="' + fmt(x.d) + ': ' + it(x.s) + ' visite · conv. ' + (x.s ? (x.o / x.s * 100).toFixed(2).replace('.', ',') : '0') + '%"></span>'; }).join('') + '</div>'
        + '<div class="t-axis"><span>' + fmt(gg[0].d) + '</span><span>' + fmt(gg[gg.length - 1].d) + '</span></div>';
    }
    box.innerHTML = html + '<div class="t-src" id="t-src" hidden></div><div class="t-kpi t-nl" id="t-nl"><span class="ch-lab">Iscritti newsletter</span><span class="t-sub">carico…</span></div><div class="t-kpi t-nl" id="t-ads"><span class="ch-lab">Pubblicità</span><span class="t-sub">carico…</span></div>';
    TRAFFICO_QS = qs;
    caricaIscritti(qs);
    caricaAds(qs);
  }).catch(function () { box.innerHTML = '<div class="t-err">Visite non disponibili.</div>'; });
}
var TRAFFICO_QS = '';
// v5.72: spesa pubblicitaria Google + Meta del periodo, ripartita sulle vendite dirette (T. Luxy proprio)
var ADS_DATA = null, LAST_BD = null;
function caricaAds(qs) {
  ADS_DATA = null;
  fetch('/api/ads-spesa?' + qs).then(function (r) { return r.json(); }).then(function (d) { ADS_DATA = d; renderAds(); }).catch(function () { var el = document.getElementById('t-ads'); if (el) el.innerHTML = '<span class="ch-lab">Pubblicità</span><span class="t-sub">non disponibile</span>'; });
}
function renderAds() {
  var el = document.getElementById('t-ads'), d = ADS_DATA; if (!el || !d) return;
  var eu = function (v) { return '€' + Math.round(v || 0).toLocaleString('it-IT'); };
  if (!d.success || !d.caricati) { el.innerHTML = '<span class="ch-lab">Pubblicità</span><span class="t-sub">' + (d.success ? 'spesa non ancora caricata per questo periodo (si aggiorna ogni notte)' : 'non disponibile') + '</span>'; return; }
  var dir = LAST_BD && LAST_BD.TLUXY_SITE ? LAST_BD.TLUXY_SITE : null;
  var g = d.canali.google ? d.canali.google.totale : 0, m = d.canali.meta ? d.canali.meta.totale : 0;
  var h = '<div class="nl-head"><span class="ch-lab nl-click" role="button" tabindex="0" onclick="toggleAds()" onkeydown="if(event.key===&quot;Enter&quot;)toggleAds()">Pubblicità Google + Meta <span class="t-more">· dove sono andati i soldi ›</span></span></div>'
    + '<div class="nl-main"><span class="t-val">' + eu(d.totale) + '</span><span class="t-neg">Google ' + eu(g) + ' · Meta ' + eu(m) + '</span></div>';
  if (dir && dir.fatturato > 0) {
    var pct = d.totale / dir.fatturato * 100, perOrd = dir.ordini ? d.totale / dir.ordini : 0, dopo = (dir.margine || 0) - d.totale;
    h += '<div class="t-neg">' + pct.toFixed(1).replace('.', ',') + '% delle vendite dirette (' + eu(dir.fatturato) + ', ' + dir.ordini + ' ordini) · ' + eu(perOrd) + ' a ordine</div>'
      + '<div class="t-neg">Margine vendite dirette dopo pubblicità: <b style="color:' + (dopo >= 0 ? 'var(--green,#2F6B3A)' : '#c0392b') + '">' + (dopo < 0 ? '−' : '') + eu(Math.abs(dopo)) + ' · ' + (dopo / dir.fatturato * 100).toFixed(1).replace('.', ',') + '%</b> (prima ' + eu(dir.margine) + ')</div>';
  }
  if (d.mancanti && d.mancanti.length) h += '<div class="t-neg">Mancano ' + d.mancanti.length + ' giorni di dati (' + d.mancanti.slice(0, 3).map(function (x) { return x.slice(8, 10) + '/' + x.slice(5, 7); }).join(', ') + (d.mancanti.length > 3 ? '…' : '') + ')</div>';
  h += '<div class="nl-form" id="ads-det" hidden></div>';
  el.innerHTML = h;
}
function toggleAds() {
  var el = document.getElementById('ads-det'), d = ADS_DATA; if (!el || !d) return;
  if (!el.hidden) { el.hidden = true; return; }
  var eu = function (v) { return '€' + Math.round(v || 0).toLocaleString('it-IT'); };
  var nomi = { google: 'Google Ads', meta: 'Meta (Facebook + Instagram)' };
  var html = '';
  ['google', 'meta'].forEach(function (c) {
    var x = d.canali[c]; if (!x) return;
    var max = Math.max.apply(null, x.campagne.map(function (k) { return k.spesa; }).concat([1]));
    html += '<div class="nl-fr" style="font-weight:700;margin-top:6px"><span>' + nomi[c] + '</span><span>' + eu(x.totale) + '</span></div>'
      + x.campagne.map(function (k) { return '<div class="nl-fr"><span title="' + k.nome.replace(/"/g, '') + '">' + k.nome.replace(/</g, '&lt;') + (k.tipo ? ' <span class="t-neg">· ' + k.tipo + '</span>' : '') + '</span><span>' + eu(k.spesa) + ' · ' + Math.round(k.spesa / (d.totale || 1) * 100) + '%</span></div><div style="height:4px;background:#EEE9DF;border-radius:2px;margin:0 0 4px"><div style="height:4px;border-radius:2px;background:' + (c === 'google' ? '#4A7FBC' : '#8E4FBF') + ';width:' + Math.max(2, Math.round(k.spesa / max * 100)) + '%"></div></div>'; }).join('');
  });
  el.innerHTML = html || '<div class="t-sub">Nessun dettaglio.</div>'; el.hidden = false;
}
function caricaIscritti(qs) {
  var el = document.getElementById('t-nl'); if (!el) return;
  fetch('/api/newsletter-iscritti?' + qs).then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success) {
      el.innerHTML = '<span class="ch-lab">Iscritti newsletter</span><span class="t-sub">' + (d && d.error === 'NO_KEY' ? 'da collegare: manca la chiave API di Omnisend' : 'non disponibili') + '</span>';
      return;
    }
    var gg = d.giorni || [], n = gg.length, it = function (v) { return Math.round(v).toLocaleString('it-IT'); };
    var delta = function (a, b) {
      if (!b) return a ? '<span class="nl-d up">▲ nuovo</span>' : '<span class="nl-d">=</span>';
      var p = Math.round((a - b) / b * 100);
      return '<span class="nl-d ' + (p > 0 ? 'up' : p < 0 ? 'down' : '') + '">' + (p > 0 ? '▲ +' : p < 0 ? '▼ ' : '= ') + p + '%</span>';
    };
    var lbl = n === 1 ? 'giorno prima' : 'periodo prima';
    var tot = d.totale && d.totale.totale ? '<span class="nl-tot" title="Contatti iscritti alla newsletter oggi">● ' + it(d.totale.totale) + ' iscritti totali</span>' : '';
    var h = '<div class="nl-head"><span class="ch-lab nl-click" role="button" tabindex="0" onclick="toggleNlForm()" onkeydown="if(event.key===&quot;Enter&quot;)toggleNlForm()">Iscritti newsletter <span class="t-more">· da quale form ›</span></span>' + tot + '</div>'
      + '<div class="nl-main"><span class="t-val">+' + it(d.iscritti) + '</span>'
      + (d.prec ? delta(d.iscritti, d.prec.iscritti) + '<span class="t-neg">vs +' + it(d.prec.iscritti) + ' ' + lbl + '</span>' : '') + '</div>'
      + '<div class="t-neg">' + it(d.disiscritti) + ' disiscritti · netto ' + (d.iscritti - d.disiscritti >= 0 ? '+' : '') + it(d.iscritti - d.disiscritti) + (n > 1 ? ' · media +' + Math.round(d.iscritti / n) + ' al giorno' : '') + (d.approx ? ' · dato mensile' : '') + '</div>' + (d.finti ? '<div class="t-sub" title="Email di test dei bot o iscritti e disiscritti entro 2 minuti">esclusi ' + it(d.finti) + ' contatti finti (bot) negli ultimi 60 giorni</div>' : '');
    if (d.confronti && d.confronti.length) h += '<div class="nl-cmp">' + d.confronti.map(function (c) { return '<div class="nl-c"><div class="nl-ck">' + c.k + '</div><div class="nl-cv">+' + it(c.a) + ' ' + delta(c.a, c.b) + '</div><div class="nl-cs">vs +' + it(c.b) + ' ' + c.vs + '</div></div>'; }).join('') + '</div>';
    h += '<div class="nl-form" id="nl-form" hidden></div>';
    NL_TOT = d.iscritti || 0;
    el.innerHTML = h;
  }).catch(function () { el.innerHTML = '<span class="ch-lab">Iscritti newsletter</span><span class="t-sub">non disponibili</span>'; });
}
var NL_TOT = 0;
function nomeForm(n) {
  n = String(n || '');
  if (/avvisami|notify me|back in stock/i.test(n)) return (n.indexOf('(IT') >= 0 ? 'Avvisami quando torna (IT)' : n.indexOf('(EN') >= 0 ? 'Notify me – back in stock (EN)' : 'Avviso disponibilità');
  if (/landing/i.test(n)) return 'Landing page newsletter';
  if (/welcome/i.test(n)) return 'Popup benvenuto −10%';
  return n;
}
function toggleNlForm() {
  var el = document.getElementById('nl-form'); if (!el) return;
  if (!el.hidden) { el.hidden = true; return; }
  el.hidden = false; el.innerHTML = '<div class="t-sub">Carico i form…</div>';
  fetch('/api/newsletter-form?' + TRAFFICO_QS).then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success) { el.innerHTML = '<div class="t-sub">Dettaglio form non disponibile.</div>'; return; }
    var it = function (v) { return Math.round(v).toLocaleString('it-IT'); };
    var rows = d.form || [], somma = rows.reduce(function (t, f) { return t + f.iscritti; }, 0);
    var max = Math.max.apply(null, rows.map(function (f) { return f.iscritti; }).concat([1]));
    var html = rows.map(function (f) {
      var conv = f.viste ? (f.invii / f.viste * 100).toFixed(1).replace('.', ',') + '% di chi lo vede' : '';
      return '<div class="nl-fr"><div class="nl-fn">' + nomeForm(f.nome) + (f.stato !== 'enabled' ? ' <span class="nl-off">spento</span>' : '') + '</div><div class="nl-fb"><span style="width:' + Math.max(3, Math.round(f.iscritti / max * 100)) + '%"></span></div><div class="nl-fv">+' + it(f.iscritti) + '</div><div class="nl-fs">' + it(f.viste) + ' visualizzazioni' + (conv ? ' · ' + conv : '') + '</div></div>';
    }).join('');
    var altri = NL_TOT - somma;
    if (altri > 0) html += '<div class="nl-fr"><div class="nl-fn">Altri canali</div><div class="nl-fb"><span class="alt" style="width:' + Math.max(3, Math.round(altri / Math.max(max, altri) * 100)) + '%"></span></div><div class="nl-fv">+' + it(altri) + '</div><div class="nl-fs">checkout, fascia/popup Black Friday del sito, concierge, import</div></div>';
    el.innerHTML = html || '<div class="t-sub">Nessuna iscrizione dai form nel periodo.</div>';
  }).catch(function () { el.innerHTML = '<div class="t-sub">Dettaglio form non disponibile.</div>'; });
}
var FONTI_NOMI = { direct: 'Diretto', search: 'Ricerca', social: 'Social', email: 'Email / newsletter', unknown: 'Altri siti', paid: 'A pagamento', referral: 'Altri siti' };
function nomeFonte(f) {
  var n = (f.nome || '').trim(), low = n.toLowerCase(), src = f.fonte;
  if (src === 'direct' || (!n && src === 'unknown')) return ['Diretto', 'digitato l’indirizzo, preferiti o app'];
  if (/google/.test(low)) return ['Google', src === 'search' ? 'ricerca' : (FONTI_NOMI[src] || src)];
  if (/instagram/.test(low)) return ['Instagram', 'Meta'];
  if (/facebook|fb\b/.test(low)) return ['Facebook', 'Meta'];
  if (/bing/.test(low)) return ['Bing', 'ricerca'];
  if (/omnisend|klaviyo|mail|newsletter/.test(low) || src === 'email') return ['Newsletter / email', n || 'email'];
  if (/chatgpt|openai/.test(low)) return ['ChatGPT', 'assistente AI'];
  if (/tiktok/.test(low)) return ['TikTok', 'social'];
  return [n || (FONTI_NOMI[src] || src || 'Altro'), FONTI_NOMI[src] || src || ''];
}
function toggleFonti() {
  var el = document.getElementById('t-src'); if (!el) return;
  if (!el.hidden) { el.hidden = true; return; }
  el.hidden = false; el.innerHTML = '<div class="t-err" style="padding:8px 0">Carico le fonti…</div>';
  fetch('/api/traffico-fonti?' + TRAFFICO_QS).then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success || !d.fonti || !d.fonti.length) { el.innerHTML = '<div class="t-err" style="padding:8px 0">Fonti non disponibili.</div>'; return; }
    var agg = {};
    d.fonti.forEach(function (f) { var nm = nomeFonte(f); var k = nm[0]; if (!agg[k]) agg[k] = { nome: k, det: nm[1], s: 0, o: 0 }; agg[k].s += f.s; agg[k].o += f.o; });
    var righe = Object.keys(agg).map(function (k) { return agg[k]; }).sort(function (a, b) { return b.s - a.s; });
    var tot = righe.reduce(function (t, x) { return t + x.s; }, 0) || 1;
    el.innerHTML = righe.slice(0, 12).map(function (x) {
      var pct = Math.round(x.s / tot * 100);
      return '<div class="t-src-row"><div class="t-src-name">' + x.nome + (x.det ? '<small>' + x.det + '</small>' : '') + '</div><div class="t-src-n">' + x.s.toLocaleString('it-IT') + ' <small style="color:var(--gray-500)">' + pct + '%</small></div><div class="t-src-c">' + x.o + ' acq. · ' + (x.s ? (x.o / x.s * 100).toFixed(1).replace('.', ',') : '0') + '%</div><div class="t-src-bar"><span style="width:' + pct + '%"></span></div></div>';
    }).join('');
  }).catch(function () { el.innerHTML = '<div class="t-err" style="padding:8px 0">Fonti non disponibili.</div>'; });
}
async function setPeriod(p, btn) { setActiveButton('[data-analytics-periods] .period-btn', btn); var pi = document.getElementById('perf-ieri'); if (pi) pi.innerHTML = ''; var ok = await fetchAnalytics('/api/analytics?periodo=' + p); if (p === 'today') caricaIeriRiga(); return ok; }
// v5.52: riga "Ieri" sotto i KPI quando il periodo è Oggi (prima stava in un box separato duplicato)
function caricaIeriRiga() {
  var el = document.getElementById('perf-ieri'); if (!el) return;
  fetch('/api/analytics?periodo=yesterday').then(function (r) { return r.json(); }).then(function (y) {
    var attivo = document.querySelector('[data-analytics-periods] .period-btn.active');
    if (!y || !y.success || !attivo || attivo.dataset.period !== 'today') return;
    el.innerHTML = 'Ieri: €' + Math.round(y.lordo_iva_inclusa).toLocaleString('it-IT') + ' incassati · margine €' + Math.round(y.margine_netto).toLocaleString('it-IT') + ' (' + (y.margine_percentuale || 0).toFixed(1) + '%) · ' + (y.ordini_totali || 0) + ' ordini';
  }).catch(function () {});
}
async function applyCustomRange() {
  const from = document.getElementById('date-from').value; const to = document.getElementById('date-to').value;
  if (!from || !to) { alert('Seleziona date'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-analytics-periods] .period-btn', null); await fetchAnalytics('/api/analytics?from=' + from + '&to=' + to);
}
async function loadBestSellers(p, btn) {
  setActiveButton('[data-bs-periods] .period-btn', btn);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty bs-loading">Caricamento prodotti...</div>';
  const req = ++BS_REQ;
  try { const data = await fetchNoCache('/api/bestsellers?periodo=' + p); if (req !== BS_REQ) return; if (data.success && data.modelli && data.modelli.length > 0) { renderBestSellers2(data); return; } cont.innerHTML = '<div class="bs-empty">' + (data.success ? 'Nessun prodotto venduto nel periodo.' : 'Errore: ' + (data.error || '')) + '</div>'; } catch(e) { if (req === BS_REQ) cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
async function applyBsCustomRange() {
  const from = document.getElementById('bs-date-from').value; const to = document.getElementById('bs-date-to').value;
  if (!from || !to) { alert('Seleziona date'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-bs-periods] .period-btn', null);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty bs-loading">Caricamento...</div>';
  const req = ++BS_REQ;
  try { const data = await fetchNoCache('/api/bestsellers?from=' + from + '&to=' + to); if (req !== BS_REQ) return; if (data.success && data.modelli && data.modelli.length > 0) { renderBestSellers2(data); return; } cont.innerHTML = '<div class="bs-empty">' + (data.success ? 'Nessun prodotto venduto nel periodo.' : 'Errore: ' + (data.error || '')) + '</div>'; } catch(e) { if (req === BS_REQ) cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
var BS_DATA = null, BS_FILTRO = 'tutti', BS_REQ = 0; // v5.45: BS_REQ scarta risposte vecchie (cambio periodo durante il caricamento)
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
  var html = '<div class="bs2-kpi"><div><span>Fatturato</span><b>' + bsEur(t.fatturato) + '</b></div><div><span>Pezzi</span><b>' + t.pezzi + '</b></div><div><span>Margine netto</span><b>' + bsEur(t.ricavo) + ' <small>' + t.margine_pct + '%</small></b></div><div><span>Di cui sito</span><b>' + bsEur(sitoTot) + ' <small>' + (t.fatturato ? Math.round(sitoTot / t.fatturato * 100) : 0) + '%</small></b></div></div>';
  html += '<div class="bs2-sec">Brand</div><div class="bs2-brands"><div class="bs2-brand bs2-bhead"><span>Brand</span><span>Fatturato</span><span>Margine</span><span>Sul sito</span></div>' + d.brand.slice(0, 10).map(function (b) {
    var sitoPct = b.fatturato ? Math.round(b.sito / b.fatturato * 100) : 0;
    return '<div class="bs2-brand"><span class="bs2-bn"><b>' + bsEsc(b.brand) + '</b><small>' + b.pezzi + ' pz · media ' + bsEur(b.pezzi ? b.fatturato / b.pezzi : 0) + '</small></span><span class="bs2-bv">' + bsEur(b.fatturato) + '<small>' + b.quota_pct + '% del totale</small></span><span class="bs2-bm"><span class="bs2-m ' + bsMargCls(b.margine_pct) + '">' + b.margine_pct + '%</span><small>' + bsEur(b.ricavo) + '</small></span><span class="bs2-bs">' + sitoPct + '%<small>' + bsEur(b.sito) + '</small></span></div>';
  }).join('') + '</div>';
  html += '<div class="bs2-head"><div class="bs2-sec" style="margin:0">Modelli più venduti</div><div class="bs2-chips">' + [['tutti', 'Tutti'], ['sito', 'Sito'], ['mp', 'Marketplace']].map(function (c) { return '<button class="bs2-chip' + (BS_FILTRO === c[0] ? ' on' : '') + '" data-f="' + c[0] + '" onclick="bsFiltro(this.dataset.f)">' + c[1] + '</button>'; }).join('') + '</div></div>';
  html += '<div class="bs2-list">' + (modelli.length ? modelli.slice(0, 30).map(function (m, i) {
    var img = m.immagine ? '<img src="' + bsEsc(m.immagine) + '&width=160" loading="lazy" alt="">' : '<span>◇</span>';
    var colori = m.varianti.slice(0, 4).map(function (v) { return bsEsc(v.nome.split(' / ')[0]) + (v.pezzi > 1 ? ' ×' + v.pezzi : ''); }).join(', ') + (m.varianti.length > 4 ? '…' : '');
    var canali = m.canali.map(function (c) { return '<span class="bs2-ch">' + bsEsc(c.nome) + ' ' + c.pezzi + ' · ' + bsEur(c.fatturato) + '</span>'; }).join('');
    return '<details class="bs2-row"><summary><span class="bs2-rank' + (i < 3 ? ' top' : '') + '">' + (i + 1) + '</span><span class="bs2-img">' + img + '</span><span class="bs2-info"><span class="bs2-t">' + fornChipSku(m.sku) + bsEsc(m.titolo) + '</span><span class="bs2-s">' + bsEsc(m.brand) + ' · ' + m.pezzi + ' pz · media ' + bsEur(m.prezzo_medio) + '</span></span><span class="bs2-num"><b>' + bsEur(m.fatturato) + '</b><span class="bs2-m ' + bsMargCls(m.margine_pct) + '">' + (m.senza_costo === m.pezzi ? 'costo ?' : m.margine_pct + '%') + '</span></span></summary>'
      + '<div class="bs2-det"><div><span class="bs2-l">Colori</span> ' + colori + '</div><div><span class="bs2-l">Canali</span> ' + canali + '</div><div><span class="bs2-l">Margine netto</span> ' + bsEur(m.ricavo) + (m.senza_costo ? ' <small>(' + m.senza_costo + ' pz senza costo in Shopify)</small>' : '') + '</div></div></details>';
  }).join('') : '<div class="bs-empty">Nessun modello per questo filtro.</div>') + '</div>';
  html += '<div class="alerts-meta" style="margin-top:10px">Margine netto = incasso reale (sconti e rimborsi inclusi) meno IVA, commissioni marketplace/Shopify, spedizione e costo merce; % sul lordo, come in Analytics. Solo pezzi con costo in Shopify. ' + (t.pezzi_senza_costo ? t.pezzi_senza_costo + ' pezzi senza costo. ' : '') + t.ordini + ' ordini, ' + t.modelli + ' modelli venduti.</div>';
  cont.innerHTML = html;
}
function renderBestSellers(prodotti) {
  const cont = document.getElementById('bs-content');
  if (!prodotti || prodotti.length === 0) { cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; return; }
  cont.innerHTML = prodotti.map((p, i) => {
    const rank = p.rank || (i + 1); const rankClass = rank <= 3 ? 'top3' : '';
    const img = p.immagine ? '<img src="' + p.immagine + '" alt="' + p.titolo + '" loading="lazy">' : '<div class="bs-image-placeholder">◇</div>';
    return '<div class="bs-card"><div class="bs-rank ' + rankClass + '">' + rank + '</div><div class="bs-image">' + img + '</div><div class="bs-body"><div class="bs-title">' + fornChipSku(p.sku) + p.titolo + '</div><div class="bs-variant">' + (p.variante || '') + (p.sku ? ' · ' + p.sku : '') + '</div><div class="bs-stats"><div class="bs-stat"><div class="bs-stat-label">Prezzo</div><div class="bs-stat-value">€' + p.prezzo_unit_lordo.toFixed(2) + '</div></div><div class="bs-stat"><div class="bs-stat-label">Pezzi</div><div class="bs-stat-value">' + p.quantita_venduta + '</div></div><div class="bs-stat fatturato"><div class="bs-stat-label">Fatturato</div><div class="bs-stat-value">€' + Math.round(p.fatturato_lordo).toLocaleString('it-IT') + '</div></div><div class="bs-stat ricavo"><div class="bs-stat-label">Ricavo</div><div class="bs-stat-value">€' + Math.round(p.ricavo_stimato).toLocaleString('it-IT') + '</div></div></div></div></div>';
  }).join('');
}
function confronta() {
  const prezzoLordo = parseFloat(document.getElementById('c-prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('c-iva').value) || 0;
  const costo = parseFloat(document.getElementById('c-costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('c-spedizione').value) || 0;
  const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100);
  const risultati = Object.entries(MARKETPLACES).map(([key, mp]) => {
    const prezzoNetto = (mp.iva_esente ? prezzoLordo : prezzoNettoIva) * (1 - mp.sconto_percentuale / 100);
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
  const prezzoNettoIva = mp.iva_esente ? prezzoLordo : prezzoLordo / (1 + ivaPerc / 100); const ivaScorporata = prezzoLordo - prezzoNettoIva;
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
  const prezzoNettoIva = mp.iva_esente ? prezzoLordo : prezzoLordo / (1 + ivaPerc / 100);
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
  const coef = (1 - scontoPerc) * (1 - totalPercFee) / (1 + (mp.iva_esente ? 0 : ivaPerc) / 100) - margineTargetPerc / 100;
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
            '<span class="mp-badge" style="background:' + color + '; font-size:0.8rem;color:' + mpTextColor(color) + '">' + mp.nome + '</span>' +
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
  if (mp.iva_esente) iva = 0; // Balardi: prezzo di vendita −35% senza scorporo IVA
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


// v5.55: calendario intervallo tipo Booking (un solo calendario: tocchi il giorno di inizio e quello di fine)
const RP_MESI = ['gennaio','febbraio','marzo','aprile','maggio','giugno','luglio','agosto','settembre','ottobre','novembre','dicembre'];
const RP_MESI_B = ['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
const rpFmt = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
const rpParse = s => { if (!s) return null; const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const rpShort = d => d.getDate() + ' ' + RP_MESI_B[d.getMonth()];
let rpState = { trig: null, start: null, end: null };
function rpLabel(trig) {
  const a = rpParse(document.getElementById(trig.dataset.from).value), b = rpParse(document.getElementById(trig.dataset.to).value);
  const lab = trig.querySelector('.rp-label');
  if (!a) { lab.textContent = 'Scegli le date'; return; }
  if (!b || +a === +b) { lab.textContent = rpShort(a) + ' ' + a.getFullYear(); return; }
  const n = Math.round((b - a) / 86400000) + 1;
  lab.textContent = rpShort(a) + ' → ' + rpShort(b) + (a.getFullYear() !== b.getFullYear() ? ' ' + b.getFullYear() : '') + ' · ' + n + ' giorni';
}
function rpBuild() {
  if (document.getElementById('rp-overlay')) return;
  const o = document.createElement('div'); o.id = 'rp-overlay'; o.className = 'rp-overlay';
  o.innerHTML = '<div class="rp-sheet" role="dialog" aria-label="Scegli intervallo di date">' +
    '<div class="rp-head"><div class="rp-title"><b>Scegli le date</b><button type="button" class="rp-x" aria-label="Chiudi">✕</button></div>' +
    '<div class="rp-sel"><span id="rp-s1">Inizio</span><span style="flex:0">→</span><span id="rp-s2">Fine</span></div>' +
    '<div class="rp-chips"><button type="button" class="rp-chip" data-q="today">Oggi</button><button type="button" class="rp-chip" data-q="yesterday">Ieri</button><button type="button" class="rp-chip" data-q="7">Ultimi 7 giorni</button><button type="button" class="rp-chip" data-q="30">Ultimi 30 giorni</button><button type="button" class="rp-chip" data-q="month">Questo mese</button><button type="button" class="rp-chip" data-q="lastmonth">Mese scorso</button></div></div>' +
    '<div class="rp-dow"><span>L</span><span>M</span><span>M</span><span>G</span><span>V</span><span>S</span><span>D</span></div>' +
    '<div class="rp-body" id="rp-body"></div>' +
    '<div class="rp-foot"><button type="button" class="rp-reset">Azzera</button><button type="button" class="rp-ok" disabled>Applica</button></div></div>';
  document.body.appendChild(o);
  o.addEventListener('click', e => { if (e.target === o) rpClose(); });
  o.querySelector('.rp-x').addEventListener('click', rpClose);
  o.querySelector('.rp-reset').addEventListener('click', () => { rpState.start = rpState.end = null; rpPaint(); });
  o.querySelector('.rp-ok').addEventListener('click', rpApply);
  o.querySelectorAll('.rp-chip').forEach(c => c.addEventListener('click', () => {
    const t = new Date(); t.setHours(0, 0, 0, 0); const q = c.dataset.q; let a, b = new Date(t);
    if (q === 'today') a = new Date(t);
    else if (q === 'yesterday') { a = new Date(t); a.setDate(a.getDate() - 1); b = new Date(a); }
    else if (q === 'month') a = new Date(t.getFullYear(), t.getMonth(), 1);
    else if (q === 'lastmonth') { a = new Date(t.getFullYear(), t.getMonth() - 1, 1); b = new Date(t.getFullYear(), t.getMonth(), 0); }
    else { a = new Date(t); a.setDate(a.getDate() - (parseInt(q) - 1)); }
    rpState.start = a; rpState.end = b; rpPaint(); rpScrollTo(a);
  }));
  const body = o.querySelector('#rp-body'); const today = new Date(); today.setHours(0, 0, 0, 0);
  let html = '';
  for (let k = 12; k >= 0; k--) {
    const m0 = new Date(today.getFullYear(), today.getMonth() - k, 1);
    const days = new Date(m0.getFullYear(), m0.getMonth() + 1, 0).getDate(); const lead = (m0.getDay() + 6) % 7;
    html += '<div class="rp-month" data-ym="' + m0.getFullYear() + '-' + m0.getMonth() + '"><h4>' + RP_MESI[m0.getMonth()] + ' ' + m0.getFullYear() + '</h4><div class="rp-grid">';
    for (let i = 0; i < lead; i++) html += '<button type="button" class="rp-d empty" tabindex="-1" aria-hidden="true"></button>';
    for (let d = 1; d <= days; d++) {
      const dt = new Date(m0.getFullYear(), m0.getMonth(), d); const fut = dt > today;
      html += '<button type="button" class="rp-d' + (+dt === +today ? ' today' : '') + '" data-d="' + rpFmt(dt) + '"' + (fut ? ' disabled' : '') + ' aria-label="' + d + ' ' + RP_MESI[m0.getMonth()] + '"><span>' + d + '</span></button>';
    }
    html += '</div></div>';
  }
  body.innerHTML = html;
  body.addEventListener('click', e => {
    const b = e.target.closest('.rp-d'); if (!b || b.disabled || !b.dataset.d) return;
    const d = rpParse(b.dataset.d);
    if (!rpState.start || rpState.end) { rpState.start = d; rpState.end = null; }
    else if (d < rpState.start) { rpState.start = d; }
    else { rpState.end = d; }
    rpPaint();
  });
}
function rpPaint() {
  const o = document.getElementById('rp-overlay'); const { start, end } = rpState;
  o.querySelectorAll('.rp-d[data-d]').forEach(b => {
    const d = rpParse(b.dataset.d); const e = end || start;
    b.classList.toggle('start', !!start && +d === +start);
    b.classList.toggle('end', !!e && +d === +e);
    b.classList.toggle('in', !!start && !!end && d > start && d < end);
  });
  const s1 = o.querySelector('#rp-s1'), s2 = o.querySelector('#rp-s2');
  s1.textContent = start ? rpShort(start) + ' ' + start.getFullYear() : 'Inizio';
  s2.textContent = end ? rpShort(end) + ' ' + end.getFullYear() : (start ? 'Tocca la fine' : 'Fine');
  s1.classList.toggle('on', !start); s2.classList.toggle('on', !!start && !end);
  if (!start) s1.classList.add('on');
  const ok = o.querySelector('.rp-ok'); ok.disabled = !start;
  ok.textContent = start ? 'Applica · ' + (Math.round(((end || start) - start) / 86400000) + 1) + ' giorni' : 'Applica';
}
function rpScrollTo(d) {
  const m = document.querySelector('.rp-month[data-ym="' + d.getFullYear() + '-' + d.getMonth() + '"]');
  if (m) m.scrollIntoView({ block: 'start' });
}
function rpOpen(trig) {
  rpBuild(); rpState.trig = trig;
  rpState.start = rpParse(document.getElementById(trig.dataset.from).value);
  rpState.end = rpParse(document.getElementById(trig.dataset.to).value);
  const o = document.getElementById('rp-overlay'); o.classList.add('open'); document.body.style.overflow = 'hidden';
  rpPaint();
  const body = o.querySelector('#rp-body');
  if (rpState.start) rpScrollTo(rpState.start); else body.scrollTop = body.scrollHeight;
  if (rpState.start && rpState.start.getMonth() === new Date().getMonth()) body.scrollTop = body.scrollHeight;
}
function rpClose() { const o = document.getElementById('rp-overlay'); if (o) o.classList.remove('open'); document.body.style.overflow = ''; }
function rpApply() {
  const t = rpState.trig; if (!t || !rpState.start) return;
  document.getElementById(t.dataset.from).value = rpFmt(rpState.start);
  document.getElementById(t.dataset.to).value = rpFmt(rpState.end || rpState.start);
  rpLabel(t); rpClose();
  document.getElementById(t.dataset.apply).click();
}
function initRangePickers() {
  document.querySelectorAll('.rp-trigger').forEach(t => { t.addEventListener('click', () => rpOpen(t)); rpLabel(t); });
}
document.addEventListener('DOMContentLoaded', () => {
  loadMarketplaces();
  // v5.46: i campi data partono da oggi (data locale, non UTC), così il calendario si apre sul mese corrente
  const today = new Date();
  const fmt = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  ['date-from', 'bs-date-from'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(today); });
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
  initRangePickers();
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
        main = rigaConfronto('Oggi finora', s.oggi, 'Ieri stessa ora', s.ieri_stessa_ora, s.variazione_pct) + rigaConfronto('Ultimi 7 giorni', s.settimana.corrente, '7 precedenti', s.settimana.precedente, s.settimana.variazione_pct)
          + (s.mese ? rigaConfronto('Dal 1° ' + s.mese.mese, s.mese.corrente, 'Stesso periodo ' + s.mese.mese_prec, s.mese.precedente, s.mese.variazione_pct) : '');
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

// ===== v5.42 Vendite DUOMO oggi / 7 / 30 giorni =====
function caricaDuoVendite(refresh) {
  var box = document.getElementById('duo-vendite'); if (!box) return;
  var head = '<div class="alerts-head"><div class="alerts-title">Vendite DUOMO</div><button class="alerts-refresh" onclick="caricaDuoVendite(true)">Aggiorna</button></div>';
  box.innerHTML = head + '<div class="alerts-meta">Calcolo vendite DUOMO…</div>';
  fetch('/api/duo-vendite' + (refresh ? '?refresh=1' : '')).then(function (r) { return r.json(); }).then(function (d) {
    if (!d || !d.success) { box.innerHTML = head + '<div class="alerts-meta">Dato non disponibile' + (d && d.error ? ': ' + escAlert(d.error) : '') + '</div>'; return; }
    var eu = function (n) { return '€' + Math.round(n || 0).toLocaleString('it-IT'); };
    var cella = function (lab, w) {
      var col = w.margine < 0 ? '#B42318' : 'var(--gray-900)';
      return '<div style="flex:1;min-width:0;padding:10px 8px;border:1px solid var(--gray-200);border-radius:12px;">'
        + '<div class="ch-lab">' + lab + '</div>'
        + '<div style="font-size:1.25rem;font-weight:600;margin:2px 0;">' + w.pezzi + ' <span style="font-size:0.75rem;font-weight:400;color:var(--gray-500);">pz</span></div>'
        + '<div style="font-size:0.8rem;color:var(--gray-700);">' + eu(w.fatturato) + '</div>'
        + '<div style="font-size:0.8rem;color:' + col + ';">margine ' + eu(w.margine) + ' · ' + w.margine_pct + '%</div>'
        + (w.senza_costo ? '<div style="font-size:0.7rem;color:var(--gray-500);">' + w.senza_costo + ' pz senza costo</div>' : '')
        + '</div>';
    };
    var ora = new Date(d.generato_il).toLocaleString('it-IT', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    box.innerHTML = head + '<div style="display:flex;gap:8px;">' + cella('Oggi', d.oggi) + cella('Ultimi 7 gg', d.giorni7) + cella('Ultimi 30 gg', d.giorni30) + '</div>'
      + '<div class="alerts-meta">Margine netto dopo IVA, commissioni, spedizione e costo · % sul lordo · aggiornato ' + ora + '</div>';
  }).catch(function () { box.innerHTML = head + '<div class="alerts-meta">Dato non disponibile.</div>'; });
}
setTimeout(function () { caricaDuoVendite(false); }, 600);

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
function ricItem(foto, testo, sotto) { return '<div class="ric-it"><span class="ric-img">' + (foto ? '<img src="' + bsEsc(foto.indexOf('cdn.shopify.com') > -1 ? foto + (foto.indexOf('?') > -1 ? '&' : '?') + 'width=120' : foto) + '" loading="lazy" referrerpolicy="no-referrer" alt="">' : '◇') + '</span><span>' + testo + (sotto ? '<small>' + sotto + '</small>' : '') + '</span></div>'; }
var RIC_TESTI = {};
function ricCopia(k) {
  var testo = RIC_TESTI[k] || ''; if (!testo) return;
  var ok = function () { var e = document.getElementById('ric-copia-esito'); if (e) e.textContent = 'Copiato (' + (k === 'tutto' ? 'borse e scarpe' : k.toLowerCase()) + '): incollalo nel messaggio al fornitore.'; };
  var fallback = function () { var ta = document.createElement('textarea'); ta.value = testo; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) {} document.body.removeChild(ta); ok(); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(testo).then(ok, fallback); else fallback();
}
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
  if (opp.length) {
    var NL = String.fromCharCode(10);
    var oppOrd = opp.slice().sort(function (a, b) { return (b.yoy || 0) - (a.yoy || 0); });
    var modsDi = function (b) { return (b.modelli || []).slice(0, 2).map(function (m) { return m.split(' · ')[0].split(' (')[0].trim(); }).filter(Boolean); };
    var gruppi = [['Borse', oppOrd.filter(function (b) { return b.cat === 'Borse'; })], ['Scarpe', oppOrd.filter(function (b) { return b.cat === 'Scarpe'; })]].filter(function (g) { return g[1].length; });
    var testoGruppo = function (g) { return g[0].toUpperCase() + NL + g[1].map(function (b) { var m = modsDi(b); return '- ' + b.brand + (m.length ? ': ' + m.join(', ') : ''); }).join(NL); };
    var intro = 'Buongiorno,' + NL + 'per la SS27 siamo interessati a disponibilità e prezzi per questi brand e modelli (colori preferiti: nero, marrone, beige):' + NL + NL;
    var firma = NL + NL + 'Grazie,' + NL + 'Alessio – T.Luxy';
    RIC_TESTI = { tutto: intro + gruppi.map(testoGruppo).join(NL + NL) + firma };
    gruppi.forEach(function (g) { RIC_TESTI[g[0]] = intro + testoGruppo(g) + firma; });
    html += '<div class="bs2-head"><div class="bs2-sec" style="margin:0">Lista acquisti per i fornitori (' + opp.length + ' brand)</div><button class="bs2-chip on" data-k="tutto" onclick="ricCopia(this.dataset.k)">Copia tutto</button></div>';
    html += gruppi.map(function (g) {
      return '<div class="ric-forn"><div class="ric-forn-h"><b>' + g[0] + ' · ' + g[1].length + '</b><button class="bs2-chip" data-k="' + g[0] + '" onclick="ricCopia(this.dataset.k)">Copia ' + g[0].toLowerCase() + '</button></div>'
        + g[1].map(function (b) {
          var foto = b.foto_web || ((b.modelli_foto || []).filter(Boolean)[0]) || ((b.tluxy_top || []).map(function (t) { return t.foto; }).filter(Boolean)[0]) || null;
          var m = modsDi(b);
          return ricItem(foto, '<b>' + bsEsc(b.brand) + '</b> <span class="bs2-m ok">' + (b.yoy > 0 ? '+' : '') + b.yoy + '%</span>', m.length ? bsEsc(m.join(', ')) : 'modelli non indicati nel report');
        }).join('') + '</div>';
    }).join('');
    html += '<div class="alerts-meta" id="ric-copia-esito" style="margin:0 0 16px">Il testo copiato contiene solo brand e modelli, senza nostri numeri: pronto per email o WhatsApp.</div>';
  }
  html += '<div class="bs2-head"><div class="bs2-sec" style="margin:0">Brand: Miinto vs TLuxy</div><div class="bs2-chips">' + [['tutti', 'Tutti'], ['Borse', 'Borse'], ['Scarpe', 'Scarpe']].map(function (c) { return '<button class="bs2-chip' + (RIC_FILTRO === c[0] ? ' on' : '') + '" data-f="' + c[0] + '" onclick="ricFiltro(this.dataset.f)">' + c[1] + '</button>'; }).join('') + '</div></div>';
  var rows = d.brand.filter(function (b) { return RIC_FILTRO === 'tutti' || b.cat === RIC_FILTRO; });
  html += '<div class="ric-table"><div class="ric-row ric-h"><span>Brand</span><span>Miinto</span><span>Crescita</span><span>TLuxy 180 gg</span><span>Segnale</span></div>' + rows.map(function (b) {
    var sg = RIC_SEGNALI[b.segnale] || ['—', ''];
    var det = '<div class="ric-det"><div><span class="bs2-l">Più venduti su Miinto</span>' + ((b.modelli && b.modelli.length) ? b.modelli.slice(0, 2).map(function (m, i) { var fc = (b.modelli_foto || [])[i], fw = i === 0 ? b.foto_web : null; return ricItem(fc || fw, (i + 1) + '. ' + bsEsc(m), fc ? 'foto dal nostro catalogo' : (fw ? 'foto dal web' : '')); }).join('') : '<div class="ric-na">non indicati nel report</div>') + '</div>'
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
setTimeout(caricaMeseStrip, 200);
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

    // ============ WEBHOOK PRODOTTI → LORD & TAYLOR (v5.48, HMAC) ============
    if (req.method === 'POST' && path === LT_WEBHOOK_PATH) {
      let raw = ''; await new Promise((resolve, reject) => { req.on('data', c => raw += c); req.on('end', resolve); req.on('error', reject); });
      const hmac = req.headers['x-shopify-hmac-sha256'] || '';
      const atteso = crypto.createHmac('sha256', SHOPIFY_CLIENT_SECRET).update(raw, 'utf8').digest('base64');
      const ok = hmac && atteso.length === String(hmac).length && crypto.timingSafeEqual(Buffer.from(atteso), Buffer.from(String(hmac)));
      if (!ok) { console.log('[lord-taylor webhook] HMAC non valido'); return res.status(401).json({ ok: false }); }
      try {
        const p = JSON.parse(raw);
        let gid;
        if (String(req.headers['x-shopify-topic'] || '').startsWith('inventory_levels')) {
          const d = await shopifyGraphQL(`query($id: ID!) { inventoryItem(id: $id) { variant { product { id } } } }`, { id: 'gid://shopify/InventoryItem/' + p.inventory_item_id });
          gid = d?.inventoryItem?.variant?.product?.id;
          if (!gid) return res.status(200).json({ ok: true });
        } else gid = p.admin_graphql_api_id || ('gid://shopify/Product/' + p.id);
        const e = await ltSincronizzaProdotto(gid);
        if (e && (e.tag_aggiunti || e.tag_rimossi || e.mf_scritti || e.mf_cancellati)) console.log('[lord-taylor webhook]', gid, JSON.stringify(e));
      } catch (e) { console.log('[lord-taylor webhook] errore', e.message); }
      return res.status(200).json({ ok: true });
    }
    // Sincronizzazione completa (cron Vercel giornaliero, o chiamata con Bearer CRON_SECRET / utente loggato)
    if (req.method === 'GET' && path === LT_SYNC_PATH) {
      const bearer = String(req.headers['authorization'] || '');
      if (!((CRON_SECRET && bearer === 'Bearer ' + CRON_SECRET) || getAuthenticatedUser(req))) return res.status(401).json({ ok: false });
      cachedToken = null; tokenExpiry = null; // token fresco: prende subito eventuali nuovi permessi dell'app
      try { return res.json({ ok: true, webhook: await assicuraWebhookLordTaylor(), sync: await ltSincronizzaTutto() }); }
      catch (e) {
        let scopes = null;
        try { const t = await getShopifyAccessToken(); const r = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_scopes.json`, { headers: { 'X-Shopify-Access-Token': t } }); scopes = (await r.json()).access_scopes?.map(x => x.handle); } catch (_) {}
        return res.status(500).json({ ok: false, error: e.message, scopes });
      }
    }

    // ============ RICHIESTE AVVISO PREZZO (v5.65) ============
    // Pubblico: il tema avvisa l'ERP quando una cliente attiva l'avviso → notifica push ad Alessio (limite 40/ora).
    if (req.method === 'GET' && path === '/api/pa-riservato') {
      res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Cache-Control', 'no-store');
      try { const v = await paRiservatoPubblico(query.get('c')); return res.status(200).json(v ? { ok: true, ...v } : { ok: false }); } catch (e) { return res.status(200).json({ ok: false }); }
    }
    if (req.method === 'POST' && path === '/api/pa-segnala') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (_) { b = {}; } } if (!b || typeof b !== 'object') b = await readJsonBody(req);
      const handle = String(b.handle || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 120);
      const email = String(b.email || '').toLowerCase().slice(0, 120);
      if (!handle || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || EMAIL_TEST_BOT.test(email)) return res.status(204).end();
      const ck = 'pa:notif:' + new Date().toISOString().slice(0, 13); const n = parseInt(await kvGet(ck) || '0', 10);
      if (n >= 40) return res.status(204).end(); await kvSetEx(ck, 3700, String(n + 1));
      try {
        const p = await paDettaglio(handle);
        if (p && NTFY_TOPIC) {
          const titolo = `🔔 Avviso prezzo: ${p.brand} ${p.title}`.slice(0, 120);
          const testo = `${email.replace(/(^.).*(@.*$)/, '$1…$2')} vuole sapere se scende.\nPrezzo ${paEuro(p.prezzo)}` + (p.margine != null ? ` · margine ${paEuro(p.margine)}` : '') + (p.sconto_max_pct ? ` · sconto max ${p.sconto_max_pct}%` : '');
          await fetch('https://ntfy.sh/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ topic: NTFY_TOPIC, title: titolo, message: testo, tags: ['bell'], priority: 4, click: ERP_PUBLIC_URL + '/avvisi' }) });
        }
      } catch (e) { console.log('[pa-segnala]', e.message); }
      return res.status(204).end();
    }
    if (req.method === 'OPTIONS' && path === '/api/pa-segnala') { res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type'); return res.status(204).end(); }

    // ============ AVVISO CALO PREZZO (v5.64) ============
    // Cron giornaliero; anche Bearer CRON_SECRET o utente loggato. ?email=&handle= (solo loggato) manda subito un evento di prova.
    if (req.method === 'GET' && path === PA_PATH) {
      const bearer = String(req.headers['authorization'] || '');
      const utente = getAuthenticatedUser(req);
      if (!((CRON_SECRET && bearer === 'Bearer ' + CRON_SECRET) || utente)) return res.status(401).json({ ok: false });
      const soloEmail = utente ? (query.get('email') || '') : '';
      const soloHandle = utente ? (query.get('handle') || '') : '';
      try { return res.json({ ok: true, ...(await paEsegui({ live: process.env.PRICE_ALERT_LIVE === '1', soloEmail, soloHandle, testBf: utente ? parseInt(query.get('bf') || '0', 10) : 0 })) }); }
      catch (e) { console.log('[price-alert]', e.message); return res.status(500).json({ ok: false, error: e.message }); }
    }

    // ============ GIGLIO → SHOPIFY (v5.57) ============
    // Pubblico ma innocuo: importa solo ordini Giglio non ancora presenti; senza autenticazione risponde con i soli conteggi
    // e al massimo una volta ogni 5 minuti. ?dry=1 (solo utente loggato / CRON_SECRET) simula senza creare nulla.
    if (req.method === 'GET' && path === GIGLIO_SYNC_PATH) {
      const bearer = String(req.headers['authorization'] || '');
      const autorizzato = (CRON_SECRET && bearer === 'Bearer ' + CRON_SECRET) || !!getAuthenticatedUser(req);
      const dryRichiesto = req.query?.dry === '1' || /[?&]dry=1/.test(req.url || '');
      if (dryRichiesto && !autorizzato) return res.status(401).json({ ok: false, error: 'Simulazione disponibile solo dopo il login ERP' });
      const dry = autorizzato && dryRichiesto;
      if (!dry) {
        const libero = await kvGet(GIGLIO_KV_LOCK);
        if (libero) return res.status(200).json({ ok: true, saltato: 'eseguito da meno di 5 minuti', ultimo: autorizzato ? JSON.parse((await kvGet(GIGLIO_KV_ULTIMO)) || 'null') : undefined });
        await kvSetEx(GIGLIO_KV_LOCK, 290, '1');
      }
      try {
        const esito = await giglioImporta({ dry });
        if (autorizzato) return res.json({ ok: true, ...esito });
        return res.json({ ok: true, creati: esito.creati.length, da_controllare: esito.no_stock.length + esito.barcode_sconosciuti.length + esito.errori.length });
      } catch (e) {
        console.log('[giglio] errore', e.message);
        if (!dry && !/Credenziali/.test(e.message)) await giglioNotifica('Giglio: import ordini non riuscito', e.message, true);
        return res.status(500).json({ ok: false, error: autorizzato ? e.message : 'errore' });
      }
    }

    // v5.75: invito — link personale (48h) con cui la persona sceglie da sola la propria password
    if (req.method === 'POST' && path === '/api/utenti-invito') {
      const bearer = String(req.headers['authorization'] || '');
      if (!((CRON_SECRET && bearer === 'Bearer ' + CRON_SECRET) || isAdmin(getAuthenticatedUser(req)))) return res.status(401).json({ ok: false });
      const b = await readJsonBody(req); const email = String(b.email || '').trim().toLowerCase();
      if (email !== ERP_USER && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json({ ok: false, error: 'Email non valida' });
      const t = crypto.randomBytes(24).toString('base64url');
      await kvSetEx('erp:invito:' + t, 48 * 3600, email);
      return res.json({ ok: true, link: DASHBOARD_URL.replace(/\/$/, '') + '/benvenuto?t=' + t, scade_ore: 48 });
    }
    if (path === '/benvenuto') {
      res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'text/html; charset=utf-8');
      let raw = '', t = query.get('t') || '', pass = '', pass2 = '';
      if (req.method === 'POST') {
        if (Buffer.isBuffer(req.body)) raw = req.body.toString('utf8'); else if (req.body && typeof req.body === 'object') raw = new URLSearchParams(req.body).toString(); else if (typeof req.body === 'string') raw = req.body; else await new Promise((ok, ko) => { req.on('data', c => raw += c); req.on('end', ok); req.on('error', ko); });
        const f = new URLSearchParams(raw); t = f.get('t') || t; pass = f.get('password') || ''; pass2 = f.get('password2') || '';
      }
      t = String(t).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);
      const email = t ? await kvGet('erp:invito:' + t) : null;
      const pagina = (corpo) => `<!DOCTYPE html><html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Benvenuta · TLuxy Business Manager</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F6F4EF;color:#1b1b1b;margin:0;padding:24px 16px}main{max-width:420px;margin:0 auto;background:#fff;border-radius:14px;padding:24px}h1{font-size:1.2rem;margin:0 0 6px}p{color:#666;font-size:.9rem;line-height:1.5}label{display:block;font-size:.8rem;font-weight:600;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ddd;border-radius:8px;font-size:1rem}button,a.btn{display:block;text-align:center;margin-top:16px;width:100%;box-sizing:border-box;padding:12px;border:0;border-radius:8px;background:#111;color:#fff;font:inherit;font-weight:600;text-decoration:none}.err{background:#FBEAEA;color:#9B2C2C;padding:10px;border-radius:8px;font-size:.88rem}</style></head><body><main>${corpo}</main></body></html>`;
      if (!email) return res.status(200).send(pagina('<h1>Link non valido</h1><p>Il link è scaduto o è già stato usato. Chiedi ad Alessio di mandartene uno nuovo.</p>'));
      let errore = '';
      if (req.method === 'POST') {
        if (pass.length < 10) errore = 'La password deve avere almeno 10 caratteri.';
        else if (pass !== pass2) errore = 'Le due password non coincidono.';
        else {
          let salvato;
          if (email === ERP_USER) salvato = await kvSetBody('erp:admin_hash', hashPassword(pass));
          else { const ux = await utentiExtra(); ux[email] = hashPassword(pass); salvato = await kvSetBody(UTENTI_KEY, JSON.stringify(ux)); }
          if (salvato) { await kvDel('erp:invito:' + t); return res.status(200).send(pagina('<h1>Fatto!</h1><p>La tua password è impostata. Per entrare usa come utente <b>' + email + '</b> e la password che hai scelto.</p><a class="btn" href="/login">Vai al login</a>')); }
          errore = 'Errore nel salvataggio, riprova.';
        }
      }
      return res.status(200).send(pagina('<h1>Imposta la password dell’ERP TLuxy</h1><p>Scegli la tua password. Il tuo nome utente sarà <b>' + email + '</b>.</p>' + (errore ? '<div class="err">' + errore + '</div>' : '') + '<form method="post" action="/benvenuto"><input type="hidden" name="t" value="' + t + '"><label>Password (almeno 10 caratteri)</label><input type="password" name="password" required minlength="10" autocomplete="new-password"><label>Ripetila</label><input type="password" name="password2" required minlength="10" autocomplete="new-password"><button>Imposta password</button></form>'));
    }
    // v5.79.1: diagnosi ATELIER READY senza scrivere (solo CRON_SECRET)
    if (req.method === 'GET' && path === '/api/atelier-diag') {
      if (!(CRON_SECRET && String(req.headers['authorization'] || '') === 'Bearer ' + CRON_SECRET)) return res.status(401).json({ ok: false });
      if (query.get('offerte')) { const kv = async (cmd) => (await (await fetch(KV_REST_API_URL, { method: 'POST', headers: { 'Authorization': 'Bearer ' + KV_REST_API_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify(cmd) })).json()).result; let cur = '0', keys = []; do { const r = await kv(['SCAN', cur, 'MATCH', 'pa:offer:*', 'COUNT', '500']); cur = r[0]; keys = keys.concat(r[1]); } while (cur !== '0' && keys.length < 2000); const out = []; for (const k of keys) { try { const o = JSON.parse(await kv(['GET', k])); out.push({ email: o.email, title: o.title, nuovo: o.nuovo, prezzo: o.prezzo, creata: o.creata, scade: o.scade, email_inviata: o.email_inviata, email_errore: o.email_errore, code: o.code }); } catch (_) {} } out.sort((a, b) => String(b.creata).localeCompare(String(a.creata))); return res.json(out.slice(0, 15)); }
      if (query.get('prodcoll')) return res.json(await shopifyGraphQL('query($id:ID!){ product(id:$id){ title tags collections(first:30){ nodes{ handle title } } } }', { id: 'gid://shopify/Product/' + query.get('prodcoll') }));
      if (query.get('ordsc')) return res.json(await shopifyGraphQL('query($q:String){ orders(first:40, query:$q, sortKey:CREATED_AT, reverse:true){ nodes{ name createdAt sourceName totalDiscountsSet{ shopMoney{ amount } } discountApplications(first:5){ nodes{ __typename value{ ... on PricingPercentageValue{ percentage } } ... on AutomaticDiscountApplication{ title } ... on DiscountCodeApplication{ code } } } } } }', { q: query.get('ordsc') }));
      if (query.get('sposta')) { const pid = 'gid://shopify/Product/' + query.get('sposta').replace(/\D/g, ''); const da = 'gid://shopify/Collection/' + String(query.get('da')).replace(/\D/g, ''); const a = 'gid://shopify/Collection/' + String(query.get('a')).replace(/\D/g, ''); const r1 = await shopifyGraphQL('mutation($id:ID!,$p:[ID!]!){ collectionAddProducts(id:$id, productIds:$p){ userErrors{ message } } }', { id: a, p: [pid] }); const r2 = await shopifyGraphQL('mutation($id:ID!,$p:[ID!]!){ collectionRemoveProducts(id:$id, productIds:$p){ job{ id } userErrors{ message } } }', { id: da, p: [pid] }); const chk = await shopifyGraphQL('query($id:ID!){ product(id:$id){ title collections(first:60){ nodes{ handle } } } }', { id: pid }); return res.json({ r1, r2, chk }); }
      if (query.get('colls')) return res.json(await shopifyGraphQL('query($q:String){ collections(first:50, query:$q){ nodes{ title handle productsCount{ count } } } }', { q: query.get('colls') }));
      if (query.get('discounts')) return res.json(await shopifyGraphQL('{ discountNodes(first:100, query:"status:active"){ nodes{ id discount{ __typename ... on DiscountAutomaticBasic{ title startsAt endsAt combinesWith{ orderDiscounts productDiscounts shippingDiscounts } customerGets{ value{ ... on DiscountPercentage{ percentage } } items{ __typename ... on DiscountCollections{ collections(first:5){ nodes{ handle productsCount{ count } } } } ... on DiscountProducts{ products(first:3){ nodes{ title } } } } } } ... on DiscountCodeBasic{ title startsAt endsAt } } } } }'));
      if (query.get('coll')) { const h = query.get('coll'); let after = null, out = [], info = null; for (let i = 0; i < 20; i++) { const d = await shopifyGraphQL('query($h:String!,$a:String){ collectionByHandle(handle:$h){ title productsCount{ count } products(first:250, after:$a){ pageInfo{ hasNextPage endCursor } nodes{ title vendor handle status totalInventory productType tags variants(first:1){ nodes{ price compareAtPrice sku } } } } } }', { h, a: after }); const c = d.collectionByHandle; if (!c) return res.json({ error: 'no coll' }); info = { title: c.title, count: c.productsCount?.count }; out = out.concat(c.products.nodes.map(n => ({ t: n.title, v: n.vendor, h: n.handle, s: n.status, q: n.totalInventory, ty: n.productType, p: n.variants.nodes[0]?.price, c: n.variants.nodes[0]?.compareAtPrice, sku: n.variants.nodes[0]?.sku, tg: n.tags.filter(x => /DIFETTO|DUOMO|AMM/i.test(x)).join(',') }))); if (!c.products.pageInfo.hasNextPage) break; after = c.products.pageInfo.endCursor; } return res.json({ info, prodotti: out }); }
      if (query.get('scopes')) return res.json(await shopifyGraphQL('{ currentAppInstallation { accessScopes { handle } } }'));
      if (query.get('q') != null) { const r = await shopifyGraphQL('query($q:String){ orders(first:8, query:$q, sortKey:CREATED_AT, reverse:true){ edges { node { id name createdAt tags lineItems(first:5){ edges { node { sku } } } } } } }', { q: query.get('q') || null }); return res.json(r); }
      try { return res.json(await atelierReady(String(query.get('name') || ''), query.get('oid') || '', query.get('scrivi') !== '1')); } catch (e) { return res.json({ success: false, error: e.message, stack: String(e.stack || '').slice(0, 500) }); }
    }
    // v5.74: elenco email utenti aggiuntivi (solo con CRON_SECRET, per assistenza)
    if (req.method === 'GET' && path === '/api/utenti-elenco') {
      if (!(CRON_SECRET && String(req.headers['authorization'] || '') === 'Bearer ' + CRON_SECRET)) return res.status(401).json({ ok: false });
      return res.json({ ok: true, utenti: Object.keys(await utentiExtra()), admin: ERP_USER, admin_pw_nuova: !!(await kvGet('erp:admin_hash')), kv: KV_CREDENTIALS ? KV_CREDENTIALS.source : null, kv_ok: !!(await kvGet('passkeys_v1') !== undefined), prova: await kvSetEx('erp:ping', 60, '1'), chiavi: await (async () => { try { const r = await fetch(KV_REST_API_URL, { method: 'POST', headers: { 'Authorization': 'Bearer ' + KV_REST_API_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify(['DBSIZE']) }); return (await r.json()).result; } catch (e) { return null; } })() });
    }
    // v5.72: carico spesa pubblicitaria di un giorno (Bearer CRON_SECRET o utente loggato)
    if (req.method === 'POST' && path === '/api/ads-spesa') {
      const bearer = String(req.headers['authorization'] || '');
      if (!((CRON_SECRET && bearer === 'Bearer ' + CRON_SECRET) || getAuthenticatedUser(req))) return res.status(401).json({ ok: false });
      let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (_) { b = null; } } if (!b || typeof b !== 'object') b = await readJsonBody(req);
      const giorni = Array.isArray(b.giorni) ? b.giorni : [b];
      const fatti = [];
      for (const g of giorni.slice(0, 120)) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(String(g.data || ''))) continue;
        const pulisci = x => x ? { totale: Math.round((+x.totale || 0) * 100) / 100, campagne: (Array.isArray(x.campagne) ? x.campagne : []).slice(0, 60).map(k => ({ nome: String(k.nome || '').slice(0, 140), spesa: Math.round((+k.spesa || 0) * 100) / 100, tipo: String(k.tipo || '').slice(0, 30) })) } : null;
        await kvSet('ads:giorno:' + g.data, JSON.stringify({ google: pulisci(g.google), meta: pulisci(g.meta), aggiornato: new Date().toISOString() }));
        fatti.push(g.data);
      }
      return res.json({ ok: true, salvati: fatti });
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
        let chi = passwordOk(user, pass) ? ERP_USER : null;
        if (!chi && String(user || '').trim().toLowerCase() === ERP_USER) { const ah = await kvGet('erp:admin_hash'); if (ah && hashOk(pass, ah)) chi = ERP_USER; }
        if (!chi) { const ux = await utentiExtra(); const u = String(user || '').trim().toLowerCase(); if (ux[u] && hashOk(pass, ux[u])) chi = u; }
        if (!chi) { t.n++; tentativiLogin.set(ip, t); return res.status(401).send(passwordLoginPage('Utente o password non corretti')); }
        tentativiLogin.delete(ip);
        setAuthCookie(res, 'utente:' + chi);
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
      if (req.method === 'GET' && (path === '/' || path === '/dashboard' || path === '/avvisi' || path === '/utenti')) {
        res.writeHead(302, { Location: '/login?expired=1' });
        return res.end();
      }
      return res.status(401).json({ success: false, error: 'Non autorizzato. Effettua il login.', auth_required: true });
    }

    // v5.70: un utente aggiuntivo rimosso da /utenti perde subito l'accesso
    if (AUTH_ENABLED && authUser && !isAdmin(authUser) && String(authUser.email).startsWith('utente:')) {
      const ux = await utentiExtra();
      if (!ux[String(authUser.email).slice(7)]) { clearAuthCookie(res); if (req.method === 'GET' && !path.startsWith('/api/')) { res.writeHead(302, { Location: '/login' }); return res.end(); } return res.status(401).json({ success: false, error: 'Accesso revocato', auth_required: true }); }
    }
    if (path === '/utenti') {
      res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'text/html; charset=utf-8');
      if (!isAdmin(authUser)) return res.status(403).send('Solo l’amministratore può gestire gli utenti.');
      let msg = '';
      if (req.method === 'POST') {
        let raw = ''; if (Buffer.isBuffer(req.body)) raw = req.body.toString('utf8'); else if (req.body && typeof req.body === 'object') raw = new URLSearchParams(req.body).toString(); else if (typeof req.body === 'string') raw = req.body; else await new Promise((ok, ko) => { req.on('data', c => raw += c); req.on('end', ok); req.on('error', ko); });
        const f = new URLSearchParams(raw); const email = String(f.get('email') || '').trim().toLowerCase();
        const ux = await utentiExtra();
        if (f.get('azione') === 'rimuovi') { delete ux[email]; await kvSetBody(UTENTI_KEY, JSON.stringify(ux)); msg = 'Accesso tolto a ' + email; }
        else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email === ERP_USER) msg = 'Email non valida';
        else if (String(f.get('password') || '').length < 10) msg = 'La password deve avere almeno 10 caratteri';
        else { ux[email] = hashPassword(f.get('password')); const okSalva = await kvSetBody(UTENTI_KEY, JSON.stringify(ux)); msg = okSalva ? 'Utente ' + email + ' aggiunto: può entrare con questa email e la password scelta' : 'Errore nel salvataggio, riprova'; }
      }
      return res.status(200).send(utentiPage(Object.keys(await utentiExtra()).sort(), msg));
    }

    // ============ v5.65 PAGINA AVVISI PREZZO ============
    if (req.method === 'GET' && path === '/avvisi') { res.setHeader('Content-Type', 'text/html; charset=utf-8'); return res.status(200).send(PA_PAGE); }
    if (req.method === 'GET' && path === '/api/avvisi') {
      try { return res.json({ success: true, righe: await paRichieste() }); } catch (e) { return res.json({ success: false, error: e.message }); }
    }
    if (req.method === 'POST' && path === '/api/avvisi/offerta') {
      const b = await readJsonBody(req);
      try { return res.json({ success: true, offerta: await paCreaOfferta({ email: String(b.email || '').toLowerCase(), handle: String(b.handle || ''), pct: Math.max(0, Math.min(50, parseInt(b.pct || 0, 10))), prezzoFinale: parseFloat(b.prezzoFinale || 0) || 0, lang: b.lang === 'it' ? 'it' : 'en' }) }); }
      catch (e) { return res.json({ success: false, error: e.message }); }
    }

    // v5.69: tag ATELIER READY sugli ordini Mantova Moda → Atelier/Zucchetti prende in carico l'ordine
    if (req.method === 'POST' && path === '/api/ordine-atelier-ready') {
      const b = await readJsonBody(req);
      const nome = String(b.name || '').trim().slice(0, 80);
      if (!nome) return res.json({ success: false, error: 'Ordine mancante' });
      let out;
      try { out = await atelierReady(nome, b.oid, false); } catch (e) { out = { success: false, error: e.message }; }
      console.log('[atelier-ready]', nome, b.oid || '-', JSON.stringify(out).slice(0, 400));
      return res.json(out);
    }

    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      return res.json({ sistema: 'TLuxy Business Manager v5.72', status: 'LIVE', store: SHOPIFY_STORE, credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET), auth_enabled: AUTH_ENABLED, auth_type: 'magic_link_resend', kv_enabled: KV_ENABLED, kv_source: KV_SOURCE, anthropic_configured: !!process.env.ANTHROPIC_API_KEY, user_email: authUser?.email || null, funzionalita: ['🧾 Controllo margini DUOMO (/api/duo-alerts)', '🔔 Alert canali lenti (/api/alerts)', '📅 Regole MP con data di validità (Miinto 21,5% dal 01/11/2026, Bradery 90/10)', '🧮 Scorciatoia Retail+Sconti nel Calcolatore', '📊 Excel batch con Retail + Sconto% fornitore', '💡 Sconto Max accettabile per 20% margine', '💬 Chat AI assistant (Claude Haiku 4.5)', 'GIGLIO.COM marketplace', 'Mark Foy: incasso = prezzo B2B (metafield mark_foy_price → listino → DUOMO costo×1,15)', 'Split costi KPI (Merce + Fees)', 'Simulatore DUO on-demand', 'Snapshot Inventario', 'Cache KV 24h', 'Previsioni Incassi', 'Balardi wallet', 'Gestione resi/refund', 'Conversione valuta automatica'], marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length });
    }

    if (req.method === 'GET' && path === '/api/newsletter-form') {
      try {
        const rg = getDateRange(query.get('periodo') || 'today', query.get('from'), query.get('to'));
        const da = getRomeDateString(new Date(rg.dateFrom)), a = getRomeDateString(new Date(rg.dateTo));
        const form = await omnisendIscrittiPerForm(da, a);
        return res.json({ success: true, da, a, form });
      } catch (e) { console.log('[newsletter-form]', e.message); return res.json({ success: false, error: e.message }); }
    }
    if (req.method === 'GET' && path === '/api/ads-spesa') {
      try {
        const rg = getDateRange(query.get('periodo') || 'today', query.get('from'), query.get('to'));
        return res.json({ success: true, ...(await adsPeriodo(getRomeDateString(new Date(rg.dateFrom)), getRomeDateString(new Date(rg.dateTo)))) });
      } catch (e) { return res.json({ success: false, error: e.message }); }
    }
    if (req.method === 'GET' && path === '/api/newsletter-iscritti') {
      try {
        const rg = getDateRange(query.get('periodo') || 'today', query.get('from'), query.get('to'));
        const da = getRomeDateString(new Date(rg.dateFrom)), a = getRomeDateString(new Date(rg.dateTo));
        const v = await omnisendIscritti();
        const minG = v.giorni.length ? v.giorni[0].d : a;
        const DAY = 86400000, dPiu = (d, n) => new Date(new Date(d + 'T12:00:00Z').getTime() + n * DAY).toISOString().slice(0, 10);
        const somma = (x, y) => {
          if (x >= minG) { const r = v.giorni.filter(g => g.d >= x && g.d <= y); return { i: r.reduce((t, g) => t + g.i, 0), u: r.reduce((t, g) => t + g.u, 0), righe: r, approx: false }; }
          const r = v.mesi.filter(g => g.d.slice(0, 7) >= x.slice(0, 7) && g.d.slice(0, 7) <= y.slice(0, 7));
          return { i: r.reduce((t, g) => t + g.i, 0), u: r.reduce((t, g) => t + g.u, 0), righe: [], approx: true };
        };
        const cur = somma(da, a);
        const lung = Math.round((new Date(a + 'T12:00:00Z') - new Date(da + 'T12:00:00Z')) / DAY) + 1;
        const pa = dPiu(da, -1), pda = dPiu(da, -lung);
        const prec = somma(pda, pa);
        const oggi = getRomeDateString(), ieri = dPiu(oggi, -1);
        const meseDa = oggi.slice(0, 8) + '01';
        const pm = new Date(oggi.slice(0, 7) + '-01T12:00:00Z'); pm.setUTCMonth(pm.getUTCMonth() - 1);
        const pmDa = pm.toISOString().slice(0, 10);
        const ggPm = new Date(Date.UTC(pm.getUTCFullYear(), pm.getUTCMonth() + 1, 0)).getUTCDate();
        const pmA = pmDa.slice(0, 8) + String(Math.min(+oggi.slice(8, 10), ggPm)).padStart(2, '0');
        const confronti = [
          { k: 'Oggi', vs: 'ieri', a: somma(oggi, oggi).i, b: somma(ieri, ieri).i },
          { k: 'Ultimi 7 giorni', vs: '7 giorni prima', a: somma(dPiu(oggi, -6), oggi).i, b: somma(dPiu(oggi, -13), dPiu(oggi, -7)).i },
          { k: 'Questo mese', vs: 'stesso periodo mese scorso', a: somma(meseDa, oggi).i, b: somma(pmDa, pmA).i }
        ];
        let totale = null;
        try { totale = await omnisendTotale(); } catch (e2) { console.log('[newsletter-totale]', e2.message); }
        return res.json({ success: true, da, a, iscritti: cur.i, disiscritti: cur.u, giorni: cur.approx ? [] : cur.righe, approx: cur.approx, prec: { da: pda, a: pa, iscritti: prec.i, disiscritti: prec.u, approx: prec.approx }, confronti, totale, finti: v.finti || 0, aggiornato: v.agg });
      } catch (e) { console.log('[newsletter-iscritti]', e.message); return res.json({ success: false, error: e.message === 'NO_KEY' ? 'NO_KEY' : e.message }); }
    }
    if (req.method === 'GET' && path === '/api/traffico-fonti') {
      try {
        const rg = getDateRange(query.get('periodo') || 'today', query.get('from'), query.get('to'));
        const da = getRomeDateString(new Date(rg.dateFrom)), a = getRomeDateString(new Date(rg.dateTo));
        return res.json({ success: true, fonti: await trafficoFonti(da, a) });
      } catch (e) { return res.json({ success: false, error: e.message }); }
    }
    if (req.method === 'GET' && path === '/api/traffico') {
      try {
        const rg = getDateRange(query.get('periodo') || 'today', query.get('from'), query.get('to'));
        const da = getRomeDateString(new Date(rg.dateFrom)), a = getRomeDateString(new Date(rg.dateTo));
        return res.json({ success: true, da, a, ...(await trafficoSito(da, a)) });
      } catch (e) {
        let scopes = null;
        try { const t = await getShopifyAccessToken(); const r = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_scopes.json`, { headers: { 'X-Shopify-Access-Token': t } }); scopes = (await r.json()).access_scopes?.map(x => x.handle); } catch (_) {}
        return res.json({ success: false, error: e.message, read_reports: scopes ? scopes.includes('read_reports') : null });
      }
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
        await caricaPrezziMarkFoy(ordini); await caricaCmpLoveTheSales(ordini);
        
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
          const spedizione = mp.key === 'LUOSOPHY' ? 0 : (ordine.shipping_lines || []).reduce((sum, line) => sum + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency), 0);
          const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
          const ivaPerc = mp.key === 'POIZON' ? 22 : (mp.key === 'REFLAUNT' ? 0 : getIvaPerPaese(country));
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
            oid: ordine.id,
            tags: ordine.tags || '',
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
      try { return res.json({ success: true, ntfy: !!NTFY_TOPIC, email: !!(RESEND_API_KEY && DUO_NOTIFY_EMAIL), webhook: await assicuraWebhookOrdini(), webhook_lord_taylor: await assicuraWebhookLordTaylor().catch(e => 'errore ' + e.message) }); }
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
        await caricaPrezziMarkFoy(ordini); await caricaCmpLoveTheSales(ordini);
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
    if (req.method === 'GET' && path === '/api/duo-vendite') {
      try {
        const refresh = query.get('refresh') === '1';
        if (!refresh && CACHE_DUO_VENDITE && Date.now() - new Date(CACHE_DUO_VENDITE.generato_il).getTime() < 10 * 60000) return res.json({ success: true, cached: true, ...CACHE_DUO_VENDITE });
        const oggiS = getRomeDateString();
        const da = getRomeDateString(new Date(Date.now() - 31 * 86400000));
        let ordini = await getShopifyOrders('custom', da, oggiS);
        ordini = await processOrders(ordini);
        const vids = new Set(), pids = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(it => { if (isDuoSku(it.sku)) { if (it.variant_id) vids.add(it.variant_id); if (it.product_id) pids.add(it.product_id); } }));
        const variantCosts = vids.size ? (await fetchVariantCosts([...vids], [...pids])).costs : {};
        await caricaPrezziMarkFoy(ordini); await caricaCmpLoveTheSales(ordini);
        CACHE_DUO_VENDITE = calcolaVenditeDuo(ordini, variantCosts);
        return res.json({ success: true, cached: false, ...CACHE_DUO_VENDITE });
      } catch (e) { return res.json({ success: false, error: e.message }); }
    }

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
        const cacheKey = 'pannello_canali_v571';
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
        const FORECAST_CACHE_KEY = 'forecast_cache_v571';
        const FORECAST_META_KEY = 'forecast_cache_meta_v544';
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
        await caricaPrezziMarkFoy(ordini); await caricaCmpLoveTheSales(ordini);
        
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
          const ivaPerc = mp.key === 'POIZON' ? 22 : (mp.key === 'REFLAUNT' ? 0 : getIvaPerPaese(country));
          const prezzoNettoIva = cfg.iva_esente ? prezzoLordo : prezzoLordo / (1 + ivaPerc / 100);
          const prezzoDopoSconto = prezzoNettoIva * (1 - (cfg.prezzo_ordine_netto ? 0 : (cfg.sconto_percentuale || 0)) / 100);
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
            balardiConsumo.importo_eur += prezzoLordo; // v5.43: il credito scala il prezzo articoli (spedizione esclusa: non è su Shopify)
            balardiConsumo.ordini.push({
              order_number: ordine.order_number,
              name: ordine.name,
              created_at: ordine.created_at,
              importo_consumato: prezzoLordo,
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
