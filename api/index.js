// ERP Marginalità v5.9 - Snapshot Inventario (categorie × gender, filtro DUO)

import * as crypto from 'node:crypto';

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
const AUTH_SESSION_DAYS = 7;
const MAGIC_LINK_MINUTES = 15;
const MAGIC_LINK_RATE_LIMIT = 3; // max 3 magic link/ora per email
const AUTH_ENABLED = !!(RESEND_API_KEY && ALLOWED_EMAILS.length > 0);

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

// Pagine HTML di login/conferma/errore
function loginHTMLPage(message, isError) {
  const msgBlock = message ? `<div class="${isError ? 'error' : 'info'} show">${message}</div>` : '';
  return `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>T. Luxy ERP · Accesso</title>
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
// kvSetEx: set con TTL (seconds)
async function kvSetEx(key, ttlSec, value) {
  if (!KV_ENABLED) return false;
  try {
    // Upstash Redis REST: SET key value EX ttl → /set/{key}/{value}?EX={ttl}
    const url = `${KV_REST_API_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}?EX=${ttlSec}`;
    const res = await fetch(url, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
    return res.ok;
  } catch (e) { return false; }
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
  'THE_BRADERY': { nome: 'The Bradery', sconto_percentuale: 5, fee_principale: 17, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 2, pagamento: 'Split 80/20 (mese+1 / mese+2)', payment_policy: { type: 'split', parts: [{ pct: 80, month_offset: 1, payout_day: 10 }, { pct: 20, month_offset: 2, payout_day: 10 }] } },
  'BOUTIQUE_MALL': { nome: 'Boutique Mall', sconto_percentuale: 33.3, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'ARCHIVIST': { nome: 'Archivist', sconto_percentuale: 0, fee_principale: 22, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'MIINTO': { nome: 'Miinto', sconto_percentuale: 0, fee_principale: 17.75, fee_secondaria: 2.25, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'WINKELSTRAAT': { nome: 'Winkelstraat', sconto_percentuale: 0, fee_principale: 17, fee_secondaria: 0, fee_accessoria: 9, fee_fissa_trasporto: 15, fee_fissa_packaging: 0, pagamento: 'Settimanale (~21gg)', payment_policy: { type: 'weekly', days_offset: 21 } },
  'ITALIST': { nome: 'Italist', sconto_percentuale: 20, fee_principale: 25.5, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 4, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', month_offset: 2, payout_day: 10 } },
  'JAMMY_DUDE': { nome: 'Jammy Dude', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: '10gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 10 } },
  'POIZON': { nome: 'Poizon', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Immediato', payment_policy: { type: 'immediate' } },
  'BRANDSGATEWAY': { nome: 'Brandsgateway', sconto_percentuale: 13, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 0, pagamento: '45gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 45 } },
  'TLUXY_SITE': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato (Shopify +2gg)', payment_policy: { type: 'fixed_days', days_offset: 2 } }
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

function riconosciMarketplace(ordine) {
  const rawSource = (ordine.source_name || '').trim();
  const sourceName = normalizeSourceName(rawSource);
  const tags = (ordine.tags || '').toLowerCase();
  
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
  
  // Match diretto normalizzato su source_name
  if (SOURCE_NAME_MAP[sourceName]) return { key: SOURCE_NAME_MAP[sourceName], config: MARKETPLACE_CONFIGS[SOURCE_NAME_MAP[sourceName]] };
  
  // Poizon detection: source numerico + email customer "poizon"
  const email = (ordine.email || ordine.customer?.email || '').toLowerCase();
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
  
  // Solo variant_id che NON abbiamo già nel KV vanno chiamati su Shopify
  const variantsToFetch = uniqueVariantIds.filter(v => !(v in costsFromKV));
  const uniqueProductIds = [...new Set(orderProductIds.filter(Boolean))];
  const variantToInventoryItem = {};
  
  // Se tutti i variant sono in cache, skip le chiamate Shopify
  if (variantsToFetch.length === 0) {
    return { costs: costsFromKV, stats };
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

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>T. Luxy ERP — Dashboard Marginalità</title>
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
  @media (max-width: 768px) { .container { padding: 16px; } .header { padding: 24px; } .logo { font-size: 1.9rem; } .section { padding: 24px; } .tabs { flex-direction: column; } .tab { min-width: auto; } .header-divider { display: none; } .kpi-value { font-size: 1.5rem; } .filter-bar { flex-direction: column; align-items: stretch; } .custom-range { flex-wrap: wrap; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-left">
      <div class="logo">T<span class="dot">.</span> LUXY</div>
      <div class="header-divider"></div>
      <div class="header-info">
        <h1>ERP Marginalità</h1>
        <p>Business Intelligence Dashboard · v5.9</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill"><div class="status-dot"></div>Sistema Live</div>
      <button id="logoutBtn" style="background:transparent; border:1px solid rgba(0,0,0,0.15); padding:8px 14px; border-radius:50px; cursor:pointer; font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:var(--gray-700); margin-left:12px; font-family:var(--font-main); transition:all 0.2s;" onmouseover="this.style.background='var(--gray-100)'" onmouseout="this.style.background='transparent'">🚪 Esci</button>
    </div>
  </div>
  <div class="tabs-wrap">
    <div class="tabs">
      <button class="tab active" data-tab="analytics">Analytics</button>
      <button class="tab" data-tab="bestsellers">Best Seller</button>
      <button class="tab" data-tab="compare">Confronto MP</button>
      <button class="tab" data-tab="calculator">Calcolatore</button>
      <button class="tab" data-tab="marketplaces">Marketplace</button>
      <button class="tab" data-tab="duo">Simulatore DUO</button>
      <button class="tab" data-tab="forecast">💰 Previsioni Incassi</button>
      <button class="tab" data-tab="inventory">📦 Inventario</button>
    </div>
  </div>
  <div id="analytics-tab" class="tab-content active">
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
        <div class="kpi"><div class="kpi-label">Costi Totali</div><div class="kpi-value" id="costi">—</div><div class="kpi-sub">Merce + Fees + IVA</div></div>
        <div class="kpi green"><div class="kpi-label">Margine Netto</div><div class="kpi-value" id="netto">—</div><div class="kpi-sub">Profitto reale</div></div>
        <div class="kpi gold"><div class="kpi-label">Margine %</div><div class="kpi-value" id="margine">—</div><div class="kpi-sub">Su lordo</div></div>
      </div>
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
      <div class="section-header"><div><div class="section-title">Best Seller</div><div class="section-subtitle">Top 20 prodotti più venduti per fatturato</div></div></div>
      <div class="info-box">Foto, prezzo, costo merce reale e ricavo effettivo.</div>
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
</div>
<script>
const MARKETPLACES = ${JSON.stringify(MARKETPLACE_CONFIGS)};
const MP_COLORS = { TLUXY_SITE:'#1A1A1A', THE_BRADERY:'#C9A961', MIINTO:'#008060', BALARDI:'#BF4747', ITALIST:'#2D2D2D', JAMMY_DUDE:'#8E4FBF', SECRET_SALES:'#6B5320', FASHION_TAMERS:'#5C5C5C', INTRA_MIRROR:'#B89550', ARCHIVIST:'#004C3F', BOUTIQUE_MALL:'#E8573A', WINKELSTRAAT:'#479CCF', POIZON:'#D4397A', BRANDSGATEWAY:'#4A7FBC' };

function setActiveButton(selector, btn) { document.querySelectorAll(selector).forEach(b => b.classList.remove('active')); if (btn) btn.classList.add('active'); }
async function fetchNoCache(url) { const sep = url.includes('?') ? '&' : '?'; const res = await fetch(url + sep + '_=' + Date.now(), { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } }); return res.json(); }

function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  const tabBtn = document.querySelector('.tab[data-tab="' + name + '"]'); if (tabBtn) tabBtn.classList.add('active');
  if (name === 'compare' && !document.getElementById('compare-body').children.length) confronta();
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
  panel.innerHTML = '<div style="background:#FFF4D6; border-left:4px solid #E8C77A; border-radius:8px; padding:14px 18px; margin-bottom:16px;"><div style="font-weight:700; color:#8B6914; margin-bottom:8px;">💱 ' + ordiniEstero.length + ' ordine' + (ordiniEstero.length > 1 ? ' in' : '') + ' valuta estera (convertit' + (ordiniEstero.length > 1 ? 'i' : 'o') + ' in EUR al cambio storico Shopify)</div><div style="font-size:0.82rem; color:#6B4E0E;">' + summary + '</div></div>';
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
      document.getElementById('netto').textContent = '€' + Math.round(data.margine_netto).toLocaleString('it-IT');
      document.getElementById('margine').textContent = data.margine_percentuale.toFixed(1) + '%';
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
  try { const data = await fetchNoCache('/api/bestsellers?periodo=' + p); if (data.success && data.prodotti && data.prodotti.length > 0) { renderBestSellers(data.prodotti); return; } cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
async function applyBsCustomRange() {
  const from = document.getElementById('bs-date-from').value; const to = document.getElementById('bs-date-to').value;
  if (!from || !to) { alert('Seleziona date'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-bs-periods] .period-btn', null);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty">Caricamento...</div>';
  try { const data = await fetchNoCache('/api/bestsellers?from=' + from + '&to=' + to); if (data.success && data.prodotti && data.prodotti.length > 0) { renderBestSellers(data.prodotti); return; } cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
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
    card.innerHTML = '<div class="mp-name">' + mp.nome + '</div><div class="mp-pay">Pagamento: ' + (mp.pagamento || 'N/D') + '</div><div class="mp-fees"><div><strong>Sconto</strong>' + mp.sconto_percentuale + '%</div><div><strong>Fee Princ.</strong>' + mp.fee_principale + '%</div><div><strong>Fee Sec.</strong>' + (mp.fee_secondaria || 0) + '%</div><div><strong>Trasporto</strong>€' + (mp.fee_fissa_trasporto || 0) + '</div><div><strong>Packaging</strong>€' + (mp.fee_fissa_packaging || 0) + '</div>' + (mp.fee_accessoria ? '<div><strong>Fee Acc.</strong>' + mp.fee_accessoria + '%</div>' : '') + '</div>';
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
    const imgHtml = p.image ? '<img src="' + p.image + '" alt="" loading="lazy">' : '<div class="bs-image-placeholder">◇</div>';
    const costoSaved = p.costo_fornitore !== null && p.costo_fornitore !== undefined ? p.costo_fornitore : '';
    return '<div class="duo-card" data-vid="' + p.variant_id + '">' +
      '<div class="duo-img">' + imgHtml + '</div>' +
      '<div class="duo-body">' +
        '<div class="duo-title">' + p.title + '</div>' +
        '<div class="duo-meta">SKU: ' + p.sku + ' · Stock: ' + p.inventory_quantity + '</div>' +
        '<div class="duo-listino">Listino Shopify: <strong>€' + p.prezzo_listino.toFixed(2) + '</strong>' + (p.compare_at_price > 0 ? ' <span style="text-decoration:line-through; color:var(--gray-500); margin-left:6px;">€' + p.compare_at_price.toFixed(2) + '</span>' : '') + '</div>' +
        '<div class="duo-input-row"><label>Costo fornitore €</label><input type="number" class="duo-cost" value="' + costoSaved + '" step="0.01" min="0" data-vid="' + p.variant_id + '"></div>' +
        '<div class="duo-input-row"><label>Marketplace</label><select class="duo-mp" data-vid="' + p.variant_id + '"><option value="">— scegli —</option>' + mpOptions + '</select></div>' +
        '<div class="duo-input-row"><label>IVA paese %</label><select class="duo-iva" data-vid="' + p.variant_id + '"><option value="22">IT (22%)</option><option value="20">FR/UK/AT (20%)</option><option value="19">DE (19%)</option><option value="21">ES/NL/BE (21%)</option><option value="23">PL/IE/PT (23%)</option><option value="25">SE/DK (25%)</option><option value="0">Extra-UE (0%)</option></select></div>' +
        '<div class="duo-input-row"><label>Prezzo test €</label><input type="number" class="duo-prezzo-test" value="' + p.prezzo_listino.toFixed(2) + '" step="0.01" data-vid="' + p.variant_id + '"></div>' +
        '<div class="duo-result" id="duo-res-' + p.variant_id + '">—</div>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
  
  // Listeners
  cont.querySelectorAll('.duo-cost, .duo-mp, .duo-iva, .duo-prezzo-test').forEach(el => {
    el.addEventListener('input', e => updateDuoCard(e.target.dataset.vid));
    el.addEventListener('change', e => updateDuoCard(e.target.dataset.vid));
  });
  // Save costo on blur (persistenza KV)
  cont.querySelectorAll('.duo-cost').forEach(el => {
    el.addEventListener('blur', async e => {
      const vid = e.target.dataset.vid; const cost = parseFloat(e.target.value);
      if (!isNaN(cost) && cost >= 0) {
        try { await fetch('/api/duo-cost-set', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({variant_id: vid, cost}) }); } catch(_) {}
      }
    });
  });
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

document.addEventListener('DOMContentLoaded', () => {
  loadMarketplaces();
  const today = new Date(); const monthAgo = new Date(); monthAgo.setMonth(monthAgo.getMonth() - 1);
  const fmt = d => d.toISOString().split('T')[0];
  ['date-from', 'bs-date-from'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(monthAgo); });
  ['date-to', 'bs-date-to'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(today); });
  document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => {
    showTab(btn.dataset.tab);
    if (btn.dataset.tab === 'duo') { checkKvStatus(); if (duoProducts.length === 0) loadDuoProducts(); }
    if (btn.dataset.tab === 'forecast') { if (!forecastData) loadForecast(); }
    if (btn.dataset.tab === 'inventory') { if (!inventoryData) loadInventory(false); }
  }));
  document.querySelectorAll('[data-analytics-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => setPeriod(btn.dataset.period, btn)));
  document.querySelectorAll('[data-bs-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => loadBestSellers(btn.dataset.period, btn)));
  document.getElementById('analytics-apply').addEventListener('click', applyCustomRange);
  document.getElementById('bs-apply').addEventListener('click', applyBsCustomRange);
  ['c-prezzo', 'c-iva', 'c-costo', 'c-spedizione'].forEach(id => { const el = document.getElementById(id); if (el) { el.addEventListener('input', confronta); if (el.tagName === 'SELECT') el.addEventListener('change', confronta); } });
  document.getElementById('calcola-btn').addEventListener('click', calcola);
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
  // Logout handler
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (!confirm('Vuoi uscire dalla dashboard?')) return;
      try { await fetch('/api/logout', { method: 'POST' }); } catch(_) {}
      window.location.href = '/login';
    });
  }
  setTimeout(() => { calcola(); confronta(); const todayBtn = document.querySelector('[data-analytics-periods] .period-btn[data-period="today"]'); setPeriod('today', todayBtn); }, 300);
});
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

  try {
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
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      return res.json({ sistema: 'T. Luxy ERP — Marginalità v5.9', status: 'LIVE', store: SHOPIFY_STORE, credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET), auth_enabled: AUTH_ENABLED, auth_type: 'magic_link_resend', kv_enabled: KV_ENABLED, kv_source: KV_SOURCE, user_email: authUser?.email || null, funzionalita: ['Snapshot Inventario (cat × gender, filtro DUO)', 'Cache KV 24h (forecast + discovery + inventory)', 'Previsioni Incassi (scadenziari MP)', 'Balardi wallet prepagato', 'Gestione resi/refund (full + partial)', 'Magic link auth (Resend)', 'Winkelstraat detection', 'Conversione valuta automatica', 'KV storage costi', 'Simulatore DUO', 'Breakdown MP espandibile', 'Brandsgateway via tag', 'Fuso Roma reale', 'Poizon + Secret Sales'], marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length, endpoints: ['/', '/login', '/logout', '/api', '/api/request-magic-link', '/api/verify-magic-link', '/api/logout', '/api/auth-status', '/api/analytics', '/api/bestsellers', '/api/forecast', '/api/balardi-ricarica', '/api/balardi-ricarica-delete', '/api/inventory', '/api/inventory-discovery', '/api/inventory-discovery-reset', '/api/duo-products', '/api/duo-costs-import', '/api/duo-cost-set', '/api/kv-status', '/api/test-shopify', '/api/marketplaces', '/api/debug-orders', '/api/debug-jd', '/api/debug-winkelstraat', '/api/debug-costs', '/api/debug-single-cost'] });
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
        // Aggregati refund (separati per analisi)
        let resi_totale_eur = 0, resi_count = 0, resi_full_count = 0, resi_partial_count = 0;
        let resi_articoli_qty = 0;
        const breakdown_marketplace = {};
        const ordini_con_errori = [];
        const ordini_valuta_estera = [];
        const ordini_con_resi = []; // dettaglio resi per visualizzazione
        ordini.forEach(ordine => {
          const { costo: costo_merce, errori } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
          const mp = riconosciMarketplace(ordine);
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
          } else if (refundInfo.isPartialRefund && refundInfo.totalQuantity > 0) {
            // Sottrai costo della quantità rimborsata (proporzionale)
            const ratioReso = refundInfo.refundedQuantity / refundInfo.totalQuantity;
            costo_merce_effettivo = costo_merce * (1 - ratioReso);
          }
          
          const ris = calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce_effettivo, spedizione, mp.config, mp.key);
          
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
          margine_netto += ris.margine_netto;
          
          if (currencyInfo.isForeign) {
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
            spedizione,
            margine_netto: ris.margine_netto,
            margine_percentuale: ris.margine_percentuale,
            currency: currencyInfo.originalCurrency,
            is_foreign_currency: currencyInfo.isForeign,
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
              prezzo_unit: toEurAmount(item.price_set, item.price, currencyInfo.originalCurrency),
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
        let prodotti = calcolaBestSellers(ordini, 20, variantCosts);
        prodotti = await arricchisciConImmagini(prodotti);
        return res.json({ success: true, periodo: from && to ? `${from} → ${to}` : periodo, totale_prodotti_unici: prodotti.length, prodotti });
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
        let url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&status=active&fields=id,title,image,variants`;
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
                  title: p.title,
                  image: p.image?.src || null,
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
        
        // Leggi costi salvati (se utente ha fatto import CSV o ha dati in KV)
        const userCosts = {};
        if (KV_ENABLED && products.length > 0) {
          const keys = products.map(p => `duo_user_cost_${p.variant_id}`);
          const results = await kvMGet(keys);
          products.forEach(p => {
            const key = `duo_user_cost_${p.variant_id}`;
            if (results[key] !== undefined) {
              const parsed = parseFloat(results[key]);
              if (!isNaN(parsed)) userCosts[p.variant_id] = parsed;
            }
          });
        }
        
        // Applica costo noto e ordina: prima quelli con costo, poi senza
        const enriched = products.map(p => ({ ...p, costo_fornitore: userCosts[p.variant_id] !== undefined ? userCosts[p.variant_id] : null }));
        enriched.sort((a, b) => {
          if ((a.costo_fornitore !== null) !== (b.costo_fornitore !== null)) return a.costo_fornitore !== null ? -1 : 1;
          return a.title.localeCompare(b.title);
        });
        
        return res.json({ success: true, totale: enriched.length, kv_enabled: KV_ENABLED, prodotti: enriched });
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
    if (req.method === 'GET' && path === '/api/forecast') {
      try {
        const forceRefresh = query.get('refresh') === '1';
        const FORECAST_CACHE_KEY = 'forecast_cache';
        const FORECAST_META_KEY = 'forecast_cache_meta';
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
          const nettoFromMP = Math.max(0, prezzoDopoSconto - feesMP - (cfg.fee_fissa_trasporto === 'GLS' ? 15 : (cfg.fee_fissa_trasporto || 0)) - (cfg.fee_fissa_packaging || 0));
          
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
        
        // Keyword gender
        const KW_WOMAN = ['woman', 'women', 'ladies', 'donna', 'donne', 'female', 'femme', 'mujer', 'w-', ' w ', 'femminile'];
        const KW_MAN = ['man', 'men', 'uomo', 'uomini', 'male', 'homme', 'hombre', 'm-', ' m ', 'maschile'];
        const KW_UNISEX = ['unisex', 'bambino', 'bambini', 'kid', 'kids', 'child', 'children', 'junior', 'baby'];
        
        function detectCategoria(searchText) {
          const t = ' ' + searchText.toLowerCase() + ' ';
          // Check più specifico per primo
          for (const [key, cfg] of Object.entries(CATEGORIE)) {
            for (const kw of cfg.keywords) {
              // Match con word boundary
              if (t.includes(' ' + kw.toLowerCase() + ' ') || t.includes(' ' + kw.toLowerCase()) || t.includes(kw.toLowerCase() + ' ')) {
                return key;
              }
            }
          }
          return null;
        }
        
        function detectGender(searchText) {
          const t = ' ' + searchText.toLowerCase() + ' ';
          // Unisex/kids ha precedenza
          for (const kw of KW_UNISEX) if (t.includes(kw)) return 'unisex';
          // Check woman e man
          const isW = KW_WOMAN.some(kw => t.includes(kw));
          const isM = KW_MAN.some(kw => t.includes(kw));
          if (isW && !isM) return 'donna';
          if (isM && !isW) return 'uomo';
          if (isW && isM) return 'unisex'; // ambiguo
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

    if (req.method === 'GET' && path === '/api/marketplaces') {
      return res.json({ marketplace_disponibili: MARKETPLACE_CONFIGS, source_name_map: SOURCE_NAME_MAP, iva_per_paese: IVA_PER_PAESE });
    }

    return res.status(404).json({ error: 'Endpoint non trovato' });
  } catch (error) { return res.status(500).json({ error: 'Errore interno', dettagli: error.message }); }
}
