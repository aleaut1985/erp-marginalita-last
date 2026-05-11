// ERP Marginalità v5.12.1 - Calcolatore singolo: Retail + 2 sconti% (versione semplificata anti-crash)

import * as crypto from 'node:crypto';

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'autore-luxit.myshopify.com';
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || '';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || '';

// ============ CONFIGURAZIONE AUTORIZZAZIONE (LINK MAGICO) ============
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || 'T. Luxy ERP <onboarding@resend.dev>';
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const AUTH_SECRET = process.env.AUTH_SECRET || (RESEND_API_KEY + '_tluxy_erp_secret_salt_2026');
const DASHBOARD_URL = process.env.DASHBOARD_URL || 'https://erp-marginalita-last.vercel.app';
const AUTH_COOKIE_NAME = 'tluxy_erp_session';
const AUTH_SESSION_DAYS = 7;
const MAGIC_LINK_MINUTES = 15;
const MAGIC_LINK_RATE_LIMIT = 3; // massimo 3 magic link/ora per email
const AUTH_ENABLED = !!(RESEND_API_KEY && ALLOWED_EMAILS.length > 0);

funzione hmacSign(payload) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('hex');
}

funzione createSessionToken(email) {
  const expiresAt = Date.now() + (AUTH_SESSION_DAYS * 24 * 60 * 60 * 1000);
  // email base64 per evitare caratteri problematici nel cookie
  const emailB64 = Buffer.from(email).toString('base64url');
  const payload = `v1.${expiresAt}.${emailB64}`;
  const sig = hmacSign(payload);
  restituisci `${payload}.${sig}`;
}

funzione verifySessionToken(token) {
  se (!token || typeof token !== 'string') restituisci null;
  const parts = token.split('.');
  se (parts.length !== 4 || parts[0] !== 'v1') restituisci null;
  const expiresAt = parseInt(parts[1], 10);
  se (isNaN(expiresAt) || expiresAt < Date.now()) restituisce null;
  const expectedSig = hmacSign(`v1.${parts[1]}.${parts[2]}`);
  Tentativo {
    se (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(parts[3]))) restituisce null;
    const email = Buffer.from(parts[2], 'base64url').toString('utf8');
    restituisci { email, expiresAt };
  } catch (e) { return null; }
}

funzione parseCookies(cookieHeader) {
  const cookies = {};
  se (!cookieHeader) restituisci i cookie;
  cookieHeader.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    se (k) cookies[k] = v.join('=');
  });
  restituire i cookie;
}

funzione getAuthenticatedUser(req) {
  se (!AUTH_ENABLED) restituisci { email: 'autenticazione disabilitata' };
  const cookies = parseCookies(req.headers.cookie || '');
  restituisci verifySessionToken(cookies[AUTH_COOKIE_NAME]);
}

funzione setAuthCookie(res, email) {
  const token = createSessionToken(email);
  const maxAge = GIORNI_SESSIONE_AUTORIZZAZIONE * 24 * 60 * 60;
  res.setHeader('Set-Cookie', `${AUTH_COOKIE_NAME}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`);
}

funzione clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

// Genera token sicuro per magic link (32 byte casuali = ~43 caratteri url-safe)
funzione generateMagicLinkToken() {
  restituisci crypto.randomBytes(32).toString('base64url');
}

// Invia email tramite API di reinvio
funzione asincrona sendMagicLinkEmail(email, magicLink) {
  se (!RESEND_API_KEY) genera un nuovo errore ('RESEND_API_KEY mancante');
  const html = `<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif; max-width:560px; margin:40px auto; padding:40px 32px; background:#F5F1E8; border-radius:16px; color:#1A1A1A;">
  <div style="background:#FFFFFF; padding:40px 36px; border-radius:14px; box-shadow:0 8px 24px rgba(0,0,0,0.06);">
    <div style="font-size:1.35rem; font-weight:800; letter-spacing:0.08em; text-transform:uppercase; margin-bottom:6px;">T. <span style="color:#C9A961;">Luxy</span> · ERP</div>
    <div style="font-size:0.72rem; color:#8E8E8E; text-transform:uppercase; letter-spacing:0.15em; font-weight:600; margin-bottom:32px;">Dashboard di marginalità</div>
    <h1 style="font-size:1.1rem; margin:0 0 18px 0;">🔐 Il tuo link di accesso</h1>
    <p style="font-size:0.92rem; line-height:1.6; color:#444; margin-bottom:28px;">Clicca il bottone qui sotto per accedere alla dashboard. Il collegamento è valido per <strong>${MAGIC_LINK_MINUTES} minuti</strong> e può essere utilizzato una sola volta.</p>
    <div style="text-align:center; margin:32px 0;">
      <a href="${magicLink}" style="display:inline-block; background:#1A1A1A; color:#FFFFFF; text-decoration:none; padding:14px 32px; border-radius:10px; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; font-size:0.88rem;">Entra nella Dashboard</a>
    </div>
    <p style="font-size:0.78rem; color:#8E8E8E; line-height:1.5; margin-top:32px; padding-top:20px; border-top:1px solid #F0EBDF;">Se non hai richiesto questo link, ignora semplicemente questa email — nessun accesso sarà concesso.<br><br>Link diretto (se il bottone non funziona):<br><span style="word-break:break-all; colore:#666; dimensione carattere:0,72rem;">${magicLink}</span></p>
  </div>
  <div style="text-align:center; font-size:0.7rem; color:#8E8E8E; margin-top:20px; letter-spacing:0.04em;">T. Luxy ERP · Business Intelligence</div>
  </body></html>`;
  const testo = `T. LUXY ERP - Accesso Dashboard\n\nClicca il link per accedere (valido ${MAGIC_LINK_MINUTES} minuti):\n${magicLink}\n\nSe non hai richiesto tu questo link, ignora questa email.`;
  const res = await fetch('https://api.resend.com/emails', {
    metodo: 'POST',
    intestazioni: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    corpo: JSON.stringify({
      da: EMAIL_FROM,
      a: [email],
      oggetto: 'Il tuo link di accesso T. Luxy ERP',
      html,
      testo
    })
  });
  se (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Errore API di reinvio ${res.status}: ${errorBody}`);
  }
  restituisci await res.json();
}

// Pagina HTML di login/conferma/errore
funzione loginHTMLPage(messaggio, isError) {
  const msgBlock = messaggio ? `<div class="${isError ? 'errore' : 'info'} mostra">${messaggio}</div>` : '';
  restituisci `<!DOCTYPE html>
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
  .btn { larghezza: 100%; spaziatura interna: 14px 20px; sfondo: #1A1A1A; colore: #FFFFFF; bordo: nessuno; raggio del bordo: 10px; dimensione del carattere: 0,9rem; peso del carattere: 700; trasformazione del testo: maiuscolo; spaziatura tra le lettere: 0,08em; cursore: puntatore; transizione: tutte 0,2s; margine superiore: 8px; famiglia di caratteri: ereditarietà; }
  .btn:hover { background: #333; transform: translateY(-1px); }
  .btn:disabled { background: #BBB; cursor: not-allowed; transform: none; }
  .error { background: #FCEEEE; color: #BF4747; padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 20px; border-left: 3px solid #BF4747; display: none; }
  .info { background: #E6F4EE; color: #006b4a; padding: 14px 18px; border-radius: 8px; font-size: 0.88rem; margin-bottom: 20px; border-left: 3px solid #008060; display: none; line-height: 1.5; }
  .error.show, .info.show { display: block; }
  .footer { margin-top: 28px; padding-top: 20px; border-top: 1px solid #F0EBDF; font-size: 0.72rem; color: #8E8E8E; text-align: center; letter-spacing: 0.04em; }
</style></head>
<corpo>
  <div class="card">
    <div class="logo">T. <span class="logo-accent">Luxy</span> · ERP</div>
    <div class="subtitle">Dashboard della marginalità</div>
    <h1>🔐Accesso riservato</h1>
    <p class="intro">Inserisci la tua email autorizzata. Riceverai un link sicuro per entrare. Valido ${MAGIC_LINK_MINUTES} minuti.</p>
    ${msgBlock}
    <form id="loginForm" action="/api/request-magic-link" method="POST">
      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" autocomplete="email" autofocus required placeholder="nome@azienda.com">
      </div>
      <button type="submit" class="btn" id="submitBtn">Invia link magico</button>
    </form>
    <div class="footer">Business Intelligence · Autenticazione protetta</div>
  </div>
<script>
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const btn = document.getElementById('submitBtn');
  btn.disabled = vero; btn.textContent = 'Invio in corso...';
  Tentativo {
    const res = await fetch('/api/request-magic-link', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email}) });
    const data = await res.json();
    // Sempre successo percepito (anti-enumerazione): mostriamo lo stesso messaggio
    window.location.href = '/login?sent=1';
  } catch(e) {
    btn.disabled = false; btn.textContent = 'Tramite link magico';
    alert('Errore di rete, riprova');
  }
});
</script>
</body></html>`;
}

// ============ RILEVAMENTO AMBIENTE KV ============
// Vercel può creare env vars con nomi diversi alla seconda versione integrazione:
// - KV_REST_API_URL + KV_REST_API_TOKEN (vecchio Vercel KV)
// - UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN (Upstash diretto)
// - KV_REDIS_URL (nuovo Upstash marketplace — formato rediss://default:TOKEN@HOST:PORT)
// Questo codice prova tutti e 3 i formati automaticamente.
funzione detectKvCredentials() {
  se (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
    restituisci { url: process.env.KV_REST_API_URL, token: process.env.KV_REST_API_TOKEN, source: 'kv_rest' };
  }
  se (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    restituisci { url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN, source: 'upstash_rest' };
  }
  const redisUrl = process.env.KV_REDIS_URL || process.env.REDIS_URL;
  se (redisUrl) {
    Tentativo {
      const u = nuovo URL(redisUrl);
      const token = u.password || u.username;
      const host = u.hostname;
      se (host && token) {
        restituisci { url: `https://${host}`, token, source: 'parsed_from_redis_url' };
      }
    } catch (e) {}
  }
  restituisci null;
}
const KV_CREDENTIALS = detectKvCredentials();
const KV_REST_API_URL = KV_CREDENTIALS ? KV_CREDENTIALS.url : '';
const KV_REST_API_TOKEN = KV_CREDENTIALS ? KV_CREDENTIALS.token : '';
const KV_SOURCE = KV_CREDENTIALS ? KV_CREDENTIALS.source : null;
const KV_ENABLED = !!(KV_REST_API_URL && KV_REST_API_TOKEN);

const SHOPIFY_FEE_PERCENT = 0,0015;
const SHOPIFY_FEE_FIXED = 0;

// ============ ARCHIVIAZIONE KV (Upstash Redis tramite Vercel KV) ============
// Cache persistente dei costi: sopravvive all'archiviazione dei prodotti su Shopify.
funzione asincrona kvGet(chiave) {
  se (!KV_ENABLED) restituisci null;
  Tentativo {
    const res = await fetch(`${KV_REST_API_URL}/get/${encodeURIComponent(key)}`, {
      intestazioni: { 'Autorizzazione': `Portatore ${KV_REST_API_TOKEN}` }
    });
    se (!res.ok) restituisci null;
    const data = await res.json();
    restituisci i dati.risultato; // stringa o null
  } catch (e) { return null; }
}
funzione asincrona kvSet(chiave, valore) {
  se (!KV_ENABLED) restituisci falso;
  Tentativo {
    const res = await fetch(`${KV_REST_API_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}`, {
      intestazioni: { 'Autorizzazione': `Portatore ${KV_REST_API_TOKEN}` }
    });
    restituisci res.ok;
  } catch (e) { return false; }
}
// kvSetEx: imposta con TTL (secondi)
funzione asincrona kvSetEx(chiave, ttlSec, valore) {
  se (!KV_ENABLED) restituisci falso;
  Tentativo {
    // Upstash Redis REST: SET chiave valore EX ttl → /set/{chiave}/{valore}?EX={ttl}
    const url = `${KV_REST_API_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}?EX=${ttlSec}`;
    const res = await fetch(url, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
    restituisci res.ok;
  } catch (e) { return false; }
}
// kvDel: elimina chiave
funzione asincrona kvDel(chiave) {
  se (!KV_ENABLED) restituisci falso;
  Tentativo {
    const res = await fetch(`${KV_REST_API_URL}/del/${encodeURIComponent(key)}`, {
      intestazioni: { 'Autorizzazione': `Portatore ${KV_REST_API_TOKEN}` }
    });
    restituisci res.ok;
  } catch (e) { return false; }
}
funzione asincrona kvMGet(chiavi) {
  se (!KV_ENABLED || keys.length === 0) restituisci {};
  Tentativo {
    // MGET accetta array di chiavi
    const url = `${KV_REST_API_URL}/mget/${keys.map(k => encodeURIComponent(k)).join('/')}`;
    const res = await fetch(url, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
    se (!res.ok) restituisci {};
    const data = await res.json();
    const risultati = {};
    (data.result || []).forEach((val, idx) => { if (val !== null) results[keys[idx]] = val; });
    risultati di ritorno;
  } catch (e) { return {}; }
}
funzione asincrona kvMSet(pairs) {
  se (!KV_ENABLED || Object.keys(pairs).length === 0) restituisci false;
  Tentativo {
    // Facciamo più SET in parallelo (Upstash non ha MSET in REST)
    const concorrenza = 5;
    const entries = Object.entries(coppie);
    per (sia i = 0; i < entries.length; i += concurrency) {
      const batch = entries.slice(i, i + concurrency);
      await Promise.all(batch.map(([k, v]) => kvSet(k, v)));
    }
    restituisci vero;
  } catch (e) { return false; }
}

// Riconosce prodotti DUO dallo SKU (DUO- all'inizio)
funzione isDuoSku(sku) {
  return !!(sku && typeof sku === 'string' && /^DUO-/i.test(sku.trim()));
}

// ============ AIUTI PER LA VALUTA ============
// Tassi di cambio fallback (aggiornare periodicamente). Usati SOLO se Shopify non fornisce shop_money
// (caso estremamente raro: ordini molto vecchi pre-multi-valuta).
const SHOP_CURRENCY = 'EUR';
const FALLBACK_RATES_TO_EUR = {
  EUR: 1,0,
  USD: 0,92,
  GBP: 1,17,
  SEK: 0,087,
  NOK: 0,086,
  DKK: 0,134,
  CHF: 1.05,
  PLN: 0,23,
  CZK: 0,041,
  HUF: 0,0026,
  JPY: 0,0061,
  CAD: 0,67,
  AUD: 0,61,
  SGD: 0,68,
  HKD: 0,118,
  RON: 0,20
};

// Converti un prezzo in EUR. Prova nell'ordine:
// 1) money_set.shop_money (già convertito da Shopify al cambio del giorno — il più accurato)
// 2) calcolo manuale con tasso fallback
// 3) prezzo originale se già in EUR
funzione toEurAmount(moneySet, fallbackAmount, fallbackCurrency) {
  // moneySet = esempio ordine.total_price_set (o line_item.price_set)
  se (moneySet && moneySet.shop_money && moneySet.shop_money.amount !== undefined) {
    const amt = parseFloat(moneySet.shop_money.amount);
    se (!isNaN(amt) && (moneySet.shop_money.currency_code === SHOP_CURRENCY || !moneySet.shop_money.currency_code)) {
      importo di ritorno;
    }
  }
  // Fallback: conversione manuale
  const amt = parseFloat(fallbackAmount);
  se (isNaN(amt)) restituisce 0;
  const cur = (fallbackCurrency || SHOP_CURRENCY).toUpperCase();
  se (valuta === VALUTA_NEGOZIO) restituisci importo;
  const rate = FALLBACK_RATES_TO_EUR[cur];
  se (tasso) restituisci importo * tasso;
  importo del reso; // ultima spiaggia: ritorna così com'è
}

// Estrai informazioni sulla valuta di un ordine
funzione getOrderCurrencyInfo(ordine) {
  const originalCurrency = ordine.currency || SHOP_CURRENCY;
  const isForeign = originalCurrency !== SHOP_CURRENCY;
  const eurTotal = toEurAmount(ordine.total_price_set, ordine.total_price, originalCurrency);
  const originalTotal = parseFloat(ordine.total_price) || 0;
  const exchangeRate = isForeign && originalTotal > 0 ? eurTotal / originalTotal : 1;
  restituisci { valuta originale, è estera, totale euro, totale originale, tasso di cambio };
}

// Estrai informazioni sul rimborso di un ordine (Shopify espone array rimborsi nel JSON ordine)
// Restituisce: importo totale rimborsato (in EUR), articoli rimborsati, status, ecc.
funzione getOrderRefundInfo(ordine) {
  const rimborsi = ordine.rimborsi || [];
  se (rimborsi.lunghezza === 0) {
    return { hasRefund: false, isFullRefund: false, isPartialRefund: false, totalRefundedEur: 0, rimborsatoQuantità: 0, rimborsatoLineItems: [], returnCount: 0 };
  }
  const ordCurrency = ordine.currency || SHOP_CURRENCY;
  lascia totalRefundedEur = 0;
  lascia che la quantità rimborsata sia pari a 0;
  const refundedLineItems = [];
  
  rimborsi.perOgni(rimborso => ​​{
    // 1) Importo monetario rimborsato (transazioni di tipo 'refund')
    (rimborso.transazioni || []).perOgni(tx => {
      se (tx.kind === 'refund' && (tx.status === 'success' || !tx.status)) {
        const amt = toEurAmount(tx.amount_set, tx.amount, tx.currency || ordCurrency);
        totaleRimborsatoEur += importo;
      }
    });
    
    // 2) Quali line_items sono stati rimborsati (per quantità)
    (rimborso.rimborso_articoli_rimborso || []).perogni(rli => {
      const qty = parseInt(rli.quantity) || 0;
      quantità rimborsata += quantità;
      // line_item_id punta al line_item originale dell'ordine
      const subtotalEur = toEurAmount(rli.subtotal_set, rli.subtotal, ordCurrency);
      const totalTaxEur = toEurAmount(rli.total_tax_set, rli.total_tax, ordCurrency);
      refundedLineItems.push({
        line_item_id: rli.line_item_id,
        quantità: quantità,
        subtotale_euro: subtotaleEur,
        imposte_totali_euro: imposte_totali_euro
      });
    });
  });
  
  // Determina se è rimborso completo: confronto con prezzo totale dell'ordine
  const orderTotalEur = toEurAmount(ordine.total_price_set, ordine.total_price, ordCurrency);
  const totalQty = (ordine.line_items || []).reduce((s, li) => s + (parseInt(li.quantity) || 0), 0);
  const isFullRefund = totalRefundedEur > 0 && Math.abs(totalRefundedEur - orderTotalEur) < 0,5; // tolleranza 50 cent
  const isPartialRefund = totalRefundedEur > 0 && !isFullRefund;
  
  ritorno {
    hasRefund: totalRefundedEur > 0,
    èRimborso completo,
    èRimborsoParziale,
    Rimborso totale in euro,
    Quantità rimborsata,
    quantità totale: quantità totale,
    voci di riga rimborsate,
    numero di rimborsi: rimborsi.lunghezza
  };
}

// ============ PREVISIONE DI PAGAMENTO ============
// Dato un ordine + config MP, calcola quando arriverà il pagamento (o più pagamenti se divisi).
// Ritorna array di { data: Date, importo_eur: number, nota: string, parte: number }
function calcolaPagamentiPrevisti(dataOrdine, policy, nettoIncassato) {
  se (!policy || nettoIncassato <= 0) restituisci [];
  const orderDate = new Date(dataOrdine);
  if (isNaN(orderDate.getTime())) return [];
  
  const risultato = [];
  
  switch (policy.type) {
    caso 'immediato': {
      risultato.push({ data: orderDate, importo_eur: nettoIncassato, nota: 'Accredito immediato', parte: 1 });
      rottura;
    }
    caso 'giorni_fissi': {
      const d = nuova data(dataordine);
      d.setDate(d.getDate() + (policy.days_offset || 0));
      result.push({ data: d, importo_eur: nettoIncassato, nota: `Ordine + ${policy.days_offset}gg`, parte: 1 });
      rottura;
    }
    caso 'settimanale': {
      // Stima: ordine + N giorni, poi arrotondato al lunedì successivo
      const d = nuova data(dataordine);
      d.setDate(d.getDate() + (policy.days_offset || 21));
      const dayOfWeek = d.getDay(); // 0 = domenica, 1 = lunedì
      const daysToMonday = dayOfWeek === 0 ? 1 : (dayOfWeek === 1 ? 0 : (8 - dayOfWeek));
      d.setDate(d.getDate() + daysToMonday);
      result.push({ data: d, importo_eur: nettoIncassato, nota: `Settimanale (~${policy.days_offset}gg)`, parte: 1 });
      rottura;
    }
    caso 'monthly_decade': {
      // Ordini del mese M pagati il ​​giorno X (es. 10) del mese M + mese_offset
      const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (policy.month_offset || 2), policy.payout_day || 10);
      risultato.push({ data: target, importo_eur: nettoIncassato, nota: `Prima decade mese+${policy.month_offset}`, parte: 1 });
      rottura;
    }
    caso 'monthly_mid': {
      const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (policy.month_offset || 2), policy.payout_day || 15);
      risultato.push({ data: target, importo_eur: nettoIncassato, nota: `Prima metà mese+${policy.month_offset}`, parte: 1 });
      rottura;
    }
    caso 'split': {
      (policy.parts || []).forEach((part, idx) => {
        const target = new Date(orderDate.getFullYear(), orderDate.getMonth() + (part.month_offset || 1), part.payout_day || 10);
        const importoParte = nettoIncassato * (part.pct / 100);
        risultato.push({ dati: target, importo_eur: importoParte, nota: `${part.pct}% (mese+${part.month_offset})`, parte: idx + 1 });
      });
      rottura;
    }
    caso 'prepaid_balance': {
      // Non genera pagamento futuro, scala dal wallet
      result.push({ data: orderDate, importo_eur: 0, nota: 'Wallet (scalato da credito)', parte: 1, is_wallet: true });
      rottura;
    }
    predefinito: {
      // Fallback: usa data ordine + 30gg
      const d = nuova data(dataordine);
      d.setDate(d.getDate() + 30);
      result.push({ data: d, importo_eur: nettoIncassato, nota: 'Policy sconosciuta (+30gg)', parte: 1 });
    }
  }
  
  restituisci il risultato;
}

// Funzione di supporto: formatta i dati nel formato YYYY-MM-DD
funzione fmtDateISO(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  restituisci `${y}-${m}-${dd}`;
}

// Helper: chiave mese AAAA-MM
funzione fmtMonthKey(d) {
  restituisci `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

lascia cachedToken = null;
lascia che tokenExpiry = null;

funzione asincrona getShopifyAccessToken() {
  se (cachedToken && tokenExpiry && Date.now() < tokenExpiry) restituisci cachedToken;
  se (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET) genera un nuovo errore ('Credenziali mancanti');
  const body = new URLSearchParams();
  body.append('client_id', SHOPIFY_CLIENT_ID);
  body.append('client_secret', SHOPIFY_CLIENT_SECRET);
  body.append('grant_type', 'client_credentials');
  const response = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
    metodo: 'POST',
    intestazioni: { 'Content-Type': 'application/x-www-form-urlencoded' },
    corpo: corpo.toString()
  });
  if (!response.ok) { const errText = await response.text(); throw new Error(`HTTP ${response.status}: ${errText}`); }
  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
  restituisci il token memorizzato nella cache;
}

// Politiche di pagamento (da Excel TL_REGOLE_MARKET_PLACE + istruzioni utente):
// tipo: 'monthly_decade' → ordini del mese M pagati il ​​giorno X del mese M+offset
// tipo: 'monthly_mid' → prima metà del mese (~giorno 15)
// tipo: 'split' → % al giorno X1, % al giorno X2 dopo data ordine
// tipo: 'fixed_days' → data_ordine + N giorni
// tipo: 'settimanale' → pagamento settimanale (stima: data_ordine + N giorni)
// tipo: 'immediato' → data_ordine (accreditato ~subito)
// digita: 'saldo_prepagato' → sistema wallet (Balardi: inserisci ricariche, scali)
const CONFIGURAZIONI_MARKETPLACE = {
  'SECRET_SALES': { nome: 'Secret Sales', sconto_percentuale: 0, fee_principale: 20, fee_secondaria: 0, fee_fissa_trasporto: 2, fee_fissa_packaging: 2, pagamento: 'Prima metà mese+2', payment_policy: { type: 'monthly_mid', Month_offset: 2, payout_day: 15 } },
  'FASHION_TAMERS': { nome: 'Fashion Tamers', sconto_percentuale: 0, fee_principale: 32, fee_secondaria: 0, fee_accessoria: 2, fee_fissa_trasporto: 15, fee_fissa_packaging: 6, pagamento: 'Prima metà mese+2', payment_policy: { type: 'monthly_mid', Month_offset: 2, giorno_pagamento: 15 } },
  'INTRA_MIRROR': { nome: 'Intra Mirror', sconto_percentuale: 15, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', Month_offset: 2, payout_day: 10 } },
  'BALARDI': { nome: 'Balardi', sconto_percentuale: 35, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Prepagato (wallet)', payment_policy: { type: 'prepaid_balance' } },
  'THE_BRADERY': { nome: 'The Bradery', sconto_percentuale: 5, fee_principale: 17, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 2, pagamento: 'Split 80/20 (mese+1 / mese+2)', payment_policy: { type: 'split', parts: [{ pct: 80, offset_mese: 1, giorno_pagamento: 10 }, { pct: 20, offset_mese: 2, giorno_pagamento: 10 }] } },
  'BOUTIQUE_MALL': { nome: 'Boutique Mall', sconto_percentuale: 33.3, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', Month_offset: 2, payout_day: 10}},
  'ARCHIVISTA': { nome: 'Archivist', sconto_percentuale: 0, fee_principale: 22, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', Month_offset: 2, payout_day: 10 } },
  'MIINTO': { nome: 'Miinto', sconto_percentuale: 0, fee_principale: 17.75, fee_secondaria: 2.25, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', Month_offset: 2, giorno_pagamento: 10 } },
  'WINKELSTRAAT': { nome: 'Winkelstraat', sconto_percentuale: 0, fee_principale: 17, fee_secondaria: 0, fee_accessoria: 9, fee_fissa_trasporto: 15, fee_fissa_packaging: 0, pagamento: 'Settimanale (~21gg)', payment_policy: { type: 'weekly', days_offset: 21 } },
  'ITALIST': { nome: 'Italist', sconto_percentuale: 20, fee_principale: 25.5, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 4, pagamento: 'Prima decade mese+2', payment_policy: { type: 'monthly_decade', Month_offset: 2, payout_day: 10 } },
  'JAMMY_DUDE': { nome: 'Jammy Dude', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: '10gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 10 } },
  'POIZON': { nome: 'Poizon', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Immediato', payment_policy: { type: 'immediate' } },
  'BRANDSGATEWAY': { nome: 'Brandsgateway', sconto_percentuale: 13, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 0, pagamento: '45gg data ordine', payment_policy: { type: 'fixed_days', days_offset: 45 } },
  'TLUXY_SITO': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato (Shopify +2gg)', payment_policy: { type: 'fixed_days', days_offset: 2 } },
  'MARK_FOYS': { nome: 'Mark Foy', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Prepagato immediato', payment_policy: { type: 'immediate' } },
  'GIGLIO': { nome: 'GIGLIO.COM', sconto_percentuale: 0, fee_principale: 30, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'TBD (prepagato per ora)', payment_policy: { type: 'immediate' } }
};

// Normalizza source_name per corrispondenza più robusto: minuscolo + spazi→trattini
funzione normalizeSourceName(name) {
  return (nome || '').toLowerCase().trim().replace(/\s+/g, '-');
}

const SOURCE_NAME_MAP = {
  'web': 'TLUXY_SITE', 'pos': 'TLUXY_SITE', 'shopify_draft_order': 'TLUXY_SITE', 'shopify-draft-order': 'TLUXY_SITE',
  'miinto': 'MIINTO', 'miinto-app': 'MIINTO',
  'vendite segrete': 'SEGRETI_VENDITE', 'vendite segrete': 'SEGRETI_VENDITE',
  'fashion-tamers': 'FASHION_TAMERS', 'fashiontamers': 'FASHION_TAMERS',
  'intra-mirror': 'INTRA_MIRROR', 'intramirror': 'INTRA_MIRROR',
  'balardi': 'BALARDI',
  'the-bradery': 'THE_BRADERY', 'thebradery': 'THE_BRADERY', 'bradery': 'THE_BRADERY',
  'my-moon-store': 'THE_BRADERY', 'mymoonstore': 'THE_BRADERY', 'my-moon-store-syncio-order': 'THE_BRADERY', '1615469': 'THE_BRADERY',
  'boutique-mall': 'BOUTIQUE_MALL', 'boutiquemall': 'BOUTIQUE_MALL',
  'archivista': 'ARCHIVISTA', 'winkelstraat': 'WINKELSTRAAT',
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

funzione getIvaPerPaese(countryCode) {
  se (!countryCode) restituisci 22;
  restituisci IVA_PER_PAESE[countryCode.toUpperCase()] ?? 0;
}

funzione èWinkelstraatOrdine(ordine) {
  // Controllo multicriterio in OR
  const email = (ordine.email || ordine.customer?.email || '').toLowerCase();
  se (email.include('@winkelstraat.nl')) restituisce 'email';
  
  const tags = (ordine.tags || '').toLowerCase();
  if (tags.includes('winkelstraat')) restituisce 'tag';
  
  // source_name può contenere "copernicus" per importazione automatica
  const sourceName = (ordine.source_name || '').toLowerCase();
  se (sourceName.include('copernicus') || sourceName.include('winkelstraat')) restituisce 'source_name';
  
  // Nota ordine e attributi nota
  const note = (ordine.note || '').toLowerCase();
  se (note.include('winkelstraat') || note.include('copernicus')) restituisce 'note';
  
  const noteAttrs = (ordine.note_attributes || []).map(a => ((a.name || '') + ' ' + (a.value || '')).toLowerCase()).join(' ');
  se (noteAttrs.include('winkelstraat') || noteAttrs.include('copernicus')) restituisci 'note_attributes';
  
  // Indirizzo di spedizione: indirizzo1, indirizzo2, nome, azienda
  const ship = ordine_shipping_address || {};
  const shipFields = [ship.address1, ship.address2, ship.name, ship.company, ship.first_name, ship.last_name].filter(Boolean).map(s => s.toLowerCase()).join(' ');
  se (shipFields.include('winkelstraat')) restituisce 'indirizzo_di_spedizione';
  
  restituisci null;
}

funzione riconosciMercato(ordine) {
  const rawSource = (ordine.source_name || '').trim();
  const sourceName = normalizeSourceName(rawSource);
  const tags = (ordine.tags || '').toLowerCase();
  const email = (ordine.email || ordine.customer?.email || '').toLowerCase();
  
  // PRIORITÀ 1: tag specifici che hanno precedenza sul source_name
  // Brandsgateway è un fornitore dropship, arriva con source=web ma è stato classificato come BRANDSGATEWAY
  se (tag.include('brandsgateway')) {
    restituisci { chiave: 'BRANDSGATEWAY', configurazione: MARKETPLACE_CONFIGS.BRANDSGATEWAY };
  }
  
  // PRIORITÀ 2: Winkelstraat via Copernicus (import da external) - multicriterio
  const wsMatch = isWinkelstraatOrder(ordine);
  se (wsMatch) {
    return { chiave: 'WINKELSTRAAT', configurazione: MARKETPLACE_CONFIGS.WINKELSTRAAT };
  }
  
  // PRIORITÀ 3: Mark Foy's Department Store (condivide fonte 1615469 con The Bradery)
  // Rilevamento tramite tag "mark foy" oppure email non-bradery con source 1615469
  se (tag.include('mark foy') || tags.include("mark foy's")) {
    restituisci { chiave: 'MARK_FOYS', configurazione: MARKETPLACE_CONFIGS.MARK_FOYS };
  }
  // Caso sub: source 1615469 MA email non è di thebradery → Mark Foy's
  se (rawSource === '1615469' && email && !email.includes('thebradery')) {
    restituisci { chiave: 'MARK_FOYS', configurazione: MARKETPLACE_CONFIGS.MARK_FOYS };
  }
  
  // PRIORITÀ 4: Giglio.com - rilevamento tramite il nome della società di spedizione/fatturazione
  // Il cliente ha sempre ragione sociale "Giglio.com Spa"
  const shipCompany = (ordine.shipping_address?.company || '').toLowerCase();
  const billCompany = (ordine.billing_address?.company || '').toLowerCase();
  const custFirstName = (ordine.customer?.first_name || '').toLowerCase();
  const custLastName = (ordine.customer?.last_name || '').toLowerCase();
  const custDefaultCompany = (ordine.customer?.default_address?.company || '').toLowerCase();
  Se (
    shipCompany.includes('giglio') ||
    billCompany.includes('giglio') ||
    custDefaultCompany.includes('giglio') ||
    custFirstName.includes('giglio') ||
    custLastName.includes('giglio')
  ) {
    restituisci { chiave: 'GIGLIO', configurazione: MARKETPLACE_CONFIGS.GIGLIO };
  }
  
  // Match diretto normalizzato su source_name
  se (SOURCE_NAME_MAP[sourceName]) restituisci { chiave: SOURCE_NAME_MAP[sourceName], configurazione: MARKETPLACE_CONFIGS[SOURCE_NAME_MAP[sourceName]] };
  
  // Rilevamento veleno: fonte numerica + email cliente "poizon"
  const isNumericSource = /^\d+$/.test(rawSource);
  se (isNumericSource && email.includes('poizon')) {
    restituisci { chiave: 'POIZON', configurazione: MARKETPLACE_CONFIGS.POIZON };
  }
  
  // Corrispondenza parziale su source_name
  per (const [pattern, mpKey] di Object.entries(SOURCE_NAME_MAP)) {
    se (sourceName.include(pattern) || pattern.include(sourceName)) restituisce { chiave: mpKey, configurazione: MARKETPLACE_CONFIGS[mpKey] };
  }
  
  // Corrispondenza dei tag su
  per (const [pattern, mpKey] di Object.entries(SOURCE_NAME_MAP)) {
    se (tags.includes(pattern)) restituisce { chiave: mpKey, configurazione: MARKETPLACE_CONFIGS[mpKey] };
  }
  
  const defaultKey = process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE';
  restituisci { chiave: defaultKey, configurazione: MARKETPLACE_CONFIGS[defaultKey] };
}

funzione hasJDTag(productTagsString) {
  se (!productTagsString) restituisce falso;
  const tags = productTagsString.split(',').map(t => t.trim());
  const regex = /(^|[\s,\-_])JD([\s,\-_]|$)/i;
  restituisci tags.some(tag => regex.test(tag));
}

funzione asincrona fetchProductsTags(productIds, cache = {}) {
  const toFetch = productIds.filter(id => id && !(id in cache));
  se (toFetch.length === 0) restituisci cache;
  const token = await getShopifyAccessToken();
  const chunks = [];
  per (lascia i = 0; i < toFetch.length; i += 100) chunks.push(toFetch.slice(i, i + 100));
  per (blocco costante di blocchi) {
    Tentativo {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?ids=${chunk.join(',')}&fields=id,tags`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      se (!response.ok) continua;
      const data = await response.json();
      (data.products || []).forEach(p => { cache[p.id] = p.tags || ''; });
      chunk.forEach(id => { if (!(id in cache)) cache[id] = ''; });
    } catch (e) {
      chunk.forEach(id => { if (!(id in cache)) cache[id] = ''; });
    }
  }
  restituisci la cache;
}

funzione asincrona applyJDFilter(ordini) {
  const jdOrders = ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE');
  se (jdOrders.length === 0) restituisci ordini;
  const productIdsSet = new Set();
  jdOrders.forEach(o => (o.line_items || []).forEach(item => { if (item.product_id) productIdsSet.add(item.product_id); }));
  const tagsCache = await fetchProductsTags([...productIdsSet]);
  restituisci ordini.map(o => {
    se (riconosciMarketplace(o).key !== 'JAMMY_DUDE') restituisci o;
    const filteredItems = (o.line_items || []).filter(item => hasJDTag(tagsCache[item.product_id]));
    restituisci { ...o, line_items: filteredItems, _jd_excluded: filteredItems.length === 0 };
  }).filter(o => !o._jd_excluded);
}

funzione asincrona processOrders(ordini) {
  const jdOrdersOriginalIds = new Set(ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE').map(o => o.id));
  const filtered = await applyJDFilter(ordini);
  restituisci filtered.map(o => {
    se (jdOrdersOriginalIds.has(o.id)) {
      const newTotal = (o.line_items || []).reduce((sum, item) => sum + (parseFloat(item.price) || 0) * (parseInt(item.quantity) || 0), 0);
      restituisci { ...o, prezzo_totale: String(newTotal.toFixed(2)), imposta_totale: '0.00' };
    }
    ritorno o;
  });
}

// ============ COSTO REALE (v4.3 - strategia product/{id}.json con logging) ============
// Strategia: per ogni product_id unico, 1 chiamata a /products/{id}.json che ritorna
// tutte le varianti del prodotto con il loro inventory_item_id. Batch Poi /inventory_items.json
// Aggiunge logging dettagliato delle chiamate fallite.
funzione asincrona fetchVariantCosts(variantIds, orderProductIds = []) {
  const stats = { products_tentati: 0, products_ok: 0, products_falliti: [], variants_mappati: 0, inventory_tentati: 0, inventory_ok: 0, inventory_falliti: [], kv_hit: 0, kv_miss: 0, kv_new_saved: 0 };
  se (variantIds.length === 0) restituisci { costi: {}, statistiche };
  
  const uniqueVariantIds = [...new Set(variantIds.filter(Boolean))];
  const costsFromKV = {};
  
  // STEP 0: PROVO A LEGGERE DAL KV (cache persistente) PRIMA di chiamare Shopify
  se (KV_ENABLED) {
    const kvKeys = uniqueVariantIds.map(v => `variant_cost_${v}`);
    const kvResults = await kvMGet(kvKeys);
    uniqueVariantIds.forEach(v => {
      const key = `variant_cost_${v}`;
      se (kvResults[key] !== undefined) {
        const parsed = parseFloat(kvResults[key]);
        if (!isNaN(parsed)) { costsFromKV[v] = parsed; stats.kv_hit++; }
        altrimenti stats.kv_miss++;
      } altrimenti stats.kv_miss++;
    });
  }
  
  // Solo variante_id che NON abbiamo già nel KV vanno chiamati su Shopify
  const variantsToFetch = uniqueVariantIds.filter(v => !(v in costsFromKV));
  const uniqueProductIds = [...new Set(orderProductIds.filter(Boolean))];
  const variantToInventoryItem = {};
  
  // Se tutti i varianti sono in cache, salta le chiamate Shopify
  se (variantsToFetch.length === 0) {
    restituisci { costi: costiDaKV, statistiche };
  }
  
  const token = await getShopifyAccessToken();
  
  // STEP 1: per ogni product_id, chiamo /products/{id}.json (funziona sempre)
  funzione asincrona fetchProductWithRetry(pid, attempt = 0) {
    statistiche_prodotti_tentati++;
    Tentativo {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products/${pid}.json?fields=id,variants`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      se (response.status === 429 || response.status >= 500) {
        se (tentativo < 4) {
          const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
          attendi nuova Promise(r => impostaTimeout(r, attendi));
          restituisci fetchProductWithRetry(pid, tentativo + 1);
        }
        stats.products_falliti.push({ product_id: pid, status: response.status, reason: 'max_retries' });
        ritorno;
      }
      se (!risposta.ok) {
        stats.products_falliti.push({ product_id: pid, status: response.status, reason: 'http_error' });
        ritorno;
      }
      const data = await response.json();
      statistiche_prodotti_ok++;
      (data.product?.variants || []).forEach(v => {
        se (v.id && v.inventory_item_id) {
          variantToInventoryItem[v.id] = v.inventory_item_id;
          statistiche.varianti_mappati++;
        }
      });
    } catch (e) {
      se (tentativo < 3) {
        attendi nuova Promise(r => impostaTimeout(r, 600 * (tentativo + 1)));
        restituisci fetchProductWithRetry(pid, tentativo + 1);
      }
      stats.products_falliti.push({ product_id: pid, status: 'exception', reason: e.message });
    }
  }
  
  const concorrenza = 3;
  per (sia i = 0; i < uniqueProductIds.length; i += concorrenza) {
    const batch = uniqueProductIds.slice(i, i + concurrency);
    await Promise.all(batch.map(p => fetchProductWithRetry(p)));
  }
  
  // PASSO 1b: per variante non trovata tramite product, fallback a /variants/{id}.json
  const missing = uniqueVariantIds.filter(vid => !(vid in variantToInventoryItem));
  se (lunghezza mancante > 0) {
    funzione asincrona fetchVariantSingle(vid, attempt = 0) {
      Tentativo {
        const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/variants/${vid}.json?fields=id,inventory_item_id`;
        const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
        se (response.status === 429 || response.status >= 500) {
          se (tentativo < 4) {
            const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
            attendi nuova Promise(r => impostaTimeout(r, attendi));
            restituisci fetchVariantSingle(vid, tentativo + 1);
          }
          ritorno;
        }
        se (!risposta.ok) restituisci;
        const data = await response.json();
        se (data.variant && data.variant.inventory_item_id) {
          variantToInventoryItem[vid] = data.variant.inventory_item_id;
          statistiche.varianti_mappati++;
        }
      } catch (e) {
        se (tentativo < 3) {
          attendi nuova Promise(r => impostaTimeout(r, 600 * (tentativo + 1)));
          restituisci fetchVariantSingle(vid, tentativo + 1);
        }
      }
    }
    per (sia i = 0; i < lunghezza mancante; i += concorrenza) {
      const batch = missing.slice(i, i + concorrenza);
      await Promise.all(batch.map(v => fetchVariantSingle(v)));
    }
  }
  
  // PASSO 2: batch /inventory_items.json?ids= (questo endpoint supporta ids multipli)
  const inventoryIds = [...new Set(Object.values(variantToInventoryItem).filter(Boolean))];
  const inventoryToCost = {};
  const invChunks = [];
  for (let i = 0; i < inventoryIds.length; i += 50) invChunks.push(inventoryIds.slice(i, i + 50)); // chunk 50 invece di 100 per sicurezza
  
  funzione asincrona fetchInvWithRetry(chunk, attempt = 0) {
    statistiche_inventario_tentati++;
    Tentativo {
      const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${chunk.join(',')}`;
      const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      se (response.status === 429 || response.status >= 500) {
        se (tentativo < 4) {
          const wait = 600 * Math.pow(2, attempt) + Math.random() * 400;
          attendi nuova Promise(r => impostaTimeout(r, attendi));
          restituisci fetchInvWithRetry(chunk, tentativo + 1);
        }
        stats.inventory_falliti.push({ chunk_size: chunk.length, status: response.status, reason: 'max_retries' });
        ritorno;
      }
      se (!risposta.ok) {
        stats.inventory_falliti.push({ chunk_size: chunk.length, status: response.status, reason: 'http_error' });
        ritorno;
      }
      const data = await response.json();
      statistiche inventario_ok++;
      (data.inventory_items || []).forEach(item => {
        const costValue = item.cost;
        inventoryToCost[item.id] = (costValue !== null && costValue !== undefinito && costValue !== '' && !isNaN(parseFloat(costValue))) ? parseFloat(valorecosto): null;
      });
    } catch (e) {
      se (tentativo < 3) {
        attendi nuova Promise(r => impostaTimeout(r, 600 * (tentativo + 1)));
        restituisci fetchInvWithRetry(chunk, tentativo + 1);
      }
      stats.inventory_falliti.push({ chunk_size: chunk.length, status: 'exception', reason: e.message });
    }
  }
  
  per (blocco costante di invChunks) {
    attendi fetchInvWithRetry(chunk);
  }
  
  // Mappa finale + salvataggio KV dei NUOVI costi letti
  const newCostsFromShopify = {};
  Object.entries(variantToInventoryItem).forEach(([variantId, invId]) => {
    costo const = invId && inventoryToCost[invId] !== undefinito ? inventarioToCost[invId]: null;
    se (costo !== null && costo !== undefined) newCostsFromShopify[variantId] = costo;
  });
  
  // SALVA i nuovi costi su KV per il futuro (anche se il prodotto sarà cancellato)
  se (KV_ENABLED && Object.keys(newCostsFromShopify).length > 0) {
    const kvPairs = {};
    Object.entries(newCostsFromShopify).forEach(([vid, cost]) => {
      kvPairs[`variant_cost_${vid}`] = String(cost);
    });
    attendi kvMSet(kvPairs);
    stats.kv_new_saved = Object.keys(kvPairs).length;
  }
  
  // Unisci: costi da KV (già persistenti) + costi nuovi letti da Shopify
  const costi = { ...costiDaKV, ...nuoviCostiDaShopify };
  // Aggiungo null per i variante che Shopify non ha restituito e che non erano in KV
  uniqueVariantIds.forEach(v => { if (!(v in costs)) costs[v] = null; });
  
  restituisci { costi, statistiche };
}

funzione calcolaCostoOrdine(ordine, variantCosts, duoUserCosts = {}) {
  lascia costo_totale = 0;
  const errori = [];
  per (elemento costante di (ordine_line_items || [])) {
    const quantity = parseInt(item.quantity) || 0;
    let costUnit = item.variant_id ? variantCosts[item.variant_id] : null;
    // Fallback: per prodotti DUO, usa il costo inserito manualmente dall'utente nel simulatore
    se ((costUnit === null || costUnit === undefined) && isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) {
      costoUnità = duoUserCosts[item.variant_id];
    }
    se (costUnit === null || costUnit === undefined) {
      errori.push({ titolo: item.title, sku: item.sku || '', variant_id: item.variant_id, is_duo: isDuoSku(item.sku) });
      continuare;
    }
    costo_totale +=unità di costo * quantità;
  }
  return { costo: costo_totale, errori };
}

funzione calcolaFeesShopify(prezzo_netto, mpKey) {
  se (mpKey !== 'TLUXY_SITE') restituisci 0;
  restituisci prezzo_netto * PERCENTUALE_COMMISSIONE_SHOPIFY + COMMISSIONE_FISSA_SHOPIFY;
}

funzione calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce, spedizione, mp, mpKey) {
  const prezzo_netto_iva = prezzo_lordo - iva_scorporata;
  const prezzo_netto_marketplace = prezzo_netto_iva*(1 - mp.sconto_percentuale/100);
  const fees_shopify = calcolaFeesShopify(prezzo_netto_marketplace, mpKey);
  const fee_principale = prezzo_netto_marketplace* (mp.fee_principale/100);
  const commissione_secondaria = prezzo_netto_marketplace * ((mp.commissione_secondaria || 0) / 100);
  const tariffa_accessoria = prezzo_netto_marketplace * ((mp.tariffa_accessoria || 0) / 100);
  const fee_marketplace = fee_principale + fee_secondaria + fee_accessoria + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine_netto = prezzo_netto_marketplace - fees_shopify - fees_marketplace - costo_merce - spedizione;
  const margine_percentuale = prezzo_lordo > 0 ? (margine_netto/prezzo_lordo*100): 0;
  const costi_totali = costo_merce + spedizione + fees_shopify + fees_marketplace + iva_scorporata;
  return { prezzo_lordo_iva_inclusa: prezzo_lordo, iva_scorporata, prezzo_netto_iva, prezzo_netto_marketplace, fees_shopify, fees_marketplace, costo_merce, spedizione, costi_totali, margine_netto, margine_percentuale: parseFloat(margine_percentuale.toFixed(2)) };
}

// ============ FUSO ORARIO EUROPA/ROMA REALE ============
// Ottiene la data di oggi in formato AAAA-MM-GG secondo il fuso di Roma
funzione getRomeDateString(date = new Date()) {
  // Usa Intl per ottenere dati reali a Roma (gestisce automaticamente DST)
  const formatter = new Intl.DateTimeFormat('en-CA', {
    Fuso orario: 'Europa/Roma',
    anno: 'numerico', mese: 'a 2 cifre', giorno: 'a 2 cifre'
  });
  return formatter.format(date); // es. "2026-04-20"
}

// Ottiene offset in minuti di Roma per una data specifica (gestisce DST)
funzione getRomeOffset(data) {
  const romeStr = date.toLocaleString('en-US', { timeZone: 'Europe/Rome' });
  const utcStr = date.toLocaleString('en-US', { timeZone: 'UTC' });
  const rome = new Date(romeStr);
  const utc = new Date(utcStr);
  andata e ritorno (roma - utc)/60000; // minuti
}

// Converte una data Rome (YYYY-MM-DD HH:mm:ss) in Date UTC
funzione romeDateTimeToUTC(dateStr, timeStr = '00:00:00') {
  // Creiamo una data ipotetica locale e calcoliamo l'offset Roma per quel momento
  const testDate = new Date(dateStr + 'T' + timeStr + 'Z');
  const offsetMin = getRomeOffset(testDate);
  // Invertiamo: se Roma è UTC+2, dobbiamo sottrarre 2 ore per ottenere l'UTC
  restituisci nuovo Date(testDate.getTime() - offsetMin * 60000);
}

funzione getDateRange(periodo, dateFromCustom, dateToCustom) {
  siano dateDa, dateA;
  se (dateFromCustom && dateToCustom) {
    dateFrom = romeDateTimeToUTC(dateFromCustom, '00:00:00');
    dateTo = romeDateTimeToUTC(dateToCustom, '23:59:59');
    restituisci { dataDa, dataA };
  }
  
  const romeToday = getRomeDateString(); // es. "2026-04-20"
  const now = new Date();
  
  interruttore(periodo) {
    caso 'oggi':
      dateFrom = romeDateTimeToUTC(romeToday, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      rottura;
    caso 'ieri': {
      // Calcola i dati di ieri a Roma
      const yesterdayRome = new Date(now.getTime() - 24*60*60*1000);
      const yesterdayStr = getRomeDateString(yesterdayRome);
      dateFrom = romeDateTimeToUTC(yesterdayStr, '00:00:00');
      dateTo = romeDateTimeToUTC(yesterdayStr, '23:59:59');
      rottura;
    }
    caso 'settimana': {
      const weekAgo = new Date(now.getTime() - 7*24*60*60*1000);
      const weekAgoStr = getRomeDateString(weekAgo);
      dateFrom = romeDateTimeToUTC(weekAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      rottura;
    }
    caso 'mese': {
      const monthAgo = new Date(now.getTime() - 30*24*60*60*1000);
      const monthAgoStr = getRomeDateString(monthAgo);
      dateFrom = romeDateTimeToUTC(meseAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      rottura;
    }
    caso 'trimestre': {
      const qAgo = new Date(now.getTime() - 90*24*60*60*1000);
      const qAgoStr = getRomeDateString(qAgo);
      dateFrom = romeDateTimeToUTC(qAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      rottura;
    }
    caso 'anno': {
      const yAgo = new Date(now.getTime() - 365*24*60*60*1000);
      const yAgoStr = getRomeDateString(yAgo);
      dateFrom = romeDateTimeToUTC(yAgoStr, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
      rottura;
    }
    predefinito:
      dateFrom = romeDateTimeToUTC(romeToday, '00:00:00');
      dateTo = romeDateTimeToUTC(romeToday, '23:59:59');
  }
  restituisci { dataDa, dataA };
}

funzione asincrona getShopifyOrders(periodo = 'oggi', dateFromCustom = null, dateToCustom = null) {
  const token = await getShopifyAccessToken();
  const { dateFrom, dateTo } = getDateRange(periodo, dateFromCustom, dateToCustom);
  lascia tutti gli ordini = [];
  let url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&created_at_min=${dateFrom.toISOString()}&created_at_max=${dateTo.toISOString()}&limit=250`;
  lascia pageCount = 0;
  const maxPages = 20;
  mentre (url && pageCount < maxPages) {
    const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
    se (!response.ok) genera un nuovo Errore(`HTTP ${response.status}`);
    const data = await response.json();
    allOrders = allOrders.concat(data.orders || []);
    const linkHeader = response.headers.get('link') || response.headers.get('Link');
    url = null;
    if (linkHeader) { const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/); if (nextMatch) url = nextMatch[1]; }
    pageCount++;
  }
  restituisci tutti gli ordini;
}

funzionecalBestSellers(ordini, top = 20, variantCosts = {}) {
  const prodotti = {};
  ordini.forEach(ordine => {
    const paese = ordine.indirizzo_spedizione?.codice_paese || ordine.indirizzo_fatturazione?.codice_paese;
    const ivaPerc = getIvaPerPaese(country);
    const ordCurrency = ordine.currency || SHOP_CURRENCY;
    (ordine_line_items || []).forEach(item => {
      const productId = item.product_id || item.variant_id || item.title;
      // PREZZO IN EUR (da price_set.shop_money quando disponibile)
      const prezzo_unit_lordo = toEurAmount(item.price_set, item.price, ordCurrency);
      const quantity = parseInt(item.quantity) || 0;
      const prezzo_unit_netto = prezzo_unit_lordo/(1+ivaPerc/100);
      const costo_unit_reale = item.variant_id && variantCosts[item.variant_id] != null ? variantCosts[item.variant_id] : 0;
      const fatturato_lordo = prezzo_unit_lordo * quantità;
      const fatturato_netto = prezzo_unit_netto * quantità;
      const costo_tot = costo_unit_reale * quantità;
      const ricavo_stimato = fatturato_netto - costo_tot;
      se (!prodotti[productId]) {
        prodotti[productId] = { product_id: articolo.product_id, variante_id: articolo.variant_id, titolo: articolo.title, variante: articolo.variant_title || '', sku: articolo.sku || '', venditore: item.vendor || '', prezzo_unit_lordo, prezzo_unit_netto, costo_unit: costo_unit_reale, quantita_venduta: 0, fatturato_lordo: 0, fatturato_netto: 0, ricavo_stimato: 0, immagine: null };
      }
      prodotti[productId].quantita_venduta += quantità;
      prodotti[productId].fatturato_lordo += fatturato_lordo;
      prodotti[productId].fatturato_netto += fatturato_netto;
      prodotti[productId].ricavo_stimato +=ricavo_stimato;
    });
  });
  return Object.values(prodotti).sort((a, b) => b.fatturato_lordo - a.fatturato_lordo).slice(0, top);
}

funzione asincrona arricchisciConImmagini(prodotti) {
  if (prodotti.length === 0) return prodotti;
  Tentativo {
    const token = await getShopifyAccessToken();
    const productIds = prodotti.map(p => p.product_id).filter(Boolean).join(',');
    if (!productIds) restituisce prodotti;
    const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?ids=${productIds}&fields=id,image,images`, { headers: { 'X-Shopify-Access-Token': token } });
    if (!response.ok) restituisce prodotti;
    const data = await response.json();
    const imageMap = {};
    (data.products || []).forEach(p => { imageMap[p.id] = p.image?.src || (p.images?.[0]?.src) || ​​null; });
    restituisci prodotti.map(p => ({ ...p, immagine: imageMap[p.product_id] || null }));
  } catch (e) { return prodotti; }
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<testa>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>T. Luxy ERP — Marginalità del pannello di controllo</title>
<style>
  :radice {
    --green-primary: #008060; --green-dark: #004C3F; --green-light: #E8F4F0;
    --oro: #C9A961; --oro chiaro: #F4ECD8;
    --beige: #F4F1EB; --crema: #FAFAF7;
    --nero: #1A1A1A; --grigio-900: #2D2D2D; --grigio-700: #5C5C5C; --grigio-500: #8E8E8E;
    --gray-300: #D4D4D4; --gray-200: #E8E8E8; --gray-100: #F2F2F0;
    --bianco: #FFFFFF; --rosso: #BF4747; --luce rossa: #FCEEEE;
    --shadow-sm: 0 1px 2px rgba(26,26,26,0.04);
    --shadow-md: 0 4px 12px rgba(26,26,26,0.06);
    --shadow-lg: 0 12px 32px rgba(26,26,26,0.08);
    --radius-sm: 8px; --radius-md: 12px; --radius-lg: 20px;
    --font-main: 'Century Gothic', 'CenturyGothic', 'AppleGothic', Futura, 'Trebuchet MS', sans-serif;
  }
  * { margine: 0; spaziatura interna: 0; ridimensionamento box: bordo; }
  body { font-family: var(--font-main); background: var(--beige); min-height: 100vh; color: var(--black); -webkit-font-smoothing: antialiased; line-height: 1.5; letter-spacing: 0.01em; }
  .container { max-width: 1440px; margin: 0 auto; padding: 24px; }
  .header { background: var(--white); border-radius: var(--radius-lg); padding: 32px 40px; margin-bottom: 24px; box-shadow: var(--shadow-md); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 20px; border: 1px solid var(--gray-100); }
  .header-left { display: flex; align-items: center; gap: 28px; }
  .logo { font-family: var(--font-main); font-weight: 700; font-size: 2.6rem; color: var(--black); letter-spacing: 0.02em; line-height: 1; text-transform: uppercase; }
  .logo .dot { color: var(--gold); }
  .header-divider { larghezza: 1px; altezza: 52px; sfondo: var(--gray-200); }
  .header-info h1 { font-size: 1.05rem; font-weight: 700; color: var(--gray-900); margin-bottom: 3px; text-transform: uppercase; letter-spacing: 0.05em; }
  .header-info p { font-size: 0.8rem; color: var(--gray-500); letter-spacing: 0.03em; }
  .header-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .status-pill { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; background: var(--green-light); color: var(--green-dark); border-radius: 50px; font-size: 0.75rem; font-weight: 700; border: 1px solid rgba(0,128,96,0.15); letter-spacing: 0.05em; text-transform: uppercase; }
  .status-dot { larghezza: 7px; altezza: 7px; sfondo: var(--green-primary); raggio del bordo: 50%; animazione: impulso 2s infinito; }
  @keyframes pulse { 0%,100% { opacità: 1; } 50% { opacità: 0.4; } }
  .tabs-wrap { background: var(--white); border-radius: var(--radius-lg); padding: 8px; margin-bottom: 24px; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-100); }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tab { flex: 1; min-width: 130px; padding: 14px 20px; border: none; background: transparent; border-radius: var(--radius-md); cursor: pointer; font-family: var(--font-main); font-weight: 700; font-size: 0.82rem; color: var(--gray-700); transition: all 0.25s ease; letter-spacing: 0.06em; text-transform: uppercase; }
  .tab:hover { background: var(--gray-100); color: var(--black); }
  .tab.active { background: var(--black); color: var(--white); }
  .tab-content { display: none; animation: fade 0.4s ease; }
  .tab-content.active { display: block; }
  @keyframes fade { da { opacità: 0; trasformazione: translateY(8px); } a { opacità: 1; trasformazione: translateY(0); } }
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
  .breakdown-table { larghezza: 100%; bordo-collasso: collasso; sfondo: var(--white); }
  .breakdown-table head { background: var(--black); color: var(--white); }
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
  .duo-input-row { display: flex; align-it ems: center; gap: 10px; margin-bottom: 8px; }
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
<corpo>
<div class="container">
  <div class="header">
    <div class="header-left">
      <div class="logo">T<span class="dot">.</span> LUXY</div>
      <div class="header-divider"></div>
      <div class="header-info">
        <h1>Marginalità ERP</h1>
        <p>Dashboard di Business Intelligence · v5.12.1</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill"><div class="status-dot"></div>Sistema Live</div>
      <button id="logoutBtn" style="background:transparent; border:1px solid rgba(0,0,0,0.15); padding:8px 14px; border-radius:50px; cursor:pointer; font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; color:var(--gray-700); margin-left:12px; font-family:var(--font-main); transition:all 0.2s;" onmouseover="this.style.background='var(--gray-100)'" onmouseout="this.style.background='transparent'">🚪 Esci</button>
    </div>
  </div>
  <div class="tabs-wrap">
    <div class="tabs">
      <button class="tab active" data-tab="analytics">Analisi</button>
      <button class="tab" data-tab="bestsellers">Più venduti</button>
      <button class="tab" data-tab="compare">Confronto MP</button>
      <button class="tab" data-tab="calcolatore">Calcolatore</button>
      <button class="tab" data-tab="marketplaces">Marketplace</button>
      <button class="tab" data-tab="duo">Simulatore DUO</button>
      <button class="tab" data-tab="forecast">💰 Previsioni Incassi</button>
      <button class="tab" data-tab="inventory">📦 Inventario</button>
      <button class="tab" data-tab="chat">💬 Assistente AI</button>
    </div>
  </div>
  <div id="analytics-tab" class="tab-content active">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Performance</div><div class="section-subtitle">Analisi vendite e marginalità in tempo reale</div></div></div>
      <div class="info-box">Fuso orario Europa/Roma reale. Costo merce letto da Shopify. Ordini senza "Costo per articolo" segnalati sotto.</div>
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
        <div class="kpi primary"><div class="kpi-label">Lordo IVA incluso</div><div class="kpi-value" id="lordo">—</div><div class="kpi-sub" id="ordini-count">— ordini</div></div>
        <div class="kpi"><div class="kpi-label">IVA Scorporata</div><div class="kpi-value" id="iva">—</div><div class="kpi-sub">Da versare</div></div>
        <div class="kpi"><div class="kpi-label">Costi Totali</div><div class="kpi-value" id="costi">—</div><div class="kpi-split" id="costi-split" style="margin-top:8px; padding-top:8px; border-top:1px solid rgba(0,0,0,0.08); font-size:0.78rem; line-height:1.5;"><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Merce</span><span id="costi-merce" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div><div style="display:flex; justify-content:space-between;"><span style="color:var(--gray-700);">Costi + velocità.</span><span id="costi-fees" style="font-weight:600; font-variant-numeric:tabular-nums;">—</span></div></div></div>
        <div class="kpi green"><div class="kpi-label">Margine Netto</div><div class="kpi-value" id="netto">—</div><div class="kpi-sub">Profitto reale</div></div>
        <div class="kpi gold"><div class="kpi-label">Margine %</div><div class="kpi-value" id="margine">—</div><div class="kpi-sub">Su lordo</div></div>
      </div>
      <div id="refunds-panel"></div>
      <div id="foreign-currency-panel"></div>
      <div id="errors-panel"></div>
      <div class="breakdown-section">
        <div class="breakdown-title">Ripartizione per Marketplace</div>
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
      <div class="section-header"><div><div class="section-title">I più venduti</div><div class="section-subtitle">I 20 prodotti più venduti per fatturato</div></div></div>
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
          <div class="form-group"><label>Prezzo IVA incluso (€)</label><input type="number" id="c-prezzo" value="100" step="0.01"></div>
          <div class="form-group"><label>Paese / IVA</label><select id="c-iva">
            <option value="22">🇮🇹 Italia (22%)</option><option value="20">🇫🇷 Francia (20%)</option><option value="19">🇩🇪 Germania (19%)</option><option value="21">🇪🇸 Spagna (21%)</option><option value="21">🇳🇱 Olanda (21%)</option><option value="21">🇧🇪 Belgio (21%)</option><option value="20">🇦🇹 Austria (20%)</option><option value="23">🇮🇪 Irlanda (23%)</option><option value="23">🇵🇱 Polonia (23%)</option><option value="25">🇸🇪 Svezia (25%)</option><option value="25">🇩🇰 Danimarca (25%)</option><option value="20">🇬🇧 Regno Unito (20%)</option><option value="0">🇺🇸 USA / Extra-UE (0%)</option>
          </select></div>
          <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="c-costo" value="45" step="0.01"></div>
          <div class="form-group"><label>Spedizione (€)</label><input type="number" id="c-spedizione" value="5" step="0.01"></div>
        </div>
      </div>
      <div class="table-wrap"><table class="compare-table" id="compare-table"><thead><tr><th>Marketplace</th><th>Sconto</th><th>Prezzo Netto</th><th>Commissioni Shopify</th><th>Commissioni MP</th><th>Margine €</th><th>Margine %</th><th>Esito</th></tr></thead><tbody id="compare-body"></tbody></table></div>
      <div class="compare-summary" id="compare-summary"></div>
    </div>
  </div>
  <div id="calculator-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Calcolatore</div><div class="section-subtitle">Simulator marginalità singolo marketplace</div></div></div>
      <div class="info-box">Inserisci il <strong>Retail</strong> ei due sconti (vendita + costo fornitore) — Prezzo IVA e Costo Merce si calcolano automaticamente. Oppure compila direttamente Prezzo e Costo.</div>
      
      <!-- Box Retail + 2 sconti (scorciatoia) -->
      <div style="background:var(--cream); border:1.5px solid var(--gray-200); border-radius:var(--radius-md); padding:18px 20px; margin-bottom:20px;">
        <div style="font-size:0.7rem; color:var(--gray-700); text-transform:uppercase; letter-spacing:0.08em; font-weight:700; margin-bottom:12px;">🧮 Scorciatoia Retail → auto-calcolo</div>
        <div class="form-grid" style="margin-bottom:0;">
          <div class="form-group"><label>Prezzo al dettaglio consigliato (€)</label><input type="number" id="calc-retail" placeholder="es. 500" step="0.01"></div>
          <div class="form-group"><label>Sconto vendita % (dal retail)</label><input type="number" id="calc-sconto-vendita" placeholder="es. 10" step="0.1" min="0" max="100"></div>
          <div class="form-group"><label>Sconto costo % (fornitore)</label><input type="number" id="calc-sconto-costo" placeholder="es. 50" step="0.1" min="0" max="100"></div>
        </div>
        <div id="calc-retail-summary" style="margin-top:12px; padding:10px 14px; background:var(--green-light); border-left:3px solid var(--green-primary); border-radius:8px; font-size:0.85rem; color:var(--green-dark); display:none;"></div>
      </div>
      
      <div class="form-grid">
        <div class="form-group"><label>Prezzo IVA incluso (€)</label><input type="number" id="prezzo" placeholder="es. 100" step="0.01"></div>
        <div class="form-group"><label>Paese / IVA</label><select id="iva-select">
          <option value="22">🇮🇹 Italia (22%)</option><option value="20">🇫🇷 Francia (20%)</option><option value="19">🇩🇪 Germania (19%)</option><option value="21">🇪🇸 Spagna (21%)</option><option value="21">🇳🇱 Olanda (21%)</option><option value="21">🇧🇪 Belgio (21%)</option><option value="20">🇦🇹 Austria (20%)</option><option value="23">🇮🇪 Irlanda (23%)</option><option value="23">🇵🇱 Polonia (23%)</option><option value="25">🇸🇪 Svezia (25%)</option><option value="25">🇩🇰 Danimarca (25%)</option><option value="20">🇬🇧 Regno Unito (20%)</option><option value="0">🇺🇸 USA / Extra-UE (0%)</option>
        </select></div>
        <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="costo" placeholder="es. 45" step="0.01"></div>
        <div class="form-group"><label>Spedizione (€)</label><input type="number" id="spedizione" value="5" step="0.01"></div>
        <div class="form-group"><label>Marketplace</label><select id="mp-select"></select></div>
      </div>
      <button class="btn-primary" id="calcola-btn">Calcola Marginalità</button>
      <div class="risultati" id="risultati" style="display:none;">
        <div class="result-card"><div class="result-label">Lordo IVA incl.</div><div class="result-value" id="r-lordo">-</div></div>
        <div class="result-card"><div class="result-label">IVA Società</div><div class="result-value" id="r-iva">-</div></div>
        <div class="result-card"><div class="result-label">Netto IVA</div><div class="result-value" id="r-netto-iva">-</div></div>
        <div class="result-card"><div class="result-label">Netto Marketplace</div><div class="result-value" id="r-netto">-</div></div>
        <div class="result-card"><div class="result-label">Commissioni Shopify</div><div class="result-value" id="r-shopify">-</div></div>
        <div class="result-card"><div class="result-label">Mercato delle tariffe</div><div class="result-value" id="r-mp">-</div></div>
        <div class="result-card" id="r-margine-card"><div class="result-label">Margine Netto</div><div class="result-value" id="r-margine">-</div></div>
        <div class="result-card"><div class="result-label">Margine %</div><div class="result-value" id="r-perc">-</div></div>
        <div class="result-card" id="r-redd-card"><div class="result-label">Esito</div><div class="result-value" id="r-redd">-</div></div>
      </div>
    </div>
    
    <!-- ============ CALCOLATORE LOTTO EXCEL (v5.10) ============ -->
    <div class="section" style="margin-top:24px;">
      <div class="section-header">
        <div>
          <div class="section-title">📊 Calcolo batch da Excel</div>
          <div class="section-subtitle">Carica un file Excel/CSV con prodotti · calcolo del margine su tutti i 16 marketplace · supporta il fornitore di sconto%</div>
        </div>
      </div>
      <div class="info-box">
        <strong>Obbligatori</strong>: <code>SKU</code>, <code>Retail</code> (o Listino), e <code>Costo</code> O <code>Sconto%</code>. <strong>Opzionali</strong>: <code>Titolo</code>, <code>Stock</code>, <code>Listino</code> (di vendita), <code>IVA</code>.<br>
        <strong>Esempio</strong>: Retail €500 con Sconto% 50 → Costo €250 calcolato automaticamente. Puoi anche caricare direttamente Retail + Costo.
      </div>
      <div class="filter-bar" style="gap:12px;">
        <label class="apply-btn" style="background:var(--green-primary); cursor:pointer; padding:10px 18px;">
          <i style="display:inline-block; transform:scale(1.2); margin-right:4px;">📤</i> Carica Excel/CSV
          <input type="file" id="batch-file" accept=".xlsx,.xls,.csv" style="display:none;">
        </label>
        <button id="batch-template-btn" class="apply-btn" style="background:var(--gray-700); padding:10px 18px;">
          <i style="display:inline-block; transform:scale(1.2); margin-right:4px;">📥</i> Scarica il template
        </button>
        <div style="margin-left:auto; display:flex; gap:10px; align-items:center;">
          <label style="font-size:0.72rem; color:var(--gray-700); font-weight:700; text-transform:uppercase; letter-spacing:0.06em;">IVA predefinita</label>
          <select id="batch-iva-default" style="padding:8px 12px; border:1.5px solid var(--gray-200); border-radius:8px; font-size:0.85rem; font-family:inherit;">
            <option value="22" selected>🇮🇹 Italia 22%</option>
            <option value="20">🇫🇷🇬🇧🇦🇹 20%</option>
            <option value="19">🇩🇪 Germania 19%</option>
            <option value="21">🇪🇸🇳🇱🇧🇪 21%</option>
            <option value="23">🇵🇱🇮🇪🇵🇹 23%</option>
            <option value="25">🇸🇪🇩🇰 25%</option>
            <option value="0">🌍 Extra-UE 0%</option>
          </seleziona>
        </div>
      </div>
      <div id="batch-status" style="font-size:0.85rem; color:var(--gray-700); margin:10px 0;"></div>
      <div id="batch-content"></div>
    </div>
  </div>
  <div id="marketplaces-tab" class="tab-content">
    <div class="section">
      <div class="section-header"><div><div class="section-title">Marketplace del portfolio</div><div class="section-subtitle">Configurazioni canali</div></div></div>
      <div class="warn-box">Riconoscimento tramite <code>source_name</code>. Verifica con <code>/api/debug-orders</code>.</div>
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
        <label class="apply-btn" style="background:var(--green-primary); cursor:pointer;">📤 Importa costi CSV
          <input type="file" id="duo-csv-file" accept=".csv" style="display:none;">
        </label>
        <span id="duo-import-status" style="font-size:0.85rem; color:var(--gray-700);"></span>
        <div style="margin-left:auto; display:flex; gap:8px; align-items:center;">
          <label style="font-size:0.78rem; color:var(--gray-700); font-weight:700; text-transform:uppercase;">Cerca</label>
          <input type="text" id="duo-search" placeholder="Titolo / SKU..." style="padding:8px 14px; border:1.5px solid var(--gray-200); border-radius:50px; font-size:0.85rem; min-width:220px;">
        </div>
      </div>
      <div class="info-box" style="margin-top:12px;">
        <strong>Come funziona</strong>: clicca "Ricarica prodotti" per vedere tutti i DUO attivi. Inserisci il costo fornitore e il prezzo di vendita, scegli il marketplace → ti mostro il margine reale. Puoi anche importare tutti i costi in blocco da un file CSV con colonne <code>variant_id,cost</code> (o <code>sku,cost</code>).
      </div>
      <div id="duo-content">
        <div class="bs-empty">Fai clic su "Ricarica prodotti" per caricare il DUO da Shopify.</div>
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
          <button class="apply-btn" id="forecast-reload" style=" background:var(--gray-700);" title="Ricarica dalla cache (veloce)">Mostra</button>
          <button class="apply-btn" id="forecast-refresh" style=" background:var(--black);" title="Rifà tutti i calcoli (lento)">🔄 Aggiorna ora</button>
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
          <div class="section-subtitle">Pezzi attivi con stock > 0 · categoria × genere · cache 24h</div>
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
        <div class="bs-empty">Fai clic su "Mostra" o "Aggiorna ora" per caricare lo snapshot.</div>
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
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">📊 Quanto ho guadagnato questo mese?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">🏆 Qual è il MP più redditizio?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">⚠️ Quanti ordini hanno costi mancanti?</button>
            <button class="chat-suggest" style="padding:10px 14px; background:var(--white); border:1px solid var(--gray-200); border-radius:8px; font-size:0.82rem; cursor:pointer; text-align:left; font-family:inherit;">↩️ Mostrami i risultati recenti</button>
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
const MERCATI = ${JSON.stringify(CONFIGURAZIONI_MERCATI)};
const MP_COLORS = { TLUXY_SITE:'#1A1A1A', THE_BRADERY:'#C9A961', MIINTO:'#008060', BALARDI:'#BF4747', ITALIST:'#2D2D2D', JAMMY_DUDE:'#8E4FBF', SECRET_SALES:'#6B5320', FASHION_TAMERS:'#5C5C5C', INTRA_MIRROR:'#B89550', ARCHIVIST:'#004C3F', BOUTIQUE_MALL:'#E8573A', WINKELSTRAAT:'#479CCF', POIZON:'#D4397A', BRANDSGATEWAY:'#4A7FBC', MARK_FOYS:'#2E5F8F', GIGLIO:'#7B4F8A' };

function setActiveButton(selector, btn) { document.querySelectorAll(selector).forEach(b => b.classList.remove('active')); if (btn) btn.classList.add('active'); }
async function fetchNoCache(url) { const sep = url.includes('?') ? '&' : '?'; const res = await fetch(url + sep + '_=' + Date.now(), { cache: 'no-store', headers: { 'Cache-Control': 'no-cache' } }); return res.json(); }

funzione mostraTab(nome) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  const tabBtn = document.querySelector('.tab[data-tab="' + name + '"]'); if (tabBtn) tabBtn.classList.add('active');
  se (nome === 'compare' && !document.getElementById('compare-body').children.length) confronta();
  if (name === 'bestsellers') { const bsContent = document.getElementById('bs-content'); if (bsContent.querySelector('.bs-empty')) { const activeBtn = document.querySelector('[data-bs-periods] .period-btn.active') || document.querySelector('[data-bs-periods] .period-btn[data-period="month"]'); loadBestSellers(activeBtn ? activeBtn.dataset.period : 'month', activeBtn); } }
}

funzione renderErrors(ordiniConErrori) {
  const panel = document.getElementById('errors-panel');
  if (!ordiniConErrori || ordiniConErrori.length === 0) { panel.innerHTML = ''; return; }
  const rows = ordiniConErrori.slice(0, 50).map(o => {
    const prods = o.prodotti_senza_costo.map(p => '   • ' + (p.title || 'Senza titolo') + (p.sku ? ' [SKU: ' + p.sku + ']' : '')).join('<br>');
    const origPrice = o.currency && o.currency !== 'EUR' ? o.currency + ' ' + o.total_price + ' → €' + (o.total_price_eur || 0).toFixed(2) : '€' + o.total_price;
    restituisci '<div><strong>Ordine n.' + (o.order_number || o.name || o.id) + '</strong> (' + o.marketplace + ', ' + origPrice + ')<br>' + prods + '</div>';
  }).giuntura('');
  const moreMsg = ordiniConErrori.length > 50 ? '<div style="margin-top:8px; font-style:italic;">... e altri ' + (ordiniConErrori.length - 50) + ' ordini</div>' : '';
  panel.innerHTML = '<div class="error-box"><strong>⚠ ' + ordiniConErrori.length + ' ordini esclusi: prodotti senza "Cost per item" su Shopify</strong>Aggiungi il costo su Shopify → Prodotti → Inventario.<div class="error-list">' + rows + moreMsg + '</div></div>';
}

funzione renderForeignCurrency(ordiniEstero) {
  const panel = document.getElementById('foreign-currency-panel');
  se (!pannello) restituisci;
  if (!ordiniEstero || ordiniEstero.length === 0) { panel.innerHTML = ''; return; }
  // Raggruppa per valuta
  const byCurrency = {};
  ordiniEstero.forEach(o => {
    se (!byCurrency[o.currency]) byCurrency[o.currency] = { count: 0, total_orig: 0, total_eur: 0, rates: [] };
    byCurrency[o.currency].count++;
    byCurrency[o.currency].total_orig += o.total_original;
    byCurrency[o.currency].total_eur += o.total_eur;
    byCurrency[o.currency].rates.push(o.exchange_rate);
  });
  const summary = Object.entries(byCurrency).map(([cur, info]) => {
    const avgRate = info.rates.reduce((a, b) => a + b, 0) / info.rates.length;
    return '<div style="padding:6px 0; border-bottom:1px dotted #E8C77A;"><strong>' + cur + '</strong>: ' + info.count + ' ordini · ' + cur + ' ' + info.total_orig.toFixed(2) + ' → <strong>€' + info.total_eur.toFixed(2) + '</strong> (cambio medio ~' + avgRate.toFixed(4) + ')</div>';
  }).giuntura('');
  panel.innerHTML = '<div style="background:#FFF4D6; border-left:4px solid #E8C77A; border-radius:8px; padding:14px 18px; margin-bottom:16px;"><div style="font-weight:700; color:#8B6914; margin-bottom:8px;">💱 ' + ordiniEstero.length + ' ordine' + (ordiniEstero.length > 1 ? ' in' : '') + ' valuta estera (convertit' + (ordiniEstero.length > 1 ? 'i' : 'o') + ' in EUR al cambio storico Shopify)</div><div style="font-size:0.82rem; color:#6B4E0E;">' + summary + '</div></div>';
}

funzione renderRefunds(resi) {
  const panel = document.getElementById('refunds-panel');
  se (!pannello) restituisci;
  if (!resi || resi.totale_count === 0) { panel.innerHTML = ''; ritorno; }
  // Riepilogo
  const dettagliRecenti = (resi.dettaglio || []).slice(0, 8).map(r => {
    const dataFmt = r.created_at ? new Date(r.created_at).toLocaleDateString('it-IT', {day:'2-digit', month:'2-digit'}) : '—';
    const tipoBadge = r.tipo === 'totale' ? '<span style="background:#FCEEEE; color:#BF4747; padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">TOTALE</span>' : '<span style="background:#FFE4D6; color:#8B4F14; padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">PARZIALE</span>';
    return '<div style="padding:4px 0; border-bottom:1px dotted #E89A5A;"><strong>' + (r.name || '#' + r.order_number) + '</strong>' + tipoBadge + ' · ' + dataFmt + ' · ' + r.marketplace + ' · <strong>€' + r.importo_rimborsato_eur.toFixed(2) + '</strong> rimborsati' + (r.tipo === 'parziale' ? ' (' + r.quantita_rimborsata + '/' + r.quantita_totale + ' articoli)' : '') + '</div>';
  }).giuntura('');
  const moreMsg = (resi.dettaglio || []).lunghezza > 8 ? '<div style="margin-top:6px; font-style:italic; font-size:0.78rem; color:#8B4F14;">... e altri ' + ((resi.dettaglio || []).length - 8) + ' resi</div>' : '';
  panel.innerHTML = '<div style="background:#FFE4D6; border-left:4px solid #E89A5A; border-radius:8px; padding:14px 18px; margin-bottom:16px;">' +
    '<div style="font-weight:700; color:#8B4F14; margin-bottom:10px; font-size:0.95rem;">↩️ ' + resi.totale_count + ' resi nel periodo · €' + resi.importo_totale_eur.toFixed(2) + ' rimborsati (' + resi.percentuale_su_lordo.toFixed(1) + '% del fatturato lordo)</div>' +
    '<div style="font-size:0.78rem; color:#6B3D14; margin-bottom:8px;">📊 ' + resi.totali_count + ' totali · ' + resi.parziali_count + ' parziali · ' + resi.articoli_resi_qty + ' articoli rimborsati</div>' +
    '<div style="font-size:0.82rem; color:#6B3D14; line-height:1.6; margin-top:10px;"><strong style="font-size:0.72rem; text-transform:uppercase; letter-spacing:0.05em;">Resi recenti:</strong><br>' + dettagliRecenti + moreMsg + '</div>' +
  '</div>';
}

funzione renderBreakdown(breakdown) {
  const body = document.getElementById('breakdown-body'); const foot = document.getElementById('breakdown-foot');
  if (!breakdown || Object.keys(breakdown).length === 0) { body.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;"> Nessun ordine.</td></tr>'; foot.innerHTML = ''; return; }
  const arr = Object.entries(breakdown).map(([key, v]) => ({ key, ...v })); arr.sort((a, b) => b.fatturato - a.fatturato);
  poniamo totOrdini = 0, totFatt = 0, totIva = 0, totCosti = 0, totMargine = 0;
  body.innerHTML = arr.map(r => {
    totOrdini += r.ordini; totFatt += r.fatturato; totIva += (r.iva || 0); totCosti += (r.costo_merce || 0); totMargine += r.margine;
    const marginePerc = r.fatturato > 0 ? (r.margine / r.fatturato*100) : 0;
    const marginCls = r.margine >= 0 ? 'margin-pos' : 'margin-neg';
    const color = MP_COLORS[r.key] || '#8E8E8E';
    // Riga principale cliccabile + riga dettagli nascosta
    const mainRow = '<tr class="mp-row" data-mp-key="' + r.key + '" style="cursor:pointer"><td><span class="toggle-arrow" id="arrow-' + r.key + '">▶</span> <span class="mp-badge" style="background:' + color + '">' + r.nome + '</span></td><td class="num">' + r.ordini + '</td><td class="num">€' + Math.round(r.fatturato).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.iva || 0).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(r.costo_merce || 0).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">€' + Math.round(r.margine).toLocaleString('it-IT') + '</td><td class="num ' + marginCls + '">' + marginePerc.toFixed(1) + '%</td></tr>';
    // Dettaglio ordini (nascosto default)
    const detailRow = '<tr class="mp-detail" id="detail-' + r.key + '" style="display:none;"><td colspan="7" style="padding:0; background:var(--cream);"><div style="padding:16px;"><table class="detail-table"><thead><tr><th>Ordine</th><th>Data</th><th>Paese</th><th>Articoli</th><th class="num">Fatturato</th><th class="num">IVA</th><th class="num">Costo</th><th class="num">Fees MP</th><th class="num">Margine €</th><th class="num">%</th></tr></thead><tbody>' +
      (r.dettaglio_ordini || []).map(o => {
        const dataFmt = o.created_at ? new Date(o.created_at).toLocaleDateString('it-IT', {day:'2-digit', month:'2-digit', year:'2-digit'}) : '—';
        const orderNumFmt = o.nome || ('#' + o.numero_ordine);
        const articoli = (o.articoli || []).map(a => {
          // Margine netto unitario = allocato proporzionalmente sul fatturato del singolo articolo
          const totFatturatoOrdine = (o.articoli || []).reduce((s, x) => s + (x.prezzo_unit * x.quantità), 0);
          const fattArticolo = a.prezzo_unità * a.quantità;
          const quotaFatt = totFatturatoOrdine > 0 ? fattArticolo / totFatturatoOrdine: 0;
          const margineNettoArticolo = o.margine_netto *quotaFatt;
          const margineNettoUnit = a.quantity > 0 ? margineNettoArticolo / a.quantity : 0;
          const badgeStyle = margineNettoUnit >= 0
            ? 'display:inline-block; background:var(--green-light); color:var(--green-dark); border:1px solid rgba(0,128,96,0.3); padding:2px 9px; border-radius:6px; font-weight:700; font-size:0.78rem;'
            : 'display:inline-block; background:var(--red-light); color:var(--red); border:1px solid rgba(191,71,71,0.3); padding:2px 9px; border-radius:6px; font-weight:700; font-size:0.78rem;';
          const segno = margineNettoUnità >= 0 ? '+':'';
          return '<div style="padding:4px 0; border-bottom:1px dotted var(--gray-200);"><strong style="font-size:0.82rem;">' + a.title + '</strong><br><span style="font-size:0.72rem; color:var(--gray-500);">SKU: ' + a.sku + ' · qty ' + a.quantity + '</span><br><span style="font-size:0.75rem;">Prezzo: <strong>€' + a.prezzo_unit.toFixed(2) + '</strong> · Costo: <strong>€' + a.cost_unit.toFixed(2) + '</strong> · <span style="' + badgeStyle + '" title="Margine netto per unità (dopo IVA, commissioni, spedizione)">Netto ' + segno + '€' + margineNettoUnit.toFixed(2) + '</span></span></div>';
        }).giuntura('');
        const marginCls2 = o.margine_netto >= 0 ? 'margine-pos': 'margine-neg';
        const currencyBadge = o.is_foreign_currency ? '<span style="display:inline-block; background:#FFF4D6; color:#8B6914; padding:2px 7px; border-radius:10px; font-size:0.68rem; font-weight:700; margin-left:6px; border:1px solid #E8C77A;" title="Ordine in ' + o.currency + ' convert in EUR al cambio del giorno (' + o.exchange_rate.toFixed(4) + ')">💱 ' + o.currency + ' ' + (o.total_original || 0).toFixed(0) + '</span>' : '';
        const refundBadge = o.refund_status === 'partial' ? '<span style="display:inline-block; background:#FFE4D6; color:#8B4F14; padding:2px 7px; border-radius:10px; font-size:0.68rem; font-weight:700; margin-left:6px; border:1px solid #E89A5A;" title="Rimborso parziale: ' + (o.refund_quantity || 0) + '/' + (o.refund_total_quantity || 0) + ' articoli, €' + (o.refund_amount_eur || 0).toFixed(2) + ' rimborsati">↩️ RISPARMIO PARZIALE €' + (o.refund_amount_eur || 0).toFixed(0) + '</span>' : '';
        restituisci '<tr><td><strong>' + orderNumFmt + '</strong>' + currencyBadge + refundBadge + '</td><td>' + dataFmt + '</td><td>' + (o.country || '—') + '</td><td style="max-width:340px;">' + articoli + '</td><td class="num">€' + o.fatturato.toFixed(2) + '</td><td class="num">€' + o.iva.toFixed(2) + '</td><td class="num">€' + o.costo_merce.toFixed(2) + '</td><td class="num">€' + o.fees_marketplace.toFixed(2) + '</td><td class="num ' + marginCls2 + '">€' + o.margine_netto.toFixed(2) + '</td><td class="num ' + marginCls2 + '">' + o.margine_percentuale.toFixed(1) + '%</td></tr>';
      }).join('') +
      '</tbody></table></div></td></tr>';
    restituisci rigaprincipale + rigadettaglio;
  }).giuntura('');
  // Gestore di attivazione/disattivazione tramite delega di eventi
  document.querySelectorAll('.mp-row').forEach(row => {
    riga.aggiungiListenerEvent('click', () => {
      const key = row.dataset.mpKey;
      const detail = document.getElementById('detail-' + key);
      const arrow = document.getElementById('arrow-' + key);
      se (dettaglio e freccia) {
        const isOpen = detail.style.display !== 'none';
        detail.style.display = isOpen ? 'none' : 'table-row';
        arrow.textContent = isOpen ? '▶' : '▼';
      }
    });
  });
  const totMargPerc = totFatt > 0 ? (totMargine / totFatt * 100) : 0;
  foot.innerHTML = '<tr><td>TOTALE</td><td class="num">' + totOrdini + '</td><td class="num">€' + Math.round(totFatt).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totIva).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totCosti).toLocaleString('it-IT') + '</td><td class="num">€' + Math.round(totMargine).toLocaleString('it-IT') + '</td><td class="num">' + totMargPerc.toFixed(1) + '%</td></tr>';
}

funzione asincrona fetchAnalytics(url) {
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '...'; });
  document.getElementById('ordini-count').textContent = 'Caricamento (leggo costi reali)...';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--gray-500); font-style:italic;">Caricamento...</td></tr>';
  document.getElementById('breakdown-foot').innerHTML = ''; document.getElementById('errors-panel').innerHTML = '';
  Tentativo {
    const data = await fetchNoCache(url);
    se (dati di successo) {
      document.getElementById('lordo').textContent = '€' + Math.round(data.lordo_iva_inclusa).toLocaleString('it-IT');
      document.getElementById('iva').textContent = '€' + Math.round(data.iva_totale).toLocaleString('it-IT');
      document.getElementById('costi').textContent = '€' + Math.round(data.costi_totali).toLocaleString('it-IT');
      // Dividi Merce / Commissioni + spedizione.
      const merce = data.costi_merce_totali || 0;
      const fees = data.costi_fees_totali || 0;
      document.getElementById('costi-merce').textContent = '€' + Math.round(merce).toLocaleString('it-IT');
      document.getElementById('costi-fees').textContent = '€' + Math.round(fees).toLocaleString('it-IT');
      document.getElementById('netto').textContent = '€' + Math.round(data.margine_netto).toLocaleString('it-IT');
      document.getElementById('margine').textContent = data.margine_percentuale.toFixed(1) + '%';
      const countLabel = data.ordini_con_errori_count > 0 ? data.ordini_totali + ' validi (' + data.ordini_con_errori_count + ' esclusioni)' : data.ordini_totali + ' ordini';
      document.getElementById('ordini-count').textContent = countLabel;
      renderBreakdown(data.breakdown_marketplace);
      renderErrors(data.ordini_con_errori || []);
      renderForeignCurrency(data.ordini_valuta_estera || []);
      renderRefunds(data.resi || null);
      restituisci vero;
    }
  } catch(e) { console.error(e); }
  ['lordo','iva','costi','netto','margine'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '—'; });
  document.getElementById('ordini-count').textContent = 'Errore caricamento';
  document.getElementById('breakdown-body').innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--red);">Errore.</td></tr>';
  restituire falso;
}

async function setPeriod(p, btn) { setActiveButton('[data-analytics-periods] .period-btn', btn); await fetchAnalytics('/api/analytics?periodo=' + p); }
funzione asincrona applyCustomRange() {
  const from = document.getElementById('date-from').value; const to = document.getElementById('date-to').value;
  if (!from || !to) { alert('Seleziona data'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-analytics-periods] .period-btn', null); await fetchAnalytics('/api/analytics?from=' + from + '&to=' + to);
}
funzione asincrona loadBestSellers(p, btn) {
  setActiveButton('[data-bs-periods] .period-btn', btn);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty">Caricamento prodotti...</div>';
  try { const data = await fetchNoCache('/api/bestsellers?periodo=' + p); if (data.success && data.prodotti && data.prodotti.length > 0) { renderBestSellers(data.prodotti); return; } cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
funzione asincrona applyBsCustomRange() {
  const from = document.getElementById('bs-date-from').value; const to = document.getElementById('bs-date-to').value;
  if (!from || !to) { alert('Seleziona data'); return; } if (from > to) { alert('Da deve precedere A'); return; }
  setActiveButton('[data-bs-periods] .period-btn', null);
  const cont = document.getElementById('bs-content'); cont.innerHTML = '<div class="bs-empty">Caricamento...</div>';
  try { const data = await fetchNoCache('/api/bestsellers?from=' + from + '&to=' + to); if (data.success && data.prodotti && data.prodotti.length > 0) { renderBestSellers(data.prodotti); return; } cont.innerHTML = '<div class="bs-empty"> Nessun prodotto.</div>'; } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}
funzione renderBestSellers(prodotti) {
  const cont = document.getElementById('bs-content');
  if (!prodotti || prodotti.length === 0) { cont.innerHTML = '<div class="bs-empty">Nessun prodotto.</div>'; ritorno; }
  cont.innerHTML = prodotti.map((p, i) => {
    const rank = p.rank || (i + 1); const rankClass = rank <= 3 ? 'top3' : '';
    const img = p.immagine ? '<img src="' + p.immagine + '" alt="' + p.titolo + '" loading="lazy">' : '<div class="bs-image-placeholder">◇</div>';
    return '<div class="bs-card"><div class="bs-rank ' + rankClass + '">' + rank + '</div><div class="bs-image">' + img + '</div><div class="bs-body"><div class="bs-title">' + p.titolo + '</div><div class="bs-variant">' + (p.variante || '') + (p.sku ? ' · ' + p.sku : '') + '</div><div class="bs-stats"><div class="bs-stat"><div class="bs-stat-label">Prezzo</div><div class="bs-stat-value">€' + p.prezzo_unit_lordo.toFixed(2) + '</div></div><div class="bs-stat"><div class="bs-stat-label">Pezzi</div><div class="bs-stat-value">' + p.quantita_venduta + '</div></div><div class="bs-stat rotazione"><div class="bs-stat-label">Fatturato</div><div class="bs-stat-value">€' + Math.round(p.fatturato_lordo).toLocaleString('it-IT') + '</div></div><div class="bs-stat ricavo"><div class="bs-stat-label">Ricavo</div><div class="bs-stat-value">€' + Math.round(p.ricavo_stimato).toLocaleString('it-IT') + '</div></div></div></div></div>';
  }).giuntura('');
}
funzione di confronto() {
  const prezzoLordo = parseFloat(document.getElementById('c-prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('c-iva').value) || 0;
  const costo = parseFloat(document.getElementById('c-costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('c-spedizione').value) || 0;
  const prezzoNettoIva = prezzoLordo/(1+ivaPerc/100);
  const risultati = Object.entries(MARKETPLACES).map(([key, mp]) => {
    const prezzoNetto = prezzoNettoIva* (1 - mp.sconto_percentuale/100);
    const feesShop = key === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
    tariffa constP = prezzoNetto * (mp.fee_principale/100); tariffa const = prezzoNetto * ((mp.fee_secondaria || 0) / 100); tariffa constA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
    const tariffeMp = tariffaP + tariffaS + tariffaA + (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
    const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
    const margineP = prezzoLordo > 0 ? (margine/prezzoLordo*100) : 0;
    return { key, nome: mp.nome, sconto: mp.sconto_percentuale, prezzoNetto, feesShop, feesMp, margine, margineP };
  });
  risultati.sort((a, b) => b.margine - a.margine);
  const migliore = risultati[0]; const peggiori = risultati[risultati.length - 1];
  document.getElementById('compare-body').innerHTML = risultati.map((r, i) => {
    lascia cls = '', pill = '';
    if (i === 0) { cls = 'migliore'; pill = '<span class="mp-pill win">Migliore</span>'; }
    if (i === risultati.length - 1) { cls = 'peggiore'; pill = '<span class="mp-pill lose">Ultima</span>'; }
    const numCls = r.margine >= 0 ? 'num-pos': 'num-neg';
    const esito = r.margine >= 0 ? ' ✓' : '✕';
    return '<tr class="' + cls + '"><td><strong>' + r.nome + '</strong>' + pill + '</td><td>' + r.sconto + '%</td><td>€' + r.prezzoNetto.toFixed(2) + '</td><td>€' + r.feesShop.toFixed(2) + '</td><td>€' + r.feesMp.toFixed(2) + '</td><td class="' + numCls + '">€' + r.margine.toFixed(2) + '</td><td class="' + numCls + '">' + r.margineP.toFixed(1) + '%</td><td style="font-size:1.1rem; font-weight:700; color:' + (r.margine >= 0 ? 'var(--green-primary)' : 'var(--red)') + '">' + esito + '</td></tr>';
  }).giuntura('');
  const redditizi = risultati.filter(r => r.margine > 0).length; const inPerdita = risultati.filter(r => r.margine <= 0).length;
  document.getElementById('compare-summary').innerHTML = '<div class="summary-card best-mp"><div class="summary-label">Migliore</div><div class="summary-value">' + best.nome + '</div><div class="summary-detail">€' + best.margine.toFixed(2) + ' (' + best.margineP.toFixed(1) + '%)</div></div><div class="summary-card worst-mp"><div class="summary-label">Peggiore</div><div class="summary-value">' + worst.nome + '</div><div class="summary-detail">€' + worst.margine.toFixed(2) + ' (' + worst.margineP.toFixed(1) + '%)</div></div><div class="summary-card info"><div class="summary-label">Redditizi</div><div class="summary-value">' + redditizi + ' su ' + risultati.length + '</div><div class="summary-detail">' + inPerdita + ' in perdita</div></div>';
}
// ============ CALCOLATORE: RETAIL + SCONTI (v5.12 step1 - logica minima) ============
funzione calcUpdateFromRetail() {
  Tentativo {
    const retailEl = document.getElementById('calc-retail');
    const scontoVEl = document.getElementById('calc-sconto-vendita');
    const scontoCEl = document.getElementById('calc-sconto-costo');
    const prezzoEl = document.getElementById('prezzo');
    const costoEl = document.getElementById('costo');
    const summary = document.getElementById('calc-retail-summary');
    se (!retailEl || !valoreEl || !costoEl) restituisci;
    const retail = parseFloat(retailEl.value);
    const scontoV = parseFloat(scontoVEl.value);
    const scontoC = parseFloat(scontoCEl.value);
    if (!isNaN(vendita al dettaglio) && vendita al dettaglio > 0) {
      // Prezzo da vendita al dettaglio + sconto vendita
      if (!isNaN(scontoV) && scontoV >= 0 && scontoV <= 100) {
        prezzoEl.value = (prezzoal dettaglio * (1 - scontoV / 100)).toFixed(2);
      } altrimenti se (isNaN(scontoV)) {
        prezzoEl.value = retail.toFixed(2);
      }
      // Costo da vendita al dettaglio + sconto costo
      if (!isNaN(scontoC) && scontoC >= 0 && scontoC <= 100) {
        costoEl.value = (prezzo al dettaglio * (1 - scontoC / 100)).toFixed(2);
      }
      // Riepilogo
      const pV = parseFloat(prezzoEl.value);
      const cV = parseFloat(costoEl.value);
      let html = '<strong>Riepilogo</strong> · Prezzo consigliato al pubblico <strong>€' + retail.toFixed(2) + '</strong>';
      se (!isNaN(pV) && pV > 0) {
        const sV = ((prezzo al dettaglio - pV) / prezzo al dettaglio * 100);
        html += ' · vendo a <strong>€' + pV.toFixed(2) + '</strong> (' + (sV >= 0 ? '-' : '+') + Math.abs(sV).toFixed(1) + '%)';
      }
      se (!isNaN(cV) && cV >= 0) {
        const sC = ((prezzo al dettaglio - cV) / prezzo al dettaglio * 100);
        html += ' · compro a <strong>€' + cV.toFixed(2) + '</strong> (' + (sC >= 0 ? '-' : '+') + Math.abs(sC).toFixed(1) + '%)';
      }
      summary.innerHTML = html;
      summary.style.display = 'block';
    } altro {
      summary.style.display = 'none';
    }
  } catch(e) { console.error('Errore in calcUpdateFromRetail:', e); }
}

funzione c_c() {
  const prezzoLordo = parseFloat(document.getElementById('prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('iva-select').value) || 0;
  const costo = parseFloat(document.getElementById('costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('spedizione').value) || 0;
  const mpKey = document.getElementById('mp-select').value;
  const mp = MERCATI[mpKey];
  // Protezione: se prezzo a 0 o MP non valido, non calcolare
  if (prezzoLordo <= 0 || !mp) {
    document.getElementById('results').style.display = 'none';
    ritorno;
  }
  const prezzoNettoIva = prezzoLordo/(1+ivaPerc/100); const ivaScorporata = prezzoLordo - prezzoNettoIva;
  const prezzoNetto = prezzoNettoIva* (1 - mp.sconto_percentuale/100);
  const feesShop = mpKey === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
  tariffa constP = prezzoNetto * (mp.fee_principale/100); tariffa const = prezzoNetto * ((mp.fee_secondaria || 0) / 100); tariffa constA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
  const tariffeMp = tariffaP + tariffaS + tariffaA + (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
  const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
  const margineP = prezzoLordo > 0 ? (margine/prezzoLordo*100) : 0;
  document.getElementById('results').style.display = 'grid';
  document.getElementById('r-lordo').textContent = '€' + prezzoLordo.toFixed(2);
  document.getElementById('r-iva').textContent = '€' + ivaScorporata.toFixed(2);
  document.getElementById('r-netto-iva').textContent = '€' + prezzoNettoIva.toFixed(2);
  document.getElementById('r-netto').textContent = '€' + prezzoNetto.toFixed(2);
  document.getElementById('r-shopify').textContent = '€' + feesShop.toFixed(2);
  document.getElementById('r-mp').textContent = '€' + feeMp.toFixed(2);
  document.getElementById('r-margine').textContent = '€' + margine.toFixed(2);
  document.getElementById('r-perc').textContent = margineP.toFixed(1) + '%';
  const mc = document.getElementById('r-margine-card'); const rc = document.getElementById('r-redd-card'); const re = document.getElementById('r-redd');
  if (margine > 0) { mc.className = 'result-card positive'; rc.className = 'result-card positive'; re.textContent = '✓ Redditizio'; }
  altrimenti { mc.className = 'result-card negative'; rc.className = 'result-card negative'; re.textContent = '✕ In Perdita'; }
}
funzione loadMarketplaces() {
  const select = document.getElementById('mp-select'); const grid = document.getElementById('mp-grid');
  Object.entries(MARKETPLACES).forEach(([key, mp]) => {
    const opt ​​= document.createElement('option'); opt.value = key; opt.textContent = mp.nome; select.appendChild(opt);
    const card = document.createElement('div'); card.className = 'mp-card';
    card.addEventListener('click', () => { select.value = key; showTab('calcolatrice'); calcola(); });
    card.innerHTML = '<div class="mp-name">' + mp.nome + '</div><div class="mp-pay">Pagamento: ' + (mp.pagamento || 'N/D') + '</div><div class="mp-fees"><div><strong>Sconto</strong>' + mp.sconto_percentuale + '%</div><div><strong>Commissione principale.</strong>' + mp.fee_principale + '%</div><div><strong>Commissione secondaria.</strong>' + (mp.fee_secondaria || 0) + '%</div><div><strong>Trasporto</strong>€' + (mp.fee_fissa_trasporto || 0) + '</div><div><strong>Imballaggio</strong>€' + (mp.fee_fissa_packaging || 0) + '</div>' + (mp.fee_accessoria ? '<div><strong>Commissione Acc.</strong>' + mp.fee_accessoria + '%</div>' : '') + '</div>';
    grid.appendChild(card);
  });
}

// ============ SIMULATORE DUO ============
lascia duoProducts = [];
funzione calcolaMargineDUO(prezzoLordo, costo, mpKey, ivaPerc) {
  se (!valoreLordo || !mpKey) restituisci null;
  const mp = MERCATI[mpKey]; se (!mp) restituisci null;
  const prezzoNettoIva = prezzoLordo/(1+ivaPerc/100);
  const ivaScorp = prezzoLordo - prezzoNettoIva;
  const prezzoNetto = prezzoNettoIva* (1 - mp.sconto_percentuale/100);
  const feesShop = mpKey === 'TLUXY_SITE' ? prezzoNetto * 0.0015 : 0;
  tariffa constP = prezzoNetto * (mp.fee_principale/100);
  tariffa const = prezzoNetto * ((mp.fee_secondaria || 0) / 100);
  tariffa constA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
  const tariffeMp = tariffaP + tariffaS + tariffaA + (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
  const margine = prezzoNetto - feesShop - feesMp - costo;
  const marginePerc = prezzoLordo > 0 ? (margine/prezzoLordo*100) : 0;
  return { margine, marginePerc, prezzoNetto, ivaScorp, feesShop, feesMp };
}

// Calcola il prezzo minimo (IVA inclusa) per raggiungere un margine target
function prezzoMinimoPerMargine(costo, mpKey, ivaPerc, margineTargetPerc) {
  const mp = MERCATI[mpKey]; se (!mp) restituisci null;
  const totalPercFee = (mp.fee_principale + (mp.fee_secondaria || 0) + (mp.fee_accessoria || 0) + (mpKey === 'TLUXY_SITE' ? 0.15 : 0)) / 100;
  const scontoPerc = mp.sconto_percentuale/100;
  tariffa fissaFissa = (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
  // Formula: prezzoNetto(1-totalPercFee) - costo - feeFissa = margineTarget
  // prezzoNetto = prezzoLordo/(1+iva) * (1-scontoPerc)
  // prezzoLordo = X. Risolvo per X.
  // margine = X/(1+iva)*(1-sconto)*(1-totalFee) - costo - feeFissa
  // margineTarget = margineTargetPerc/100 * X
  // X/(1+iva)*(1-sconto)*(1-totalFee) - costo - feeFissa = margineTargetPerc/100 * X
  // X * [(1-sconto)*(1-totalFee)/(1+iva) - margineTargetPerc/100] = costo + feeFissa
  const coef = (1 - scontoPerc) * (1 - totalPercFee) / (1 + ivaPerc / 100) - margineTargetPerc / 100;
  se (coef <= 0) restituisce Infinito; // impossibile raggiungere quel margine
  reso (costo+commissioneFissa)/coef;
}

funzione asincrona loadDuoProducts() {
  const cont = document.getElementById('duo-content');
  cont.innerHTML = '<div class="bs-empty">Caricamento prodotti DUO da Shopify...</div>';
  Tentativo {
    const data = await fetchNoCache('/api/duo-products');
    if (!data.success) { cont.innerHTML = '<div class="bs-empty">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    duoProdotti = dati.prodotti || [];
    renderDuoProducts(duoProducts);
  } catch(e) { cont.innerHTML = '<div class="bs-empty">Errore: ' + e.message + '</div>'; }
}

funzione renderDuoProducts(prodotti) {
  const cont = document.getElementById('duo-content');
  if (!products ||products.length === 0) { cont.innerHTML = '<div class="bs-empty">Nessun prodotto DUO trovato (SKU che inizia con "DUO-").</div>'; ritorno; }
  const mpOptions = Object.entries(MARKETPLACES).map(([k, v]) => '<option value="' + k + '">' + v.nome + '</option>').join('');
  cont.innerHTML = '<div class="duo-grid">' + products.map(p => {
    // Segnaposto compatto con iniziale + sfondo colorato (no immagini)
    const initial = (p.title || 'D').charAt(0).toUpperCase();
    const hue = ((p.variant_id || 0) % 360);
    const costoSaved = p.costo_fornitore !== null && p.costo_fornitore !== unfine ? p.costo_fornitore:'';
    const costBadge = p.costo_fornitore !== null
      ? '<span style="display:inline-block; background:#E6F4EE; color:var(--green-dark); padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">Costo Shopify</span>'
      : '<span style="display:inline-block; background:#FCEEEE; color:var(--red); padding:1px 6px; border-radius:8px; font-size:0.65rem; font-weight:700; margin-left:4px;">Costo mancante</span>';
    restituisci '<div class="duo-card" data-vid="' + p.variant_id + '">' +
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
        '<div class="duo-input-row"><label>Test Prezzo €</label><input type="number" class="duo-prezzo-test" value="' + p.prezzo_listino.toFixed(2) + '" step="0.01" data-vid="' + p.variant_id + '"></div>' +
        '<div class="duo-result" id="duo-res-' + p.variant_id + '">—</div>' +
      '</div>' +
    '</div>';
  }).join('') + '</div>';
  
  // Ascoltatori: solo calcolo locale, NO salvataggio KV (semplice)
  cont.querySelectorAll('.duo-cost, .duo-mp, .duo-iva, .duo-prezzo-test').forEach(el => {
    el.addEventListener('input', e => updateDuoCard(e.target.dataset.vid));
    el.addEventListener('change', e => updateDuoCard(e.target.dataset.vid));
  });
  
  // Aggiornamento automatico di tutti i prodotti con costo noto (attiva calcolo margine immediato)
  setTimeout(() => {
    cont.querySelectorAll('.duo-card').forEach(card => {
      const vid = card.dataset.vid;
      se (vid) aggiornaDuoCard(vid);
    });
  }, 50);
}

funzione updateDuoCard(vid) {
  const card = document.querySelector('.duo-card[data-vid="' + vid + '"]'); if (!card) return;
  const costo = parseFloat(card.querySelector('.duo-cost').value) || 0;
  const mpKey = card.querySelector('.duo-mp').value;
  const iva = parseFloat(card.querySelector('.duo-iva').value);
  const prezzo = parseFloat(card.querySelector('.duo-prezzo-test').value) || 0;
  const resDiv = card.querySelector('.duo-result');
  if (!costo || !mpKey || !prezzo) { resDiv.innerHTML = '<span style="color:var(--gray-500); font-style:italic;">Compila costo, marketplace e prezzo per vedere il margine</span>'; resDiv.className = 'duo-risultato'; ritorno; }
  const r = calcolaMargineDUO(prezzo, costo, mpKey, iva);
  if (!r) { resDiv.innerHTML = 'Errore calcolo'; ritorno; }
  const prezzoBE = prezzoMinimoPerMargine(costo, mpKey, iva, 0);
  const prezzo20 = prezzoMinimoPerMargine(costo, mpKey, iva, 20);
  const prezzo30 = prezzoMinimoPerMargine(costo, mpKey, iva, 30);
  const marginCls = r.margine >= 0 ? 'margin-pos' : 'margin-neg';
  resDiv.className = 'duo-result ' + (r.margine >= 0 ? 'duo-pos' : 'duo-neg');
  resDiv.innerHTML = '<div class="duo-main-result"><span class="duo-result-label">MARGINE</span><span class="' + marginCls + '" style="font-size:1.3rem; font-weight:700;">€' + r.margine.toFixed(2) + '</span><span class="' + marginCls + '">' + r.marginePerc.toFixed(1) + '%</span></div>' +
    '<div class="duo-breakeven"><strong>Pareggio</strong>: €' + (isFinite(prezzoBE) ? prezzoBE.toFixed(2) : '—') + '<br><strong>Margine del 20%</strong>: €' + (isFinite(prezzo20) ? prezzo20.toFixed(2) : '—') + '<br><strong>Per Margine 30%</strong>: €' + (isFinite(prezzo30) ? prezzo30.toFixed(2) : '—') + '</div>';
}

funzione filterDuoProducts() {
  const q = (document.getElementById('duo-search').value || '').toLowerCase().trim();
  if (!q) { renderDuoProducts(duoProducts); return; }
  const filtered = duoProducts.filter(p => p.title.toLowerCase().includes(q) || p.sku.toLowerCase().includes(q));
  renderDuoProducts(filtrato);
}

funzione asincrona checkKvStatus() {
  const el = document.getElementById('duo-kv-status');
  Tentativo {
    const data = await fetchNoCache('/api/kv-status');
    se (data.kv_enabled) {
      el.className = 'info-box';
      el.style.cssText = 'background:var(--green-light); border-left-color:var(--green-primary); color:var(--green-dark);';
      el.innerHTML = '✅ <strong>DB persistente attivo</strong>: i costi vengono salvati permanentemente (non si perdono se i prodotti archiviati).';
    } altro {
      el.className = 'warn-box';
      el.innerHTML = '⚠️ <strong>DB persistente NON configurato</strong>. Vai su Vercel → Archiviazione → Crea database KV. Senza KV il simulatore non può salvare i costi.';
    }
  } catch(e) { el.innerHTML = '❌ Errore verifica KV: ' + e.message; }
}

funzione parseCSV(testo) {
  const lines = text.split(/\\r?\\n/).filter(l => l.trim());
  se (lines.length === 0) restituisci { costi: {}, err: 'File vuoto' };
  const header = lines[0].split(/[,;]/).map(h => h.trim().toLowerCase().replace(/^"|"$/g, ''));
  const vidIdx = header.findIndex(h => h === 'variant_id' || h === 'variantid');
  const skuIdx = header.findIndex(h => h === 'sku');
  const costIdx = header.findIndex(h => h === 'costo' || h === 'costo' || h === 'costo_fornitore');
  if (costIdx < 0) return {costs: {}, err: 'Colonna "cost" non trovata nel CSV' };
  if (vidIdx < 0 && skuIdx < 0) return { costs: {}, err: 'Devi avere colonna "variant_id" o "sku"' };
  const costi = {}; const skippedSkus = [];
  per (sia i = 1; i < lines.length; i++) {
    const parts = lines[i].split(/[,;]/).map(p => p.trim().replace(/^"|"$/g, ''));
    const cost = parseFloat(parts[costIdx]);
    se (costo è NaN) continua;
    lascia vid = null;
    se (vidIdx >= 0 e parti[vidIdx]) vid = parti[vidIdx];
    altrimenti se (skuIdx >= 0 e parti[skuIdx]) {
      const sku = parts[skuIdx];
      const match = duoProducts.find(p => p.sku === sku);
      if (match) vid = String(match.variant_id); else { skippedSkus.push(sku); continue; }
    }
    se (vid) costi[vid] = costo;
  }
  restituisci { costi, skippedSkus };
}

funzione asincrona handleCsvImport(file) {
  const status = document.getElementById('duo-import-status');
  status.textContent = '📄 Lettura CSV...';
  Tentativo {
    const testo = await file.text();
    const { costi, err, skippedSkus } = parseCSV(testo);
    if (err) { status.textContent = '❌ ' + err; status.style.color = 'var(--red)'; return; }
    const n = Object.keys(costs).length;
    if (n === 0) { status.textContent = '❌ Nessun costo valido nel CSV'; status.style.color = 'var(--red)'; ritorno; }
    status.textContent = '💾 Salvataggio ' + n + 'costi...';
    const res = await fetch('/api/duo-costs-import', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({costs}) });
    const data = await res.json();
    se (dati di successo) {
      let msg = '✅ Salvati ' + data.salvati + 'costi';
      if (skippedSkus && skippedSkus.length) msg ​​+= ' (' + skippedSkus.length + ' SKU sconosciuti skippati)';
      status.textContent = msg; status.style.color = 'var(--green-dark)';
      setTimeout(loadDuoProducts, 500);
    } else { status.textContent = '❌ ' + data.error; status.style.color = 'var(--red)'; }
  } catch(e) { status.textContent = '❌ ' + e.message; status.style.color = 'var(--red)'; }
}

// ============ PREVISIONI INCASSI ============
lascia forecastData = null;

funzione fmtEur(n) { restituisce '€' + Math.round(n).toLocaleString('it-IT'); }
funzione fmtEur2(n) { restituisce '€' + (n || 0).toFixed(2); }
funzione fmtDateIT(dateStr) {
  se (!dateStr) restituisci '—';
  const d = new Date(dateStr + 'T00:00:00');
  restituisci d.toLocaleDateString('it-IT', { day: '2 cifre', month: 'breve', year: 'numerico' });
}
funzione fmtMonthIT(monthKey) {
  se (!monthKey) restituisci '—';
  const [y, m] = monthKey.split('-');
  const d = new Date(parseInt(y), parseInt(m) - 1, 1);
  restituisci d.toLocaleDateString('it-IT', { month: 'long', year: 'numeric' });
}

funzione asincrona loadForecast(forceRefresh) {
  const cont = document.getElementById('forecast-content');
  cont.innerHTML = '<div class="bs-empty">' + (forceRefresh ? '🔄 Ricalcolo in corso (legge 120gg ordini da Shopify, ~10-30 sec)...' : 'Caricamento previsioni...') + '</div>';
  Tentativo {
    const url = forceRefresh ? '/api/forecast?refresh=1' : '/api/forecast';
    const data = await fetchNoCache(url);
    if (!data.success) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    forecastData = dati;
    renderForecast(dati);
  } catch(e) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + e.message + '</div>'; }
}

funzione renderForecast(dati) {
  const cont = document.getElementById('forecast-content');
  const kpi = data.kpi;
  const bg = data.balardi_wallet;
  const todayStr = new Date().toISOString().split('T')[0];
  
  // Stato della cache del banner
  lascia cacheInfoHtml = '';
  se (dati dalla cache) {
    const età = data.cache_età_ore || 0;
    const ageLabel = age < 1 ? Math.round(age * 60) + ' min fa' : age.toFixed(1) + ' ore fa';
    cacheInfoHtml = '<div style="background:#E8F0F5; border-left:3px solid #4A7FBC; border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:#1A4A78; display:flex; justify-content:space-between; align-items:center;">' +
      '<span>⚡ Dati dalla cache · ultimo aggiornamento ' + ageLabel + ' · scade tra ' + (data.cache_expires_in_hours || 0).toFixed(1) + ' ore</span>' +
    '</div>';
  } altrimenti se (data.cached_to_kv) {
    cacheInfoHtml = '<div style="background:#E6F4EE; border-left:3px solid var(--green-primary); border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:var(--green-dark);">' +
      '✅ Dati appena calcolati e salvati in cache (valida 24h)' +
    '</div>';
  }
  
  // Schede KPI: solo mese corrente, mese prossimo, totale 2 mesi
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
      '<div style="font-size:0.75rem; color:var(--gray-700); margin-top:2px;">' + count2mesi + ' transazioni</div>' +
    '</div>' +
  '</div>';
  
  // Carta per marketplace con scadenziari aggregati
  // Raggruppo i pagamenti per MP al mese
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
      se (!perMese[monthKey]) perMese[monthKey] = { importo: 0, conteggio: 0, nota: nuovo Set() };
      perMese[monthKey].importo += p.importo_eur;
      perMese[monthKey].count++;
      se (p.nota) perMese[monthKey].note.add(p.nota);
    });
    mpAggregato[mp.nome] = {
      ...mp,
      decanze: Object.entries(perMese).map(([mese, info]) => ({
        mese, importo: info.importo, count: info.count, note: [...info.note].join(' · ')
      })).sort((a, b) => a.mese.localeCompare(b.mese))
    };
  });
  
  // Filtra cadenze: solo mese corrente in avanti
  const mpVisibili = Object.values(mpAggregato).filter(mp => {
    const future = mp.scadenze.filter(s => s.mese >= meseCorrente);
    mp.scadenzeFuture = futuro;
    restituisci future.length > 0;
  });
  
  // Ordina per: prima MP con pagamenti nel mese corrente, poi per totale futuro
  mpVisibili.sort((a, b) => {
    const aNow = a.scadenzeFuture.some(s => s.mese === meseCorrente) ? 1:0;
    const bNow = b.scadenzeFuture.some(s => s.mese === meseCorrente) ? 1 : 0;
    se (aNow !== bNow) restituisci bNow - aNow;
    const aTot = a.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
    const bTot = b.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
    restituisci bTot - aTot;
  });
  
  const MP_BADGE_COLORS = { Miinto:'#008060', 'The Bradery':'#C9A961', Brandsgateway:'#4A7FBC', Winkelstraat:'#479CCF', 'Secret Sales':'#6B5320', Italist:'#2D2D2D', Archivist:'#004C3F', 'Intra Mirror':'#B89550', 'Fashion Tamers':'#5C5C5C', 'Boutique Mall':'#E8573A', 'Jammy Dude':'#8E4FBF', 'T. Luxy (proprio)':'#1A1A1A', Poizon:'#D4397A' };
  
  const cardsHtml = '<div style="margin-bottom:12px; font-size:1rem; font-weight:700; color:var(--black);">Scadenziario per marketplace</div>' +
    '<div style="display:flex; flex-direction:column; gap:10px; margin-bottom:24px;">' +
    (mpVisibili.length > 0 ? mpVisibili.map(mp => {
      const color = MP_BADGE_COLORS[mp.nome] || '#8E8E8E';
      const totaleFuturo = mp.scadenzeFuture.reduce((s, x) => s + x.importo, 0);
      const decadenzeHtml = mp.scadenzeFuture.map(sc => {
        const isCorrente = sc.mese === meseCorrente;
        const isProssimo = sc.mese === meseProssimo;
        const mensileLabel = isCorrente ? ' (corrente)' : (isProssimo ? ' (prossimo)' : '');
        const color2 = isCorrente ? 'var(--green-dark)' : (isProssimo ? '#8B6914' : 'var(--gray-700)');
        restituisci '<div style="display:flex; justify-content:space-between; align-items:baseline; padding:5px 0; font-size:0.88rem;">' +
          '<span style="color:' + color2 + ';"><strong style="text-transform:capitalize;">' + fmtMonthIT(sc.mese) + '</strong>' + mensileLabel + ' · ' + sc.count + ' ord.' + (sc.note ? ' <span style="color:var(--gray-500); font-size:0.78rem;">(' + sc.note + ')</span>' : '') + '</span>' +
          '<span style="font-weight:700; font-variant-numeric:tabular-nums;">' + fmtEur(sc. importanza) + '</span>' +
        '</div>';
      }).giuntura('');
      restituisci '<div style="background:var(--white); border:1px solid var(--gray-200); border-radius:12px; padding:14px 18px;">' +
        '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; padding-bottom:10px; border-bottom:1px solid var(--gray-100);">' +
          '<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">' +
            '<span class="mp-badge" style="background:' + color + '; font-size:0.8rem;">' + mp.nome + '</span>' +
            '<span style="font-size:0.78rem; color:var(--gray-700); font-style:italic;">' + (mp.pagamento_desc || '') + '</span>' +
          '</div>' +
          '<div style="font-size:1.05rem; font-weight:800;">Totale <span style="color:var(--black);">' + fmtEur(totaleFuturo) + '</span></div>' +
        '</div>' +
        degradanzeHtml +
      '</div>';
    }).join('') : '<div style="text-align:center; padding:24px; color:var(--gray-500); font-style:italic;">Nessun pagamento previsto nei prossimi 2 mesi.</div>') +
    '</div>';
  
  // Balardi — pannello compatto in basso
  const residuo = bg.credito_residuo;
  const percConsumo = bg.credito_ricaricato > 0 ? (bg.credito_consumato/bg.credito_ricaricato*100): 0;
  const residuoClass = residuo > 300 ? 'var(--green-primary)' : (residuo > 0 ? '#C9A961' : 'var(--red)');
  const residuoLabel = residuo < 300 && residuo >= 0 ? ' ⚠️ Ricarica presto' : (residuo < 0 ? ' 🔴 Credito esaurito' : '');
  const ricaricheHtml = (bg.ricariche || []).slice().reverse().slice(0, 5).map(r =>
    '<div style="padding:5px 0; border-bottom:1px dotted var(--gray-200); font-size:0.8rem; display:flex; justify-content:space-between;">' +
      '<span>' + fmtDateIT(r.data_ricarica) + (r.nota ? ' · <span style="color:var(--gray-500);">' + r.nota + '</span>' : '') + '</span>' +
      '<span><strong>+' + fmtEur2(r. importanza) + '</strong> <button onclick="deleteRicarica(' + r.id + ')" style="background:none; border:none; color:var(--red); cursor:pointer; font-size:0.75rem; margin-left:6px;" title="Elimina">✕</button></span>' +
    '</div>'
  ).giuntura('');
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
  
  cont.innerHTML = cacheInfoHtml + kpiHtml +cardsHtml + balardiHtml;
  
  // Handler ricaricabile Balardi
  const ricBtn = document.getElementById('balardi-ricarica-btn');
  se (ricBtn) {
    ricBtn.addEventListener('click', async () => {
      const importo = parseFloat(document.getElementById('balardi-new-importo').value);
      const nota = document.getElementById('balardi-new-nota').value;
      if (isNaN(importo) || importo <= 0) { alert('Inserisci un importo valido'); ritorno; }
      ricBtn.disabled = true; ricBtn.textContent = '...';
      Tentativo {
        const res = await fetch('/api/balardi-ricarica', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ importo, nota }) });
        const r = await res.json();
        if (r.success) { loadForecast(); } else { alert('Errore: ' + (r.error || 'sconosciuto')); ricBtn.disabled = falso; ricBtn.textContent = '+ Ricarica'; }
      } catch(e) { alert('Errore: ' + e.message); ricBtn.disabled = falso; ricBtn.textContent = '+ Ricarica'; }
    });
  }
}

funzione asincrona deleteRicarica(id) {
  if (!confirm('Eliminare questa ricarica?')) return;
  Tentativo {
    const res = await fetch('/api/balardi-ricarica-delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id }) });
    const r = await res.json();
    se (r.successo) caricaPrevisione();
    else alert('Errore: ' + (r.error || 'sconosciuto'));
  } catch(e) { alert('Errore: ' + e.message); }
}

// ============ RIEPILOGO DELL'INVENTARIO ============
lascia che inventoryData = null;
let inventoryFilter = 'tutto';

funzione asincrona loadInventory(forceRefresh) {
  const cont = document.getElementById('inventory-content');
  cont.innerHTML = '<div class="bs-empty">' + (forceRefresh ? '🔄 Fetch catalogo da Shopify in corso (20-60 secondi)...' : 'Caricamento snapshot...') + '</div>';
  Tentativo {
    const url = forceRefresh ? '/api/inventory?refresh=1' : '/api/inventory';
    const data = await fetchNoCache(url);
    if (!data.success) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + (data.error || 'sconosciuto') + '</div>'; return; }
    dati_inventario = dati;
    renderInventory();
  } catch(e) { cont.innerHTML = '<div class="bs-empty" style="color:var(--red);">Errore: ' + e.message + '</div>'; }
}

funzione renderInventory() {
  se (!dati di inventario) restituisci;
  const d = dati_inventario;
  const cont = document.getElementById('inventory-content');
  const snap = d.snapshot[inventoryFilter];
  
  // Informazioni di intestazione
  lascia sottotitolo = '';
  if (inventoryFilter === 'tutto') subtitle = d.totale_prodotti_attivi_con_stock + ' prodotti · ' + d.totale_pezzi.toLocaleString('it-IT') + ' pezzi (di cui ' + d.duo_prodotti + ' DUO)';
  else if (inventoryFilter === 'own') sottotitolo = d.own_prodotti + ' prodotti · ' + d.own_pezzi.toLocaleString('it-IT') + ' pezzi (esclusi ' + d.duo_prodotti + ' DUO)';
  else sottotitolo = d.duo_prodotti + ' prodotti DUO · ' + d.duo_pezzi.toLocaleString('it-IT') + ' pezzi';
  
  // Cache del banner
  lascia cacheHtml = '';
  se (d.dalla_cache_discovery && d.cached_at) {
    const age = Math.round((Date.now() - new Date(d.cached_at).getTime()) / 3600000 * 10) / 10;
    cacheHtml = '<div style="background:#E8F0F5; border-left:3px solid #4A7FBC; border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:#1A4A78;">⚡ Dati dalla cache · aggiornati ' + age + ' ore fa</div>';
  } altro {
    cacheHtml = '<div style="background:#E6F4EE; border-left:3px solid var(--green-primary); border-radius:6px; padding:8px 14px; margin-bottom:16px; font-size:0.78rem; color:var(--green-dark);">✅ Dati appena scaricati da Shopify e salvati in cache (24h)</div>';
  }
  
  // Tabella categoria × genere
  const CATEGORIA = [
    { chiave: 'borsa', nome: 'Borsa' },
    { chiave: 'scarpe', nome: 'Scarpe' },
    { chiave: 'accessori', nome: 'Accessori' },
    { chiave: 'abbigliamento', nome: 'Abbigliamento' }
  ];
  
  funzione fmtCell(p, pz) {
    return '<td class="num" style="font-variant-numeric:tabular-nums;"><span style="color:var(--gray-500);">' + p.toLocaleString('it-IT') + '</span> · <strong>' + pz.toLocaleString('it-IT') + '</strong></td>';
  }
  
  lascia righe = '';
  poniamo totDonnaP = 0, totDonnaPz = 0, totUomoP = 0, totUomoPz = 0, totUniP = 0, totUniPz = 0;
  CATEGORIE.forEach(cat => {
    const c = snap[cat.key];
    const rigaP = c.donna.prodotti + c.uomo.prodotti + c.unisex.prodotti;
    const rigaPz = c.donna.pezzi + c.uomo.pezzi + c.unisex.pezzi;
    totDonnaP += c.donna.prodotti; totDonnaPz += c.donna.pezzi;
    totUomoP += c.uomo.prodotti; totUomoPz += c.uomo.pezzi;
    totUniP += c.unisex.prodotti; totUniPz += c.unisex.pezzi;
    righe += '<tr>' +
      '<td style="font-weight:600;">' + cat.nome + '</td>' +
      fmtCell(c.donna.prodotti, c.donna.pezzi) +
      fmtCell(c.uomo.prodotti, c.uomo.pezzi) +
      fmtCell(c.unisex.prodotti, c.unisex.pezzi) +
      '<td class="num" style="font-variant-numeric:tabular-nums; background:var(--gray-100);"><span style="color:var(--gray-500);">' + rowP.toLocaleString('it-IT') + '</span> · <strong style="font-size:1.05rem;">' + rowPz.toLocaleString('it-IT') + '</strong></td>' +
    '</tr>';
  });
  const totRowP = totDonnaP + totUomoP + totUniP;
  const totRowPz = totDonnaPz + totUomoPz + totUniPz;
  righe += '<tr style="background:var(--gray-100); font-weight:700;">' +
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
      '<tbody>' + righe + '</tbody>' +
    '</table>' +
  '</div>';
  
  // Non classificati
  let orfaniHtml = '';
  const nc = d.non_classificati;
  se (nc && nc.prodotti > 0) {
    const orfaniTop = (nc.product_types_orfani || []).slice(0, 10).map(o =>
      '<div style="padding:4px 0; font-size:0.82rem;"><strong>' + o.product_type + '</strong> · ' + o.count + ' prodotti</div>'
    ).giuntura('');
    const sampleHtml = (nc.sample_orfani || []).slice(0, 5).map(s =>
      '<div style="padding:4px 0; font-size:0.78rem; color:var(--gray-700); border-bottom:1px dotted var(--gray-200);"><strong>' + s.title + '</strong><br><span style="color:var(--gray-500);">tipo_prodotto: "' + (s.product_type || '(vuoto)') + '" · stock: ' + s.stock + '</span></div>'
    ).giuntura('');
    orfaniHtml = '<div style="background:#FFF4D6; border-left:4px solid #E8C77A; border-radius:8px; padding:14px 18px; margin-bottom:16px;">' +
      '<div style="font-weight:700; color:#8B6914; margin-bottom:8px; font-size:0.92rem;">⚠️ ' + nc.prodotti + ' prodotti non classificati (' + nc.pezzi.toLocaleString('it-IT') + ' pezzi)</div>' +
      '<div style="font-size:0.8rem; color:#6B4E0E; margin-bottom:10px;">Tipi di prodotto orfani più frequenti — dimmeli nella chat per aggiungerli alla classificazione:</div>' +
      '<div style="margin-bottom:10px;">' + orfaniTop + '</div>' +
      '<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:0.78rem; color:#6B4E0E; font-weight:600;">📋 Esempi di prodotti orfani</summary><div style="margin-top:8px;">' + sampleHtml + '</div></details>' +
    '</div>';
  }
  
  cont.innerHTML = cacheHtml + orfaniHtml + tableHtml;
}

// ============ CALCOLATORE LOTTO EXCEL (v5.10) ============
// Caricamento dinamico SheetJS (CDN) per leggere/scrivere XLSX
lascia SHEETJS_LOADED = false;
funzione asincrona loadSheetJS() {
  if (SHEETJS_LOADED || (typeof XLSX !== 'undefined')) { SHEETJS_LOADED = true; return true; }
  restituisci una nuova Promise((risolvi, rifiuta) => {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js';
    script.onload = () => { SHEETJS_LOADED = true; resolve(true); };
    script.onerror = () => reject(new Error('Caricamento SheetJS fallito'));
    document.head.appendChild(script);
  });
}

lascia batchProdotti = []; // {sku, titolo, stock, costo, listino, iva, calcoli: [{mp, margine, ...}]}
lascia che batchExpanded = null; // sku attualmente espanso

funzione batchNormalizeHeader(h) {
  restituisci String(h || '').trim().toLowerCase().replace(/[\s_\-]+/g, '');
}
funzione batchFindCol(intestazioni, candidati) {
  per (costante c di candidati) {
    const idx = headers.findIndex(h => batchNormalizeHeader(h) === batchNormalizeHeader(c));
    se (idx >= 0) restituisci idx;
  }
  restituisci -1;
}

funzione asincrona handleBatchFile(file) {
  const status = document.getElementById('batch-status');
  status.textContent = '⏳ Caricamento libreria Excel...';
  status.style.color = 'var(--gray-700)';
  Tentativo {
    attendi loadSheetJS();
    status.textContent = '📄 File di lettura...';
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(buf, { type: 'array' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    if (!ws) { status.textContent = '❌ Nessun foglio trovato nel file'; status.style.color = 'var(--red)'; ritorno; }
    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
    if (rows.length < 2) { status.textContent = "❌ Il file ha solo l'intestazione, manca dati"; status.style.color = 'var(--red)'; ritorno; }
    
    const headers = rows[0];
    const skuIdx = batchFindCol(headers, ['sku', 'codice', 'codiceprodotto']);
    // RRP al dettaglio = prezzo di vendita pieno (può essere il listino se non c'è sconto vendita)
    const retailIdx = batchFindCol(headers, ['retail', 'rrp', 'retailprice', 'prezzoretail', 'prezzopieno']);
    // Sconto% fornitore (opzionale)
    const scontoIdx = batchFindCol(headers, ['sconto', 'sconto%', 'scontofornitore', 'discountfornitore', 'sconto%', 'scontoacquisto']);
    // Costo (opzionale, calcolato da sconto se manca)
    const costoIdx = batchFindCol(headers, ['costo', 'cost', 'costofornitore', 'costoacquisto', 'costopzunit']);
    // Listino di vendita (opzionale, default = retail)
    const listinoIdx = batchFindCol(headers, ['listino', 'prezzovendita', 'prezzo', 'price', 'prezzolistino', 'sellprice']);
    const titoloIdx = batchFindCol(headers, ['titolo', 'title', 'nome', 'description', 'descrizione', 'product']);
    const stockIdx = batchFindCol(headers, ['stock', 'inventario', 'quantity', 'qty', 'disponibilita', 'pezzi']);
    const ivaIdx = batchFindCol(headers, ['iva', 'vat', 'tax']);
    
    if (skuIdx < 0) { status.textContent = '❌ Colonna SKU non trovata'; status.style.color = 'var(--red)'; ritorno; }
    if (retailIdx < 0 && listinoIdx < 0) { status.textContent = '❌ Manca colonna Retail (o Listino)'; status.style.color = 'var(--red)'; ritorno; }
    if (costoIdx < 0 && scontoIdx < 0) { status.textContent = '❌ Manca colonna Costo (o Sconto% fornitore)'; status.style.color = 'var(--red)'; ritorno; }
    
    const ivaDefault = parseFloat(document.getElementById('batch-iva-default').value) || 22;
    const prodotti = [];
    per (sia i = 1; i < rows.length; i++) {
      const riga = righe[i];
      se (!riga || riga.ogni(c => c === '' || c === null || c === undefined)) continua;
      const sku = String(row[skuIdx] || '').trim();
      se (!sku) continua;
      // Vendita al dettaglio (se manca, usa listino)
      let retail = retailIdx >= 0 ? parseFloat(row[retailIdx]) : NaN;
      let listino = listinoIdx >= 0 ? parseFloat(row[listinoIdx]) : NaN;
      // Fallback: se manca uno, usa l'altro
      if (isNaN(retail) && !isNaN(listino)) retail = listino;
      if (isNaN(listino) && !isNaN(retail)) listino = retail;
      if (isNaN(retail) || retail <= 0) continua;
      //Sconto% e costo
      const scontoForn = scontoIdx >= 0 ? parseFloat(row[scontoIdx]) : NaN;
      let costo = costoIdx >= 0 ? parseFloat(row[costoIdx]) : NaN;
      // Se costo manca ma c'è sconto%, calcola da retail
      if (isNaN(costo) && !isNaN(scontoForn) && scontoForn >= 0 && scontoForn <= 100) {
        costo = vendita al dettaglio * (1 - scontoForn / 100);
      }
      if (isNaN(costo) || costo < 0) continua;
      // Sconto% effettivo (calcolato dal costo)
      const scontoEffettivo = dettaglio > 0 ? ((vendita al dettaglio - costo) / vendita al dettaglio * 100) : 0;
      const titolo = titoloIdx >= 0 ? String(row[titoloIdx] || '').trim() : '';
      const stock = stockIdx >= 0 ? (parseInt(row[stockIdx]) || 0) : null;
      let iva = ivaDefault;
      se (ivaIdx >= 0) {
        const ivaCol = parseFloat(row[ivaIdx]);
        if (!isNaN(ivaCol) && ivaCol >= 0 && ivaCol <= 30) iva = ivaCol;
      }
      prodotti.push({ sku, titolo, stock, retail, scontoForn: scontoEffettivo, costo, listino, iva });
    }
    
    se (products.length === 0) {
      status.textContent = '❌ Nessuna riga valida (controlla SKU + Retail + Costo/Sconto%)';
      status.style.color = 'var(--red)';
      ritorno;
    }
    
    // Calcola i margini per ogni prodotto su tutti i MP
    prodotti.perogni(p => {
      p.calcoli = Object.entries(MARKETPLACES).map(([key, mp]) => {
        const r = batchCalcMargine(p.listino, p.costo, key, p.iva, p.retail);
        return { mp_key: chiave, mp_nome: mp.nome, ...r };
      }).sort((a, b) => b.margine - a.margine);
    });
    
    batchProducts = prodotti;
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
  const mp = MERCATI[mpKey];
  se (!mp) restituisci null;
  const nettoIva = listino/(1+iva/100);
  const dopoSconto = nettoIva* (1 - mp.sconto_percentuale/100);
  const feeShop = mpKey === 'TLUXY_SITE' ? dopoSconto*0.0015:0;
  const feeP = dopoSconto* (mp.fee_principale/100);
  tariffa const = dopoSconto * ((mp.tariffa_secondaria || 0) / 100);
  const tariffaA = dopoSconto * ((mp.tariffa_accessoria || 0) / 100);
  const tariffeMp = tariffaP + tariffaS + tariffaA + (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
  const margine = dopoSconto - feeShop - feesMp - costo;
  const marginePerc = listino > 0 ? (margine/listino*100): 0;
  // Break-even, prezzo per 20%, prezzo per 30% (formula: stesso meccanismo di prezzoMinimoPerMargine)
  funzione prezzoMin(targetPerc) {
    const totalPercFee = (mp.fee_principale + (mp.fee_secondaria || 0) + (mp.fee_accessoria || 0) + (mpKey === 'TLUXY_SITE' ? 0.15 : 0)) / 100;
    const scontoP = mp.sconto_percentuale/100;
    tariffa fissaFissa = (mp.tariffa_fissa_trasporto || 0) + (mp.tariffa_fissa_imballaggio || 0);
    coef cost = (1 - scontoP) * (1 - totalPercFee) / (1 + iva / 100) - targetPerc / 100;
    se (coef <= 0) restituisci null;
    reso (costo+commissioneFissa)/coef;
  }
  // Margine se vendo a retail pieno
  lascia margineRetail = null, margineRetailPerc = null;
  se (vendita al dettaglio && vendita al dettaglio > 0 && vendita al dettaglio !== listino) {
    const r = batchCalcMargine(retail, costo, mpKey, iva, null);
    margineRetail = r ? r.margine : null;
    margineRetailPerc = r ? r.marginePerc : null;
  }
  // Sconto massimo accettabile dal retail per tariffa 20% margine
  // Se per fare 20% serve prezzo X, allora sconto max = (retail - X) / retail * 100
  lascia scontoMax20 = null;
  se (vendita al dettaglio && vendita al dettaglio > 0) {
    const p20 = prezzoMin(20);
    se (p20 !== null && p20 > 0) {
      scontoMax20 = ((prezzo al dettaglio - p20) / prezzo al dettaglio) * 100;
      // Se negativo significa che NON puoi scontare (devi vendere SOPRA retail)
      se (scontoMax20 < 0) scontoMax20 = nullo; // impossibile
    }
  }
  ritorno {
    margine, marginePerc, dopoSconto, feesMp, feeShop,
    punto di pareggio: prezzoMin(0),
    prezzo20: prezzoMin(20),
    prezzo30: prezzoMin(30),
    margineRetail, margineRetailPerc,
    Sconto Max20
  };
}

funzione renderBatch() {
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
      '<div style="font-size:0.75rem; color:var(--gray-700);">' + (mpVincente ? mpVincente[1] + ' volte in alto' : '') + '</div>' +
    '</div>' +
  '</div>';
  
  // Bottone Esporta
  const exportBtn = '<div style="display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap;">' +
    '<button id="batch-export-btn" class="apply-btn" style="background:var(--green-primary); padding:10px 18px;">📥 Esporta Excel completo (16 MP × tutti i prodotti)</button>' +
    '<button id="batch-clear-btn" class="apply-btn" style="background:var(--gray-700); padding:10px 18px;">🗑️ Pulisci</button>' +
  '</div>';
  
  // Tabella condivisa
  const tableHtml = '<div class="table-wrap" style="margin-top:8px;">' +
    '<table class="breakdown-table" style="font-size:0.85rem;">' +
      '<thead><tr>' +
        '<th>SKU</th>' +
        '<th>Titolo</th>' +
        (batchProducts.some(p => p.stock !== null) ? '<th class="num">Stock</th>' : '') +
        '<th class="num">Vendita al dettaglio</th>' +
        '<th class="num">Sc.%</th>' +
        '<th class="num">Costo</th>' +
        '<th class="num">Listino</th>' +
        '<th class="num">IVA</th>' +
        '<th>I 3 migliori MP</th>' +
        '<th></th>' +
      '</tr></thead>' +
      '<tbody>' +
      batchProducts.map((p, idx) => {
        const top3 = p.calcoli.slice(0, 3);
        const top3Html = top3.map(c => {
          const cls = c.margine >= 0 ? 'margin-pos' : 'margin-neg';
          const segno = c.margine >= 0 ? '+':'';
          return '<span style="display:inline-block; background:var(--gray-100); padding:2px 8px; border-radius:6px; font-size:0.75rem; margin:1px 2px;"><strong>' + c.mp_nome + '</strong> · <span class="' + cls + '">' + segno + '€' + c.margine.toFixed(0) + '</span> <span style="color:var(--gray-700);">(' + c.marginePerc.toFixed(1) + '%)</span></span>';
        }).giuntura(' ');
        const isExpanded = batchExpanded === p.sku;
        const sameRetailListino = Math.abs(p.retail - p.listino) < 0,5;
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
        lascia detailRow = '';
        se (è espanso) {
          const colspan = batchProducts.some(pp => pp.stock !== null) ? '10' : '9';
          const detTable = '<tr><td colspan="' + colspan + '" style="padding:0; background:var(--cream);">' +
            '<div style="padding:14px;">' +
            '<div style="margin-bottom:8px; font-size:0.78rem; color:var(--gray-700);"><strong>Retail di riferimento: €' + p.retail.toFixed(2) + '</strong> · sconto fornitore -' + p.scontoForn.toFixed(1) + '% (costo €' + p.costo.toFixed(2) + ')</div>' +
            '<table class="detail-table" style="font-size:0.78rem;">' +
              '<thead><tr><th>Mercato</th><th class="num">Prezzo netto MP</th><th class="num">Commissioni MP</th><th class="num">Margine €</th><th class="num">Margine %</th><th class="num">Pareggio</th><th class="num">Al 20%</th><th class="num">Al 30%</th><th class="num" title="Sconto massimo che puoi fare dal retail e ancora avere 20% margine">Sc.Max 20%</th></tr></thead>' +
              '<tbody>' +
              p.calcoli.map((c, ci) => {
                const cls = c.margine >= 0 ? 'margin-pos' : 'margin-neg';
                const isTop = ci < 3;
                const bg = èTop? 'sfondo:rgba(0,128,96,0.06);' :'';
                const segno = c.margine >= 0 ? '+':'';
                medaglia const = isTop? ' 🏆' : '';
                // Rimozione max formato
                lascia scMaxFmt = '—';
                se (c.scontoMax20 !== null && c.scontoMax20 !== undefined) {
                  if (c.scontoMax20 < 0) scMaxFmt = '<span style="color:var(--red);" title="Impossibile fare 20%: devi vendere sopra retail">impossibile</span>';
                  altrimenti scMaxFmt = '<span style="color:var(--green-dark); font-weight:600;">-' + c.scontoMax20.toFixed(1) + '%</span>';
                }
                restituisci '<tr style="' + bg + '">' +
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
          rigaDettaglio = TabellaDettaglio;
        }
        restituisci rigaprincipale + rigadettaglio;
      }).join('') +
      '</tbody></table></div>';
  
  cont.innerHTML = summary + exportBtn + tableHtml;
  
  // Gestori di clic
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

funzione exportBatchExcel() {
  se (!batchProducts.length) restituisci;
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
          c.scontoMax20 !== null && c.scontoMax20 !== non definito && c.scontoMax20 >= 0 ? parseFloat(c.scontoMax20.toFixed(2)): 'N/D'
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
        riga.push(c ? parseFloat(c.margine.toFixed(2)) : '');
      });
      pivotRows.push(row);
    });
    const wsPivot = XLSX.utils.aoa_to_sheet(pivotRows);
    XLSX.utils.book_append_sheet(wb, wsPivot, 'Margine matrice €');
    
    // Foglio 4: matrice pivot %
    const pivotHeaderPerc = ['SKU', 'Titolo', 'Listino'].concat(mpKeys.map(k => MARKETPLACES[k].nome + ' %'));
    const pivotRowsPerc = [pivotHeaderPerc];
    batchProducts.forEach(p => {
      const row = [p.sku, p.titolo || '', p.listino];
      mpKeys.forEach(k => {
        const c = p.calcoli.find(x => x.mp_key === k);
        riga.push(c ? parseFloat(c.marginePerc.toFixed(2)) : '');
      });
      pivotRowsPerc.push(row);
    });
    const wsPivotPerc = XLSX.utils.aoa_to_sheet(pivotRowsPerc);
    XLSX.utils.book_append_sheet(wb, wsPivotPerc, 'Margine matrice %');
    
    const date = new Date().toISOString().split('T')[0];
    XLSX.writeFile(wb, 'tluxy_calcolo_batch_' + date + '.xlsx');
  }).catch(e => alert('Errore durante l'esportazione: ' + e.message));
}

funzione downloadBatchTemplate() {
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
    // Imposta la larghezza delle colonne in base alla leggibilità
    ws['!cols'] = [{wch:18}, {wch:32}, {wch:8}, {wch:10}, {wch:10}, {wch:10}, {wch:12}, {wch:6}];
    XLSX.utils.book_append_sheet(wb, ws, 'Prodotti');
    
    // Aggiungo un foglio "Istruzioni" per chiarezza
    const istr = [
      ['ISTRUZIONI USO TEMPLATE'],
      [''],
      ['COLONNE OBBLIGATORIE:'],
      ['• SKU - codice prodotto'],
      ['• Retail (o Listino) - prezzo al dettaglio pieno RRP'],
      ['• Costo OPPURE Sconto% - almeno una delle due'],
      [''],
      ['COLONNE OPZIONALI:'],
      ['• Titolo - nome prodotto'],
      ['• Stock - pezzi disponibili'],
      ['• Listino - prezzo di vendita effettivo (default = Retail)'],
      ['• IVA - aliquota IVA (impostazione predefinita = 22%)'],
      [''],
      ['LOGICA CALCOLO COSTO:'],
      ['• Se compili "Sconto%", il costo è calcolato: Retail × (1 - Sconto%/100)'],
      ['• Se compili "Costo", uso quel valore direttamente'],
      ['• Se compili entrambi, prevale "Costo"'],
      [''],
      ['ESEMPI:'],
      ['• Retail 500€ + Sconto% 50 = Costo 250€'],
      ['• Vendita al dettaglio 380€ + Costo 152€ = Sconto effettivo 60%'],
      [''],
      ['NOMI COLONNE ACCETTATI (senza distinzione tra maiuscole e minuscole):'],
      ['• SKU: sku, codice, codice prodotto'],
      ['• Vendita al dettaglio: retail, rrp, retail price, prezzo retail, prezzo pieno'],
      ['• Sconto%: sconto, sconto%, sconto fornitore, sconto%'],
      ['• Costo: costo, cost, costo fornitore, costo acquisto'],
      ['• Listino: listino, prezzo vendita, prezzo, prezzo, prezzo di vendita']
    ];
    const wsIstr = XLSX.utils.aoa_to_sheet(istr);
    wsIstr['!cols'] = [{wch:70}];
    XLSX.utils.book_append_sheet(wb, wsIstr, 'Istruzioni');
    
    XLSX.writeFile(wb, 'tluxy_template_calcolo_batch.xlsx');
  }).catch(e => alert('Errore: ' + e.message));
}

// ============ ASSISTENTE CHAT AI (v5.10) ============
let chatHistory = []; // {ruolo, contenuto}
lascia chatBusy = falso;

funzione asincrona checkChatStatus() {
  const bar = document.getElementById('chat-status-bar');
  se (!bar) restituisci;
  Tentativo {
    const data = await fetchNoCache('/api/chat-status');
    se (dati abilitati) {
      bar.className = 'info-box';
      bar.style.cssText = 'background:var(--green-light); border-left-color:var(--green-primary); color:var(--green-dark);';
      bar.innerHTML = '✅ <strong>Assistente attivo</strong> · usa modello ' + (data.model || 'Claude') + ' · costo stimato per messaggio: ' + (data.cost_per_msg || '€0.01-0.05');
    } altro {
      bar.className = 'warn-box';
      bar.innerHTML = '⚠️ <strong>Assistente non configurato</strong>. Per attivarlo: Vercel → Impostazioni → Variabili d'ambiente → aggiungi <code>ANTHROPIC_API_KEY</code> con la tua chiave da console.anthropic.com';
    }
  } catch(e) {
    bar.innerHTML = '❌ Errore verifica stato: ' + e.message;
  }
}

funzione chatRender() {
  const container = document.getElementById('chat-messages');
  se (!container) restituisci;
  if (chatHistory.length === 0) return; // mostra suggerito
  container.innerHTML = chatHistory.map(msg => {
    const isUser = msg.role === 'user';
    const align = isUser ? 'flex-end' : 'flex-start';
    const bg = isUser ? 'var(--nero)' : 'var(--bianco)';
    const color = isUser ? 'var(--white)' : 'var(--black)';
    const border = isUser ? 'none' : '1px solid var(--gray-200)';
    const radius = isUser ? '14px 14px 4px 14px' : '14px 14px 14px 4px';
    // Markdown molto basico: doppio asterisco per bold, newline per a-capo
    let content = String(msg.content || '').replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>');
    contenuto = contenuto.sostituisci(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
    contenuto = contenuto.sostituisci(/\\n/g, '<br>');
    restituisci '<div style="display:flex; justify-content:' + align + '; margin-bottom:12px;">' +
      '<div style="max-width:80%; padding:11px 16px; background:' + bg + '; color:' + color + '; border:' + border + '; border-radius:' + radius + '; font-size:0.92rem; line-height:1.5; white-space:pre-wrap; overflow-wrap:break-word;">' + content + '</div>' +
    '</div>';
  }).giuntura('');
  se (chatOccupata) {
    container.innerHTML += '<div style="display:flex; justify-content:flex-start; margin-bottom:12px;">' +
      '<div style="padding:11px 16px; background:var(--white); border:1px solid var(--gray-200); border-radius:14px 14px 14px 4px; font-size:0.9rem; color:var(--gray-700);">' +
      '<span style="display:inline-block; animation:pulse 1.4s infinite;">●</span><span style="display:inline-block; animation:pulse 1.4s infinite 0.2s; margin:0 4px;">●</span><span style="display:inline-block; animation:pulse 1.4s infinite 0.4s;">●</span></div></div>';
  }
  container.scrollTop = container.scrollHeight;
}

funzione asincrona chatSend(messaggio) {
  se (!messaggio || chatOccupata) restituisci;
  chatHistory.push({ ruolo: 'utente', contenuto: messaggio });
  chatOccupato = vero;
  chatRender();
  document.getElementById('chat-input').value = '';
  
  Tentativo {
    const res = await fetch('/api/chat', {
      metodo: 'POST',
      intestazioni: { 'Content-Type': 'application/json' },
      corpo: JSON.stringify({ messaggi: chatHistory })
    });
    const data = await res.json();
    chatOccupato = falso;
    se (dati di successo) {
      chatHistory.push({ role: 'assistente', content: data.reply });
    } altro {
      chatHistory.push({ role: 'assistant', content: '❌ Errore: ' + (data.error || 'sconosciuto') });
    }
    chatRender();
  } catch(e) {
    chatOccupato = falso;
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
    mostraTab(btn.dataset.tab);
    if (btn.dataset.tab === 'duo') { checkKvStatus(); /* on-demand: niente auto-caricamento, clicca Ricarica */ }
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
  // Calcolatore: Retail + Sconti ascoltatori (solo monodirezionale, lato sicuro)
  ['calc-retail', 'calc-sconto-vendita', 'calc-sconto-costo'].forEach(id => {
    const el = document.getElementById(id);
    se (el) el.addEventListener('input', calcUpdateFromRetail);
  });
  // Listener di Batch Excel
  const batchFile = document.getElementById('batch-file');
  if (batchFile) batchFile.addEventListener('change', e => { if (e.target.files[0]) handleBatchFile(e.target.files[0]); });
  const batchTplBtn = document.getElementById('batch-template-btn');
  se (batchTplBtn) batchTplBtn.addEventListener('click', downloadBatchTemplate);
  const batchIvaSel = document.getElementById('batch-iva-default');
  se (batchIvaSel) batchIvaSel.addEventListener('change', () => {
    // Ricalcola utilizzando la nuova IVA come default
    se (batchProducts.length > 0) {
      const newIva = parseFloat(batchIvaSel.value) || 22;
      batchProducts.forEach(p => {
        p.iva = newIva;
        p.calcoli = Object.entries(MARKETPLACES).map(([key, mp]) => {
          const r = batchCalcMargine(p.listino, p.costo, key, p.iva, p.retail);
          return { mp_key: chiave, mp_nome: mp.nome, ...r };
        }).sort((a, b) => b.margine - a.margine);
      });
      renderBatch();
    }
  });
  // Ascoltatori DUO
  document.getElementById('duo-reload').addEventListener('click', loadDuoProducts);
  const fcBtn = document.getElementById('forecast-reload');
  se (fcBtn) fcBtn.addEventListener('click', () => loadForecast(false));
  const fcRefresh = document.getElementById('forecast-refresh');
  se (fcRefresh) fcRefresh.addEventListener('click', () => {
    if (confirm('Ricalcolare tutte le previsioni? Richiede 10-30 secondi.')) loadForecast(true);
  });
  
  // Listener di inventario
  const invBtn = document.getElementById('inventory-reload');
  se (invBtn) invBtn.addEventListener('click', () => loadInventory(false));
  const invRefresh = document.getElementById('inventory-refresh');
  se (invRefresh) invRefresh.addEventListener('click', () => {
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
      filtro_inventario = btn.dataset.filter;
      se (inventoryData) renderInventory();
    });
  });
  document.getElementById('duo-csv-file').addEventListener('change', e => { if (e.target.files[0]) handleCsvImport(e.target.files[0]); });
  document.getElementById('duo-search').addEventListener('input', filterDuoProducts);
  // Listener di Chat AI
  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send');
  const chatClearBtn = document.getElementById('chat-clear');
  se (chatSendBtn) chatSendBtn.addEventListener('click', () => {
    const v = (chatInput.value || '').trim();
    se (v) chatSend(v);
  });
  se (chatInput) chatInput.addEventListener('keydown', e => {
    se (e.key === 'Invio') {
      const v = (chatInput.value || '').trim();
      se (v) chatSend(v);
    }
  });
  se (chatClearBtn) chatClearBtn.addEventListener('click', () => {
    chatHistory = [];
    chatOccupato = falso;
    chatRender();
    // Mostra schermata vuota con suggerimenti
    document.getElementById('chat-messages').innerHTML = document.getElementById('chat-messages').innerHTML; // forza il re-render iniziale
    location.hash = '#chat-tab'; setTimeout(() => location.hash = '', 100); // reset Visualizzazione
  });
  // Bottoni ha suggerito nella chat
  document.querySelectorAll('.chat-suggest').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.textContent.replace(/^[^a-zA-Z0-9]+\s*/, '').trim();
      chatSend(testo);
    });
  });
  // Gestore del logout
  const logoutBtn = document.getElementById('logoutBtn');
  se (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (!confirm('Vuoi uscire dalla dashboard?')) return;
      try { await fetch('/api/logout', { method: 'POST' }); } catch(_) {}
      window.location.href = '/login';
    });
  }
  setTimeout(() => { confronta(); const todayBtn = document.querySelector('[data-analytics-periods] .period-btn[data-period="today"]'); setPeriod('today', todayBtn); }, 300);
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

  Tentativo {
    // ============ ENDPOINT DI AUTENTICAZIONE (LINK MAGICO) ============
    // Pagina login: GET /login (pubblica, sempre accessibile)
    se (req.method === 'GET' && path === '/login') {
      res.setHeader('Content-Type', 'text/html');
      const sent = query.get('sent');
      const err = query.get('err');
      const expired = query.get('expired');
      lascia msg = null, isErr = false;
      if (sent === '1') msg ​​= "✉️ Se l'email è autorizzata, riceverai il magic link in breve. Controlla la posta (anche spam).";
      else if (err === 'invalid') { msg = 'Link non valido o già usato. Richiedine uno nuovo.'; isErr = vero; }
      else if (err === 'rate') { msg = "Troppi tentativi. Ripova tra un'ora."; isErr = vero; }
      else if (err === 'config') { msg = "Sistema auth non configurato. Contatta l'amministratore."; isErr = vero; }
      else if (expired === '1') { msg = 'Sessione scaduta, rifai login.'; isErr = vero; }
      restituisci res.status(200).send(loginHTMLPage(msg, isErr));
    }
    
    // Richiesta del link magico: POST /api/request-magic-link { email }
    se (req.method === 'POST' && path === '/api/request-magic-link') {
      if (!AUTH_ENABLED) return res.status(503).json({ success: false, error: 'Auth non configurato (RESEND_API_KEY o ALLOWED_EMAILS mancanti)' });
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurabile — necessario per magic link' });
      Tentativo {
        lascia corpo = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const email = (data.email || '').trim().toLowerCase();
        // Validazione base email
        se (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return res.status(200).json({ success: true }); // nessuna perdita di informazioni
        }
        // Check whitelist (silenzioso per evitare enumeration)
        se (!EMAIL_CONSENTITE.include(email)) {
          // Ritorna comunque successo: vero per non dare info su quali email sono autorizzate
          restituisci res.status(200).json({ success: true });
        }
        // Limitazione della velocità tramite KV
        const rateLimitKey = `auth_rate_${email}`;
        const currentCount = await kvGet(rateLimitKey);
        se (currentCount && parseInt(currentCount, 10) >= MAGIC_LINK_RATE_LIMIT) {
          return res.status(200).json({ success: true }); // nessuna perdita
        }
        // Genera il link magico del token
        const token = generateMagicLinkToken();
        const tokenKey = `magic_token_${token}`;
        const expiresAt = Date.now() + (MAGIC_LINK_MINUTES * 60 * 1000);
        // Salva in KV con payload email + expiresAt
        await kvSet(tokenKey, JSON.stringify({ email, expiresAt }));
        // Imposta TTL tramite EXPIRE (Upstash supporta tramite percorso URL)
        Tentativo {
          await fetch(`${KV_REST_API_URL}/expire/${encodeURIComponent(tokenKey)}/${MAGIC_LINK_MINUTES * 60}`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
        } presa (_) {}
        // Incremento del contatore del limite di frequenza (TTL 1h)
        Tentativo {
          const newCount = currentCount ? parseInt(currentCount, 10) + 1 : 1;
          attendi kvSet(rateLimitKey, String(newCount));
          await fetch(`${KV_REST_API_URL}/expire/${encodeURIComponent(rateLimitKey)}/3600`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } });
        } presa (_) {}
        // Costruisci magic link e invia email
        const magicLink = `${DASHBOARD_URL}/api/verify-magic-link?token=${token}`;
        Tentativo {
          attendi sendMagicLinkEmail(email, magicLink);
        } catch (sendErr) {
          console.error('Errore durante l'invio dell'e-mail:', sendErr.message);
          // Non leakare informazioni sull'errore all'utente
        }
        restituisci res.status(200).json({ success: true });
      } catch (errore) {
        console.error('Errore nella richiesta del collegamento magico:', error.message);
        return res.status(200).json({ success: true }); // nessuna perdita
      }
    }
    
    // Verifica il link magico: GET /api/verify-magic-link?token=XXX (clicca sul link nell'email)
    se (req.method === 'GET' && path === '/api/verify-magic-link') {
      se (!AUTH_ENABLED) restituisci res.redirect(302, '/login?err=config');
      const token = query.get('token');
      se (!token) restituisci res.redirect(302, '/login?err=invalid');
      Tentativo {
        const tokenKey = `magic_token_${token}`;
        const raw = await kvGet(tokenKey);
        se (!raw) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          restituisci res.end();
        }
        lasciare il payload;
        try { payload = JSON.parse(raw); } catch (e) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          restituisci res.end();
        }
        se (!payload.email || !payload.expiresAt || payload.expiresAt < Date.now()) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          restituisci res.end();
        }
        // Token di annullamento (monouso)
        try { await fetch(`${KV_REST_API_URL}/del/${encodeURIComponent(tokenKey)}`, { headers: { 'Authorization': `Bearer ${KV_REST_API_TOKEN}` } }); } catch (_) {}
        // Verifica che email sia ancora autorizzata (la whitelist può essere modificata)
        se (!EMAIL_CONSENTITE.include(payload.email)) {
          res.writeHead(302, { Location: '/login?err=invalid' });
          restituisci res.end();
        }
        // Setta cookie sessione e reindirizza alla dashboard
        setAuthCookie(res, payload.email);
        res.writeHead(302, { Location: '/' });
        restituisci res.end();
      } catch (errore) {
        console.error('Errore durante la verifica del collegamento magico:', error.message);
        res.writeHead(302, { Location: '/login?err=invalid' });
        restituisci res.end();
      }
    }
    
    //Logout: cancella cookie e reindirizza il login
    se (req.method === 'POST' && path === '/api/logout') {
      clearAuthCookie(res);
      restituisci res.status(200).json({ success: true });
    }
    se (req.method === 'GET' && path === '/logout') {
      clearAuthCookie(res);
      res.writeHead(302, { Location: '/login' });
      restituisci res.end();
    }

    // ============ GATE DI AUTORIZZAZIONE ============
    // Tutti gli altri endpoint richiedono autenticazione (se abilitata)
    const authUser = getAuthenticatedUser(req);
    se (AUTH_ENABLED && !authUser) {
      se (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
        res.writeHead(302, { Location: '/login?expired=1' });
        restituisci res.end();
      }
      return res.status(401).json({ success: false, error: 'Non autorizzato. Effettua il login.', auth_required: true });
    }

    se (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      restituisci res.status(200).send(DASHBOARD_HTML);
    }

    se (req.method === 'GET' && path === '/api') {
      return res.json({ sistema: 'T. Luxy ERP — Marginalità v5.12.1', status: 'LIVE', store: SHOPIFY_STORE, credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET), auth_enabled: AUTH_ENABLED, auth_type: 'magic_link_resend', kv_enabled: KV_ENABLED, kv_source: KV_SOURCE, anthropic_configured: !!process.env.ANTHROPIC_API_KEY, user_email: authUser?.email || null, funzionalita: ['🧮 Calcolatore con Retail + 2 sconti (monodirezionale)', '📊 Excel batch con Retail + Sconto% fornito', '💡 Sconto Max corretto per 20% margine', '💬 Chat AI Assistant (Claude Haiku 4.5)', 'GIGLIO.COM marketplace', 'Mark Foy Department Store', 'Split costi KPI (Merce + Fees)', 'Simulatore DUO on-demand', 'Snapshot Inventario', 'Cache KV 24h', 'Previsioni Incassi', 'Balardi wallet', 'Gestione resi/refund', 'Conversione valuta automatica'], marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length });
    }

    se (req.method === 'GET' && path === '/api/analytics') {
      const periodo = query.get('periodo') || 'oggi';
      const from = query.get('from'); const to = query.get('to');
      Tentativo {
        let ordini = await getShopifyOrders(periodo, da, a);
        ordini = attendono processoOrdini(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => {
          se (item.variant_id) variantIds.add(item.variant_id);
          se (item.product_id) productIds.add(item.product_id);
        }));
        const fetchResult = await fetchVariantCosts([...variantIds], [...productIds]);
        const variantCosts = fetchResult.costs;
        const fetchStats = fetchResult.stats;
        
        // Carica costi DUO salvati manualmente dall'utente (per gli ordini dove Shopify ha perso il costo)
        const duoUserCosts = {};
        se (KV_ENABLED) {
          const duoSkuVariantIds = [];
          ordini.forEach(o => (o.line_items || []).forEach(item => {
            if (item.variant_id && isDuoSku(item.sku)) duoSkuVariantIds.push(item.variant_id);
          }));
          const uniqueDuoVids = [...new Set(duoSkuVariantIds)];
          se (uniqueDuoVids.length > 0) {
            const duoKeys = uniqueDuoVids.map(v => `duo_user_cost_${v}`);
            const duoResults = await kvMGet(duoKeys);
            uniqueDuoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              se (duoResults[key] !== undefined) {
                const parsed = parseFloat(duoResults[key]);
                se (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        
        poniamo lordo_iva_inclusa = 0, iva_totale = 0, costi_totali = 0, margine_netto = 0;
        // Ripartizione dei costi per KPI "merce" vs "commissioni + spedizione + imballaggio"
        poniamo costi_merce_totali = 0, costi_commissioni_totali = 0;
        // Rimborso aggregato (separati per analisi)
        poniamo resi_totale_eur = 0, resi_count = 0, resi_full_count = 0, resi_partial_count = 0;
        lascia resi_articoli_qty = 0;
        const breakdown_marketplace = {};
        const ordini_con_errori = [];
        const ordini_valuta_estera = [];
        const ordini_con_resi = []; // dettaglio resi per visualizzazione
        ordini.forEach(ordine => {
          const { costo: costo_merce, errori } = calcolaCostoOrdine(ordine, variableCosts, duoUserCosts);
          const mp = riconosciMarketplace(ordine);
          const currencyInfo = getOrderCurrencyInfo(ordine);
          const refundInfo = getOrderRefundInfo(ordine);
          se (errori.length > 0) {
            ordini_con_errori.push({ id: ordine.id, order_number: ordine.order_number, name: ordine.name, total_price: ordine.total_price, total_price_eur: valutaInfo.eurTotal, valuta: valutaInfo.originalCurrency, marketplace: mp.config.nome, prodotti_senza_costo: errori });
            ritorno;
          }
          // PREZZO LORDO IN EUR (rimborso al netto)
          const prezzo_lordo_originale = valutaInfo.eurTotale;
          const prezzo_lordo = Math.max(0, prezzo_lordo_originale - rimborsoInfo.totalRefundedEur); // sosterrò il rimborso
          const spedizione = (ordine.shipping_lines || []).reduce((sum, line) => sum + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency), 0);
          const paese = ordine.indirizzo_spedizione?.codice_paese || ordine.indirizzo_fatturazione?.codice_paese;
          const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(paese);
          const shopifyTaxEur = toEurAmount(ordine.total_tax_set, ordine.total_tax, currencyInfo.originalCurrency);
          const iva_scorporata = shopifyTaxEur > 0 ? shopifyTaxEur: (prezzo_lordo - prezzo_lordo/(1+ivaPerc/100));
          
          // Costo merce: se reso totale → 0 (la merce torna a magazzino), se reso parziale → proporzionale
          poniamo costo_merce_effettivo = costo_merce;
          se (refundInfo.isFullRefund) {
            costo_merce_effettivo = 0;
          } altrimenti se (refundInfo.isPartialRefund && refundInfo.totalQuantity > 0) {
            // Sottrai costo della quantità rimborsata (proporzionale)
            const ratioReso = refundInfo.refundedQuantity / refundInfo.totalQuantity;
            costo_merce_effettivo = costo_merce*(1 - ratioReso);
          }
          
          const ris = calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce_effettivo, spedizione, mp.config, mp.key);
          
          // Se reso totale → conta come 0 fatturato/margine (ma traccialo a parte)
          se (refundInfo.isFullRefund) {
            // Non sommare nulla ai KPI principali, registra solo come reso
            resi_totale_eur += rimborsoInfo.totalRefundedEur;
            resi_count++;
            resi_full_count++;
            resi_articoli_qty += returnInfo.refundedQuantity;
            ordini_con_resi.push({
              numero_ordine: numero_ordine,
              nome: ordine.name,
              creato_al: ordine.creato_al,
              mercato: mp.config.nome,
              tipo: 'totale',
              importo_originale_eur: prezzo_lordo_originale,
              importo_rimborsato_eur: rimborsoInfo.totalRefundedEur,
              quantita_rimborsata: returnInfo.refundedQuantity,
              quantità_totale: rimborsoInfo.totalQuantity
            });
            ritorno; // salta ulteriore scomposizione
          }
          
          se (refundInfo.isPartialRefund) {
            resi_totale_eur += rimborsoInfo.totalRefundedEur;
            resi_count++;
            resi_partial_count++;
            resi_articoli_qty += returnInfo.refundedQuantity;
            ordini_con_resi.push({
              numero_ordine: numero_ordine,
              nome: ordine.name,
              creato_al: ordine.creato_al,
              mercato: mp.config.nome,
              tipo: 'parziale',
              importo_originale_eur: prezzo_lordo_originale,
              importo_rimborsato_eur: rimborsoInfo.totalRefundedEur,
              quantita_rimborsata: returnInfo.refundedQuantity,
              quantità_totale: rimborsoInfo.totalQuantity
            });
          }
          
          lordo_iva_inclusa += ris.prezzo_lordo_iva_inclusa;
          iva_totale += ris.iva_scorporata;
          costi_totali += ris.costi_totali;
          // Diviso: merce da una parte; spese + spedizione + imballo dall'altra
          // (costo_fees = fees_shopify + fees_marketplace + spedizione — packaging è incluso in fees_marketplace)
          costi_merce_totali += costo_merce_effettivo;
          costi_fees_totali += (ris.fees_shopify || 0) + (ris.fees_marketplace || 0) + (spedizione || 0);
          margine_netto += ris.margine_netto;
          
          se (currencyInfo.isForeign) {
            ordini_valuta_estera.push({
              numero_ordine: numero_ordine,
              nome: ordine.name,
              valuta: currencyInfo.originalCurrency,
              total_original: currencyInfo.originalTotal,
              total_eur: currencyInfo.eurTotal,
              tasso_di_cambio: currencyInfo.exchangeRate,
              mercato: mp.config.nome
            });
          }
          
          if (!breakdown_marketplace[mp.key]) breakdown_marketplace[mp.key] = { nome: mp.config.nome, ordini: 0, fatturato: 0, iva: 0, costo_merce: 0, margine: 0, resi_count: 0, resi_eur: 0, dettaglio_ordini: [] };
          breakdown_marketplace[mp.key].ordini += 1;
          breakdown_marketplace[mp.key].fatturato += ris.prezzo_lordo_iva_inclusa;
          breakdown_marketplace[mp.key].iva += ris.iva_scorporata;
          breakdown_marketplace[mp.key].costo_merce += costo_merce_effettivo;
          breakdown_marketplace[mp.key].margine += ris.margine_netto;
          se (refundInfo.hasRefund) {
            breakdown_marketplace[mp.key].resi_count += 1;
            breakdown_marketplace[mp.key].resi_eur += refundInfo.totalRefundedEur;
          }
          breakdown_marketplace[mp.key].dettaglio_ordini.push({
            numero_ordine: numero_ordine,
            nome: ordine.name,
            creato_al: ordine.creato_al,
            Paese,
            fatturato: ris.prezzo_lordo_iva_inclusa,
            iva: ris.iva_scorporata,
            costo_merce: costo_merce_effettivo,
            mercato_delle_tariffe: mercato_delle_tariffe_del_ris,
            commissioni_shopify: ris.commissioni_shopify,
            spedizione,
            margine_netto: ris.margine_netto,
            margine_percentuale: ris.margine_percentuale,
            valuta: currencyInfo.originalCurrency,
            is_foreign_currency: currencyInfo.isForeign,
            total_original: currencyInfo.originalTotal,
            tasso_di_cambio: currencyInfo.exchangeRate,
            // Informazioni sul rimborso
            stato_rimborso: refundInfo.isFullRefund ? 'full' : (refundInfo.isPartialRefund ? 'partial' : 'none'),
            importo_rimborso_euro: informazioni_rimborso.totaleEur_rimborsati,
            quantità_rimborso: informazioni_rimborso quantità_rimborsata,
            quantità_totale_rimborso: informazioni_rimborso.totale,
            articoli: (ordine.line_items || []).map(item => ({
              titolo: titolo dell'articolo,
              sku: item.sku || '',
              quantità: parseInt(item.quantity) || 0,
              prezzo_unit: toEurAmount(item.price_set, item.price, currencyInfo.originalCurrency),
              costo_unità: (funzione() {
                se (item.variant_id && variantCosts[item.variant_id] !== null && variantCosts[item.variant_id] !== undefined) restituisci variantCosts[item.variant_id];
                se (isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) restituisci duoUserCosts[item.variant_id];
                restituisci 0;
              })()
            }))
          });
        });
        const ordini_validi = ordini.length - ordini_con_errori.length - resi_full_count;
        const margine_percentuale = lordo_iva_inclusa > 0 ? (margine_netto/lordo_iva_inclusa*100): 0;
        // Ordina i resi più recenti prima
        ordini_con_resi.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        restituisci res.json({
          successo: vero,
          periodo: da && a ? `${da} → ${a}` : periodo,
          ordini_totali: ordini_validi,
          ordini_con_errori_count: ordini_con_errori.length,
          ordini_con_errori,
          lordo_iva_inclusa,
          iva_totale,
          costi_totale,
          costi_merce_totale,
          costi_commissioni_totale,
          margine_netto,
          margine_percentuale,
          // Sezione reside
          resi: {
            totale_count: resi_count,
            totali_count: resi_full_count,
            conteggio_parziale: conteggio_partiale_resi,
            articoli_resi_qtà: resi_articoli_qtà,
            importo_totale_eur: resi_totale_eur,
            percentuale_su_lordo: lordo_iva_inclusa > 0 ? (resi_totale_eur / (lordo_iva_inclusa + resi_totale_eur) * 100) : 0,
            dettaglio: ordini_con_resi.slice(0, 100)
          },
          mercato di rottura,
          messaggi_valuta_estera,
          fetch_stats: fetchStats,
          ultima_sincronizzazione: new Date().toISOString()
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    se (req.method === 'GET' && path === '/api/bestsellers') {
      const periodo = query.get('periodo') || 'month';
      const from = query.get('from'); const to = query.get('to');
      Tentativo {
        let ordini = await getShopifyOrders(periodo, da, a);
        ordini = attendono processoOrdini(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => {
          se (item.variant_id) variantIds.add(item.variant_id);
          se (item.product_id) productIds.add(item.product_id);
        }));
        const variantCosts = (await fetchVariantCosts([...variantIds], [...productIds])).costs;
        let prodotti = calcolaBestSellers(ordini, 20, variantCosts);
        prodotti = attendono arricchisciConImmagini(prodotti);
        return res.json({ success: true, periodo: from && to ? `${from} → ${to}` : periodo, totale_prodotti_unici: prodotti.length, prodotti });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    se (req.method === 'GET' && path === '/api/debug-costs') {
      Tentativo {
        const periodo = query.get('periodo') || 'ieri';
        const ordini = attendono getShopifyOrders(periodo);
        const processati = attendono ordiniprocesso(ordini);
        const variantIds = new Set();
        const productIds = new Set();
        processati.forEach(o => (o.line_items || []).forEach(item => {
          se (item.variant_id) variantIds.add(item.variant_id);
          se (item.product_id) productIds.add(item.product_id);
        }));
        const fetchResult = await fetchVariantCosts([...variantIds], [...productIds]);
        const variantCosts = fetchResult.costs;
        // Costi DUO manuali
        const duoUserCosts = {};
        se (KV_ENABLED) {
          const duoSkuVariantIds = [];
          processati.forEach(o => (o.line_items || []).forEach(item => {
            if (item.variant_id && isDuoSku(item.sku)) duoSkuVariantIds.push(item.variant_id);
          }));
          const uniqueDuoVids = [...new Set(duoSkuVariantIds)];
          se (uniqueDuoVids.length > 0) {
            const duoKeys = uniqueDuoVids.map(v => `duo_user_cost_${v}`);
            const duoResults = await kvMGet(duoKeys);
            uniqueDuoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              se (duoResults[key] !== undefined) {
                const parsed = parseFloat(duoResults[key]);
                se (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        const debug = processati.map(o => {
          const { costo, errori } = calcolaCostoOrdine(o, variantCosts, duoUserCosts);
          ritorno {
            numero_ordine: o.numero_ordine, nome: o.nome, creato_il: o.creato_il,
            prezzo_totale: o.prezzo_totale, paese: o.indirizzo_spedizione?.codice_paese || o.indirizzo_fatturazione?.codice_paese,
            marketplace: riconosciMarketplace(o).config.nome, costo_merce_reale: costo.toFixed(2),
            line_items: (o.line_items || []).map(item => {
              poniamo costo_per_unità = 'MANCANTE';
              lascia che la fonte di costo sia nulla;
              se (item.variant_id && variantCosts[item.variant_id] !== null && variantCosts[item.variant_id] !== undefined) {
                costo_per_unità = costi_variante[item.variant_id]; fonte_costo = 'shopify';
              } else if (isDuoSku(item.sku) && item.variant_id && duoUserCosts[item.variant_id] !== undefined) {
                costo_per_unità = duoUserCosts[item.variant_id]; fonte_costo = 'duo_manual';
              }
              restituisci { titolo: item.title, sku: item.sku, variant_id: item.variant_id, quantità: item.quantity, prezzo: item.price, costo_per_unità, costo_fonte };
            }),
            riscaldamento
          };
        });
        return res.json({ success: true, periodo, fetch_stats: fetchResult.stats, kv_enabled: KV_ENABLED, duo_costs_loaded: Object.keys(duoUserCosts).length, ordini: debug });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    se (req.method === 'GET' && path === '/api/debug-orders') {
      Tentativo {
        const ordini = await getShopifyOrders('month');
        const debug = ordini.slice(0, 50).map(o => {
          const paese = o.indirizzo_spedizione?.codice_paese || o.indirizzo_fatturazione?.codice_paese;
          return { order_number: o.order_number, name: o.name, created_at: o.created_at, source_name: o.source_name, email: o.email, tags: o.tags, total_price: o.total_price, total_tax_shopify: o.total_tax, country, iva_paese: getIvaPerPaese(country) + '%', marketplace: riconosciMarketplace(o).config.nome, num_line_items: (o.line_items || []).length };
        });
        return res.json({ success: true, ordini_totali: ordini.length, primi_50: debug });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    se (req.method === 'GET' && path === '/api/debug-jd') {
      Tentativo {
        const periodo = query.get('periodo') || 'month';
        const ordini = attendono getShopifyOrders(periodo);
        const jdOrders = ordini.filter(o => riconosciMarketplace(o).key === 'JAMMY_DUDE');
        const productIds = new Set();
        jdOrders.forEach(o => (o.line_items || []).forEach(item => { if (item.product_id) productIds.add(item.product_id); }));
        const tagsCache = await fetchProductsTags([...productIds]);
        const breakdown = jdOrders.map(o => ({ order_number: o.order_number, source_name: o.source_name, total_price: o.total_price, country: o.shipping_address?.country_code || o.billing_address?.country_code, line_items: (o.line_items || []).map(item => ({ product_id: item.product_id, title: item.title, sku: item.sku, price: item.price, quantity: item.quantity, product_tags: tagsCache[item.product_id] || '', ha_tag_JD: hasJDTag(tagsCache[item.product_id]) })) }));
        const inclusi = breakdown.filter(o => o.line_items.some(i => i.ha_tag_JD)).length;
        return res.json({ success: true, periodo, totale_ordini_jammy_dude: jdOrders.length, ordini_inclusi_dopo_filtro: inclusi, ordini_esclusi_dopo_filtro: breakdown.length - inclusi, dettaglio_ordini: breakdown });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // DIAGNOSTICA: traccia chiamate Shopify per singolo variante_id
    // ============ SIMULATORE DUO ============
    // Lista tutti i prodotti DUO attivi (SKU che inizia con DUO-) con informazioni utili per simulazione
    se (req.method === 'GET' && path === '/api/duo-products') {
      Tentativo {
        const token = await getShopifyAccessToken();
        const prodotti = [];
        // NB: aggiungiamo inventory_item_id per poter recuperare i costi in batch dopo
        let url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&status=active&fields=id,title,variants`;
        lascia pageCount = 0;
        const maxPages = 30;
        mentre (url && pageCount < maxPages) {
          const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          se (!risposta.ok) interrompi;
          const data = await response.json();
          (dati.prodotti || []).forEach(p => {
            (p.varianti || []).forEach(v => {
              se (èDuoSku(v.sku)) {
                prodotti.spinta({
                  product_id: p.id,
                  variant_id: v.id,
                  inventory_item_id: v.inventory_item_id, // servi per batch di costi di recupero
                  titolo: p.title,
                  titolo_variante: v.title,
                  sku: v.sku,
                  prezzo_listino: parseFloat(v.price) || 0,
                  compare_at_price: parseFloat(v.compare_at_price) || 0,
                  quantità_inventario: v.quantità_inventario || 0
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
        // Shopify espone il costo via /inventory_items.json?ids=1,2,3 (max 100 per chiamata)
        const inventoryItemIds = products.map(p => p.inventory_item_id).filter(Boolean);
        const costsByItemId = {};
        const BATCH_SIZE = 100;
        per (lascia i = 0; i < inventoryItemIds.length; i += BATCH_SIZE) {
          const batch = inventoryItemIds.slice(i, i + BATCH_SIZE);
          const batchUrl = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${batch.join(',')}&limit=${BATCH_SIZE}`;
          Tentativo {
            const r = await fetch(batchUrl, { headers: { 'X-Shopify-Access-Token': token } });
            se (!r.ok) continua;
            const data = await r.json();
            (data.inventory_items || []).forEach(item => {
              const c = parseFloat(articolo.costo);
              se (!isNaN(c)) costsByItemId[item.id] = c;
            });
          } catch (e) { /* continua con batch successivo */ }
        }
        
        // Applica costo Shopify a ciascun prodotto (senza KV, come richiesto)
        const enriched = products.map(p => ({
          product_id: p.product_id,
          variant_id: p.variant_id,
          titolo: p.title,
          titolo_variante: p.titolo_variante,
          sku: p.sku,
          prezzo_listino: p.prezzo_listino,
          confronta_al_prezzo: p.compara_al_prezzo,
          quantità_inventario: p.quantità_inventario,
          costo_fornitore: costsByItemId[p.inventory_item_id] !== undefined ? costsByItemId[p.inventory_item_id] : null,
          costo_source: costsByItemId[p.inventory_item_id] !== undefined ? 'shopify' : 'missing'
        }));
        
        // Ordina: prima quelli con costo, poi per titolo
        enriched.sort((a, b) => {
          if ((a.costo_fornitore !== null) !== (b.costo_fornitore !== null)) return a.costo_fornitore !== null ? -1:1;
          restituisci a.title.localeCompare(b.title);
        });
        
        const withCost = enriched.filter(p => p.costo_fornitore !== null).length;
        restituisci res.json({
          successo: vero,
          totale: lunghezza arricchita,
          con_costo_shopify: conCosto,
          senza_costo: lunghezza arricchita - conCosto,
          prodotti: arricchiti
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Importa costi DUO da CSV (payload JSON: {costs: {variant_id: cost}})
    se (req.method === 'POST' && path === '/api/duo-costs-import') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV storage non configurabile. Abilita Vercel KV.' });
      Tentativo {
        lascia corpo = '';
        attendi nuova Promise((risolvi, rifiuta) => {
          req.on('data', chunk => body += chunk);
          req.on('end', resolve);
          req.on('errore', rifiuta);
        });
        const data = JSON.parse(body);
        const costi = dati.costi || {};
        const pairs = {};
        lascia count = 0;
        Object.entries(costs).forEach(([vid, cost]) => {
          const parsed = parseFloat(cost);
          se (vid && !isNaN(parsed) && parsed >= 0) {
            coppie[`duo_user_cost_${vid}`] = Stringa(analizzata);
            conteggio++;
          }
        });
        if (count === 0) return res.json({ success: false, error: 'Nessun costo valido nel CSV' });
        attendi kvMSet(coppie);
        restituisci res.json({ success: true, salvati: count });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Salva singolo costo DUO (per editing inline dal browser)
    se (req.method === 'POST' && path === '/api/duo-cost-set') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV storage non configurato' });
      Tentativo {
        lascia corpo = '';
        attendi nuova Promise((risolvi, rifiuta) => {
          req.on('data', chunk => body += chunk);
          req.on('end', resolve);
          req.on('errore', rifiuta);
        });
        const data = JSON.parse(body);
        const vid = data.variant_id;
        const cost = parseFloat(data.cost);
        if (!vid || isNaN(cost) || cost < 0) return res.json({ success: false, error: 'Dati non validi' });
        await kvSet(`duo_user_cost_${vid}`, String(cost));
        restituisci res.json({ success: true });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Controllo sanitario KV
    // Debug Winkelstraat: mostra ordini riconosciuti come WINKELSTRAAT e il motivo
    // ============ PREVISIONE INCASSI ============
    // Calcola pagamenti previsti per il mese corrente + mese prossimo (default)
    // Cache KV 24h come /api/inventory-discovery. ?refresh=1 per forzare ricalcolo
    se (req.method === 'GET' && path === '/api/forecast') {
      Tentativo {
        const forceRefresh = query.get('refresh') === '1';
        const FORECAST_CACHE_KEY = 'forecast_cache';
        const FORECAST_META_KEY = 'forecast_cache_meta';
        const PREVISIONE_TTL_ORE = 24;
        
        // 1) Prova cache KV (se non forza l'aggiornamento)
        se (!forceRefresh && KV_ENABLED) {
          Tentativo {
            const meta = await kvGet(FORECAST_META_KEY);
            se (meta) {
              const metaObj = JSON.parse(meta);
              const ageMs = Date.now() - (metaObj.generated_at || 0);
              const ageHours = ageMs / (1000 * 60 * 60);
              se (etàOre < PREVISIONE_TTL_ORE) {
                const cached = await kvGet(FORECAST_CACHE_KEY);
                se (memorizzato nella cache) {
                  const cachedObj = JSON.parse(cached);
                  // RICALCOLA SOLO il portafoglio Balardi (rapido, legge solo le ricariche da KV)
                  // per averlo sempre aggiornato anche se si aggiunge una ricarica oggi
                  Tentativo {
                    const rawRic = await kvGet('balardi_wallet_ricariche');
                    se (rawRic) {
                      const ricariche = JSON.parse(rawRic);
                      const totRicaricato = (ricariche || []).reduce((s, r) => s + parseFloat(r.importo || 0), 0);
                      cachedObj.balardi_wallet = cachedObj.balardi_wallet || { consumo_periodo: { importo_eur: 0 } };
                      cachedObj.balardi_wallet.credito_ricaricato = totRicaricato;
                      cachedObj.balardi_wallet.credito_residuo = totRicaricato - (cachedObj.balardi_wallet.credito_consumato || 0);
                      cachedObj.balardi_wallet.ricariche = ricariche;
                    }
                  } catch(e) { /* ignora */ }
                  cachedObj.from_cache = true;
                  cachedObj.cache_age_hours = Math.round(ageHours * 10) / 10;
                  cachedObj.cache_generated_at = new Date(metaObj.generated_at).toISOString();
                  cachedObj.cache_expires_in_hours = Math.round((FORECAST_TTL_HOURS - ageHours) * 10) / 10;
                  restituisci res.json(cachedObj);
                }
              }
            }
          } catch (e) { /* ignora gli errori della cache, recupera i dati aggiornati */ }
        }
        
        // Periodo di LOOKUP ordini: ultimi 120 giorni (per coprire futuri pagamenti dei MP mensili)
        const daysBack = parseInt(query.get('days_back') || '120', 10);
        const monthsAhead = parseInt(query.get('months_ahead') || '2', 10);
        const dateTo = new Date();
        const dateFrom = new Date();
        dateFrom.setDate(dateFrom.getDate() - daysBack);
        
        // Recupera intervalli personalizzati degli ordini
        let ordini = await getShopifyOrders(null, fmtDateISO(dateFrom), fmtDateISO(dateTo));
        ordini = attendono processoOrdini(ordini);
        
        // Recupera costi (per calcolare netto incassato)
        const variantIds = new Set();
        const productIds = new Set();
        ordini.forEach(o => (o.line_items || []).forEach(item => {
          se (item.variant_id) variantIds.add(item.variant_id);
          se (item.product_id) productIds.add(item.product_id);
        }));
        const { costi: variantCosts } = await fetchVariantCosts([...variantIds], [...productIds]);
        
        // Carica costi utente DUO
        const duoUserCosts = {};
        se (KV_ENABLED) {
          const duoVids = [];
          ordini.forEach(o => (o.line_items || []).forEach(item => {
            se (item.variant_id && isDuoSku(item.sku)) duoVids.push(item.variant_id);
          }));
          const uniq = [...new Set(duoVids)];
          se (uniq.length > 0) {
            const keys = uniq.map(v => `duo_user_cost_${v}`);
            const risultati = await kvMGet(chiavi);
            uniq.forEach(v => {
              const key = `duo_user_cost_${v}`;
              se (risultati[chiave] !== indefinito) {
                const parsed = parseFloat(results[key]);
                se (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        
        // Calcola previsione per ogni ordine
        const paymentsByDate = {}; // YYYY-MM-DD → array pagamenti
        const paymentsByMP = {}; // MP_KEY → aggregato
        const paymentsByMonth = {}; // YYYY-MM → aggregato
        const balardiConsumo = { count: 0, importo_eur: 0, ordini: [] };
        lascia ordiniForecast = 0;
        lascia ordiniSaltati = 0;
        
        ordini.forEach(ordine => {
          const mp = riconosciMarketplace(ordine);
          const policy = mp.config.payment_policy;
          if (!policy) { ordiniSkipped++; return; }
          
          const refundInfo = getOrderRefundInfo(ordine);
          if (refundInfo.isFullRefund) { ordiniSkipped++; return; } // nessuna previsione su resi totali
          
          const currencyInfo = getOrderCurrencyInfo(ordine);
          const prezzoLordoOriginale = currencyInfo.eurTotal;
          const prezzoLordo = Math.max(0, prezzoLordoOriginale - refundInfo.totalRefundedEur);
          
          // Calcola costo merce (costo fallback DUO)
          const { costo: costoMerce } = costoCostoOrdine(ordine, variantCosts, duoUserCosts);
          poniamo costoMerceEffettivo = costoMerce;
          se (refundInfo.isPartialRefund && refundInfo.totalQuantity > 0) {
            const ratio = refundInfo.refundedQuantity / refundInfo.totalQuantity;
            costoMerceEffettivo = costoMerce* (1 - rapporto);
          }
          
          // Brigata EUR
          const spedizione = (ordine.shipping_lines || []).reduce((s, line) => s + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency), 0);
          
          // Calcola netto per il venditore (prezzo_netto - fee - sped - packaging, MA netto merce rimanente)
          // Il "netto da incassare dal MP" = prezzo_lordo - sconto - fee_mp - fee_accessoria (NON include costo merce: quello è tuo)
          const cfg = mp.config;
          const paese = ordine.indirizzo_spedizione?.codice_paese || ordine.indirizzo_fatturazione?.codice_paese;
          const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(paese);
          const prezzoNettoIva = prezzoLordo/(1+ivaPerc/100);
          const prezzoDopoSconto = prezzoNettoIva * (1 - (cfg.sconto_percentuale || 0) / 100);
          commissioni constMP = prezzoDopoSconto * ((cfg.fee_principale || 0) / 100)
                       + prezzoDopoSconto * ((cfg.fee_secondaria || 0) / 100)
                       +prezzoDopoSconto* ((cfg.fee_accessoria || 0)/100);
          const nettoFromMP = Math.max(0, prezzoDopoSconto - feesMP - (cfg.fee_fissa_trasporto === 'GLS' ? 15 : (cfg.fee_fissa_trasporto || 0)) - (cfg.fee_fissa_packaging || 0));
          
          const pagamenti = calcolaPagamentiPrevisti(ordine.created_at, policy, nettoFromMP);
          if (pagamenti.length === 0) { ordiniSkipped++; return; }
          orologiForecast++;
          
          // Se è Balardi, traccia come consumo wallet (non genera incasso)
          se (policy.type === 'prepaid_balance') {
            balardiConsumo.count++;
            balardiConsumo.importo_eur += nettoFromMP;
            balardiConsumo.ordini.push({
              numero_ordine: numero_ordine,
              nome: ordine.name,
              creato_al: ordine.creato_al,
              importo_consumato: nettoFromMP,
              prezzo_lordo: prezzoLardo
            });
            ritorno;
          }
          
          controlli.forEach(pg => {
            const dateKey = fmtDateISO(pg.data);
            const monthKey = fmtMonthKey(pg.data);
            se (!pagamentiPerData[chiavedata]) pagamentiPerData[chiavedata] = [];
            pagamentiPerData[chiaveData].push({
              numero_ordine: numero_ordine,
              nome: ordine.name,
              creato_al: ordine.creato_al,
              mercato: mp.config.nome,
              mp_key: mp.key,
              importo_eur: pag. importo_eur,
              nota: pg.nota,
              parte: pg.parte
            });
            if (!paymentsByMP[mp.key]) PaymentsByMP[mp.key] = { nome: mp.config.nome, pagamento_desc: mp.config.pagamento, ordini: 0, importo_totale: 0, prossimo_bonifico: null, pagamenti: [] };
            pagamentiByMP[mp.key].ordini++;
            paymentsByMP[mp.key].importo_totale += pg.importo_eur;
            paymentsByMP[mp.key].pagamenti.push({ data: dateKey, order_number: ordine.order_number, importo_eur: pg.importo_eur, nota: pg.nota });
            se (!pagamentiPerMese[ChiaveMese]) pagamentiPerMese[ChiaveMese] = { mese: ChiaveMese, importo_totale: 0, ordini_count: 0, per_mp: {} };
            pagamentiPerMese[chiaveMese].importo_totale += pg.importo_eur;
            pagamentiPerMese[ChiaveMese].Conteggio_ordini++;
            se (!paymentsByMonth[monthKey].per_mp[mp.key]) paymentsByMonth[monthKey].per_mp[mp.key] = { nome: mp.config.nome, importo: 0, count: 0 };
            pagamentiPerMese[chiaveMese].per_mp[chiavemp].importo += pg.importo_eur;
            pagamentiPerMese[chiaveMese].per_mp[chiavemp].conteggio++;
          });
        });
        
        // Determina prossimo bonifico per ogni MP (data minima >= oggi)
        const todayStr = fmtDateISO(new Date());
        Object.keys(paymentsByMP).forEach(k => {
          const futuri = paymentsByMP[k].pagamenti.filter(p => p.data >= todayStr).sort((a, b) => a.data.localeCompare(b.data));
          pagamentiByMP[k].prossimo_bonifico = futuri.length > 0 ? { data: futuri[0].data, importo_parziale: futuri.filter(f => f.data === futuri[0].data).reduce((s, f) => s + f.importo_eur, 0) } : null;
        });
        
        // Mesi correnti e futuri
        const oggi = new Date();
        const meseCorrente = fmtMonthKey(oggi);
        const meseProssimo = fmtMonthKey(new Date(oggi.getFullYear(), oggi.getMonth() + 1, 1));
        const mesiSecondoProssimo = fmtMonthKey(new Date(oggi.getFullYear(), oggi.getMonth() + 2, 1));
        
        const incassoMeseCorrente = pagamentiPerMese[meseCorrente] || {importo_totale: 0, ordini_count: 0 };
        const incassoMeseProssimo = pagamentiPerMese[meseProssimo] || {importo_totale: 0, ordini_count: 0 };
        const incassoMeseSecondoProssimo = pagamentiPerMese[mesiSecondoProssimo] || {importo_totale: 0, ordini_count: 0 };
        
        // Totale in attesa (da oggi in avanti)
        lascia pendingTotale = 0, pendingCount = 0;
        Object.entries(paymentsByDate).forEach(([date, arr]) => {
          if (date >= todayStr) { arr.forEach(p => { pendingTotale += p.importo_eur; pendingCount++; }); }
        });
        
        // Portafoglio Balardi: leggi ricariche da KV
        let balardiWallet = { credito_ricaricato: 0, credito_consumato: balardiConsumo.importo_eur, credito_residuo: -balardiConsumo.importo_eur, ricariche: [], consumo_periodo: balardiConsumo };
        se (KV_ENABLED) {
          Tentativo {
            const raw = await kvGet('balardi_wallet_ricariche');
            se (grezzo) {
              const ricariche = JSON.parse(raw);
              const totRicaricato = (ricariche || []).reduce((s, r) => s + parseFloat(r.importo || 0), 0);
              balardiWallet.credito_ricaricato = totRicaricato;
              balardiWallet.credito_residuo = totRicaricato - balardiConsumo.importo_eur;
              balardiWallet.ricariche = ricariche;
            }
          } catch (e) {}
        }
        
        // Ripartizione ordina MP per prossimo bont
        const breakdownMP = Object.values(paymentsByMP).sort((a, b) => {
          if (!a.prossimo_bonifico) return 1;
          if (!b.prossimo_bonifico) return -1;
          return a.prossimo_bonifico.data.localeCompare(b.prossimo_bonifico.data);
        });
        
        const forecastResult = {
          successo: vero,
          periodo_analisi: { da: fmtDateISO(dateFrom), a: fmtDateISO(dateTo), giorni_indietro: giorni_indietro },
          ordini_analizzati: ordini.length,
          ordini_con_forecast: ordiniForecast,
          ordini_skipped: ordiniSaltati,
          kpi: {
            incasso_mese_corrente: { mese: meseCorrente, importo: incassoMeseCorrente.importo_totale, ordini: incassoMeseCorrente.ordini_count },
            incasso_mese_prossimo: { mese: meseProssimo, importo: incassoMeseProssimo.importo_totale, ordini: incassoMeseProssimo.ordini_count },
            incasso_mese_dopo: { mese: mesiSecondoProssimo, importo: incassoMeseSecondoProssimo.importo_totale, ordini: incassoMeseSecondoProssimo.ordini_count },
            pending_totale: pendingTotale,
            in sospeso: numero_in sospeso
          },
          mercato_di_sintesi: breakdownMP,
          timeline_mensile: Object.values(paymentsByMonth).sort((a, b) => a.mese.localeCompare(b.mese)),
          balardi_wallet: balardiWallet,
          from_cache: false,
          ultima_sincronizzazione: new Date().toISOString()
        };
        
        // Salva nella cache KV (24h)
        se (KV_ENABLED) {
          Tentativo {
            await kvSet(FORECAST_CACHE_KEY, JSON.stringify(forecastResult));
            await kvSet(FORECAST_META_KEY, JSON.stringify({ generated_at: Date.now(), ordini_count: ordini.length }));
            forecastResult.cached_to_kv = true;
            forecastResult.cache_valid_for_hours = PREECAST_TTL_HOURS;
          } catch (e) { forecastResult.cache_error = e.message; }
        }
        
        restituisci res.json(risultatoprevisto);
      } catch (error) { return res.status(500).json({ success: false, error: error.message, stack: error.stack }); }
    }
    
    // Portafoglio Balardi: aggiungi ricarica
    if (req.method === 'POST' && percorso === '/api/balardi-ricarica') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurabile' });
      Tentativo {
        lascia corpo = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const importo = parseFloat(data.importo);
        const nota = (data.nota || '').substring(0, 200);
        const data_ricarica = data.data_ricarica || fmtDateISO(nuova data());
        if (isNaN(importo) || importo <= 0) return res.status(400).json({ success: false, error: 'Importo non valido' });
        const raw = await kvGet('balardi_wallet_ricariche');
        const ricariche = grezzo ? JSON.parse(raw): [];
        ricariche.push({ id: Date.now(), data_ricarica, importo, nota, creato: new Date().toISOString() });
        attendono kvSet('balardi_wallet_ricariche', JSON.stringify(ricariche));
        restituisci res.json({ success: true, ricariche });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }
    
    // Portafoglio Balardi: rimuovi ricarica
    if (req.method === 'POST' && percorso === '/api/balardi-ricarica-delete') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurabile' });
      Tentativo {
        lascia corpo = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const id = parseInt(data.id);
        if (isNaN(id)) return res.status(400).json({ success: false, error: 'ID non valido' });
        const raw = await kvGet('balardi_wallet_ricariche');
        const ricariche = grezzo ? JSON.parse(raw): [];
        const filtered = ricariche.filter(r => r.id !== id);
        await kvSet('balardi_wallet_ricariche', JSON.stringify(filtered));
        restituisci res.json({ success: true, ricariche: filtered });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    // ============ SCOPERTA INVENTARIO (temporaneo per v5.9) ============
    // Analizza i prodotti Shopify per capire come sono classificazione product_type + tags
    // INVENTORY DISCOVERY: analizza TUTTO il catalogo con paginazione cursor + cache 24h
    se (req.method === 'GET' && path === '/api/inventory-discovery') {
      Tentativo {
        const forceRefresh = query.get('refresh') === '1';
        const cacheKey = 'inventory_discovery_cache_v1';
        const CACHE_TTL_SEC = 24 * 60 * 60; // 24 ore
        
        // Prova cache prima (se KV disponibile e non forzata)
        se (!forceRefresh && KV_ENABLED) {
          Tentativo {
            const cached = await kvGet(cacheKey);
            se (memorizzato nella cache) {
              const data = JSON.parse(cached);
              const ageMin = Math.floor((Date.now() - new Date(data.generated_at).getTime()) / 60000);
              data.dalla_cache = true;
              data.cache_age_minutes = ageMin;
              data.cache_age_human = etàMin < 60 ? `${ageMin} minuti fa` : `${Math.floor(ageMin / 60)} ore fa`;
              restituisci res.json(dati);
            }
          } catch (e) { /* procedi col fetch */ }
        }
        
        // Recupero completo con impaginazione basata sul cursore
        const token = await getShopifyAccessToken();
        const fields = 'id,title,handle,product_type,vendor,tags,status,published_at,variants';
        lascia tutti i prodotti = [];
        lascia pageInfo = null;
        lascia pagesDone = 0;
        const MAX_PAGES = 60; // sicurezza: 60 × 250 = 15.000 prodotti
        
        mentre (pagineCompletate < MAX_PAGES) {
          lascia url;
          se (pageInfo) {
            url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&page_info=${encodeURIComponent(pageInfo)}`;
          } altro {
            url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?status=active&limit=250&fields=${fields}`;
          }
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } });
          se (!r.ok) {
            const t = await r.text();
            return res.status(500).json({ success: false, error: `Pagina Shopify ${pagesDone + 1} ${r.status}: ${t.substring(0, 200)}`, pages_done: pagesDone, partial_products: allProducts.length });
          }
          const data = await r.json();
          const batch = data.products || [];
          tutti iProdotti = tutti iProdotti.concat(batch);
          pagineCompletate++;
          
          // Analizza l'intestazione del collegamento per paginazione del cursore
          const linkHeader = r.headers.get('Link') || r.headers.get('link');
          pageInfo = null;
          se (linkHeader) {
            const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
            se (nextMatch) {
              Tentativo {
                const nextUrl = new URL(nextMatch[1]);
                pageInfo = nextUrl.searchParams.get('page_info');
              } catch (e) { pageInfo = null; }
            }
          }
          
          se (!pageInfo || batch.length < 250) interrompi;
        }
        
        // Analizza l'intero catalogo
        const productTypes = {};
        const vendors = {};
        const tagsAll = {};
        lascia che i prodottiAttivi siano 0;
        lascia che prodottiConStock = 0;
        lascia che prodottiZeroStock = 0;
        lascia totalePezzi = 0;
        lascia totaleVarianti = 0;
        lascia duoProdotti = 0;
        lascia duoPezzi = 0;
        const sampleProducts = [];
        
        tutti i prodotti.perogni(p => {
          se (p.status !== 'active') restituisci;
          prodottiAttivi++;
          const pt = (p.product_type || '(vuoto)').trim();
          productTypes[pt] = (productTypes[pt] || 0) + 1;
          const v = (p.venditore || '(vuoto)').trim();
          venditori[v] = (venditori[v] || 0) + 1;
          (p.tags || '').split(',').map(t => t.trim()).filter(t => t).forEach(tag => {
            tagsAll[tag] = (tagsAll[tag] || 0) + 1;
          });
          const varianti = p.varianti || [];
          const qty = variants.reduce((s, v) => s + Math.max(0, parseInt(v.inventory_quantity) || 0), 0);
          TotalePezzi += qty;
          totaleVarianti += varianti.lunghezza;
          se (qty > 0) prodottiConStock++; altrimenti prodottiZeroStock++;
          
          // Rileva DUO: tag TLX_PRODUCT:DUO oppure modello SKU
          const tagsLower = (p.tags || '').toLowerCase();
          const hasDuoTag = tagsLower.includes('tlx_product:duo') || /(^|,)\s*duo(\s*,|$)/.test(tagsLower);
          const firstSku = variants[0] ? (variants[0].sku || '') : '';
          const isDuo = hasDuoTag || (firstSku && isDuoSku(firstSku));
          se (èDuo) { duoProdotti++; duoPezzi += qty; }
          
          se (sampleProducts.length < 10) {
            sampleProducts.push({
              id: p.id, titolo: (p.title || '').substring(0, 60), handle: p.handle,
              tipo_prodotto: p.tipo_prodotto, fornitore: p.fornitore, tag: p.tag,
              stock: qty, varianti: varianti.lunghezza,
              prima_variante_sku: primoSku, is_duo: isDuo
            });
          }
        });
        
        const sortByCount = obj => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ valore: k, count: v }));
        
        risultato costante = {
          successo: vero,
          generated_at: new Date().toISOString(),
          dalla_cache: false,
          cache_age_minutes: 0,
          cache_age_human: 'appena generata',
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
          propri_prodotti: prodottiAttivi - duoProdotti,
          proprio_pezzi: totalePezzi - duoPezzi,
          product_types_distinti: Object.keys(productTypes).length,
          tipi_prodotto: sortByCount(tipi_prodotto),
          vendors_distinti: Object.keys(vendors).length,
          fornitori: sortByCount(fornitori).slice(0, 50),
          tags_distinti: Object.keys(tagsAll).length,
          tags_top_80: sortByCount(tagsAll).slice(0, 80),
          sample_prodotti: sampleProdotti
        };
        
        // Salva nella cache 24h
        se (KV_ENABLED) {
          Tentativo {
            await kvSetEx(cacheKey, CACHE_TTL_SEC, JSON.stringify(result));
          } catch (e) { /* cache best-effort, continua */ }
        }
        
        restituisci res.json(risultato);
      } catch (e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }
    
    // Reimposta il rilevamento dell'inventario della cache (per aggiornamento forzato)
    se (req.method === 'POST' && path === '/api/inventory-discovery-reset') {
      if (!KV_ENABLED) return res.status(503).json({ success: false, error: 'KV non configurabile' });
      Tentativo {
        await kvDel('inventory_discovery_cache_v1');
        return res.json({ success: true, message: 'Cache resettata. Prossima chiamata farà fetch fresco.' });
      } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
    }

    // ============ RIEPILOGO DELL'INVENTARIO ============
    // Istantanea categorizzata (bag/shoes/accessori/clothing × donna/uomo/unisex)
    // Usa la stessa cache discovery (prodotti grezzi già scaricati)
    se (req.method === 'GET' && path === '/api/inventory') {
      Tentativo {
        const forceRefresh = query.get('refresh') === '1';
        const cacheKey = 'inventory_discovery_cache_v1';
        lascia discoveryData = null;
        
        // Prova a prendere dalla cache discovery (che contiene già i prodotti raw)
        se (!forceRefresh && KV_ENABLED) {
          Tentativo {
            const cached = await kvGet(cacheKey);
            se (memorizzato nella cache) {
              discoveryData = JSON.parse(cached);
            }
          } catch (e) { /* ignora */ }
        }
        
        // Se niente cache, chiama lo stesso endpoint discovery per popolarla
        // (ma noi abbiamo bisogno di più dati: product_type + tags + stock per ogni prodotto, non solo aggregati)
        // Scarichiamo da zero con gli stessi parametri
        se (!discoveryData || !discoveryData._raw_products) {
          // Full fetch: scarica tutti i prodotti
          const token = await getShopifyAccessToken();
          const allProducts = [];
          lascia nextPageInfo = null;
          lascia pagesDone = 0;
          const MAX_PAGES = 60;
          
          mentre (pagineCompletate < MAX_PAGES) {
            lascia url;
            se (nextPageInfo) {
              url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?limit=250&page_info=${encodeURIComponent(nextPageInfo)}`;
            } altro {
              url = `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?status=active&limit=250&fields=id,title,handle,product_type,vendor,tags,status,variants`;
            }
            const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } });
            if (!r.ok) { const t = await r.text(); return res.status(500).json({ success: false, error: `Shopify ${r.status}: ${t.substring(0, 300)}` }); }
            const data = await r.json();
            const batch = data.products || [];
            allProducts.push(...batch);
            pagineCompletate++;
            const linkHeader = r.headers.get('link') || r.headers.get('Link') || '';
            const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
            se (nextMatch && batch.length === 250) {
              const piMatch = nextMatch[1].match(/page_info=([^&>]+)/);
              se (piMatch) nextPageInfo = decodeURIComponent(piMatch[1]);
              altrimenti interrompi;
            } altrimenti interrompi;
          }
          
          discoveryData = { _raw_products: allProducts, pagine_scaricate: pagesDone, generated_at: Date.now() };
          se (KV_ENABLED) {
            Tentativo {
              // Salva cache per riuso (24h). Salviamo i prodotti crudi per il categorizzatore
              const cacheable = { ...discoveryData, cached_at: new Date().toISOString() };
              await kvSetEx(cacheKey, 86400, JSON.stringify(cacheable));
            } catch (e) { /* ignora */ }
          }
        }
        
        const products = discoveryData._raw_products || [];
        
        // ============ CATEGORIZZATORE ============
        // Parole chiave per categoria (priorità: più specifica vince)
        // Corrispondenza senza distinzione tra maiuscole e minuscole su: product_type, tags, title
        const CATEGORIA = {
          borsa: {
            etichetta: 'Borsa',
            parole chiave: ['bag', 'handbag', 'shoulder', 'crossbody', 'tote', 'clutch', 'pochette', 'borsa', 'borse', 'zaino', 'backpack', 'sacca', 'shopper', 'hobo', 'bauletto', 'marsupio', 'belt bag']
          },
          scarpe: {
            etichetta: 'Scarpe',
            parole chiave: ['shoe', 'shoes', 'sneaker', 'sneakers', 'boot', 'boots', 'stivale', 'stivali', 'decolleté', 'décolleté', 'sandalo', 'sandali', 'sandalo', 'mocassino', 'mocassino', 'tacco', 'tacchi', 'tacco', 'ballerina', 'flat', 'scarpa', 'scarpe', 'espadrilla', 'stringata', 'ankle boot', 'slipper']
          },
          accessori: {
            etichetta: 'Accessorio',
            parole chiave: ['accessor', 'cintura', 'cinture', 'belt', 'portafoglio', 'portafogli', 'wallet', 'cappello', 'hat', 'cap', 'occhiali', 'sunglasses', 'eyewear', 'bijoux', 'jewel', 'gioiello', 'collana', 'necklace', 'bracciale', 'bracelet', 'anello', 'ring', 'orecchino', 'earring', 'sciarpa', 'scarf', 'foulard', 'guanti', 'guanti', 'cravatta', 'cravatta', 'papillon', 'porta carte', 'porta carte', 'key', 'chiave']
          },
          vestiario: {
            etichetta: 'Abbigliamento',
            parole chiave: ['giacca', 'giacca', 'cappotto', 'cappotto', 'parka', 'piumino', 'blazer', 'giubbotto', 'bomber', 'shirt', 'camicia', 't-shirt', 'tshirt', 'polo', 'maglia', 'sweater', 'felpa', 'hoodie', 'sweatshirt', 'maglione', 'cardigan', 'pant', 'pants', 'pantalone', 'pantaloni', 'jeans', 'leggings', 'shorts', 'bermuda', 'skirt', 'gonna', 'dress', 'abito', 'vestito', 'top', 'tank', 'body', 'body', 'tuta', 'jumpsuit', 'blouse', 'camicetta', 'knit', 'intimo', 'underwear', 'costume', 'swimsuit', 'bikini', 'trench', 'gilet', 'vest', 'pigiama', 'pyjama']
          }
        };
        
        // Genere della parola chiave (con regex word-boundary per evitare match errato "man" dentro "woman")
        const KW_WOMAN = ['woman', 'women', 'ladies', 'donna', 'donne', 'female', 'femme', 'mujer', 'femminile'];
        const KW_MAN = ['man', 'men', 'uomo', 'uomini', 'male', 'homme', 'hombre', 'maschile'];
        const KW_UNISEX = ['unisex', 'bambino', 'bambini', 'kid', 'kids', 'child', 'children', 'junior', 'baby'];
        
        funzione wordMatch(testo, kw) {
          // Matcher case-insensitive con word boundary: non matcha "man" dentro "woman"
          const re = new RegExp('(^|[^a-zàèéìòù])' + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^a-zàèéìòù]|$)', 'i');
          restituisci re.test(testo);
        }
        
        funzione rilevaCategoria(testo_ricerca) {
          se (!searchText) restituisce null;
          // Check più specifico per primo (ordine categorie è già dal più specifico)
          per (costante [chiave, cfg] di Object.entries(CATEGORIE)) {
            per (costante kw di cfg.keywords) {
              se (parolaCorrispondenza(testoricercato, kw)) restituisce la chiave;
            }
          }
          restituisci null;
        }
        
        funzione rilevaGenere(testo_ricerca) {
          se (!searchText) restituisce null;
          // Priorità: donna PRIMA di uomo (altrimenti "borse da donna" matcha "uomo")
          // Il confine della parola evita la corrispondenza della sottostringa
          // 1) Controllo donna (con limite di parola)
          const isW = KW_WOMAN.some(kw => wordMatch(searchText, kw));
          se (isW) restituisce 'donna'; // se c'è donna/donna, è donna (anche se appare anche man da qualche parte)
          // 2) Controllo dell'uomo
          const isM = KW_MAN.some(kw => wordMatch(searchText, kw));
          se (isM) restituisci 'uomo';
          // 3) Controllo unisex/bambini
          per (costante kw di KW_UNISEX) se (parolaMatch(testoricercato, kw)) restituisci 'unisex';
          restituisci null;
        }
        
        funzione isDuoProduct(prodotto) {
          // DUO: se lo SKU della prima variante matcha il pattern èDuoSku
          const firstVariantSku = (product.variants && product.variants[0]) ? product.variants[0].sku : null;
          se (firstVariantSku && isDuoSku(firstVariantSku)) restituisce vero;
          // Oppure se ha un tag DUO esplicito
          const tags = (product.tags || '').toLowerCase();
          se (tags.includes('tlx_product:duo') || tags.includes('duo')) restituisce true;
          restituire falso;
        }
        
        // ============ CLASSIFICAZIONE ============
        const snapshot = {
          tutto: { borsa: {}, scarpe: {}, accessori: {}, abbigliamento: {} },
          proprio: { borsa: {}, scarpe: {}, accessori: {}, abbigliamento: {} },
          duo: { borsa: {}, scarpe: {}, accessori: {}, abbigliamento: {} }
        };
        
        // Inizializzazione struttura
        per (gruppo costante di ['tutto', 'proprio', 'duo']) {
          per (const cat di ['borsa', 'scarpe', 'accessori', 'abbigliamento']) {
            snapshot[gruppo][gatto] = {
              donna: { prodotti: 0, pezzi: 0 },
              uomo: { prodotti: 0, pezzi: 0 },
              unisex: { prodotti: 0, pezzi: 0 }
            };
          }
        }
        
        const nonClassificati = { prodotti: 0, pezzi: 0, product_types_orfani: {}, sample_orfani: [] };
        poniamo totPezzi = 0, totProdotti = 0, totDuoProdotti = 0, totDuoPezzi = 0;
        
        prodotti.perogni(p => {
          se (p.status !== 'active') restituisci;
          
          const qty = (p.variants || []).reduce((s, v) => s + Math.max(0, parseInt(v.inventory_quantity) || 0), 0);
          if (qtà <= 0) ritorno; // Esclude qty = 0 (come da requisito utente)
          
          totProdotti++;
          totPezzi += qty;
          
          const isDuo = isDuoProduct(p);
          se (isDuo) { totDuoProdotti++; totDuoPezzi += qty; }
          
          // Cerca categoria e gender in product_type + tags + title
          const searchText = [p.product_type || '', p.tags || '', p.title || ''].join(' ');
          const cat = detectCategoria(searchText);
          const gender = detectGender(searchText) || 'unisex'; // fallback unisex
          
          se (!gatto) {
            nonClassificati.prodotti++;
            nonClassificati.pezzi += qty;
            const pt = (p.product_type || '(vuoto)').trim();
            nonClassificati.product_types_orfani[pt] = (nonClassificati.product_types_orfani[pt] || 0) + 1;
            if (nonClassificati.sample_orfani.length < 10) {
              nonClassificati.sample_orfani.push({ id: p.id, title: p.title, product_type: p.product_type, tags: p.tags, stock: qty });
            }
            ritorno;
          }
          
          // Aggrega in tutto/own/duo
          snapshot.tutto[cat][gender].prodotti++;
          snapshot.tutto[cat][gender].pezzi += qtà;
          
          se (èDuo) {
            snapshot.duo[cat][gender].prodotti++;
            snapshot.duo[cat][gender].pezzi += qty;
          } altro {
            snapshot.own[cat][gender].prodotti++;
            snapshot.own[cat][gender].pezzi += qty;
          }
        });
        
        // Converti sample orfani nell'array ordinato
        nonClassificati.product_types_orfani = Object.entries(nonClassificati.product_types_orfani)
          .sort((a, b) => b[1] - a[1])
          .map(([pt, count]) => ({ product_type: pt, count }));
        
        restituisci res.json({
          successo: vero,
          generated_at: new Date().toISOString(),
          dalla_cache_discovery: !forceRefresh && discoveryData && discoveryData.cached_at ? true : false,
          cached_at: discoveryData?.cached_at || null,
          totale_prodotti_attivi_con_stock: totProdotti,
          totale_pezzi: totPezzi,
          duo_prodotti: totDuoProdotti,
          duo_pezzi: totDuoPezzi,
          propri_prodotti: totProdotti - totDuoProdotti,
          proprio_pezzi: totPezzi - totDuoPezzi,
          istantanea,
          non_classificati: nonClassificati
        });
      } catch (e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }

    if (req.method === 'GET' && percorso === '/api/debug-winkelstraat') {
      Tentativo {
        const periodo = query.get('periodo') || 'month';
        const ordini = attendono getShopifyOrders(periodo);
        const winkelstraatOrders = [];
        const fallbackDefaultOrders = []; // ordini che non hanno matchato e finiscono in TLUXY_SITE (candidati mancati?)
        ordini.forEach(o => {
          const match = isWinkelstraatOrder(o);
          const mp = riconosciMarketplace(o);
          const email = (o.email || o.customer?.email || '').toLowerCase();
          const ship = o.shipping_address || {};
          const info = {
            numero_ordine: o.order_number,
            nome: o.name,
            creato_al: o.creato_al,
            nome_fonte: o.source_name,
            e-mail,
            tag: o.tags,
            nota: o.nota,
            indirizzo_spedizione1: indirizzo_spedizione1,
            compagnia_di_spedizione: compagnia_di_spedizione,
            shipping_name: [ship.first_name, ship.last_name].filter(Boolean).join(' '),
            marketplace_assegnato: mp.config.nome,
            winkelstraat_match: match // null oppure il campo che ha matchato
          };
          if (corrispondenza) winkelstraatOrders.push(info);
          altrimenti se (mp.key === 'TLUXY_SITE') fallbackDefaultOrders.push(info);
        });
        restituisci res.json({
          successo: vero,
          periodo,
          totale_ordini: ordini.lunghezza,
          winkelstraat_riconosciuti: winkelstraatOrders.length,
          ordini_winkelstraat: winkelstraatOrdini,
          ordini_tluxy_site_campione: fallbackDefaultOrders.slice(0, 20) // per capire se qualcuno è sfuggito
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // Diagnostica di autenticazione
    se (req.method === 'GET' && path === '/api/auth-status') {
      restituisci res.json({
        auth_enabled: AUT_ENABLED,
        auth_type: 'magic_link_resend',
        reinvia_configurato: !!CHIAVE_API_INVIA,
        mail_from: MAIL_FROM,
        numero_di_email_consentite: ALLOWED_EMAILS.length,
        giorni_sessione: GIORNI_SESSIONE_AUTORIZZAZIONE,
        magic_link_minutes: MAGIC_LINK_MINUTES,
        autenticato: !!authUser,
        user_email: authUser?.email || null
      });
    }

    se (req.method === 'GET' && path === '/api/kv-status') {
      const envVarsDetected = {
        KV_REST_API_URL: !!process.env.KV_REST_API_URL,
        KV_REST_API_TOKEN: !!process.env.KV_REST_API_TOKEN,
        UPSTASH_REDIS_REST_URL: !!process.env.UPSTASH_REDIS_REST_URL,
        UPSTASH_REDIS_REST_TOKEN: !!process.env.UPSTASH_REDIS_REST_TOKEN,
        KV_REDIS_URL: !!process.env.KV_REDIS_URL,
        REDIS_URL: !!process.env.REDIS_URL
      };
      se (!KV_ENABLED) {
        restituisci res.json({
          kv_enabled: false,
          kv_source: null,
          env_vars_detected: envVarsDetected,
          messaggio: 'Nessuna credenziale KV trovata. Verifica che Vercel abbia creato le env vars.'
        });
      }
      Tentativo {
        const testKey = '_ _kv_test__';
        const testVal = String(Date.now());
        const writeOk = await kvSet(testKey, testVal);
        const read = await kvGet(testKey);
        restituisci res.json({
          kv_enabled: true,
          kv_source: KV_SOURCE,
          kv_url_host: KV_REST_API_URL.replace(/^https?:\/\//, '').split('/')[0],
          env_vars_detected: envVarsDetected,
          write_ok: !!writeOk,
          read_ok: read === testVal,
          valore_letto: letto
        });
      } catch (error) { return res.json({ kv_enabled: true, kv_source: KV_SOURCE, error: error.message }); }
    }

    // Diagnostica: verifica perché un ordine specifico potrebbe mancare dall'analytics
    // Usa: /api/debug-order?name=13027 oppure /api/debug-order?id=5783212343468
    se (req.method === 'GET' && path === '/api/debug-order') {
      Tentativo {
        const orderName = query.get('name');
        const orderId = query.get('id');
        if (!orderName && !orderId) return res.status(400).json({ success: false, error: 'Passa ?name=13027 oppure ?id=5783212343468' });
        const token = await getShopifyAccessToken();
        const diag = { checks: {}, warnings: [], orderFound: null };
        
        // Step 1: cerca l'ordine su Shopify (by name o by id)
        lascia ordine = null;
        se (orderId) {
          const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders/${orderId}.json`;
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          diag.checks.fetch_by_id = { url, status: r.status };
          if (r.ok) { const d = await r.json(); ordine = d.order; }
        } altro {
          // Cerca per nome (serve scorrere gli ordini recenti)
          const cleaned = String(orderName).replace('#', '').trim();
          const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&name=%23${cleaned}&limit=10`;
          const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
          diag.checks.fetch_by_name = { url, status: r.status };
          se (r.ok) {
            const d = await r.json();
            ordine = (d.orders || []).find(o => String(o.order_number) === cleaned || o.name === '#' + cleaned || o.name === cleaned);
            se (!ordine && (d.orders || []).length > 0) ordine = d.orders[0];
          }
        }
        
        se (!ordine) {
          diag.checks.exists_on_shopify = false;
          diag.warnings.push('Ordine NON trovato su Shopify. Controlla il numero esatto.');
          restituisci res.json({ success: true, diagnostica: diag });
        }
        
        diag.checks.exists_on_shopify = true;
        diag.orderFound = {
          id: ordine.id,
          numero_ordine: numero_ordine,
          nome: ordine.name,
          creato_al: ordine.creato_al,
          aggiornato_alle: ordine.aggiornato_alle,
          stato_finanziario: ordine stato_finanziario,
          stato_di_adempimento: ordine.stato_di_adempimento,
          canceled_at: ordinecancelled_at,
          prezzo_totale: ordine.prezzo_totale,
          valuta: ordinecurrency,
          nome_fonte: ordine.nome_fonte,
          tag: ordine.tags,
          email_cliente: ordine.cliente?.email,
          paese_spedizione: ordine.indirizzo_spedizione?.codice_paese,
          line_items_count: (ordine.line_items || []).length,
          numero_rimborsi: (ordine.rimborsi || []).lunghezza
        };
        
        // Passo 2: verifica stato (cancellato?)
        if (ordine.cancelled_at) diag.warnings.push('Ordine CANCELLATO il ' + ordine.cancelled_at);
        
        // Passo 3: verifica periodo "mese" (che probabilmente è quello selezionato nella dashboard)
        const now = new Date();
        const romeOffset = new Date().toLocaleString('en-US', { timeZone: 'Europe/Rome' });
        const monthStart = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0);
        const createdAt = new Date(ordine.created_at);
        const inMeseCorrente = createdAt >= monthStart;
        diag.checks.created_at = ordine.created_at;
        diag.checks.mese_corrente_start = monthStart.toISOString();
        diag.checks.dentro_mese_corrente = inMeseCorrente;
        if (!inMeseCorrente) diag.warnings.push('Ordine NON dentro il mese corrente (periodo=mese). Created ' + ordine.created_at);
        
        // Passaggio 4: verifica il marketplace
        const mp = riconosciMarketplace(ordine);
        diag.checks.marketplace_riconosciuto = { chiave: mp.key, nome: mp.config.nome };
        if (mp.key === 'TLUXY_SITE' && ordine.source_name && !['web', 'pos', 'shopify_draft_order'].includes(ordine.source_name)) {
          diag.warnings.push('⚠️ Marketplace defaultato a TLUXY_SITE ma source_name è "' + ordine.source_name + '". Controllare mappatura.');
        }
        
        // Passo 5: verifica il rimborso (totale?)
        const refundInfo = getOrderRefundInfo(ordine);
        diag.checks.refund_info = refundInfo;
        if (refundInfo.isFullRefund) diag.warnings.push('Ordine con RIMBORSO TOTALE → escluso dai conteggi analytics.');
        
        // Passo 6: verifica costi merce (errore?)
        const variantIds = [...new Set((ordine.line_items || []).map(li => li.variant_id).filter(Boolean))];
        const productIds = [...new Set((ordine.line_items || []).map(li => li.product_id).filter(Boolean))];
        const { costi: variantCosts } = await fetchVariantCosts(variantIds, productIds);
        const duoUserCosts = {};
        se (KV_ENABLED) {
          const duoVids = (ordine.line_items || []).filter(li => isDuoSku(li.sku)).map(li => li.variant_id).filter(Boolean);
          se (duoVids.length) {
            const keys = duoVids.map(v => `duo_user_cost_${v}`);
            const risultati = await kvMGet(chiavi);
            duoVids.forEach(v => {
              const key = `duo_user_cost_${v}`;
              se (risultati[chiave] !== indefinito) {
                const parsed = parseFloat(results[key]);
                se (!isNaN(parsed)) duoUserCosts[v] = parsed;
              }
            });
          }
        }
        const { costo, errori } = calcolaCostoOrdine(ordine, variableCosts, duoUserCosts);
        diag.checks.costo_totale_calcolato = costo;
        diag.checks.errori_costi = errori;
        if (errori.length > 0) diag.warnings.push('⚠️ Errori costi: ' + errori.length + ' varianti senza costo → ordine va in "Ordini con errori"');
        
        // Passaggio 7: verifica che fetchShopifyOrders lo includerebbe (periodo=mese)
        const ordiniPeriodo = await getShopifyOrders('month');
        const trovatoNelPeriodo = (ordiniPeriodo || []).some(o => String(o.id) === String(ordine.id));
        diag.checks.trovato_in_getShopifyOrders_month = trovatoNelPeriodo;
        diag.checks.totale_ordini_fetchati_mese = (ordiniPeriodo || []).length;
        if (!trovatoNelPeriodo) diag.warnings.push('❌ CRITICO: getShopifyOrders(month) NON include questo ordine. Controllare filtri create_at_min/max.');
        
        // Riepilogo finale
        diag.verdict = errori.length > 0 ? 'ESCLUSO per costi mancanti (visibile in "Ordini con errori")'
          : (refundInfo.isFullRefund ? 'ESCLUSO per rimborso totale'
          : (!trovatoNelPeriodo ? 'NON FETCHATO nel periodo selezionato'
          : (ordine.cancelled_at ? 'CANCELLATO' : 'DOVREBBE ESSERE INCLUSO nei conteggi')));
        
        restituisci res.json({ success: true, diagnostica: diag });
      } catch (error) { return res.status(500).json({ success: false, error: error.message, stack: error.stack }); }
    }

    se (req.method === 'GET' && path === '/api/debug-single-cost') {
      Tentativo {
        const variantId = query.get('variant_id') || '47254190325972';
        const token = await getShopifyAccessToken();
        const v1url = `https://${SHOPIFY_STORE}/admin/api/2024-01/variants/${variantId}.json`;
        const v1res = await fetch(v1url, { headers: { 'X-Shopify-Access-Token': token } });
        const v1body = await v1res.text();
        lascia inventoryItemId = null, v1parsed = null;
        try { v1parsed = JSON.parse(v1body); inventoryItemId = v1parsed?.variant?.inventory_item_id; } catch(e) {}
        lascia che step2 sia nullo;
        se (inventoryItemId) {
          const i1url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items/${inventoryItemId}.json`;
          const i1res = await fetch(i1url, { headers: { 'X-Shopify-Access-Token': token } });
          const i1body = await i1res.text();
          let i1parsed = null; try { i1parsed = JSON.parse(i1body); } catch(e) {}
          step2 = { url: i1url, status: i1res.status, response: i1parsed || i1body.substring(0, 500) };
        }
        lascia che step3 sia nullo;
        se (inventoryItemId) {
          const i2url = `https://${SHOPIFY_STORE}/admin/api/2024-01/inventory_items.json?ids=${inventoryItemId}`;
          const i2res = await fetch(i2url, { headers: { 'X-Shopify-Access-Token': token } });
          const i2body = await i2res.text();
          let i2parsed = null; try { i2parsed = JSON.parse(i2body); } catch(e) {}
          step3 = { url: i2url, status: i2res.status, response: i2parsed || i2body.substring(0, 500) };
        }
        restituisci res.json({
          successo: vero,
          variante_id_testato: varianteId,
          step1_variant: { url: v1url, status: v1res.status, response: v1parsed || v1body.substring(0, 500) },
          inventory_item_id_Intro: inventoryItemId,
          step2_inventory_item_singolo: passaggio2,
          step3_inventory_items_con_ids: step3
        });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    se (req.method === 'GET' && path === '/api/test-shopify') {
      Tentativo {
        const token = await getShopifyAccessToken();
        const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/shop.json`, { headers: { 'X-Shopify-Access-Token': token } });
        se (!response.ok) genera un nuovo Errore(`HTTP ${response.status}`);
        const data = await response.json();
        return res.json({ success: true, shop_name: data.shop.name, message: 'Shopify connesso' });
      } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
    }

    // ============ ASSISTENTE CHAT AI (v5.10) ============
    se (req.method === 'GET' && path === '/api/chat-status') {
      const apiKey = process.env.ANTHROPIC_API_KEY || '';
      restituisci res.json({
        abilitato: !!apiKey,
        configurato: !!apiKey,
        modello: 'claude-haiku-4-5',
        cost_per_msg: '€0,005-0,02 per messaggio',
        configure_hint: apiKey ? null : 'Aggiungi env var ANTHROPIC_API_KEY su Vercel (chiave da console.anthropic.com)'
      });
    }
    
    se (req.method === 'POST' && path === '/api/chat') {
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) return res.status(503).json({ success: false, error: 'ANTHROPIC_API_KEY non configurabile. Aggiungi su Vercel → Impostazioni → Variabili d'ambiente.' });
      Tentativo {
        lascia corpo = '';
        await new Promise((resolve, reject) => { req.on('data', c => body += c); req.on('end', resolve); req.on('error', reject); });
        const data = JSON.parse(body || '{}');
        const userMessages = data.messages || [];
        if (userMessages.length === 0) return res.status(400).json({ success: false, error: ' Nessun messaggio' });
        
        // Prompt del sistema: dice a Claude che è l'assistente del tuo ERP
        const systemPrompt = `Sei l'assistente AI di T. Luxy ERP, una dashboard di Business Intelligence per un negozio di lusso off-price gestito da Alessio. Hai accesso a strumenti per leggere dati Shopify in tempo reale: ordini, marginalità, marketplace, inventario, previsioni incassi.

Marketplace manager: Miinto, The Bradery, Italist, Secret Sales, Fashion Tamers, Intra Mirror, Balardi, Boutique Mall, Archivist, Winkelstraat, Jammy Dude, Poizon, Brandsgateway, T. Luxy sito proprio, Mark Foy, GIGLIO.COM.

Requisiti:
- Rispondi sempre in italiano
- Quando ti chiedono dati specifici (fatturato, ordini, ecc.), usa lo strumento per leggere i dati REALI, non inventarli
- Sii conciso: rispondi al punto, evita preamboli
- Usa formattazione markdown leggero (**bold** per evidenziare numeri chiave)
- Se non puoi rispondere a una domanda, dillo onestamente
- Per il contesto: oggi è ${new Date().toLocaleDateString('it-IT')}, fuso orario Europa/Roma`;
        
        // Definizioni degli strumenti: gli endpoint del nostro ERP esposti come strumenti per Claude
        strumenti const = [
          {
            nome: 'get_analytics',
            descrizione: 'Ottieni analytics completi (fatturato, IVA, margine, breakdown per marketplace, errori) per un periodo. Utilizzalo per domande su KPI, fatturato, marginalità, MP migliori/peggiori.',
            schema_di_input: {
              tipo: 'oggetto',
              proprietà: {
                periodo: { type: 'string', enum: ['today', 'yesterday', 'week', 'month', 'quarter', 'year'], description: 'Periodo di analisi' }
              },
              richiesto: ['punto']
            }
          },
          {
            nome: 'get_bestsellers',
            descrizione: 'Ottieni i top 20 prodotti più venduti per fatturato in un periodo.',
            schema_di_input: {
              tipo: 'oggetto',
              proprietà: {
                periodo: { tipo: 'stringa', enum: ['oggi', 'settimana', 'mese', 'trimestre', 'anno'] }
              },
              richiesto: ['punto']
            }
          },
          {
            nome: 'get_forecast',
            descrizione: 'Ottieni le previsioni di incasso (bonifici futuri da marketplace) per i prossimi 2 mesi, con scadenziario per MP.',
            input_schema: { type: 'object', properties: {} }
          },
          {
            nome: 'get_inventory',
            descrizione: "Ottieni snapshot dell'inventario corrente: prodotti per categoria (bag/shoes/accessori/clothing) × genere.",
            input_schema: { type: 'object', properties: {} }
          },
          {
            nome: 'get_marketplaces_config',
            descrizione: 'Ottieni la configurazione dei marketplace (commissioni, sconti, modalità pagamento).',
            input_schema: { type: 'object', properties: {} }
          }
        ];
        
        // Funzione che esegue uno strumento e restituisce il risultato
        funzione asincrona executeTool(toolName, toolInput) {
          const baseUrl = `https://${req.headers.host || 'erp-marginalita-last.vercel.app'}`;
          const cookie = req.headers.cookie || '';
          const headers = cookie ? { 'Cookie': cookie } : {};
          Tentativo {
            lascia url;
            interruttore (nomestrumento) {
              caso 'get_analytics':
                url = `${baseUrl}/api/analytics?periodo=${encodeURIComponent(toolInput.periodo)}`;
                rottura;
              caso 'get_bestsellers':
                url = `${baseUrl}/api/bestsellers?periodo=${encodeURIComponent(toolInput.periodo)}`;
                rottura;
              caso 'get_forecast':
                url = `${baseUrl}/api/forecast`;
                rottura;
              caso 'get_inventory':
                url = `${baseUrl}/api/inventory`;
                rottura;
              caso 'get_marketplaces_config':
                url = `${baseUrl}/api/marketplaces`;
                rottura;
              predefinito:
                restituisci { errore: 'Strumento sconosciuto: ' + toolName };
            }
            const r = await fetch(url, { headers });
            const d = await r.json();
            // Comprime l'output per non saturare il contesto (rimuove campi inutili)
            se (toolName === 'get_analytics' && d.success) {
              ritorno {
                periodo: d.periodo,
                ordini_totali: d.ordini_totali,
                lordo_iva_inclusa: Math.round(d.lordo_iva_inclusa),
                iva_totale: Math.round(d.iva_totale),
                costi_merce: Math.round(d.costi_merce_totali || 0),
                costi_commissioni: Math.round(d.costi_commissioni_totale || 0),
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
            se (toolName === 'get_bestsellers' && d.success) {
              return { totale: d.totale_prodotti_unici, prodotti: (d.prodotti || []).slice(0, 10).map(p => ({ titolo: p.titolo, sku: p.sku, fatturato: Math.round(p.fatturato_lordo), pezzi: p.quantita_venduta, ricavo: Math.round(p.ricavo_stimato) })) };
            }
            se (toolName === 'get_forecast' && d.success) {
              ritorno {
                kpi: d.kpi,
                scomposizione: (d.breakdown_marketplace || []).slice(0, 10).map(mp => ({
                  nome: mp.nome,
                  prossimo_bonifico: mp.prossimo_bonifico,
                  importo_totale: Math.round(mp.importo_totale)
                })),
                balardi_residuo: d.balardi_wallet ? Math.round(d.balardi_wallet.credito_residuo * 100) / 100 : null
              };
            }
            se (toolName === 'get_inventory' && d.success) {
              ritorno {
                totale_prodotti: d.totale_prodotti_attivi_con_stock,
                totale_pezzi: d.totale_pezzi,
                duo: { prodotti: d.duo_prodotti, pezzi: d.duo_pezzi },
                proprio: { prodotti: d.own_prodotti, pezzi: d.own_pezzi },
                istantanea: d.snapshot.tutto,
                non_classificati: d.non_classificati ? { prodotti: d.non_classificati.prodotti, pezzi: d.non_classificati.pezzi } : null
              };
            }
            se (toolName === 'get_marketplaces_config') {
              return { marketplace: Object.entries(d.marketplace_disponibili || {}).map(([k, mp]) => ({ key: k, nome: mp.nome, sconto: mp.sconto_percentuale, fee_principale: mp.fee_principale, fee_secondaria: mp.fee_secondaria || 0, sped: mp.fee_fissa_trasporto, pack: mp.fee_fissa_packaging, pagamento: mp.pagamento })) };
            }
            restituisci d;
          } catch(e) { return { error: e.message }; }
        }
        
        // Chiama Claude API con chiamata loop tool (max 10 iterazioni)
        const claudeMessages = userMessages.map(m => ({ role: m.role, content: m.content }));
        lascia finalReply = '';
        sia l'iterazione = 0;
        const MAX_ITERATIONS = 8;
        
        mentre (iterazione < MAX_ITERATIONS) {
          iterazione++;
          const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
            metodo: 'POST',
            intestazioni: {
              'Content-Type': 'application/json',
              'x-api-key': apiKey,
              'anthropic-version': '2023-06-01'
            },
            corpo: JSON.stringify({
              modello: 'claude-haiku-4-5-20251001',
              max_tokens: 2048,
              sistema: systemPrompt,
              utensili,
              messaggi: claudeMessages
            })
          });
          
          se (!claudeRes.ok) {
            const errBody = await claudeRes.text();
            return res.status(500).json({ success: false, error: `Errore API Claude ${claudeRes.status}: ${errBody.substring(0, 300)}` });
          }
          
          const claudeData = await claudeRes.json();
          
          // Aggiunge la risposta dell'assistente all'history
          claudeMessages.push({ ruolo: 'assistente', contenuto: claudeData.content });
          
          // Se è un tool_use, esegui e itera
          const toolUses = (claudeData.content || []).filter(b => b.type === 'tool_use');
          se (toolUses.length > 0 e claudeData.stop_reason === 'tool_use') {
            const toolResults = [];
            per (const toolUse di toolUses) {
              const risultato = await executeTool(toolUse.name, toolUse.input);
              toolResults.push({
                tipo: 'risultato_strumento',
                tool_use_id: toolUse.id,
                contenuto: JSON.stringify(risultato).substring(0, 8000) // limita il contesto
              });
            }
            claudeMessages.push({ role: 'user', content: toolResults });
            continuare;
          }
          
          // Altrimenti raccogli risposta testuale finale
          const textBlocks = (claudeData.content || []).filter(b => b.type === 'text');
          finalReply = textBlocks.map(b => b.text).join('\n');
          rottura;
        }
        
        if (!finalReply) finalReply = '⚠️ Non sono riuscito a completare la richiesta dopo ' + MAX_ITERAZIONI + ' iterazioni.';
        
        restituisci res.json({ success: true, reply: finalReply, iterations: iteration });
      } catch(e) { return res.status(500).json({ success: false, error: e.message, stack: e.stack }); }
    }
    
    se (req.method === 'GET' && path === '/api/marketplaces') {
      return res.json({ marketplace_disponibili: MARKETPLACE_CONFIGS, source_name_map: SOURCE_NAME_MAP, iva_per_paese: IVA_PER_PAESE });
    }

    restituisci res.status(404).json({ error: 'Endpoint non trovato' });
  } catch (error) { return res.status(500).json({ error: 'Errore interno', dettagli: error.message }); }
}
