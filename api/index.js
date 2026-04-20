// ERP Marginalità v5.4 - Winkelstraat detection via email/shipping/tag/copernicus

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'autore-luxit.myshopify.com';
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || '';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || '';

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

const MARKETPLACE_CONFIGS = {
  'SECRET_SALES': { nome: 'Secret Sales', sconto_percentuale: 0, fee_principale: 20, fee_secondaria: 0, fee_fissa_trasporto: 2, fee_fissa_packaging: 2, pagamento: 'Variabile' },
  'FASHION_TAMERS': { nome: 'Fashion Tamers', sconto_percentuale: 0, fee_principale: 32, fee_secondaria: 2, fee_fissa_trasporto: 15, fee_fissa_packaging: 6, pagamento: 'Variabile' },
  'INTRA_MIRROR': { nome: 'Intra Mirror', sconto_percentuale: 15, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Variabile' },
  'BALARDI': { nome: 'Balardi', sconto_percentuale: 35, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3, pagamento: 'Variabile' },
  'THE_BRADERY': { nome: 'The Bradery', sconto_percentuale: 5, fee_principale: 17, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 2, pagamento: 'Variabile' },
  'BOUTIQUE_MALL': { nome: 'Boutique Mall', sconto_percentuale: 33.3, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Variabile' },
  'ARCHIVIST': { nome: 'Archivist', sconto_percentuale: 0, fee_principale: 22, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2, pagamento: 'Variabile' },
  'MIINTO': { nome: 'Miinto', sconto_percentuale: 0, fee_principale: 17.75, fee_secondaria: 2.25, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5, pagamento: 'Variabile' },
  'WINKELSTRAAT': { nome: 'Winkelstraat', sconto_percentuale: 0, fee_principale: 17, fee_secondaria: 0, fee_accessoria: 9, fee_fissa_trasporto: 15, fee_fissa_packaging: 0, pagamento: 'Variabile' },
  'ITALIST': { nome: 'Italist', sconto_percentuale: 0, fee_principale: 20, fee_secondaria: 25.5, fee_fissa_trasporto: 0, fee_fissa_packaging: 4, pagamento: 'Mensile (~30gg)' },
  'JAMMY_DUDE': { nome: 'Jammy Dude', sconto_percentuale: 0, fee_principale: 19, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Variabile' },
  'POIZON': { nome: 'Poizon', sconto_percentuale: 0, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 0, pagamento: 'Variabile' },
  'BRANDSGATEWAY': { nome: 'Brandsgateway', sconto_percentuale: 13, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 0, pagamento: 'Variabile' },
  'TLUXY_SITE': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato' }
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
        <p>Business Intelligence Dashboard · v5.4</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill"><div class="status-dot"></div>Sistema Live</div>
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
        return '<tr><td><strong>' + orderNumFmt + '</strong>' + currencyBadge + '</td><td>' + dataFmt + '</td><td>' + (o.country || '—') + '</td><td style="max-width:340px;">' + articoli + '</td><td class="num">€' + o.fatturato.toFixed(2) + '</td><td class="num">€' + o.iva.toFixed(2) + '</td><td class="num">€' + o.costo_merce.toFixed(2) + '</td><td class="num">€' + o.fees_marketplace.toFixed(2) + '</td><td class="num ' + marginCls2 + '">€' + o.margine_netto.toFixed(2) + '</td><td class="num ' + marginCls2 + '">' + o.margine_percentuale.toFixed(1) + '%</td></tr>';
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

document.addEventListener('DOMContentLoaded', () => {
  loadMarketplaces();
  const today = new Date(); const monthAgo = new Date(); monthAgo.setMonth(monthAgo.getMonth() - 1);
  const fmt = d => d.toISOString().split('T')[0];
  ['date-from', 'bs-date-from'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(monthAgo); });
  ['date-to', 'bs-date-to'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(today); });
  document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => {
    showTab(btn.dataset.tab);
    if (btn.dataset.tab === 'duo') { checkKvStatus(); if (duoProducts.length === 0) loadDuoProducts(); }
  }));
  document.querySelectorAll('[data-analytics-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => setPeriod(btn.dataset.period, btn)));
  document.querySelectorAll('[data-bs-periods] .period-btn').forEach(btn => btn.addEventListener('click', () => loadBestSellers(btn.dataset.period, btn)));
  document.getElementById('analytics-apply').addEventListener('click', applyCustomRange);
  document.getElementById('bs-apply').addEventListener('click', applyBsCustomRange);
  ['c-prezzo', 'c-iva', 'c-costo', 'c-spedizione'].forEach(id => { const el = document.getElementById(id); if (el) { el.addEventListener('input', confronta); if (el.tagName === 'SELECT') el.addEventListener('change', confronta); } });
  document.getElementById('calcola-btn').addEventListener('click', calcola);
  // DUO listeners
  document.getElementById('duo-reload').addEventListener('click', loadDuoProducts);
  document.getElementById('duo-csv-file').addEventListener('change', e => { if (e.target.files[0]) handleCsvImport(e.target.files[0]); });
  document.getElementById('duo-search').addEventListener('input', filterDuoProducts);
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
    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      return res.json({ sistema: 'T. Luxy ERP — Marginalità v5.4', status: 'LIVE', store: SHOPIFY_STORE, credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET), kv_enabled: KV_ENABLED, kv_source: KV_SOURCE, funzionalita: ['Winkelstraat detection (email/shipping/tag/copernicus)', 'Conversione valuta automatica (shop_money)', 'Fix regex parseCSV', 'KV multi-format detection', 'KV storage costi persistenti', 'Simulatore DUO con CSV import', 'Breakdown MP espandibile', 'Brandsgateway via tag', 'Products/{id}.json strategy', 'Fuso Roma reale', 'Poizon + Secret Sales', 'Filtro JD'], marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length, endpoints: ['/', '/api', '/api/analytics', '/api/bestsellers', '/api/duo-products', '/api/duo-costs-import', '/api/duo-cost-set', '/api/kv-status', '/api/test-shopify', '/api/marketplaces', '/api/debug-orders', '/api/debug-jd', '/api/debug-winkelstraat', '/api/debug-costs', '/api/debug-single-cost'] });
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
        const breakdown_marketplace = {};
        const ordini_con_errori = [];
        const ordini_valuta_estera = []; // Tracciamento ordini convertiti
        ordini.forEach(ordine => {
          const { costo: costo_merce, errori } = calcolaCostoOrdine(ordine, variantCosts, duoUserCosts);
          const mp = riconosciMarketplace(ordine);
          const currencyInfo = getOrderCurrencyInfo(ordine);
          if (errori.length > 0) {
            ordini_con_errori.push({ id: ordine.id, order_number: ordine.order_number, name: ordine.name, total_price: ordine.total_price, total_price_eur: currencyInfo.eurTotal, currency: currencyInfo.originalCurrency, marketplace: mp.config.nome, prodotti_senza_costo: errori });
            return;
          }
          // USA SEMPRE IL PREZZO IN EUR (convertito da Shopify al cambio del giorno)
          const prezzo_lordo = currencyInfo.eurTotal;
          // Spedizione: usa shop_money se disponibile
          const spedizione = (ordine.shipping_lines || []).reduce((sum, line) => {
            return sum + toEurAmount(line.price_set, line.price, currencyInfo.originalCurrency);
          }, 0);
          const country = ordine.shipping_address?.country_code || ordine.billing_address?.country_code;
          // Poizon usa sempre IVA IT
          const ivaPerc = mp.key === 'POIZON' ? 22 : getIvaPerPaese(country);
          // Tax: converti in EUR
          const shopifyTaxEur = toEurAmount(ordine.total_tax_set, ordine.total_tax, currencyInfo.originalCurrency);
          const iva_scorporata = shopifyTaxEur > 0 ? shopifyTaxEur : (prezzo_lordo - prezzo_lordo / (1 + ivaPerc / 100));
          const ris = calcolaMarginalita(prezzo_lordo, iva_scorporata, costo_merce, spedizione, mp.config, mp.key);
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
          
          if (!breakdown_marketplace[mp.key]) breakdown_marketplace[mp.key] = { nome: mp.config.nome, ordini: 0, fatturato: 0, iva: 0, costo_merce: 0, margine: 0, dettaglio_ordini: [] };
          breakdown_marketplace[mp.key].ordini += 1;
          breakdown_marketplace[mp.key].fatturato += ris.prezzo_lordo_iva_inclusa;
          breakdown_marketplace[mp.key].iva += ris.iva_scorporata;
          breakdown_marketplace[mp.key].costo_merce += costo_merce;
          breakdown_marketplace[mp.key].margine += ris.margine_netto;
          // Dettaglio ordine per drill-down
          breakdown_marketplace[mp.key].dettaglio_ordini.push({
            order_number: ordine.order_number,
            name: ordine.name,
            created_at: ordine.created_at,
            country,
            fatturato: ris.prezzo_lordo_iva_inclusa,
            iva: ris.iva_scorporata,
            costo_merce,
            fees_marketplace: ris.fees_marketplace,
            fees_shopify: ris.fees_shopify,
            spedizione,
            margine_netto: ris.margine_netto,
            margine_percentuale: ris.margine_percentuale,
            // Info valuta
            currency: currencyInfo.originalCurrency,
            is_foreign_currency: currencyInfo.isForeign,
            total_original: currencyInfo.originalTotal,
            exchange_rate: currencyInfo.exchangeRate,
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
        const ordini_validi = ordini.length - ordini_con_errori.length;
        const margine_percentuale = lordo_iva_inclusa > 0 ? (margine_netto / lordo_iva_inclusa * 100) : 0;
        return res.json({ success: true, periodo: from && to ? `${from} → ${to}` : periodo, ordini_totali: ordini_validi, ordini_con_errori_count: ordini_con_errori.length, ordini_con_errori, lordo_iva_inclusa, iva_totale, costi_totali, margine_netto, margine_percentuale, breakdown_marketplace, ordini_valuta_estera, fetch_stats: fetchStats, ultima_sincronizzazione: new Date().toISOString() });
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
