// ERP Marginalità v3.4 - Italist + Filtro Custom + Century Gothic

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'autore-luxit.myshopify.com';
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || '';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || '';

let cachedToken = null;
let tokenExpiry = null;

async function getShopifyAccessToken() {
  if (cachedToken && tokenExpiry && Date.now() < tokenExpiry) return cachedToken;
  if (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET) throw new Error('Missing credentials');
  const response = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: SHOPIFY_CLIENT_ID, client_secret: SHOPIFY_CLIENT_SECRET, grant_type: 'client_credentials' })
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
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
  'TLUXY_SITE': { nome: 'T. Luxy (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1, pagamento: 'Immediato' }
};

const SOURCE_NAME_MAP = {
  'web': 'TLUXY_SITE', 'pos': 'TLUXY_SITE', 'shopify_draft_order': 'TLUXY_SITE',
  'miinto': 'MIINTO', 'miinto-app': 'MIINTO',
  'secret-sales': 'SECRET_SALES', 'secretsales': 'SECRET_SALES',
  'fashion-tamers': 'FASHION_TAMERS', 'fashiontamers': 'FASHION_TAMERS',
  'intra-mirror': 'INTRA_MIRROR', 'intramirror': 'INTRA_MIRROR',
  'balardi': 'BALARDI',
  'the-bradery': 'THE_BRADERY', 'thebradery': 'THE_BRADERY', 'bradery': 'THE_BRADERY',
  'boutique-mall': 'BOUTIQUE_MALL', 'boutiquemall': 'BOUTIQUE_MALL',
  'archivist': 'ARCHIVIST', 'winkelstraat': 'WINKELSTRAAT',
  'italist': 'ITALIST', 'italist-app': 'ITALIST'
};

function riconosciMarketplace(ordine) {
  const sourceName = (ordine.source_name || '').toLowerCase().trim();
  if (SOURCE_NAME_MAP[sourceName]) return { key: SOURCE_NAME_MAP[sourceName], config: MARKETPLACE_CONFIGS[SOURCE_NAME_MAP[sourceName]] };
  for (const [pattern, mpKey] of Object.entries(SOURCE_NAME_MAP)) {
    if (sourceName.includes(pattern) || pattern.includes(sourceName)) return { key: mpKey, config: MARKETPLACE_CONFIGS[mpKey] };
  }
  const tags = (ordine.tags || '').toLowerCase();
  for (const [pattern, mpKey] of Object.entries(SOURCE_NAME_MAP)) {
    if (tags.includes(pattern)) return { key: mpKey, config: MARKETPLACE_CONFIGS[mpKey] };
  }
  const defaultKey = process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE';
  return { key: defaultKey, config: MARKETPLACE_CONFIGS[defaultKey] };
}

function calcolaMarginalita(prezzo_lordo, total_tax, costo_merce, spedizione, mp) {
  const prezzo_netto_iva = prezzo_lordo - total_tax;
  const prezzo_netto_marketplace = prezzo_netto_iva * (1 - mp.sconto_percentuale / 100);
  const fees_shopify = prezzo_netto_marketplace * 0.029 + 0.30;
  const fee_principale = prezzo_netto_marketplace * (mp.fee_principale / 100);
  const fee_secondaria = prezzo_netto_marketplace * ((mp.fee_secondaria || 0) / 100);
  const fee_accessoria = prezzo_netto_marketplace * ((mp.fee_accessoria || 0) / 100);
  const fees_marketplace = fee_principale + fee_secondaria + fee_accessoria + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine_netto = prezzo_netto_marketplace - fees_shopify - fees_marketplace - costo_merce - spedizione;
  const margine_percentuale = prezzo_lordo > 0 ? (margine_netto / prezzo_lordo * 100) : 0;
  const costi_totali = costo_merce + spedizione + fees_shopify + fees_marketplace + total_tax;
  return { prezzo_lordo_iva_inclusa: prezzo_lordo, iva_scorporata: total_tax, prezzo_netto_iva, prezzo_netto_marketplace, fees_shopify, fees_marketplace, costo_merce, spedizione, costi_totali, margine_netto, margine_percentuale: parseFloat(margine_percentuale.toFixed(2)) };
}

async function getShopifyOrders(periodo = 'today', dateFromCustom = null, dateToCustom = null) {
  const token = await getShopifyAccessToken();
  let dateFrom, dateTo;
  
  if (dateFromCustom && dateToCustom) {
    dateFrom = new Date(dateFromCustom);
    dateFrom.setHours(0, 0, 0, 0);
    dateTo = new Date(dateToCustom);
    dateTo.setHours(23, 59, 59, 999);
  } else {
    dateFrom = new Date();
    dateTo = new Date();
    switch(periodo) {
      case 'today': dateFrom.setHours(0, 0, 0, 0); break;
      case 'yesterday': dateFrom.setDate(dateFrom.getDate() - 1); dateFrom.setHours(0, 0, 0, 0); dateTo.setDate(dateTo.getDate() - 1); dateTo.setHours(23, 59, 59, 999); break;
      case 'week': dateFrom.setDate(dateFrom.getDate() - 7); break;
      case 'month': dateFrom.setDate(dateFrom.getDate() - 30); break;
      case 'quarter': dateFrom.setDate(dateFrom.getDate() - 90); break;
      case 'year': dateFrom.setDate(dateFrom.getDate() - 365); break;
    }
  }
  
  const url = `https://${SHOPIFY_STORE}/admin/api/2024-01/orders.json?status=any&created_at_min=${dateFrom.toISOString()}&created_at_max=${dateTo.toISOString()}&limit=250`;
  const response = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  return data.orders || [];
}

function calcolaBestSellers(ordini, top = 20) {
  const prodotti = {};
  ordini.forEach(ordine => {
    const total_tax = parseFloat(ordine.total_tax) || 0;
    const total_price = parseFloat(ordine.total_price) || 0;
    const fattore_iva = total_price > 0 ? (total_price - total_tax) / total_price : 1;
    (ordine.line_items || []).forEach(item => {
      const productId = item.product_id || item.variant_id || item.title;
      const prezzo_unit_lordo = parseFloat(item.price) || 0;
      const quantity = parseInt(item.quantity) || 0;
      const prezzo_unit_netto = prezzo_unit_lordo * fattore_iva;
      const fatturato_lordo = prezzo_unit_lordo * quantity;
      const fatturato_netto = prezzo_unit_netto * quantity;
      const costo_stimato = prezzo_unit_netto * 0.4 * quantity;
      const ricavo_stimato = fatturato_netto - costo_stimato;
      if (!prodotti[productId]) {
        prodotti[productId] = { product_id: item.product_id, variant_id: item.variant_id, titolo: item.title, variante: item.variant_title || '', sku: item.sku || '', vendor: item.vendor || '', prezzo_unit_lordo, prezzo_unit_netto, quantita_venduta: 0, fatturato_lordo: 0, fatturato_netto: 0, ricavo_stimato: 0, immagine: null };
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
    const response = await fetch(
      `https://${SHOPIFY_STORE}/admin/api/2024-01/products.json?ids=${productIds}&fields=id,image,images`,
      { headers: { 'X-Shopify-Access-Token': token } }
    );
    if (!response.ok) return prodotti;
    const data = await response.json();
    const imageMap = {};
    (data.products || []).forEach(p => { imageMap[p.id] = p.image?.src || (p.images?.[0]?.src) || null; });
    return prodotti.map(p => ({ ...p, immagine: imageMap[p.product_id] || null }));
  } catch (e) {
    return prodotti;
  }
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>T. Luxy ERP — Dashboard Marginalità</title>
<style>
  :root {
    --green-primary: #008060;
    --green-dark: #004C3F;
    --green-light: #E8F4F0;
    --gold: #C9A961;
    --gold-light: #F4ECD8;
    --beige: #F4F1EB;
    --cream: #FAFAF7;
    --black: #1A1A1A;
    --gray-900: #2D2D2D;
    --gray-700: #5C5C5C;
    --gray-500: #8E8E8E;
    --gray-300: #D4D4D4;
    --gray-200: #E8E8E8;
    --gray-100: #F2F2F0;
    --white: #FFFFFF;
    --red: #BF4747;
    --red-light: #FCEEEE;
    --shadow-sm: 0 1px 2px rgba(26,26,26,0.04);
    --shadow-md: 0 4px 12px rgba(26,26,26,0.06);
    --shadow-lg: 0 12px 32px rgba(26,26,26,0.08);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 20px;
    --font-main: 'Century Gothic', 'CenturyGothic', 'AppleGothic', Futura, 'Trebuchet MS', sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { 
    font-family: var(--font-main);
    background: var(--beige);
    min-height: 100vh; 
    color: var(--black);
    -webkit-font-smoothing: antialiased;
    line-height: 1.5;
    letter-spacing: 0.01em;
  }
  .container { max-width: 1440px; margin: 0 auto; padding: 24px; }

  /* HEADER */
  .header { 
    background: var(--white); 
    border-radius: var(--radius-lg); 
    padding: 32px 40px;
    margin-bottom: 24px;
    box-shadow: var(--shadow-md);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 20px;
    border: 1px solid var(--gray-100);
  }
  .header-left { display: flex; align-items: center; gap: 28px; }
  .logo {
    font-family: var(--font-main);
    font-weight: 700;
    font-size: 2.6rem;
    color: var(--black);
    letter-spacing: 0.02em;
    line-height: 1;
    text-transform: uppercase;
  }
  .logo .dot { color: var(--gold); }
  .header-divider { width: 1px; height: 52px; background: var(--gray-200); }
  .header-info h1 { 
    font-size: 1.05rem; 
    font-weight: 700; 
    color: var(--gray-900); 
    margin-bottom: 3px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .header-info p { font-size: 0.8rem; color: var(--gray-500); letter-spacing: 0.03em; }
  .header-right { display: flex; align-items: center; gap: 16px; }
  .status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 8px 16px;
    background: var(--green-light);
    color: var(--green-dark);
    border-radius: 50px;
    font-size: 0.75rem;
    font-weight: 700;
    border: 1px solid rgba(0,128,96,0.15);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .status-dot {
    width: 7px; height: 7px;
    background: var(--green-primary);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* TABS */
  .tabs-wrap { background: var(--white); border-radius: var(--radius-lg); padding: 8px; margin-bottom: 24px; box-shadow: var(--shadow-sm); border: 1px solid var(--gray-100); }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tab { 
    flex: 1; min-width: 130px;
    padding: 14px 20px; 
    border: none; background: transparent; 
    border-radius: var(--radius-md); 
    cursor: pointer; 
    font-family: var(--font-main);
    font-weight: 700; 
    font-size: 0.82rem; 
    color: var(--gray-700);
    transition: all 0.25s ease;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .tab:hover { background: var(--gray-100); color: var(--black); }
  .tab.active { background: var(--black); color: var(--white); }
  .tab-content { display: none; animation: fade 0.4s ease; }
  .tab-content.active { display: block; }
  @keyframes fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

  /* SECTIONS */
  .section { 
    background: var(--white); 
    border-radius: var(--radius-lg); 
    padding: 36px; 
    margin-bottom: 24px; 
    box-shadow: var(--shadow-sm);
    border: 1px solid var(--gray-100);
  }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; flex-wrap: wrap; gap: 16px; }
  .section-title { 
    font-family: var(--font-main);
    font-size: 1.6rem; 
    font-weight: 700; 
    color: var(--black); 
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  .section-subtitle { font-size: 0.85rem; color: var(--gray-500); margin-top: 6px; letter-spacing: 0.02em; }

  /* INFO BOXES */
  .info-box { 
    background: var(--green-light); 
    border-left: 3px solid var(--green-primary); 
    padding: 14px 20px; 
    border-radius: var(--radius-sm); 
    margin-bottom: 24px; 
    font-size: 0.85rem; 
    color: var(--green-dark);
  }
  .warn-box { 
    background: var(--gold-light); 
    border-left: 3px solid var(--gold); 
    padding: 14px 20px; 
    border-radius: var(--radius-sm); 
    margin-bottom: 24px; 
    font-size: 0.85rem; 
    color: #6B5320;
  }

  /* PERIOD SELECTOR */
  .filter-bar { 
    display: flex; 
    align-items: center; 
    gap: 16px; 
    margin-bottom: 28px; 
    flex-wrap: wrap;
  }
  .period-selector { 
    display: flex; gap: 6px;
    background: var(--gray-100);
    padding: 6px;
    border-radius: 50px;
    flex-wrap: wrap;
  }
  .period-btn { 
    padding: 10px 22px; 
    border: none; 
    background: transparent; 
    border-radius: 50px; 
    cursor: pointer; 
    font-family: var(--font-main);
    font-weight: 700; 
    font-size: 0.78rem; 
    color: var(--gray-700);
    transition: all 0.2s ease;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .period-btn:hover { color: var(--black); }
  .period-btn.active { background: var(--white); color: var(--black); box-shadow: var(--shadow-sm); }
  .custom-range {
    display: flex; align-items: center; gap: 8px;
    background: var(--white);
    border: 1.5px solid var(--gray-200);
    border-radius: 50px;
    padding: 6px 8px 6px 18px;
  }
  .custom-range label { font-size: 0.72rem; font-weight: 700; color: var(--gray-500); text-transform: uppercase; letter-spacing: 0.06em; }
  .custom-range input[type="date"] {
    border: none; background: transparent;
    font-family: var(--font-main);
    font-size: 0.85rem; color: var(--black);
    padding: 6px 8px; cursor: pointer;
  }
  .custom-range input[type="date"]:focus { outline: none; }
  .custom-range .apply-btn {
    background: var(--black); color: var(--white);
    border: none; padding: 8px 18px;
    border-radius: 50px;
    font-family: var(--font-main);
    font-size: 0.72rem; font-weight: 700;
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    transition: background 0.2s;
  }
  .custom-range .apply-btn:hover { background: var(--green-dark); }

  /* KPI CARDS */
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
  .kpi { 
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-md); 
    padding: 24px;
    transition: all 0.25s ease;
    position: relative;
    overflow: hidden;
  }
  .kpi:hover { border-color: var(--gray-300); transform: translateY(-2px); box-shadow: var(--shadow-md); }
  .kpi.primary { background: var(--black); color: var(--white); border-color: var(--black); }
  .kpi.primary .kpi-label { color: rgba(255,255,255,0.7); }
  .kpi.primary .kpi-sub { color: rgba(255,255,255,0.5); }
  .kpi.green { background: var(--green-primary); color: var(--white); border-color: var(--green-primary); }
  .kpi.green .kpi-label { color: rgba(255,255,255,0.85); }
  .kpi.green .kpi-sub { color: rgba(255,255,255,0.65); }
  .kpi.gold { background: var(--gold-light); border-color: var(--gold); }
  .kpi-label { 
    font-size: 0.7rem; 
    text-transform: uppercase; 
    letter-spacing: 0.1em; 
    font-weight: 700; 
    color: var(--gray-500);
    margin-bottom: 14px;
  }
  .kpi-value { 
    font-family: var(--font-main);
    font-size: 1.9rem; 
    font-weight: 700;
    line-height: 1.1;
    margin-bottom: 6px;
    letter-spacing: 0.01em;
  }
  .kpi-sub { font-size: 0.74rem; color: var(--gray-500); letter-spacing: 0.04em; }

  /* FORMS */
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; }
  .form-group { display: flex; flex-direction: column; gap: 8px; }
  .form-group label { font-weight: 700; color: var(--black); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; }
  .form-group input, .form-group select { 
    padding: 13px 16px; 
    border: 1.5px solid var(--gray-200); 
    border-radius: var(--radius-md); 
    font-size: 0.95rem; 
    font-family: var(--font-main);
    background: var(--white);
    color: var(--black);
    transition: all 0.2s ease;
  }
  .form-group input:focus, .form-group select:focus { 
    outline: none; 
    border-color: var(--green-primary); 
    box-shadow: 0 0 0 3px rgba(0,128,96,0.1); 
  }
  .btn-primary { 
    background: var(--black); 
    color: var(--white); 
    border: none; 
    padding: 16px 32px; 
    border-radius: var(--radius-md); 
    font-size: 0.85rem; 
    font-family: var(--font-main);
    font-weight: 700; 
    cursor: pointer; 
    width: 100%; 
    margin-top: 20px; 
    transition: all 0.2s ease;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .btn-primary:hover { background: var(--green-dark); transform: translateY(-1px); box-shadow: var(--shadow-md); }

  /* RESULTS */
  .results { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-top: 28px; }
  .result-card { 
    background: var(--gray-100); 
    border-radius: var(--radius-md); 
    padding: 18px; 
    border: 1.5px solid transparent;
    transition: all 0.2s ease;
  }
  .result-card.positive { background: var(--green-light); border-color: var(--green-primary); }
  .result-card.negative { background: var(--red-light); border-color: var(--red); }
  .result-label { font-size: 0.68rem; color: var(--gray-500); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 8px; }
  .result-value { font-family: var(--font-main); font-size: 1.25rem; font-weight: 700; color: var(--black); letter-spacing: 0.01em; }

  /* MARKETPLACE GRID */
  .mp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
  .mp-card { 
    background: var(--white);
    border: 1.5px solid var(--gray-200); 
    border-radius: var(--radius-md); 
    padding: 24px; 
    cursor: pointer; 
    transition: all 0.25s ease;
  }
  .mp-card:hover { border-color: var(--green-primary); transform: translateY(-3px); box-shadow: var(--shadow-md); }
  .mp-name { font-family: var(--font-main); font-size: 1.1rem; font-weight: 700; color: var(--black); margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
  .mp-pay { font-size: 0.7rem; color: var(--gray-500); margin-bottom: 14px; letter-spacing: 0.04em; }
  .mp-fees { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem; color: var(--gray-700); }
  .mp-fees strong { color: var(--gray-500); font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 2px; font-weight: 700; }

  /* BEST SELLERS */
  .bs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; }
  .bs-card { 
    background: var(--white); 
    border: 1.5px solid var(--gray-200); 
    border-radius: var(--radius-md); 
    overflow: hidden; 
    transition: all 0.25s ease; 
    position: relative;
  }
  .bs-card:hover { border-color: var(--gold); transform: translateY(-4px); box-shadow: var(--shadow-lg); }
  .bs-rank { 
    position: absolute; top: 14px; left: 14px; 
    background: var(--black); 
    color: var(--white); 
    width: 36px; height: 36px; 
    border-radius: 50%; 
    display: flex; align-items: center; justify-content: center; 
    font-weight: 700; font-size: 0.95rem; 
    z-index: 2;
    box-shadow: 0 4px 12px rgba(26,26,26,0.3);
  }
  .bs-rank.top3 { background: var(--gold); color: var(--black); }
  .bs-image { width: 100%; height: 220px; background: var(--gray-100); display: flex; align-items: center; justify-content: center; overflow: hidden; }
  .bs-image img { width: 100%; height: 100%; object-fit: cover; }
  .bs-image-placeholder { color: var(--gray-300); font-size: 3rem; }
  .bs-body { padding: 20px; }
  .bs-title { 
    font-family: var(--font-main);
    font-weight: 700; color: var(--black); 
    font-size: 1rem; margin-bottom: 4px; 
    line-height: 1.3; 
    display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
    letter-spacing: 0.01em;
    text-transform: uppercase;
  }
  .bs-variant { font-size: 0.74rem; color: var(--gray-500); margin-bottom: 14px; letter-spacing: 0.03em; }
  .bs-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .bs-stat { padding: 10px 12px; background: var(--gray-100); border-radius: var(--radius-sm); }
  .bs-stat-label { font-size: 0.6rem; color: var(--gray-500); text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 4px; }
  .bs-stat-value { font-weight: 700; color: var(--black); font-size: 0.9rem; }
  .bs-stat.fatturato { background: var(--gold-light); }
  .bs-stat.ricavo { background: var(--green-light); color: var(--green-dark); }
  .bs-stat.ricavo .bs-stat-value { color: var(--green-dark); }
  .bs-empty { text-align: center; padding: 80px 20px; color: var(--gray-500); font-style: italic; grid-column: 1 / -1; }

  /* COMPARE */
  .confronto-form { background: var(--cream); padding: 24px; border-radius: var(--radius-md); margin-bottom: 24px; border: 1px solid var(--gray-200); }
  .table-wrap { overflow-x: auto; border-radius: var(--radius-md); border: 1px solid var(--gray-200); }
  .compare-table { width: 100%; border-collapse: collapse; background: var(--white); }
  .compare-table thead { background: var(--black); color: var(--white); }
  .compare-table th { 
    padding: 16px 14px; 
    text-align: left; 
    font-size: 0.68rem; 
    text-transform: uppercase; 
    letter-spacing: 0.1em; 
    font-weight: 700; 
    white-space: nowrap;
  }
  .compare-table td { padding: 16px 14px; border-bottom: 1px solid var(--gray-100); font-size: 0.88rem; color: var(--gray-900); }
  .compare-table tbody tr { transition: background 0.15s ease; }
  .compare-table tbody tr:hover { background: var(--cream); }
  .compare-table tr.best { background: var(--green-light); }
  .compare-table tr.best td:first-child { border-left: 3px solid var(--green-primary); font-weight: 700; }
  .compare-table tr.best:hover { background: #DDF0E8; }
  .compare-table tr.worst { background: var(--red-light); }
  .compare-table tr.worst td:first-child { border-left: 3px solid var(--red); }
  .compare-table tr.worst:hover { background: #FAE0E0; }
  .mp-pill { 
    display: inline-block; 
    padding: 3px 10px; 
    border-radius: 20px; 
    font-size: 0.62rem; 
    font-weight: 700; 
    margin-left: 8px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
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

  @media (max-width: 768px) { 
    .container { padding: 16px; }
    .header { padding: 24px; }
    .logo { font-size: 1.9rem; }
    .section { padding: 24px; }
    .tabs { flex-direction: column; }
    .tab { min-width: auto; }
    .header-divider { display: none; }
    .kpi-value { font-size: 1.5rem; }
    .filter-bar { flex-direction: column; align-items: stretch; }
    .custom-range { flex-wrap: wrap; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <div class="logo">T<span class="dot">.</span> LUXY</div>
      <div class="header-divider"></div>
      <div class="header-info">
        <h1>ERP Marginalità</h1>
        <p>Business Intelligence Dashboard · v3.4</p>
      </div>
    </div>
    <div class="header-right">
      <div class="status-pill">
        <div class="status-dot"></div>
        Sistema Live
      </div>
    </div>
  </div>

  <!-- TABS -->
  <div class="tabs-wrap">
    <div class="tabs">
      <button class="tab active" onclick="showTab('analytics', event)">Analytics</button>
      <button class="tab" onclick="showTab('bestsellers', event)">Best Seller</button>
      <button class="tab" onclick="showTab('compare', event)">Confronto MP</button>
      <button class="tab" onclick="showTab('calculator', event)">Calcolatore</button>
      <button class="tab" onclick="showTab('marketplaces', event)">Marketplace</button>
    </div>
  </div>

  <!-- ANALYTICS -->
  <div id="analytics-tab" class="tab-content active">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Performance</div>
          <div class="section-subtitle">Analisi vendite e marginalità in tempo reale</div>
        </div>
      </div>
      <div class="info-box">I valori netti sono calcolati scorporando l'IVA effettiva di ogni ordine, gestita da Shopify in base al paese del cliente.</div>
      <div class="filter-bar">
        <div class="period-selector">
          <button class="period-btn active" onclick="setPeriod('today', event)">Oggi</button>
          <button class="period-btn" onclick="setPeriod('yesterday', event)">Ieri</button>
          <button class="period-btn" onclick="setPeriod('week', event)">Settimana</button>
          <button class="period-btn" onclick="setPeriod('month', event)">Mese</button>
          <button class="period-btn" onclick="setPeriod('quarter', event)">Trimestre</button>
          <button class="period-btn" onclick="setPeriod('year', event)">Anno</button>
        </div>
        <div class="custom-range">
          <label>Da</label>
          <input type="date" id="date-from">
          <label>A</label>
          <input type="date" id="date-to">
          <button class="apply-btn" onclick="applyCustomRange()">Applica</button>
        </div>
      </div>
      <div class="kpi-grid">
        <div class="kpi primary">
          <div class="kpi-label">Lordo IVA inclusa</div>
          <div class="kpi-value" id="lordo">€15.240</div>
          <div class="kpi-sub">Vendite totali</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">IVA Scorporata</div>
          <div class="kpi-value" id="iva">€2.748</div>
          <div class="kpi-sub">Da versare</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Costi Totali</div>
          <div class="kpi-value" id="costi">€8.432</div>
          <div class="kpi-sub">Merce + Fees + IVA</div>
        </div>
        <div class="kpi green">
          <div class="kpi-label">Margine Netto</div>
          <div class="kpi-value" id="netto">€4.060</div>
          <div class="kpi-sub">Profitto reale</div>
        </div>
        <div class="kpi gold">
          <div class="kpi-label">Margine %</div>
          <div class="kpi-value" id="margine">26.6%</div>
          <div class="kpi-sub">Su lordo</div>
        </div>
      </div>
    </div>
  </div>

  <!-- BEST SELLERS -->
  <div id="bestsellers-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Best Seller</div>
          <div class="section-subtitle">Top 20 prodotti più venduti per fatturato</div>
        </div>
      </div>
      <div class="info-box">Foto, prezzo unitario e ricavo stimato per i prodotti più venduti nel periodo selezionato.</div>
      <div class="filter-bar">
        <div class="period-selector">
          <button class="period-btn" onclick="loadBestSellers('today', event)">Oggi</button>
          <button class="period-btn" onclick="loadBestSellers('week', event)">Settimana</button>
          <button class="period-btn active" onclick="loadBestSellers('month', event)">Mese</button>
          <button class="period-btn" onclick="loadBestSellers('quarter', event)">Trimestre</button>
          <button class="period-btn" onclick="loadBestSellers('year', event)">Anno</button>
        </div>
        <div class="custom-range">
          <label>Da</label>
          <input type="date" id="bs-date-from">
          <label>A</label>
          <input type="date" id="bs-date-to">
          <button class="apply-btn" onclick="applyBsCustomRange()">Applica</button>
        </div>
      </div>
      <div id="bs-content" class="bs-grid">
        <div class="bs-empty">Caricamento prodotti...</div>
      </div>
    </div>
  </div>

  <!-- CONFRONTO -->
  <div id="compare-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Confronto Marketplace</div>
          <div class="section-subtitle">Margine effettivo a parità di prezzo, costo e spedizione</div>
        </div>
      </div>
      <div class="info-box">Modifica i valori per vedere il confronto aggiornato in tempo reale su tutti i marketplace.</div>
      <div class="confronto-form">
        <div class="form-grid">
          <div class="form-group"><label>Prezzo IVA inclusa (€)</label><input type="number" id="c-prezzo" value="100" step="0.01" oninput="confronta()"></div>
          <div class="form-group"><label>Paese / IVA</label><select id="c-iva" onchange="confronta()">
            <option value="22">🇮🇹 Italia (22%)</option>
            <option value="20">🇫🇷 Francia (20%)</option>
            <option value="19">🇩🇪 Germania (19%)</option>
            <option value="21">🇪🇸 Spagna (21%)</option>
            <option value="21">🇳🇱 Olanda (21%)</option>
            <option value="21">🇧🇪 Belgio (21%)</option>
            <option value="20">🇦🇹 Austria (20%)</option>
            <option value="23">🇮🇪 Irlanda (23%)</option>
            <option value="20">🇬🇧 Regno Unito (20%)</option>
            <option value="0">🇺🇸 USA / Extra-UE (0%)</option>
          </select></div>
          <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="c-costo" value="45" step="0.01" oninput="confronta()"></div>
          <div class="form-group"><label>Spedizione (€)</label><input type="number" id="c-spedizione" value="5" step="0.01" oninput="confronta()"></div>
        </div>
      </div>
      <div class="table-wrap">
        <table class="compare-table" id="compare-table">
          <thead>
            <tr>
              <th>Marketplace</th>
              <th>Sconto</th>
              <th>Prezzo Netto</th>
              <th>Fees Shopify</th>
              <th>Fees MP</th>
              <th>Margine €</th>
              <th>Margine %</th>
              <th>Esito</th>
            </tr>
          </thead>
          <tbody id="compare-body"></tbody>
        </table>
      </div>
      <div class="compare-summary" id="compare-summary"></div>
    </div>
  </div>

  <!-- CALCOLATORE -->
  <div id="calculator-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Calcolatore</div>
          <div class="section-subtitle">Simulatore marginalità per singolo marketplace</div>
        </div>
      </div>
      <div class="info-box">Inserisci il prezzo IVA inclusa e l'aliquota IVA del paese di vendita. Il sistema scorpora automaticamente.</div>
      <div class="form-grid">
        <div class="form-group"><label>Prezzo Vendita IVA inclusa (€)</label><input type="number" id="prezzo" value="100" step="0.01"></div>
        <div class="form-group"><label>Paese / IVA</label><select id="iva-select">
          <option value="22">🇮🇹 Italia (22%)</option>
          <option value="20">🇫🇷 Francia (20%)</option>
          <option value="19">🇩🇪 Germania (19%)</option>
          <option value="21">🇪🇸 Spagna (21%)</option>
          <option value="21">🇳🇱 Olanda (21%)</option>
          <option value="21">🇧🇪 Belgio (21%)</option>
          <option value="20">🇦🇹 Austria (20%)</option>
          <option value="23">🇮🇪 Irlanda (23%)</option>
          <option value="20">🇬🇧 Regno Unito (20%)</option>
          <option value="0">🇺🇸 USA / Extra-UE (0%)</option>
        </select></div>
        <div class="form-group"><label>Costo Merce (€)</label><input type="number" id="costo" value="45" step="0.01"></div>
        <div class="form-group"><label>Spedizione (€)</label><input type="number" id="spedizione" value="5" step="0.01"></div>
        <div class="form-group"><label>Marketplace</label><select id="mp-select"></select></div>
      </div>
      <button class="btn-primary" onclick="calcola()">Calcola Marginalità</button>
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

  <!-- MARKETPLACES -->
  <div id="marketplaces-tab" class="tab-content">
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">Portfolio Marketplace</div>
          <div class="section-subtitle">Configurazioni e commissioni di tutti i canali di vendita</div>
        </div>
      </div>
      <div class="warn-box">Riconoscimento automatico via <code>source_name</code> di Shopify. Verificabile con <code>/api/debug-orders</code>.</div>
      <div class="mp-grid" id="mp-grid"></div>
    </div>
  </div>

</div>
<script>
const MARKETPLACES = ${JSON.stringify(MARKETPLACE_CONFIGS)};
const PERIODS_DEMO = {
  today: { lordo: 15240, iva: 2748, costi: 8432, netto: 4060, margine: 26.6 },
  yesterday: { lordo: 12890, iva: 2324, costi: 7016, netto: 3550, margine: 27.5 },
  week: { lordo: 89350, iva: 16110, costi: 48670, netto: 24570, margine: 27.5 },
  month: { lordo: 342180, iva: 61688, costi: 187242, netto: 93250, margine: 27.2 },
  quarter: { lordo: 1024680, iva: 184731, costi: 558559, netto: 281390, margine: 27.5 },
  year: { lordo: 4128500, iva: 743130, costi: 2249340, netto: 1136030, margine: 27.5 }
};
const BS_DEMO = [
  { rank: 1, titolo: 'Sneakers Premium Bianche', variante: 'Taglia 42', sku: 'SNK-001', prezzo_unit_lordo: 189, quantita_venduta: 24, fatturato_lordo: 4536, ricavo_stimato: 1240, immagine: null },
  { rank: 2, titolo: 'Borsa in Pelle Nera', variante: 'Standard', sku: 'BAG-022', prezzo_unit_lordo: 320, quantita_venduta: 12, fatturato_lordo: 3840, ricavo_stimato: 980, immagine: null },
  { rank: 3, titolo: 'Trench Beige Premium', variante: 'M', sku: 'GCK-088', prezzo_unit_lordo: 245, quantita_venduta: 14, fatturato_lordo: 3430, ricavo_stimato: 870, immagine: null },
  { rank: 4, titolo: 'Camicia Bianca Classica', variante: 'L', sku: 'CMC-101', prezzo_unit_lordo: 89, quantita_venduta: 32, fatturato_lordo: 2848, ricavo_stimato: 690, immagine: null },
  { rank: 5, titolo: 'Pantaloni Chino Slim', variante: '32x32', sku: 'PNT-045', prezzo_unit_lordo: 110, quantita_venduta: 22, fatturato_lordo: 2420, ricavo_stimato: 580, immagine: null }
];

function showTab(name, ev) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  ev.target.classList.add('active');
  if (name === 'compare' && !document.getElementById('compare-body').children.length) confronta();
  if (name === 'bestsellers' && document.getElementById('bs-content').querySelector('.bs-empty')) loadBestSellers('month', { target: document.querySelectorAll('#bestsellers-tab .period-btn')[2] });
}

async function fetchAnalytics(url) {
  try {
    const res = await fetch(url);
    const data = await res.json();
    if (data.success) {
      document.getElementById('lordo').textContent = '€' + Math.round(data.lordo_iva_inclusa).toLocaleString('it-IT');
      document.getElementById('iva').textContent = '€' + Math.round(data.iva_totale).toLocaleString('it-IT');
      document.getElementById('costi').textContent = '€' + Math.round(data.costi_totali).toLocaleString('it-IT');
      document.getElementById('netto').textContent = '€' + Math.round(data.margine_netto).toLocaleString('it-IT');
      document.getElementById('margine').textContent = data.margine_percentuale.toFixed(1) + '%';
      return true;
    }
  } catch(e) {}
  return false;
}

async function setPeriod(p, ev) {
  document.querySelectorAll('#analytics-tab .period-btn').forEach(b => b.classList.remove('active'));
  if (ev) ev.target.classList.add('active');
  const ok = await fetchAnalytics('/api/analytics?periodo=' + p);
  if (!ok) {
    const d = PERIODS_DEMO[p] || PERIODS_DEMO.today;
    document.getElementById('lordo').textContent = '€' + d.lordo.toLocaleString('it-IT');
    document.getElementById('iva').textContent = '€' + d.iva.toLocaleString('it-IT');
    document.getElementById('costi').textContent = '€' + d.costi.toLocaleString('it-IT');
    document.getElementById('netto').textContent = '€' + d.netto.toLocaleString('it-IT');
    document.getElementById('margine').textContent = d.margine + '%';
  }
}

async function applyCustomRange() {
  const from = document.getElementById('date-from').value;
  const to = document.getElementById('date-to').value;
  if (!from || !to) { alert('Seleziona data Da e A'); return; }
  if (from > to) { alert('La data "Da" deve essere precedente alla data "A"'); return; }
  document.querySelectorAll('#analytics-tab .period-btn').forEach(b => b.classList.remove('active'));
  await fetchAnalytics('/api/analytics?from=' + from + '&to=' + to);
}

async function loadBestSellers(p, ev) {
  document.querySelectorAll('#bestsellers-tab .period-btn').forEach(b => b.classList.remove('active'));
  if (ev) ev.target.classList.add('active');
  const cont = document.getElementById('bs-content');
  cont.innerHTML = '<div class="bs-empty">Caricamento prodotti...</div>';
  try {
    const res = await fetch('/api/bestsellers?periodo=' + p);
    const data = await res.json();
    if (data.success && data.prodotti.length > 0) {
      renderBestSellers(data.prodotti);
      return;
    }
  } catch(e) {}
  renderBestSellers(BS_DEMO);
}

async function applyBsCustomRange() {
  const from = document.getElementById('bs-date-from').value;
  const to = document.getElementById('bs-date-to').value;
  if (!from || !to) { alert('Seleziona data Da e A'); return; }
  if (from > to) { alert('La data "Da" deve essere precedente alla data "A"'); return; }
  document.querySelectorAll('#bestsellers-tab .period-btn').forEach(b => b.classList.remove('active'));
  const cont = document.getElementById('bs-content');
  cont.innerHTML = '<div class="bs-empty">Caricamento prodotti...</div>';
  try {
    const res = await fetch('/api/bestsellers?from=' + from + '&to=' + to);
    const data = await res.json();
    if (data.success && data.prodotti.length > 0) {
      renderBestSellers(data.prodotti);
      return;
    }
  } catch(e) {}
  renderBestSellers(BS_DEMO);
}

function renderBestSellers(prodotti) {
  const cont = document.getElementById('bs-content');
  if (!prodotti || prodotti.length === 0) {
    cont.innerHTML = '<div class="bs-empty">Nessun prodotto trovato in questo periodo.</div>';
    return;
  }
  cont.innerHTML = prodotti.map((p, i) => {
    const rank = p.rank || (i + 1);
    const rankClass = rank <= 3 ? 'top3' : '';
    const img = p.immagine 
      ? '<img src="' + p.immagine + '" alt="' + p.titolo + '" loading="lazy">'
      : '<div class="bs-image-placeholder">◇</div>';
    return '<div class="bs-card">' +
      '<div class="bs-rank ' + rankClass + '">' + rank + '</div>' +
      '<div class="bs-image">' + img + '</div>' +
      '<div class="bs-body">' +
        '<div class="bs-title">' + p.titolo + '</div>' +
        '<div class="bs-variant">' + (p.variante || '') + (p.sku ? ' · ' + p.sku : '') + '</div>' +
        '<div class="bs-stats">' +
          '<div class="bs-stat"><div class="bs-stat-label">Prezzo</div><div class="bs-stat-value">€' + p.prezzo_unit_lordo.toFixed(2) + '</div></div>' +
          '<div class="bs-stat"><div class="bs-stat-label">Pezzi</div><div class="bs-stat-value">' + p.quantita_venduta + '</div></div>' +
          '<div class="bs-stat fatturato"><div class="bs-stat-label">Fatturato</div><div class="bs-stat-value">€' + Math.round(p.fatturato_lordo).toLocaleString('it-IT') + '</div></div>' +
          '<div class="bs-stat ricavo"><div class="bs-stat-label">Ricavo stim.</div><div class="bs-stat-value">€' + Math.round(p.ricavo_stimato).toLocaleString('it-IT') + '</div></div>' +
        '</div>' +
      '</div>' +
    '</div>';
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
    const feesShop = prezzoNetto * 0.029 + 0.30;
    const feeP = prezzoNetto * (mp.fee_principale / 100);
    const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100);
    const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
    const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
    const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
    const margineP = prezzoLordo > 0 ? (margine / prezzoLordo * 100) : 0;
    return { key, nome: mp.nome, sconto: mp.sconto_percentuale, prezzoNetto, feesShop, feesMp, margine, margineP };
  });

  risultati.sort((a, b) => b.margine - a.margine);
  const best = risultati[0];
  const worst = risultati[risultati.length - 1];

  document.getElementById('compare-body').innerHTML = risultati.map((r, i) => {
    let cls = '';
    let pill = '';
    if (i === 0) { cls = 'best'; pill = '<span class="mp-pill win">Top</span>'; }
    if (i === risultati.length - 1) { cls = 'worst'; pill = '<span class="mp-pill lose">Last</span>'; }
    const numCls = r.margine >= 0 ? 'num-pos' : 'num-neg';
    const esito = r.margine >= 0 ? '✓' : '✕';
    return '<tr class="' + cls + '">' +
      '<td><strong>' + r.nome + '</strong>' + pill + '</td>' +
      '<td>' + r.sconto + '%</td>' +
      '<td>€' + r.prezzoNetto.toFixed(2) + '</td>' +
      '<td>€' + r.feesShop.toFixed(2) + '</td>' +
      '<td>€' + r.feesMp.toFixed(2) + '</td>' +
      '<td class="' + numCls + '">€' + r.margine.toFixed(2) + '</td>' +
      '<td class="' + numCls + '">' + r.margineP.toFixed(1) + '%</td>' +
      '<td style="font-size:1.1rem; font-weight:700; color:' + (r.margine >= 0 ? 'var(--green-primary)' : 'var(--red)') + '">' + esito + '</td>' +
    '</tr>';
  }).join('');

  const redditizi = risultati.filter(r => r.margine > 0).length;
  const inPerdita = risultati.filter(r => r.margine <= 0).length;

  document.getElementById('compare-summary').innerHTML = 
    '<div class="summary-card best-mp">' +
      '<div class="summary-label">Marketplace Migliore</div>' +
      '<div class="summary-value">' + best.nome + '</div>' +
      '<div class="summary-detail">€' + best.margine.toFixed(2) + ' (' + best.margineP.toFixed(1) + '%)</div>' +
    '</div>' +
    '<div class="summary-card worst-mp">' +
      '<div class="summary-label">Marketplace Peggiore</div>' +
      '<div class="summary-value">' + worst.nome + '</div>' +
      '<div class="summary-detail">€' + worst.margine.toFixed(2) + ' (' + worst.margineP.toFixed(1) + '%)</div>' +
    '</div>' +
    '<div class="summary-card info">' +
      '<div class="summary-label">Marketplace Redditizi</div>' +
      '<div class="summary-value">' + redditizi + ' su ' + risultati.length + '</div>' +
      '<div class="summary-detail">' + inPerdita + ' in perdita</div>' +
    '</div>';
}

function calcola() {
  const prezzoLordo = parseFloat(document.getElementById('prezzo').value) || 0;
  const ivaPerc = parseFloat(document.getElementById('iva-select').value) || 0;
  const costo = parseFloat(document.getElementById('costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('spedizione').value) || 0;
  const mp = MARKETPLACES[document.getElementById('mp-select').value];
  const prezzoNettoIva = prezzoLordo / (1 + ivaPerc / 100);
  const ivaScorporata = prezzoLordo - prezzoNettoIva;
  const prezzoNetto = prezzoNettoIva * (1 - mp.sconto_percentuale / 100);
  const feesShop = prezzoNetto * 0.029 + 0.30;
  const feeP = prezzoNetto * (mp.fee_principale / 100);
  const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100);
  const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
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
  const mc = document.getElementById('r-margine-card');
  const rc = document.getElementById('r-redd-card');
  const re = document.getElementById('r-redd');
  if (margine > 0) {
    mc.className = 'result-card positive';
    rc.className = 'result-card positive';
    re.textContent = '✓ Redditizio';
  } else {
    mc.className = 'result-card negative';
    rc.className = 'result-card negative';
    re.textContent = '✕ In Perdita';
  }
}

function loadMarketplaces() {
  const select = document.getElementById('mp-select');
  const grid = document.getElementById('mp-grid');
  Object.entries(MARKETPLACES).forEach(([key, mp]) => {
    const opt = document.createElement('option');
    opt.value = key;
    opt.textContent = mp.nome;
    select.appendChild(opt);
    const card = document.createElement('div');
    card.className = 'mp-card';
    card.onclick = () => { select.value = key; showTab('calculator', { target: document.querySelectorAll('.tab')[3] }); calcola(); };
    card.innerHTML = '<div class="mp-name">' + mp.nome + '</div>' +
      '<div class="mp-pay">Pagamento: ' + (mp.pagamento || 'N/D') + '</div>' +
      '<div class="mp-fees">' +
      '<div><strong>Sconto</strong>' + mp.sconto_percentuale + '%</div>' +
      '<div><strong>Fee Princ.</strong>' + mp.fee_principale + '%</div>' +
      '<div><strong>Fee Sec.</strong>' + (mp.fee_secondaria || 0) + '%</div>' +
      '<div><strong>Trasporto</strong>€' + (mp.fee_fissa_trasporto || 0) + '</div>' +
      '<div><strong>Packaging</strong>€' + (mp.fee_fissa_packaging || 0) + '</div>' +
      (mp.fee_accessoria ? '<div><strong>Fee Acc.</strong>' + mp.fee_accessoria + '%</div>' : '') +
    '</div>';
    grid.appendChild(card);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  loadMarketplaces();
  // Imposta date default ultimo mese
  const today = new Date();
  const monthAgo = new Date();
  monthAgo.setMonth(monthAgo.getMonth() - 1);
  const fmt = d => d.toISOString().split('T')[0];
  ['date-from', 'bs-date-from'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(monthAgo); });
  ['date-to', 'bs-date-to'].forEach(id => { const el = document.getElementById(id); if (el) el.value = fmt(today); });
  setTimeout(() => { calcola(); confronta(); }, 300);
});
</script>
</body>
</html>`;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const path = req.url.split('?')[0];
  const query = new URLSearchParams(req.url.split('?')[1] || '');

  try {
    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      return res.json({
        sistema: 'T. Luxy ERP — Marginalità v3.4',
        status: 'LIVE',
        store: SHOPIFY_STORE,
        credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET),
        funzionalita: ['Analytics live', 'Best Seller Top 20', 'Confronto Marketplace', 'Calcolatore', 'Filtro periodo custom', 'Italist incluso'],
        marketplaces_supportati: Object.keys(MARKETPLACE_CONFIGS).length,
        endpoints: ['/', '/api', '/api/analytics?periodo=today | ?from=YYYY-MM-DD&to=YYYY-MM-DD', '/api/bestsellers?periodo=month | ?from=...&to=...', '/api/test-shopify', '/api/marketplaces', '/api/debug-orders']
      });
    }

    if (req.method === 'GET' && path === '/api/analytics') {
      const periodo = query.get('periodo') || 'today';
      const from = query.get('from');
      const to = query.get('to');
      try {
        const ordini = await getShopifyOrders(periodo, from, to);
        let lordo_iva_inclusa = 0, iva_totale = 0, costi_totali = 0, margine_netto = 0;
        const breakdown_marketplace = {};
        ordini.forEach(ordine => {
          const prezzo_lordo = parseFloat(ordine.total_price) || 0;
          const total_tax = parseFloat(ordine.total_tax) || 0;
          const spedizione = (ordine.shipping_lines || []).reduce((sum, line) => sum + parseFloat(line.price || 0), 0);
          const costo_merce = (prezzo_lordo - total_tax) * 0.4;
          const mp = riconosciMarketplace(ordine);
          const ris = calcolaMarginalita(prezzo_lordo, total_tax, costo_merce, spedizione, mp.config);
          lordo_iva_inclusa += ris.prezzo_lordo_iva_inclusa;
          iva_totale += ris.iva_scorporata;
          costi_totali += ris.costi_totali;
          margine_netto += ris.margine_netto;
          if (!breakdown_marketplace[mp.key]) breakdown_marketplace[mp.key] = { nome: mp.config.nome, ordini: 0, fatturato: 0, margine: 0 };
          breakdown_marketplace[mp.key].ordini += 1;
          breakdown_marketplace[mp.key].fatturato += ris.prezzo_lordo_iva_inclusa;
          breakdown_marketplace[mp.key].margine += ris.margine_netto;
        });
        const margine_percentuale = lordo_iva_inclusa > 0 ? (margine_netto / lordo_iva_inclusa * 100) : 0;
        return res.json({ 
          success: true, 
          periodo: from && to ? `Custom: ${from} → ${to}` : periodo, 
          ordini_totali: ordini.length, 
          lordo_iva_inclusa, iva_totale, costi_totali, margine_netto, margine_percentuale, 
          breakdown_marketplace, 
          ultima_sincronizzazione: new Date().toISOString() 
        });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    if (req.method === 'GET' && path === '/api/bestsellers') {
      const periodo = query.get('periodo') || 'month';
      const from = query.get('from');
      const to = query.get('to');
      try {
        const ordini = await getShopifyOrders(periodo, from, to);
        let prodotti = calcolaBestSellers(ordini, 20);
        prodotti = await arricchisciConImmagini(prodotti);
        return res.json({ 
          success: true, 
          periodo: from && to ? `Custom: ${from} → ${to}` : periodo, 
          totale_prodotti_unici: prodotti.length, 
          prodotti 
        });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    if (req.method === 'GET' && path === '/api/debug-orders') {
      try {
        const ordini = await getShopifyOrders('month');
        const debug = ordini.slice(0, 20).map(o => ({
          order_number: o.order_number,
          source_name: o.source_name,
          tags: o.tags,
          total_price: o.total_price,
          total_tax: o.total_tax,
          country: o.shipping_address?.country_code || o.billing_address?.country_code,
          marketplace_riconosciuto: riconosciMarketplace(o)
        }));
        return res.json({ success: true, ordini_analizzati: debug.length, ordini: debug });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
      }
    }

    if (req.method === 'GET' && path === '/api/test-shopify') {
      try {
        const token = await getShopifyAccessToken();
        const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/shop.json`, { headers: { 'X-Shopify-Access-Token': token } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        return res.json({ success: true, shop_name: data.shop.name, message: 'Shopify connesso correttamente' });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message, message: 'Dashboard disponibile anche senza Shopify' });
      }
    }

    if (req.method === 'GET' && path === '/api/marketplaces') {
      return res.json({ marketplace_disponibili: MARKETPLACE_CONFIGS, source_name_map: SOURCE_NAME_MAP, marketplace_corrente: process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE' });
    }

    return res.status(404).json({ error: 'Endpoint non trovato', endpoints: ['/', '/api', '/api/analytics', '/api/bestsellers', '/api/test-shopify', '/api/marketplaces', '/api/debug-orders'] });

  } catch (error) {
    return res.status(500).json({ error: 'Errore interno', dettagli: error.message });
  }
}
