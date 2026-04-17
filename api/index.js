// ERP Marginalità v3.0 - Sistema completo con Dashboard integrata

const SHOPIFY_STORE = process.env.SHOPIFY_STORE || 'autore-luxit.myshopify.com';
const SHOPIFY_CLIENT_ID = process.env.SHOPIFY_CLIENT_ID || '';
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET || '';

let cachedToken = null;
let tokenExpiry = null;

async function getShopifyAccessToken() {
  if (cachedToken && tokenExpiry && Date.now() < tokenExpiry) {
    return cachedToken;
  }

  if (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET) {
    throw new Error('Missing SHOPIFY_CLIENT_ID or SHOPIFY_CLIENT_SECRET');
  }

  const response = await fetch(`https://${SHOPIFY_STORE}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: SHOPIFY_CLIENT_ID,
      client_secret: SHOPIFY_CLIENT_SECRET,
      grant_type: 'client_credentials'
    })
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
  return cachedToken;
}

const MARKETPLACE_CONFIGS = {
  'SECRET_SALES': { nome: 'Secret Sales', sconto_percentuale: 0, fee_principale: 20, fee_secondaria: 0, fee_fissa_trasporto: 2, fee_fissa_packaging: 2 },
  'FASHION_TAMERS': { nome: 'Fashion Tamers', sconto_percentuale: 0, fee_principale: 32, fee_secondaria: 2, fee_fissa_trasporto: 15, fee_fissa_packaging: 6 },
  'INTRA_MIRROR': { nome: 'Intra Mirror', sconto_percentuale: 15, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3 },
  'BALARDI': { nome: 'Balardi', sconto_percentuale: 35, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 0, fee_fissa_packaging: 3 },
  'THE_BRADERY': { nome: 'The Bradery', sconto_percentuale: 5, fee_principale: 17, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 2 },
  'BOUTIQUE_MALL': { nome: 'Boutique Mall', sconto_percentuale: 33.3, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2 },
  'ARCHIVIST': { nome: 'Archivist', sconto_percentuale: 0, fee_principale: 22, fee_secondaria: 0, fee_fissa_trasporto: 10, fee_fissa_packaging: 2 },
  'MIINTO': { nome: 'Miinto', sconto_percentuale: 0, fee_principale: 17.75, fee_secondaria: 2.25, fee_fissa_trasporto: 12, fee_fissa_packaging: 1.5 },
  'WINKELSTRAAT': { nome: 'Winkelstraat', sconto_percentuale: 0, fee_principale: 17, fee_secondaria: 0, fee_accessoria: 9, fee_fissa_trasporto: 15, fee_fissa_packaging: 0 },
  'TLUXY_SITE': { nome: 'TLuxy Site (proprio)', sconto_percentuale: 10, fee_principale: 0, fee_secondaria: 0, fee_fissa_trasporto: 12, fee_fissa_packaging: 1 }
};

const getCurrentMarketplace = () => {
  const key = process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE';
  return MARKETPLACE_CONFIGS[key] || MARKETPLACE_CONFIGS['TLUXY_SITE'];
};

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ERP Marginalità Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
  .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }
  .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; text-align: center; }
  .header h1 { font-size: 2.8rem; font-weight: 800; margin-bottom: 10px; color: #E8573A; }
  .header p { font-size: 1.2rem; opacity: 0.9; }
  .status-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(40,167,69,0.2); color: #28a745; padding: 6px 16px; border-radius: 20px; font-size: 0.9rem; font-weight: 600; margin-top: 15px; border: 2px solid rgba(40,167,69,0.3); }
  .status-indicator { width: 8px; height: 8px; background: #28a745; border-radius: 50%; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
  .main-content { padding: 40px; }
  .tabs { display: flex; gap: 8px; margin-bottom: 30px; background: #f8f9fa; padding: 8px; border-radius: 15px; }
  .tab { flex: 1; padding: 15px 25px; border: none; background: transparent; border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 1rem; transition: all 0.3s ease; }
  .tab.active { background: linear-gradient(135deg, #E8573A, #ff6b4a); color: white; box-shadow: 0 4px 15px rgba(232,87,58,0.3); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .section { background: white; border-radius: 20px; padding: 35px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); border: 1px solid rgba(232,87,58,0.1); }
  .section-title { font-size: 1.6rem; font-weight: 700; color: #1a1a2e; margin-bottom: 25px; }
  .period-selector { display: flex; gap: 12px; margin-bottom: 30px; flex-wrap: wrap; justify-content: center; }
  .period-btn { padding: 12px 24px; border: 2px solid #e1e5e9; background: white; border-radius: 25px; cursor: pointer; font-weight: 600; transition: all 0.3s ease; }
  .period-btn.active, .period-btn:hover { background: linear-gradient(135deg, #E8573A, #ff6b4a); color: white; border-color: #E8573A; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin-bottom: 35px; }
  .card { background: linear-gradient(135deg, #E8573A 0%, #ff6b4a 100%); color: white; border-radius: 20px; padding: 30px; text-align: center; transition: transform 0.3s ease; }
  .card:hover { transform: translateY(-5px); }
  .card.dark { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); }
  .card.green { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
  .card.blue { background: linear-gradient(135deg, #17a2b8 0%, #138496 100%); }
  .card-label { font-size: 0.95rem; opacity: 0.9; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 1px; }
  .card-value { font-size: 2.5rem; font-weight: 800; margin-bottom: 8px; }
  .card-sub { font-size: 0.85rem; opacity: 0.8; }
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin-bottom: 25px; }
  .form-group { display: flex; flex-direction: column; gap: 10px; }
  .form-group label { font-weight: 600; color: #1a1a2e; }
  .form-group input, .form-group select { padding: 15px 20px; border: 2px solid #e1e5e9; border-radius: 12px; font-size: 1.05rem; transition: all 0.3s ease; }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: #E8573A; box-shadow: 0 0 0 3px rgba(232,87,58,0.1); }
  .calc-btn { background: linear-gradient(135deg, #E8573A 0%, #ff6b4a 100%); color: white; border: none; padding: 18px 40px; border-radius: 50px; font-size: 1.1rem; font-weight: 700; cursor: pointer; width: 100%; margin-top: 15px; box-shadow: 0 4px 15px rgba(232,87,58,0.3); text-transform: uppercase; letter-spacing: 1px; transition: all 0.3s ease; }
  .calc-btn:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(232,87,58,0.4); }
  .results { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 25px; }
  .result-card { background: #f8f9fa; border-radius: 15px; padding: 25px; text-align: center; border: 3px solid transparent; transition: all 0.3s ease; }
  .result-card.positive { border-color: #28a745; background: linear-gradient(135deg, #d4edda, #c3e6cb); }
  .result-card.negative { border-color: #dc3545; background: linear-gradient(135deg, #f8d7da, #f5c6cb); }
  .result-label { font-size: 0.9rem; color: #666; margin-bottom: 12px; text-transform: uppercase; font-weight: 600; }
  .result-value { font-size: 1.4rem; font-weight: 800; color: #1a1a2e; }
  .mp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 25px; }
  .mp-card { border: 2px solid #e1e5e9; border-radius: 15px; padding: 25px; cursor: pointer; transition: all 0.3s ease; background: white; }
  .mp-card:hover { border-color: #E8573A; transform: translateY(-8px); box-shadow: 0 12px 30px rgba(232,87,58,0.2); }
  .mp-name { font-size: 1.2rem; font-weight: 700; color: #1a1a2e; margin-bottom: 15px; }
  .mp-fees { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.9rem; color: #666; }
  @media (max-width: 768px) { .header h1 { font-size: 2.2rem; } .main-content { padding: 20px; } .tabs { flex-direction: column; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>📊 ERP Marginalità</h1>
    <p>Sistema Completo di Business Intelligence</p>
    <div class="status-badge"><div class="status-indicator"></div>Sistema Live</div>
  </div>
  <div class="main-content">
    <div class="tabs">
      <button class="tab active" onclick="showTab('analytics', event)">📈 Analytics</button>
      <button class="tab" onclick="showTab('calculator', event)">🧮 Calcolatore</button>
      <button class="tab" onclick="showTab('marketplaces', event)">🏪 Marketplace</button>
    </div>
    <div id="analytics-tab" class="tab-content active">
      <div class="section">
        <h2 class="section-title">Analisi Performance</h2>
        <div class="period-selector">
          <button class="period-btn active" onclick="setPeriod('today', event)">Oggi</button>
          <button class="period-btn" onclick="setPeriod('yesterday', event)">Ieri</button>
          <button class="period-btn" onclick="setPeriod('week', event)">Settimana</button>
          <button class="period-btn" onclick="setPeriod('month', event)">Mese</button>
          <button class="period-btn" onclick="setPeriod('quarter', event)">Trimestre</button>
        </div>
        <div class="grid">
          <div class="card"><div class="card-label">Incasso Lordo</div><div class="card-value" id="lordo">€15.240</div><div class="card-sub">Vendite totali</div></div>
          <div class="card dark"><div class="card-label">Costi Totali</div><div class="card-value" id="costi">€11.180</div><div class="card-sub">Merce + Fees</div></div>
          <div class="card green"><div class="card-label">Incasso Netto</div><div class="card-value" id="netto">€4.060</div><div class="card-sub">Margine effettivo</div></div>
          <div class="card blue"><div class="card-label">Margine %</div><div class="card-value" id="margine">26.6%</div><div class="card-sub">Redditività</div></div>
        </div>
      </div>
    </div>
    <div id="calculator-tab" class="tab-content">
      <div class="section">
        <h2 class="section-title">Simulatore Marginalità</h2>
        <div class="form-grid">
          <div class="form-group"><label>💰 Prezzo Vendita (€)</label><input type="number" id="prezzo" value="100"></div>
          <div class="form-group"><label>📦 Costo Merce (€)</label><input type="number" id="costo" value="45"></div>
          <div class="form-group"><label>🚚 Spedizione (€)</label><input type="number" id="spedizione" value="5"></div>
          <div class="form-group"><label>🏪 Marketplace</label><select id="mp-select"></select></div>
        </div>
        <button class="calc-btn" onclick="calcola()">🧮 Calcola Marginalità</button>
        <div class="results" id="results" style="display:none;">
          <div class="result-card"><div class="result-label">Prezzo Netto</div><div class="result-value" id="r-netto">-</div></div>
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
        <h2 class="section-title">Portfolio Marketplace</h2>
        <div class="mp-grid" id="mp-grid"></div>
      </div>
    </div>
  </div>
</div>
<script>
const MARKETPLACES = ${JSON.stringify(MARKETPLACE_CONFIGS)};
const PERIODS = {
  today: { lordo: 15240, costi: 11180, netto: 4060, margine: 26.6 },
  yesterday: { lordo: 12890, costi: 9340, netto: 3550, margine: 27.5 },
  week: { lordo: 89350, costi: 64780, netto: 24570, margine: 27.5 },
  month: { lordo: 342180, costi: 248930, netto: 93250, margine: 27.2 },
  quarter: { lordo: 1024680, costi: 743290, netto: 281390, margine: 27.5 }
};
function showTab(name, ev) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById(name + '-tab').classList.add('active');
  ev.target.classList.add('active');
}
function setPeriod(p, ev) {
  document.querySelectorAll('.period-btn').forEach(b => b.classList.remove('active'));
  ev.target.classList.add('active');
  const d = PERIODS[p];
  document.getElementById('lordo').textContent = '€' + d.lordo.toLocaleString();
  document.getElementById('costi').textContent = '€' + d.costi.toLocaleString();
  document.getElementById('netto').textContent = '€' + d.netto.toLocaleString();
  document.getElementById('margine').textContent = d.margine + '%';
}
function calcola() {
  const prezzo = parseFloat(document.getElementById('prezzo').value) || 0;
  const costo = parseFloat(document.getElementById('costo').value) || 0;
  const spedizione = parseFloat(document.getElementById('spedizione').value) || 0;
  const mp = MARKETPLACES[document.getElementById('mp-select').value];
  const prezzoNetto = prezzo * (1 - mp.sconto_percentuale / 100);
  const feesShop = prezzoNetto * 0.029 + 0.30;
  const feeP = prezzoNetto * (mp.fee_principale / 100);
  const feeS = prezzoNetto * ((mp.fee_secondaria || 0) / 100);
  const feeA = prezzoNetto * ((mp.fee_accessoria || 0) / 100);
  const feesMp = feeP + feeS + feeA + (mp.fee_fissa_trasporto || 0) + (mp.fee_fissa_packaging || 0);
  const margine = prezzoNetto - feesShop - feesMp - costo - spedizione;
  const margineP = prezzo > 0 ? (margine / prezzo * 100) : 0;
  document.getElementById('results').style.display = 'grid';
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
    re.textContent = '✅ REDDITIZIO';
  } else {
    mc.className = 'result-card negative';
    rc.className = 'result-card negative';
    re.textContent = '❌ IN PERDITA';
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
    card.onclick = () => { select.value = key; showTab('calculator', { target: document.querySelectorAll('.tab')[1] }); calcola(); };
    card.innerHTML = '<div class="mp-name">' + mp.nome + '</div><div class="mp-fees"><div><strong>Sconto:</strong> ' + mp.sconto_percentuale + '%</div><div><strong>Fee:</strong> ' + mp.fee_principale + '%</div><div><strong>Trasporto:</strong> €' + (mp.fee_fissa_trasporto || 0) + '</div><div><strong>Packaging:</strong> €' + (mp.fee_fissa_packaging || 0) + '</div></div>';
    grid.appendChild(card);
  });
}
document.addEventListener('DOMContentLoaded', () => { loadMarketplaces(); setTimeout(calcola, 300); });
</script>
</body>
</html>`;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') return res.status(200).end();

  const path = req.url.split('?')[0];

  try {
    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(200).send(DASHBOARD_HTML);
    }

    if (req.method === 'GET' && path === '/api') {
      const mp = getCurrentMarketplace();
      return res.json({
        sistema: '📊 ERP Marginalità v3.0',
        status: 'LIVE',
        store: SHOPIFY_STORE,
        credentials_configured: !!(SHOPIFY_CLIENT_ID && SHOPIFY_CLIENT_SECRET),
        marketplace_attuale: mp.nome,
        marketplace_disponibili: Object.keys(MARKETPLACE_CONFIGS),
        endpoints: ['/', '/api', '/api/test-shopify', '/api/marketplaces']
      });
    }

    if (req.method === 'GET' && path === '/api/test-shopify') {
      try {
        const token = await getShopifyAccessToken();
        const response = await fetch(`https://${SHOPIFY_STORE}/admin/api/2024-01/shop.json`, {
          headers: { 'X-Shopify-Access-Token': token }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        return res.json({ success: true, shop_name: data.shop.name, message: '✅ Shopify connesso!' });
      } catch (error) {
        return res.status(500).json({ success: false, error: error.message, message: 'Dashboard disponibile anche senza Shopify' });
      }
    }

    if (req.method === 'GET' && path === '/api/marketplaces') {
      return res.json({
        marketplace_disponibili: MARKETPLACE_CONFIGS,
        marketplace_corrente: process.env.CURRENT_MARKETPLACE || 'TLUXY_SITE'
      });
    }

    return res.status(404).json({ error: 'Endpoint non trovato', endpoints: ['/', '/api', '/api/test-shopify', '/api/marketplaces'] });

  } catch (error) {
    return res.status(500).json({ error: 'Errore interno', dettagli: error.message });
  }
}
