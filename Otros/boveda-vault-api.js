// Auto-detect API URL from current page origin
document.getElementById('login-api-url').value = window.location.origin;

// ============================================================
// STATE
// ============================================================
let VAULT = { emails: [], accounts: [], links: [] };
let MASTER_KEY = null;     // CryptoKey, never serialized
let MASTER_SALT = null;    // Uint8Array, stored alongside ciphertext
let isNewVault = true;
let activeFileBaseName = "boveda";

// ============================================================
// BACKEND SYNC STATE
// ============================================================
let API_URL = "";            // ej: https://api.onrender.com
let LOGGED_IN_USER = null;  // username or null if offline
let SERVER_BLOB = null;     // { salt, iv, data, version } from server

async function apiCall(method, path, body) {
  try {
    const opts = {
      method,
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`${API_URL}${path}`, opts);
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: { error: "No se pudo conectar al servidor" } };
  }
}

const CATEGORY_COLORS = {
  "correo":      "#5b8cff",
  "hosting":     "#3ecf8e",
  "base de datos":"#9b6bff",
  "social":      "#e2a23a",
  "mensajería":  "#3ab0e2",
  "ia":          "#e25c9e",
  "banco":       "#e25c5c",
  "monitoreo":   "#5cc9c0",
  "otro":        "#9aa1b4"
};
function colorFor(cat){ return CATEGORY_COLORS[(cat||"otro").toLowerCase()] || CATEGORY_COLORS["otro"]; }

function uid(){ return crypto.randomUUID(); }

// ============================================================
// CRYPTO  (AES-256-GCM + PBKDF2)
// ============================================================
async function deriveKey(password, saltBytes){
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  // 310,000 iteraciones para SHA-256 según recomendación OWASP 2023 (cheatsheet de almacenamiento de contraseñas)
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt: saltBytes, iterations: 310000, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
}

function bufToB64(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(b64){
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  return arr;
}

async function encryptVault(){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(VAULT));
  const cipherBuf = await crypto.subtle.encrypt({name:"AES-GCM", iv}, MASTER_KEY, plaintext);
  return {
    v: 1,
    salt: bufToB64(MASTER_SALT),
    iv: bufToB64(iv),
    data: bufToB64(cipherBuf)
  };
}

async function decryptVault(fileObj, password){
  const salt = b64ToBuf(fileObj.salt);
  const iv = b64ToBuf(fileObj.iv);
  const key = await deriveKey(password, salt);
  const cipherBuf = b64ToBuf(fileObj.data);
  const plainBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, cipherBuf);
  const dec = new TextDecoder();
  const json = JSON.parse(dec.decode(plainBuf));
  return { key, salt, data: json };
}

// ============================================================
// LOGIN SCREEN (backend auth)
// ============================================================
const loginScreen = document.getElementById('login-screen');
const loginApiUrl = document.getElementById('login-api-url');
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const loginError = document.getElementById('login-error');
const btnLogin = document.getElementById('btn-login');
const btnSkipLogin = document.getElementById('btn-skip-login');

function showLoginError(msg) {
  loginError.textContent = msg;
  loginError.style.display = 'block';
}
function clearLoginError() { loginError.style.display = 'none'; }

btnLogin.addEventListener('click', async () => {
  clearLoginError();
  const url = loginApiUrl.value.trim().replace(/\/+$/, '');
  // Validate API URL
  try {
    new URL(url);
  } catch {
    showLoginError('La URL del servidor no es válida. Debe ser una URL completa (ej: http://localhost:3000).');
    return;
  }
  const user = loginUsername.value.trim();
  const pass = loginPassword.value;

  if (!url) { showLoginError('Ingresa la URL del servidor.'); return; }
  if (!user || !pass) { showLoginError('Ingresa usuario y contraseña.'); return; }

  API_URL = url;
  btnLogin.disabled = true;
  btnLogin.textContent = 'Iniciando sesión...';

  const { ok, data } = await apiCall('POST', '/api/auth/login', {
    username: user,
    password: pass,
  });

  if (!ok) {
    showLoginError(data.error || 'Error al iniciar sesión');
    btnLogin.disabled = false;
    btnLogin.textContent = 'Iniciar sesión';
    return;
  }

  LOGGED_IN_USER = data.username;
  loginPassword.value = '';
  btnLogin.disabled = false;
  btnLogin.textContent = 'Iniciar sesión';

  // Check if vault exists on server
  const vaultRes = await apiCall('GET', '/api/vault');
  if (vaultRes.ok) {
    // Vault exists — save blob and go to unlock screen with it
    SERVER_BLOB = vaultRes.data;
    pendingFileObj = {
      salt: SERVER_BLOB.salt,
      iv: SERVER_BLOB.iv,
      data: SERVER_BLOB.data,
    };
    isNewVault = false;
    confirmRow.classList.add('hidden');
    masterPassConfirm.value = '';
    lockTitle.textContent = 'Desbloquear bóveda del servidor';
    lockSub.textContent = 'Ingresa tu contraseña maestra para descifrar la bóveda sincronizada.';
    btnCreateNew.style.display = 'none';
    btnUnlock.style.display = 'block';
    fileLabel.style.display = 'none';
    masterPassInput.value = '';
    lockError.textContent = '';
    loginScreen.style.display = 'none';
    lockScreen.style.display = 'flex';
    masterPassInput.focus();
  } else if (vaultRes.status === 404) {
    // No vault yet — go to lock screen to create new
    SERVER_BLOB = null;
    loginScreen.style.display = 'none';
    lockScreen.style.display = 'flex';
    lockTitle.textContent = 'Crear bóveda nueva';
    lockSub.textContent = 'Elige una contraseña maestra para cifrar tus credenciales.';
    confirmRow.classList.remove('hidden');
    btnCreateNew.style.display = 'block';
    btnCreateNew.textContent = 'Crear bóveda nueva';
    btnUnlock.style.display = 'none';
    fileLabel.style.display = 'flex';
    masterPassInput.value = '';
    masterPassConfirm.value = '';
    lockError.textContent = '';
  } else {
    showLoginError(vaultRes.data.error || 'Error al conectar con el servidor');
  }
});

btnSkipLogin.addEventListener('click', () => {
  API_URL = loginApiUrl.value.trim().replace(/\/+$/, '');
  LOGGED_IN_USER = null;
  SERVER_BLOB = null;
  loginScreen.style.display = 'none';
  lockScreen.style.display = 'flex';
  // Reset lock screen to default state
  lockTitle.textContent = 'Bóveda de credenciales';
  lockSub.textContent = 'Crea una contraseña maestra nueva, o carga un archivo .vault que ya tengas.';
  confirmRow.classList.add('hidden');
  btnCreateNew.style.display = 'block';
  btnCreateNew.textContent = 'Crear bóveda nueva';
  btnUnlock.style.display = 'none';
  fileLabel.style.display = 'flex';
  masterPassInput.value = '';
  masterPassConfirm.value = '';
  lockError.textContent = '';
});

// Also submit on Enter in password field
loginPassword.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') btnLogin.click();
});

// ============================================================
// LOCK SCREEN LOGIC
// ============================================================
const lockScreen = document.getElementById('lock-screen');
const appScreen = document.getElementById('app-screen');
const masterPassInput = document.getElementById('master-pass');
const confirmRow = document.getElementById('confirm-row');
const masterPassConfirm = document.getElementById('master-pass-confirm');
const lockError = document.getElementById('lock-error');
const lockTitle = document.getElementById('lock-title');
const lockSub = document.getElementById('lock-sub');
const btnCreateNew = document.getElementById('btn-create-new');
const btnUnlock = document.getElementById('btn-unlock');
const fileInput = document.getElementById('file-input');
const fileLabel = document.getElementById('file-label');

let pendingFileObj = null;

fileInput.addEventListener('change', (e)=>{
  const file = e.target.files[0];
  if(!file) return;
  activeFileBaseName = file.name.replace(/\.(vault|json)$/i,'') || 'boveda';
  const reader = new FileReader();
  reader.onload = ()=>{
    try{
      const parsed = JSON.parse(reader.result);
      if(!parsed.salt || !parsed.iv || !parsed.data){
        lockError.textContent = "Este archivo no parece ser un .vault válido.";
        return;
      }
      pendingFileObj = parsed;
      isNewVault = false;
      confirmRow.classList.add('hidden');
      masterPassConfirm.value='';
      lockTitle.textContent = "Desbloquear bóveda";
      lockSub.textContent = "Ingresa tu contraseña maestra para abrir " + file.name;
      btnCreateNew.style.display='none';
      btnUnlock.style.display='block';
      fileLabel.style.display='none';
      masterPassInput.value='';
      masterPassInput.focus();
      lockError.textContent='';
    }catch(err){
      lockError.textContent = "No se pudo leer el archivo: " + err.message;
    }
  };
  reader.readAsText(file);
});

btnCreateNew.addEventListener('click', ()=>{
  if(confirmRow.classList.contains('hidden')){
    // first click: ask to confirm password
    if(!masterPassInput.value || masterPassInput.value.length < 6){
      lockError.textContent = "Usa al menos 6 caracteres para tu contraseña maestra.";
      return;
    }
    confirmRow.classList.remove('hidden');
    masterPassConfirm.focus();
    lockError.textContent='';
    btnCreateNew.textContent = "Confirmar y crear";
    return;
  }
  if(masterPassInput.value !== masterPassConfirm.value){
    lockError.textContent = "Las contraseñas no coinciden.";
    return;
  }
  createNewVault(masterPassInput.value);
});

btnUnlock.addEventListener('click', async ()=>{
  const pw = masterPassInput.value;
  if(!pw){ lockError.textContent = "Ingresa tu contraseña maestra."; return; }
  btnUnlock.disabled = true;
  btnUnlock.textContent = "Desbloqueando...";
  try{
    const { key, salt, data } = await decryptVault(pendingFileObj, pw);
    MASTER_KEY = key;
    MASTER_SALT = salt;
    VAULT = data;
    enterApp();
  }catch(err){
    lockError.textContent = "Contraseña incorrecta o archivo dañado.";
    btnUnlock.disabled = false;
    btnUnlock.textContent = "Desbloquear";
  }
});

async function createNewVault(password){
  MASTER_SALT = crypto.getRandomValues(new Uint8Array(16));
  MASTER_KEY = await deriveKey(password, MASTER_SALT);
  VAULT = { emails: [], accounts: [], links: [] };
  isNewVault = true;
  enterApp();
}

function enterApp(){
  // Update sync indicator
  const syncEl = document.getElementById('sync-indicator');
  if (LOGGED_IN_USER) {
    syncEl.textContent = `☁️ ${LOGGED_IN_USER}`;
    syncEl.title = 'Sincronizado con el servidor';
  } else {
    syncEl.textContent = '💻 Local';
    syncEl.title = 'Modo local (sin sincronización)';
  }
  lockScreen.style.display='none';
  appScreen.style.display='flex';
  renderAll();
}

document.getElementById('btn-lock').addEventListener('click', async ()=>{
  if(!confirm("¿Bloquear la bóveda? Asegúrate de haber exportado los cambios recientes antes de continuar.")) return;
  MASTER_KEY=null; MASTER_SALT=null; VAULT={emails:[],accounts:[],links:[]};
  appScreen.style.display='none';
  // If was logged in, go back to login screen; otherwise to lock screen
  if (LOGGED_IN_USER) {
    loginScreen.style.display = 'flex';
    lockScreen.style.display = 'none';
    loginPassword.value = '';
  } else {
    lockScreen.style.display='flex';
    masterPassInput.value=''; masterPassConfirm.value='';
    confirmRow.classList.add('hidden');
    btnCreateNew.style.display='block'; btnCreateNew.textContent='Crear bóveda nueva';
    btnUnlock.style.display='none';
    fileLabel.style.display='flex';
    lockTitle.textContent='Bóveda de credenciales';
    lockSub.textContent='Crea una contraseña maestra nueva, o carga un archivo .vault que ya tengas.';
    lockError.textContent='';
  }
});

// ============================================================
// EXPORT & SYNC
// ============================================================
document.getElementById('btn-export').addEventListener('click', async ()=>{
  const fileObj = await encryptVault();
  // Download locally
  const blob = new Blob([JSON.stringify(fileObj)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().slice(0,10);
  a.href = url;
  a.download = `${activeFileBaseName}-${ts}.vault`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showCopyFeedback("Archivo .vault descargado");

  // Sync to server if logged in
  if (LOGGED_IN_USER) {
    const syncRes = await apiCall('PUT', '/api/vault', {
      salt: fileObj.salt,
      iv: fileObj.iv,
      data: fileObj.data,
    });
    if (syncRes.ok) {
      SERVER_BLOB = { salt: fileObj.salt, iv: fileObj.iv, data: fileObj.data, version: SERVER_BLOB?.version || 1 };
      showCopyFeedback("✅ Sincronizado con el servidor");
    } else {
      showCopyFeedback("⚠️ No se pudo sincronizar con el servidor");
    }
  }
});

function showCopyFeedback(msg){
  const el = document.getElementById('copy-feedback');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'), 1600);
}

// ============================================================
// AUTOSAVE: persist every change (add/edit/delete/link) to the
// server immediately, instead of only on "Exportar .vault".
// ============================================================
async function autosave(){
  if(!LOGGED_IN_USER) return; // local-only mode: nothing to sync
  try{
    const fileObj = await encryptVault();
    const syncRes = await apiCall('PUT', '/api/vault', {
      salt: fileObj.salt,
      iv: fileObj.iv,
      data: fileObj.data,
    });
    if(syncRes.ok){
      SERVER_BLOB = { salt: fileObj.salt, iv: fileObj.iv, data: fileObj.data, version: SERVER_BLOB?.version || 1 };
    } else {
      console.error("Autosave falló:", syncRes.data?.error || syncRes.status);
    }
  }catch(err){
    console.error("Autosave error:", err);
  }
}

// Save/sync to server
document.getElementById('btn-save').addEventListener('click', async () => {
  if (!LOGGED_IN_USER) {
    showCopyFeedback("💻 Modo local — no hay servidor para guardar");
    return;
  }
  try {
    const fileObj = await encryptVault();
    const syncRes = await apiCall('PUT', '/api/vault', {
      salt: fileObj.salt,
      iv: fileObj.iv,
      data: fileObj.data,
    });
    if (syncRes.ok) {
      SERVER_BLOB = {
        salt: fileObj.salt,
        iv: fileObj.iv,
        data: fileObj.data,
        version: SERVER_BLOB?.version || 1,
      };
      showCopyFeedback("✅ Guardado en el servidor");
    } else {
      showCopyFeedback("⚠️ Error al guardar: " + (syncRes.data?.error || "desconocido"));
    }
  } catch (err) {
    showCopyFeedback("⚠️ Error al conectar con el servidor");
  }
});

// ============================================================
// TABS
// ============================================================
document.querySelectorAll('.tab').forEach(tab=>{
  tab.addEventListener('click', ()=>{
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    tab.classList.add('active');
    const target = tab.dataset.tab;
    document.getElementById('view-list').classList.toggle('hidden', target!=='list');
    document.getElementById('view-graph').classList.toggle('hidden', target!=='graph');
    document.getElementById('view-recommend').classList.toggle('hidden', target!=='recommend');
    if(target==='graph') renderGraph();
    if(target==='recommend') renderRecommendations();
  });
});

// ============================================================
// RENDER: STATS
// ============================================================
function renderStats(){
  const el = document.getElementById('stats-row');
  const totalAccounts = VAULT.accounts.length;
  const totalEmails = VAULT.emails.length;
  const totalLinks = VAULT.links.length;
  const cats = new Set(VAULT.accounts.map(a=>a.category||'otro')).size;
  el.innerHTML = `
    <div class="stat"><div class="num">${totalEmails}</div><div class="lbl">Correos</div></div>
    <div class="stat"><div class="num">${totalAccounts}</div><div class="lbl">Cuentas</div></div>
    <div class="stat"><div class="num">${totalLinks}</div><div class="lbl">Conexiones</div></div>
    <div class="stat"><div class="num">${cats}</div><div class="lbl">Categorías</div></div>
  `;
}

// ============================================================
// RENDER: LIST VIEW
// ============================================================
function getAllNodes(){
  const emailNodes = VAULT.emails.map(e=>({
    id:e.id, type:'email', name:e.address, category:'correo', username:e.address,
    password:e.password||'', url:e.url||'', notes:e.notes||''
  }));
  const accountNodes = VAULT.accounts.map(a=>({...a, type:'account'}));
  return [...emailNodes, ...accountNodes];
}

function refreshCategoryFilter(){
  const sel = document.getElementById('filter-category');
  const cats = Array.from(new Set(VAULT.accounts.map(a=>a.category||'otro'))).sort();
  const current = sel.value;
  sel.innerHTML = '<option value="">Todas las categorías</option>' +
    cats.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(cap(c))}</option>`).join('');
  sel.value = current;
}

function renderList(){
  refreshCategoryFilter();
  const grid = document.getElementById('card-grid');
  const search = document.getElementById('search-input').value.toLowerCase().trim();
  const catFilter = document.getElementById('filter-category').value;

  let items = [
    ...VAULT.emails.map(e=>({...e, type:'email', category:'correo'})),
    ...VAULT.accounts.map(a=>({...a, type:'account'}))
  ];

  if(catFilter) items = items.filter(i => (i.category||'otro')===catFilter);
  if(search){
    items = items.filter(i=>{
      const hay = [i.name, i.address, i.username, i.url, i.notes].filter(Boolean).join(' ').toLowerCase();
      return hay.includes(search);
    });
  }

  if(items.length===0){
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">No hay cuentas que coincidan. Usa "+ Cuenta" arriba para agregar la primera.</div>`;
    return;
  }

  grid.innerHTML = items.map(item=>{
    const isEmail = item.type==='email';
    const label = isEmail ? item.address : item.name;
    const cat = isEmail ? 'correo' : (item.category||'otro');
    const col = colorFor(cat);
    const sub1 = isEmail ? 'Correo' : (item.username||'—');
    const linkedCount = countLinksFor(item.id);
    return `
      <div class="acc-card" data-id="${item.id}" data-kind="${item.type}">
        <div class="acc-card-top">
          <div class="acc-card-name"><span class="swatch" style="background:${col}"></span>${escapeHtml(label)}</div>
          <span class="badge">${escapeHtml(cap(cat))}</span>
        </div>
        <div class="acc-card-row"><span>Usuario</span><span>${escapeHtml(sub1)}</span></div>
        <div class="acc-card-row"><span>Conexiones</span><span>${linkedCount}</span></div>
      </div>`;
  }).join('');

  grid.querySelectorAll('.acc-card').forEach(card=>{
    card.addEventListener('click', ()=>{
      openDetailModal(card.dataset.id, card.dataset.kind);
    });
  });
}

function countLinksFor(id){
  return VAULT.links.filter(l=>l.from===id||l.to===id).length;
}

document.getElementById('search-input').addEventListener('input', renderList);
document.getElementById('filter-category').addEventListener('change', renderList);

function cap(s){ return s.charAt(0).toUpperCase()+s.slice(1); }
function escapeHtml(s){
  return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ============================================================
// DUPLICATE DETECTION  (filtro inteligente)
// ============================================================
function findDuplicates(type, name, username, excludeId) {
  const results = [];
  const nameNorm = name.toLowerCase().trim();

  if (type === 'email') {
    const exact = VAULT.emails.find(
      e => e.id !== excludeId && e.address.toLowerCase() === nameNorm
    );
    if (exact) {
      results.push({ kind: 'exact', match: exact, label: 'Correo exacto: ' + exact.address });
    }
    const at = nameNorm.indexOf('@');
    if (at > 0) {
      const domain = nameNorm.slice(at);
      VAULT.emails.forEach(e => {
        if (e.id !== excludeId && e.id !== (exact && exact.id) && e.address.toLowerCase().endsWith(domain)) {
          results.push({ kind: 'domain', match: e, label: 'Mismo dominio: ' + e.address });
        }
      });
      VAULT.accounts.forEach(a => {
        if ((a.username || '').toLowerCase().endsWith(domain)) {
          results.push({ kind: 'domain', match: a, label: 'Cuenta "' + a.name + '" con ese dominio en usuario' });
        }
      });
    }
  } else {
    const exact = VAULT.accounts.find(
      a => a.id !== excludeId && a.name.toLowerCase() === nameNorm
    );
    if (exact) {
      results.push({ kind: 'exact', match: exact, label: 'Cuenta exacta: "' + exact.name + '"' });
    }
    VAULT.accounts.forEach(a => {
      if (a.id !== excludeId && a.id !== (exact && exact.id)) {
        const aNorm = a.name.toLowerCase();
        if ((aNorm.includes(nameNorm) || nameNorm.includes(aNorm)) && aNorm !== nameNorm) {
          results.push({ kind: 'similar', match: a, label: 'Similar: "' + a.name + '"' });
        }
      }
    });
    if (username) {
      const uNorm = username.toLowerCase().trim();
      VAULT.accounts.forEach(a => {
        if (a.id !== excludeId && (a.username || '').toLowerCase().trim() === uNorm) {
          if (!results.some(r => r.match.id === a.id)) {
            results.push({ kind: 'username', match: a, label: 'Mismo usuario en: "' + a.name + '"' });
          }
        }
      });
    }
  }
  return results;
}

function showDuplicateWarning(duplicates, onProceed) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML =
    '<div class="modal" style="max-width:440px;">' +
      '<h2 style="color:var(--warning);margin-bottom:12px;">\u26A0\uFE0F Posible duplicado</h2>' +
      '<p style="font-size:13px;color:var(--text-secondary);margin:0 0 14px;">' +
        'Se encontraron <strong>' + duplicates.length + '</strong> registro(s) similar(es) en tu b\u00F3veda:' +
      '</p>' +
      '<div style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px;">' +
        duplicates.map(function(d) {
          return '<div style="background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12.5px;">' + escapeHtml(d.label) + '</div>';
        }).join('') +
      '</div>' +
      '<p style="font-size:12.5px;color:var(--text-muted);margin:0 0 6px;">' +
        '\u00BFAgregar o actualizar de todas formas?' +
      '</p>' +
      '<div class="modal-actions">' +
        '<button class="btn" id="dw-cancel">Cancelar</button>' +
        '<button class="btn btn-primary" id="dw-proceed">Guardar de todas formas</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.querySelector('#dw-cancel').addEventListener('click', function() { overlay.remove(); });
  overlay.querySelector('#dw-proceed').addEventListener('click', function() { overlay.remove(); onProceed(); });
  overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
}

function renderAll(){
  renderStats();
  renderList();
}

// ============================================================
// MODAL: ADD ACCOUNT / EMAIL
// ============================================================
document.getElementById('btn-add-account').addEventListener('click', ()=>openAddModal());

function openAddModal(){
  const overlay = document.createElement('div');
  overlay.className='modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <h2>Agregar correo o cuenta</h2>
      <div class="field">
        <label>Tipo</label>
        <select id="m-type">
          <option value="account">Cuenta / servicio (Render, Neon, Telegram...)</option>
          <option value="email">Correo (hub que agrupa varias cuentas)</option>
        </select>
      </div>
      <div class="field">
        <label id="m-name-label">Nombre del servicio</label>
        <input id="m-name" placeholder="Ej: Render, Neon, Telegram, BCP">
      </div>
      <div class="field-row">
        <div class="field">
          <label>Usuario / correo de acceso</label>
          <input id="m-username" placeholder="usuario@dominio.com">
        </div>
        <div class="field">
          <label>Categoría</label>
          <select id="m-category">
            <option value="hosting">Hosting</option>
            <option value="base de datos">Base de datos</option>
            <option value="social">Social</option>
            <option value="mensajería">Mensajería</option>
            <option value="ia">IA</option>
            <option value="banco">Banco</option>
            <option value="monitoreo">Monitoreo</option>
            <option value="otro">Otro</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label>Contraseña</label>
        <div class="pw-row">
          <input id="m-password" type="password">
          <button type="button" class="pw-toggle" data-target="m-password">👁</button>
        </div>
      </div>
      <div class="field">
        <label>URL de acceso (opcional)</label>
        <input id="m-url" placeholder="https://dashboard.render.com">
      </div>
      <div class="field" id="m-owner-field">
        <label>Correo dueño (opcional)</label>
        <select id="m-owner"><option value="">— Ninguno —</option></select>
      </div>
      <div class="field">
        <label>Notas (opcional)</label>
        <textarea id="m-notes" placeholder="2FA, recovery codes, etc."></textarea>
      </div>
      <div class="modal-actions">
        <button class="btn" id="m-cancel">Cancelar</button>
        <button class="btn btn-primary" id="m-save">Guardar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const ownerSelect = overlay.querySelector('#m-owner');
  VAULT.emails.forEach(e=> ownerSelect.innerHTML += `<option value="${e.id}">${escapeHtml(e.address)}</option>`);

  const typeSelect = overlay.querySelector('#m-type');
  const nameLabel = overlay.querySelector('#m-name-label');
  const ownerField = overlay.querySelector('#m-owner-field');
  const categoryField = overlay.querySelector('#m-category').closest('.field');

  function syncType(){
    if(typeSelect.value==='email'){
      nameLabel.textContent = 'Dirección de correo';
      overlay.querySelector('#m-name').placeholder = 'nombre@gmail.com';
      ownerField.style.display='none';
      categoryField.style.display='none';
    }else{
      nameLabel.textContent = 'Nombre del servicio';
      overlay.querySelector('#m-name').placeholder = 'Ej: Render, Neon, Telegram, BCP';
      ownerField.style.display='block';
      categoryField.style.display='block';
    }
  }
  typeSelect.addEventListener('change', syncType);

  overlay.querySelectorAll('.pw-toggle').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const inp = overlay.querySelector('#'+btn.dataset.target);
      inp.type = inp.type==='password' ? 'text' : 'password';
    });
  });

  overlay.querySelector('#m-cancel').addEventListener('click', ()=>overlay.remove());
  overlay.addEventListener('click', (e)=>{ if(e.target===overlay) overlay.remove(); });

  overlay.querySelector('#m-save').addEventListener('click', ()=>{
    const name = overlay.querySelector('#m-name').value.trim();
    if(!name){ alert('El nombre no puede estar vacío.'); return; }
    const username = overlay.querySelector('#m-username').value.trim();
    const password = overlay.querySelector('#m-password').value;
    const url = overlay.querySelector('#m-url').value.trim();
    const notes = overlay.querySelector('#m-notes').value.trim();

    // Filtro inteligente de duplicados
    const duplicates = findDuplicates(typeSelect.value, name, username);
    if (duplicates.length > 0) {
      showDuplicateWarning(duplicates, function() { actuallySave(); });
      return;
    }
    actuallySave();

    function actuallySave() {
      if(typeSelect.value==='email'){
        VAULT.emails.push({ id:uid(), address:name, password, url, notes });
      } else {
        const category = overlay.querySelector('#m-category').value;
        const ownerId = ownerSelect.value;
        const newAcc = { id:uid(), name, username, password, url, category, notes };
        VAULT.accounts.push(newAcc);
        if(ownerId){
          VAULT.links.push({ id:uid(), from:ownerId, to:newAcc.id, type:'owner', label:'' });
        }
      }
      overlay.remove();
      renderAll();
      autosave();
    }
  });
}

// ============================================================
// MODAL: DETAIL / EDIT + RELATIONS
// ============================================================
function findNodeById(id){
  const e = VAULT.emails.find(x=>x.id===id);
  if(e) return {...e, type:'email', name:e.address, category:'correo'};
  const a = VAULT.accounts.find(x=>x.id===id);
  if(a) return {...a, type:'account'};
  return null;
}

function openDetailModal(id, kind){
  const node = findNodeById(id);
  if(!node) return;
  const overlay = document.createElement('div');
  overlay.className='modal-overlay';

  const relatedLinks = VAULT.links.filter(l=>l.from===id||l.to===id);
  const relHtml = relatedLinks.map(l=>{
    const otherId = l.from===id ? l.to : l.from;
    const other = findNodeById(otherId);
    const dirLabel = l.from===id ? '→' : '←';
    const otherName = other ? (other.type==='email'?other.address:other.name) : '(eliminado)';
    const typeLabel = l.type==='owner' ? 'dueño de' : (l.label || 'vinculado');
    return `<div class="rel-item">
      <span>${dirLabel} ${escapeHtml(otherName)} <span style="color:var(--text-muted)">· ${escapeHtml(typeLabel)}</span></span>
      <button class="x" data-link-id="${l.id}" title="Quitar conexión">✕</button>
    </div>`;
  }).join('') || `<div style="font-size:12.5px;color:var(--text-muted);">Sin conexiones aún.</div>`;

  const otherNodes = getAllNodes().filter(n=>n.id!==id);

  overlay.innerHTML = `
    <div class="modal">
      <h2>${escapeHtml(node.type==='email'?node.address:node.name)}</h2>

      ${node.type==='account' ? `
      <div class="field">
        <label>Nombre del servicio</label>
        <input id="d-name" value="${escapeHtml(node.name)}">
      </div>
      <div class="field-row">
        <div class="field">
          <label>Usuario</label>
          <input id="d-username" value="${escapeHtml(node.username||'')}">
        </div>
        <div class="field">
          <label>Categoría</label>
          <select id="d-category">
            ${Object.keys(CATEGORY_COLORS).filter(c=>c!=='correo').map(c=>
              `<option value="${c}" ${node.category===c?'selected':''}>${cap(c)}</option>`).join('')}
          </select>
        </div>
      </div>` : `
      <div class="field">
        <label>Dirección</label>
        <input id="d-name" value="${escapeHtml(node.address)}">
      </div>`}

      <div class="field">
        <label>Contraseña</label>
        <div class="pw-row">
          <input id="d-password" type="password" value="${escapeHtml(node.password||'')}">
          <button type="button" class="pw-toggle" data-target="d-password">👁</button>
        </div>
      </div>
      <div class="field">
        <label>URL de acceso</label>
        <input id="d-url" value="${escapeHtml(node.url||'')}">
      </div>
      <div class="field">
        <label>Notas</label>
        <textarea id="d-notes">${escapeHtml(node.notes||'')}</textarea>
      </div>

      <div class="field">
        <label>Conexiones con otras cuentas</label>
        <div class="rel-list" id="rel-list">${relHtml}</div>
        <div class="add-rel-row">
          <select id="rel-target">
            <option value="">Vincular con...</option>
            ${otherNodes.map(n=>`<option value="${n.id}">${escapeHtml(n.type==='email'?n.address:n.name)}</option>`).join('')}
          </select>
          <input id="rel-label" placeholder="Etiqueta (ej: mismo teléfono)">
          <button class="btn btn-sm" id="rel-add">Vincular</button>
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn btn-danger modal-actions-left" id="d-delete">Eliminar</button>
        <button class="btn" id="d-cancel">Cerrar</button>
        <button class="btn btn-primary" id="d-save">Guardar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelectorAll('.pw-toggle').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const inp = overlay.querySelector('#'+btn.dataset.target);
      inp.type = inp.type==='password' ? 'text' : 'password';
    });
  });

  overlay.querySelector('#d-cancel').addEventListener('click', ()=>overlay.remove());
  overlay.addEventListener('click', (e)=>{ if(e.target===overlay) overlay.remove(); });

  overlay.querySelector('#d-delete').addEventListener('click', ()=>{
    if(!confirm('¿Eliminar este registro y todas sus conexiones? Esta acción no se puede deshacer.')) return;
    VAULT.emails = VAULT.emails.filter(x=>x.id!==id);
    VAULT.accounts = VAULT.accounts.filter(x=>x.id!==id);
    VAULT.links = VAULT.links.filter(l=>l.from!==id && l.to!==id);
    overlay.remove();
    renderAll();
    autosave();
  });

  overlay.querySelector('#d-save').addEventListener('click', ()=>{
    const newName = overlay.querySelector('#d-name').value.trim();
    if(!newName){ alert('El nombre no puede estar vacío.'); return; }
    const password = overlay.querySelector('#d-password').value;
    const url = overlay.querySelector('#d-url').value.trim();
    const notes = overlay.querySelector('#d-notes').value.trim();

    const typeLabel = node.type==='account' ? 'account' : 'email';
    const username = node.type==='account' ? overlay.querySelector('#d-username').value.trim() : '';

    // Filtro inteligente de duplicados (excluye el registro actual)
    const duplicates = findDuplicates(typeLabel, newName, username, id);
    if (duplicates.length > 0) {
      showDuplicateWarning(duplicates, function() { actuallySaveEdit(); });
      return;
    }
    actuallySaveEdit();

    function actuallySaveEdit() {
      if(node.type==='account'){
        const acc = VAULT.accounts.find(x=>x.id===id);
        acc.name = newName;
        acc.username = overlay.querySelector('#d-username').value.trim();
        acc.category = overlay.querySelector('#d-category').value;
        acc.password = password; acc.url = url; acc.notes = notes;
      } else {
        const em = VAULT.emails.find(x=>x.id===id);
        em.address = newName;
        em.password = password; em.url = url; em.notes = notes;
      }
      overlay.remove();
      renderAll();
      autosave();
    }
  });

  overlay.querySelector('#rel-add').addEventListener('click', ()=>{
    const targetId = overlay.querySelector('#rel-target').value;
    if(!targetId){
      overlay.querySelector('#rel-target').focus();
      showCopyFeedback("⚠️ Elige una cuenta para vincular");
      return;
    }
    const label = overlay.querySelector('#rel-label').value.trim();
    VAULT.links.push({ id:uid(), from:id, to:targetId, type:'cross', label: label || 'vinculado' });
    overlay.remove();
    renderAll();
    autosave();
    openDetailModal(id, kind);
  });

  overlay.querySelectorAll('[data-link-id]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      VAULT.links = VAULT.links.filter(l=>l.id!==btn.dataset.linkId);
      overlay.remove();
      renderAll();
      autosave();
      openDetailModal(id, kind);
    });
  });
}

// ============================================================
// GRAPH VIEW (D3 force layout)
// ============================================================
let simulation = null;
let svgZoomG = null;
let currentZoom = d3.zoomIdentity;

function renderGraph(){
  const svg = d3.select('#graph-svg');
  svg.selectAll('*').remove();
  const wrap = document.getElementById('graph-wrap');
  const width = wrap.clientWidth;
  const height = wrap.clientHeight;
  svg.attr('viewBox', `0 0 ${width} ${height}`);

  const defs = svg.append('defs');
  defs.append('marker')
    .attr('id','arrowhead')
    .attr('viewBox','0 0 10 10')
    .attr('refX',8).attr('refY',5)
    .attr('markerWidth',6).attr('markerHeight',6)
    .attr('orient','auto-start-reverse')
    .append('path')
    .attr('d','M2 1L8 5L2 9')
    .attr('fill','none')
    .attr('stroke','#5a6172')
    .attr('stroke-width',1.5);

  const g = svg.append('g');
  svgZoomG = g;

  const zoom = d3.zoom()
    .scaleExtent([0.3, 3])
    .on('zoom', (event)=>{ currentZoom = event.transform; g.attr('transform', event.transform); });
  svg.call(zoom);
  svg.call(zoom.transform, currentZoom);

  document.getElementById('zoom-in').onclick = ()=> svg.transition().duration(200).call(zoom.scaleBy, 1.3);
  document.getElementById('zoom-out').onclick = ()=> svg.transition().duration(200).call(zoom.scaleBy, 0.75);
  document.getElementById('zoom-reset').onclick = ()=>{
    currentZoom = d3.zoomIdentity;
    svg.transition().duration(250).call(zoom.transform, currentZoom);
  };

  const nodesData = getAllNodes().map(n=>({...n}));
  const linksData = VAULT.links
    .filter(l => nodesData.find(n=>n.id===l.from) && nodesData.find(n=>n.id===l.to))
    .map(l=>({...l}));

  if(nodesData.length===0){
    svg.append('text')
      .attr('x', width/2).attr('y', height/2)
      .attr('text-anchor','middle')
      .attr('fill','#6b7286')
      .attr('font-size','13px')
      .text('Agrega cuentas para ver el mapa de relaciones.');
    renderLegend([]);
    return;
  }

  const usedCats = Array.from(new Set(nodesData.map(n=>n.category||'otro')));
  renderLegend(usedCats);

  simulation = d3.forceSimulation(nodesData)
    .force('link', d3.forceLink(linksData).id(d=>d.id).distance(d=> d.type==='owner'?90:130).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-260))
    .force('center', d3.forceCenter(width/2, height/2))
    .force('collide', d3.forceCollide(34));

  const link = g.append('g').selectAll('line')
    .data(linksData).enter().append('line')
    .attr('class', d=> 'glink' + (d.type==='cross' ? ' cross':''))
    .attr('marker-end','url(#arrowhead)');

  const linkLabel = g.append('g').selectAll('text')
    .data(linksData.filter(d=>d.label && d.type==='cross')).enter().append('text')
    .attr('class','glink-label')
    .text(d=>d.label);

  const node = g.append('g').selectAll('g')
    .data(nodesData).enter().append('g')
    .attr('class','gnode')
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended))
    .on('click', (event, d)=>{ openDetailModal(d.id, d.type); });

  node.append('circle')
    .attr('r', d=> d.type==='email' ? 20 : 15)
    .attr('fill', d=> colorFor(d.category) + (d.type==='email' ? '' : ''))
    .attr('fill-opacity', d=> d.type==='email' ? 0.9 : 0.85)
    .attr('stroke', d=> colorFor(d.category))
    .attr('stroke-width', d=> d.type==='email' ? 2 : 1.5);

  node.append('text')
    .attr('text-anchor','middle')
    .attr('dy', d=> d.type==='email' ? 32 : 26)
    .text(d=> truncateLabel(d.type==='email' ? d.address : d.name));

  simulation.on('tick', ()=>{
    link
      .attr('x1', d=>d.source.x).attr('y1', d=>d.source.y)
      .attr('x2', d=>d.target.x).attr('y2', d=>d.target.y);
    linkLabel
      .attr('x', d=> (d.source.x+d.target.x)/2)
      .attr('y', d=> (d.source.y+d.target.y)/2 - 4);
    node.attr('transform', d=>`translate(${d.x},${d.y})`);
  });

  function dragstarted(event, d){
    if(!event.active) simulation.alphaTarget(0.25).restart();
    d.fx = d.x; d.fy = d.y;
  }
  function dragged(event, d){ d.fx = event.x; d.fy = event.y; }
  function dragended(event, d){
    if(!event.active) simulation.alphaTarget(0);
    d.fx = null; d.fy = null;
  }
}

function truncateLabel(s){
  s = s||'';
  return s.length>16 ? s.slice(0,15)+'…' : s;
}

function renderLegend(cats){
  const el = document.getElementById('graph-legend');
  if(cats.length===0){ el.innerHTML=''; return; }
  el.innerHTML = cats.map(c=>`
    <div class="legend-item"><span class="legend-dot" style="background:${colorFor(c)}"></span>${escapeHtml(cap(c))}</div>
  `).join('');
}

window.addEventListener('resize', ()=>{
  if(!document.getElementById('view-graph').classList.contains('hidden')) renderGraph();
});

// ============================================================
// RECOMMENDATIONS  (algoritmo inteligente de optimizaci\u00F3n)
// ============================================================

function generateRecommendations() {
  const recs = [];
  var i, j, k, a, e, l, key, nameNorm, aNorm, emailUser, other, links, owners, linkedIds;

  // --- 1. Duplicate account names (mismo nombre Y misma categoria) ---
  var dupKeyMap = {};
  for (i = 0; i < VAULT.accounts.length; i++) {
    a = VAULT.accounts[i];
    key = a.name.toLowerCase().trim() + '|' + (a.category || 'otro').toLowerCase().trim();
    if (!dupKeyMap[key]) dupKeyMap[key] = [];
    dupKeyMap[key].push(a);
  }
  var dupKeys = Object.keys(dupKeyMap);
  for (i = 0; i < dupKeys.length; i++) {
    var group = dupKeyMap[dupKeys[i]];
    if (group.length > 1) {
      owners = [];
      for (j = 0; j < group.length; j++) {
        links = VAULT.links.filter(function(l) { return l.to === group[j].id && l.type === 'owner'; });
        for (k = 0; k < links.length; k++) {
          var ownerEmail = findNodeById(links[k].from);
          if (ownerEmail && ownerEmail.type === 'email') owners.push(ownerEmail.address);
        }
      }
      recs.push({
        type: 'duplicate_accounts',
        severity: 'warning',
        icon: '\u26A0\uFE0F',
        title: 'Cuentas duplicadas: "' + group[0].name + '"',
        desc: 'Hay ' + group.length + ' cuentas con el mismo nombre y categoría "' + cap(group[0].category || 'otro') + '". ' +
          (owners.length > 0 ? 'Están asociadas a: ' + owners.join(', ') + '. ' : '') +
          'Considera consolidarlas en una sola.',
        items: group.map(function(g) { return { id: g.id, name: g.name, type: 'account' }; })
      });
    }
  }

  // --- 2. Similar names (substring) across accounts (misma categoria) ---
  var accList = VAULT.accounts;
  for (i = 0; i < accList.length; i++) {
    for (j = i + 1; j < accList.length; j++) {
      nameNorm = accList[i].name.toLowerCase().trim();
      aNorm = accList[j].name.toLowerCase().trim();
      if (nameNorm !== aNorm && (nameNorm.includes(aNorm) || aNorm.includes(nameNorm))) {
        if ((accList[i].category || 'otro') !== (accList[j].category || 'otro')) continue;
        var already = false;
        for (k = 0; k < recs.length; k++) {
          if (recs[k].type === 'similar_accounts') {
            var ids = recs[k].items.map(function(it) { return it.id; });
            if (ids.indexOf(accList[i].id) >= 0 && ids.indexOf(accList[j].id) >= 0) { already = true; break; }
          }
        }
        if (!already) {
          recs.push({
            type: 'similar_accounts',
            severity: 'suggestion',
            icon: '\uD83D\uDD0D',
            title: 'Nombres similares: "' + accList[i].name + '" y "' + accList[j].name + '"',
            desc: 'Estas cuentas tienen nombres parecidos y son de la misma categoria. Verifica si son el mismo servicio y consolida.',
            items: [
              { id: accList[i].id, name: accList[i].name, type: 'account' },
              { id: accList[j].id, name: accList[j].name, type: 'account' }
            ]
          });
        }
      }
    }
  }

  // --- 3. Orphan emails (no linked accounts) ---
  for (i = 0; i < VAULT.emails.length; i++) {
    e = VAULT.emails[i];
    links = VAULT.links.filter(function(l) { return l.from === e.id; });
    if (links.length === 0) {
      recs.push({
        type: 'orphan_email',
        severity: 'info',
        icon: '\uD83D\uDCE7',
        title: 'Correo sin cuentas vinculadas',
        desc: '"' + e.address + '" no tiene cuentas vinculadas. Si ya no se usa, considera eliminar el registro.',
        items: [{ id: e.id, name: e.address, type: 'email' }]
      });
    }
  }

  // --- 4. Unlinked accounts (no owner email) ---
  for (i = 0; i < VAULT.accounts.length; i++) {
    a = VAULT.accounts[i];
    links = VAULT.links.filter(function(l) { return l.to === a.id && l.type === 'owner'; });
    if (links.length === 0) {
      recs.push({
        type: 'unlinked_account',
        severity: 'info',
        icon: '\uD83D\uDD17',
        title: 'Cuenta sin correo due\u00F1o',
        desc: '"' + a.name + '" no tiene un correo due\u00F1o asignado. Vincularlo a un correo ayuda a mantener el orden.',
        items: [{ id: a.id, name: a.name, type: 'account' }]
      });
    }
  }

  // --- 5. Suggest link: email local-part matches account username ---
  for (i = 0; i < VAULT.emails.length; i++) {
    e = VAULT.emails[i];
    emailUser = e.address.split('@')[0].toLowerCase().trim();
    if (!emailUser) continue;
    for (j = 0; j < VAULT.accounts.length; j++) {
      a = VAULT.accounts[j];
      var aUser = (a.username || '').toLowerCase().trim();
      if (aUser && (aUser.indexOf(emailUser) >= 0 || emailUser.indexOf(aUser) >= 0)) {
        var isLinked = VAULT.links.some(function(l) {
          return (l.from === e.id && l.to === a.id) || (l.from === a.id && l.to === e.id);
        });
        if (!isLinked && aUser.length > 2) {
          var alreadySuggested = false;
          for (k = 0; k < recs.length; k++) {
            if (recs[k].type === 'suggest_link') {
              var recIds = recs[k].items.map(function(it) { return it.id; });
              if (recIds.indexOf(e.id) >= 0 && recIds.indexOf(a.id) >= 0) { alreadySuggested = true; break; }
            }
          }
          if (!alreadySuggested) {
            recs.push({
              type: 'suggest_link',
              severity: 'suggestion',
              icon: '\uD83D\uDCAC',
              title: 'Posible v\u00EDnculo: ' + e.address + ' \u2192 ' + a.name,
              desc: 'El usuario de "' + a.name + '" coincide con el correo "' + e.address + '". Podr\u00EDan estar vinculados.',
              items: [
                { id: e.id, name: e.address, type: 'email' },
                { id: a.id, name: a.name, type: 'account' }
              ]
            });
          }
        }
      }
    }
  }

  // --- 6. Same username across different services ---
  var userMap = {};
  for (i = 0; i < VAULT.accounts.length; i++) {
    a = VAULT.accounts[i];
    if (a.username) {
      key = a.username.toLowerCase().trim();
      if (!userMap[key]) userMap[key] = [];
      userMap[key].push(a);
    }
  }
  var userKeys = Object.keys(userMap);
  for (i = 0; i < userKeys.length; i++) {
    var group = userMap[userKeys[i]];
    if (group.length > 1) {
      var ownerSet = {};
      for (j = 0; j < group.length; j++) {
        links = VAULT.links.filter(function(l) { return l.to === group[j].id && l.type === 'owner'; });
        for (k = 0; k < links.length; k++) {
          var owner = findNodeById(links[k].from);
          if (owner && owner.type === 'email') ownerSet[owner.address] = true;
        }
      }
      var ownerCount = Object.keys(ownerSet).length;
      if (ownerCount > 1) {
        recs.push({
          type: 'same_username_multi_owner',
          severity: 'warning',
          icon: '\uD83D\uDC64',
          title: 'Mismo usuario en varios servicios con due\u00F1os distintos',
          desc: 'El usuario "' + userKeys[i] + '" se usa en ' + group.length + ' servicios pero est\u00E1n vinculados a ' +
            ownerCount + ' correos diferentes. Revisa si deber\u00EDan estar bajo un mismo correo.',
          items: group.map(function(g) { return { id: g.id, name: g.name, type: 'account' }; })
        });
      }
    }
  }

  // --- 7. Emails with same domain could be consolidated ---
  var domainMap = {};
  for (i = 0; i < VAULT.emails.length; i++) {
    e = VAULT.emails[i];
    var parts = e.address.split('@');
    if (parts.length === 2) {
      key = parts[1].toLowerCase();
      if (!domainMap[key]) domainMap[key] = [];
      domainMap[key].push(e);
    }
  }
  var domainKeys = Object.keys(domainMap);
  for (i = 0; i < domainKeys.length; i++) {
    var domain = domainKeys[i];
    var emails = domainMap[domain];
    if (emails.length > 1) {
      var linkedAccounts = {};
      for (j = 0; j < emails.length; j++) {
        links = VAULT.links.filter(function(l) { return l.from === emails[j].id; });
        for (k = 0; k < links.length; k++) {
          var target = findNodeById(links[k].to);
          if (target && target.type === 'account') {
            if (!linkedAccounts[target.name]) linkedAccounts[target.name] = [];
            linkedAccounts[target.name].push(emails[j].address);
          }
        }
      }
      var colliding = Object.keys(linkedAccounts).filter(function(n) { return linkedAccounts[n].length > 1; });
      if (colliding.length > 0) {
        recs.push({
          type: 'domain_consolidation',
          severity: 'suggestion',
          icon: '\uD83D\uDCE8',
          title: 'M\u00FAltiples correos en ' + domain,
          desc: 'Tienes ' + emails.length + ' correos en ' + domain + ' (' +
            emails.map(function(em) { return em.address; }).join(', ') +
            '). ' + colliding.length + ' servicio(s) tienen cuentas en varios de estos correos. Considera consolidar.',
          items: emails.map(function(em) { return { id: em.id, name: em.address, type: 'email' }; })
        });
      }
    }
  }

  // Sort: warnings first, then suggestions, then info
  recs.sort(function(a, b) {
    var order = { warning: 0, suggestion: 1, info: 2 };
    return (order[a.severity] || 99) - (order[b.severity] || 99);
  });

  return recs;
}

function renderRecommendations() {
  var el = document.getElementById('rec-list');
  var summary = document.getElementById('rec-summary');
  var recs = generateRecommendations();

  if (recs.length === 0) {
    el.innerHTML = '<div class="rec-empty">\u2705 No se encontraron oportunidades de optimizaci\u00F3n. \u00A1Tu b\u00F3veda est\u00E1 en orden!</div>';
    summary.textContent = '0 recomendaciones';
    return;
  }

  var warningCount = 0, suggestionCount = 0, infoCount = 0;
  for (var i = 0; i < recs.length; i++) {
    if (recs[i].severity === 'warning') warningCount++;
    else if (recs[i].severity === 'suggestion') suggestionCount++;
    else infoCount++;
  }

  summary.textContent = warningCount + ' cr\u00EDtica' + (warningCount !== 1 ? 's' : '') +
    (suggestionCount ? ', ' + suggestionCount + ' sugerencia' + (suggestionCount !== 1 ? 's' : '') : '') +
    (infoCount ? ', ' + infoCount + ' aviso' + (infoCount !== 1 ? 's' : '') : '');

  el.innerHTML = recs.map(function(rec) {
    var sevClass = 'rec-severity-' + rec.severity;
    var chipsHtml = rec.items.map(function(it) {
      var label = it.name.length > 24 ? it.name.slice(0, 23) + '\u2026' : it.name;
      return '<span class="rec-chip" data-id="' + it.id + '" data-type="' + it.type + '">' +
        escapeHtml(label) + '</span>';
    }).join('');
    return '<div class="rec-card ' + sevClass + '">' +
      '<div class="rec-card-header">' +
        '<span class="rec-icon">' + rec.icon + '</span>' +
        '<div><div class="rec-card-title">' + escapeHtml(rec.title) + '</div>' +
        '<p class="rec-card-desc">' + escapeHtml(rec.desc) + '</p></div>' +
      '</div>' +
      (chipsHtml ? '<div class="rec-card-items">' + chipsHtml + '</div>' : '') +
    '</div>';
  }).join('');

  el.querySelectorAll('.rec-chip').forEach(function(chip) {
    chip.addEventListener('click', function() {
      openDetailModal(chip.dataset.id, chip.dataset.type);
    });
  });

  document.getElementById('btn-reanalyze').addEventListener('click', function() {
    renderRecommendations();
  });
}
