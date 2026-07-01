// Auto-detect API URL from current page origin
document.getElementById('login-api-url').value = window.location.origin;

// ============================================================
// STATE
// ============================================================
let VAULT = { emails: [], accounts: [], links: [], categories: [], todos: [] };
let MASTER_KEY = null;     // CryptoKey, never serialized
let MASTER_SALT = null;    // Uint8Array, stored alongside ciphertext
let isNewVault = true;
let activeFileBaseName = "boveda";

// ============================================================
// PANEL TOGGLE STATE
// ============================================================
let panelCollapsed = false;

// Toggle panel visibility
document.getElementById('btn-toggle-panel').addEventListener('click', () => {
  const tabs = document.querySelector('.tabs');
  const main = document.querySelector('.main');
  panelCollapsed = !panelCollapsed;
  
  if (panelCollapsed) {
    tabs.classList.add('collapsed');
    main.classList.add('panel-hidden');
  } else {
    tabs.classList.remove('collapsed');
    main.classList.remove('panel-hidden');
  }
  
  // Guardar preferencia en localStorage
  localStorage.setItem('panelCollapsed', panelCollapsed);
  
  // Disparar resize para que el grafo se ajuste al nuevo espacio
  setTimeout(() => {
    window.dispatchEvent(new Event('resize'));
  }, 350);
});

// Restaurar estado del panel al cargar
window.addEventListener('load', () => {
  const savedState = localStorage.getItem('panelCollapsed');
  if (savedState === 'true') {
    panelCollapsed = true;
    const tabs = document.querySelector('.tabs');
    const main = document.querySelector('.main');
    tabs.classList.add('collapsed');
    main.classList.add('panel-hidden');
  }
});


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

// Categorías por defecto: solo se usan para crear una bóveda nueva o para
// migrar una bóveda vieja que no tenía VAULT.categories todavía.
const DEFAULT_CATEGORIES = [
  { id:"correo",        name:"Correo",         color:"#5b8cff" },
  { id:"hosting",        name:"Hosting",        color:"#3ecf8e" },
  { id:"base de datos",  name:"Base de datos",  color:"#9b6bff" },
  { id:"social",         name:"Social",         color:"#e2a23a" },
  { id:"mensajería",     name:"Mensajería",     color:"#3ab0e2" },
  { id:"ia",             name:"IA",             color:"#e25c9e" },
  { id:"banco",          name:"Banco",          color:"#e25c5c" },
  { id:"monitoreo",      name:"Monitoreo",      color:"#5cc9c0" },
  { id:"otro",           name:"Otro",           color:"#9aa1b4" }
];

// Valida y normaliza la forma de VAULT después de descifrar un archivo.
// Si falta o viene mal alguno de los arrays esperados, se reemplaza por uno
// vacío en vez de dejar que el resto de la app falle con un error críptico.
// Devuelve true si la forma era válida, false si tuvo que corregir algo
// (la app sigue funcionando, pero conviene avisarle al usuario).
function ensureVaultShape(){
  let wasValid = true;
  if(typeof VAULT !== 'object' || VAULT === null){
    VAULT = {};
    wasValid = false;
  }
  if(!Array.isArray(VAULT.emails)){ VAULT.emails = []; wasValid = false; }
  if(!Array.isArray(VAULT.accounts)){ VAULT.accounts = []; wasValid = false; }
  if(!Array.isArray(VAULT.links)){ VAULT.links = []; wasValid = false; }
  if(!Array.isArray(VAULT.categories)){ VAULT.categories = []; wasValid = false; }
  if(!Array.isArray(VAULT.todos)){ VAULT.todos = []; wasValid = false; }
  return wasValid;
}

// Asegura que VAULT.categories exista y tenga al menos "otro" y "correo".
// Se llama cada vez que se crea o abre una bóveda (nueva o vieja).
function ensureCategories(){
  if(!Array.isArray(VAULT.categories) || VAULT.categories.length===0){
    VAULT.categories = DEFAULT_CATEGORIES.map(c=>({...c}));
    return;
  }
  // Si por alguna razón faltara "otro" (categoría de respaldo), la agregamos.
  if(!VAULT.categories.some(c=>c.id==='otro')){
    VAULT.categories.push({ id:'otro', name:'Otro', color:'#9aa1b4' });
  }
}

function getCategories(){
  // Categorías que se pueden asignar a una cuenta (excluye "correo", que es
  // un tipo de nodo especial, no una categoría elegible).
  return VAULT.categories.filter(c=>c.id!=='correo');
}
function getCategoryById(id){
  return VAULT.categories.find(c=>c.id===id);
}
function colorFor(catId){
  const c = getCategoryById(catId);
  if(c) return c.color;
  const fallback = getCategoryById('otro');
  return fallback ? fallback.color : '#9aa1b4';
}
function nameForCategory(catId){
  const c = getCategoryById(catId);
  return c ? c.name : cap(catId||'otro');
}
function slugifyCategoryName(name){
  return name.trim().toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'') // quita tildes
    .replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'') || ('cat-'+Date.now());
}

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

// Also submit on Enter in master password field
masterPassInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    if (btnUnlock.style.display !== 'none') {
      btnUnlock.click();
    } else if (btnCreateNew.style.display !== 'none') {
      btnCreateNew.click();
    }
  }
});

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
  VAULT = { emails: [], accounts: [], links: [], categories: [], todos: [] };
  isNewVault = true;
  enterApp();
}

// Asegura que VAULT.todos exista como array. Se llama al abrir cualquier bóveda
// (nueva o vieja, esta última puede no tener el campo todavía).
function ensureTodos(){
  if(!Array.isArray(VAULT.todos)) VAULT.todos = [];
}

function enterApp(){
  const shapeWasValid = ensureVaultShape();
  ensureCategories();
  ensureTodos();
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
  if(!shapeWasValid){
    showCopyFeedback("⚠️ El archivo tenía un formato inesperado, se abrió de forma parcial");
  }
}

document.getElementById('btn-lock').addEventListener('click', async ()=>{
  if(!confirm("¿Bloquear la bóveda? Asegúrate de haber exportado los cambios recientes antes de continuar.")) return;
  MASTER_KEY=null; MASTER_SALT=null; VAULT={emails:[],accounts:[],links:[],categories:[],todos:[]};
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
    document.getElementById('view-tree').classList.toggle('hidden', target!=='tree');
    document.getElementById('view-categories').classList.toggle('hidden', target!=='categories');
    document.getElementById('view-todos').classList.toggle('hidden', target!=='todos');
    document.getElementById('view-recommend').classList.toggle('hidden', target!=='recommend');
    if(target==='graph') renderGraph();
    if(target==='tree') renderTree();
    if(target==='categories') renderCategories();
    if(target==='todos') renderTodos();
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
  const cats = getCategories().length;
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
  const cats = getCategories();
  const current = sel.value;
  sel.innerHTML = '<option value="">Todas las categorías</option>' +
    cats.map(c=>`<option value="${escapeHtml(c.id)}">${escapeHtml(c.name)}</option>`).join('');
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
          <span class="badge">${escapeHtml(nameForCategory(cat))}</span>
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
    // 1) Exact match
    const exact = VAULT.emails.find(
      e => e.id !== excludeId && e.address.toLowerCase() === nameNorm
    );
    if (exact) {
      results.push({ kind: 'exact', match: exact, label: 'Correo exacto: ' + exact.address });
    }
    // 2) Same domain
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
    // --- Account ---
    // 1) Exact name (case-insensitive)
    const exact = VAULT.accounts.find(
      a => a.id !== excludeId && a.name.toLowerCase() === nameNorm
    );
    if (exact) {
      results.push({ kind: 'exact', match: exact, label: 'Cuenta exacta: "' + exact.name + '"' });
    }
    // 2) Similar name (substring match)
    VAULT.accounts.forEach(a => {
      if (a.id !== excludeId && a.id !== (exact && exact.id)) {
        const aNorm = a.name.toLowerCase();
        if ((aNorm.includes(nameNorm) || nameNorm.includes(aNorm)) && aNorm !== nameNorm) {
          results.push({ kind: 'similar', match: a, label: 'Similar: "' + a.name + '"' });
        }
      }
    });
    // 3) Same username
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
  if(!document.getElementById('view-categories').classList.contains('hidden')) renderCategories();
  if(!document.getElementById('view-todos').classList.contains('hidden')) renderTodos();
}

// ============================================================
// PENDIENTES (TODOs): notas sueltas, opcionalmente ligadas a una cuenta
// ============================================================
// Nota de nombres: esto es VAULT.todos (lista global de pendientes/recordatorios).
// Es DISTINTO del campo account.notes / email.notes, que es el cuadro de texto
// libre que ya existía dentro del detalle de cada cuenta para apuntes privados
// de esa cuenta puntual. No conviene unificarlos: un pendiente tiene título,
// fecha y estado (resuelto o no); una nota de cuenta es solo un campo de texto.

function getTodoLinkedNode(todo){
  if(!todo.linkedId) return null;
  return getAllNodes().find(n=>n.id===todo.linkedId) || null;
}

function renderTodos(){
  ensureTodos();
  const wrap = document.getElementById('todo-list');
  const filter = document.getElementById('todos-filter').value;
  let items = VAULT.todos.slice().sort((a,b)=> (b.createdAt||0)-(a.createdAt||0));
  if(filter==='pending') items = items.filter(t=>!t.resolved);
  if(filter==='resolved') items = items.filter(t=>t.resolved);

  if(items.length===0){
    const msg = filter==='resolved' ? 'No hay pendientes resueltos todavía.'
              : filter==='pending' ? 'No tienes pendientes abiertos. 🎉'
              : 'No hay pendientes todavía. Usa "+ Nuevo pendiente" arriba.';
    wrap.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">${msg}</div>`;
    return;
  }

  wrap.innerHTML = items.map(t=>{
    const linked = getTodoLinkedNode(t);
    const linkedLabel = linked ? (linked.type==='email' ? linked.address : linked.name) : null;
    return `
      <div class="todo-card ${t.resolved?'resolved':''}" data-id="${escapeHtml(t.id)}">
        <div class="todo-card-top">
          <div class="todo-card-title">${escapeHtml(t.title)}</div>
          <span class="todo-badge ${t.resolved?'resolved':'pending'}">${t.resolved?'Resuelto':'Pendiente'}</span>
        </div>
        ${t.description ? `<div class="todo-card-desc">${escapeHtml(t.description)}</div>` : ''}
        ${linkedLabel ? `<div class="todo-card-link">🔗 ${escapeHtml(linkedLabel)}</div>` : ''}
        <div class="todo-card-actions">
          <button class="btn btn-sm" data-action="toggle" data-id="${escapeHtml(t.id)}">${t.resolved?'Marcar pendiente':'Marcar resuelto'}</button>
          <button class="btn btn-sm" data-action="edit" data-id="${escapeHtml(t.id)}">Editar</button>
          <button class="btn btn-sm btn-danger" data-action="delete" data-id="${escapeHtml(t.id)}">Borrar</button>
        </div>
      </div>`;
  }).join('');

  wrap.querySelectorAll('[data-action="toggle"]').forEach(btn=>{
    btn.addEventListener('click', ()=>toggleTodo(btn.dataset.id));
  });
  wrap.querySelectorAll('[data-action="edit"]').forEach(btn=>{
    btn.addEventListener('click', ()=>openTodoModal(btn.dataset.id));
  });
  wrap.querySelectorAll('[data-action="delete"]').forEach(btn=>{
    btn.addEventListener('click', ()=>deleteTodo(btn.dataset.id));
  });
}

document.getElementById('todos-filter').addEventListener('change', renderTodos);
document.getElementById('btn-add-todo').addEventListener('click', ()=>openTodoModal(null));

function toggleTodo(todoId){
  const t = VAULT.todos.find(x=>x.id===todoId);
  if(!t) return;
  t.resolved = !t.resolved;
  renderTodos();
  autosave();
}

function deleteTodo(todoId){
  const t = VAULT.todos.find(x=>x.id===todoId);
  if(!t) return;
  if(!confirm(`¿Borrar el pendiente "${t.title}"?`)) return;
  VAULT.todos = VAULT.todos.filter(x=>x.id!==todoId);
  renderTodos();
  autosave();
}

// Si existingId es null, se crea un pendiente nuevo. Si no, se edita ese pendiente.
// preselectLinkedId permite abrir el modal ya enlazado a una cuenta/correo en
// particular (se usa desde el botón "+ Pendiente" dentro del detalle de una cuenta).
function openTodoModal(existingId, preselectLinkedId, onClose){
  const existing = existingId ? VAULT.todos.find(x=>x.id===existingId) : null;
  const nodes = getAllNodes();
  const linkedValue = existing ? (existing.linkedId||'') : (preselectLinkedId||'');

  const overlay = document.createElement('div');
  overlay.className='modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <h2>${existing ? 'Editar pendiente' : 'Nuevo pendiente'}</h2>
      <div class="field">
        <label>Título</label>
        <input id="t-title" placeholder="Ej: Conectar Cloudinary" value="${existing?escapeHtml(existing.title):''}">
      </div>
      <div class="field">
        <label>Descripción (opcional)</label>
        <textarea id="t-desc" placeholder="Ej: No se puede acceder por bloqueo de Google, probar con otro correo">${existing?escapeHtml(existing.description||''):''}</textarea>
      </div>
      <div class="field">
        <label>Vincular a una cuenta o correo (opcional)</label>
        <select id="t-linked">
          <option value="">Sin vincular</option>
          ${nodes.map(n=>{
            const label = n.type==='email' ? `✉️ ${n.address}` : `🔑 ${n.name}`;
            return `<option value="${escapeHtml(n.id)}" ${linkedValue===n.id?'selected':''}>${escapeHtml(label)}</option>`;
          }).join('')}
        </select>
      </div>
      <div class="modal-actions">
        <button class="btn" id="t-cancel">Cancelar</button>
        <button class="btn btn-primary" id="t-save">Guardar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const closeAndReturn = ()=>{ overlay.remove(); if(onClose) onClose(); };
  overlay.querySelector('#t-cancel').addEventListener('click', closeAndReturn);
  overlay.addEventListener('click', (e)=>{ if(e.target===overlay) closeAndReturn(); });

  overlay.querySelector('#t-save').addEventListener('click', ()=>{
    const title = overlay.querySelector('#t-title').value.trim();
    if(!title){ alert('El título no puede estar vacío.'); return; }
    const description = overlay.querySelector('#t-desc').value.trim();
    const linkedId = overlay.querySelector('#t-linked').value || null;

    if(existing){
      existing.title = title;
      existing.description = description;
      existing.linkedId = linkedId;
    } else {
      VAULT.todos.push({
        id: uid(), title, description, linkedId,
        resolved: false, createdAt: Date.now()
      });
    }
    closeAndReturn();
    renderTodos();
    autosave();
  });
}

// ============================================================
// CATEGORIES: crear, editar, borrar
// ============================================================
function countAccountsInCategory(catId){
  return VAULT.accounts.filter(a=>(a.category||'otro')===catId).length;
}

function renderCategories(){
  const wrap = document.getElementById('category-list');
  const cats = getCategories();
  if(cats.length===0){
    wrap.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">No hay categorías todavía. Usa "+ Nueva categoría" arriba.</div>`;
    return;
  }
  wrap.innerHTML = cats.map(c=>{
    const n = countAccountsInCategory(c.id);
    const canDelete = c.id !== 'otro'; // "otro" es la categoría de respaldo, siempre debe existir
    return `
      <div class="cat-card" data-id="${escapeHtml(c.id)}">
        <div class="cat-card-top">
          <span class="swatch" style="background:${c.color}"></span>
          <span class="cat-card-name">${escapeHtml(c.name)}</span>
        </div>
        <div class="cat-card-count">${n} cuenta${n===1?'':'s'} usando esta categoría</div>
        <div class="cat-card-actions">
          <button class="btn btn-sm" data-action="edit" data-id="${escapeHtml(c.id)}">Editar</button>
          <button class="btn btn-sm btn-danger" data-action="delete" data-id="${escapeHtml(c.id)}" ${canDelete?'':'disabled title="Esta categoría no se puede borrar"'}>Borrar</button>
        </div>
      </div>`;
  }).join('');

  wrap.querySelectorAll('[data-action="edit"]').forEach(btn=>{
    btn.addEventListener('click', ()=>openCategoryModal(btn.dataset.id));
  });
  wrap.querySelectorAll('[data-action="delete"]').forEach(btn=>{
    btn.addEventListener('click', ()=>deleteCategory(btn.dataset.id));
  });
}

document.getElementById('btn-add-category').addEventListener('click', ()=>openCategoryModal(null));

// Si existingId es null, se crea una categoría nueva. Si no, se edita esa categoría.
function openCategoryModal(existingId){
  const existing = existingId ? getCategoryById(existingId) : null;
  const overlay = document.createElement('div');
  overlay.className='modal-overlay';
  const defaultColor = existing ? existing.color : '#5b8cff';
  overlay.innerHTML = `
    <div class="modal">
      <h2>${existing ? 'Editar categoría' : 'Nueva categoría'}</h2>
      <div class="field">
        <label>Nombre</label>
        <input id="c-name" placeholder="Ej: Render, Neon, Cloudinary..." value="${existing?escapeHtml(existing.name):''}">
      </div>
      <div class="field">
        <label>Color</label>
        <div style="display:flex;align-items:center;gap:10px;">
          <input id="c-color" type="color" value="${defaultColor}" style="width:46px;height:36px;padding:2px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);">
          <span style="font-size:12.5px;color:var(--text-muted);">Color que se usa en las tarjetas y mapas</span>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn" id="c-cancel">Cancelar</button>
        <button class="btn btn-primary" id="c-save">Guardar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('#c-cancel').addEventListener('click', ()=>overlay.remove());
  overlay.addEventListener('click', (e)=>{ if(e.target===overlay) overlay.remove(); });

  overlay.querySelector('#c-save').addEventListener('click', ()=>{
    const name = overlay.querySelector('#c-name').value.trim();
    if(!name){ alert('El nombre no puede estar vacío.'); return; }
    const color = overlay.querySelector('#c-color').value;

    if(existing){
      existing.name = name;
      existing.color = color;
    } else {
      let id = slugifyCategoryName(name);
      // evitar colisión de id con una categoría existente
      if(getCategoryById(id)){
        let i = 2;
        while(getCategoryById(`${id}-${i}`)) i++;
        id = `${id}-${i}`;
      }
      VAULT.categories.push({ id, name, color });
    }
    overlay.remove();
    renderCategories();
    renderAll();
    autosave();
  });
}

function deleteCategory(catId){
  if(catId==='otro'){ return; } // protegida
  const n = countAccountsInCategory(catId);
  const cat = getCategoryById(catId);
  const catName = cat ? cat.name : catId;
  const msg = n>0
    ? `"${catName}" tiene ${n} cuenta${n===1?'':'s'}. Si la borras, esa${n===1?'':'s'} cuenta${n===1?'':'s'} pasará${n===1?'':'n'} a la categoría "Otro". ¿Continuar?`
    : `¿Borrar la categoría "${catName}"?`;
  if(!confirm(msg)) return;

  // Reasignar cuentas afectadas a "otro"
  VAULT.accounts.forEach(a=>{
    if((a.category||'otro')===catId) a.category = 'otro';
  });
  VAULT.categories = VAULT.categories.filter(c=>c.id!==catId);

  renderCategories();
  renderAll();
  autosave();
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
            ${getCategories().map(c=>`<option value="${escapeHtml(c.id)}">${escapeHtml(c.name)}</option>`).join('')}
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
  const currentOwnerLink = VAULT.links.find(l=>l.to===id && l.type==='owner');
  const currentOwnerId = currentOwnerLink ? currentOwnerLink.from : '';

  ensureTodos();
  const nodeTodos = VAULT.todos.filter(t=>t.linkedId===id);
  const nodeTodosHtml = nodeTodos.length===0
    ? `<div style="font-size:12.5px;color:var(--text-muted);">Sin pendientes para esta cuenta.</div>`
    : nodeTodos.map(t=>`
      <div class="rel-item">
        <span class="${t.resolved?'todo-card resolved':''}" style="background:none;border:none;padding:0;">
          ${t.resolved?'✅':'🟡'} ${escapeHtml(t.title)}
        </span>
        <button class="x" data-todo-id="${t.id}" title="Editar pendiente">✎</button>
      </div>`).join('');

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
            ${getCategories().map(c=>
              `<option value="${escapeHtml(c.id)}" ${node.category===c.id?'selected':''}>${escapeHtml(c.name)}</option>`).join('')}
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
      ${node.type==='account' ? `
      <div class="field">
        <label>Correo dueño</label>
        <select id="d-owner">
          <option value="">— Ninguno —</option>
          ${VAULT.emails.map(e=>`<option value="${e.id}" ${currentOwnerId===e.id?'selected':''}>${escapeHtml(e.address)}</option>`).join('')}
        </select>
      </div>` : ''}
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

      <div class="field">
        <label>Pendientes de esta cuenta</label>
        <div id="d-todo-list">${nodeTodosHtml}</div>
        <button class="btn btn-sm" id="d-add-todo" type="button">+ Agregar pendiente</button>
      </div>

      <div class="modal-actions">
        <button class="btn btn-danger modal-actions-left" id="d-delete">Eliminar</button>
        <button class="btn" id="d-cancel">Cerrar</button>
        <button class="btn btn-primary" id="d-save">Guardar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('#d-add-todo').addEventListener('click', ()=>{
    overlay.remove();
    openTodoModal(null, id, ()=>openDetailModal(id, kind));
  });
  overlay.querySelectorAll('[data-todo-id]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      overlay.remove();
      openTodoModal(btn.dataset.todoId, null, ()=>openDetailModal(id, kind));
    });
  });

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
        // Actualizar correo dueño si cambió
        const newOwnerId = overlay.querySelector('#d-owner').value;
        const oldOwnerLink = VAULT.links.find(l=>l.to===id && l.type==='owner');
        if(newOwnerId){
          if(oldOwnerLink){
            if(oldOwnerLink.from !== newOwnerId){
              oldOwnerLink.from = newOwnerId;
            }
          } else {
            VAULT.links.push({ id: uid(), from: newOwnerId, to: id, type: 'owner', label: '' });
          }
        } else {
          if(oldOwnerLink){
            VAULT.links = VAULT.links.filter(l=>l.id !== oldOwnerLink.id);
          }
        }
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
    const alreadyLinked = VAULT.links.some(l=>
      (l.from===id && l.to===targetId) || (l.from===targetId && l.to===id)
    );
    if(alreadyLinked){
      showCopyFeedback("⚠️ Ya existe una conexión entre estas dos cuentas");
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

function slugCat(c){ return (c||'otro').toLowerCase().replace(/[^a-z0-9]+/g,'-'); }

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
  // d3.forceLink necesita las claves "source"/"target"; nuestros links usan "from"/"to",
  // así que las espejamos acá (sin esto, el grafo crasheaba apenas existía una relación).
  const linksData = VAULT.links
    .filter(l => nodesData.find(n=>n.id===l.from) && nodesData.find(n=>n.id===l.to))
    .map(l=>({...l, source:l.from, target:l.to}));

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

  // Filtros de "brillo neuronal" — uno por color de categoría usada (sutil, no protagonista)
  usedCats.forEach(cat=>{
    const filter = defs.append('filter')
      .attr('id', `glow-${slugCat(cat)}`)
      .attr('x','-150%').attr('y','-150%').attr('width','400%').attr('height','400%');
    filter.append('feGaussianBlur')
      .attr('in','SourceGraphic')
      .attr('stdDeviation', 2.6);
  });

  // Filtro de resplandor eléctrico para enlaces
  const electricFilter = defs.append('filter')
    .attr('id', 'electric-glow')
    .attr('x','-50%').attr('y','-50%').attr('width','200%').attr('height','200%');
  electricFilter.append('feGaussianBlur')
    .attr('in','SourceGraphic')
    .attr('stdDeviation', 1.8);

  // Mapa de adyacencia directa para resaltar dependencias al pasar el cursor
  const neighborMap = new Map(nodesData.map(n=>[n.id, new Set([n.id])]));
  linksData.forEach(l=>{
    neighborMap.get(l.from)?.add(l.to);
    neighborMap.get(l.to)?.add(l.from);
  });

  // Clustering por correo: cada correo + sus cuentas se ancla a un punto propio
  // del lienzo para que, con muchos correos, no se forme una sola maraña central.
  const emailIds = nodesData.filter(n=>n.type==='email').map(n=>n.id);
  const clusterOf = new Map();
  emailIds.forEach((id,i)=> clusterOf.set(id, i));
  linksData.forEach(l=>{
    if(l.type==='owner' && clusterOf.has(l.from)) clusterOf.set(l.to, clusterOf.get(l.from));
  });
  const clusterCount = Math.max(emailIds.length, 1);
  const cols = Math.ceil(Math.sqrt(clusterCount));
  const cellW = width / Math.max(cols,1);
  const rows = Math.ceil(clusterCount/cols);
  const cellH = height / Math.max(rows,1);
  const clusterCenters = emailIds.map((id,i)=>({
    x: cellW*(i%cols) + cellW/2,
    y: cellH*Math.floor(i/cols) + cellH/2
  }));
  nodesData.forEach(n=>{ n.cluster = clusterOf.get(n.id) ?? 0; });
  const clusterStrength = clusterCount > 4 ? 0.12 : 0; // solo activa si hay varios correos

  simulation = d3.forceSimulation(nodesData)
    .force('link', d3.forceLink(linksData).id(d=>d.id).distance(d=> d.type==='owner'?80:120).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(width/2, height/2))
    .force('collide', d3.forceCollide(28))
    .force('clusterX', d3.forceX(d=> clusterCenters[d.cluster]?.x ?? width/2).strength(clusterStrength))
    .force('clusterY', d3.forceY(d=> clusterCenters[d.cluster]?.y ?? height/2).strength(clusterStrength));

  const link = g.append('g').selectAll('line')
    .data(linksData).enter().append('line')
    .attr('class', d=> 'glink' + (d.type==='cross' ? ' cross':''))
    .attr('marker-end','url(#arrowhead)')
    .style('animation-delay', (d,i)=> ((i*0.18) % 3.2).toFixed(2)+'s');

  const linkLabel = g.append('g').selectAll('text')
    .data(linksData.filter(d=>d.label && d.type==='cross')).enter().append('text')
    .attr('class','glink-label')
    .text(d=>d.label);

  const node = g.append('g').selectAll('g')
    .data(nodesData).enter().append('g')
    .attr('class','gnode')
    .style('animation-delay', (d,i)=> ((i*0.31) % 3.8).toFixed(2)+'s')
    .call(d3.drag()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended))
    .on('click', (event, d)=>{ openDetailModal(d.id, d.type); })
    .on('mouseenter', (event, d)=> highlightNode(d.id))
    .on('mouseleave', ()=> clearHighlight());

  // Halo brillante pulsante (la "neurona") detrás del círculo principal — sutil, no protagonista
  node.append('circle')
    .attr('class','halo')
    .attr('r', d=> (d.type==='email' ? 16 : 12) + 5)
    .attr('fill', d=> colorFor(d.category))
    .attr('filter', d=> `url(#glow-${slugCat(d.category)})`)
    .style('animation-delay', (d,i)=> ((i*0.53) % 2.6).toFixed(2)+'s');

  node.append('circle')
    .attr('class','core')
    .attr('r', d=> d.type==='email' ? 16 : 12)
    .attr('fill', d=> colorFor(d.category))
    .attr('fill-opacity', d=> d.type==='email' ? 0.92 : 0.86)
    .attr('stroke', d=> colorFor(d.category))
    .attr('stroke-width', d=> d.type==='email' ? 2 : 1.5);

  node.append('text')
    .attr('text-anchor','middle')
    .attr('dy', d=> d.type==='email' ? 28 : 23)
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

  // Resalta un nodo y sus dependencias directas; atenúa el resto del mapa
  function highlightNode(id){
    const related = neighborMap.get(id) || new Set([id]);
    node.classed('dimmed', d=> !related.has(d.id)).classed('highlighted', d=> related.has(d.id));
    link.classed('dimmed', d=> !(d.from===id || d.to===id)).classed('highlighted', d=> (d.from===id || d.to===id));
    linkLabel.classed('dimmed', d=> !(d.from===id || d.to===id)).classed('highlighted', d=> (d.from===id || d.to===id));
  }
  function clearHighlight(){
    node.classed('dimmed', false).classed('highlighted', false);
    link.classed('dimmed', false).classed('highlighted', false);
    linkLabel.classed('dimmed', false).classed('highlighted', false);
  }

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

// Estimación simple del ancho en px de un texto en la fuente del árbol (~12px),
// suficiente para ubicar la etiqueta de categoría sin solaparse con el nombre.
function estimateTextWidth(s){
  return (s||'').length * 6.6;
}

function renderLegend(cats){
  const el = document.getElementById('graph-legend');
  if(cats.length===0){ el.innerHTML=''; return; }
  el.innerHTML = cats.map(c=>`
    <div class="legend-item"><span class="legend-dot" style="background:${colorFor(c)}"></span>${escapeHtml(nameForCategory(c))}</div>
  `).join('');
}

window.addEventListener('resize', ()=>{
  if(!document.getElementById('view-graph').classList.contains('hidden')) renderGraph();
  if(!document.getElementById('view-tree').classList.contains('hidden')) renderTree();
});

// ============================================================
// TREE VIEW (jerarquía plana y sobria: correo -> cuentas)
// Pensada para ubicar algo rápido cuando hay muchos correos:
// sin glow, sin física, colapsable y con buscador.
// ============================================================
let treeRoot = null;
let treeScale = 1;
const treeCollapsed = new Set(); // ids de correos colapsados

function buildTreeHierarchy(){
  const accountsByOwner = new Map();
  const ownedAccountIds = new Set();
  VAULT.links.filter(l=>l.type==='owner').forEach(l=>{
    ownedAccountIds.add(l.to);
    if(!accountsByOwner.has(l.from)) accountsByOwner.set(l.from, []);
    accountsByOwner.get(l.from).push(l.to);
  });

  const accountNode = a => ({ id:a.id, type:'account', name:a.name, category:a.category||'otro', username:a.username, children:[] });

  const emailChildren = VAULT.emails
    .slice()
    .sort((a,b)=> a.address.localeCompare(b.address))
    .map(e=>{
      const accIds = accountsByOwner.get(e.id) || [];
      const accs = accIds
        .map(id=> VAULT.accounts.find(a=>a.id===id))
        .filter(Boolean)
        .sort((a,b)=> a.name.localeCompare(b.name))
        .map(accountNode);
      return { id:e.id, type:'email', name:e.address, category:'correo', children: accs };
    });

  const orphanAccs = VAULT.accounts
    .filter(a=> !ownedAccountIds.has(a.id))
    .sort((a,b)=> a.name.localeCompare(b.name))
    .map(accountNode);

  const children = [...emailChildren];
  if(orphanAccs.length) children.push({ id:'__sin_correo__', type:'group', name:'Sin correo asignado', children: orphanAccs });

  return { id:'__root__', type:'root', name:'Bóveda', children };
}

function renderTree(){
  const svg = d3.select('#tree-svg');
  svg.selectAll('*').remove();
  const wrap = document.getElementById('tree-wrap');
  const width = wrap.clientWidth;

  const data = buildTreeHierarchy();
  if(data.children.length===0){
    svg.attr('width', width).attr('height', 200);
    svg.append('text').attr('x',20).attr('y',40).attr('fill','#6b7286').attr('font-size','13px')
      .text('Agrega correos y cuentas para ver el árbol.');
    return;
  }

  const root = d3.hierarchy(data);
  root.each(d=>{ if(treeCollapsed.has(d.data.id) && d.children){ d._children = d.children; d.children = null; } });
  treeRoot = root;

  const dx = 30;
  const dy = 260;
  const layout = d3.tree().nodeSize([dx, dy]);

  function update(){
    layout(treeRoot);
    let minX = Infinity, maxX = -Infinity, maxY = 0;
    treeRoot.each(d=>{ minX=Math.min(minX,d.x); maxX=Math.max(maxX,d.x); maxY=Math.max(maxY,d.y); });
    const height = Math.max(maxX - minX + dx*2, 200);
    const svgWidth = Math.max(maxY + dy + 160, width);
    svg.attr('width', svgWidth).attr('height', height);
    svg.style('transform', `scale(${treeScale})`);
    const offsetX = -minX + dx;

    const g = svg.selectAll('g.tree-g').data([null]);
    const gEnter = g.enter().append('g').attr('class','tree-g');
    const gMerged = gEnter.merge(g).attr('transform', `translate(20,${offsetX})`);

    const linkGen = d3.linkHorizontal().x(d=>d.y).y(d=>d.x);

    const links = gMerged.selectAll('path.tlink').data(treeRoot.links(), d=> d.target.data.id);
    links.exit().remove();
    links.enter().append('path').attr('class','tlink').merge(links)
      .attr('d', linkGen);

    const nodes = gMerged.selectAll('g.tnode').data(treeRoot.descendants(), d=> d.data.id);
    nodes.exit().remove();

    const nodeEnter = nodes.enter().append('g').attr('class','tnode');
    nodeEnter.append('circle');
    nodeEnter.append('text').attr('class','tcaret');
    nodeEnter.append('text').attr('class','tlabel');
    nodeEnter.append('text').attr('class','tsub');

    const nodeMerged = nodeEnter.merge(nodes)
      .attr('transform', d=>`translate(${d.y},${d.x})`)
      .attr('class', d=> 'tnode' + (d.children||d._children ? ' thasChildren':''))
      .style('cursor', d=> (d.data.children && d.data.children.length) ? 'pointer' : 'default')
      .on('click', (event,d)=>{
        const hasKids = (d.data.children && d.data.children.length>0);
        if((d.data.type==='email' || d.data.type==='group') && hasKids){
          if(d.children){ d._children = d.children; d.children = null; treeCollapsed.add(d.data.id); }
          else if(d._children){ d.children = d._children; d._children = null; treeCollapsed.delete(d.data.id); }
          update();
        } else if(d.data.type==='account' || d.data.type==='email'){
          openDetailModal(d.data.id, d.data.type);
        }
      });

    nodeMerged.select('circle')
      .attr('r', d=> d.data.type==='root' ? 0 : (d.data.type==='email' ? 6 : 4.5))
      .attr('fill', d=> d.data.type==='group' ? '#6b7286' : colorFor(d.data.category))
      .attr('stroke', 'var(--bg)');

    nodeMerged.select('.tcaret')
      .attr('x', d=> (d.data.type==='email'||d.data.type==='group') ? -14 : 0)
      .attr('dy', 4)
      .text(d=>{
        if(!(d.data.type==='email'||d.data.type==='group')) return '';
        const has = (d.data.children && d.data.children.length>0);
        if(!has) return '';
        return d.children ? '\u25BE' : '\u25B8';
      });

    nodeMerged.select('.tlabel')
      .attr('x', 12)
      .attr('dy', 4)
      .text(d=> d.data.type==='root' ? '' : d.data.name);

    nodeMerged.select('.tsub')
      .attr('x', d=> d.data.type==='account' ? 12 + estimateTextWidth(d.data.name) + 10 : 0)
      .attr('dy', 4)
      .text(d=> d.data.type==='account' ? nameForCategory(d.data.category) : '');
  }

  update();

  document.getElementById('tree-zoom-in').onclick = ()=>{ treeScale = Math.min(treeScale*1.2, 2.5); svg.style('transform',`scale(${treeScale})`); };
  document.getElementById('tree-zoom-out').onclick = ()=>{ treeScale = Math.max(treeScale*0.8, 0.4); svg.style('transform',`scale(${treeScale})`); };
  document.getElementById('tree-zoom-reset').onclick = ()=>{ treeScale = 1; svg.style('transform','scale(1)'); };

  document.getElementById('tree-expand-all').onclick = ()=>{ treeCollapsed.clear(); renderTree(); };
  document.getElementById('tree-collapse-all').onclick = ()=>{
    treeRoot.children?.forEach(d=>{ if(d.data.type==='email'||d.data.type==='group') treeCollapsed.add(d.data.id); });
    renderTree();
  };

  const searchInput = document.getElementById('tree-search');
  searchInput.oninput = ()=>{
    const q = searchInput.value.toLowerCase().trim();
    if(!q){
      d3.selectAll('.tnode').classed('tdim', false).classed('tmatch', false);
      d3.selectAll('.tlink').classed('tdim', false);
      return;
    }
    let changed = false;
    treeRoot.each(d=>{
      if(d._children){
        const matchInside = d._children.some(c => (c.data.name||'').toLowerCase().includes(q));
        if(matchInside){ d.children = d._children; d._children = null; treeCollapsed.delete(d.data.id); changed = true; }
      }
    });
    if(changed){ update(); }
    d3.selectAll('.tnode').each(function(d){
      const match = d.data.type!=='root' && (d.data.name||'').toLowerCase().includes(q);
      d3.select(this).classed('tmatch', match).classed('tdim', !match);
    });
    d3.selectAll('.tlink').classed('tdim', true);
  };
}



// ============================================================
// RECOMMENDATIONS  (algoritmo inteligente de optimización)
// ============================================================

function generateRecommendations() {
  const recs = [];
  var i, j, k, a, e, l, key, nameNorm, aNorm, emailUser, other, links, owners, linkedIds;

  // --- 1. Duplicate account names (mismo nombre Y misma categoría) ---
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
        desc: 'Hay ' + group.length + ' cuentas con el mismo nombre y categor\u00EDa "' + cap(group[0].category || 'otro') + '". ' +
          (owners.length > 0 ? 'Est\u00E1n asociadas a: ' + owners.join(', ') + '. ' : '') +
          'Considera consolidarlas en una sola.',
        items: group.map(function(g) { return { id: g.id, name: g.name, type: 'account' }; })
      });
    }
  }

  // --- 2. Similar names (substring) across accounts (misma categoría) ---
  var accList = VAULT.accounts;
  for (i = 0; i < accList.length; i++) {
    for (j = i + 1; j < accList.length; j++) {
      nameNorm = accList[i].name.toLowerCase().trim();
      aNorm = accList[j].name.toLowerCase().trim();
      if (nameNorm !== aNorm && (nameNorm.includes(aNorm) || aNorm.includes(nameNorm))) {
        // Solo sugerir si son de la misma categoría
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
            desc: 'Estas cuentas tienen nombres parecidos y son de la misma categor\u00EDa. Verifica si son el mismo servicio y consolida.',
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
          // Check not already suggested
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
      // Get unique owner emails
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
      // Get accounts linked to each
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
            '). ' + colliding.length + ' servicio(s) tienen cuentas en varios de estos correos. ' +
            'Considera consolidar.',
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

  // Click handlers for chips
  el.querySelectorAll('.rec-chip').forEach(function(chip) {
    chip.addEventListener('click', function() {
      openDetailModal(chip.dataset.id, chip.dataset.type);
    });
  });

  // Re-analyze button
  document.getElementById('btn-reanalyze').addEventListener('click', function() {
    renderRecommendations();
  });
}
