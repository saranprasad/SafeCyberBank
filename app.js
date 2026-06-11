// SAFE CYBER BANK - app.js
const STORAGE_KEY = 'scb_state_v1';
const SESSION_KEY = 'scb_current';

const defaultState = {
  users: [
    { username: 'saran', password: 'saran2026', role: 'client', balance: 1000, transactions: [] },
    { username: 'naveen', password: 'naveen2026', role: 'client', balance: 1000, transactions: [] },
    { username: 'prasanna', password: 'prasanna2026', role: 'client', balance: 1000, transactions: [] },
    { username: 'administrator', password: 'admin2026', role: 'admin', balance: 0, transactions: [] }
  ]
};

function loadState(){
  const raw = localStorage.getItem(STORAGE_KEY);
  if(!raw){
    localStorage.setItem(STORAGE_KEY, JSON.stringify(defaultState));
    return JSON.parse(JSON.stringify(defaultState));
  }
  try { return JSON.parse(raw); } catch(e){ console.error('corrupt state, resetting', e); localStorage.setItem(STORAGE_KEY, JSON.stringify(defaultState)); return JSON.parse(JSON.stringify(defaultState)); }
}

function saveState(state){ localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); }

let state = loadState();
let currentUser = null;

// Helpers
function findUser(username){ return state.users.find(u => u.username === username); }
function formatMoney(n){ return Number(n).toFixed(2); }
function now(){ return new Date().toISOString(); }

// Auth
function authenticate(username, password){ const u = findUser(username); if(!u) return null; if(u.password !== password) return null; return u; }

// Session
function setCurrent(username){ sessionStorage.setItem(SESSION_KEY, username); currentUser = findUser(username); }
function clearCurrent(){ sessionStorage.removeItem(SESSION_KEY); currentUser = null; }
function restoreSession(){ const username = sessionStorage.getItem(SESSION_KEY); if(username){ currentUser = findUser(username); } }

// UI elements
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const welcomeEl = document.getElementById('welcome');
const balanceEl = document.getElementById('balance');
const debitList = document.getElementById('debit-list');
const creditList = document.getElementById('credit-list');
const logoutBtn = document.getElementById('logout-btn');
const sendBtn = document.getElementById('send-money-btn');
const addCreditBtn = document.getElementById('add-credit-btn');

const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const modalSelect = document.getElementById('modal-select');
const modalAmount = document.getElementById('modal-amount');
const modalForm = document.getElementById('modal-form');
const modalCancel = document.getElementById('modal-cancel');
const modalError = document.getElementById('modal-error');

// Rendering
function showLogin(){ loginView.classList.remove('hidden'); dashboardView.classList.add('hidden'); }
function showDashboard(){ loginView.classList.add('hidden'); dashboardView.classList.remove('hidden'); }

function render(){ restoreSession(); if(!currentUser){ showLogin(); } else { renderDashboard(); } }

function renderDashboard(){ showDashboard(); welcomeEl.textContent = `Hello, ${currentUser.username}`;
  balanceEl.textContent = formatMoney(currentUser.balance);
  // show/hide buttons
  if(currentUser.role === 'client'){
    sendBtn.style.display = 'inline-block';
    addCreditBtn.style.display = 'none';
  } else if(currentUser.role === 'admin'){
    sendBtn.style.display = 'none';
    addCreditBtn.style.display = 'inline-block';
  } else { sendBtn.style.display = 'none'; addCreditBtn.style.display = 'none'; }

  // transactions
  const debits = currentUser.transactions.filter(t => t.type === 'debit').slice().sort((a,b)=> b.timestamp.localeCompare(a.timestamp));
  const credits = currentUser.transactions.filter(t => t.type === 'credit').slice().sort((a,b)=> b.timestamp.localeCompare(a.timestamp));

  debitList.innerHTML = debits.length ? debits.map(t => `<li>${t.timestamp.slice(0,19).replace('T',' ')} — $${formatMoney(t.amount)} to ${t.to}</li>`).join('') : '<li>No debit transactions</li>';
  creditList.innerHTML = credits.length ? credits.map(t => `<li>${t.timestamp.slice(0,19).replace('T',' ')} — $${formatMoney(t.amount)} from ${t.from}</li>`).join('') : '<li>No credit transactions</li>';
}

// Login
loginForm.addEventListener('submit', (e)=>{
  e.preventDefault(); loginError.textContent = '';
  const u = document.getElementById('username').value.trim();
  const p = document.getElementById('password').value;
  const auth = authenticate(u,p);
  if(!auth){ loginError.textContent = 'Wrong username or password'; return; }
  setCurrent(auth.username); state = loadState(); currentUser = findUser(auth.username); renderDashboard();
});

logoutBtn.addEventListener('click', ()=>{ clearCurrent(); render(); });

// Modal utilities
function openModal({title, recipients, onConfirm}){
  modalTitle.textContent = title; modalError.textContent = '';
  modalSelect.innerHTML = recipients.map(r => `<option value="${r}">${r}</option>`).join('');
  modalAmount.value = '';
  modal.classList.remove('hidden');

  function submit(e){ e.preventDefault(); modalError.textContent = ''; const to = modalSelect.value; const amount = Number(modalAmount.value); onConfirm(to, amount, modalError); }
  modalForm._handler = submit;
  modalForm.addEventListener('submit', submit);
  modalCancel.addEventListener('click', closeModal);
}

function closeModal(){ modalForm.removeEventListener('submit', modalForm._handler); modal.classList.add('hidden'); }

// Send money (clients only)
sendBtn.addEventListener('click', ()=>{
  if(!currentUser) return; const recipients = state.users.filter(u => u.username !== currentUser.username && u.role === 'client').map(u=>u.username);
  openModal({ title: 'Send Money', recipients, onConfirm: (to, amount, errEl) => {
    if(!to){ errEl.textContent = 'Select a recipient'; return; }
    if(!amount || amount <= 0){ errEl.textContent = 'Enter a valid amount'; return; }
    if(amount > currentUser.balance){ errEl.textContent = 'Insufficient funds'; return; }
    // perform transfer
    const sender = findUser(currentUser.username);
    const recipient = findUser(to);
    if(!recipient){ errEl.textContent = 'Recipient not found'; return; }
    sender.balance = Number((sender.balance - amount).toFixed(2));
    recipient.balance = Number((recipient.balance + amount).toFixed(2));
    const ts = now();
    sender.transactions.push({ type: 'debit', amount, from: sender.username, to: recipient.username, timestamp: ts });
    recipient.transactions.push({ type: 'credit', amount, from: sender.username, to: recipient.username, timestamp: ts });
    saveState(state); currentUser = findUser(currentUser.username); renderDashboard(); closeModal();
  }});
});

// Add credit (admin)
addCreditBtn.addEventListener('click', ()=>{
  if(!currentUser || currentUser.role !== 'admin') return;
  const recipients = state.users.map(u => u.username);
  openModal({ title: 'Add Credit', recipients, onConfirm: (to, amount, errEl) => {
    if(!to){ errEl.textContent = 'Select a username'; return; }
    if(!amount || amount <= 0){ errEl.textContent = 'Enter a valid amount'; return; }
    const user = findUser(to);
    if(!user){ errEl.textContent = 'User not found'; return; }
    user.balance = Number((user.balance + amount).toFixed(2));
    user.transactions.push({ type: 'credit', amount, from: currentUser.username, to: user.username, timestamp: now() });
    saveState(state); renderDashboard(); closeModal();
  }});
});

// start
render();
