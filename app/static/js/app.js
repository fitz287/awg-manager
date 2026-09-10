// State
let token = localStorage.getItem('awg_token');
let interfaces = [];
let users = [];
let activeConfText = '';

// API Helper
async function api(path, options = {}) {
  const headers = options.headers || {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  options.headers = headers;

  const res = await fetch(`/api${path}`, options);
  if (res.status === 401) {
    logout();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let errorMsg = 'Error occurred';
    try {
      const err = await res.json();
      errorMsg = err.detail || errorMsg;
    } catch (_) {}
    throw new Error(errorMsg);
  }
  return res.json();
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Auth Flow
function initAuth() {
  if (!token) {
    document.getElementById('authView').classList.remove('hidden');
    document.getElementById('appView').classList.add('hidden');
  } else {
    document.getElementById('authView').classList.add('hidden');
    document.getElementById('appView').classList.remove('hidden');
    refreshData();
  }
  lucide.createIcons();
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorEl = document.getElementById('loginError');
  errorEl.classList.add('hidden');

  try {
    const res = await api('/auth/login', {
      method: 'POST',
      body: { username, password }
    });
    token = res.access_token;
    localStorage.setItem('awg_token', token);
    initAuth();
  } catch (err) {
    errorEl.textContent = err.message || 'Неверный логин или пароль';
    errorEl.classList.remove('hidden');
  }
});

function logout() {
  token = null;
  localStorage.removeItem('awg_token');
  initAuth();
}

// Data Refresh
async function refreshData() {
  try {
    const [ifacesData, usersData] = await Promise.all([
      api('/interfaces'),
      api('/users')
    ]);

    interfaces = ifacesData;
    users = usersData;

    renderStats();
    renderInterfaces();
    renderUsers();
    lucide.createIcons();
  } catch (err) {
    console.error('Refresh error:', err);
  }
}

// Render Stats
function renderStats() {
  document.getElementById('statInterfaces').textContent = interfaces.length;
  document.getElementById('statUsers').textContent = users.length;

  let totalDevices = 0;
  let onlineDevices = 0;
  let totalRx = 0;
  let totalTx = 0;

  users.forEach(u => {
    (u.configs || []).forEach(c => {
      totalDevices++;
      if (c.is_online) onlineDevices++;
      totalRx += (c.rx_bytes || 0);
      totalTx += (c.tx_bytes || 0);
    });
  });

  document.getElementById('statDevices').innerHTML = `${totalDevices} <span class="text-xs font-normal text-emerald-400">(${onlineDevices} в сети)</span>`;
  document.getElementById('statTraffic').textContent = `${formatBytes(totalRx)} / ${formatBytes(totalTx)}`;
}

// Render Interfaces
function renderInterfaces() {
  const container = document.getElementById('interfacesContainer');
  if (!interfaces.length) {
    container.innerHTML = `<div class="p-6 bg-zinc-900 border border-zinc-800 rounded-2xl text-zinc-400 text-sm">Интерфейсы не найдены. Проверьте файлы в /etc/amnezia/amneziawg/</div>`;
    return;
  }

  container.innerHTML = interfaces.map(iface => {
    const isUp = iface.is_active;
    const badgeColor = isUp ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20';
    const statusDot = isUp ? 'bg-emerald-400 animate-pulse' : 'bg-red-500';
    const btnClass = isUp ? 'bg-zinc-800 hover:bg-red-500/20 hover:text-red-300 text-zinc-300' : 'bg-indigo-600 hover:bg-indigo-500 text-white';
    const btnText = isUp ? 'Остановить' : 'Запустить';
    const btnAction = isUp ? `stopInterface('${iface.name}')` : `startInterface('${iface.name}')`;

    return `
      <div class="bg-zinc-900/80 border border-zinc-800 rounded-2xl p-5 shadow-sm hover:border-zinc-700/80 transition space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2.5">
            <span class="w-2.5 h-2.5 rounded-full ${statusDot}"></span>
            <span class="font-bold text-white text-base">${iface.name}</span>
            <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-zinc-800 text-indigo-400 border border-zinc-700">${iface.protocol_version}</span>
          </div>
          <span class="text-xs font-medium px-2.5 py-1 rounded-full border ${badgeColor}">
            ${isUp ? 'Работает' : 'Остановлен'}
          </span>
        </div>

        <div class="grid grid-cols-2 gap-3 text-xs bg-zinc-950/60 p-3 rounded-xl border border-zinc-800/60">
          <div>
            <span class="text-zinc-500">Порт:</span>
            <span class="font-mono text-zinc-300 ml-1">${iface.listen_port}</span>
          </div>
          <div>
            <span class="text-zinc-500">Подсеть:</span>
            <span class="font-mono text-zinc-300 ml-1">${iface.address}</span>
          </div>
          <div>
            <span class="text-zinc-500">Клиенты:</span>
            <span class="font-semibold text-zinc-200 ml-1">${iface.peers_online} / ${iface.peers_count} online</span>
          </div>
          <div>
            <span class="text-zinc-500">Трафик:</span>
            <span class="text-zinc-300 ml-1">${formatBytes(iface.total_rx + iface.total_tx)}</span>
          </div>
        </div>

        <div class="flex items-center justify-between pt-1">
          <span class="text-[11px] text-zinc-500 font-mono truncate max-w-[200px]" title="${iface.public_key}">🔑 ${iface.public_key}</span>
          <button onclick="${btnAction}" class="px-3 py-1.5 rounded-lg text-xs font-medium transition border border-zinc-700/50 ${btnClass}">
            ${btnText}
          </button>
        </div>
      </div>
    `;
  }).join('');
}

async function startInterface(name) {
  try {
    await api(`/interfaces/${name}/start`, { method: 'POST' });
    await refreshData();
  } catch (err) {
    alert(`Ошибка запуска: ${err.message}`);
  }
}

async function stopInterface(name) {
  try {
    await api(`/interfaces/${name}/stop`, { method: 'POST' });
    await refreshData();
  } catch (err) {
    alert(`Ошибка остановки: ${err.message}`);
  }
}

// Render Users
function renderUsers() {
  const container = document.getElementById('usersContainer');
  if (!users.length) {
    container.innerHTML = `
      <div class="p-8 bg-zinc-900 border border-zinc-800 rounded-2xl text-center space-y-3">
        <div class="w-12 h-12 rounded-2xl bg-indigo-600/10 text-indigo-400 mx-auto flex items-center justify-center">
          <i data-lucide="user-x" class="w-6 h-6"></i>
        </div>
        <p class="text-zinc-400 text-sm">Пользователей пока нет. Создайте первого пользователя!</p>
        <button onclick="openCreateUserModal()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-medium transition">
          + Создать пользователя
        </button>
      </div>
    `;
    return;
  }

  container.innerHTML = users.map(user => {
    const configs = user.configs || [];

    const deviceRows = configs.length ? configs.map(cfg => {
      const isOnline = cfg.is_online;
      const statusIcon = isOnline ? '🟢' : '⚪';
      const statusText = isOnline ? 'В сети' : 'Офлайн';

      return `
        <div class="flex items-center justify-between py-2.5 px-3 rounded-xl bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800/80 transition">
          <div class="flex items-center gap-3">
            <span title="${statusText}">${statusIcon}</span>
            <div>
              <div class="text-sm font-semibold text-white flex items-center gap-2">
                <span>${cfg.label}</span>
                <span class="text-xs font-mono text-indigo-400 font-normal">(${cfg.device_ip})</span>
              </div>
              <div class="text-[11px] text-zinc-500 flex items-center gap-2 mt-0.5">
                <span>⬇️ ${formatBytes(cfg.rx_bytes)}</span>
                <span>⬆️ ${formatBytes(cfg.tx_bytes)}</span>
              </div>
            </div>
          </div>

          <div class="flex items-center gap-1.5">
            <button onclick="openQrModal(${cfg.id})" title="QR-код" class="p-2 text-zinc-400 hover:text-indigo-400 hover:bg-indigo-500/10 rounded-lg transition">
              <i data-lucide="qr-code" class="w-4 h-4"></i>
            </button>
            <button onclick="downloadConfig(${cfg.id})" title="Скачать .conf" class="p-2 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg transition">
              <i data-lucide="download" class="w-4 h-4"></i>
            </button>
            <button onclick="deleteConfig(${cfg.id}, '${cfg.label}')" title="Удалить" class="p-2 text-zinc-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition">
              <i data-lucide="trash-2" class="w-4 h-4"></i>
            </button>
          </div>
        </div>
      `;
    }).join('') : `<div class="text-xs text-zinc-500 italic py-2">Нет выпущенных устройств. Нажмите «+ Добавить устройство».</div>`;

    return `
      <div class="bg-zinc-900/70 border border-zinc-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800/60 pb-3">
          <div>
            <div class="flex items-center gap-2.5">
              <span class="text-base font-bold text-white">${user.username}</span>
              <span class="text-xs font-mono px-2 py-0.5 rounded-md bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                Подсеть: ${user.subnet}
              </span>
              <span class="text-xs px-2 py-0.5 rounded-md bg-zinc-800 text-zinc-400 border border-zinc-700">
                ${user.interface_name}
              </span>
            </div>
            ${user.notes ? `<div class="text-xs text-zinc-500 mt-1">📝 ${user.notes}</div>` : ''}
          </div>

          <div class="flex items-center gap-2">
            <button onclick="openAddDeviceModal(${user.id}, '${user.username}', '${user.subnet}')" class="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 rounded-xl text-xs font-medium transition">
              <i data-lucide="plus" class="w-3.5 h-3.5"></i>
              <span>Добавить устройство</span>
            </button>
            <button onclick="deleteUser(${user.id}, '${user.username}')" title="Удалить пользователя" class="p-1.5 text-zinc-500 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition">
              <i data-lucide="trash-2" class="w-4 h-4"></i>
            </button>
          </div>
        </div>

        <div class="space-y-2">
          ${deviceRows}
        </div>
      </div>
    `;
  }).join('');
}

// Modal Handlers
function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
  lucide.createIcons();
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

function openCreateUserModal() {
  const select = document.getElementById('newUserIface');
  select.innerHTML = interfaces.map(i => `<option value="${i.name}">${i.name} (${i.protocol_version})</option>`).join('');
  document.getElementById('newUsername').value = '';
  document.getElementById('newUserNotes').value = '';
  document.getElementById('createUserError').classList.add('hidden');
  openModal('modalCreateUser');
}

document.getElementById('formCreateUser').addEventListener('submit', async (e) => {
  e.preventDefault();
  const iface = document.getElementById('newUserIface').value;
  const username = document.getElementById('newUsername').value.trim();
  const notes = document.getElementById('newUserNotes').value.trim();
  const errEl = document.getElementById('createUserError');

  try {
    await api('/users', {
      method: 'POST',
      body: { username, interface_name: iface, notes: notes || null }
    });
    closeModal('modalCreateUser');
    await refreshData();
  } catch (err) {
    errEl.textContent = err.message || 'Ошибка создания';
    errEl.classList.remove('hidden');
  }
});

function openAddDeviceModal(userId, username, subnet) {
  document.getElementById('addDeviceUserId').value = userId;
  document.getElementById('addDeviceUserName').textContent = username;
  document.getElementById('addDeviceUserSubnet').textContent = subnet;
  document.getElementById('addDeviceLabel').value = '';
  document.getElementById('addDeviceError').classList.add('hidden');
  openModal('modalAddDevice');
}

document.getElementById('formAddDevice').addEventListener('submit', async (e) => {
  e.preventDefault();
  const userId = parseInt(document.getElementById('addDeviceUserId').value);
  const label = document.getElementById('addDeviceLabel').value.trim();
  const usePsk = document.getElementById('addDeviceUsePsk').checked;
  const btn = document.getElementById('btnSubmitAddDevice');
  const errEl = document.getElementById('addDeviceError');

  btn.disabled = true;
  btn.innerHTML = '<span>Создание...</span>';

  try {
    const res = await api('/configs', {
      method: 'POST',
      body: { user_id: userId, label, use_psk: usePsk }
    });
    closeModal('modalAddDevice');
    await refreshData();
    showQrView(res);
  } catch (err) {
    errEl.textContent = err.message || 'Ошибка создания конфига';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Выпустить конфиг</span>';
  }
});

async function openQrModal(configId) {
  try {
    const res = await api(`/configs/${configId}`);
    showQrView(res);
  } catch (err) {
    alert(`Ошибка загрузки: ${err.message}`);
  }
}

function showQrView(data) {
  document.getElementById('qrModalTitle').textContent = `${data.username} — ${data.label}`;
  document.getElementById('qrModalSubtitle').textContent = `IP: ${data.device_ip} | Интерфейс: ${data.interface_name}`;
  document.getElementById('qrModalImage').src = data.qr_base64;
  document.getElementById('qrModalConfText').textContent = data.config_content;
  document.getElementById('qrDownloadBtn').onclick = () => downloadConfig(data.id);
  activeConfText = data.config_content;
  openModal('modalQrView');
}

async function downloadConfig(configId) {
  try {
    const res = await fetch(`/api/configs/${configId}/download`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) {
      const altRes = await fetch(`/api/configs/${configId}/download?token=${token}`);
      if (!altRes.ok) throw new Error('Ошибка авторизации при скачивании');
      return handleBlobDownload(altRes);
    }
    await handleBlobDownload(res);
  } catch (err) {
    alert('Ошибка скачивания: ' + err.message);
  }
}

async function handleBlobDownload(response) {
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition');
  let filename = 'client.conf';
  if (disposition && disposition.includes('filename=')) {
    filename = disposition.split('filename=')[1].replace(/["']/g, '').trim();
  }
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
}

function copyConfText() {
  if (!activeConfText) return;
  navigator.clipboard.writeText(activeConfText).then(() => {
    const btn = document.getElementById('copyBtnText');
    btn.textContent = 'Скопировано!';
    setTimeout(() => { btn.textContent = 'Скопировать текст'; }, 2000);
  });
}

async function deleteConfig(configId, label) {
  if (!confirm(`Удалить конфигурацию "${label}"? Устройство больше не сможет подключаться к серверу.`)) {
    return;
  }
  try {
    await api(`/configs/${configId}`, { method: 'DELETE' });
    await refreshData();
  } catch (err) {
    alert(`Ошибка удаления: ${err.message}`);
  }
}

async function deleteUser(userId, username) {
  if (!confirm(`Удалить пользователя "${username}" и ВСЕ его устройства? Его подсеть будет освобождена.`)) {
    return;
  }
  try {
    await api(`/users/${userId}`, { method: 'DELETE' });
    await refreshData();
  } catch (err) {
    alert(`Ошибка удаления: ${err.message}`);
  }
}

// Initial Boot
window.addEventListener('DOMContentLoaded', () => {
  initAuth();
});
