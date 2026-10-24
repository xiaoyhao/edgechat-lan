// ---------------------------------------------------------------- 基础状态
let TOKEN = localStorage.getItem('ec_token') || '';
let ME = null, ROOMS = [], USERS = [], CUR = null;
let inboxWs = null, roomWs = null, replyTo = null;
const $ = id => document.getElementById(id);

async function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Authorization': 'Bearer ' + TOKEN }, opts.headers || {});
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  const r = await fetch('/api/v1' + path, opts);
  if (r.status === 401) { // 会话过期 → 重新自动登录
    localStorage.removeItem('ec_token'); TOKEN = '';
    await autoLogin();
    throw new Error('会话已刷新，请重试');
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || '请求失败');
  return data;
}
function toast(msg) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 2600); }
function esc(s) { return (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function fmtTime(iso) { try { return new Date(iso).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }); } catch (e) { return ''; } }
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1024).toFixed(1) + ' KB'; }

// ---------------------------------------------------------------- 浏览器指纹 + 免密自动登录
let canvasFp = '';   // 画布指纹哈希（在 autoLogin 中计算，用于生成用户名）
function drawCanvasFp() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Fingerprint👆', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Fingerprint👆', 4, 17);
    return canvas.toDataURL();
  } catch (e) { return ''; }
}
async function sha256hex(s) {
  if (window.crypto && crypto.subtle && crypto.subtle.digest) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      const fullHex = Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      // ✅ 截取前 16 个字符 (64 bits)，足以满足设备标识的唯一性需求
      const result = fullHex.slice(0, 16);
      return result;
    } catch (e) {/* http 环境可能不可用，回落 */ }
  }
  // 2. 降级方案：简易回落哈希 (FNV-1a 变体，仅用于设备标识，非安全场景)
  let h1 = 0x811c9dc5 >>> 0, h2 = 0x01000193 >>> 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0; h2 = Math.imul(h2 ^ (c + i), 0x85ebca6b) >>> 0; }
  const hex1 = h1.toString(16).padStart(8, '0');
  const hex2 = h2.toString(16).padStart(8, '0');
  const fallbackResult = (hex1 + hex2).slice(0, 16);
  return fallbackResult;
}
async function computeFingerprint() {
  // 画布指纹哈希：canvas.toDataURL() -> hash，作为 username 依据
  canvasFp = await sha256hex(drawCanvasFp());
  let saved = localStorage.getItem('ec_fp');
  if (saved) return saved;
  const parts = [
    navigator.userAgent, navigator.language, screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
    new Date().getTimezoneOffset(), navigator.hardwareConcurrency || 0, navigator.platform || '',
    (navigator.deviceMemory || 0), canvasFp
  ].join('||');
  const fp = await sha256hex(parts);
  localStorage.setItem('ec_fp', fp);
  return fp;
}
async function autoLogin() {
  $('authMsg').textContent = '正在识别设备，自动进入聊天…';
  try {
    const fp = await computeFingerprint();
    const r = await fetch('/api/v1/auth/auto-login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint: fp, canvasFp: canvasFp, userAgent: navigator.userAgent })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || '自动登录失败');
    TOKEN = d.token; localStorage.setItem('ec_token', TOKEN);
    if (d.isNew) toast('已为你创建账号：' + d.user.displayName);
    await enterApp();
  } catch (e) {
    $('authMsg').textContent = '自动登录失败';
    $('authErr').textContent = e.message + '（可刷新页面重试）';
  }
}

// ---------------------------------------------------------------- 进入应用
function renderMe() {
  $('meName').textContent = ME.displayName;
  $('meRole').textContent = '@' + ME.username;
  $('meAvatar').textContent = ME.displayName[0] || '?';
  $('meAvatar').style.background = ME.color || '#4f7cff';
}
async function enterApp() {
  const me = await api('/me');
  ME = me.user;
  $('authView').classList.add('hidden'); $('appView').classList.remove('hidden');
  renderMe();
  connectInbox();
  await Promise.all([loadRooms(), loadUsers()]);
}
async function editDisplayName() {
  if (!ME) return;
  const input = prompt('设置我的昵称（留空则恢复默认，显示用户名）：', ME.displayName === ME.username ? '' : ME.displayName);
  if (input === null) return;
  try {
    const d = await api('/me', { method: 'PATCH', body: { displayName: input } });
    ME = d.user; renderMe(); loadUsers();
    toast('昵称已更新为：' + ME.displayName);
  } catch (e) { toast(e.message); }
}
async function loadRooms() {
  const d = await api('/rooms'); ROOMS = d.rooms; renderRooms();
}
function renderRooms() {
  const mk = (r) => `<div class="roomItem ${CUR && CUR.id === r.id ? 'active' : ''}" onclick="selectRoomById(${r.id})">
     <div class="avatar" style="background:${r.kind === 'channel' ? '#4f7cff' : '#7a5cff'}">${esc((r.name || '?')[0])}</div>
     <div class="meta"><div class="name">${esc(r.name)}</div><div class="prev">${esc(r.lastPreview || '')}</div></div>
     ${r.unreadCount ? `<span class="badge">${r.unreadCount}</span>` : ''}</div>`;
  $('channelList').innerHTML = ROOMS.filter(r => r.kind === 'channel').map(mk).join('') || '<div style="color:var(--muted);font-size:12px;padding:6px 8px">暂无频道</div>';
  $('privateList').innerHTML = ROOMS.filter(r => r.kind === 'private').map(mk).join('') || '<div style="color:var(--muted);font-size:12px;padding:6px 8px">暂无私信</div>';
}
async function loadUsers() {
  const d = await api('/users'); USERS = d.users;
  $('userList').innerHTML = USERS.map(u => `<div class="userItem" onclick="startPrivate(${u.id})">
    <div class="${u.online ? 'dotOn' : 'dotOff'}"></div>
    <div class="avatar sm" style="background:${u.color || '#4f7cff'}">${esc(u.displayName[0] || '?')}</div>
    <div style="font-size:13px;min-width:0"><div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(u.displayName)}</div>
    <div style="font-size:11px;color:var(--muted)">@${esc(u.username)}</div></div></div>`).join('');
}
async function startPrivate(uid) {
  if (uid === ME.id) return;
  const d = await api('/rooms', { method: 'POST', body: { kind: 'private', userId: uid } });
  await loadRooms(); selectRoom(d.room);
}

// ---------------------------------------------------------------- WebSocket（一次性 ticket，对齐上游 WS v1）
async function openTicket(scope, roomId) {
  const d = await api('/realtime/tickets', { method: 'POST', body: { scope, roomId: roomId || 0 } });
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}${d.wsPath}?ticket=${d.ticket}`;
}
async function connectInbox() {
  try { if (inboxWs) inboxWs.close(); } catch (e) { }
  const url = await openTicket('inbox');
  inboxWs = new WebSocket(url);
  inboxWs.onmessage = e => handleFrame(JSON.parse(e.data), 'inbox');
  inboxWs.onclose = ev => { if (ME && ![1000, 1008, 4401, 4403].includes(ev.code)) setTimeout(connectInbox, 2000); };
  setInterval(() => { if (inboxWs && inboxWs.readyState === 1) inboxWs.send(JSON.stringify({ type: 'ping' })); }, 25000);
}
async function connectRoom(roomId) {
  try { if (roomWs) roomWs.close(); } catch (e) { }
  const url = await openTicket('room', roomId);
  roomWs = new WebSocket(url);
  roomWs.onmessage = e => handleFrame(JSON.parse(e.data), 'room');
  roomWs.onclose = ev => { if (ME && CUR && CUR.id === roomId && ![1000, 1008, 4401, 4403].includes(ev.code)) setTimeout(() => connectRoom(roomId), 1500); };
}
function handleFrame(f, kind) {
  if (f.type === 'ready') { if (kind === 'room' && f.pinned && f.pinned.length) showPinned(f.pinned); return; }
  if (f.type === 'message' && kind === 'room') { upsertMessage(f.message); return; }
  if (f.type === 'message_deleted' && kind === 'room') { removeMessage(f.messageId); return; }
  if (f.type === 'message_pinned' && kind === 'room') { addPin(f.message); return; }
  if (f.type === 'message_unpinned' && kind === 'room') { unpinById(f.messageId); return; }
  if (f.type === 'typing' && kind === 'room') { showTyping(f.user); return; }
  if (f.type === 'presence') { loadUsers(); return; }
  if (f.type === 'userUpdated' && f.user) {
    if (ME && f.user.id === ME.id) { ME = f.user; renderMe(); }
    loadUsers();
    return;
  }
  if (f.type === 'room_message') { loadRooms(); loadUsers(); }
  if (f.type === 'room_created') { toast('新频道已创建：' + (f.room && f.room.name)); loadRooms(); loadUsers(); }
}

// ---------------------------------------------------------------- 会话与消息渲染
function selectRoomById(id) { const r = ROOMS.find(x => x.id === id); if (r) selectRoom(r); }
async function selectRoom(room) {
  CUR = room; cancelReply();
  renderRooms();
  $('roomTitle').textContent = (room.kind === 'channel' ? '# ' : '💬 ') + room.name;
  $('roomTopic').textContent = room.topic || ((room.members && room.members.length || 0) + ' 名成员');
  pins = []; renderPins();
  $('msgList').innerHTML = '<div style="color:var(--muted);text-align:center;margin-top:60px">加载中…</div>';
  const d = await api(`/rooms/${room.id}/messages?limit=60`);
  $('msgList').innerHTML = '';
  d.messages.forEach(m => upsertMessage(m, true));
  scrollBottom();
  connectRoom(room.id);
  markRead(room);
}
function markRead(room) {
  api(`/rooms/${room.id}/read`, { method: 'POST', body: { lastMessageId: 999999999 } }).then(() => loadRooms()).catch(() => { });
}
function upsertMessage(m, silent) {
  const list = $('msgList');
  if (!list.querySelector(`[data-mid="${m.id}"]`)) {
    const mine = m.sender && ME && m.sender.id === ME.id;
    const el = document.createElement('div');
    el.className = 'msgRow' + (mine ? ' mine' : ''); el.dataset.mid = m.id;
    let body = '';
    if (m.file) {
      if (m.type === 'image' || (m.file.mime || '').startsWith('image/')) body += `<div class="attach"><img src="${m.file.url}" alt="${esc(m.file.name)}" loading="lazy"></div>`;
      else body += `<a class="fileChip" href="${m.file.url}" download="${esc(m.file.name)}">📄 ${esc(m.file.name)} <span style="color:var(--muted)">${fmtSize(m.file.size)}</span></a>`;
    }
    const content = m.deleted ? '<span style="color:var(--muted)">该消息已撤回</span>' : esc(m.content || ''); // 取消 @ highlightMentions()
    const reply = m.replyToMessageId ? `<div class="replyRef" onclick="jumpTo(${m.replyToMessageId})">回复消息 #${m.replyToMessageId}</div>` : '';
    const safePrev = esc((m.content || '').slice(0, 30)).replace(/'/g, '&#39;').replace(/"/g, '&quot;');
    el.innerHTML = `<div class="avatar" style="background:${(m.sender && m.sender.color) || '#4f7cff'}">${esc(((m.sender && m.sender.displayName) || '?')[0])}</div>
     <div class="bubble">${reply}<div class="who">${esc(m.sender ? m.sender.displayName : '?')} ${m.pinned ? '📌' : ''}</div>
     <div class="content">${content}</div>${body}<div class="time">${fmtTime(m.createdAt)}</div>
     </div>`;
    //  <div class="actions">
    //    <button title="回复" onclick="setReply(${m.id},'${safePrev}')">↩</button>
    //    <button title="置顶/取消" onclick="pinMsg(${m.id},${!m.pinned})">📌</button>
    //    ${mine && !m.deleted ? `<button title="撤回" onclick="delMsg(${m.id})">🗑</button>` : ''}
    //  </div>
    list.appendChild(el);
  }
  if (m.pinned) addPin(m, true);
  if (!silent) scrollBottom();
}
function highlightMentions(html) { return html.replace(/@([A-Za-z0-9_\u4e00-\u9fff.\-]+)/g, '<span style="color:#8ab4ff;font-weight:600">@$1</span>'); }
function removeMessage(id) { const el = $('msgList').querySelector(`[data-mid="${id}"]`); if (el) { el.querySelector('.content').innerHTML = '<span style="color:var(--muted)">该消息已撤回</span>'; el.querySelectorAll('.actions,.attach,.fileChip').forEach(x => x.remove()); } unpinById(id); }
function jumpTo(id) { const el = $('msgList').querySelector(`[data-mid="${id}"]`); if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.style.outline = '2px solid var(--accent)'; setTimeout(() => el.style.outline = '', 1200); } }
function scrollBottom() { const l = $('msgList'); l.scrollTop = l.scrollHeight; }
let pins = [];
function showPinned(arr) { arr.forEach(m => upsertMessage(m, true)); pins = arr; renderPins(); }
function addPin(m, quiet) { if (!pins.some(p => p.id === m.id)) { pins = [m, ...pins]; } if (!quiet) renderPins(); if (!m._noRender) upsertMessage(m, true); }
function unpinById(id) { pins = pins.filter(p => p.id !== id); renderPins(); }
function renderPins() { const b = $('pinnedBar'); if (!pins.length) { b.classList.add('hidden'); return; } b.classList.remove('hidden'); b.innerHTML = '📌 ' + pins.map(p => `<a style="color:#8ab4ff;cursor:pointer" onclick="jumpTo(${p.id})">${esc((p.content || '[文件]').slice(0, 30))}</a>`).join(' &nbsp;·&nbsp; '); }
let typingTimer = null;
function showTyping(u) { $('typingHint').textContent = `${u.displayName} 正在输入…`; clearTimeout(typingTimer); typingTimer = setTimeout(() => $('typingHint').textContent = '', 3500); }

// ---------------------------------------------------------------- 发送
// crypto.randomUUID() 仅在安全上下文(HTTPS/localhost)可用；
// 手机通过 http://192.168.x.x 访问时不存在，这里提供降级方案
function genId() {
  if (window.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  if (window.crypto && typeof crypto.getRandomValues === 'function') {
    const b = new Uint8Array(16); crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }
  return Date.now().toString(16) + '-' + Math.random().toString(16).slice(2, 10) + '-' + Math.random().toString(16).slice(2, 10);
}
function setReply(id, text) { replyTo = id; $('replyBox').classList.remove('hidden'); $('replyText').textContent = '回复: ' + text; }
function cancelReply() { replyTo = null; $('replyBox').classList.add('hidden'); }
async function sendMessage() {
  const inp = $('msgInput'); const text = inp.value.trim(); if (!text || !CUR) return;
  inp.value = '';
  try {
    const d = await api(`/rooms/${CUR.id}/messages`, { method: 'POST', body: { content: text, clientMessageId: genId(), replyToMessageId: replyTo || 0 } });
    upsertMessage(d.message); cancelReply(); markRead(CUR);
  } catch (e) { toast(e.message); }
}
async function uploadFile(input) {
  const f = input.files[0]; input.value = ''; if (!f || !CUR) return;
  const fd = new FormData(); fd.append('file', f);
  try {
    const up = await api('/uploads', { method: 'POST', body: fd });
    const d = await api(`/rooms/${CUR.id}/messages`, { method: 'POST', body: { content: '', type: up.file.type, fileId: up.file.id, clientMessageId: genId() } });
    upsertMessage(d.message); loadRooms();
  } catch (e) { toast(e.message); }
}
async function delMsg(id) { if (!confirm('确认撤回该消息？')) return; await api('/messages/' + id, { method: 'DELETE' }); removeMessage(id); }
async function pinMsg(id, on) { await api(`/messages/${id}/pin`, { method: 'POST', body: { pinned: on } }); if (on) toast('已置顶'); }
$('msgInput').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
$('msgInput').addEventListener('input', () => { if (roomWs && roomWs.readyState === 1) roomWs.send(JSON.stringify({ type: 'typing' })); });

// ---------------------------------------------------------------- 频道 / 管理后台
async function showNewChannel() {
  const name = prompt('新频道名称：'); if (!name) return;
  const topic = prompt('频道简介（可留空）：') || '';
  try { const d = await api('/rooms', { method: 'POST', body: { kind: 'channel', name, topic } }); await loadRooms(); selectRoom(d.room); } catch (e) { toast(e.message); }
}
// ---------------------------------------------------------------- 启动
$('meBar').addEventListener('click', editDisplayName);
autoLogin();
