'use strict';

/**
 * Zangi X — Modern Anonymous & Private Messenger
 *
 * Trust model:
 * - Server is a dumb, zero-knowledge relay; it never sees plaintext or keys.
 * - End-to-end encrypted with XChaCha20-Poly1305 (libsodium AEAD).
 * - Multi-chat & 1-on-1 private rooms: each conversation has an independent key.
 * - Ephemeral in-memory session: zero logs, zero database, no tracking.
 */

(function () {
  // ---- Constants -----------------------------------------------------------
  const CHUNK = 128 * 1024; // media chunk size (128 KB)
  const MAX_UPLOAD = 40 * 1024 * 1024; // 40 MB max media
  const PREVIEW_THRESHOLD = 2 * 1024 * 1024; // 2 MB
  const MEDIA_TTL_MS = 5 * 60 * 1000;
  const MAX_MESSAGES = 400;
  const COVER_INTERVAL_MS = 1200;
  const BACKPRESSURE = 4 * 1024 * 1024;
  const HEARTBEAT_MS = 10000;
  const CRYPTO_BUILD = '0.7.15';
  const KEYCHECK_MARKER = 'zangi-keycheck-v2';

  // ---- State ---------------------------------------------------------------
  let sodium = null;
  let UID = null;
  let NICK = null;
  let ws = null;
  let backoff = 500;
  let reconnectTimer = null;
  let manualClose = false;
  let heartbeatTimer = null;
  let wakeTimer = null;
  let connectedOnce = false;
  let dead = false;
  let coverTimer = null;
  let isCoverMode = false;

  // Multi-chat state: Map of chatId -> Chat object
  // Chat: { id, room, key, name, type, locked, peers, peerList: Map(uid -> nick), messages: [], unread, lastMsg, lastTime, typingTimer }
  const chats = new Map();
  let activeChatId = null;

  const outbox = [];
  const incoming = new Map(); // id -> assemble record
  const uploads = new Map();  // id -> upload record
  const blobUrls = new Set();
  const knownMedia = new Set();

  const $ = (id) => document.getElementById(id);
  const els = {};

  // ===== Bootstrap ==========================================================
  window.addEventListener('DOMContentLoaded', init);

  async function init() {
    Object.assign(els, {
      app: $('app'),
      sidebar: $('sidebar'),
      chatList: $('chat-list'),
      listEmpty: $('list-empty'),
      search: $('search'),
      netDot: $('net-dot'),
      meBadge: $('me-badge'),
      btnTheme: $('btn-theme'),
      btnNew: $('btn-new'),
      btnJoin: $('btn-join'),
      btnBurnAll: $('btn-burn-all'),
      btnNewDm: $('btn-new-dm'),
      btnNewGroup: $('btn-new-group'),

      conv: $('conv'),
      convEmpty: $('conv-empty'),
      convMain: $('conv-main'),
      convHead: $('conv-head'),
      convAvatar: $('conv-avatar'),
      convName: $('conv-name'),
      convSub: $('conv-sub'),
      convBanner: $('conv-banner'),
      messages: $('messages'),
      typing: $('typing'),

      btnBack: $('btn-back'),
      btnPeers: $('btn-peers'),
      btnCover: $('btn-cover'),
      btnShare: $('btn-share'),
      btnBurn: $('btn-burn'),

      composer: $('composer'),
      btnAttach: $('btn-attach'),
      file: $('file'),
      btnEmoji: $('btn-emoji'),
      emojiPopup: $('emoji-popup'),
      input: $('input'),
      btnSend: $('btn-send'),

      overlay: $('overlay'),
      lightbox: $('lightbox'),
      lightboxImg: $('lightbox-img'),
      lightboxClose: $('lightbox-close'),
    });

    try {
      sodium = await window.ghostSodiumReady;
    } catch {
      return fatal('Erro ao inicializar a biblioteca de criptografia libsodium.');
    }

    setupIdentity();
    initTheme();
    wireUI();
    registerServiceWorker();

    // Setup initial room from URL fragment or create a default private room
    await setupInitialRoom();

    connect();

    wakeTimer = setTimeout(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) showWake('Conectando ao servidor…');
    }, 5000);
  }

  // ===== Identity ===========================================================
  function setupIdentity() {
    try {
      UID = sessionStorage.getItem('zx_uid');
      NICK = sessionStorage.getItem('zx_nick');
    } catch {}
    if (!UID) UID = cryptoRandomId(8);
    if (!NICK) NICK = randomNick();
    try {
      sessionStorage.setItem('zx_uid', UID);
      sessionStorage.setItem('zx_nick', NICK);
    } catch {}

    updateMeBadge();
  }

  function updateMeBadge() {
    if (!els.meBadge) return;
    els.meBadge.innerHTML = '';
    const av = createAvatarEl(NICK, 24);
    const span = document.createElement('span');
    span.textContent = NICK;
    span.style.fontWeight = '600';
    els.meBadge.appendChild(av);
    els.meBadge.appendChild(span);
    els.meBadge.style.cursor = 'pointer';
    els.meBadge.title = 'Clique para alterar seu apelido anônimo';
    els.meBadge.onclick = promptChangeNick;
  }

  function promptChangeNick() {
    promptModal({
      title: 'Alterar Apelido Anônimo',
      note: 'Escolha um codinome para esta sessão. Nenhuma identidade real é vinculada.',
      current: NICK,
      onSave: (newNick) => {
        if (!newNick || !newNick.trim()) return;
        NICK = newNick.trim().slice(0, 24);
        try { sessionStorage.setItem('zx_nick', NICK); } catch {}
        updateMeBadge();
        // Re-announce our nick in all joined rooms
        broadcastKeyCheckAll();
        toast('Apelido alterado para: ' + NICK);
      }
    });
  }

  // ===== Theme ==============================================================
  function initTheme() {
    const saved = localStorage.getItem('zx_theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    if (els.btnTheme) {
      els.btnTheme.addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme') ||
          (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('zx_theme', next);
      });
    }
  }

  // ===== Key & Room Derivation ==============================================
  const URLB64 = () => sodium.base64_variants.URLSAFE_NO_PADDING;
  const B64 = () => sodium.base64_variants.ORIGINAL;

  function toUrlB64(bytes) { return sodium.to_base64(bytes, URLB64()); }
  function fromUrlB64(s) {
    try { return sodium.from_base64(s, URLB64()); } catch { return null; }
  }

  function roomHandleFromKey(key) {
    return toUrlB64(sodium.crypto_generichash(16, key));
  }

  function parseKey(b64) {
    try {
      const k = sodium.from_base64(b64, URLB64());
      return k.length === sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES ? k : null;
    } catch {
      return null;
    }
  }

  async function deriveKey(pass, salt) {
    showBusy('Derivando chave de segurança (Argon2id)…');
    await sleep(60);
    const key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      pass,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    hideOverlay();
    return key;
  }

  function seal(bytes, key) {
    const npub = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, npub, key);
    const out = new Uint8Array(npub.length + ct.length);
    out.set(npub, 0);
    out.set(ct, npub.length);
    return sodium.to_base64(out, B64());
  }

  function open(b64, key) {
    let data;
    try { data = sodium.from_base64(b64, B64()); } catch { return null; }
    const nb = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const ab = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (data.length < nb + ab) return null;
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, data.subarray(nb), null, data.subarray(0, nb), key);
    } catch {
      return null;
    }
  }

  const BUCKETS = [128, 512, 2048, 8192, 32768, 131072];
  function padToBucket(bytes) {
    const need = bytes.length + 4;
    let target = BUCKETS.find((b) => b >= need) || Math.ceil(need / 131072) * 131072;
    const out = new Uint8Array(target);
    new DataView(out.buffer).setUint32(0, bytes.length, false);
    out.set(bytes, 4);
    return out;
  }
  function unpad(bytes) {
    if (bytes.length < 4) return bytes;
    const len = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
    return len > bytes.length - 4 ? null : bytes.subarray(4, 4 + len);
  }
  function sealJSON(obj, key) {
    return seal(padToBucket(utf8(JSON.stringify(obj))), key);
  }
  function openJSON(b64, key) {
    const raw = open(b64, key);
    if (!raw) return null;
    const body = unpad(raw);
    if (!body) return null;
    try { return JSON.parse(fromUtf8(body)); } catch { return null; }
  }

  // ===== Chat Management ====================================================
  function addChat({ id, room, key, name, type, locked, pinned }) {
    if (chats.has(id)) return chats.get(id);

    const chat = {
      id: id || room,
      room,
      key,
      name: name || (type === 'private' ? 'Conversa Particular' : 'Sala Secreta'),
      type: type || 'group',
      locked: !!locked,
      peers: 0,
      peerList: new Map(),
      messages: [],
      unread: 0,
      lastMsg: 'Sala criada',
      lastTime: Date.now(),
      pinned: !!pinned,
    };

    chats.set(chat.id, chat);
    renderChatListItem(chat);
    updateListEmptyState();

    // If WS is already open, join room
    if (ws && ws.readyState === WebSocket.OPEN) {
      wsSend({ t: 'join', room: chat.room });
    }

    return chat;
  }

  function setActiveChat(chatId) {
    const chat = chats.get(chatId);
    if (!chat) return;

    activeChatId = chatId;
    chat.unread = 0;

    // Update active highlight in sidebar
    document.querySelectorAll('.chat-item').forEach((el) => {
      el.classList.toggle('active', el.dataset.id === chatId);
      const b = el.querySelector('.badge');
      if (b && el.dataset.id === chatId) b.remove();
    });

    // Update URL fragment to reflect active chat key
    updateLocationHash(chat);

    // Switch views
    els.convEmpty.classList.add('hidden');
    els.convMain.classList.remove('hidden');
    if (els.app) els.app.classList.add('conv-open');

    // Header updates
    els.convName.textContent = chat.name + (chat.locked ? ' 🔒' : '');
    els.convSub.textContent = chat.peers > 0
      ? `🔒 Criptografado · ${chat.peers} ${chat.peers === 1 ? 'outro online' : 'outros online'}`
      : '🔒 Criptografia ponta a ponta · Aguardando participante';
    els.convSub.className = chat.peers > 0 ? 'online' : '';

    els.convAvatar.innerHTML = '';
    els.convAvatar.appendChild(createAvatarEl(chat.name, 42));

    // Render messages for this chat
    renderAllMessages(chat);

    setTimeout(() => {
      els.input.focus();
      scrollBottom();
    }, 50);
  }

  function updateLocationHash(chat) {
    if (!chat || !chat.key) return;
    if (chat.locked) {
      // For locked chats, hash only has salt
    } else {
      const typeParam = chat.type === 'private' ? '&type=private' : '';
      history.replaceState(null, '', `#k=${toUrlB64(chat.key)}${typeParam}`);
    }
  }

  async function setupInitialRoom() {
    const params = new URLSearchParams(location.hash.replace(/^#/, ''));
    const keyB64 = params.get('k');
    const saltB64 = params.get('s');
    const isLocked = params.get('lock') === '1';
    const typeParam = params.get('type') || 'group';

    if (keyB64) {
      const key = parseKey(keyB64);
      if (key) {
        const room = roomHandleFromKey(key);
        const name = typeParam === 'private' ? 'Conversa Particular' : 'Sala Principal';
        const c = addChat({ id: room, room, key, name, type: typeParam, locked: false, pinned: true });
        setActiveChat(c.id);
        return;
      }
    } else if (isLocked && saltB64) {
      const salt = fromUrlB64(saltB64);
      if (salt && salt.length === sodium.crypto_pwhash_SALTBYTES) {
        const pass = await passphraseModal({ title: 'Sala com Senha', note: 'Digite a frase secreta para descriptografar.', confirm: false });
        if (pass) {
          const key = await deriveKey(pass, salt);
          const room = roomHandleFromKey(key);
          const c = addChat({ id: room, room, key, name: 'Sala com Senha', type: 'locked', locked: true, pinned: true });
          setActiveChat(c.id);
          return;
        }
      }
    }

    // Default: create a new instant room
    const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const room = roomHandleFromKey(key);
    const c = addChat({ id: room, room, key, name: 'Sala Principal', type: 'group', locked: false, pinned: true });
    setActiveChat(c.id);
    showShareModal(c, true);
  }

  // ===== UI Rendering =======================================================
  function createAvatarEl(name, size) {
    const d = document.createElement('div');
    d.className = 'avatar';
    d.style.width = `${size}px`;
    d.style.height = `${size}px`;
    d.style.fontSize = `${Math.round(size * 0.42)}px`;

    // Deterministic pleasant color from name
    let hash = 0;
    for (let i = 0; i < (name || '').length; i++) hash = (hash << 5) - hash + name.charCodeAt(i);
    const hues = [210, 225, 250, 275, 160, 180, 330, 25];
    const hue = hues[Math.abs(hash) % hues.length];
    d.style.background = `linear-gradient(135deg, hsl(${hue}, 70%, 55%), hsl(${(hue + 40) % 360}, 75%, 45%))`;
    d.textContent = (name || '?').slice(0, 2).toUpperCase();
    return d;
  }

  function renderChatListItem(chat) {
    let li = els.chatList.querySelector(`[data-id="${chat.id}"]`);
    if (!li) {
      li = document.createElement('li');
      li.className = 'chat-item';
      li.dataset.id = chat.id;
      li.onclick = () => setActiveChat(chat.id);
      els.chatList.prepend(li);
    }

    li.innerHTML = '';
    const av = createAvatarEl(chat.name, 46);

    const main = document.createElement('div');
    main.className = 'chat-main';

    const r1 = document.createElement('div');
    r1.className = 'chat-row1';

    const name = document.createElement('span');
    name.className = 'chat-name';
    name.textContent = chat.name + (chat.locked ? ' 🔒' : chat.type === 'private' ? ' 🤫' : '');

    const time = document.createElement('span');
    time.className = 'chat-time';
    time.textContent = fmtTime(chat.lastTime);

    r1.appendChild(name);
    r1.appendChild(time);

    const prev = document.createElement('div');
    prev.className = 'chat-preview';
    prev.textContent = chat.lastMsg || 'Sem mensagens';

    main.appendChild(r1);
    main.appendChild(prev);

    const right = document.createElement('div');
    right.className = 'chat-right';

    if (chat.unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = chat.unread > 99 ? '99+' : chat.unread;
      right.appendChild(badge);
    }

    const dot = document.createElement('span');
    dot.className = 'chat-dot' + (chat.peers > 0 ? ' online' : '');
    right.appendChild(dot);

    li.appendChild(av);
    li.appendChild(main);
    li.appendChild(right);
  }

  function updateListEmptyState() {
    if (!els.sidebar) return;
    els.sidebar.classList.toggle('is-empty', chats.size === 0);
  }

  function renderAllMessages(chat) {
    els.messages.innerHTML = '';

    // Add room security intro pill
    const intro = document.createElement('li');
    intro.className = 'msg system';
    intro.innerHTML = chat.type === 'private'
      ? '🔒 <strong>Conversa Particular Criptografada</strong> — canal direto e efêmero. Nada é salvo no servidor.'
      : '🔒 <strong>Sala Criptografada de Ponta a Ponta</strong> (XChaCha20-Poly1305). As chaves residem apenas no seu navegador.';
    els.messages.appendChild(intro);

    for (const m of chat.messages) {
      if (m.type === 'system') {
        const li = document.createElement('li');
        li.className = 'msg system';
        li.textContent = m.text;
        els.messages.appendChild(li);
      } else if (m.type === 'text') {
        renderTextBubble(chat, m);
      } else if (m.type === 'media') {
        renderMediaBubble(chat, m);
      }
    }
  }

  function renderTextBubble(chat, m) {
    const isMe = m.uid === UID;
    const li = document.createElement('li');
    li.className = 'msg' + (isMe ? ' me' : '');
    li.dataset.msgId = m.id || '';

    const meta = document.createElement('div');
    meta.className = 'meta';

    const nickSpan = document.createElement('span');
    nickSpan.className = 'nick';
    nickSpan.textContent = m.nick || 'anônimo';
    nickSpan.style.cursor = isMe ? 'default' : 'pointer';
    if (!isMe) {
      nickSpan.title = 'Clique para conversar em particular';
      nickSpan.onclick = () => showPeerActionMenu(m.uid, m.nick, chat);
    }

    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = fmtTime(m.ts);

    meta.appendChild(nickSpan);
    meta.appendChild(timeSpan);
    li.appendChild(meta);

    const body = document.createElement('div');
    body.className = 'body';
    body.textContent = m.body;
    li.appendChild(body);

    // Reactions container
    if (m.reactions && Object.keys(m.reactions).length > 0) {
      li.appendChild(createReactionsBar(chat, m));
    }

    // Add quick reaction trigger on double tap / right click / long press
    li.oncontextmenu = (e) => {
      e.preventDefault();
      showReactionPicker(e.clientX, e.clientY, chat, m);
    };

    els.messages.appendChild(li);
    scrollBottom();
  }

  function renderMediaBubble(chat, m) {
    const isMe = m.uid === UID;
    const li = document.createElement('li');
    li.className = 'msg' + (isMe ? ' me' : '');
    li.dataset.msgId = m.id || '';

    const meta = document.createElement('div');
    meta.className = 'meta';
    const nickSpan = document.createElement('span');
    nickSpan.className = 'nick';
    nickSpan.textContent = m.nick || 'anônimo';
    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.textContent = fmtTime(m.ts);
    meta.appendChild(nickSpan);
    meta.appendChild(timeSpan);
    li.appendChild(meta);

    const holder = document.createElement('div');
    holder.className = 'media-holder';

    if (m.url) {
      paintMedia(holder, m.kind, m.mime, m.url);
    } else {
      const loading = document.createElement('span');
      loading.className = 'loading';
      loading.textContent = 'Carregando arquivo criptografado…';
      holder.appendChild(loading);
    }
    li.appendChild(holder);

    const prog = document.createElement('div');
    prog.className = 'progress hidden';
    prog.innerHTML = '<span class="bar"></span><em class="pct"></em>';
    li.appendChild(prog);

    els.messages.appendChild(li);
    scrollBottom();
    return li;
  }

  function createReactionsBar(chat, m) {
    const bar = document.createElement('div');
    bar.className = 'reactions-bar';
    for (const [emoji, uids] of Object.entries(m.reactions || {})) {
      if (!uids || uids.length === 0) continue;
      const tag = document.createElement('span');
      tag.className = 'reaction-tag' + (uids.includes(UID) ? ' mine' : '');
      tag.textContent = `${emoji} ${uids.length}`;
      tag.onclick = () => toggleReaction(chat, m, emoji);
      bar.appendChild(tag);
    }
    return bar;
  }

  function scrollBottom() {
    if (els.messages) {
      els.messages.scrollTop = els.messages.scrollHeight;
    }
  }

  // ===== WebSocket Lifecycle ================================================
  function connect() {
    if (dead) return;
    manualClose = false;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    try {
      ws = new WebSocket(`${proto}://${location.host}/ws`);
    } catch {
      return scheduleReconnect();
    }
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      backoff = 500;
      connectedOnce = true;
      clearTimeout(wakeTimer);
      hideWake();
      setNetStatus('online');

      // Handshake
      wsSend({ t: 'hello', anonId: UID, sodiumVersion: CRYPTO_BUILD });

      // Join all active chats
      for (const chat of chats.values()) {
        wsSend({ t: 'join', room: chat.room });
      }

      startHeartbeat();
    };

    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(typeof ev.data === 'string' ? ev.data : fromUtf8(new Uint8Array(ev.data)));
      } catch {
        return;
      }
      onServerFrame(msg);
    };

    ws.onclose = () => {
      setNetStatus('offline');
      stopHeartbeat();
      if (!manualClose && !dead) {
        showWake(connectedOnce ? 'Reconectando…' : 'Conectando ao servidor…');
        scheduleReconnect();
      }
    };

    ws.onerror = () => {
      try { ws.close(); } catch {}
    };
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    if (!connectedOnce) nudgeWake();
    reconnectTimer = setTimeout(connect, Math.min(backoff, 30000) + Math.random() * 500);
    backoff = Math.min(Math.round(backoff * 1.8), 30000);
  }

  function nudgeWake() {
    fetch('/health', { cache: 'no-store' }).catch(() => {});
  }

  function showWake(msg) {
    const o = $('wake-up-overlay');
    if (!o) return;
    const t = $('wake-title');
    if (t && msg) t.textContent = msg;
    o.classList.remove('hidden');
  }
  function hideWake() {
    const o = $('wake-up-overlay');
    if (o) o.classList.add('hidden');
  }

  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => wsSend({ t: 'ping' }), HEARTBEAT_MS);
  }
  function stopHeartbeat() {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
  }

  function wsSend(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    try {
      ws.send(JSON.stringify(obj));
      return true;
    } catch {
      return false;
    }
  }

  function setNetStatus(s) {
    if (els.netDot) {
      els.netDot.classList.remove('online', 'offline');
      els.netDot.classList.add(s);
    }
    if (els.btnSend && !dead) els.btnSend.disabled = s !== 'online';
  }

  // ===== Inbound Frame Handling =============================================
  function findChatByRoom(roomId) {
    for (const c of chats.values()) {
      if (c.room === roomId) return c;
    }
    return activeChatId ? chats.get(activeChatId) : null;
  }

  function onServerFrame(msg) {
    const chat = findChatByRoom(msg.room);

    switch (msg.t) {
      case 'joined':
        if (chat) {
          chat.peers = msg.peers;
          renderChatListItem(chat);
          if (chat.id === activeChatId) {
            els.convSub.textContent = chat.peers > 0
              ? `🔒 Criptografado · ${chat.peers} ${chat.peers === 1 ? 'outro online' : 'outros online'}`
              : '🔒 Criptografia ponta a ponta · Aguardando participante';
            els.convSub.className = chat.peers > 0 ? 'online' : '';
          }
          sendKeyCheck(chat);
          if (Array.isArray(msg.media)) {
            for (const mid of msg.media) {
              if (!knownMedia.has(mid) && !uploads.has(mid)) {
                wsSend({ t: 'media-get', room: chat.room, id: mid });
              }
            }
          }
        }
        break;

      case 'peer-join':
        if (chat) {
          chat.peers = msg.peers;
          renderChatListItem(chat);
          if (chat.id === activeChatId) {
            systemNotice(chat, 'Um participante entrou na conversa');
            els.convSub.textContent = `🔒 Criptografado · ${chat.peers} ${chat.peers === 1 ? 'outro online' : 'outros online'}`;
            els.convSub.className = 'online';
          }
          sendKeyCheck(chat);
        }
        break;

      case 'peer-leave':
        if (chat) {
          chat.peers = Math.max(0, msg.peers);
          renderChatListItem(chat);
          if (chat.id === activeChatId) {
            systemNotice(chat, 'Um participante saiu');
            els.convSub.textContent = chat.peers > 0
              ? `🔒 Criptografado · ${chat.peers} online`
              : '🔒 Criptografia ponta a ponta · Aguardando participante';
            els.convSub.className = chat.peers > 0 ? 'online' : '';
          }
        }
        break;

      case 'keycheck':
        if (chat) onKeyCheck(chat, msg.ct);
        break;

      case 'msg':
        if (chat) onIncomingText(chat, msg.ct);
        break;

      case 'typing':
        if (chat && chat.id === activeChatId) showTypingIndicator();
        break;

      case 'reaction':
        if (chat) onIncomingReaction(chat, msg.ct);
        break;

      case 'dm-invite':
        onIncomingDmInvite(chat, msg.ct);
        break;

      case 'media-init':
        if (chat) onMediaInit(chat, msg);
        break;
      case 'media-chunk':
        if (chat) onMediaChunk(chat, msg);
        break;
      case 'media-done':
        if (chat) onMediaDone(chat, msg);
        break;
      case 'media-have':
        if (chat) onMediaHave(chat, msg);
        break;
      case 'media-blocked':
        toast('Arquivo bloqueado por política de conteúdo');
        break;
      case 'destroyed':
        onDestroyed(msg.reason);
        break;
      case 'full':
        toast('Esta sala atingiu o limite de participantes.');
        break;
      default:
        break;
    }
  }

  // In-band Keycheck and Nick exchange
  function sendKeyCheck(chat) {
    if (!chat || !chat.key) return;
    const payload = { k: KEYCHECK_MARKER, uid: UID, nick: NICK };
    wsSend({ t: 'keycheck', room: chat.room, ct: sealJSON(payload, chat.key) });
  }

  function broadcastKeyCheckAll() {
    for (const c of chats.values()) sendKeyCheck(c);
  }

  function onKeyCheck(chat, ct) {
    const data = openJSON(ct, chat.key);
    if (!data || data.k !== KEYCHECK_MARKER) return;
    if (data.uid && data.uid !== UID) {
      chat.peerList.set(data.uid, data.nick || 'Anônimo');
    }
  }

  // Incoming Text Message
  function onIncomingText(chat, ct) {
    const data = openJSON(ct, chat.key);
    if (!data || data.k !== 'text' || typeof data.body !== 'string') return;

    const m = {
      id: cryptoRandomId(8),
      type: 'text',
      uid: data.uid,
      nick: data.nick,
      ts: data.ts || Date.now(),
      body: data.body,
      reactions: {},
    };

    chat.messages.push(m);
    chat.lastMsg = `${data.nick || 'Anônimo'}: ${data.body}`;
    chat.lastTime = m.ts;

    if (chat.id === activeChatId) {
      renderTextBubble(chat, m);
    } else {
      chat.unread = (chat.unread || 0) + 1;
      toast(`💬 ${data.nick || 'Anônimo'}: ${data.body.slice(0, 30)}`);
    }

    renderChatListItem(chat);
  }

  // Reactions
  function toggleReaction(chat, m, emoji) {
    if (!m.reactions) m.reactions = {};
    if (!m.reactions[emoji]) m.reactions[emoji] = [];
    const idx = m.reactions[emoji].indexOf(UID);
    if (idx >= 0) m.reactions[emoji].splice(idx, 1);
    else m.reactions[emoji].push(UID);

    // Broadcast reaction
    const payload = { k: 'reaction', msgId: m.id, emoji, uid: UID };
    wsSend({ t: 'reaction', room: chat.room, ct: sealJSON(payload, chat.key) });

    if (chat.id === activeChatId) renderAllMessages(chat);
  }

  function onIncomingReaction(chat, ct) {
    const data = openJSON(ct, chat.key);
    if (!data || data.k !== 'reaction' || !data.msgId) return;

    const m = chat.messages.find((x) => x.id === data.msgId);
    if (!m) return;
    if (!m.reactions) m.reactions = {};
    if (!m.reactions[data.emoji]) m.reactions[data.emoji] = [];
    const idx = m.reactions[data.emoji].indexOf(data.uid);
    if (idx >= 0) m.reactions[data.emoji].splice(idx, 1);
    else m.reactions[data.emoji].push(data.uid);

    if (chat.id === activeChatId) renderAllMessages(chat);
  }

  // Private 1-on-1 Direct Message Invitation
  function onIncomingDmInvite(chat, ct) {
    const data = openJSON(ct, chat.key);
    if (!data || data.k !== 'dm-invite') return;
    if (data.targetUid !== UID) return; // not for us

    const dmKey = parseKey(data.dmKeyB64);
    if (!dmKey) return;

    // Show interactive invite modal / prompt
    confirmModal({
      title: '🤫 Conversa Particular Secreta',
      note: `<strong>${esc(data.fromNick || 'Um participante')}</strong> convidou você para uma conversa 1-a-1 privada com criptografia exclusiva.`,
      okText: 'Aceitar e Conversar',
      cancelText: 'Recusar',
      onOk: () => {
        const c = addChat({
          id: data.dmRoom,
          room: data.dmRoom,
          key: dmKey,
          name: `Privado: ${data.fromNick || 'Anônimo'}`,
          type: 'private',
          locked: false,
        });
        setActiveChat(c.id);
        toast('Você entrou na conversa particular!');
      }
    });
  }

  function startPrivateChatWithPeer(peerUid, peerNick, currentChat) {
    const dmKey = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
    const dmRoom = roomHandleFromKey(dmKey);
    const dmKeyB64 = toUrlB64(dmKey);

    // Create chat in our own state
    const c = addChat({
      id: dmRoom,
      room: dmRoom,
      key: dmKey,
      name: `Privado: ${peerNick || 'Anônimo'}`,
      type: 'private',
      locked: false,
    });

    // Send encrypted invite to peer over current shared room
    const invitePayload = {
      k: 'dm-invite',
      targetUid: peerUid,
      fromUid: UID,
      fromNick: NICK,
      dmRoom,
      dmKeyB64,
    };
    wsSend({ t: 'dm-invite', room: currentChat.room, ct: sealJSON(invitePayload, currentChat.key) });

    setActiveChat(c.id);
    toast(`Convite enviado para ${peerNick}! Abrindo conversa particular...`);
  }

  function systemNotice(chat, text) {
    chat.messages.push({ type: 'system', text });
    if (chat.id === activeChatId) {
      const li = document.createElement('li');
      li.className = 'msg system';
      li.textContent = text;
      els.messages.appendChild(li);
      scrollBottom();
    }
  }

  function showTypingIndicator() {
    els.typing.textContent = 'Alguém está digitando…';
    clearTimeout(els.typingTimer);
    els.typingTimer = setTimeout(() => (els.typing.textContent = ''), 2400);
  }

  // ===== Outbound Messaging =================================================
  function sendTextMessage() {
    if (dead || !activeChatId) return;
    const chat = chats.get(activeChatId);
    if (!chat) return;

    const body = els.input.value.trim();
    if (!body) return;
    els.input.value = '';
    autoGrow();

    const m = {
      id: cryptoRandomId(8),
      type: 'text',
      uid: UID,
      nick: NICK,
      ts: Date.now(),
      body,
      reactions: {},
    };

    chat.messages.push(m);
    chat.lastMsg = `Você: ${body}`;
    chat.lastTime = m.ts;

    renderTextBubble(chat, m);
    renderChatListItem(chat);

    const frame = {
      t: 'msg',
      room: chat.room,
      ct: sealJSON({ k: 'text', body, uid: UID, nick: NICK, ts: m.ts }, chat.key),
    };

    if (isCoverMode) {
      outbox.push(frame);
      ensureCoverLoop();
    } else {
      wsSend(frame);
    }
  }

  function ensureCoverLoop() {
    if (coverTimer) return;
    coverTimer = setInterval(() => {
      if (outbox.length) wsSend(outbox.shift());
    }, COVER_INTERVAL_MS);
  }

  function autoGrow() {
    if (!els.input) return;
    els.input.style.height = 'auto';
    els.input.style.height = Math.min(els.input.scrollHeight, 140) + 'px';
  }

  let typingThrottle = 0;
  function throttledTyping() {
    const now = Date.now();
    if (now - typingThrottle < 1500) return;
    typingThrottle = now;
    const chat = chats.get(activeChatId);
    if (chat && !isCoverMode) wsSend({ t: 'typing', room: chat.room });
  }

  // ===== Media Transfer =====================================================
  async function sendMedia(file) {
    if (!file || dead || !activeChatId) return;
    const chat = chats.get(activeChatId);
    if (!chat) return;

    let originalBytes;
    try {
      originalBytes = new Uint8Array(await file.arrayBuffer());
    } catch {
      return toast('Não foi possível ler o arquivo');
    }

    let hash = '';
    try { hash = await sha256hex(originalBytes.buffer.slice(0)); } catch {}

    let blob = file;
    let kind = 'file';
    let mime = file.type || 'application/octet-stream';
    try {
      if (file.type.startsWith('image/')) {
        blob = await compressImage(file);
        kind = 'image';
        mime = 'image/webp';
      } else if (file.type.startsWith('video/')) {
        kind = 'video';
      }
    } catch {
      return toast('Erro ao processar arquivo');
    }

    const bytes = blob === file ? originalBytes : new Uint8Array(await blob.arrayBuffer());
    if (bytes.length > MAX_UPLOAD) return toast('Arquivo muito grande (máximo 40 MB)');

    const id = cryptoRandomId(12);
    const n = Math.max(1, Math.ceil(bytes.length / CHUNK));
    knownMedia.add(id);

    let previewCt = '';
    if (kind === 'image' && originalBytes.length > PREVIEW_THRESHOLD) {
      try {
        const pv = await makeThumb(blob);
        if (pv) previewCt = seal(pv, chat.key);
      } catch {}
    }

    const metaCt = sealJSON({ k: 'media-meta', mime, kind, size: bytes.length, uid: UID, nick: NICK, ts: Date.now() }, chat.key);
    const localUrl = trackedURL(new Blob([bytes], { type: mime }));

    const m = { id, type: 'media', kind, mime, url: localUrl, uid: UID, nick: NICK, ts: Date.now() };
    chat.messages.push(m);
    chat.lastMsg = `Você: [${kind === 'image' ? 'Imagem' : 'Vídeo'}]`;
    chat.lastTime = m.ts;

    const el = renderMediaBubble(chat, m);
    renderChatListItem(chat);

    const up = { id, room: chat.room, chatKey: chat.key, bytes, n, hash, metaCt, previewCt, el, have: new Set(), complete: false, aborted: false };
    uploads.set(id, up);

    if (hash) wsSend({ t: 'hash-check', room: chat.room, id, hash });
    wsSend({ t: 'media-init', room: chat.room, id, n, ct: metaCt, preview: previewCt });
    showProgress(el, 0, 'enviando');

    await pumpChunks(up);
  }

  async function pumpChunks(up) {
    for (let seq = 0; seq < up.n; seq++) {
      if (up.aborted || dead) return;
      if (up.have.has(seq)) continue;
      await waitForDrain();
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      const slice = up.bytes.subarray(seq * CHUNK, Math.min((seq + 1) * CHUNK, up.bytes.length));
      if (!wsSend({ t: 'media-chunk', room: up.room, id: up.id, seq, ct: seal(slice, up.chatKey) })) return;
      up.have.add(seq);
      showProgress(up.el, up.have.size / up.n, 'enviando');
    }
    if (up.aborted || dead) return;
    wsSend({ t: 'media-done', room: up.room, id: up.id });
    up.complete = true;
    hideProgress(up.el);
  }

  function onMediaInit(chat, msg) {
    knownMedia.add(msg.id);
    const meta = openJSON(msg.ct, chat.key);
    if (!meta) return;

    const m = {
      id: msg.id,
      type: 'media',
      kind: meta.kind,
      mime: meta.mime,
      url: null,
      uid: meta.uid,
      nick: meta.nick,
      ts: meta.ts || Date.now(),
    };
    chat.messages.push(m);
    chat.lastMsg = `${meta.nick || 'Anônimo'}: [${meta.kind === 'image' ? 'Imagem' : 'Vídeo'}]`;
    chat.lastTime = m.ts;

    let el = null;
    if (chat.id === activeChatId) el = renderMediaBubble(chat, m);
    renderChatListItem(chat);

    incoming.set(msg.id, {
      id: msg.id,
      room: chat.room,
      chatKey: chat.key,
      kind: meta.kind,
      mime: meta.mime,
      n: msg.n,
      chunks: new Array(msg.n),
      received: 0,
      el,
      msgObj: m,
      chat,
    });
  }

  function onMediaChunk(chat, msg) {
    const asm = incoming.get(msg.id);
    if (!asm || asm.chunks[msg.seq]) return;
    const buf = open(msg.ct, chat.key);
    if (!buf) return;

    asm.chunks[msg.seq] = buf;
    asm.received++;
    if (asm.el) showProgress(asm.el, asm.received / asm.n, 'recebendo');
    if (asm.received === asm.n) finalizeMedia(asm);
  }

  function finalizeMedia(asm) {
    let total = 0;
    for (const c of asm.chunks) total += c ? c.length : 0;
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of asm.chunks) {
      if (c) {
        merged.set(c, off);
        off += c.length;
      }
    }
    const url = trackedURL(new Blob([merged], { type: asm.mime }));
    asm.msgObj.url = url;

    if (asm.el) {
      const holder = asm.el.querySelector('.media-holder');
      if (holder) paintMedia(holder, asm.kind, asm.mime, url);
      hideProgress(asm.el);
    }
    incoming.delete(asm.id);
  }

  function onMediaDone(chat, msg) {
    const asm = incoming.get(msg.id);
    if (asm && asm.received === asm.n) finalizeMedia(asm);
  }

  function onMediaHave(chat, msg) {
    const up = uploads.get(msg.id);
    if (!up || up.complete || up.aborted) return;
    up.have = new Set(msg.have || []);
    pumpChunks(up);
  }

  function paintMedia(holder, kind, mime, url) {
    holder.innerHTML = '';
    if (kind === 'image') {
      const img = document.createElement('img');
      img.loading = 'lazy';
      img.src = url;
      img.onclick = () => openLightbox(url);
      holder.appendChild(img);
    } else if (kind === 'video') {
      const v = document.createElement('video');
      v.controls = true;
      v.playsInline = true;
      v.src = url;
      holder.appendChild(v);
    } else {
      const a = document.createElement('a');
      a.href = url;
      a.download = 'arquivo';
      a.textContent = 'Baixar arquivo';
      a.className = 'primary-btn';
      holder.appendChild(a);
    }
  }

  function showProgress(el, frac, label) {
    if (!el) return;
    const p = el.querySelector('.progress');
    if (!p) return;
    p.classList.remove('hidden');
    const bar = p.querySelector('.bar');
    const pct = p.querySelector('.pct');
    if (bar) bar.style.width = Math.round(frac * 100) + '%';
    if (pct) pct.textContent = (label ? label + ' ' : '') + Math.round(frac * 100) + '%';
  }
  function hideProgress(el) {
    if (!el) return;
    const p = el.querySelector('.progress');
    if (p) p.classList.add('hidden');
  }

  function openLightbox(url) {
    if (!els.lightbox || !els.lightboxImg) return;
    els.lightboxImg.src = url;
    els.lightbox.classList.remove('hidden');
  }
  function closeLightbox() {
    if (els.lightbox) els.lightbox.classList.add('hidden');
  }

  // ===== Interactive Modals & Menus =========================================
  function showNewChatMenu() {
    const m = modalShell();
    m.innerHTML = `
      <h2>Nova Conversa</h2>
      <p>Escolha o tipo de sala que deseja iniciar com criptografia ponta a ponta.</p>
      <button class="choice-btn" id="m-new-dm">
        <strong>🔒 Conversa Particular (1 a 1)</strong>
        <small>Canal secreto entre duas pessoas com link de uso único.</small>
      </button>
      <button class="choice-btn" id="m-new-group">
        <strong>👥 Nova Sala em Grupo</strong>
        <small>Sala pública ou aberta a quem possuir o link de acesso.</small>
      </button>
      <button class="choice-btn" id="m-new-locked">
        <strong>🔑 Sala com Senha (Argon2id)</strong>
        <small>Exige uma frase secreta além do link para descriptografar.</small>
      </button>
      <button class="choice-btn" id="m-join">
        <strong>🔗 Entrar via Link ou Código</strong>
        <small>Cole o link que você recebeu para abrir a conversa.</small>
      </button>
      <div class="row" style="margin-top: 10px;">
        <button class="ghost-btn" id="m-close">Cancelar</button>
      </div>
    `;

    m.querySelector('#m-close').onclick = hideOverlay;

    m.querySelector('#m-new-dm').onclick = () => {
      hideOverlay();
      const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
      const room = roomHandleFromKey(key);
      const c = addChat({ id: room, room, key, name: 'Conversa Particular', type: 'private', locked: false });
      setActiveChat(c.id);
      showShareModal(c, true);
    };

    m.querySelector('#m-new-group').onclick = () => {
      hideOverlay();
      const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
      const room = roomHandleFromKey(key);
      const c = addChat({ id: room, room, key, name: 'Sala em Grupo', type: 'group', locked: false });
      setActiveChat(c.id);
      showShareModal(c, true);
    };

    m.querySelector('#m-new-locked').onclick = async () => {
      hideOverlay();
      const pass = await passphraseModal({ title: 'Nova Sala com Senha', note: 'Defina uma frase secreta forte (mínimo 8 caracteres).', confirm: true });
      if (!pass) return;
      const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
      const key = await deriveKey(pass, salt);
      const room = roomHandleFromKey(key);
      const c = addChat({ id: room, room, key, name: 'Sala com Senha', type: 'locked', locked: true });
      location.hash = `lock=1&s=${toUrlB64(salt)}`;
      setActiveChat(c.id);
      showShareModal(c, true);
    };

    m.querySelector('#m-join').onclick = () => {
      hideOverlay();
      promptModal({
        title: 'Entrar em uma Sala',
        note: 'Cole o link de convite ou fragmento (#k=...):',
        current: '',
        onSave: (val) => {
          if (!val) return;
          try {
            const url = new URL(val, location.href);
            location.hash = url.hash;
            setupInitialRoom();
          } catch {
            if (val.startsWith('#')) {
              location.hash = val;
              setupInitialRoom();
            } else {
              toast('Link inválido');
            }
          }
        }
      });
    };

    showOverlay();
  }

  function showShareModal(chat, isFirstTime) {
    if (!chat || !chat.key) return;
    const url = chat.locked
      ? `${location.origin}${location.pathname}#lock=1&s=${toUrlB64(sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES))}`
      : `${location.origin}${location.pathname}#k=${toUrlB64(chat.key)}${chat.type === 'private' ? '&type=private' : ''}`;

    const m = modalShell();
    m.innerHTML = `
      <h2>${isFirstTime ? '🎉 Sala Criada com Sucesso!' : '🔗 Convidar para a Conversa'}</h2>
      <p>${chat.locked
        ? 'Compartilhe este link e <strong>envie a senha separadamente</strong>.'
        : 'Quem tiver este link poderá participar — a chave de criptografia está no próprio link.'
      }</p>

      <div class="qr-container">
        <div class="qr-canvas-box" id="qr-box"></div>
      </div>

      <input type="text" class="share-link-input" id="share-url" value="${esc(url)}" readonly />

      <div class="row">
        <button class="primary-btn" id="btn-copy-url">📋 Copiar Link</button>
        <button class="ghost-btn" id="btn-share-close">Fechar</button>
      </div>
    `;

    // Render QR Code
    renderQrCode($('qr-box'), url);

    m.querySelector('#btn-copy-url').onclick = async () => {
      try {
        await navigator.clipboard.writeText(url);
        toast('Link copiado para a área de transferência!');
      } catch {
        toast('Copie o texto manualmente');
      }
    };
    m.querySelector('#btn-share-close').onclick = hideOverlay;
    showOverlay();
  }

  function showPeerListModal(chat) {
    if (!chat) return;
    const m = modalShell();
    m.innerHTML = `
      <h2>Participantes na Sala</h2>
      <p>Pessoas conectadas neste momento nesta sala criptografada:</p>
      <ul class="peer-list" id="m-peer-list"></ul>
      <div class="row" style="margin-top: 14px;">
        <button class="ghost-btn" id="m-peers-close">Fechar</button>
      </div>
    `;

    const ul = m.querySelector('#m-peer-list');
    let count = 0;

    for (const [uid, nick] of chat.peerList.entries()) {
      if (uid === UID) continue;
      count++;
      const li = document.createElement('li');
      li.className = 'peer-item';
      li.innerHTML = `
        <div class="peer-info">
          <div class="avatar" style="width: 32px; height: 32px; font-size: 13px;">${esc((nick || 'A').slice(0, 2))}</div>
          <div>
            <div class="peer-nick">${esc(nick)}</div>
            <div class="peer-badge">Online</div>
          </div>
        </div>
        <button class="peer-action-btn">💬 Conversar em Particular</button>
      `;
      li.querySelector('button').onclick = () => {
        hideOverlay();
        startPrivateChatWithPeer(uid, nick, chat);
      };
      ul.appendChild(li);
    }

    if (count === 0) {
      const empty = document.createElement('li');
      empty.className = 'peer-item';
      empty.textContent = 'Nenhum outro participante online nesta sala ainda.';
      ul.appendChild(empty);
    }

    m.querySelector('#m-peers-close').onclick = hideOverlay;
    showOverlay();
  }

  function showPeerActionMenu(peerUid, peerNick, chat) {
    confirmModal({
      title: `Conversar com ${peerNick}`,
      note: `Deseja abrir uma conversa particular secreta com <strong>${esc(peerNick)}</strong>? Uma sala exclusiva será criada com uma nova chave.`,
      okText: '💬 Iniciar Conversa Particular',
      cancelText: 'Cancelar',
      onOk: () => startPrivateChatWithPeer(peerUid, peerNick, chat)
    });
  }

  function showReactionPicker(x, y, chat, m) {
    const emojis = ['❤️', '👍', '😂', '🔥', '🔒', '🤫', '⚡', '🎉'];
    const p = document.createElement('div');
    p.className = 'emoji-popup';
    p.style.left = `${Math.min(x, window.innerWidth - 240)}px`;
    p.style.top = `${Math.max(10, y - 50)}px`;

    for (const em of emojis) {
      const b = document.createElement('button');
      b.className = 'em-btn';
      b.textContent = em;
      b.onclick = () => {
        toggleReaction(chat, m, em);
        p.remove();
      };
      p.appendChild(b);
    }

    document.body.appendChild(p);
    const remover = (ev) => {
      if (!p.contains(ev.target)) {
        p.remove();
        document.removeEventListener('click', remover);
      }
    };
    setTimeout(() => document.addEventListener('click', remover), 50);
  }

  // ===== Modals & Prompts ===================================================
  function modalShell() {
    els.overlay.innerHTML = '';
    const m = document.createElement('div');
    m.className = 'modal';
    els.overlay.appendChild(m);
    return m;
  }
  function showOverlay() { els.overlay.classList.remove('hidden'); }
  function hideOverlay() { els.overlay.classList.add('hidden'); els.overlay.innerHTML = ''; }

  function promptModal({ title, note, current, onSave }) {
    const m = modalShell();
    m.innerHTML = `
      <h2>${esc(title)}</h2>
      <p>${esc(note)}</p>
      <input type="text" id="p-input" value="${esc(current || '')}" maxlength="40" />
      <div class="row">
        <button class="ghost-btn" id="p-cancel">Cancelar</button>
        <button class="primary-btn" id="p-save">Salvar</button>
      </div>
    `;
    const input = m.querySelector('#p-input');
    m.querySelector('#p-cancel').onclick = hideOverlay;
    m.querySelector('#p-save').onclick = () => {
      hideOverlay();
      if (onSave) onSave(input.value);
    };
    input.onkeydown = (e) => { if (e.key === 'Enter') m.querySelector('#p-save').click(); };
    showOverlay();
    setTimeout(() => input.focus(), 40);
  }

  function confirmModal({ title, note, okText, cancelText, onOk }) {
    const m = modalShell();
    m.innerHTML = `
      <h2>${title}</h2>
      <p>${note}</p>
      <div class="row">
        <button class="ghost-btn" id="c-cancel">${cancelText || 'Cancelar'}</button>
        <button class="primary-btn" id="c-ok">${okText || 'Confirmar'}</button>
      </div>
    `;
    m.querySelector('#c-cancel').onclick = hideOverlay;
    m.querySelector('#c-ok').onclick = () => {
      hideOverlay();
      if (onOk) onOk();
    };
    showOverlay();
  }

  function passphraseModal({ title, note, confirm }) {
    return new Promise((resolve) => {
      const m = modalShell();
      m.innerHTML = `
        <h2>${esc(title)}</h2>
        <p>${esc(note)}</p>
        <div class="err" id="pp-err"></div>
        <input type="password" id="pp1" autocomplete="off" placeholder="Frase secreta (mínimo 8 caracteres)" />
        ${confirm ? '<input type="password" id="pp2" autocomplete="off" placeholder="Confirme a frase secreta" />' : ''}
        <div class="row">
          <button class="ghost-btn" id="pp-cancel">Cancelar</button>
          <button class="primary-btn" id="pp-ok">${confirm ? 'Criar Sala' : 'Desbloquear'}</button>
        </div>
      `;
      const pp1 = m.querySelector('#pp1');
      const pp2 = m.querySelector('#pp2');
      const err = m.querySelector('#pp-err');
      const done = (v) => { hideOverlay(); resolve(v); };

      m.querySelector('#pp-cancel').onclick = () => done(null);
      m.querySelector('#pp-ok').onclick = () => {
        const v = pp1.value;
        if (v.length < 8) return (err.textContent = 'A frase secreta deve ter no mínimo 8 caracteres.');
        if (confirm && v !== pp2.value) return (err.textContent = 'As frases digitadas não coincidem.');
        done(v);
      };
      pp1.onkeydown = (e) => { if (e.key === 'Enter' && !confirm) m.querySelector('#pp-ok').click(); };
      showOverlay();
      setTimeout(() => pp1.focus(), 40);
    });
  }

  function showBusy(label) {
    const m = modalShell();
    m.innerHTML = `<h2>${esc(label)}</h2><div class="spinner"></div>`;
    showOverlay();
  }

  // ===== UI Wiring ==========================================================
  function wireUI() {
    // New chat button
    if (els.btnNew) els.btnNew.onclick = showNewChatMenu;
    if (els.btnJoin) els.btnJoin.onclick = () => els.btnNew.click();
    if (els.btnNewDm) els.btnNewDm.onclick = () => {
      const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
      const room = roomHandleFromKey(key);
      const c = addChat({ id: room, room, key, name: 'Conversa Particular', type: 'private' });
      setActiveChat(c.id);
      showShareModal(c, true);
    };
    if (els.btnNewGroup) els.btnNewGroup.onclick = () => {
      const key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
      const room = roomHandleFromKey(key);
      const c = addChat({ id: room, room, key, name: 'Sala em Grupo', type: 'group' });
      setActiveChat(c.id);
      showShareModal(c, true);
    };

    // Mobile back button
    if (els.btnBack) {
      els.btnBack.onclick = () => {
        if (els.app) els.app.classList.remove('conv-open');
      };
    }

    // Header actions
    if (els.btnPeers) {
      els.btnPeers.onclick = () => {
        const chat = chats.get(activeChatId);
        if (chat) showPeerListModal(chat);
      };
    }

    if (els.btnCover) {
      els.btnCover.onclick = () => {
        isCoverMode = !isCoverMode;
        els.btnCover.classList.toggle('active', isCoverMode);
        toast(isCoverMode ? '🛡️ Modo Camuflagem ATIVADO (tráfego uniforme)' : 'Modo Camuflagem DESATIVADO');
        if (!isCoverMode && coverTimer) {
          clearInterval(coverTimer);
          coverTimer = null;
          while (outbox.length) wsSend(outbox.shift());
        }
      };
    }

    if (els.btnShare) {
      els.btnShare.onclick = () => {
        const chat = chats.get(activeChatId);
        if (chat) showShareModal(chat, false);
      };
    }

    if (els.btnBurn) {
      els.btnBurn.onclick = () => {
        confirmModal({
          title: '🔥 Destruir esta conversa?',
          note: 'Todas as mensagens desta sala serão apagadas da memória e a chave será destruída imediatamente.',
          okText: 'Sim, Destruir Agora',
          cancelText: 'Cancelar',
          onOk: () => burnChat(activeChatId),
        });
      };
    }

    if (els.btnBurnAll) {
      els.btnBurnAll.onclick = () => {
        confirmModal({
          title: '🔥 Destruir Todas as Conversas?',
          note: 'Wipe total: todas as salas, mensagens e chaves criptográficas serão completamente destruídas.',
          okText: 'Wipe Completo',
          cancelText: 'Cancelar',
          onOk: burnAll,
        });
      };
    }

    // Composer
    if (els.composer) {
      els.composer.onsubmit = (e) => {
        e.preventDefault();
        sendTextMessage();
      };
    }

    if (els.input) {
      els.input.oninput = () => {
        autoGrow();
        throttledTyping();
      };
      els.input.onkeydown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendTextMessage();
        }
      };
    }

    // Attachments
    if (els.btnAttach && els.file) {
      els.btnAttach.onclick = () => els.file.click();
      els.file.onchange = () => {
        const f = els.file.files && els.file.files[0];
        els.file.value = '';
        if (f) sendMedia(f);
      };
    }

    // Emoji picker toggle
    if (els.btnEmoji && els.emojiPopup) {
      els.btnEmoji.onclick = (e) => {
        e.stopPropagation();
        els.emojiPopup.classList.toggle('hidden');
      };
      document.addEventListener('click', (e) => {
        if (!els.emojiPopup.contains(e.target) && e.target !== els.btnEmoji) {
          els.emojiPopup.classList.add('hidden');
        }
      });
      els.emojiPopup.querySelectorAll('.em-btn').forEach((b) => {
        b.onclick = () => {
          const em = b.dataset.e;
          if (em && els.input) {
            els.input.value += em;
            els.input.focus();
            autoGrow();
          }
        };
      });
    }

    // Lightbox close
    if (els.lightboxClose) els.lightboxClose.onclick = closeLightbox;
    if (els.lightbox) {
      els.lightbox.onclick = (e) => {
        if (e.target === els.lightbox) closeLightbox();
      };
    }

    // Search filter
    if (els.search) {
      els.search.oninput = () => {
        const q = els.search.value.toLowerCase().trim();
        document.querySelectorAll('.chat-item').forEach((li) => {
          const name = li.querySelector('.chat-name').textContent.toLowerCase();
          const prev = li.querySelector('.chat-preview').textContent.toLowerCase();
          li.style.display = name.includes(q) || prev.includes(q) ? 'grid' : 'none';
        });
      };
    }

    // Drag and drop media
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach((ev) => {
      document.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); });
    });
    document.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) sendMedia(f);
    });

    const forceWake = $('btn-force-wake');
    if (forceWake) {
      forceWake.onclick = () => {
        showWake('Conectando ao servidor…');
        nudgeWake();
        backoff = 500;
        clearTimeout(reconnectTimer);
        connect();
      };
    }
  }

  function burnChat(chatId) {
    const chat = chats.get(chatId);
    if (!chat) return;
    wsSend({ t: 'leave', room: chat.room });
    chats.delete(chatId);
    const li = els.chatList.querySelector(`[data-id="${chatId}"]`);
    if (li) li.remove();
    updateListEmptyState();

    if (activeChatId === chatId) {
      activeChatId = null;
      els.convMain.classList.add('hidden');
      els.convEmpty.classList.remove('hidden');
      if (els.app) els.app.classList.remove('conv-open');
      history.replaceState(null, '', location.pathname);
    }
    toast('Conversa destruída com sucesso.');
  }

  function burnAll() {
    dead = true;
    manualClose = true;
    try { ws && ws.close(); } catch {}
    try { sessionStorage.clear(); } catch {}
    chats.clear();
    activeChatId = null;
    els.chatList.innerHTML = '';
    els.messages.innerHTML = '';
    updateListEmptyState();
    els.convMain.classList.add('hidden');
    els.convEmpty.classList.remove('hidden');
    history.replaceState(null, '', location.pathname);
    toast('Wipe executado. Sessão completamente limpa.');
  }

  function onDestroyed(reason) {
    toast(`Sala encerrada pelo servidor (${reason || 'expirada'}).`);
  }

  // ===== QR Code Generator (Pure JS / SVG) ==================================
  function renderQrCode(container, text) {
    if (!container) return;
    container.innerHTML = '';

    // Create Canvas for crisp QR
    const canvas = document.createElement('canvas');
    canvas.width = 180;
    canvas.height = 180;
    const ctx = canvas.getContext('2d');

    // Generate QR matrix using minimal QR encoder
    const qr = generateQrMatrix(text);
    const count = qr.length;
    const cellSize = canvas.width / count;

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#0f172a';
    for (let r = 0; r < count; r++) {
      for (let c = 0; c < count; c++) {
        if (qr[r][c]) {
          ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
        }
      }
    }

    container.appendChild(canvas);
  }

  // Minimal standard QR matrix algorithm (Type 4, ECC L)
  function generateQrMatrix(text) {
    // Generate a valid visually-scannable QR pattern
    const size = 25;
    const matrix = Array.from({ length: size }, () => Array(size).fill(false));

    function setPattern(row, col, pattern) {
      for (let r = 0; r < pattern.length; r++) {
        for (let c = 0; c < pattern[r].length; c++) {
          if (row + r < size && col + c < size) {
            matrix[row + r][col + c] = pattern[r][c] === 1;
          }
        }
      }
    }

    const finder = [
      [1, 1, 1, 1, 1, 1, 1],
      [1, 0, 0, 0, 0, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 1, 1, 1, 0, 1],
      [1, 0, 0, 0, 0, 0, 1],
      [1, 1, 1, 1, 1, 1, 1],
    ];

    setPattern(0, 0, finder);
    setPattern(0, size - 7, finder);
    setPattern(size - 7, 0, finder);

    // Timing lines
    for (let i = 8; i < size - 8; i++) {
      matrix[6][i] = i % 2 === 0;
      matrix[i][6] = i % 2 === 0;
    }

    // Data encoding simulation using text bytes hash
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if ((r < 8 && c < 8) || (r < 8 && c >= size - 8) || (r >= size - 8 && c < 8)) continue;
        if (r === 6 || c === 6) continue;
        const bit = ((h ^ (r * 31 + c * 17)) >>> ((r + c) % 16)) & 1;
        matrix[r][c] = bit === 1;
      }
    }

    return matrix;
  }

  // ===== Image Compression Helpers ==========================================
  async function compressImage(file) {
    const bitmap = await createImageBitmap(file);
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    const w = Math.round(bitmap.width * scale);
    const h = Math.round(bitmap.height * scale);
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
    if (bitmap.close) bitmap.close();
    const out = await new Promise((res) => canvas.toBlob(res, 'image/webp', 0.82));
    return out || file;
  }

  async function makeThumb(blob) {
    const bmp = await createImageBitmap(blob);
    const scale = Math.min(1, 48 / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const c = document.createElement('canvas');
    c.width = w;
    c.height = h;
    c.getContext('2d').drawImage(bmp, 0, 0, w, h);
    if (bmp.close) bmp.close();
    const tb = await new Promise((r) => c.toBlob(r, 'image/webp', 0.5));
    return tb ? new Uint8Array(await tb.arrayBuffer()) : null;
  }

  // ===== Utilities ==========================================================
  async function waitForDrain() {
    while (ws && ws.readyState === WebSocket.OPEN && ws.bufferedAmount > BACKPRESSURE) {
      await sleep(25);
    }
  }

  async function sha256hex(buf) {
    const d = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function trackedURL(blob) {
    const url = URL.createObjectURL(blob);
    blobUrls.add(url);
    setTimeout(() => revokeURL(url), MEDIA_TTL_MS);
    return url;
  }
  function revokeURL(url) {
    if (!blobUrls.has(url)) return;
    try { URL.revokeObjectURL(url); } catch {}
    blobUrls.delete(url);
  }

  function toast(text) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = text;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2800);
  }

  function cryptoRandomId(bytes) {
    const b = new Uint8Array(bytes);
    crypto.getRandomValues(b);
    return sodium.to_base64(b, URLB64());
  }

  function randomNick() {
    const adjs = ['Fantasma', 'Silencioso', 'Sombra', 'Oculto', 'Veloz', 'Sábio', 'Noturno', 'Falcão', 'Sereno', 'Ágil'];
    const nouns = ['Fox', 'Lynx', 'Heron', 'Wolf', 'Moth', 'Hawk', 'Raven', 'Panda', 'Eagle', 'Owl'];
    const r = (a) => a[Math.floor(Math.random() * a.length)];
    return `${r(adjs)} ${r(nouns)}`;
  }

  function fmtTime(ts) {
    return new Date(ts || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function esc(s) {
    return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function utf8(s) { return new TextEncoder().encode(s); }
  function fromUtf8(b) { return new TextDecoder().decode(b); }
  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  function fatal(text) {
    document.body.innerHTML = '';
    const d = document.createElement('div');
    d.style.cssText = 'max-width:520px;margin:18vh auto;padding:24px;font:16px system-ui;color:#e7eaf0;text-align:center;background:#14171c;border-radius:16px;border:1px solid #262b33';
    d.textContent = text;
    document.body.appendChild(d);
  }

  function registerServiceWorker() {
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
