/* WhatsApp-like tools. All user-supplied text is inserted through DOM textContent. */
(() => {
    'use strict';
    let owner = '', state = { chats: {}, stars: [] }, contactKeys = new Map();
    let archivedView = false, starredOnly = false, query = '', reply = null, draftTimer;
    let statePromise = null, inputRevision = 0;
    const messages = new Map(), reactions = new Map();
    const el = (tag, text, cls) => { const n = document.createElement(tag); if (text) n.textContent = text; if (cls) n.className = cls; return n; };
    const button = (label, action) => { const b = el('button', label); b.type = 'button'; b.onclick = action; return b; };
    async function api(url, body) {
        const response = await fetch('/api/features/' + url, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
        if (!response.ok) throw new Error('İşlem kaydedilemedi (' + response.status + ')');
        return response.json();
    }
    function hash(value) {
        // Use existing SHA-256 implementation so the tools also work over local HTTP.
        return Array.from(sha256Bytes(normalizeKey(value)), b => b.toString(16).padStart(2, '0')).join('');
    }
    function notice(error) {
        const toast = el('div', error.message || String(error), 'plus-notice');
        toast.setAttribute('role', 'alert'); document.body.append(toast); setTimeout(() => toast.remove(), 5000);
    }
    const prefs = name => {
        const normalized = normalizeKey(name);
        if (!contactKeys.has(normalized)) contactKeys.set(normalized, hash(name));
        return state.chats[contactKeys.get(normalized)] || {};
    };
    function refresh() { renderChatsList(contactsList); applyFilter(); }
    async function ensure() {
        const name = currentUser?.username || '';
        if (name === owner && statePromise) return statePromise;
        clearTimeout(draftTimer);
        owner = name; state = { chats: {}, stars: [] }; contactKeys = new Map(); messages.clear(); reactions.clear(); reply = null;
        statePromise = (async () => {
            if (!name) return;
            const loaded = await api('state');
            if (owner !== name) return;
            state = loaded;
            for (const c of contactsList) contactKeys.set(normalizeKey(c.username), await hash(c.username));
            refresh();
            for (const bubble of messagesContainer.querySelectorAll('.message-bubble')) {
                const msg = messages.get(bubble.id);
                if (msg) { bubble.querySelector('.plus-message-tools')?.remove(); messageTools(bubble, msg); }
            }
        })().catch(error => { statePromise = null; notice(error); });
        return statePromise;
    }
    async function updateChat(contact, patch) {
        const name = owner;
        const result = await api('chat', { contact, patch });
        if (owner !== name) return;
        state = result.state;
        contactKeys.set(normalizeKey(contact), await hash(contact));
        refresh();
    }
    function applyFilter() {
        for (const bubble of messagesContainer.querySelectorAll('.message-bubble')) {
            const content = bubble.querySelector('.message-text')?.textContent || '';
            bubble.hidden = !normalizeKey(content).includes(normalizeKey(query)) || (starredOnly && !state.stars.includes(bubble.id));
        }
    }
    function drawReactions(bubble) {
        bubble.querySelector('.plus-reactions')?.remove();
        const values = Object.values(reactions.get(bubble.id) || {});
        if (!values.length) return;
        const bar = el('div', '', 'plus-reactions');
        for (const emoji of new Set(values)) bar.append(el('span', emoji + ' ' + values.filter(v => v === emoji).length));
        bubble.append(bar);
    }
    function messageTools(bubble, msg) {
            messages.set(msg.id, msg);
        if (msg.pending || bubble.querySelector('.plus-message-tools')) return;
        const tools = el('details', '', 'plus-message-tools');
        tools.append(el('summary', state.stars.includes(msg.id) ? '★ ⋯' : '⋯'));
        tools.firstChild.setAttribute('aria-label', 'Mesaj işlemleri');
        const menu = el('div', '', 'plus-menu');
        const text = msg.text ? decryptE2EETextClient(msg.text, msg.sender, msg.recipient) : '';
        menu.append(button('↩ Yanıtla', () => { reply = { sender: msg.sender, text: text || '📎 Dosya' }; renderReply(); tools.open = false; messageInput.focus(); }));
        if (text) {
            menu.append(button('Kopyala', async () => { try { await navigator.clipboard.writeText(text); tools.open = false; } catch { notice(new Error('Kopyalamak için HTTPS ve pano izni gerekir')); } }));
            menu.append(button('İlet', () => forward(text)));
        }
        menu.append(button(state.stars.includes(msg.id) ? '★ Yıldızı kaldır' : '☆ Yıldızla', async () => {
            try { const result = await api('star', { id: bubble.id, starred: !state.stars.includes(bubble.id) }); state = result.state; tools.remove(); messageTools(bubble, { ...msg, id: bubble.id }); applyFilter(); } catch (error) { notice(error); }
        }));
        const emojis = el('div', '', 'plus-emojis');
        for (const emoji of ['👍', '❤️', '😂', '😮', '😢', '🙏', '']) emojis.append(button(emoji || '×', async () => {
            try { const result = await api('react', { id: bubble.id, emoji }); reactions.set(bubble.id, result.reactions); drawReactions(bubble); tools.open = false; } catch (error) { notice(error); }
        }));
        menu.append(emojis); tools.append(menu); bubble.append(tools); drawReactions(bubble); applyFilter();
    }
    function forward(text) {
        const dialog = el('dialog', '', 'plus-dialog');
        dialog.append(el('h3', 'Metni ilet'));
        const select = el('select'); select.setAttribute('aria-label', 'Alıcı');
        for (const c of contactsList) { const option = el('option', formatContactIntegratedDisplayName(c)); option.value = c.username; select.append(option); }
        dialog.append(select, button('Gönder', () => {
            const target = contactsList.find(c => c.username === select.value);
            if (!target) return;
            selectContact(target); sendTextMessage('↪ İletildi\n' + text); dialog.close();
        }), button('Vazgeç', () => dialog.close()));
        dialog.onclose = () => dialog.remove(); document.body.append(dialog); dialog.showModal();
    }
    const replyBar = el('div', '', 'plus-reply'); replyBar.hidden = true;
    messageInput.closest('footer, .chat-input-area, .message-input-container')?.prepend(replyBar);
    if (!replyBar.isConnected) messageInput.parentElement.before(replyBar);
    function renderReply() {
        replyBar.replaceChildren(); replyBar.hidden = !reply;
        if (reply) replyBar.append(el('span', reply.sender + ': ' + reply.text.slice(0, 120)), button('×', () => { reply = null; renderReply(); }));
    }
    const toolbar = el('div', '', 'plus-toolbar');
    const search = el('input'); search.type = 'search'; search.placeholder = 'Yüklenen mesajlarda ara'; search.setAttribute('aria-label', search.placeholder);
    search.oninput = () => { query = search.value; applyFilter(); };
    toolbar.append(search, button('☆ Yıldızlı', event => { starredOnly = !starredOnly; event.currentTarget.setAttribute('aria-pressed', String(starredOnly)); applyFilter(); }));
    toolbar.append(button('↓ Son mesaj', () => scrollToBottom()));
    toolbar.append(button('Sohbeti dışa aktar', () => {
        const text = [...messagesContainer.querySelectorAll('.message-bubble')].filter(b => !b.hidden).map(b => {
            const msg = messages.get(b.id); return `${msg?.createdAt || ''} ${msg?.sender || ''}: ${b.querySelector('.message-text')?.textContent || '[Dosya]'}`;
        }).join('\n');
        const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
        const a = el('a'); a.href = url; a.download = 'MSJ-yuklenen-mesajlar.txt'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }));
    messagesContainer.before(toolbar);
    document.addEventListener('keydown', event => {
        if (activeContact && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f') { event.preventDefault(); search.focus(); }
        if (event.key === 'Escape' && document.activeElement === search) { search.value = ''; query = ''; applyFilter(); messageInput.focus(); }
    });
    const archiveButton = button('Arşivlenen sohbetler', () => { archivedView = !archivedView; archiveButton.textContent = archivedView ? 'Normal sohbetler' : 'Arşivlenen sohbetler'; refresh(); });
    archiveButton.className = 'plus-archive'; chatListContainer.before(archiveButton);
    const saveDraft = () => {
        if (!currentUser || !activeContact) return;
        const contact = activeContact.username, draft = messageInput.value;
        clearTimeout(draftTimer);
        draftTimer = setTimeout(() => updateChat(contact, { draft }).catch(notice), 700);
    };
    messageInput.addEventListener('input', () => { inputRevision++; saveDraft(); });
    socket.on('chat:reaction', data => { reactions.set(data.id, data.reactions); const bubble = document.getElementById(data.id); if (bubble) drawReactions(bubble); });
    socket.on('features:state', data => {
        if (!currentUser || data.owner !== hash(currentUser.username)) return;
        state = data.state;
        refresh();
    });
    window.MSJPlus = {
        ensure,
        filterChats(list) {
            if (!owner || owner !== currentUser?.username) { queueMicrotask(ensure); return list; }
            return list.filter(c => !!prefs(c.username).archived === archivedView).sort((a, b) => Number(!!prefs(b.username).pinned) - Number(!!prefs(a.username).pinned));
        },
        decorateChat(item, contact) {
            const pref = prefs(contact.username), menu = el('details', '', 'plus-chat-tools');
            menu.onclick = event => event.stopPropagation(); menu.append(el('summary', [pref.pinned ? '📌' : '', pref.muted ? '🔕' : '', pref.draft ? '✎' : '', '⋯'].filter(Boolean).join(' ')));
            for (const [key, label] of [['pinned', 'Sabitle'], ['archived', 'Arşivle'], ['muted', 'Sessize al']]) menu.append(button((pref[key] ? '✓ ' : '') + label, () => updateChat(contact.username, { [key]: !pref[key] }).catch(notice)));
            item.append(menu);
        },
        messageTools,
        async select(contact) {
            const previous = activeContact;
            if (previous && previous.username !== contact.username) {
                clearTimeout(draftTimer);
                updateChat(previous.username, { draft: messageInput.value }).catch(notice);
            }
            reply = null; renderReply(); query = ''; search.value = ''; starredOnly = false;
            const revision = inputRevision;
            messageInput.value = '';
            await ensure();
            if (activeContact?.username !== contact.username || inputRevision !== revision) return;
            messageInput.value = prefs(contact.username).draft || '';
            messageInput.dispatchEvent(new Event('input'));
            try { const loaded = await api('reactions/' + encodeURIComponent(contact.username)); for (const [id, value] of Object.entries(loaded)) reactions.set(id, value); for (const bubble of messagesContainer.querySelectorAll('.message-bubble')) drawReactions(bubble); } catch (error) { notice(error); }
        },
        prepareText(text) {
            const result = reply ? `↩ ${reply.sender}: ${reply.text.slice(0, 500)}\n\n${text}` : text;
            reply = null; renderReply(); clearTimeout(draftTimer);
            if (activeContact) updateChat(activeContact.username, { draft: '' }).catch(notice);
            return result;
        },
        muted(name) { return !!prefs(name).muted; }
    };
    ensure();
})();
