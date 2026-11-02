'use strict';
// Additive feature store. No changes to the existing message schema or history.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
module.exports = function installFeatures(app, { db, normalizeKey, dataDir, io }) {
    const file = path.join(dataDir, 'features-v1.json');
    let store = { users: {}, reactions: {} };
    if (fs.existsSync(file)) store = JSON.parse(fs.readFileSync(file, 'utf8'));
    const key = value => crypto.createHash('sha256').update(normalizeKey(value)).digest('hex');
    const persist = () => {
        fs.writeFileSync(file + '.tmp', JSON.stringify(store), { mode: 0o600 });
        fs.renameSync(file + '.tmp', file);
    };
    const userState = user => store.users[key(user)] || { chats: {}, stars: [] };
    const idOK = id => typeof id === 'string' && /^msg_[a-zA-Z0-9_:-]{1,160}$/.test(id);
    async function message(id, username) {
        if (!idOK(id)) return null;
        const sql = 'SELECT id, sender, recipient FROM messages WHERE id = ?';
        const row = db.type === 'mysql' ? (await db.mysqlPool.query(sql, [id]))[0][0] : db.sqliteDb.prepare(sql).get(id);
        return row && [row.sender, row.recipient].some(u => normalizeKey(u) === normalizeKey(username)) ? row : null;
    }
    const limits = new Map();
    app.use('/api/features', (req, res, next) => {
        if (!req.user) return res.sendStatus(401);
        const now = Date.now();
        for (const [k, v] of limits) if (v.until < now) limits.delete(k);
        const k = key(req.user.username);
        const v = limits.get(k) || { count: 0, until: now + 60000 };
        if (++v.count > 180) return res.status(429).json({ error: 'Biraz bekleyiniz' });
        limits.set(k, v);
        next();
    });
    app.get('/api/features/state', (req, res) => res.json(userState(req.user.username)));
    app.post('/api/features/chat', async (req, res) => {
        const { contact, patch } = req.body || {};
        if (typeof contact !== 'string' || contact.length > 80 || !patch || typeof patch !== 'object') return res.sendStatus(400);
        if (!await db.getUser(contact)) return res.sendStatus(404);
        const state = userState(req.user.username);
        const k = key(contact);
        if (!state.chats[k] && Object.keys(state.chats).length >= 5000) return res.sendStatus(413);
        const entry = state.chats[k] || {};
        for (const name of ['pinned', 'archived', 'muted']) if (typeof patch[name] === 'boolean') entry[name] = patch[name];
        if (typeof patch.draft === 'string') entry.draft = patch.draft.slice(0, 10000);
        state.chats[k] = entry;
        store.users[key(req.user.username)] = state;
        persist();
        io()?.to('user:' + normalizeKey(req.user.username)).emit('features:state', { owner: key(req.user.username), state });
        res.json({ success: true, state });
    });
    app.post('/api/features/star', async (req, res) => {
        if (!await message(req.body?.id, req.user.username)) return res.sendStatus(404);
        if (typeof req.body.starred !== 'boolean') return res.sendStatus(400);
        const state = userState(req.user.username);
        const stars = new Set(state.stars);
        if (req.body.starred) stars.add(req.body.id); else stars.delete(req.body.id);
        if (stars.size > 10000) return res.sendStatus(413);
        state.stars = [...stars];
        store.users[key(req.user.username)] = state;
        persist();
        io()?.to('user:' + normalizeKey(req.user.username)).emit('features:state', { owner: key(req.user.username), state });
        res.json({ success: true, state });
    });
    app.get('/api/features/reactions/:contact', async (req, res) => {
        if (req.params.contact.length > 80) return res.sendStatus(400);
        // Ownership is checked by the conversation query; never return the global store.
        const messages = await db.getConversationMessages(req.user.username, req.params.contact);
        const result = {};
        for (const msg of messages) if (store.reactions[msg.id]) result[msg.id] = store.reactions[msg.id];
        res.json(result);
    });
    app.post('/api/features/react', async (req, res) => {
        const { id, emoji } = req.body || {};
        if (!['', '👍', '❤️', '😂', '😮', '😢', '🙏'].includes(emoji)) return res.sendStatus(400);
        const row = await message(id, req.user.username);
        if (!row) return res.sendStatus(404);
        const reactions = store.reactions[id] || {};
        const actor = key(req.user.username);
        if (emoji) reactions[actor] = emoji; else delete reactions[actor];
        if (Object.keys(reactions).length) store.reactions[id] = reactions; else delete store.reactions[id];
        persist();
        const payload = { id, reactions };
        for (const room of new Set([row.sender, row.recipient].map(u => 'user:' + normalizeKey(u)))) io()?.to(room).emit('chat:reaction', payload);
        res.json({ success: true, ...payload });
    });
    return { isMuted: (owner, contact) => !!userState(owner).chats[key(contact)]?.muted };
};
