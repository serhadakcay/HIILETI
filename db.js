const fs = require('fs');
const path = require('path');
const config = require('./db.config');

function normalizeKey(str) {
    if (!str) return '';
    return str.trim().toLocaleLowerCase('tr-TR');
}

function getConvoKey(u1, u2) {
    if (!u1 || !u2) return '';
    return [normalizeKey(u1), normalizeKey(u2)].sort().join('___');
}

class DatabaseManager {
    constructor() {
        this.type = config.type || 'sqlite';
        this.sqliteDb = null;
        this.mysqlPool = null;
    }

    async init() {
        if (this.type === 'mysql') {
            await this.initMysql();
        } else {
            await this.initSqlite();
        }

        // Eski JSON dosyalarından otomatik veri taşıma (ilk kurulumda)
        await this.migrateFromJsonIfNeeded();
    }

    // ========================================================
    // SQLITE BAŞLATMA (Lite SQL)
    // ========================================================
    async initSqlite() {
        const { DatabaseSync } = require('node:sqlite');
        const dbPath = config.sqlite.filename;
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        this.sqliteDb = new DatabaseSync(dbPath);

        // WAL modu ile hızlı ve bozulmaya karşı güvenli çalışma
        this.sqliteDb.exec('PRAGMA journal_mode = WAL;');
        this.sqliteDb.exec('PRAGMA foreign_keys = ON;');

        // Tabloları oluştur
        this.sqliteDb.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_key TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                salt TEXT NOT NULL,
                hash TEXT NOT NULL,
                avatar TEXT DEFAULT '/avatars/default.svg',
                last_seen TEXT DEFAULT 'Offline',
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_key TEXT NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT,
                last_used TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                convo_key TEXT NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                text TEXT,
                file_json TEXT,
                timestamp TEXT,
                date_str TEXT,
                created_at TEXT,
                is_read INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_users_key ON users(user_key);
            CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(user_key);
            CREATE INDEX IF NOT EXISTS idx_messages_convo ON messages(convo_key);
            CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
        `);

        console.log(`[Lite SQL] SQLite veritabanı aktif: ${dbPath}`);
    }

    // ========================================================
    // MYSQL BAŞLATMA (İsteğe bağlı geçiş için)
    // ========================================================
    async initMysql() {
        const mysql = require('mysql2/promise');
        this.mysqlPool = mysql.createPool(config.mysql);

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_key VARCHAR(100) UNIQUE NOT NULL,
                username VARCHAR(100) NOT NULL,
                salt VARCHAR(128) NOT NULL,
                hash VARCHAR(256) NOT NULL,
                avatar VARCHAR(255) DEFAULT '/avatars/default.svg',
                last_seen VARCHAR(50) DEFAULT 'Offline',
                created_at VARCHAR(50),
                INDEX idx_users_key (user_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(128) PRIMARY KEY,
                user_key VARCHAR(100) NOT NULL,
                username VARCHAR(100) NOT NULL,
                created_at VARCHAR(50),
                last_used VARCHAR(50),
                INDEX idx_sessions_key (user_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id VARCHAR(100) PRIMARY KEY,
                convo_key VARCHAR(200) NOT NULL,
                sender VARCHAR(100) NOT NULL,
                recipient VARCHAR(100) NOT NULL,
                text LONGTEXT,
                file_json LONGTEXT,
                timestamp VARCHAR(50),
                date_str VARCHAR(50),
                created_at VARCHAR(50),
                is_read TINYINT DEFAULT 0,
                INDEX idx_messages_convo (convo_key),
                INDEX idx_messages_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        console.log(`[MySQL] MySQL veritabanı aktif: ${config.mysql.host}:${config.mysql.port}/${config.mysql.database}`);
    }

    // ========================================================
    // JSON'DAN VERİTABANINA OTOMATİK AKTARIM
    // ========================================================
    async migrateFromJsonIfNeeded() {
        try {
            const userCount = await this.getUserCount();
            if (userCount > 0) return; // Zaten veritabanında veri var

            const dataDir = path.join(__dirname, 'data');
            const usersFile = path.join(dataDir, 'users.json');
            const sessionsFile = path.join(dataDir, 'sessions.json');
            const messagesFile = path.join(dataDir, 'messages.json');

            if (!fs.existsSync(usersFile)) return;

            console.log('[Veritabanı] Eski JSON verileri veritabanına taşınıyor...');

            // 1. Kullanıcılar
            if (fs.existsSync(usersFile)) {
                try {
                    const rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
                    for (const key of Object.keys(rawUsers)) {
                        const u = rawUsers[key];
                        await this.createUser({
                            username: u.username,
                            salt: u.salt,
                            hash: u.hash,
                            avatar: u.avatar || '/avatars/default.svg',
                            lastSeen: u.lastSeen || 'Offline',
                            createdAt: u.createdAt || new Date().toISOString()
                        });
                    }
                    console.log(`[Veritabanı] ${Object.keys(rawUsers).length} kullanıcı aktarıldı.`);
                } catch (e) {
                    console.error('Kullanıcı aktarım hatası:', e.message);
                }
            }

            // 2. Oturumlar
            if (fs.existsSync(sessionsFile)) {
                try {
                    const rawSessions = JSON.parse(fs.readFileSync(sessionsFile, 'utf8'));
                    for (const token of Object.keys(rawSessions)) {
                        const s = rawSessions[token];
                        await this.saveSession(token, s.username, s.createdAt, s.lastUsed);
                    }
                    console.log(`[Veritabanı] ${Object.keys(rawSessions).length} aktif oturum aktarıldı.`);
                } catch (e) {
                    console.error('Oturum aktarım hatası:', e.message);
                }
            }

            // 3. Mesajlar
            if (fs.existsSync(messagesFile)) {
                try {
                    const rawMessages = JSON.parse(fs.readFileSync(messagesFile, 'utf8'));
                    let totalMsgs = 0;
                    for (const convoKey of Object.keys(rawMessages)) {
                        const list = rawMessages[convoKey] || [];
                        for (const msg of list) {
                            await this.saveMessage({
                                id: msg.id,
                                sender: msg.sender,
                                recipient: msg.recipient,
                                text: msg.text || '',
                                file: msg.file || null,
                                timestamp: msg.timestamp || '',
                                date: msg.date || 'Bugün',
                                createdAt: msg.createdAt || new Date().toISOString(),
                                read: !!msg.read
                            });
                            totalMsgs++;
                        }
                    }
                    console.log(`[Veritabanı] ${totalMsgs} mesaj başarıyla aktarıldı.`);
                } catch (e) {
                    console.error('Mesaj aktarım hatası:', e.message);
                }
            }

            console.log('[Veritabanı] Tüm veriler kalıcı Lite SQL (SQLite) veritabanına başarıyla taşındı!');
        } catch (err) {
            console.error('Veri aktarımında genel hata:', err.message);
        }
    }

    async getUserCount() {
        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT COUNT(*) as cnt FROM users');
            return rows[0].cnt;
        } else {
            const row = this.sqliteDb.prepare('SELECT COUNT(*) as cnt FROM users').get();
            return row ? row.cnt : 0;
        }
    }

    // ========================================================
    // KULLANICI İŞLEMLERİ
    // ========================================================
    async getUser(usernameOrKey) {
        const userKey = normalizeKey(usernameOrKey);
        if (!userKey) return null;

        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT * FROM users WHERE user_key = ? LIMIT 1', [userKey]);
            if (rows.length === 0) return null;
            return this.formatUserRow(rows[0]);
        } else {
            const row = this.sqliteDb.prepare('SELECT * FROM users WHERE user_key = ? LIMIT 1').get(userKey);
            if (!row) return null;
            return this.formatUserRow(row);
        }
    }

    async getAllUsers() {
        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT * FROM users ORDER BY username ASC');
            return rows.map(r => this.formatUserRow(r));
        } else {
            const rows = this.sqliteDb.prepare('SELECT * FROM users ORDER BY username ASC').all();
            return rows.map(r => this.formatUserRow(r));
        }
    }

    async createUser(userData) {
        const userKey = normalizeKey(userData.username);
        const avatar = userData.avatar || '/avatars/default.svg';
        const lastSeen = userData.lastSeen || 'Offline';
        const createdAt = userData.createdAt || new Date().toISOString();

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO users (user_key, username, salt, hash, avatar, last_seen, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE username = VALUES(username), salt = VALUES(salt), hash = VALUES(hash), avatar = VALUES(avatar)`,
                [userKey, userData.username, userData.salt, userData.hash, avatar, lastSeen, createdAt]
            );
        } else {
            const stmt = this.sqliteDb.prepare(`
                INSERT INTO users (user_key, username, salt, hash, avatar, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_key) DO UPDATE SET
                    username = excluded.username,
                    salt = excluded.salt,
                    hash = excluded.hash,
                    avatar = excluded.avatar
            `);
            stmt.run(userKey, userData.username, userData.salt, userData.hash, avatar, lastSeen, createdAt);
        }

        return await this.getUser(userKey);
    }

    async updateUserLastSeen(usernameOrKey, lastSeen) {
        const userKey = normalizeKey(usernameOrKey);
        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE users SET last_seen = ? WHERE user_key = ?', [lastSeen, userKey]);
        } else {
            this.sqliteDb.prepare('UPDATE users SET last_seen = ? WHERE user_key = ?').run(lastSeen, userKey);
        }
    }

    formatUserRow(row) {
        return {
            id: row.id,
            userKey: row.user_key,
            username: row.username,
            salt: row.salt,
            hash: row.hash,
            avatar: row.avatar || '/avatars/default.svg',
            lastSeen: row.last_seen || 'Offline',
            createdAt: row.created_at
        };
    }

    // ========================================================
    // OTURUM (SESSION) İŞLEMLERİ
    // ========================================================
    async getSession(token) {
        if (!token) return null;
        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT * FROM sessions WHERE token = ? LIMIT 1', [token]);
            if (rows.length === 0) return null;
            return {
                token: rows[0].token,
                userKey: rows[0].user_key,
                username: rows[0].username,
                createdAt: rows[0].created_at,
                lastUsed: rows[0].last_used
            };
        } else {
            const row = this.sqliteDb.prepare('SELECT * FROM sessions WHERE token = ? LIMIT 1').get(token);
            if (!row) return null;
            return {
                token: row.token,
                userKey: row.user_key,
                username: row.username,
                createdAt: row.created_at,
                lastUsed: row.last_used
            };
        }
    }

    async saveSession(token, username, createdAt, lastUsed) {
        const userKey = normalizeKey(username);
        const created = createdAt || new Date().toISOString();
        const used = lastUsed || new Date().toISOString();

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO sessions (token, user_key, username, created_at, last_used)
                 VALUES (?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE last_used = VALUES(last_used)`,
                [token, userKey, username, created, used]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO sessions (token, user_key, username, created_at, last_used)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET last_used = excluded.last_used
            `).run(token, userKey, username, created, used);
        }
    }

    async updateSessionLastUsed(token) {
        const now = new Date().toISOString();
        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE sessions SET last_used = ? WHERE token = ?', [now, token]);
        } else {
            this.sqliteDb.prepare('UPDATE sessions SET last_used = ? WHERE token = ?').run(now, token);
        }
    }

    async deleteSession(token) {
        if (!token) return;
        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM sessions WHERE token = ?', [token]);
        } else {
            this.sqliteDb.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        }
    }

    // ========================================================
    // MESAJ (CHAT) İŞLEMLERİ
    // ========================================================
    async saveMessage(msg) {
        const convoKey = getConvoKey(msg.sender, msg.recipient);
        const id = msg.id || ('msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6));
        const fileJson = msg.file ? JSON.stringify(msg.file) : null;
        const timestamp = msg.timestamp || new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
        const dateStr = msg.date || 'Bugün';
        const createdAt = msg.createdAt || new Date().toISOString();
        const isRead = msg.read ? 1 : 0;

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, convoKey, msg.sender, msg.recipient, msg.text || '', fileJson, timestamp, dateStr, createdAt, isRead]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(id, convoKey, msg.sender, msg.recipient, msg.text || '', fileJson, timestamp, dateStr, createdAt, isRead);
        }

        return {
            id,
            convoKey,
            sender: msg.sender,
            recipient: msg.recipient,
            text: msg.text || '',
            file: msg.file || null,
            timestamp,
            date: dateStr,
            createdAt,
            read: !!isRead
        };
    }

    async getConversationMessages(u1, u2) {
        const convoKey = getConvoKey(u1, u2);
        if (!convoKey) return [];

        let rows = [];
        if (this.type === 'mysql') {
            const [dbRows] = await this.mysqlPool.query(
                'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at ASC',
                [convoKey]
            );
            rows = dbRows;
        } else {
            rows = this.sqliteDb.prepare(
                'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at ASC'
            ).all(convoKey);
        }

        return rows.map(r => this.formatMessageRow(r));
    }

    async markMessagesAsRead(contactUsername, currentUsername) {
        const convoKey = getConvoKey(contactUsername, currentUsername);
        const recipientUser = currentUsername;

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                'UPDATE messages SET is_read = 1 WHERE convo_key = ? AND recipient = ? AND is_read = 0',
                [convoKey, recipientUser]
            );
        } else {
            this.sqliteDb.prepare(
                'UPDATE messages SET is_read = 1 WHERE convo_key = ? AND recipient = ? AND is_read = 0'
            ).run(convoKey, recipientUser);
        }
    }

    // TEKİL MESAJ SİLME
    async deleteMessage(messageId, requesterUsername) {
        if (!messageId) return { success: false, error: 'Mesaj ID bulunamadı' };

        // Güvenlik kontrolü: Mesajı yalnızca gönderen veya alan kişi silebilir
        let row = null;
        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT * FROM messages WHERE id = ? LIMIT 1', [messageId]);
            if (rows.length > 0) row = rows[0];
        } else {
            row = this.sqliteDb.prepare('SELECT * FROM messages WHERE id = ? LIMIT 1').get(messageId);
        }

        if (!row) {
            return { success: false, error: 'Mesaj bulunamadı' };
        }

        const reqKey = normalizeKey(requesterUsername);
        const senderKey = normalizeKey(row.sender);
        const recKey = normalizeKey(row.recipient);

        if (reqKey !== senderKey && reqKey !== recKey) {
            return { success: false, error: 'Bu mesajı silme yetkiniz yok' };
        }

        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM messages WHERE id = ?', [messageId]);
        } else {
            this.sqliteDb.prepare('DELETE FROM messages WHERE id = ?').run(messageId);
        }

        return {
            success: true,
            deletedId: messageId,
            convoKey: row.convo_key,
            sender: row.sender,
            recipient: row.recipient
        };
    }

    // TÜM SOHBETİ / YAZIŞMALARI TEMİZLEME
    async clearConversation(u1, u2, requesterUsername) {
        const convoKey = getConvoKey(u1, u2);
        if (!convoKey) return { success: false, error: 'Sohbet bulunamadı' };

        const reqKey = normalizeKey(requesterUsername);
        const u1Key = normalizeKey(u1);
        const u2Key = normalizeKey(u2);

        if (reqKey !== u1Key && reqKey !== u2Key) {
            return { success: false, error: 'Bu sohbeti temizleme yetkiniz yok' };
        }

        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM messages WHERE convo_key = ?', [convoKey]);
        } else {
            this.sqliteDb.prepare('DELETE FROM messages WHERE convo_key = ?').run(convoKey);
        }

        return {
            success: true,
            convoKey,
            u1,
            u2
        };
    }

    // SOHBETLER LİSTESİ VE SON MESAJLAR
    async getChatsList(currentUsername, onlineUserKeysMap) {
        const currentKey = normalizeKey(currentUsername);
        const allUsers = await this.getAllUsers();
        const chatItems = [];

        for (const contact of allUsers) {
            if (contact.userKey === currentKey) continue; // Kendisini hariç tut

            const convoKey = getConvoKey(currentUsername, contact.username);
            
            // Son mesajı getir
            let lastRow = null;
            let unreadCount = 0;

            if (this.type === 'mysql') {
                const [mRows] = await this.mysqlPool.query(
                    'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at DESC LIMIT 1',
                    [convoKey]
                );
                if (mRows.length > 0) lastRow = mRows[0];

                const [uRows] = await this.mysqlPool.query(
                    'SELECT COUNT(*) as cnt FROM messages WHERE convo_key = ? AND recipient = ? AND is_read = 0',
                    [convoKey, currentUsername]
                );
                unreadCount = uRows[0].cnt;
            } else {
                lastRow = this.sqliteDb.prepare(
                    'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at DESC LIMIT 1'
                ).get(convoKey);

                const uRow = this.sqliteDb.prepare(
                    'SELECT COUNT(*) as cnt FROM messages WHERE convo_key = ? AND recipient = ? AND is_read = 0'
                ).get(convoKey, currentUsername);
                unreadCount = uRow ? uRow.cnt : 0;
            }

            const isOnline = onlineUserKeysMap && onlineUserKeysMap.has(contact.userKey) && onlineUserKeysMap.get(contact.userKey).size > 0;
            const lastMsg = lastRow ? this.formatMessageRow(lastRow) : null;

            chatItems.push({
                username: contact.username,
                avatar: contact.avatar || '/avatars/default.svg',
                isOnline,
                statusText: isOnline ? 'Online' : 'Offline',
                lastSeen: isOnline ? 'Online' : (contact.lastSeen || 'Offline'),
                lastMessage: lastMsg ? {
                    id: lastMsg.id,
                    sender: lastMsg.sender,
                    recipient: lastMsg.recipient,
                    text: lastMsg.text,
                    file: lastMsg.file,
                    timestamp: lastMsg.timestamp,
                    date: lastMsg.date || 'Bugün',
                    isOutgoing: normalizeKey(lastMsg.sender) === currentKey
                } : null,
                unreadCount
            });
        }

        return chatItems;
    }

    formatMessageRow(row) {
        let fileObj = null;
        if (row.file_json) {
            try { fileObj = JSON.parse(row.file_json); } catch (e) {}
        }

        return {
            id: row.id,
            convoKey: row.convo_key,
            sender: row.sender,
            recipient: row.recipient,
            text: row.text || '',
            file: fileObj,
            timestamp: row.timestamp || '',
            date: row.date_str || 'Bugün',
            createdAt: row.created_at,
            read: !!row.is_read
        };
    }
}

const db = new DatabaseManager();

module.exports = {
    db,
    normalizeKey,
    getConvoKey
};
