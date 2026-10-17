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

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const sessionsFile = path.join(dataDir, 'sessions.json');
const messagesFile = path.join(dataDir, 'messages.json');
const deletedUsersFile = path.join(dataDir, 'deleted_users.json');

function ensureDataDir() {
    if (!fs.existsSync(dataDir)) {
        try { fs.mkdirSync(dataDir, { recursive: true }); } catch (e) {}
    }
}

function getDeletedUsersMap() {
    try {
        if (fs.existsSync(deletedUsersFile)) {
            return JSON.parse(fs.readFileSync(deletedUsersFile, 'utf8') || '{}');
        }
    } catch (e) {}
    return {};
}

function markUserDeletedInFile(userKey) {
    if (!userKey) return;
    try {
        ensureDataDir();
        const map = getDeletedUsersMap();
        map[userKey] = new Date().toISOString();
        fs.writeFileSync(deletedUsersFile, JSON.stringify(map, null, 2), 'utf8');
    } catch (e) {}
}

function unmarkUserDeletedInFile(userKey) {
    if (!userKey) return;
    try {
        if (fs.existsSync(deletedUsersFile)) {
            const map = getDeletedUsersMap();
            if (map[userKey]) {
                delete map[userKey];
                fs.writeFileSync(deletedUsersFile, JSON.stringify(map, null, 2), 'utf8');
            }
        }
    } catch (e) {}
}

class DatabaseManager {
    constructor() {
        this.type = config.type || 'sqlite';
        this.sqliteDb = null;
        this.mysqlPool = null;
    }

    checkpointSqlite() {
        if (this.type !== 'sqlite' || !this.sqliteDb) return;
        try {
            this.sqliteDb.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        } catch (e) {
            try { this.sqliteDb.exec('PRAGMA wal_checkpoint(FULL);'); } catch (e2) {}
        }
    }

    async init() {
        ensureDataDir();

        if (this.type === 'mysql') {
            await this.initMysql();
        } else {
            await this.initSqlite();
        }

        // Çift yönlü otomatik senkronizasyon:
        // 1. JSON dosyalarındaki tüm kullanıcı ve mesajları veritabanına yükler.
        // 2. Veritabanındaki tüm kullanıcı ve mesajları JSON dosyalarına yedekler.
        // Böylece GitHub'a atıldığında veya sunucu yeniden başladığında veri ASLA kaybolmaz!
        await this.syncAllWithJson();
    }

    // ========================================================
    // 1. SQLITE BAŞLATMA (Lite SQL)
    // ========================================================
    async initSqlite() {
        const { DatabaseSync } = require('node:sqlite');
        const dbPath = config.sqlite.filename;
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        this.sqliteDb = new DatabaseSync(dbPath);

        // WAL modu + FULL senkronizasyon ile program aniden kapatılsa bile sıfır veri kaybı
        this.sqliteDb.exec('PRAGMA journal_mode = WAL;');
        this.sqliteDb.exec('PRAGMA synchronous = FULL;');
        this.sqliteDb.exec('PRAGMA foreign_keys = ON;');

        // Tabloları oluştur (Büyük/Küçük harf duyarsızlığı için COLLATE NOCASE)
        this.sqliteDb.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_key TEXT UNIQUE NOT NULL COLLATE NOCASE,
                username TEXT NOT NULL COLLATE NOCASE,
                salt TEXT NOT NULL,
                hash TEXT NOT NULL,
                avatar TEXT DEFAULT '/avatars/default.svg',
                last_seen TEXT DEFAULT 'Offline',
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_key TEXT NOT NULL COLLATE NOCASE,
                username TEXT NOT NULL COLLATE NOCASE,
                created_at TEXT,
                last_used TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                convo_key TEXT NOT NULL COLLATE NOCASE,
                sender TEXT NOT NULL COLLATE NOCASE,
                recipient TEXT NOT NULL COLLATE NOCASE,
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
            CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(recipient, is_read);
        `);

        // Başlangıçta WAL kontrol noktasını çalıştırarak veritabanı dosyasını tam olarak diske yaz
        this.checkpointSqlite();

        console.log(`[Lite SQL] SQLite veritabanı aktif: ${dbPath}`);
    }

    // ========================================================
    // 2. MYSQL BAŞLATMA
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
                INDEX idx_messages_created (created_at),
                INDEX idx_messages_unread (recipient, is_read)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        console.log(`[MySQL] MySQL veritabanı aktif: ${config.mysql.host}:${config.mysql.port}/${config.mysql.database}`);
    }

    // ========================================================
    // 3. ÇİFT YÖNLÜ JSON <-> VERİTABANI TAM SENKRONİZASYONU
    // ========================================================
    isUserDeleted(usernameOrKey) {
        const key = normalizeKey(usernameOrKey);
        if (!key) return false;
        const map = getDeletedUsersMap();
        return Boolean(map[key]);
    }

    getDeletedUserKeys() {
        return Object.keys(getDeletedUsersMap());
    }

    async syncAllWithJson() {
        try {
            ensureDataDir();
            const crypto = require('crypto');
            const deletedMap = getDeletedUsersMap();

            // 0. Kalıcı temel kullanıcıların (Serhad, S1, Ser1, cözücem) kullanıcı kendisi silmediği sürece her zaman var olmasını garanti et
            const permanentDefaults = ['Serhad', 'S1', 'Ser1', 'cözücem'];
            let rawUsersInit = {};
            if (fs.existsSync(usersFile)) {
                try { rawUsersInit = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}'); } catch (e) { rawUsersInit = {}; }
            }
            let usersFileModified = false;
            for (const defName of permanentDefaults) {
                const defKey = normalizeKey(defName);
                if (!deletedMap[defKey] && !rawUsersInit[defKey]) {
                    const salt = crypto.randomBytes(16).toString('hex');
                    const hash = crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
                    rawUsersInit[defKey] = {
                        username: defName,
                        salt,
                        hash,
                        avatar: '/avatars/default.svg',
                        lastSeen: 'Offline',
                        createdAt: new Date().toISOString()
                    };
                    usersFileModified = true;
                }
            }
            if (usersFileModified) {
                try { fs.writeFileSync(usersFile, JSON.stringify(rawUsersInit, null, 2), 'utf8'); } catch (e) {}
            }

            // A) JSON'dan veritabanına aktar (Eksik kullanıcı veya mesajları geri yükle)
            // 1. Kullanıcılar
            if (fs.existsSync(usersFile)) {
                try {
                    const rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                    for (const key of Object.keys(rawUsers)) {
                        const u = rawUsers[key];
                        if (!u || !u.username) continue;
                        const uKey = normalizeKey(u.username);
                        if (deletedMap[uKey] || uKey.startsWith('test_logout_user_') || uKey.startsWith('testuser_')) continue;
                        const existing = await this.getUser(u.username);
                        if (!existing) {
                            await this.insertUserToDb({
                                username: u.username,
                                salt: u.salt,
                                hash: u.hash,
                                avatar: u.avatar || '/avatars/default.svg',
                                lastSeen: u.lastSeen || 'Offline',
                                createdAt: u.createdAt || new Date().toISOString()
                            });
                        }
                    }
                } catch (e) {
                    console.error('[Sync] users.json okuma hatası:', e.message);
                }
            }

            // 2. Mesajlar (Mesajlarda geçen gönderici/alıcı kullanıcılar veritabanında yoksa otomatik geri yükle)
            if (fs.existsSync(messagesFile)) {
                try {
                    const rawMessages = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}');
                    for (const convoKey of Object.keys(rawMessages)) {
                        const list = rawMessages[convoKey] || [];
                        for (const msg of list) {
                            if (!msg || !msg.id) continue;
                            for (const uName of [msg.sender, msg.recipient]) {
                                if (uName && uName.trim().length >= 2) {
                                    const uKey = normalizeKey(uName);
                                    if (deletedMap[uKey] || uKey.startsWith('test_logout_user_') || uKey.startsWith('testuser_')) continue;
                                    const ex = await this.getUser(uName.trim());
                                    if (!ex) {
                                        const salt = crypto.randomBytes(16).toString('hex');
                                        const hash = crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
                                        await this.insertUserToDb({
                                            username: uName.trim(),
                                            salt,
                                            hash,
                                            avatar: '/avatars/default.svg',
                                            lastSeen: 'Offline',
                                            createdAt: msg.createdAt || new Date().toISOString()
                                        });
                                    }
                                }
                            }
                            await this.insertMessageToDbIfNotExists({
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
                        }
                    }
                } catch (e) {
                    console.error('[Sync] messages.json okuma hatası:', e.message);
                }
            }

            // 3. Oturumlar (Oturumu olan kullanıcılar veritabanında yoksa otomatik geri yükle)
            if (fs.existsSync(sessionsFile)) {
                try {
                    const rawSessions = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                    for (const token of Object.keys(rawSessions)) {
                        const s = rawSessions[token];
                        if (!s || !s.username) continue;
                        const uKey = normalizeKey(s.username);
                        if (deletedMap[uKey] || uKey.startsWith('test_logout_user_') || uKey.startsWith('testuser_')) continue;
                        const exUser = await this.getUser(s.username);
                        if (!exUser) {
                            const salt = crypto.randomBytes(16).toString('hex');
                            const hash = crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
                            await this.insertUserToDb({
                                username: s.username.trim(),
                                salt,
                                hash,
                                avatar: '/avatars/default.svg',
                                lastSeen: 'Offline',
                                createdAt: s.createdAt || new Date().toISOString()
                            });
                        }
                        const existingSession = await this.getSession(token);
                        if (!existingSession) {
                            await this.insertSessionToDb(token, s.username, s.createdAt, s.lastUsed);
                        }
                    }
                } catch (e) {
                    console.error('[Sync] sessions.json okuma hatası:', e.message);
                }
            }

            // B) Veritabanından JSON dosyalarına tam yansıtma (Her zaman güncel yedek)
            await this.exportDbToJson();
            this.checkpointSqlite();
            console.log('[Veritabanı] Çift yönlü kalıcı veri senkronizasyonu tamamlandı.');
        } catch (err) {
            console.error('[Veritabanı] Senkronizasyon genel hatası:', err.message);
        }
    }

    async exportDbToJson() {
        try {
            ensureDataDir();
            const deletedMap = getDeletedUsersMap();
            // 1. Tüm kullanıcıları mevcut users.json ile birleştirerek yaz (hiçbir kayıtlı kullanıcı silinmesin)
            let usersMap = {};
            if (fs.existsSync(usersFile)) {
                try { usersMap = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}'); } catch (e) { usersMap = {}; }
            }
            for (const k of Object.keys(usersMap)) {
                if (deletedMap[k] || k.startsWith('test_logout_user_') || k.startsWith('testuser_')) {
                    delete usersMap[k];
                }
            }
            const allUsers = await this.getAllUsers();
            for (const u of allUsers) {
                if (deletedMap[u.userKey] || u.userKey.startsWith('test_logout_user_') || u.userKey.startsWith('testuser_')) continue;
                usersMap[u.userKey] = {
                    username: u.username,
                    salt: u.salt,
                    hash: u.hash,
                    avatar: u.avatar || '/avatars/default.svg',
                    lastSeen: u.lastSeen || 'Offline',
                    createdAt: u.createdAt || new Date().toISOString()
                };
            }
            fs.writeFileSync(usersFile, JSON.stringify(usersMap, null, 2), 'utf8');

            // 2. Tüm mesajları messages.json dosyasına yaz
            let allMsgs = [];
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query('SELECT * FROM messages ORDER BY created_at ASC');
                allMsgs = rows.map(r => this.formatMessageRow(r));
            } else {
                const rows = this.sqliteDb.prepare('SELECT * FROM messages ORDER BY created_at ASC').all();
                allMsgs = rows.map(r => this.formatMessageRow(r));
            }

            const messagesMap = {};
            for (const msg of allMsgs) {
                const convoKey = msg.convoKey || getConvoKey(msg.sender, msg.recipient);
                if (!messagesMap[convoKey]) messagesMap[convoKey] = [];
                messagesMap[convoKey].push({
                    id: msg.id,
                    sender: msg.sender,
                    recipient: msg.recipient,
                    text: msg.text || '',
                    file: msg.file || null,
                    timestamp: msg.timestamp || '',
                    date: msg.date || 'Bugün',
                    createdAt: msg.createdAt,
                    read: !!msg.read
                });
            }
            fs.writeFileSync(messagesFile, JSON.stringify(messagesMap, null, 2), 'utf8');
        } catch (e) {
            console.error('[exportDbToJson] JSON dışa aktarma hatası:', e.message);
        }
    }

    // ========================================================
    // 4. KULLANICI İŞLEMLERİ
    // ========================================================
    async getUser(usernameOrKey) {
        if (!usernameOrKey) return null;
        const userKey = normalizeKey(usernameOrKey);
        const rawTrim = usernameOrKey.trim();

        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query(
                'SELECT * FROM users WHERE user_key = ? OR LOWER(username) = ? LIMIT 1',
                [userKey, userKey]
            );
            if (rows.length === 0) return null;
            return this.formatUserRow(rows[0]);
        } else {
            const row = this.sqliteDb.prepare(
                'SELECT * FROM users WHERE user_key = ? OR LOWER(username) = ? LIMIT 1'
            ).get(userKey, userKey);
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

    async insertUserToDb(userData) {
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
            this.checkpointSqlite();
        }

        // users.json dosyasına da anında yansıt (SQLite ve JSON her zaman %100 aynı olsun)
        try {
            ensureDataDir();
            let rawUsers = {};
            if (fs.existsSync(usersFile)) {
                try { rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}'); } catch (e) {}
            }
            rawUsers[userKey] = {
                username: userData.username,
                salt: userData.salt,
                hash: userData.hash,
                avatar,
                lastSeen,
                createdAt
            };
            fs.writeFileSync(usersFile, JSON.stringify(rawUsers, null, 2), 'utf8');
        } catch (e) {}
    }

    async createUser(userData) {
        const userKey = normalizeKey(userData.username);
        unmarkUserDeletedInFile(userKey);
        await this.insertUserToDb(userData);
        return await this.getUser(userData.username);
    }

    async updateUserLastSeen(usernameOrKey, lastSeen) {
        const userKey = normalizeKey(usernameOrKey);
        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE users SET last_seen = ? WHERE user_key = ?', [lastSeen, userKey]);
        } else {
            this.sqliteDb.prepare('UPDATE users SET last_seen = ? WHERE user_key = ?').run(lastSeen, userKey);
        }

        // users.json güncelle
        try {
            if (fs.existsSync(usersFile)) {
                const rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                if (rawUsers[userKey]) {
                    rawUsers[userKey].lastSeen = lastSeen;
                    fs.writeFileSync(usersFile, JSON.stringify(rawUsers, null, 2), 'utf8');
                }
            }
        } catch (e) {}
    }

    async updateUserPassword(usernameOrKey, salt, hash) {
        const userKey = normalizeKey(usernameOrKey);
        if (!userKey) return null;
        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE users SET salt = ?, hash = ? WHERE user_key = ?', [salt, hash, userKey]);
        } else {
            this.sqliteDb.prepare('UPDATE users SET salt = ?, hash = ? WHERE user_key = ?').run(salt, hash, userKey);
            this.checkpointSqlite();
        }

        // users.json senkronize et
        try {
            if (fs.existsSync(usersFile)) {
                const raw = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                if (raw[userKey]) {
                    raw[userKey].salt = salt;
                    raw[userKey].hash = hash;
                    fs.writeFileSync(usersFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}

        return await this.getUser(userKey);
    }

    async ensureUserExists(username, avatar = '/avatars/default.svg', extraData = null) {
        if (!username || username.trim().length < 2) return null;
        const clean = username.trim();
        const userKey = normalizeKey(clean);

        // Eğer senkronizasyondan geliyorsa ve kullanıcı daha önce özellikle silinmişse tekrar ekleme
        if (extraData && extraData.fromSync && this.isUserDeleted(userKey)) {
            return null;
        }

        const crypto = require('crypto');
        let existing = await this.getUser(clean);
        if (existing) {
            // Eğer senkronizasyonla gerçek şifre hash/salt bilgisi geldiyse ve mevcut kayıt varsayılan '123456' ise güncelle
            if (extraData && extraData.salt && extraData.hash && existing.salt) {
                const defaultHash = crypto.pbkdf2Sync('123456', existing.salt, 1000, 64, 'sha512').toString('hex');
                if (existing.hash === defaultHash && extraData.hash !== defaultHash) {
                    await this.updateUserPassword(clean, extraData.salt, extraData.hash);
                    existing = await this.getUser(clean);
                }
            }
            return existing;
        }

        const salt = (extraData && extraData.salt) ? extraData.salt : crypto.randomBytes(16).toString('hex');
        const hash = (extraData && extraData.hash) ? extraData.hash : crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
        const created = await this.createUser({
            username: clean,
            salt,
            hash,
            avatar: avatar || '/avatars/default.svg',
            lastSeen: 'Offline',
            createdAt: (extraData && extraData.createdAt) ? extraData.createdAt : new Date().toISOString()
        });
        if (created) created._wasCreated = true;
        return created;
    }

    // KULLANICIYI SADECE KENDİSİ İSTERSE SİLME (Otomatik silme asla yapılmaz)
    async deleteUser(usernameOrKey) {
        const userKey = normalizeKey(usernameOrKey);
        if (!userKey) return { success: false, error: 'Kullanıcı adı geçersiz' };

        markUserDeletedInFile(userKey);

        const existing = await this.getUser(userKey);
        const deletedUsername = existing ? existing.username : usernameOrKey.trim();

        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM users WHERE user_key = ?', [userKey]);
            await this.mysqlPool.query('DELETE FROM sessions WHERE user_key = ?', [userKey]);
        } else {
            this.sqliteDb.prepare('DELETE FROM users WHERE user_key = ?').run(userKey);
            this.sqliteDb.prepare('DELETE FROM sessions WHERE user_key = ?').run(userKey);
            this.checkpointSqlite();
        }

        // users.json içinden sil
        try {
            if (fs.existsSync(usersFile)) {
                const raw = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                delete raw[userKey];
                fs.writeFileSync(usersFile, JSON.stringify(raw, null, 2), 'utf8');
            }
        } catch (e) {}

        // sessions.json içinden sil
        try {
            if (fs.existsSync(sessionsFile)) {
                const rawS = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                for (const t of Object.keys(rawS)) {
                    if (normalizeKey(rawS[t].username) === userKey) {
                        delete rawS[t];
                    }
                }
                fs.writeFileSync(sessionsFile, JSON.stringify(rawS, null, 2), 'utf8');
            }
        } catch (e) {}

        return { success: true, username: deletedUsername, userKey };
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
    // 5. OTURUM (SESSION) İŞLEMLERİ
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

    async getLastSessionForUser(usernameOrKey) {
        const userKey = normalizeKey(usernameOrKey);
        if (!userKey) return null;
        if (this.type === 'mysql') {
            const [rows] = await this.mysqlPool.query('SELECT * FROM sessions WHERE user_key = ? ORDER BY last_used DESC LIMIT 1', [userKey]);
            if (rows.length === 0) return null;
            return {
                token: rows[0].token,
                userKey: rows[0].user_key,
                username: rows[0].username,
                createdAt: rows[0].created_at,
                lastUsed: rows[0].last_used
            };
        } else {
            const row = this.sqliteDb.prepare('SELECT * FROM sessions WHERE user_key = ? ORDER BY last_used DESC LIMIT 1').get(userKey);
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

    async insertSessionToDb(token, username, createdAt, lastUsed) {
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

    async saveSession(token, username, createdAt, lastUsed) {
        await this.insertSessionToDb(token, username, createdAt, lastUsed);

        // sessions.json senkronize et
        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(sessionsFile)) {
                try { raw = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}'); } catch (e) {}
            }
            raw[token] = {
                username,
                createdAt: createdAt || new Date().toISOString(),
                lastUsed: lastUsed || new Date().toISOString()
            };
            fs.writeFileSync(sessionsFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {}
    }

    async updateSessionLastUsed(token) {
        const now = new Date().toISOString();
        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE sessions SET last_used = ? WHERE token = ?', [now, token]);
        } else {
            this.sqliteDb.prepare('UPDATE sessions SET last_used = ? WHERE token = ?').run(now, token);
        }

        try {
            if (fs.existsSync(sessionsFile)) {
                const raw = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                if (raw[token]) {
                    raw[token].lastUsed = now;
                    fs.writeFileSync(sessionsFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}
    }

    async deleteSession(token) {
        if (!token) return;
        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM sessions WHERE token = ?', [token]);
        } else {
            this.sqliteDb.prepare('DELETE FROM sessions WHERE token = ?').run(token);
        }

        try {
            if (fs.existsSync(sessionsFile)) {
                const raw = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                delete raw[token];
                fs.writeFileSync(sessionsFile, JSON.stringify(raw, null, 2), 'utf8');
            }
        } catch (e) {}
    }

    async deleteSessionsForUser(usernameOrKey) {
        const userKey = normalizeKey(usernameOrKey);
        if (!userKey) return;
        if (this.type === 'mysql') {
            await this.mysqlPool.query('DELETE FROM sessions WHERE user_key = ?', [userKey]);
        } else {
            this.sqliteDb.prepare('DELETE FROM sessions WHERE user_key = ?').run(userKey);
        }

        try {
            if (fs.existsSync(sessionsFile)) {
                const raw = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                for (const t of Object.keys(raw)) {
                    if (normalizeKey(raw[t].username) === userKey) {
                        delete raw[t];
                    }
                }
                fs.writeFileSync(sessionsFile, JSON.stringify(raw, null, 2), 'utf8');
            }
        } catch (e) {}
    }

    // ========================================================
    // 6. MESAJ (CHAT) İŞLEMLERİ & OFFLINE MESAJ YÖNETİMİ
    // ========================================================
    async insertMessageToDbIfNotExists(msg) {
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
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE is_read = VALUES(is_read)`,
                [id, convoKey, msg.sender, msg.recipient, msg.text || '', fileJson, timestamp, dateStr, createdAt, isRead]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET is_read = excluded.is_read
            `).run(id, convoKey, msg.sender, msg.recipient, msg.text || '', fileJson, timestamp, dateStr, createdAt, isRead);
        }
    }

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
            this.checkpointSqlite();
        }

        const savedResult = {
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

        // messages.json dosyasına anında ekle (Offline kullanıcı için kalıcı güvence)
        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(messagesFile)) {
                try { raw = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}'); } catch (e) {}
            }
            if (!raw[convoKey]) raw[convoKey] = [];
            raw[convoKey].push(savedResult);
            fs.writeFileSync(messagesFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {
            console.error('messages.json kayıt hatası:', e.message);
        }

        return savedResult;
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

    // OFFLINE OLAN KULLANICI AÇTIĞINDA TESLİM EDİLECEK TÜM BEKLEYEN MESAJLARI GETİR
    async getUnreadMessagesForUser(username) {
        if (!username) return [];
        const userKey = normalizeKey(username);

        let rows = [];
        if (this.type === 'mysql') {
            const [dbRows] = await this.mysqlPool.query(
                'SELECT * FROM messages WHERE (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0 ORDER BY created_at ASC',
                [userKey, username]
            );
            rows = dbRows;
        } else {
            rows = this.sqliteDb.prepare(
                'SELECT * FROM messages WHERE (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0 ORDER BY created_at ASC'
            ).all(userKey, username);
        }

        return rows.map(r => this.formatMessageRow(r));
    }

    async markMessagesAsRead(contactUsername, currentUsername) {
        const convoKey = getConvoKey(contactUsername, currentUsername);
        const recipientUser = currentUsername;
        const recipientKey = normalizeKey(currentUsername);

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                'UPDATE messages SET is_read = 1 WHERE convo_key = ? AND (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0',
                [convoKey, recipientKey, recipientUser]
            );
        } else {
            this.sqliteDb.prepare(
                'UPDATE messages SET is_read = 1 WHERE convo_key = ? AND (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0'
            ).run(convoKey, recipientKey, recipientUser);
        }

        // messages.json içinde de okunma durumunu güncelle
        try {
            if (fs.existsSync(messagesFile)) {
                const raw = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}');
                if (raw[convoKey]) {
                    raw[convoKey].forEach(m => {
                        if (normalizeKey(m.recipient) === recipientKey) {
                            m.read = true;
                        }
                    });
                    fs.writeFileSync(messagesFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}
    }

    // TEKİL MESAJ SİLME
    async deleteMessage(messageId, requesterUsername) {
        if (!messageId) return { success: false, error: 'Mesaj ID bulunamadı' };

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

        // messages.json içinden de sil
        try {
            if (fs.existsSync(messagesFile)) {
                const raw = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}');
                const convoKey = row.convo_key;
                if (raw[convoKey]) {
                    raw[convoKey] = raw[convoKey].filter(m => m.id !== messageId);
                    fs.writeFileSync(messagesFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}

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

        // messages.json içinden de sil
        try {
            if (fs.existsSync(messagesFile)) {
                const raw = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}');
                if (raw[convoKey]) {
                    delete raw[convoKey];
                    fs.writeFileSync(messagesFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}

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
            
            let lastRow = null;
            let unreadCount = 0;

            if (this.type === 'mysql') {
                const [mRows] = await this.mysqlPool.query(
                    'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at DESC LIMIT 1',
                    [convoKey]
                );
                if (mRows.length > 0) lastRow = mRows[0];

                const [uRows] = await this.mysqlPool.query(
                    'SELECT COUNT(*) as cnt FROM messages WHERE convo_key = ? AND (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0',
                    [convoKey, currentKey, currentUsername]
                );
                unreadCount = uRows[0].cnt;
            } else {
                lastRow = this.sqliteDb.prepare(
                    'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at DESC LIMIT 1'
                ).get(convoKey);

                const uRow = this.sqliteDb.prepare(
                    'SELECT COUNT(*) as cnt FROM messages WHERE convo_key = ? AND (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0'
                ).get(convoKey, currentKey, currentUsername);
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
