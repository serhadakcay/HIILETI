const fs = require('fs');
const path = require('path');
const config = require('./db.config');

function normalizeKey(str) {
    if (!str) return '';
    return str.trim().toLocaleLowerCase('tr-TR');
}

function normalizePhone(phoneStr) {
    if (!phoneStr) return '';
    let digits = String(phoneStr).replace(/\D+/g, '');
    if (!digits) return '';
    if (digits.startsWith('0090')) {
        digits = digits.slice(4);
    } else if (digits.startsWith('090')) {
        digits = digits.slice(3);
    } else if (digits.startsWith('90') && digits.length >= 12) {
        digits = digits.slice(2);
    }
    if (digits.length === 10 && digits.startsWith('5')) {
        digits = '0' + digits;
    }
    return digits;
}

function isLikelyPhoneNumber(str) {
    if (!str) return false;
    const trimmed = String(str).trim();
    if (!/^[+\d\s().-]+$/.test(trimmed)) return false;
    const digits = trimmed.replace(/\D+/g, '');
    return digits.length >= 7 && digits.length <= 15;
}

function getConvoKey(u1, u2) {
    if (!u1 || !u2) return '';
    return [normalizeKey(u1), normalizeKey(u2)].sort().join('___');
}

function decryptE2EETextIfNeeded(payload, sender, recipient) {
    if (!payload || typeof payload !== 'string' || !payload.startsWith('e2ee1:')) {
        return payload || '';
    }
    try {
        const crypto = require('crypto');
        const parts = payload.split(':');
        if (parts.length !== 4) return payload;
        const [, ivHex, tagHex, cipherHex] = parts;
        const convoKey = getConvoKey(sender, recipient);
        if (!convoKey) return payload;
        const masterKeyHex = crypto.createHash('sha256')
            .update('MSJ_E2EE_V1_KEY::' + convoKey + '::HIHaberlesme_256bit_Secret', 'utf8')
            .digest('hex');

        const expectedTag = crypto.createHash('sha256')
            .update(`${masterKeyHex}:MAC:${ivHex}:${cipherHex}`, 'utf8')
            .digest('hex')
            .slice(0, 16);
        if (expectedTag !== tagHex) return payload;

        const cipherBuf = Buffer.from(cipherHex, 'hex');
        const plainBuf = Buffer.alloc(cipherBuf.length);
        let offset = 0;
        let blockIndex = 0;
        while (offset < cipherBuf.length) {
            const keystream = crypto.createHash('sha256')
                .update(`${masterKeyHex}:${ivHex}:${blockIndex}`, 'utf8')
                .digest();
            const chunkLen = Math.min(32, cipherBuf.length - offset);
            for (let i = 0; i < chunkLen; i++) {
                plainBuf[offset + i] = cipherBuf[offset + i] ^ keystream[i];
            }
            offset += chunkLen;
            blockIndex++;
        }
        return plainBuf.toString('utf8');
    } catch (e) {
        return payload;
    }
}

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const sessionsFile = path.join(dataDir, 'sessions.json');
const messagesFile = path.join(dataDir, 'messages.json');
const deletedUsersFile = path.join(dataDir, 'deleted_users.json');
const userContactsFile = path.join(dataDir, 'user_contacts.json');
const blockedUsersFile = path.join(dataDir, 'blocked_users.json');
const e2eeKeysFile = path.join(dataDir, 'e2ee_keys.json');

// SQLCipher / AES-256-GCM Yerel Veritabanı (At-Rest) Şifreleme Anahtarı Türetimi
function getAtRestDbCipherKey() {
    const crypto = require('crypto');
    const secret = process.env.MSJ_SQLCIPHER_KEY || 'MSJ_SQLCIPHER_AES256_AT_REST_HARDWARE_BOUND_SECRET_2026';
    return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

function encryptAtRestDbText(plainText) {
    if (!plainText || typeof plainText !== 'string') return plainText || '';
    if (plainText.startsWith('sqlcipher1:')) return plainText;
    try {
        const crypto = require('crypto');
        const key = getAtRestDbCipherKey();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return `sqlcipher1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
    } catch (e) {
        return plainText;
    }
}

function decryptAtRestDbText(storedText) {
    if (!storedText || typeof storedText !== 'string') return storedText || '';
    if (!storedText.startsWith('sqlcipher1:')) return storedText;
    try {
        const crypto = require('crypto');
        const parts = storedText.split(':');
        if (parts.length !== 4) return storedText;
        const [, ivHex, tagHex, encHex] = parts;
        const key = getAtRestDbCipherKey();
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
        const decrypted = Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        return storedText;
    }
}

function ensureDataDir() {
    if (!fs.existsSync(dataDir)) {
        try { fs.mkdirSync(dataDir, { recursive: true }); } catch (e) {}
    }
}

function getDeletedUsersMap() {
    try {
        if (fs.existsSync(deletedUsersFile)) {
            const raw = JSON.parse(fs.readFileSync(deletedUsersFile, 'utf8') || '{}');
            if (Array.isArray(raw)) {
                const map = {};
                raw.forEach(k => { if (k) map[normalizeKey(k)] = true; });
                return map;
            }
            return (raw && typeof raw === 'object') ? raw : {};
        }
    } catch (e) {}
    return {};
}

function markUserDeletedInFile(userKey) {
    if (!userKey || isLikelyPhoneNumber(userKey)) return;
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
                phone TEXT DEFAULT '',
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

            CREATE TABLE IF NOT EXISTS user_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_key TEXT NOT NULL COLLATE NOCASE,
                contact_key TEXT NOT NULL COLLATE NOCASE,
                contact_username TEXT NOT NULL COLLATE NOCASE,
                custom_name TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                added_at TEXT,
                UNIQUE(owner_key, contact_key)
            );
            CREATE INDEX IF NOT EXISTS idx_user_contacts_owner ON user_contacts(owner_key);

            CREATE TABLE IF NOT EXISTS blocked_users (
                owner_key TEXT NOT NULL COLLATE NOCASE,
                blocked_key TEXT NOT NULL COLLATE NOCASE,
                blocked_username TEXT NOT NULL COLLATE NOCASE,
                created_at TEXT,
                PRIMARY KEY (owner_key, blocked_key)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_users_owner ON blocked_users(owner_key);

            CREATE TABLE IF NOT EXISTS e2ee_keys (
                user_key TEXT PRIMARY KEY COLLATE NOCASE,
                username TEXT NOT NULL COLLATE NOCASE,
                protocol_version TEXT DEFAULT 'Signal-X3DH-DoubleRatchet-v2',
                identity_key TEXT,
                signing_key TEXT,
                signed_pre_key TEXT,
                spk_signature TEXT,
                one_time_pre_keys_json TEXT DEFAULT '[]',
                akd_seq INTEGER DEFAULT 1,
                akd_prev_hash TEXT DEFAULT '',
                akd_hash TEXT DEFAULT '',
                updated_at TEXT
            );
        `);

        try {
            this.sqliteDb.exec(`ALTER TABLE users ADD COLUMN phone TEXT DEFAULT '';`);
        } catch (e) {}

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
                phone VARCHAR(40) DEFAULT '',
                salt VARCHAR(128) NOT NULL,
                hash VARCHAR(256) NOT NULL,
                avatar VARCHAR(255) DEFAULT '/avatars/default.svg',
                last_seen VARCHAR(50) DEFAULT 'Offline',
                created_at VARCHAR(50),
                INDEX idx_users_key (user_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);
        try {
            await this.mysqlPool.query(`ALTER TABLE users ADD COLUMN phone VARCHAR(40) DEFAULT ''`);
        } catch (e) {}

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

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS user_contacts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                owner_key VARCHAR(100) NOT NULL,
                contact_key VARCHAR(100) NOT NULL,
                contact_username VARCHAR(100) NOT NULL,
                custom_name VARCHAR(150) DEFAULT '',
                phone VARCHAR(40) DEFAULT '',
                added_at VARCHAR(50),
                UNIQUE KEY uniq_owner_contact (owner_key, contact_key),
                INDEX idx_user_contacts_owner (owner_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS blocked_users (
                owner_key VARCHAR(100) NOT NULL,
                blocked_key VARCHAR(100) NOT NULL,
                blocked_username VARCHAR(100) NOT NULL,
                created_at VARCHAR(50),
                PRIMARY KEY (owner_key, blocked_key),
                INDEX idx_blocked_users_owner (owner_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        await this.mysqlPool.query(`
            CREATE TABLE IF NOT EXISTS e2ee_keys (
                user_key VARCHAR(100) PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                protocol_version VARCHAR(100) DEFAULT 'Signal-X3DH-DoubleRatchet-v2',
                identity_key TEXT,
                signing_key TEXT,
                signed_pre_key TEXT,
                spk_signature TEXT,
                one_time_pre_keys_json LONGTEXT,
                akd_seq INT DEFAULT 1,
                akd_prev_hash VARCHAR(128) DEFAULT '',
                akd_hash VARCHAR(128) DEFAULT '',
                updated_at VARCHAR(50)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `);

        console.log(`[MySQL] MySQL veritabanı aktif: ${config.mysql.host}:${config.mysql.port}/${config.mysql.database}`);
    }

    // ========================================================
    // 3. ÇİFT YÖNLÜ JSON <-> VERİTABANI TAM SENKRONİZASYONU
    // ========================================================
    isUserDeleted(usernameOrKey) {
        const key = normalizeKey(usernameOrKey);
        if (!key || isLikelyPhoneNumber(key)) return false;
        const map = getDeletedUsersMap();
        return Boolean(map[key]);
    }

    getDeletedUserKeys() {
        return Object.keys(getDeletedUsersMap()).filter(k => !isLikelyPhoneNumber(k));
    }

    async syncAllWithJson() {
        try {
            ensureDataDir();
            const crypto = require('crypto');
            const deletedMap = getDeletedUsersMap();

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
                                phone: u.phone || '',
                                salt: u.salt,
                                hash: u.hash,
                                avatar: u.avatar || '/avatars/default.svg',
                                lastSeen: u.lastSeen || 'Offline',
                                createdAt: u.createdAt || new Date().toISOString()
                            });
                        } else if (u.phone && !existing.phone) {
                            await this.updateUserPhone(u.username, u.phone);
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
                                    const cleanUName = uName.trim();
                                    const uKey = normalizeKey(cleanUName);
                                    if (deletedMap[uKey] || uKey.startsWith('test_logout_user_') || uKey.startsWith('testuser_')) continue;
                                    // ÖNEMLİ: Telefon numarası olan alıcıları/göndericileri kullanıcı tablosuna otomatik kullanıcı hesabı olarak ekleme!
                                    if (isLikelyPhoneNumber(cleanUName)) continue;
                                    const ex = await this.getUser(cleanUName);
                                    if (!ex) {
                                        const salt = crypto.randomBytes(16).toString('hex');
                                        const hash = crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
                                        await this.insertUserToDb({
                                            username: cleanUName,
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
                        if (isLikelyPhoneNumber(s.username)) continue;
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
                if (deletedMap[k] || k.startsWith('test_logout_user_') || k.startsWith('testuser_') || isLikelyPhoneNumber(k) || (usersMap[k] && isLikelyPhoneNumber(usersMap[k].username))) {
                    delete usersMap[k];
                }
            }
            const allUsers = await this.getAllUsers();
            for (const u of allUsers) {
                if (deletedMap[u.userKey] || u.userKey.startsWith('test_logout_user_') || u.userKey.startsWith('testuser_') || isLikelyPhoneNumber(u.username)) continue;
                usersMap[u.userKey] = {
                    username: u.username,
                    phone: u.phone || (usersMap[u.userKey] && usersMap[u.userKey].phone) || '',
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
                const updateStmt = this.sqliteDb.prepare('UPDATE messages SET text = ? WHERE id = ?');
                allMsgs = rows.map(r => {
                    const formatted = this.formatMessageRow(r);
                    if (r.text && r.text.startsWith('e2ee1:') && formatted.text !== r.text) {
                        try { updateStmt.run(formatted.text, r.id); } catch (e) {}
                    }
                    return formatted;
                });
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
            if (rows.length > 0) return this.formatUserRow(rows[0]);
        } else {
            const row = this.sqliteDb.prepare(
                'SELECT * FROM users WHERE user_key = ? OR LOWER(username) = ? LIMIT 1'
            ).get(userKey, userKey);
            if (row) return this.formatUserRow(row);
        }

        // Eğer girilen değer bir telefon numarasıysa telefon numarasından da kullanıcıyı bul
        if (isLikelyPhoneNumber(rawTrim)) {
            return await this.findUserByPhone(rawTrim);
        }
        return null;
    }

    async findUserByPhone(phoneStr) {
        const cleanPhone = normalizePhone(phoneStr);
        if (!cleanPhone || cleanPhone.length < 7) return null;
        const last10 = cleanPhone.length >= 10 ? cleanPhone.slice(-10) : cleanPhone;

        const all = await this.getAllUsers();
        let fallbackPhoneUser = null;
        for (const u of all) {
            const uPhone = normalizePhone(u.phone);
            const uNamePhone = isLikelyPhoneNumber(u.username) ? normalizePhone(u.username) : '';
            const matchesPhone = uPhone && (uPhone === cleanPhone || (uPhone.length >= 10 && uPhone.slice(-10) === last10));
            const matchesNamePhone = uNamePhone && (uNamePhone === cleanPhone || (uNamePhone.length >= 10 && uNamePhone.slice(-10) === last10));
            if (matchesPhone || matchesNamePhone) {
                // Gerçek kullanıcı adı olan (sadece numaradan ibaret olmayan) entegre kaydı önceliklendir
                if (!isLikelyPhoneNumber(u.username)) {
                    return u;
                }
                if (!fallbackPhoneUser) fallbackPhoneUser = u;
            }
        }
        return fallbackPhoneUser;
    }

    // Henüz bir kullanıcı adıyla entegre edilmemiş (kullanıcı adı telefon numarası olan) davetli kayıtları döndürür
    async getUnclaimedPhoneUsers(excludeUsername = '') {
        const exKey = normalizeKey(excludeUsername);
        const all = await this.getAllUsers();
        const realPhones = new Set();
        for (const u of all) {
            if (!isLikelyPhoneNumber(u.username) && u.phone) {
                const p = normalizePhone(u.phone);
                if (p.length >= 10) realPhones.add(p.slice(-10));
                else if (p) realPhones.add(p);
            }
        }
        const unclaimed = [];
        for (const u of all) {
            if (exKey && u.userKey === exKey) continue;
            if (isLikelyPhoneNumber(u.username)) {
                const cleanP = normalizePhone(u.phone || u.username);
                const pKey = cleanP.length >= 10 ? cleanP.slice(-10) : cleanP;
                if (cleanP && !realPhones.has(pKey)) {
                    unclaimed.push({
                        username: u.username,
                        phone: cleanP,
                        avatar: u.avatar || '/avatars/default.svg',
                        createdAt: u.createdAt
                    });
                }
            }
        }
        return unclaimed;
    }

    // Numaradan bulunan ve mesaj gönderilen kullanıcı programı kurduğunda numarası ile kullanıcı adını tek hesapta entegre eder
    async integratePhoneWithUsername(phoneStr, targetUsername, extraData = {}) {
        const cleanPhone = normalizePhone(phoneStr);
        const cleanTarget = (targetUsername || '').trim();
        const targetKey = normalizeKey(cleanTarget);
        if (!cleanPhone || cleanPhone.length < 7 || !cleanTarget || !targetKey || isLikelyPhoneNumber(cleanTarget)) {
            return { integrated: false };
        }

        const last10 = cleanPhone.length >= 10 ? cleanPhone.slice(-10) : cleanPhone;
        const allUsers = await this.getAllUsers();

        // Bu telefon numarasına ait eski (placeholder veya başka) kayıtları bul
        const phoneUsers = allUsers.filter(u => {
            if (u.userKey === targetKey) return false;
            const uPhone = normalizePhone(u.phone);
            const uNamePhone = isLikelyPhoneNumber(u.username) ? normalizePhone(u.username) : '';
            const m1 = uPhone && (uPhone === cleanPhone || (uPhone.length >= 10 && uPhone.slice(-10) === last10));
            const m2 = uNamePhone && (uNamePhone === cleanPhone || (uNamePhone.length >= 10 && uNamePhone.slice(-10) === last10));
            // Eğer başka gerçek bir kullanıcı adı varsa ve sadece telefon numarası placeholder'ı arıyorsak placeholder olanları veya eşleşenleri al
            return m1 || m2;
        });

        let targetUser = await this.getUser(cleanTarget);
        const primaryOldUser = phoneUsers.find(u => isLikelyPhoneNumber(u.username)) || phoneUsers[0] || null;
        const crypto = require('crypto');

        const salt = extraData.salt || (targetUser && targetUser.salt) || (primaryOldUser && primaryOldUser.salt) || crypto.randomBytes(16).toString('hex');
        const hash = extraData.hash || (targetUser && targetUser.hash) || (primaryOldUser && primaryOldUser.hash) || crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
        const avatar = extraData.avatar || (targetUser && targetUser.avatar) || (primaryOldUser && primaryOldUser.avatar) || '/avatars/default.svg';
        const lastSeen = extraData.lastSeen || (targetUser && targetUser.lastSeen) || 'Online';
        const createdAt = (targetUser && targetUser.createdAt) || (primaryOldUser && primaryOldUser.createdAt) || new Date().toISOString();

        unmarkUserDeletedInFile(targetKey);
        await this.insertUserToDb({
            username: cleanTarget,
            phone: cleanPhone,
            salt,
            hash,
            avatar,
            lastSeen,
            createdAt
        });

        const oldUsernames = [];
        const oldKeysToCleanup = new Set();
        const phoneKey = normalizeKey(cleanPhone);
        if (phoneKey && phoneKey !== targetKey) {
            oldKeysToCleanup.add(phoneKey);
        }
        for (const pu of phoneUsers) {
            if (pu.userKey !== targetKey && isLikelyPhoneNumber(pu.username)) {
                oldKeysToCleanup.add(pu.userKey);
                oldUsernames.push(pu.username);
            }
        }

        let migratedMessagesCount = 0;
        const affectedPartners = new Set();

        for (const oldKey of oldKeysToCleanup) {
            if (!oldKey || oldKey === targetKey) continue;
            if (!oldUsernames.some(n => normalizeKey(n) === oldKey)) {
                oldUsernames.push(oldKey);
            }

            // 1. Mesajları eski numaradan yeni kullanıcı adına taşı (convo_key ve E2EE metinleriyle birlikte)
            let msgRows = [];
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query(
                    'SELECT * FROM messages WHERE LOWER(sender) = ? OR LOWER(recipient) = ? OR sender = ? OR recipient = ?',
                    [oldKey, oldKey, cleanPhone, cleanPhone]
                );
                msgRows = rows;
            } else {
                msgRows = this.sqliteDb.prepare(
                    'SELECT * FROM messages WHERE LOWER(sender) = ? OR LOWER(recipient) = ? OR sender = ? OR recipient = ?'
                ).all(oldKey, oldKey, cleanPhone, cleanPhone);
            }

            for (const row of msgRows) {
                const formatted = this.formatMessageRow(row);
                const sKey = normalizeKey(row.sender);
                const rKey = normalizeKey(row.recipient);
                const newSender = (sKey === oldKey || normalizePhone(row.sender) === cleanPhone) ? cleanTarget : row.sender;
                const newRecipient = (rKey === oldKey || normalizePhone(row.recipient) === cleanPhone) ? cleanTarget : row.recipient;

                if (normalizeKey(newSender) === normalizeKey(newRecipient)) {
                    if (this.type === 'mysql') {
                        await this.mysqlPool.query('DELETE FROM messages WHERE id = ?', [row.id]);
                    } else {
                        this.sqliteDb.prepare('DELETE FROM messages WHERE id = ?').run(row.id);
                    }
                    continue;
                }

                const newConvoKey = getConvoKey(newSender, newRecipient);
                const newStoredText = encryptAtRestDbText(formatted.text || '');

                if (normalizeKey(newSender) !== targetKey) affectedPartners.add(newSender);
                if (normalizeKey(newRecipient) !== targetKey) affectedPartners.add(newRecipient);

                if (this.type === 'mysql') {
                    await this.mysqlPool.query(
                        'UPDATE messages SET convo_key = ?, sender = ?, recipient = ?, text = ? WHERE id = ?',
                        [newConvoKey, newSender, newRecipient, newStoredText, row.id]
                    );
                } else {
                    this.sqliteDb.prepare(
                        'UPDATE messages SET convo_key = ?, sender = ?, recipient = ?, text = ? WHERE id = ?'
                    ).run(newConvoKey, newSender, newRecipient, newStoredText, row.id);
                }
                migratedMessagesCount++;
            }

            // 1.1 messages.json dosyasındaki kayıtları ve convo_key'leri de senkronize güncelle
            try {
                if (fs.existsSync(messagesFile)) {
                    const rawM = JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '{}');
                    let changedM = false;
                    for (const ck of Object.keys(rawM)) {
                        const mList = rawM[ck] || [];
                        for (const m of mList) {
                            const sKey = normalizeKey(m.sender);
                            const rKey = normalizeKey(m.recipient);
                            if (sKey === oldKey || normalizePhone(m.sender) === cleanPhone) {
                                m.sender = cleanTarget;
                                changedM = true;
                            }
                            if (rKey === oldKey || normalizePhone(m.recipient) === cleanPhone) {
                                m.recipient = cleanTarget;
                                changedM = true;
                            }
                        }
                        const otherPart = ck.split('___').find(p => normalizeKey(p) !== oldKey && normalizePhone(p) !== cleanPhone);
                        if (otherPart && (ck.includes(oldKey) || ck.includes(cleanPhone))) {
                            const newCk = getConvoKey(cleanTarget, otherPart);
                            if (newCk !== ck) {
                                if (!rawM[newCk]) rawM[newCk] = [];
                                rawM[newCk].push(...mList);
                                delete rawM[ck];
                                changedM = true;
                            }
                        }
                    }
                    if (changedM) fs.writeFileSync(messagesFile, JSON.stringify(rawM, null, 2), 'utf8');
                }
            } catch (e) {}

            // 2. Kişisel rehber (user_contacts) kayıtlarını eski numaradan yeni kullanıcı adına taşı
            try {
                let contactRows = [];
                if (this.type === 'mysql') {
                    const [cRows] = await this.mysqlPool.query(
                        'SELECT * FROM user_contacts WHERE owner_key = ? OR contact_key = ? OR phone = ?',
                        [oldKey, oldKey, cleanPhone]
                    );
                    contactRows = cRows;
                } else {
                    contactRows = this.sqliteDb.prepare(
                        'SELECT * FROM user_contacts WHERE owner_key = ? OR contact_key = ? OR phone = ?'
                    ).all(oldKey, oldKey, cleanPhone);
                }

                for (const cr of contactRows) {
                    if (cr.owner_key === oldKey) {
                        if (cr.contact_key !== targetKey) {
                            await this.addContactForUser(cleanTarget, cr.contact_username, cr.custom_name || '', cr.phone || '');
                            affectedPartners.add(cr.contact_username);
                        }
                        if (this.type === 'mysql') {
                            await this.mysqlPool.query('DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?', [oldKey, cr.contact_key]);
                        } else {
                            this.sqliteDb.prepare('DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?').run(oldKey, cr.contact_key);
                        }
                    } else if (cr.contact_key === oldKey || normalizePhone(cr.phone) === cleanPhone) {
                        if (cr.owner_key !== targetKey) {
                            const customLabel = (cr.custom_name && !isLikelyPhoneNumber(cr.custom_name)) ? cr.custom_name : '';
                            await this.addContactForUser(cr.owner_key, cleanTarget, customLabel, cleanPhone);
                            await this.addContactForUser(cleanTarget, cr.owner_key, '', '');
                            affectedPartners.add(cr.owner_key);
                        }
                        if (cr.contact_key === oldKey) {
                            if (this.type === 'mysql') {
                                await this.mysqlPool.query('DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?', [cr.owner_key, oldKey]);
                            } else {
                                this.sqliteDb.prepare('DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?').run(cr.owner_key, oldKey);
                            }
                        }
                    }
                }

                // user_contacts.json dosyasını da güncelle
                if (fs.existsSync(userContactsFile)) {
                    const rawContacts = JSON.parse(fs.readFileSync(userContactsFile, 'utf8') || '{}');
                    if (rawContacts[oldKey]) {
                        if (!rawContacts[targetKey]) rawContacts[targetKey] = {};
                        for (const [ck, cv] of Object.entries(rawContacts[oldKey])) {
                            if (ck !== targetKey && !rawContacts[targetKey][ck]) {
                                rawContacts[targetKey][ck] = cv;
                            }
                        }
                        delete rawContacts[oldKey];
                    }
                    for (const ownerK of Object.keys(rawContacts)) {
                        if (rawContacts[ownerK] && rawContacts[ownerK][oldKey]) {
                            const oldEntry = rawContacts[ownerK][oldKey];
                            delete rawContacts[ownerK][oldKey];
                            if (ownerK !== targetKey) {
                                rawContacts[ownerK][targetKey] = {
                                    contactUsername: cleanTarget,
                                    customName: (oldEntry.customName && !isLikelyPhoneNumber(oldEntry.customName)) ? oldEntry.customName : '',
                                    phone: cleanPhone,
                                    addedAt: oldEntry.addedAt || new Date().toISOString()
                                };
                            }
                        }
                    }
                    fs.writeFileSync(userContactsFile, JSON.stringify(rawContacts, null, 2), 'utf8');
                }
            } catch (e) {}

            // 3. Oturumları (sessions) yeni kullanıcı adına taşı
            try {
                if (this.type === 'mysql') {
                    await this.mysqlPool.query('UPDATE sessions SET user_key = ?, username = ? WHERE user_key = ?', [targetKey, cleanTarget, oldKey]);
                } else {
                    this.sqliteDb.prepare('UPDATE sessions SET user_key = ?, username = ? WHERE user_key = ?').run(targetKey, cleanTarget, oldKey);
                }
                if (fs.existsSync(sessionsFile)) {
                    const rawS = JSON.parse(fs.readFileSync(sessionsFile, 'utf8') || '{}');
                    let changedS = false;
                    for (const t of Object.keys(rawS)) {
                        if (normalizeKey(rawS[t].username) === oldKey) {
                            rawS[t].username = cleanTarget;
                            changedS = true;
                        }
                    }
                    if (changedS) fs.writeFileSync(sessionsFile, JSON.stringify(rawS, null, 2), 'utf8');
                }
            } catch (e) {}

            // 4. Eski telefon numarası placeholder kaydını sil (telefon numarasını deleted_users.json listesine ekleme ki numara tekrar eklenebilsin)
            unmarkUserDeletedInFile(oldKey);
            if (this.type === 'mysql') {
                await this.mysqlPool.query('DELETE FROM users WHERE user_key = ?', [oldKey]);
            } else {
                this.sqliteDb.prepare('DELETE FROM users WHERE user_key = ?').run(oldKey);
            }
            try {
                if (fs.existsSync(usersFile)) {
                    const rawU = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                    if (rawU[oldKey]) {
                        delete rawU[oldKey];
                        fs.writeFileSync(usersFile, JSON.stringify(rawU, null, 2), 'utf8');
                    }
                }
            } catch (e) {}
        }

        // Mesajlaşılan tüm kişilerle karşılıklı rehber kaydını garantiye al
        for (const partner of affectedPartners) {
            const pUser = await this.getUser(partner);
            const pName = pUser ? pUser.username : partner;
            const pPhone = pUser ? (pUser.phone || '') : '';
            await this.addContactForUser(pName, cleanTarget, '', cleanPhone);
            await this.addContactForUser(cleanTarget, pName, '', pPhone);
        }

        this.checkpointSqlite();
        await this.exportDbToJson();

        const updatedUser = await this.getUser(cleanTarget);
        return {
            integrated: oldKeysToCleanup.size > 0 || migratedMessagesCount > 0,
            oldUsernames,
            newUsername: cleanTarget,
            phone: cleanPhone,
            migratedMessagesCount,
            user: updatedUser
        };
    }

    async findOrCreateUserByPhone(phoneStr, customName = '', excludeOwnerUsername = '') {
        const cleanPhone = normalizePhone(phoneStr);
        if (!cleanPhone || cleanPhone.length < 7) {
            return { success: false, error: 'Geçerli bir telefon numarası giriniz (Örn: 05XX XXX XX XX)' };
        }

        unmarkUserDeletedInFile(normalizeKey(cleanPhone));
        const exOwnerKey = normalizeKey(excludeOwnerUsername);

        let existing = await this.findUserByPhone(cleanPhone);
        if (existing && exOwnerKey && existing.userKey === exOwnerKey && !isLikelyPhoneNumber(existing.username)) {
            // Eğer eklenmek istenen numara yanlışlıkla davet edenin kendi hesabına yazılmışsa kendi hesabından ayır
            if (this.type === 'mysql') {
                await this.mysqlPool.query('UPDATE users SET phone = ? WHERE user_key = ?', ['', exOwnerKey]);
            } else {
                this.sqliteDb.prepare('UPDATE users SET phone = ? WHERE user_key = ?').run('', exOwnerKey);
                this.checkpointSqlite();
            }
            try {
                if (fs.existsSync(usersFile)) {
                    const rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                    if (rawUsers[exOwnerKey]) {
                        rawUsers[exOwnerKey].phone = '';
                        fs.writeFileSync(usersFile, JSON.stringify(rawUsers, null, 2), 'utf8');
                    }
                }
            } catch (e) {}
            existing = await this.findUserByPhone(cleanPhone);
        }

        if (existing) {
            unmarkUserDeletedInFile(existing.userKey);
            if (!existing.phone) {
                await this.updateUserPhone(existing.username, cleanPhone);
                existing.phone = cleanPhone;
            }
            return { success: true, user: existing, isNew: false };
        }

        const displayUsername = (customName && customName.trim().length >= 2 && (!exOwnerKey || normalizeKey(customName) !== exOwnerKey))
            ? customName.trim()
            : cleanPhone;

        unmarkUserDeletedInFile(normalizeKey(displayUsername));
        const byName = await this.getUser(displayUsername);
        if (byName && (!exOwnerKey || byName.userKey !== exOwnerKey)) {
            await this.updateUserPhone(byName.username, cleanPhone);
            byName.phone = cleanPhone;
            return { success: true, user: byName, isNew: false };
        }

        const crypto = require('crypto');
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync('123456', salt, 1000, 64, 'sha512').toString('hex');
        const created = await this.createUser({
            username: displayUsername,
            phone: cleanPhone,
            salt,
            hash,
            avatar: '/avatars/default.svg',
            lastSeen: 'Offline',
            createdAt: new Date().toISOString()
        });
        if (created) created._wasCreated = true;
        return { success: true, user: created, isNew: true };
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
        const phone = userData.phone ? normalizePhone(userData.phone) : (isLikelyPhoneNumber(userData.username) ? normalizePhone(userData.username) : '');
        const avatar = userData.avatar || '/avatars/default.svg';
        const lastSeen = userData.lastSeen || 'Offline';
        const createdAt = userData.createdAt || new Date().toISOString();

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO users (user_key, username, phone, salt, hash, avatar, last_seen, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE username = VALUES(username), phone = IF(VALUES(phone) != '', VALUES(phone), phone), salt = VALUES(salt), hash = VALUES(hash), avatar = VALUES(avatar)`,
                [userKey, userData.username, phone, userData.salt, userData.hash, avatar, lastSeen, createdAt]
            );
        } else {
            const stmt = this.sqliteDb.prepare(`
                INSERT INTO users (user_key, username, phone, salt, hash, avatar, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_key) DO UPDATE SET
                    username = excluded.username,
                    phone = CASE WHEN excluded.phone != '' THEN excluded.phone ELSE users.phone END,
                    salt = excluded.salt,
                    hash = excluded.hash,
                    avatar = excluded.avatar
            `);
            stmt.run(userKey, userData.username, phone, userData.salt, userData.hash, avatar, lastSeen, createdAt);
            this.checkpointSqlite();
        }

        // users.json dosyasına da anında yansıt (SQLite ve JSON her zaman %100 aynı olsun)
        try {
            ensureDataDir();
            let rawUsers = {};
            if (fs.existsSync(usersFile)) {
                try { rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}'); } catch (e) {}
            }
            const prevPhone = (rawUsers[userKey] && rawUsers[userKey].phone) || '';
            rawUsers[userKey] = {
                username: userData.username,
                phone: phone || prevPhone || '',
                salt: userData.salt,
                hash: userData.hash,
                avatar,
                lastSeen,
                createdAt
            };
            fs.writeFileSync(usersFile, JSON.stringify(rawUsers, null, 2), 'utf8');
        } catch (e) {}
    }

    async updateUserPhone(usernameOrKey, phoneStr) {
        if (!usernameOrKey) return null;
        const userKey = normalizeKey(usernameOrKey);
        const cleanPhone = normalizePhone(phoneStr);
        if (!userKey) return null;

        let existingUser = await this.getUser(userKey);
        if (!existingUser) {
            existingUser = await this.ensureUserExists(usernameOrKey);
        }
        if (!existingUser) {
            existingUser = await this.findUserByPhone(usernameOrKey);
        }

        const effectiveKey = existingUser ? existingUser.userKey : userKey;
        const realUsername = existingUser ? existingUser.username : usernameOrKey.trim();

        // Eğer gerçek bir kullanıcı adına telefon numarası tanımlanıyorsa, varsa o numaraya ait placeholder hesabı ve mesajları entegre et
        if (cleanPhone && cleanPhone.length >= 7 && !isLikelyPhoneNumber(realUsername)) {
            const intRes = await this.integratePhoneWithUsername(cleanPhone, realUsername);
            if (intRes && intRes.user) {
                intRes.user._integrationResult = intRes;
                return intRes.user;
            }
        }

        if (this.type === 'mysql') {
            await this.mysqlPool.query('UPDATE users SET phone = ? WHERE user_key = ? OR user_key = ?', [cleanPhone, effectiveKey, userKey]);
        } else {
            this.sqliteDb.prepare('UPDATE users SET phone = ? WHERE user_key = ? OR user_key = ?').run(cleanPhone, effectiveKey, userKey);
            this.checkpointSqlite();
        }

        try {
            if (fs.existsSync(usersFile)) {
                const raw = JSON.parse(fs.readFileSync(usersFile, 'utf8') || '{}');
                if (raw[effectiveKey]) {
                    raw[effectiveKey].phone = cleanPhone;
                    fs.writeFileSync(usersFile, JSON.stringify(raw, null, 2), 'utf8');
                } else if (raw[userKey]) {
                    raw[userKey].phone = cleanPhone;
                    fs.writeFileSync(usersFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}

        const finalUser = (await this.getUser(effectiveKey)) || (await this.getUser(userKey));
        return finalUser;
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

        // Eğer gelen kullanıcı adı bir telefon numarasıysa ama bu numara zaten gerçek bir kullanıcı adıyla entegre edilmişse,
        // numaradan tekrar mükerrer kayıt açmak yerine entegre edilmiş kullanıcıyı döndür
        if (isLikelyPhoneNumber(clean)) {
            const byPhone = await this.findUserByPhone(clean);
            if (byPhone) {
                return byPhone;
            }
            if (!extraData || !extraData.allowPhoneAsUsername) {
                return null;
            }
        }

        // Eğer gerçek bir kullanıcı adı ve telefon numarası birlikte geldiyse numaralı placeholder kaydıyla entegre et
        const extraPhone = (extraData && extraData.phone) ? normalizePhone(extraData.phone) : '';
        if (extraPhone && extraPhone.length >= 7 && !isLikelyPhoneNumber(clean)) {
            const intRes = await this.integratePhoneWithUsername(extraPhone, clean, {
                ...(extraData || {}),
                avatar: avatar || '/avatars/default.svg'
            });
            if (intRes && intRes.user) {
                if (intRes.integrated) intRes.user._wasIntegrated = intRes;
                return intRes.user;
            }
        }

        const crypto = require('crypto');
        let existing = await this.getUser(clean);
        if (existing) {
            if (extraData && extraData.phone && !existing.phone) {
                await this.updateUserPhone(existing.username, extraData.phone);
                existing = await this.getUser(existing.username);
            }
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
            phone: extraPhone || (isLikelyPhoneNumber(clean) ? normalizePhone(clean) : ''),
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
            phone: row.phone || (isLikelyPhoneNumber(row.username) ? normalizePhone(row.username) : ''),
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
        if (!msg || !msg.sender || !msg.recipient || normalizeKey(msg.sender) === normalizeKey(msg.recipient)) return;
        const convoKey = getConvoKey(msg.sender, msg.recipient);
        const id = msg.id || ('msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6));
        const fileJson = msg.file ? JSON.stringify(msg.file) : null;
        let cleanText = decryptAtRestDbText(decryptE2EETextIfNeeded(msg.text || '', msg.sender, msg.recipient));
        if (msg.file && cleanText === '📎 Dosya / Fotoğraf paylaştı') {
            cleanText = '';
        }
        const storedCipherText = encryptAtRestDbText(cleanText);
        const timestamp = msg.timestamp || new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
        const dateStr = msg.date || 'Bugün';
        const createdAt = msg.createdAt || new Date().toISOString();
        const isRead = msg.read ? 1 : 0;

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                     is_read = GREATEST(is_read, VALUES(is_read)),
                     text = IF(VALUES(file_json) IS NOT NULL AND file_json IS NULL, VALUES(text), text),
                     file_json = COALESCE(VALUES(file_json), file_json)`,
                [id, convoKey, msg.sender, msg.recipient, storedCipherText, fileJson, timestamp, dateStr, createdAt, isRead]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    is_read = MAX(messages.is_read, excluded.is_read),
                    text = CASE
                        WHEN excluded.file_json IS NOT NULL AND messages.file_json IS NULL THEN excluded.text
                        ELSE messages.text
                    END,
                    file_json = COALESCE(excluded.file_json, messages.file_json)
            `).run(id, convoKey, msg.sender, msg.recipient, storedCipherText, fileJson, timestamp, dateStr, createdAt, isRead);
        }
    }

    async saveMessage(msg) {
        if (!msg || !msg.sender || !msg.recipient || normalizeKey(msg.sender) === normalizeKey(msg.recipient)) {
            return {
                id: (msg && msg.id) || ('msg_' + Date.now()),
                convoKey: '',
                sender: (msg && msg.sender) || '',
                recipient: (msg && msg.recipient) || '',
                text: (msg && msg.text) || '',
                file: (msg && msg.file) || null,
                timestamp: '',
                date: 'Bugün',
                createdAt: new Date().toISOString(),
                read: true
            };
        }
        const convoKey = getConvoKey(msg.sender, msg.recipient);
        const id = msg.id || ('msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6));
        const fileJson = msg.file ? JSON.stringify(msg.file) : null;
        let cleanText = decryptAtRestDbText(decryptE2EETextIfNeeded(msg.text || '', msg.sender, msg.recipient));
        if (msg.file && cleanText === '📎 Dosya / Fotoğraf paylaştı') {
            cleanText = '';
        }
        const storedCipherText = encryptAtRestDbText(cleanText);
        const timestamp = msg.timestamp || new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
        const dateStr = msg.date || 'Bugün';
        const createdAt = msg.createdAt || new Date().toISOString();
        const isRead = msg.read ? 1 : 0;

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, convoKey, msg.sender, msg.recipient, storedCipherText, fileJson, timestamp, dateStr, createdAt, isRead]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO messages (id, convo_key, sender, recipient, text, file_json, timestamp, date_str, created_at, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(id, convoKey, msg.sender, msg.recipient, storedCipherText, fileJson, timestamp, dateStr, createdAt, isRead);
            this.checkpointSqlite();
        }

        // Mesajlaşılan kişileri birbirinin kişi listesine otomatik kaydet
        try {
            if (msg.sender && msg.recipient) {
                await this.addContactForUser(msg.sender, msg.recipient);
                await this.addContactForUser(msg.recipient, msg.sender);
            }
        } catch (e) {}

        const savedResult = {
            id,
            convoKey,
            sender: msg.sender,
            recipient: msg.recipient,
            text: cleanText,
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

    // ========================================================
    // KİŞİSEL REHBER (HER KULLANICI SADECE KENDİ REHBERİNDEKİ / MESAJLAŞTIĞI KİŞİLERİ GÖRÜR)
    // ========================================================
    async addContactForUser(ownerUsername, contactUsername, customName = '', phone = '') {
        const ownerKey = normalizeKey(ownerUsername);
        const contactKey = normalizeKey(contactUsername);
        if (!ownerKey || !contactKey || ownerKey === contactKey) return false;

        const now = new Date().toISOString();
        const cName = String(customName || '').trim();
        const cPhone = normalizePhone(phone || '');

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO user_contacts (owner_key, contact_key, contact_username, custom_name, phone, added_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                     contact_username = VALUES(contact_username),
                     custom_name = IF(VALUES(custom_name) != '', VALUES(custom_name), custom_name),
                     phone = IF(VALUES(phone) != '', VALUES(phone), phone)`,
                [ownerKey, contactKey, contactUsername.trim(), cName, cPhone, now]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO user_contacts (owner_key, contact_key, contact_username, custom_name, phone, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_key, contact_key) DO UPDATE SET
                    contact_username = excluded.contact_username,
                    custom_name = CASE WHEN excluded.custom_name != '' THEN excluded.custom_name ELSE user_contacts.custom_name END,
                    phone = CASE WHEN excluded.phone != '' THEN excluded.phone ELSE user_contacts.phone END
            `).run(ownerKey, contactKey, contactUsername.trim(), cName, cPhone, now);
            this.checkpointSqlite();
        }

        // JSON yedek
        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(userContactsFile)) {
                try { raw = JSON.parse(fs.readFileSync(userContactsFile, 'utf8') || '{}'); } catch (e) {}
            }
            if (!raw[ownerKey]) raw[ownerKey] = {};
            if (raw['_removed_' + ownerKey] && raw['_removed_' + ownerKey][contactKey]) {
                delete raw['_removed_' + ownerKey][contactKey];
            }
            const prev = raw[ownerKey][contactKey] || {};
            raw[ownerKey][contactKey] = {
                contactUsername: contactUsername.trim(),
                customName: cName || prev.customName || '',
                phone: cPhone || prev.phone || '',
                addedAt: prev.addedAt || now
            };
            fs.writeFileSync(userContactsFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {}

        return true;
    }

    async importContactsBatch(ownerUsername, contacts) {
        const ownerKey = normalizeKey(ownerUsername);
        if (!ownerKey || !Array.isArray(contacts)) {
            return { success: false, error: 'Geçersiz parametreler' };
        }

        const results = [];
        for (const item of contacts) {
            const rawPhone = item.phone || '';
            const cleanPhone = normalizePhone(rawPhone);
            const rawName = String(item.name || '').trim();
            if (!cleanPhone || cleanPhone.length < 7) continue;

            unmarkUserDeletedInFile(normalizeKey(cleanPhone));
            if (rawName) unmarkUserDeletedInFile(normalizeKey(rawName));

            // Sistemde kayıtlı kullanıcı var mı kontrol et
            const existingUser = await this.findUserByPhone(cleanPhone);
            const contactUsername = existingUser ? existingUser.username : (rawName || cleanPhone);
            const contactKey = normalizeKey(contactUsername);

            if (contactKey && contactKey !== ownerKey) {
                await this.addContactForUser(ownerUsername, contactUsername, rawName, cleanPhone);
                results.push({
                    username: contactUsername,
                    customName: rawName || (existingUser ? existingUser.username : ''),
                    phone: cleanPhone,
                    avatar: (existingUser && existingUser.avatar) || '/avatars/default.svg',
                    isRegistered: !!existingUser,
                    isOnline: false
                });
            }
        }

        return { success: true, count: results.length, contacts: results };
    }

    getRemovedContactsForUser(ownerUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        const set = new Set();
        if (!ownerKey) return set;
        try {
            if (fs.existsSync(userContactsFile)) {
                const raw = JSON.parse(fs.readFileSync(userContactsFile, 'utf8') || '{}');
                const rem = raw['_removed_' + ownerKey] || {};
                for (const k of Object.keys(rem)) {
                    set.add(normalizeKey(k));
                }
            }
        } catch (e) {}
        return set;
    }

    async removeContactForUser(ownerUsername, contactUsername, clearChatHistory = true) {
        const ownerKey = normalizeKey(ownerUsername);
        const contactKey = normalizeKey(contactUsername);
        if (!ownerKey || !contactKey) return { success: false, error: 'Geçersiz kullanıcı veya kişi adı' };

        try {
            if (this.type === 'mysql') {
                await this.mysqlPool.query(
                    'DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?',
                    [ownerKey, contactKey]
                );
            } else {
                this.sqliteDb.prepare(
                    'DELETE FROM user_contacts WHERE owner_key = ? AND contact_key = ?'
                ).run(ownerKey, contactKey);
                this.checkpointSqlite();
            }
        } catch (e) {}

        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(userContactsFile)) {
                try { raw = JSON.parse(fs.readFileSync(userContactsFile, 'utf8') || '{}'); } catch (e) {}
            }
            if (raw[ownerKey] && raw[ownerKey][contactKey]) {
                delete raw[ownerKey][contactKey];
            }
            if (!raw['_removed_' + ownerKey]) raw['_removed_' + ownerKey] = {};
            raw['_removed_' + ownerKey][contactKey] = new Date().toISOString();
            fs.writeFileSync(userContactsFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {}

        if (clearChatHistory) {
            await this.clearConversation(ownerUsername, contactUsername, ownerUsername);
        }

        return {
            success: true,
            ownerUsername: ownerUsername.trim(),
            contactUsername: contactUsername.trim(),
            contactKey
        };
    }

    // ========================================================
    // KİŞİ ENGELLEME VE ENGEL KALDIRMA (BLOCK / UNBLOCK)
    // ========================================================
    async blockUser(ownerUsername, targetUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        const blockedKey = normalizeKey(targetUsername);
        if (!ownerKey || !blockedKey || ownerKey === blockedKey) {
            return { success: false, error: 'Geçersiz kullanıcı adı' };
        }

        const now = new Date().toISOString();
        const cleanTarget = targetUsername.trim();

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO blocked_users (owner_key, blocked_key, blocked_username, created_at)
                 VALUES (?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE blocked_username = VALUES(blocked_username), created_at = VALUES(created_at)`,
                [ownerKey, blockedKey, cleanTarget, now]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO blocked_users (owner_key, blocked_key, blocked_username, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(owner_key, blocked_key) DO UPDATE SET
                    blocked_username = excluded.blocked_username,
                    created_at = excluded.created_at
            `).run(ownerKey, blockedKey, cleanTarget, now);
            this.checkpointSqlite();
        }

        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(blockedUsersFile)) {
                try { raw = JSON.parse(fs.readFileSync(blockedUsersFile, 'utf8') || '{}'); } catch (e) {}
            }
            if (!raw[ownerKey]) raw[ownerKey] = {};
            raw[ownerKey][blockedKey] = {
                blockedUsername: cleanTarget,
                createdAt: now
            };
            fs.writeFileSync(blockedUsersFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {}

        return {
            success: true,
            ownerUsername: ownerUsername.trim(),
            targetUsername: cleanTarget,
            blockedKey,
            isBlocked: true
        };
    }

    async unblockUser(ownerUsername, targetUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        const blockedKey = normalizeKey(targetUsername);
        if (!ownerKey || !blockedKey) {
            return { success: false, error: 'Geçersiz kullanıcı adı' };
        }

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                'DELETE FROM blocked_users WHERE owner_key = ? AND blocked_key = ?',
                [ownerKey, blockedKey]
            );
        } else {
            this.sqliteDb.prepare(
                'DELETE FROM blocked_users WHERE owner_key = ? AND blocked_key = ?'
            ).run(ownerKey, blockedKey);
            this.checkpointSqlite();
        }

        try {
            if (fs.existsSync(blockedUsersFile)) {
                const raw = JSON.parse(fs.readFileSync(blockedUsersFile, 'utf8') || '{}');
                if (raw[ownerKey] && raw[ownerKey][blockedKey]) {
                    delete raw[ownerKey][blockedKey];
                    fs.writeFileSync(blockedUsersFile, JSON.stringify(raw, null, 2), 'utf8');
                }
            }
        } catch (e) {}

        return {
            success: true,
            ownerUsername: ownerUsername.trim(),
            targetUsername: targetUsername.trim(),
            blockedKey,
            isBlocked: false
        };
    }

    async isUserBlocked(ownerUsername, targetUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        const targetKey = normalizeKey(targetUsername);
        if (!ownerKey || !targetKey) return false;

        try {
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query(
                    'SELECT 1 FROM blocked_users WHERE owner_key = ? AND blocked_key = ? LIMIT 1',
                    [ownerKey, targetKey]
                );
                if (rows.length > 0) return true;
            } else {
                const row = this.sqliteDb.prepare(
                    'SELECT 1 FROM blocked_users WHERE owner_key = ? AND blocked_key = ? LIMIT 1'
                ).get(ownerKey, targetKey);
                if (row) return true;
            }
        } catch (e) {}

        try {
            if (fs.existsSync(blockedUsersFile)) {
                const raw = JSON.parse(fs.readFileSync(blockedUsersFile, 'utf8') || '{}');
                if (raw[ownerKey] && raw[ownerKey][targetKey]) return true;
            }
        } catch (e) {}

        return false;
    }

    async getBlockedUsersForUser(ownerUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        const map = new Map();
        if (!ownerKey) return map;

        try {
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query(
                    'SELECT * FROM blocked_users WHERE owner_key = ?',
                    [ownerKey]
                );
                for (const r of rows) {
                    map.set(normalizeKey(r.blocked_key), {
                        blockedKey: normalizeKey(r.blocked_key),
                        blockedUsername: r.blocked_username,
                        createdAt: r.created_at
                    });
                }
            } else {
                const rows = this.sqliteDb.prepare(
                    'SELECT * FROM blocked_users WHERE owner_key = ?'
                ).all(ownerKey);
                for (const r of rows) {
                    map.set(normalizeKey(r.blocked_key), {
                        blockedKey: normalizeKey(r.blocked_key),
                        blockedUsername: r.blocked_username,
                        createdAt: r.created_at
                    });
                }
            }
        } catch (e) {}

        try {
            if (fs.existsSync(blockedUsersFile)) {
                const raw = JSON.parse(fs.readFileSync(blockedUsersFile, 'utf8') || '{}');
                const ownerMap = raw[ownerKey] || {};
                for (const bKey of Object.keys(ownerMap)) {
                    const normB = normalizeKey(bKey);
                    if (!map.has(normB)) {
                        map.set(normB, {
                            blockedKey: normB,
                            blockedUsername: ownerMap[bKey].blockedUsername || bKey,
                            createdAt: ownerMap[bKey].createdAt || ''
                        });
                    }
                }
            }
        } catch (e) {}

        return map;
    }

    async getContactsForUser(ownerUsername) {
        const ownerKey = normalizeKey(ownerUsername);
        if (!ownerKey) return new Map();
        const map = new Map();

        try {
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query('SELECT * FROM user_contacts WHERE owner_key = ?', [ownerKey]);
                for (const r of rows) {
                    map.set(r.contact_key, {
                        contactKey: r.contact_key,
                        contactUsername: r.contact_username,
                        customName: r.custom_name || '',
                        phone: r.phone || '',
                        addedAt: r.added_at
                    });
                }
            } else {
                const rows = this.sqliteDb.prepare('SELECT * FROM user_contacts WHERE owner_key = ?').all(ownerKey);
                for (const r of rows) {
                    map.set(r.contact_key, {
                        contactKey: r.contact_key,
                        contactUsername: r.contact_username,
                        customName: r.custom_name || '',
                        phone: r.phone || '',
                        addedAt: r.added_at
                    });
                }
            }
        } catch (e) {}

        // JSON yedekten de oku (varsa eksik olanları tamamla)
        try {
            if (fs.existsSync(userContactsFile)) {
                const raw = JSON.parse(fs.readFileSync(userContactsFile, 'utf8') || '{}');
                const ownerMap = raw[ownerKey] || {};
                for (const cKey of Object.keys(ownerMap)) {
                    if (!map.has(cKey)) {
                        const item = ownerMap[cKey];
                        map.set(cKey, {
                            contactKey: cKey,
                            contactUsername: item.contactUsername || cKey,
                            customName: item.customName || '',
                            phone: item.phone || '',
                            addedAt: item.addedAt || ''
                        });
                    }
                }
            }
        } catch (e) {}

        return map;
    }

    // Metadata Korumalı (SHA-256 Hash) Rehber Eşleştirme
    async matchHashedPhones(phoneHashesArray, ownerUsername = '') {
        const crypto = require('crypto');
        const hashSet = new Set((phoneHashesArray || []).map(h => String(h || '').toLowerCase().trim()).filter(Boolean));
        if (hashSet.size === 0) return [];

        const allUsers = await this.getAllUsers();
        const ownerKey = normalizeKey(ownerUsername);
        const matched = [];

        for (const u of allUsers) {
            if (u.userKey === ownerKey) continue;
            const candidatePhone = normalizePhone(u.phone || (isLikelyPhoneNumber(u.username) ? u.username : ''));
            if (!candidatePhone) continue;

            const h1 = crypto.createHash('sha256').update('MSJ_PRIVATE_CONTACT_DISCOVERY_V1::' + candidatePhone, 'utf8').digest('hex');
            const h2 = crypto.createHash('sha256').update(candidatePhone, 'utf8').digest('hex');

            if (hashSet.has(h1) || hashSet.has(h2)) {
                if (ownerUsername) {
                    await this.addContactForUser(ownerUsername, u.username, '', candidatePhone);
                }
                matched.push({
                    username: u.username,
                    phone: candidatePhone,
                    avatar: u.avatar || '/avatars/default.svg',
                    phoneHash: h1
                });
            }
        }
        return matched;
    }

    // ========================================================
    // SIGNAL X3DH / DOUBLE RATCHET KEY BUNDLE & AKD KEY TRANSPARENCY
    // ========================================================
    async saveUserKeyBundle(username, bundleObj = {}) {
        const uKey = normalizeKey(username);
        if (!uKey) return null;
        const crypto = require('crypto');
        const now = new Date().toISOString();

        const existing = await this.getUserKeyBundle(username);
        const nextSeq = existing ? ((existing.akdSeq || 0) + 1) : 1;
        const prevHash = existing ? (existing.akdHash || 'GENESIS_AKD_ROOT_00000000') : 'GENESIS_AKD_ROOT_00000000';

        const identityKey = String(bundleObj.identityKey || (existing && existing.identityKey) || '');
        const signingKey = String(bundleObj.signingKey || (existing && existing.signingKey) || '');
        const signedPreKey = String(bundleObj.signedPreKey || (existing && existing.signedPreKey) || '');
        const spkSignature = String(bundleObj.spkSignature || (existing && existing.spkSignature) || '');
        const oneTimePreKeys = Array.isArray(bundleObj.oneTimePreKeys)
            ? bundleObj.oneTimePreKeys
            : (existing && existing.oneTimePreKeys ? existing.oneTimePreKeys : []);

        // AKD (Auditable Key Directory) Merkle / Hash-Chain Kanıtı
        const akdHash = crypto.createHash('sha256')
            .update(`AKD_V1::${uKey}::${nextSeq}::${prevHash}::${identityKey}::${signingKey}::${signedPreKey}`, 'utf8')
            .digest('hex');

        const otpkJson = JSON.stringify(oneTimePreKeys);
        const protocolVersion = bundleObj.protocolVersion || 'Signal-X3DH-DoubleRatchet-v2';

        if (this.type === 'mysql') {
            await this.mysqlPool.query(
                `INSERT INTO e2ee_keys (user_key, username, protocol_version, identity_key, signing_key, signed_pre_key, spk_signature, one_time_pre_keys_json, akd_seq, akd_prev_hash, akd_hash, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                     username = VALUES(username),
                     protocol_version = VALUES(protocol_version),
                     identity_key = VALUES(identity_key),
                     signing_key = VALUES(signing_key),
                     signed_pre_key = VALUES(signed_pre_key),
                     spk_signature = VALUES(spk_signature),
                     one_time_pre_keys_json = VALUES(one_time_pre_keys_json),
                     akd_seq = VALUES(akd_seq),
                     akd_prev_hash = VALUES(akd_prev_hash),
                     akd_hash = VALUES(akd_hash),
                     updated_at = VALUES(updated_at)`,
                [uKey, username.trim(), protocolVersion, identityKey, signingKey, signedPreKey, spkSignature, otpkJson, nextSeq, prevHash, akdHash, now]
            );
        } else {
            this.sqliteDb.prepare(`
                INSERT INTO e2ee_keys (user_key, username, protocol_version, identity_key, signing_key, signed_pre_key, spk_signature, one_time_pre_keys_json, akd_seq, akd_prev_hash, akd_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_key) DO UPDATE SET
                    username = excluded.username,
                    protocol_version = excluded.protocol_version,
                    identity_key = excluded.identity_key,
                    signing_key = excluded.signing_key,
                    signed_pre_key = excluded.signed_pre_key,
                    spk_signature = excluded.spk_signature,
                    one_time_pre_keys_json = excluded.one_time_pre_keys_json,
                    akd_seq = excluded.akd_seq,
                    akd_prev_hash = excluded.akd_prev_hash,
                    akd_hash = excluded.akd_hash,
                    updated_at = excluded.updated_at
            `).run(uKey, username.trim(), protocolVersion, identityKey, signingKey, signedPreKey, spkSignature, otpkJson, nextSeq, prevHash, akdHash, now);
            this.checkpointSqlite();
        }

        const record = {
            userKey: uKey,
            username: username.trim(),
            protocolVersion,
            identityKey,
            signingKey,
            signedPreKey,
            spkSignature,
            oneTimePreKeys,
            akdSeq: nextSeq,
            akdPrevHash: prevHash,
            akdHash,
            updatedAt: now
        };

        try {
            ensureDataDir();
            let raw = {};
            if (fs.existsSync(e2eeKeysFile)) {
                try { raw = JSON.parse(fs.readFileSync(e2eeKeysFile, 'utf8') || '{}'); } catch (e) {}
            }
            raw[uKey] = record;
            fs.writeFileSync(e2eeKeysFile, JSON.stringify(raw, null, 2), 'utf8');
        } catch (e) {}

        return record;
    }

    async getUserKeyBundle(username) {
        const uKey = normalizeKey(username);
        if (!uKey) return null;

        try {
            let row = null;
            if (this.type === 'mysql') {
                const [rows] = await this.mysqlPool.query('SELECT * FROM e2ee_keys WHERE user_key = ?', [uKey]);
                if (rows.length > 0) row = rows[0];
            } else {
                row = this.sqliteDb.prepare('SELECT * FROM e2ee_keys WHERE user_key = ?').get(uKey);
            }
            if (row) {
                let otpk = [];
                try { otpk = JSON.parse(row.one_time_pre_keys_json || '[]'); } catch (e) {}
                return {
                    userKey: row.user_key,
                    username: row.username,
                    protocolVersion: row.protocol_version,
                    identityKey: row.identity_key,
                    signingKey: row.signing_key,
                    signedPreKey: row.signed_pre_key,
                    spkSignature: row.spk_signature,
                    oneTimePreKeys: otpk,
                    akdSeq: row.akd_seq || 1,
                    akdPrevHash: row.akd_prev_hash || '',
                    akdHash: row.akd_hash || '',
                    updatedAt: row.updated_at
                };
            }
        } catch (e) {}

        try {
            if (fs.existsSync(e2eeKeysFile)) {
                const raw = JSON.parse(fs.readFileSync(e2eeKeysFile, 'utf8') || '{}');
                if (raw[uKey]) return raw[uKey];
            }
        } catch (e) {}

        return null;
    }

    // SOHBETLER LİSTESİ VE SON MESAJLAR (Online kullanıcılar, kişisel rehber ve mesajlaşılan kişiler)
    async getChatsList(currentUsername, onlineUserKeysMap) {
        const currentKey = normalizeKey(currentUsername);
        const allUsers = await this.getAllUsers();
        const personalContactsMap = await this.getContactsForUser(currentUsername);
        const blockedUsersMap = await this.getBlockedUsersForUser(currentUsername);
        const removedContactsSet = this.getRemovedContactsForUser(currentUsername);
        const chatItems = [];
        const seenKeys = new Set();

        // Rehberdeki telefon numaralarından da hızlı eşleştirme haritası oluştur
        const personalContactsByPhone = new Map();
        for (const [, cInfo] of personalContactsMap.entries()) {
            const p = normalizePhone(cInfo.phone || (isLikelyPhoneNumber(cInfo.contactUsername) ? cInfo.contactUsername : ''));
            if (p && p.length >= 7) {
                personalContactsByPhone.set(p.length >= 10 ? p.slice(-10) : p, cInfo);
            }
        }

        for (const contact of allUsers) {
            if (contact.userKey === currentKey) continue; // Kendisini hariç tut

            const contactCleanPhone = normalizePhone(contact.phone || (isLikelyPhoneNumber(contact.username) ? contact.username : ''));
            const phoneLookupKey = contactCleanPhone.length >= 10 ? contactCleanPhone.slice(-10) : contactCleanPhone;
            const savedContactInfo = personalContactsMap.get(contact.userKey) || (phoneLookupKey ? personalContactsByPhone.get(phoneLookupKey) : null);

            if (!savedContactInfo && this.isUserDeleted(contact.userKey)) continue;

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

            // Kullanıcı bu kişiyi kendi rehberinden özel olarak sildiyse ve yeni mesajı yoksa listede gösterme
            if (removedContactsSet.has(contact.userKey) && !lastRow && unreadCount === 0) {
                continue;
            }

            const isOnline = Boolean(
                onlineUserKeysMap &&
                onlineUserKeysMap.has(contact.userKey) &&
                onlineUserKeysMap.get(contact.userKey).size > 0
            );
            const isBlocked = blockedUsersMap.has(contact.userKey);

            // Eğer sadece telefon numarasından oluşan sahipsiz/boş bir placeholder ise ve ne mesajı ne rehber kaydı ne de online durumu varsa gösterme;
            // ancak programı kullanmaya başlayan gerçek kullanıcılar ve Online olanlar her zaman listede ve Online ekranında görünsün!
            const isInPersonalContacts = Boolean(savedContactInfo);
            const isUnclaimedPhoneOnly = isLikelyPhoneNumber(contact.username);
            if (isUnclaimedPhoneOnly && !isInPersonalContacts && !lastRow && unreadCount === 0 && !isOnline) {
                continue;
            }

            const lastMsg = lastRow ? this.formatMessageRow(lastRow) : null;

            chatItems.push({
                username: contact.username,
                customName: (savedContactInfo && savedContactInfo.customName && !isLikelyPhoneNumber(savedContactInfo.customName)) ? savedContactInfo.customName : '',
                phone: contact.phone || (savedContactInfo && savedContactInfo.phone) || '',
                avatar: contact.avatar || '/avatars/default.svg',
                isOnline,
                isBlocked,
                statusText: isBlocked ? 'Engellendi' : (isOnline ? 'Online' : 'Offline'),
                lastSeen: isOnline ? 'Online' : (contact.lastSeen || 'Offline'),
                lastMessage: lastMsg ? {
                    id: lastMsg.id,
                    sender: lastMsg.sender,
                    recipient: lastMsg.recipient,
                    text: lastMsg.text,
                    file: lastMsg.file,
                    timestamp: lastMsg.timestamp,
                    date: lastMsg.date || 'Bugün',
                    createdAt: lastMsg.createdAt || '',
                    isOutgoing: normalizeKey(lastMsg.sender) === currentKey
                } : null,
                unreadCount
            });
            seenKeys.add(contact.userKey);
        }

        // 2. Kişisel rehbere (user_contacts) eklenmiş ancak henüz users tablosunda tam hesabı olmayan kişileri de sohbet listesine dahil et
        for (const [cKey, cInfo] of personalContactsMap.entries()) {
            if (cKey === currentKey || seenKeys.has(cKey)) continue;
            if (removedContactsSet.has(cKey)) continue;

            const contactUsername = cInfo.contactUsername || cInfo.customName || cInfo.phone;
            if (!contactUsername) continue;

            const convoKey = getConvoKey(currentUsername, contactUsername);
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
                unreadCount = uRows[0] ? uRows[0].cnt : 0;
            } else {
                lastRow = this.sqliteDb.prepare(
                    'SELECT * FROM messages WHERE convo_key = ? ORDER BY created_at DESC LIMIT 1'
                ).get(convoKey);

                const uRow = this.sqliteDb.prepare(
                    'SELECT COUNT(*) as cnt FROM messages WHERE convo_key = ? AND (LOWER(recipient) = ? OR recipient = ?) AND is_read = 0'
                ).get(convoKey, currentKey, currentUsername);
                unreadCount = uRow ? uRow.cnt : 0;
            }

            const lastMsg = lastRow ? this.formatMessageRow(lastRow) : null;
            const isOnline = Boolean(
                onlineUserKeysMap &&
                onlineUserKeysMap.has(cKey) &&
                onlineUserKeysMap.get(cKey).size > 0
            );

            chatItems.push({
                username: contactUsername,
                customName: cInfo.customName || '',
                phone: cInfo.phone || '',
                avatar: '/avatars/default.svg',
                isOnline,
                isBlocked: blockedUsersMap.has(cKey),
                statusText: isOnline ? 'Online' : 'Offline',
                lastSeen: isOnline ? 'Online' : 'Offline',
                lastMessage: lastMsg ? {
                    id: lastMsg.id,
                    sender: lastMsg.sender,
                    recipient: lastMsg.recipient,
                    text: lastMsg.text,
                    file: lastMsg.file,
                    timestamp: lastMsg.timestamp,
                    date: lastMsg.date || 'Bugün',
                    createdAt: lastMsg.createdAt || '',
                    isOutgoing: normalizeKey(lastMsg.sender) === currentKey
                } : null,
                unreadCount
            });
            seenKeys.add(cKey);
        }

        // Sıralama: Önce okunmamış mesajı olanlar ve Online olanlar, ardından son mesaj tarihine göre
        chatItems.sort((a, b) => {
            if ((b.unreadCount > 0) !== (a.unreadCount > 0)) return (b.unreadCount > 0) ? 1 : -1;
            if (Boolean(b.isOnline) !== Boolean(a.isOnline)) return b.isOnline ? 1 : -1;
            const tA = (a.lastMessage && a.lastMessage.createdAt) ? new Date(a.lastMessage.createdAt).getTime() : 0;
            const tB = (b.lastMessage && b.lastMessage.createdAt) ? new Date(b.lastMessage.createdAt).getTime() : 0;
            if (tB !== tA) return tB - tA;
            return a.username.localeCompare(b.username, 'tr');
        });

        return chatItems;
    }

    formatMessageRow(row) {
        let fileObj = null;
        if (row.file_json) {
            try { fileObj = JSON.parse(row.file_json); } catch (e) {}
        }

        const rawDecrypted = decryptAtRestDbText(row.text || '');
        let cleanText = decryptE2EETextIfNeeded(rawDecrypted, row.sender, row.recipient);
        if (fileObj && cleanText === '📎 Dosya / Fotoğraf paylaştı') {
            cleanText = '';
        }

        return {
            id: row.id,
            convoKey: row.convo_key,
            sender: row.sender,
            recipient: row.recipient,
            text: cleanText,
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
    normalizePhone,
    isLikelyPhoneNumber,
    getConvoKey,
    decryptE2EETextIfNeeded
};
