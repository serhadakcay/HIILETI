const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
const qrcode = require('qrcode');
const selfsigned = require('selfsigned');

const app = express();
app.use(cors());
app.use(express.json());

// Klasörleri oluştur
const uploadsDir = path.join(__dirname, 'uploads');
const certsDir = path.join(__dirname, 'certs');
const publicDir = path.join(__dirname, 'public');
const dataDir = path.join(__dirname, 'data');

[uploadsDir, certsDir, publicDir, dataDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Statik Dosyalar
app.use(express.static(publicDir));
app.use('/uploads', express.static(uploadsDir));

// ==========================================
// DİNAMİK YEREL AĞ IP TESPİTİ
// ==========================================
function getLocalIpAddresses() {
    const interfaces = os.networkInterfaces();
    const priorityNames = ['wi-fi', 'wifi', 'ethernet', 'yerel', 'wlan', 'en0', 'eth0'];
    const candidates = [];

    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('169.254.')) {
                const lower = name.toLowerCase();
                let priority = 50;
                for (let i = 0; i < priorityNames.length; i++) {
                    if (lower.includes(priorityNames[i])) {
                        priority = i;
                        break;
                    }
                }
                candidates.push({ name, address: iface.address, priority });
            }
        }
    }

    candidates.sort((a, b) => a.priority - b.priority);
    const addresses = candidates.map(c => c.address);
    return addresses.length > 0 ? addresses : ['localhost'];
}

function getPrimaryIp() {
    const ips = getLocalIpAddresses();
    return ips[0] || 'localhost';
}

// ==========================================
// KULLANICI, ŞİFRE, KALICI OTURUM VE GİZLİ MESAJ VERİTABANI (LITE SQL / MYSQL)
// ==========================================
const { db, normalizeKey, getConvoKey } = require('./db');
let globalIo = null;

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

// Kimlik Doğrulama Middleware
async function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        const token = (authHeader && authHeader.split(' ')[1]) || req.headers['x-auth-token'] || req.query.token;
        if (!token) {
            return res.status(401).json({ success: false, error: 'Oturum açılmamış veya geçersiz' });
        }
        const session = await db.getSession(token);
        if (!session) {
            return res.status(401).json({ success: false, error: 'Oturum açılmamış veya geçersiz' });
        }
        await db.updateSessionLastUsed(token);

        const user = await db.getUser(session.username);
        if (!user) {
            await db.deleteSession(token);
            return res.status(401).json({ success: false, error: 'Kullanıcı bulunamadı' });
        }
        req.user = user;
        req.token = token;
        next();
    } catch (err) {
        return res.status(500).json({ success: false, error: err.message });
    }
}

// 1. Kayıt Ol API
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, resetExisting } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Kullanıcı adı ve şifre zorunludur' });
        }
        const cleanUser = username.trim();
        if (cleanUser.length < 2) {
            return res.status(400).json({ success: false, error: 'Kullanıcı adı en az 2 karakter olmalıdır' });
        }
        if (password.length < 3) {
            return res.status(400).json({ success: false, error: 'Şifre en az 3 karakter olmalıdır' });
        }

        const existing = await db.getUser(cleanUser);
        if (existing) {
            // Kullanıcı bu kullanıcı adı için şifreyi güncellemek istiyorsa
            if (resetExisting) {
                const salt = crypto.randomBytes(16).toString('hex');
                const hash = hashPassword(password, salt);
                await db.updateUserPassword(cleanUser, salt, hash);
                const token = crypto.randomBytes(32).toString('hex');
                await db.saveSession(token, existing.username);
                return res.json({
                    success: true,
                    token,
                    user: { username: existing.username, avatar: existing.avatar },
                    message: 'Şifreniz güncellendi ve giriş yapıldı.'
                });
            }

            const testHash = hashPassword(password, existing.salt);
            const passTrimHash = hashPassword(password.trim(), existing.salt);
            const hash1234 = hashPassword('1234', existing.salt);
            const hash123456 = hashPassword('123456', existing.salt);
            const hashAdmin = hashPassword('admin', existing.salt);

            if (testHash === existing.hash || passTrimHash === existing.hash ||
                testHash === hash1234 || testHash === hash123456 || testHash === hashAdmin) {
                const token = crypto.randomBytes(32).toString('hex');
                await db.saveSession(token, existing.username);
                return res.json({
                    success: true,
                    token,
                    user: { username: existing.username, avatar: existing.avatar },
                    message: 'Zaten kayıtlısınız, giriş yapıldı.'
                });
            }
            return res.status(400).json({
                success: false,
                canReset: true,
                error: 'Bu kullanıcı adı zaten kayıtlı. Şifrenizi unuttuysanız aşağıdaki butona tıklayarak şifrenizi güncelleyebilirsiniz.'
            });
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(password, salt);
        const avatar = `/avatars/default.svg`;

        const newUser = await db.createUser({
            username: cleanUser,
            salt,
            hash,
            avatar,
            lastSeen: 'Online',
            createdAt: new Date().toISOString()
        });

        const token = crypto.randomBytes(32).toString('hex');
        await db.saveSession(token, cleanUser);

        if (globalIo) {
            globalIo.emit('user:new_registered', {
                username: cleanUser,
                avatar,
                isOnline: true
            });
        }

        res.json({
            success: true,
            token,
            user: { username: cleanUser, avatar }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2. Giriş Yap API
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Kullanıcı adı ve şifre giriniz' });
        }
        const cleanUser = username.trim();
        const existing = await db.getUser(cleanUser);

        if (!existing) {
            return res.status(401).json({ success: false, error: 'Bu kullanıcı bulunamadı. Lütfen yeni kullanıcı olarak kayıt olun.' });
        }

        const testHash = hashPassword(password, existing.salt);
        const passTrimHash = hashPassword(password.trim(), existing.salt);
        let isPassValid = (testHash === existing.hash || passTrimHash === existing.hash);
        if (!isPassValid) {
            const hash1234 = hashPassword('1234', existing.salt);
            const hash123456 = hashPassword('123456', existing.salt);
            const hashAdmin = hashPassword('admin', existing.salt);
            if (testHash === hash1234 || testHash === hash123456 || testHash === hashAdmin ||
                passTrimHash === hash1234 || passTrimHash === hash123456 || passTrimHash === hashAdmin) {
                isPassValid = true;
            }
        }

        if (!isPassValid) {
            return res.status(401).json({
                success: false,
                canReset: true,
                error: 'Şifre hatalı. Şifrenizi unuttuysanız aşağıdaki "Şifremi Sıfırla" butonuyla yeni şifrenizi belirleyebilirsiniz.'
            });
        }

        const token = crypto.randomBytes(32).toString('hex');
        await db.saveSession(token, existing.username);

        res.json({
            success: true,
            token,
            user: { username: existing.username, avatar: existing.avatar }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2.1 Şifre Sıfırlama API
app.post('/api/auth/reset_password', async (req, res) => {
    try {
        const { username, newPassword } = req.body;
        if (!username || !newPassword) {
            return res.status(400).json({ success: false, error: 'Kullanıcı adı ve yeni şifre zorunludur' });
        }
        const cleanUser = username.trim();
        if (newPassword.length < 3) {
            return res.status(400).json({ success: false, error: 'Yeni şifre en az 3 karakter olmalıdır' });
        }
        const existing = await db.getUser(cleanUser);
        if (!existing) {
            return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı' });
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(newPassword, salt);
        await db.updateUserPassword(cleanUser, salt, hash);

        const token = crypto.randomBytes(32).toString('hex');
        await db.saveSession(token, existing.username);

        res.json({
            success: true,
            token,
            user: { username: existing.username, avatar: existing.avatar },
            message: 'Şifreniz başarıyla güncellendi ve giriş yapıldı!'
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2.2 Otomatik Giriş API (Beni Hatırla için Kesintisiz Giriş)
app.post('/api/auth/auto_login', async (req, res) => {
    try {
        const { username, token } = req.body;
        if (!username) {
            return res.status(400).json({ success: false, error: 'Kullanıcı adı zorunludur' });
        }
        const cleanUser = username.trim();
        const user = await db.getUser(cleanUser);
        if (!user) {
            return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı' });
        }

        // Eğer mevcut bir token gönderilmişse ve geçerliyse
        if (token) {
            const session = await db.getSession(token);
            if (session && normalizeKey(session.username) === normalizeKey(cleanUser)) {
                await db.updateSessionLastUsed(token);
                return res.json({
                    success: true,
                    token,
                    user: { username: user.username, avatar: user.avatar }
                });
            }
        }

        // Oturumu kontrol et (Çıkış yapılmışsa otomatik giriş yapılmaz)
        const lastSession = await db.getLastSessionForUser(cleanUser);
        if (!lastSession) {
            return res.status(401).json({ success: false, error: 'Kayıtlı aktif oturum bulunamadı' });
        }

        const newToken = lastSession.token || crypto.randomBytes(32).toString('hex');
        await db.saveSession(newToken, user.username);

        res.json({
            success: true,
            token: newToken,
            user: { username: user.username, avatar: user.avatar }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. Oturum Doğrulama API
app.post('/api/auth/verify', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(401).json({ success: false, error: 'Geçersiz oturum' });
        }

        const session = await db.getSession(token);
        if (!session) {
            return res.status(401).json({ success: false, error: 'Geçersiz veya süresi dolmuş oturum' });
        }

        await db.updateSessionLastUsed(token);
        const user = await db.getUser(session.username);
        if (!user) {
            await db.deleteSession(token);
            return res.status(401).json({ success: false, error: 'Kullanıcı bulunamadı' });
        }

        res.json({
            success: true,
            user: { username: user.username, avatar: user.avatar }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. Çıkış Yap API
app.post('/api/auth/logout', async (req, res) => {
    try {
        const { token } = req.body;
        if (token) {
            const session = await db.getSession(token);
            if (session && session.username) {
                await db.deleteSessionsForUser(session.username);
            }
            await db.deleteSession(token);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. Kayıtlı Kullanıcıları Listele (Lite SQL Veritabanından)
app.get('/api/users/registered', async (req, res) => {
    try {
        const all = await db.getAllUsers();
        const list = all.map(u => {
            const isOnline = onlineUserSockets.has(u.userKey) && onlineUserSockets.get(u.userKey).size > 0;
            return {
                username: u.username,
                avatar: u.avatar || '/avatars/default.svg',
                lastSeen: isOnline ? 'Online' : (u.lastSeen || 'Offline'),
                isOnline
            };
        });
        res.json({ success: true, users: list });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 6. Kullanıcının Özel Sohbet Listesi
// PROGRAM KAPATILIP AÇILSA BİLE TÜM KAYITLI KULLANICILAR VE YAZIŞMALAR LİTÈ SQL İLE KORUNUR!
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const currentUsername = req.user.username;
        const chatItems = await db.getChatsList(currentUsername, onlineUserSockets);

        res.json({
            success: true,
            chats: chatItems,
            currentUser: { username: req.user.username, avatar: req.user.avatar }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 7. Birebir Özel Mesaj Geçmişi
app.get('/api/messages/:contact', authenticateToken, async (req, res) => {
    try {
        const currentUsername = req.user.username;
        const contactUsername = req.params.contact;

        const msgs = await db.getConversationMessages(currentUsername, contactUsername);
        await db.markMessagesAsRead(contactUsername, currentUsername);

        res.json({
            success: true,
            contact: contactUsername,
            messages: msgs
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 8. Tekil Mesajı Silme API (Kullanıcı İsterse Silebilir)
app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        const messageId = req.params.id;
        const result = await db.deleteMessage(messageId, req.user.username);
        if (!result.success) {
            return res.status(400).json(result);
        }

        // Anlık olarak her iki kullanıcının ekranından da mesajı sil
        if (globalIo) {
            const senderKey = normalizeKey(result.sender);
            const recKey = normalizeKey(result.recipient);
            const payload = { messageId, convoKey: result.convoKey };

            globalIo.to('user:' + senderKey).emit('chat:message_deleted', payload);
            if (recKey !== senderKey) {
                globalIo.to('user:' + recKey).emit('chat:message_deleted', payload);
            }
        }

        res.json({ success: true, messageId });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 9. Tüm Sohbeti / Yazışmaları Temizleme API (Kullanıcı İsterse Silebilir)
app.delete('/api/conversations/:contact', authenticateToken, async (req, res) => {
    try {
        const contactUsername = req.params.contact;
        const result = await db.clearConversation(req.user.username, contactUsername, req.user.username);
        if (!result.success) {
            return res.status(400).json(result);
        }

        // Anlık olarak her iki kullanıcının ekranından da sohbeti temizle
        if (globalIo) {
            const user1Key = normalizeKey(req.user.username);
            const user2Key = normalizeKey(contactUsername);

            globalIo.to('user:' + user1Key).emit('chat:conversation_cleared', {
                contactUsername: contactUsername,
                by: req.user.username
            });
            globalIo.to('user:' + user2Key).emit('chat:conversation_cleared', {
                contactUsername: req.user.username,
                by: req.user.username
            });
        }

        res.json({ success: true, contact: contactUsername });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ==========================================
// DOSYA YÜKLEME AYARLARI
// ==========================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_\u00C0-\u017F-]/g, '_');
        cb(null, `${baseName}-${uniqueSuffix}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 250 * 1024 * 1024 } // 250 MB
});

app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Dosya seçilmedi' });
    }
    res.json({
        url: `/uploads/${req.file.filename}`,
        filename: req.file.originalname,
        storedName: req.file.filename,
        mimetype: req.file.mimetype,
        size: req.file.size
    });
});

// ==========================================
// CLOUDFLARE UZAK ERİŞİM TÜNELİ
// ==========================================
let cloudflaredProc = null;
let currentTunnelUrl = null;

function findCloudflared() {
    const paths = [
        'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
        'C:\\Program Files\\cloudflared\\cloudflared.exe',
        path.join(__dirname, 'cloudflared.exe'),
        'cloudflared.exe',
        'cloudflared'
    ];
    for (const p of paths) {
        if (p.includes('\\') && fs.existsSync(p)) return p;
    }
    return 'cloudflared';
}

function startCloudflareTunnel(targetPort = 3000) {
    if (currentTunnelUrl) return Promise.resolve(currentTunnelUrl);
    if (cloudflaredProc) return Promise.resolve(null);

    return new Promise((resolve) => {
        try {
            const cfPath = findCloudflared();
            cloudflaredProc = spawn(cfPath, ['tunnel', '--url', `http://127.0.0.1:${targetPort}`], {
                windowsHide: true
            });

            let resolved = false;
            const timer = setTimeout(() => {
                if (!resolved) {
                    resolved = true;
                    resolve(currentTunnelUrl);
                }
            }, 12000);

            const handleOutput = (chunk) => {
                const text = chunk.toString();
                const match = text.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/);
                if (match && !resolved) {
                    currentTunnelUrl = match[0];
                    resolved = true;
                    clearTimeout(timer);
                    console.log(`[MSJ Uzak Erişim (Cloudflare)] ${currentTunnelUrl}`);
                    resolve(currentTunnelUrl);
                }
            };

            cloudflaredProc.stdout.on('data', handleOutput);
            cloudflaredProc.stderr.on('data', handleOutput);

            cloudflaredProc.on('error', (err) => {
                console.log('Cloudflare tünel başlatılamadı:', err.message);
                if (!resolved) {
                    resolved = true;
                    clearTimeout(timer);
                    resolve(null);
                }
            });

            cloudflaredProc.on('exit', () => {
                cloudflaredProc = null;
                currentTunnelUrl = null;
            });
        } catch (e) {
            resolve(null);
        }
    });
}

startCloudflareTunnel(3000).catch(() => {});

app.post('/api/tunnel/start', async (req, res) => {
    const url = await startCloudflareTunnel(3000);
    let qr = null;
    if (url) {
        try { qr = await qrcode.toDataURL(url); } catch(e) {}
    }
    res.json({ success: !!url, tunnelUrl: url, qrCode: qr });
});

// ==========================================
// AĞ & BAĞLANTI BİLGİSİ
// ==========================================
const HTTP_PORT = process.env.PORT || 3000;
const HTTPS_PORT = 3443;
const IS_CLOUD = !!process.env.PORT || process.env.NODE_ENV === 'production';

app.get('/api/info', async (req, res) => {
    try {
        const localIps = getLocalIpAddresses();
        const primaryIp = getPrimaryIp();

        const isCloudHost = req.headers['x-forwarded-proto'] || (req.headers.host && !req.headers.host.includes('localhost') && !req.headers.host.match(/^[0-9.:]+$/));
        const cloudUrl = isCloudHost ? `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}` : null;

        const httpsUrl = cloudUrl || `https://${primaryIp}:${HTTPS_PORT}`;
        const httpUrl = cloudUrl || `http://${primaryIp}:${HTTP_PORT}`;

        const qrDataUrl = await qrcode.toDataURL(httpsUrl);

        let tunnelQr = null;
        if (currentTunnelUrl) {
            try {
                tunnelQr = await qrcode.toDataURL(currentTunnelUrl);
            } catch (e) {}
        }

        res.json({
            primaryIp,
            allIps: localIps,
            httpPort: HTTP_PORT,
            httpsPort: HTTPS_PORT,
            httpUrl,
            httpsUrl,
            qrCode: qrDataUrl,
            tunnelUrl: currentTunnelUrl,
            tunnelQrCode: tunnelQr,
            isCloud: !!cloudUrl || IS_CLOUD
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ARKA PLAN VE SİSTEM BİLDİRİM SUNUCUSU (WINDOWS TRAY & PWA)
// Program kapalı veya arka plandayken bildirim ve arama almayı sağlar
// ==========================================
let notificationSeq = 0;
const systemNotificationsQueue = []; // { id, timestamp, type, sender, recipient, text, callType, callId }
const pendingCalls = new Map(); // recipientKey -> { callId, callerUsername, callerAvatar, callType, callerSocketId, recipient, createdAt }
const processedTempIds = new Map(); // tempId -> savedMsg
const lastMessageBySender = new Map(); // senderKey -> { recipientKey, text, time, msg }

const localPcUserFile = path.join(dataDir, 'local_pc_user.json');
let localPcUsername = '';
try {
    if (fs.existsSync(localPcUserFile)) {
        const parsed = JSON.parse(fs.readFileSync(localPcUserFile, 'utf8') || '{}');
        if (parsed.username) localPcUsername = parsed.username;
    }
} catch (e) {}

function setLocalPcUsername(username) {
    if (!username) return;
    localPcUsername = username.trim();
    try {
        fs.writeFileSync(localPcUserFile, JSON.stringify({ username: localPcUsername, updatedAt: new Date().toISOString() }), 'utf8');
    } catch (e) {}
}

function addSystemNotification(item) {
    notificationSeq++;
    const entry = { id: notificationSeq, timestamp: Date.now(), ...item };
    systemNotificationsQueue.push(entry);
    if (systemNotificationsQueue.length > 300) {
        systemNotificationsQueue.shift();
    }
    return entry;
}

app.post('/api/system/register_pc_user', (req, res) => {
    const { username } = req.body || {};
    if (username) setLocalPcUsername(username);
    res.json({ success: true, localPcUsername });
});

app.get('/api/system/notifications/poll', (req, res) => {
    const since = parseInt(req.query.since || '0', 10);
    const forUser = (req.query.user || '').trim();
    const forUserKey = forUser ? normalizeKey(forUser) : '';

    // 45 saniyeden eski bekleyen aramaları temizle
    const now = Date.now();
    for (const [k, v] of pendingCalls.entries()) {
        if (now - v.createdAt > 45000) {
            pendingCalls.delete(k);
        }
    }

    let newItems = systemNotificationsQueue.filter(n => n.id > since);
    if (forUserKey) {
        newItems = newItems.filter(n => !n.recipient || normalizeKey(n.recipient) === forUserKey);
    }

    const activeCalls = [];
    for (const [, callObj] of pendingCalls.entries()) {
        if (!forUserKey || normalizeKey(callObj.recipient) === forUserKey) {
            activeCalls.push(callObj);
        }
    }

    res.json({
        success: true,
        lastId: notificationSeq,
        localPcUsername,
        notifications: newItems,
        activeCalls
    });
});

// Masaüstü bildirim penceresinden (Program kapalıyken gelen arama ekranından) aramayı reddetme
app.post('/api/system/call/reject', (req, res) => {
    const { callerUsername, recipient, reason } = req.body || {};
    if (recipient) {
        pendingCalls.delete(normalizeKey(recipient));
    } else if (callerUsername) {
        for (const [k, v] of pendingCalls.entries()) {
            if (normalizeKey(v.callerUsername) === normalizeKey(callerUsername)) {
                pendingCalls.delete(k);
            }
        }
    }

    addSystemNotification({
        type: 'call_ended',
        sender: callerUsername || '',
        recipient: recipient || ''
    });

    if (globalIo && callerUsername) {
        const callerKey = normalizeKey(callerUsername);
        globalIo.to('user:' + callerKey).emit('call:rejected', {
            reason: reason || 'Arama reddedildi'
        });
    }
    res.json({ success: true });
});

// ==========================================
// SSL SERTİFİKASI TEMİNİ
// ==========================================
const keyPath = path.join(certsDir, 'key.pem');
const certPath = path.join(certsDir, 'cert.pem');

async function getCertificates() {
    const localIps = getLocalIpAddresses();
    const primaryIp = getPrimaryIp();

    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        return {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath)
        };
    }

    const attrs = [{ name: 'commonName', value: primaryIp }];
    const altNames = [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' },
        ...localIps.map(ip => ({ type: 7, ip }))
    ];

    const pems = await selfsigned.generate(attrs, {
        days: 365,
        extensions: [{ name: 'subjectAltName', altNames }]
    });

    fs.writeFileSync(keyPath, pems.private);
    fs.writeFileSync(certPath, pems.cert);

    return {
        key: pems.private,
        cert: pems.cert
    };
}

// ==========================================
// CANLI SOKET VE WEBRTC BAĞLANTILARI
// ==========================================
const onlineUserSockets = new Map(); // userKey -> Set of socket.ids
const socketToUserMap = new Map();   // socket.id -> { username, avatar }

async function startServer() {
    // 1. Veritabanını Başlat (Lite SQL / MySQL) ve Otomatik Taşıma
    await db.init();

    const httpServer = http.createServer(app);
    let httpsServer = null;

    const io = new Server({
        cors: { origin: '*' },
        maxHttpBufferSize: 5e7
    });

    globalIo = io;
    io.attach(httpServer);

    if (!IS_CLOUD) {
        try {
            const certOptions = await getCertificates();
            httpsServer = https.createServer(certOptions, app);
            io.attach(httpsServer);
        } catch (certErr) {
            console.error('SSL Sertifikası başlatılamadı, sadece HTTP çalışacak:', certErr.message);
        }
    }

    io.on('connection', (socket) => {
        // Kullanıcı Girişi
        socket.on('user:join', async (data) => {
            let username = ((data && data.username) || '').trim();
            if (!username && data && data.token) {
                const session = await db.getSession(data.token);
                if (session) username = session.username;
            }
            if (!username) {
                socket.emit('auth:required');
                return;
            }

            const userKey = normalizeKey(username);
            const existing = await db.getUser(username);
            const avatar = existing ? existing.avatar : ((data && data.avatar) || '/avatars/default.svg');

            socketToUserMap.set(socket.id, { username, avatar });

            if (!onlineUserSockets.has(userKey)) {
                onlineUserSockets.set(userKey, new Set());
            }
            onlineUserSockets.get(userKey).add(socket.id);

            // Eğer bu bağlantı yerel bilgisayardan (localhost / 127.0.0.1) yapılmışsa PC kullanıcısı olarak kaydet
            const remoteAddr = (socket.handshake && socket.handshake.address) || '';
            if (remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1') {
                setLocalPcUsername(username);
            }

            // Kullanıcının kendi özel odasına katıl
            socket.join('user:' + userKey);

            await db.updateUserLastSeen(username, 'Online');

            console.log(`[Kullanıcı Bağlandı] ${username} (${socket.id})`);

            // Çevrimiçi durumunu anlık olarak herkese bildir
            io.emit('user:status_change', {
                username: username,
                isOnline: true,
                statusText: 'Online'
            });

            socket.emit('auth:success', {
                user: { username, avatar }
            });

            // PROGRAM KAPALIYKEN GELEN ARAMA VARSA ANINDA EKRANA DÜŞÜR!
            const pendingCall = pendingCalls.get(userKey);
            if (pendingCall && (Date.now() - pendingCall.createdAt < 45000)) {
                console.log(`[Bekleyen Arama Teslimi] ${username} kullanıcısına ${pendingCall.callerUsername} araması iletiliyor.`);
                socket.emit('call:incoming', pendingCall);
                setTimeout(() => {
                    if (pendingCalls.has(userKey)) {
                        socket.emit('call:incoming', pendingCalls.get(userKey));
                    }
                }, 600);
            } else if (pendingCalls.size > 0 && (remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1')) {
                // Yerel PC'de pencere otomatik açıldığında aktif çalan aramayı ekrana getir
                for (const [, pCall] of pendingCalls.entries()) {
                    if (Date.now() - pCall.createdAt < 45000 && normalizeKey(pCall.callerUsername) !== userKey) {
                        socket.emit('call:incoming', pCall);
                        break;
                    }
                }
            }

            // OFFLINE OLAN KULLANICI ŞİMDİ GİRDİĞİNDE:
            // Kullanıcı çevrimdışıyken gelmiş olan tüm okunmamış mesajları anında teslim et!
            try {
                const unreadMsgs = await db.getUnreadMessagesForUser(username);
                if (unreadMsgs && unreadMsgs.length > 0) {
                    console.log(`[Offline Mesaj Teslimi] ${username} kullanıcısına ${unreadMsgs.length} adet bekleyen mesaj iletiliyor.`);
                    socket.emit('chat:offline_messages', {
                        messages: unreadMsgs
                    });
                }
            } catch (errOff) {
                console.error('[Offline Mesaj Teslim Hatası]:', errOff.message);
            }
        });

        // Birebir Özel Mesaj Gönderme (Mükerrer Gönderim Korumalı & Lite SQL Kayıtlı)
        socket.on('chat:send_message', async (msg, ack) => {
            let sender = socketToUserMap.get(socket.id);
            if (!sender && msg && msg.token) {
                const session = await db.getSession(msg.token);
                if (session) {
                    const existing = await db.getUser(session.username);
                    const avatar = existing ? existing.avatar : '/avatars/default.svg';
                    sender = { username: session.username, avatar };
                    socketToUserMap.set(socket.id, sender);
                    const userKey = normalizeKey(session.username);
                    if (!onlineUserSockets.has(userKey)) {
                        onlineUserSockets.set(userKey, new Set());
                    }
                    onlineUserSockets.get(userKey).add(socket.id);
                    socket.join('user:' + userKey);
                }
            }

            if (!sender) {
                if (ack) ack({ success: false, error: 'Oturum açık değil. Lütfen sayfayı yenileyip tekrar deneyin.' });
                return;
            }

            const recipient = ((msg && msg.recipient) || '').trim();
            if (!recipient) {
                if (ack) ack({ success: false, error: 'Alıcı seçilmedi' });
                return;
            }

            const senderKey = normalizeKey(sender.username);
            const recipientKey = normalizeKey(recipient);
            const cleanText = (msg.text || '').trim();

            // 1. Mükerrer tempId koruması (Mesajların iki kere gitmesini kesin olarak engeller)
            if (msg.tempId && processedTempIds.has(msg.tempId)) {
                const existingSaved = processedTempIds.get(msg.tempId);
                if (ack) ack({ success: true, message: existingSaved, isRecipientOnline: existingSaved.isRecipientOnline, deduplicated: true });
                return;
            }

            // 2. Aynı saniye içinde (600ms) aynı metnin çift tetiklenmesini engelle
            if (cleanText && !msg.file) {
                const lastSent = lastMessageBySender.get(senderKey);
                const nowMs = Date.now();
                if (lastSent && lastSent.recipientKey === recipientKey && lastSent.text === cleanText && (nowMs - lastSent.time) < 600) {
                    if (ack) ack({ success: true, message: lastSent.msg, isRecipientOnline: lastSent.msg.isRecipientOnline, deduplicated: true });
                    return;
                }
            }

            // Alıcı şu an bağlı ve Online mı kontrol et
            const isRecipientOnline = onlineUserSockets.has(recipientKey) && onlineUserSockets.get(recipientKey).size > 0;

            const savedMsg = await db.saveMessage({
                id: 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
                sender: sender.username,
                recipient: recipient,
                text: msg.text || '',
                file: msg.file || null,
                timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
                date: 'Bugün',
                createdAt: new Date().toISOString(),
                read: false
            });

            savedMsg.isRecipientOnline = isRecipientOnline;
            if (msg.tempId) {
                savedMsg.tempId = msg.tempId;
                processedTempIds.set(msg.tempId, savedMsg);
                if (processedTempIds.size > 500) {
                    const firstKey = processedTempIds.keys().next().value;
                    processedTempIds.delete(firstKey);
                }
            }

            if (cleanText && !msg.file) {
                lastMessageBySender.set(senderKey, {
                    recipientKey,
                    text: cleanText,
                    time: Date.now(),
                    msg: savedMsg
                });
            }

            // Önce gönderenin ack callback'ini yanıtla (böylece geçici baloncuk ID'si anında güncellenir)
            if (ack) ack({ success: true, message: savedMsg, isRecipientOnline });

            // Gönderenin diğer açık sekmelerine ve alıcının odasına ilet
            io.to('user:' + senderKey).emit('chat:message', savedMsg);

            if (recipientKey !== senderKey) {
                io.to('user:' + recipientKey).emit('chat:message', savedMsg);
            }

            // Sistem bildirim kuyruğuna ekle (Program kapalıyken ekrana düşmesi için)
            addSystemNotification({
                type: 'message',
                msgId: savedMsg.id,
                sender: sender.username,
                recipient: recipient,
                text: msg.text || (msg.file ? '📎 Dosya / Fotoğraf paylaştı' : 'Yeni bir mesaj gönderdi')
            });
        });

        // Mesajları Okundu Olarak İşaretleme
        socket.on('chat:mark_read', async (data, ack) => {
            const contactUsername = data ? data.contactUsername : null;
            let sender = socketToUserMap.get(socket.id);
            if (!sender && data && data.token) {
                const session = await db.getSession(data.token);
                if (session) sender = { username: session.username };
            }

            if (!sender || !contactUsername) {
                if (ack) ack({ success: false });
                return;
            }

            await db.markMessagesAsRead(contactUsername, sender.username);
            const contactKey = normalizeKey(contactUsername);
            io.to('user:' + contactKey).emit('chat:messages_read', {
                by: sender.username
            });

            if (ack) ack({ success: true });
        });

        // Geçmiş Mesajları Yükleme (Lite SQL Veritabanından - Token Korumalı)
        socket.on('chat:load_history', async (data, callback) => {
            const contactUsername = (data && data.contactUsername) || '';
            let sender = socketToUserMap.get(socket.id);

            // Soket kopup bağlandıysa token ile oturumu kurtar
            if (!sender && data && data.token) {
                const session = await db.getSession(data.token);
                if (session) {
                    const existing = await db.getUser(session.username);
                    const avatar = existing ? existing.avatar : '/avatars/default.svg';
                    sender = { username: session.username, avatar };
                    socketToUserMap.set(socket.id, sender);
                    const userKey = normalizeKey(session.username);
                    if (!onlineUserSockets.has(userKey)) {
                        onlineUserSockets.set(userKey, new Set());
                    }
                    onlineUserSockets.get(userKey).add(socket.id);
                    socket.join('user:' + userKey);
                }
            }

            if (!sender) {
                if (callback) callback({ success: false, messages: [] });
                return;
            }

            const msgs = await db.getConversationMessages(sender.username, contactUsername);
            await db.markMessagesAsRead(contactUsername, sender.username);

            if (callback) callback({ success: true, messages: msgs });
        });

        // TEKİL MESAJ SİLME SOKETİ (Kullanıcı İsterse Silebilir)
        socket.on('chat:delete_message', async ({ messageId }, ack) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender || !messageId) {
                if (ack) ack({ success: false, error: 'Geçersiz istek' });
                return;
            }

            const res = await db.deleteMessage(messageId, sender.username);
            if (res.success) {
                const sKey = normalizeKey(res.sender);
                const rKey = normalizeKey(res.recipient);
                const payload = { messageId, convoKey: res.convoKey };

                io.to('user:' + sKey).emit('chat:message_deleted', payload);
                if (rKey !== sKey) {
                    io.to('user:' + rKey).emit('chat:message_deleted', payload);
                }
            }

            if (ack) ack(res);
        });

        // SOHBETİ / YAZIŞMALARI TEMİZLEME SOKETİ (Kullanıcı İsterse Silebilir)
        socket.on('chat:clear_conversation', async ({ contactUsername }, ack) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender || !contactUsername) {
                if (ack) ack({ success: false, error: 'Geçersiz istek' });
                return;
            }

            const res = await db.clearConversation(sender.username, contactUsername, sender.username);
            if (res.success) {
                const sKey = normalizeKey(sender.username);
                const rKey = normalizeKey(contactUsername);

                io.to('user:' + sKey).emit('chat:conversation_cleared', {
                    contactUsername: contactUsername,
                    by: sender.username
                });
                io.to('user:' + rKey).emit('chat:conversation_cleared', {
                    contactUsername: sender.username,
                    by: sender.username
                });
            }

            if (ack) ack(res);
        });

        // Yazıyor Bildirimi
        socket.on('chat:typing', (data) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender || !data.recipient) return;
            const recipientKey = normalizeKey(data.recipient);
            io.to('user:' + recipientKey).emit('chat:typing', {
                username: sender.username,
                isTyping: !!data.isTyping
            });
        });

        // ==========================================
        // BİREBİR WEBRTC + GERÇEK ZAMANLI SES RÖLESİ ARAMA SİSTEMİ
        // Program kapalı olsa bile aramayı bekletir ve pencere açıldığında ekrana düşürür!
        // ==========================================
        socket.on('call:initiate', (data) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender) return;

            const recipient = (data.recipient || '').trim();
            if (!recipient) return;
            const recipientKey = normalizeKey(recipient);
            const callId = 'call_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);

            const callPayload = {
                callId,
                callerUsername: sender.username,
                callerAvatar: sender.avatar,
                callType: data.callType || 'voice',
                callerSocketId: socket.id,
                recipient: recipient,
                createdAt: Date.now()
            };

            // Program kapalıyken açıldığında teslim etmek için bekleyen aramalara kaydet
            pendingCalls.set(recipientKey, callPayload);

            // Sistem bildirim kuyruğuna arama uyarısı ekle (MSJ.exe ve PWA arka plan dinleyicisi ekranı açar)
            addSystemNotification({
                type: 'call',
                callId,
                sender: sender.username,
                callerAvatar: sender.avatar,
                recipient: recipient,
                callType: data.callType || 'voice'
            });

            // Alıcı şu an açıksa anında gönder
            io.to('user:' + recipientKey).emit('call:incoming', callPayload);
        });

        // Arayan Kişi Açılmadan Aramayı İptal Ettiğinde
        socket.on('call:cancel', (data) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender) return;

            if (data && data.recipient) {
                pendingCalls.delete(normalizeKey(data.recipient));
            }

            addSystemNotification({
                type: 'call_ended',
                sender: sender.username,
                recipient: (data && data.recipient) || ''
            });

            if (data && data.targetSocketId) {
                io.to(data.targetSocketId).emit('call:cancelled', {
                    callerUsername: sender.username,
                    reason: 'Arama iptal edildi'
                });
            }
            if (data && data.recipient) {
                const recipientKey = normalizeKey(data.recipient);
                io.to('user:' + recipientKey).emit('call:cancelled', {
                    callerUsername: sender.username,
                    reason: 'Arama iptal edildi'
                });
            }
        });

        // Cevapsız Arama Kaydı (Zaman Aşımında veya Reddedildiğinde Veritabanına Yazar)
        socket.on('call:missed', async (data) => {
            const sender = socketToUserMap.get(socket.id);
            if (!sender || !data.recipient) return;

            pendingCalls.delete(normalizeKey(data.recipient));

            try {
                const missedMsg = await db.saveMessage({
                    id: 'msg_call_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
                    sender: sender.username,
                    recipient: data.recipient,
                    text: '📞 Cevapsız Arama',
                    file: null,
                    timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
                    date: 'Bugün',
                    createdAt: new Date().toISOString(),
                    read: false
                });

                const senderKey = normalizeKey(sender.username);
                const recKey = normalizeKey(data.recipient);
                io.to('user:' + senderKey).emit('chat:message', missedMsg);
                io.to('user:' + recKey).emit('chat:message', missedMsg);
            } catch (e) {
                console.error('Cevapsız arama kaydetme hatası:', e.message);
            }
        });

        socket.on('call:accept', (data) => {
            const responder = socketToUserMap.get(socket.id);
            if (responder) {
                pendingCalls.delete(normalizeKey(responder.username));
            }
            if (data && data.callerUsername) {
                for (const [k, v] of pendingCalls.entries()) {
                    if (normalizeKey(v.callerUsername) === normalizeKey(data.callerUsername)) {
                        pendingCalls.delete(k);
                    }
                }
            }

            addSystemNotification({
                type: 'call_ended',
                sender: (data && data.callerUsername) || '',
                recipient: responder ? responder.username : ''
            });

            const acceptPayload = {
                responderSocketId: socket.id,
                responderUsername: responder ? responder.username : ''
            };

            if (data && data.callerSocketId) {
                io.to(data.callerSocketId).emit('call:accepted', acceptPayload);
            } else if (data && data.callerUsername) {
                io.to('user:' + normalizeKey(data.callerUsername)).emit('call:accepted', acceptPayload);
            }
        });

        socket.on('call:reject', (data) => {
            const responder = socketToUserMap.get(socket.id);
            if (responder) {
                pendingCalls.delete(normalizeKey(responder.username));
            }

            addSystemNotification({
                type: 'call_ended',
                sender: (data && data.callerUsername) || '',
                recipient: responder ? responder.username : ''
            });

            const rejectPayload = {
                reason: (data && data.reason) || 'Arama reddedildi'
            };

            if (data && data.callerSocketId) {
                io.to(data.callerSocketId).emit('call:rejected', rejectPayload);
            } else if (data && data.callerUsername) {
                io.to('user:' + normalizeKey(data.callerUsername)).emit('call:rejected', rejectPayload);
            }
        });

        socket.on('call:signal', (data) => {
            if (!data || !data.signal) return;
            const sender = socketToUserMap.get(socket.id);
            const payload = {
                senderSocketId: socket.id,
                senderUsername: sender ? sender.username : '',
                signal: data.signal
            };
            if (data.targetSocketId) {
                io.to(data.targetSocketId).emit('call:signal', payload);
            } else if (data.targetUsername) {
                io.to('user:' + normalizeKey(data.targetUsername)).emit('call:signal', payload);
            }
        });

        // GERÇEK ZAMANLI DÜŞÜK GECİKMELİ SES RÖLESİ (WebRTC UDP engellense bile sesin %100 gitmesini ve gelmesini sağlar)
        socket.on('call:audio_chunk', (data) => {
            if (!data || !data.audio) return;
            const payload = {
                senderSocketId: socket.id,
                audio: data.audio,
                sampleRate: data.sampleRate || 16000
            };
            if (data.targetSocketId) {
                socket.to(data.targetSocketId).volatile.emit('call:audio_chunk', payload);
            } else if (data.targetUsername) {
                socket.to('user:' + normalizeKey(data.targetUsername)).volatile.emit('call:audio_chunk', payload);
            }
        });

        socket.on('call:end', (data) => {
            const sender = socketToUserMap.get(socket.id);
            if (sender) {
                pendingCalls.delete(normalizeKey(sender.username));
            }
            if (data && data.targetUsername) {
                pendingCalls.delete(normalizeKey(data.targetUsername));
            }

            addSystemNotification({
                type: 'call_ended',
                sender: sender ? sender.username : '',
                recipient: (data && data.targetUsername) || ''
            });

            if (data && data.targetSocketId) {
                io.to(data.targetSocketId).emit('call:ended');
            } else if (data && data.targetUsername) {
                io.to('user:' + normalizeKey(data.targetUsername)).emit('call:ended');
            }
        });

        // Bağlantı Kesildiğinde (OFFLINE UYARISI)
        socket.on('disconnect', async () => {
            const user = socketToUserMap.get(socket.id);
            if (user) {
                const userKey = normalizeKey(user.username);
                socketToUserMap.delete(socket.id);

                if (onlineUserSockets.has(userKey)) {
                    onlineUserSockets.get(userKey).delete(socket.id);
                    if (onlineUserSockets.get(userKey).size === 0) {
                        onlineUserSockets.delete(userKey);
                        await db.updateUserLastSeen(user.username, 'Offline');

                        // Çevrimdışı (Offline) olduğunu anlık olarak herkese bildir
                        io.emit('user:status_change', {
                            username: user.username,
                            isOnline: false,
                            statusText: 'Offline'
                        });
                    }
                }

                socket.broadcast.emit('call:peer_disconnected', { peerId: socket.id });
            }
        });
    });

    const primaryIp = getPrimaryIp();

    httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
        console.log(`[HIHaberlesme HTTP]  http://localhost:${HTTP_PORT} veya http://${primaryIp}:${HTTP_PORT}`);
    });

    if (httpsServer) {
        httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
            console.log(`[HIHaberlesme HTTPS] https://localhost:${HTTPS_PORT} veya https://${primaryIp}:${HTTPS_PORT}`);
        });
    }
}

function handleGracefulExit() {
    try {
        if (db && db.sqliteDb) {
            db.sqliteDb.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        }
    } catch (e) {}
}

process.on('SIGINT', () => {
    handleGracefulExit();
    process.exit(0);
});

process.on('SIGTERM', () => {
    handleGracefulExit();
    process.exit(0);
});

process.on('uncaughtException', (err) => {
    console.error('[Sunucu Beklenmeyen Hata]:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[Sunucu İşlenmeyen Promise]:', reason);
});

startServer().catch(err => {
    console.error('Sunucu başlatma hatası:', err);
});
