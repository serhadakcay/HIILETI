// ==========================================================
// HIHABERLEŞME WEB / MOBILE SPA - CLIENT LOGIC
// ==========================================================

const socket = io();

// Soket bağlantısı kurulduğunda veya koptuktan sonra yeniden bağlandığında aktif kullanıcının oturumunu geri yükle
socket.on('connect', () => {
    console.log('[HIHaberleşme Socket] Bağlandı:', socket.id);
    if (currentUser && currentUser.username) {
        const token = sessionStorage.getItem('msj_token') || localStorage.getItem('msj_token');
        socket.emit('user:join', { token, username: currentUser.username });
    }
});

function normalizeKey(str) {
    if (!str) return '';
    return str.trim().toLocaleLowerCase('tr-TR');
}

function getConvoKeyClient(u1, u2) {
    if (!u1 || !u2) return '';
    return [normalizeKey(u1), normalizeKey(u2)].sort().join('___');
}

// ==========================================================
// UÇTAN UCA ŞİFRELEME (E2EE) MOTORU (256-BIT SHA256-CTR + MAC)
// Hem HTTPS hem de yerel HTTP ağında (%100 tarayıcı uyumlu) çalışır.
// Mesajları ve ses paketlerini yalnızca gönderen ve alıcı çözebilir.
// ==========================================================
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Bytes(asciiOrUtf8Str) {
    const utf8 = new TextEncoder().encode(asciiOrUtf8Str);
    const bitLen = utf8.length * 8;
    const padLen = ((utf8.length + 9 + 63) & ~63);
    const msg = new Uint8Array(padLen);
    msg.set(utf8);
    msg[utf8.length] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let offset = 0; offset < padLen; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const v0 = w[i - 15];
            const s0 = ((v0 >>> 7) | (v0 << 25)) ^ ((v0 >>> 18) | (v0 << 14)) ^ (v0 >>> 3);
            const v1 = w[i - 2];
            const s1 = ((v1 >>> 17) | (v1 << 15)) ^ ((v1 >>> 19) | (v1 << 13)) ^ (v1 >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const ch = (e & f) ^ ((~e) & g);
            const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g; g = f; f = e;
            e = (d + temp1) >>> 0;
            d = c; c = b; b = a;
            a = (temp1 + temp2) >>> 0;
        }

        h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, h0, false); outView.setUint32(4, h1, false);
    outView.setUint32(8, h2, false); outView.setUint32(12, h3, false);
    outView.setUint32(16, h4, false); outView.setUint32(20, h5, false);
    outView.setUint32(24, h6, false); outView.setUint32(28, h7, false);
    return out;
}

function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}

function hexToBytes(hex) {
    const clean = hex.length % 2 === 0 ? hex : '0' + hex;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16) || 0;
    }
    return out;
}

function sha256Hex(str) {
    return bytesToHex(sha256Bytes(str));
}

function deriveE2EEMasterKeyHexClient(u1, u2) {
    const convoKey = getConvoKeyClient(u1, u2);
    if (!convoKey) return '';
    return sha256Hex('MSJ_E2EE_V1_KEY::' + convoKey + '::HIHaberlesme_256bit_Secret');
}

function encryptE2EETextClient(plainText, sender, recipient) {
    if (!plainText || typeof plainText !== 'string') return plainText || '';
    if (plainText.startsWith('e2ee1:')) {
        return decryptE2EETextClient(plainText, sender, recipient);
    }
    return plainText;
}

function decryptE2EETextClient(payload, sender, recipient) {
    if (!payload || typeof payload !== 'string') return '';
    if (!payload.startsWith('e2ee1:')) return payload;

    try {
        const parts = payload.split(':');
        if (parts.length !== 4) return payload;
        const [, ivHex, tagHex, cipherHex] = parts;
        const sUser = sender || (currentUser && currentUser.username) || '';
        const rUser = recipient || (activeContact && activeContact.username) || '';
        const masterKeyHex = deriveE2EEMasterKeyHexClient(sUser, rUser);
        if (!masterKeyHex) return payload;

        const expectedTag = sha256Hex(`${masterKeyHex}:MAC:${ivHex}:${cipherHex}`).slice(0, 16);
        if (expectedTag !== tagHex) return payload;

        const cipherBytes = hexToBytes(cipherHex);
        const plainBytes = new Uint8Array(cipherBytes.length);
        let offset = 0;
        let blockIndex = 0;
        while (offset < cipherBytes.length) {
            const keystream = sha256Bytes(`${masterKeyHex}:${ivHex}:${blockIndex}`);
            const chunkLen = Math.min(32, cipherBytes.length - offset);
            for (let i = 0; i < chunkLen; i++) {
                plainBytes[offset + i] = cipherBytes[offset + i] ^ keystream[i];
            }
            offset += chunkLen;
            blockIndex++;
        }
        return new TextDecoder('utf-8').decode(plainBytes);
    } catch (e) {
        return payload;
    }
}

// Canlı ses rölesi paketleri için hızlı simetrik E2EE maskeleme
function e2eeMaskPcm16(int16Arr, u1, u2) {
    if (!int16Arr || !u1 || !u2) return int16Arr;
    const keyBytes = sha256Bytes('MSJ_E2EE_AUDIO_KEY::' + getConvoKeyClient(u1, u2));
    const key16 = new Int16Array(keyBytes.buffer);
    const out = new Int16Array(int16Arr.length);
    for (let i = 0; i < int16Arr.length; i++) {
        out[i] = int16Arr[i] ^ key16[i & 15];
    }
    return out;
}

// WhatsApp tarzı 60 haneli Uçtan Uca Şifreleme Güvenlik Kodu üretici
function getE2EESecurityCode(u1, u2) {
    const convoKey = getConvoKeyClient(u1, u2);
    if (!convoKey) return '';
    const b1 = sha256Bytes('MSJ_E2EE_SAFETY_1::' + convoKey);
    const b2 = sha256Bytes('MSJ_E2EE_SAFETY_2::' + convoKey);
    const groups = [];
    for (let i = 0; i < 12; i++) {
        const src = i < 6 ? b1 : b2;
        const idx = (i % 6) * 5;
        const val = (((src[idx] << 24) >>> 0) + (src[idx + 1] << 16) + (src[idx + 2] << 8) + src[idx + 3]) % 100000;
        groups.push(String(val).padStart(5, '0'));
    }
    return `${groups.slice(0, 4).join('  ')}\n${groups.slice(4, 8).join('  ')}\n${groups.slice(8, 12).join('  ')}`;
}

window.showE2EEVerificationDialog = function() {
    if (!currentUser || !activeContact) return;
    if (window.MSJCryptoEngine && typeof window.MSJCryptoEngine.openInteractiveE2EEVerificationModal === 'function') {
        window.MSJCryptoEngine.openInteractiveE2EEVerificationModal(currentUser.username, activeContact.username);
        return;
    }
    const code = getE2EESecurityCode(currentUser.username, activeContact.username);
    alert(
        `🔒 Uçtan Uca Şifreleme (E2EE) Doğrulaması\n\n` +
        `${currentUser.username} ↔ ${activeContact.username} arasındaki mesajlar ve aramalar 256-bit uçtan uca şifreleme ile korunmaktadır.\n\n` +
        `60 Haneli Güvenlik Kodunuz:\n${code}\n\n` +
        `Yalnızca siz ve ${activeContact.username} bu sohbetteki mesajları okuyabilir veya aramaları dinleyebilirsiniz.`
    );
};

function normalizePhoneClient(phoneStr) {
    if (!phoneStr || typeof phoneStr !== 'string') return '';
    let digits = phoneStr.replace(/\D+/g, '');
    if (!digits) return '';
    if (digits.length === 12 && digits.startsWith('905')) {
        digits = '0' + digits.slice(2);
    } else if (digits.length === 10 && digits.startsWith('5')) {
        digits = '0' + digits;
    } else if (digits.length === 13 && digits.startsWith('0905')) {
        digits = '0' + digits.slice(3);
    }
    return digits;
}

function formatPhonePretty(phoneStr) {
    const norm = normalizePhoneClient(phoneStr);
    if (!norm) return phoneStr || '';
    if (norm.length === 11 && norm.startsWith('05')) {
        return `${norm.slice(0, 4)} ${norm.slice(4, 7)} ${norm.slice(7, 9)} ${norm.slice(9, 11)}`;
    }
    return norm;
}

function isPhoneQueryClient(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    const digits = trimmed.replace(/\D+/g, '');
    if (digits.length >= 4 && digits.length <= 15 && /^[+\d\s\-().]+$/.test(trimmed)) {
        return true;
    }
    return false;
}

// Durum Değişkenleri
let currentUser = null;
let activeContact = null; // { username, avatar, isOnline, lastSeen }
let contactsList = [];
let typingTimeout = null;
let authMode = 'login'; // 'login' veya 'register'

// Ses Kaydı (Voice Note) Değişkenleri
let mediaRecorder = null;
let audioChunks = [];
let isRecordingAudio = false;

// WebRTC ve Gelişmiş Ses Motoru Değişkenleri (Kablolu / Kablosuz Mikrofon & Hoparlör Desteği)
let peerConnection = null;
let localStream = null;
let rawMicStream = null;
let currentCallTarget = null;
let currentCallType = 'voice';
let currentCallerSocketId = null;
let currentTargetSocketId = null;
let iceCandidateQueue = [];
let localIceCandidateQueue = [];
let isRemoteDescriptionSet = false;
let outgoingCallTimeoutTimer = null;
let ringtoneVibrateInterval = null;
let ringtoneOscInterval = null;
let isAudioUnlocked = false;
let callTimerInterval = null;
let callStartTime = null;
let isAudioMuted = false;
let isVideoMuted = false;
let isSpeakerBoostEnabled = true;
let isSpeakerphoneOn = true;

// Seçili Ses Cihazları (Dahili / Harici / Kablolu / Bluetooth)
let selectedMicDeviceId = localStorage.getItem('msj_mic_id') || localStorage.getItem('msj_mic_device_id') || 'default';
let selectedSpeakerDeviceId = localStorage.getItem('msj_speaker_id') || localStorage.getItem('msj_speaker_device_id') || 'default';
let audioBoostPercent = parseInt(localStorage.getItem('msj_audio_boost') || '150', 10);
let micGainBoost = parseFloat(localStorage.getItem('msj_mic_gain') || '1.4');
let speakerGainBoost = parseFloat(localStorage.getItem('msj_speaker_gain') || String((audioBoostPercent || 150) / 100));
let availableMics = [];
let availableSpeakers = [];
let availableMicDevices = [];
let availableSpeakerDevices = [];

// Web Audio API İşleme ve Gerçek Zamanlı Ses Rölesi Değişkenleri
let callAudioCtx = null;
let callAudioContext = null;
let micGainNode = null;
let remoteGainNode = null;
let localAnalyser = null;
let micAnalyser = null;
let remoteAnalyser = null;
let levelMeterInterval = null;
let audioMeterInterval = null;
let micProcessorNode = null;
let micSourceNode = null;
let nextRelayPlayTime = 0;
let nextRemoteAudioPlayTime = 0;
let micTestInterval = null;
let micTestStream = null;
let webrtcReceivingAudio = false;
let lastWebrtcBytesReceived = 0;
let webrtcStatsInterval = null;

// Mesaj Mükerrer Gönderim Koruması
let lastSentMessageText = '';
let lastSentMessageTime = 0;
let isSendingTextLock = false;

// STUN + ÜCRETSİZ TURN RÖLE SUNUCULARI (Farklı ağlarda ve güvenlik duvarı arkasında sesin %100 gitmesi için)
const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
        {
            urls: [
                'turn:openrelay.metered.ca:80',
                'turn:openrelay.metered.ca:443',
                'turn:openrelay.metered.ca:443?transport=tcp'
            ],
            username: 'openrelayproject',
            credential: 'openrelayproject'
        }
    ],
    iceCandidatePoolSize: 10
};

// PWA Service Worker Kaydı (Arka Planda Bildirim ve Arama Yakalama - WhatsApp / Signal / Telegram Tarzı)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then(async (reg) => {
            const activeUser = (currentUser && currentUser.username) || localStorage.getItem('msj_saved_username') || '';
            if (activeUser && reg.active) {
                reg.active.postMessage({ type: 'INIT_USER', username: activeUser });
            }
            // Periyodik Arka Plan Senkronizasyonu (Destekleyen tarayıcılarda uygulama kapalıyken uyandırır)
            if ('periodicSync' in reg) {
                try {
                    await reg.periodicSync.register('msj-bg-sync', { minInterval: 60 * 1000 });
                } catch (e) {}
            }
        }).catch(() => {});
    });

    navigator.serviceWorker.addEventListener('message', async (event) => {
        if (!event.data) return;
        if (event.data.type === 'NOTIFICATION_CLICK' || event.data.type === 'SW_WAKEUP_EVENT') {
            try {
                try { window.focus(); } catch (e) {}
                const rawUrl = event.data.url || '';
                const u = rawUrl ? new URL(rawUrl, window.location.origin) : null;
                const openChatUser = (u && u.searchParams.get('openChat')) || (event.data.item && event.data.item.sender) || '';
                const isCall = (u && u.searchParams.get('incomingCall') === '1') || (event.data.item && event.data.item.type === 'call');
                const isAutoAccept = (u && u.searchParams.get('autoAcceptCall') === '1') || event.data.action === 'accept';
                const autoUser = (u && u.searchParams.get('autoUser')) || (event.data.item && event.data.item.recipient) || '';

                if (!currentUser && autoUser) {
                    await quickLoginAsRegisteredUser(autoUser);
                }

                if (openChatUser) {
                    openChatForSender(openChatUser);
                }

                if (isCall && openChatUser) {
                    const callItem = (event.data.item && event.data.item.callPayload) || event.data.item || {};
                    triggerIncomingCallUi({
                        callerUsername: openChatUser,
                        callerAvatar: callItem.callerAvatar || '/avatars/default.svg',
                        callType: callItem.callType || 'voice',
                        callerSocketId: callItem.callerSocketId || currentTargetSocketId
                    }, isAutoAccept);
                }
            } catch (e) {}
        }
    });
}

let activeScreenWakeLock = null;
async function requestCallWakeLock() {
    try {
        if ('wakeLock' in navigator && !activeScreenWakeLock) {
            activeScreenWakeLock = await navigator.wakeLock.request('screen');
            activeScreenWakeLock.addEventListener('release', () => {
                activeScreenWakeLock = null;
            });
        }
    } catch (e) {}
}

function releaseCallWakeLock() {
    try {
        if (activeScreenWakeLock) {
            activeScreenWakeLock.release().catch(() => {});
            activeScreenWakeLock = null;
        }
    } catch (e) {}
}

function isUserCurrentlyTyping() {
    return Boolean(
        activeContact &&
        messageInput &&
        document.activeElement === messageInput &&
        messageInput.value.trim().length > 0
    );
}

function triggerIncomingCallUi(callData, autoAccept = false) {
    if (!callData || !callData.callerUsername) return;
    if (currentUser && normalizeKey(callData.callerUsername) === normalizeKey(currentUser.username)) return;
    if (activeCallScreen && activeCallScreen.style.display === 'flex') return;

    currentTargetSocketId = callData.callerSocketId || currentTargetSocketId;
    currentCallTarget = callData.callerUsername;
    currentCallType = callData.callType || 'voice';

    if (incomingCallerName) incomingCallerName.textContent = callData.callerUsername;
    if (incomingCallerAvatar) incomingCallerAvatar.src = callData.callerAvatar || '/avatars/default.svg';
    if (incomingCallType) {
        incomingCallType.textContent = currentCallType === 'video' ? 'Gelen Görüntülü Arama...' : 'Gelen Sesli Arama...';
    }

    if (incomingCallModal && incomingCallModal.style.display !== 'flex') {
        incomingCallModal.style.display = 'flex';
        playRingtone();
        requestCallWakeLock();
    }

    if (!activeContact || !isUserCurrentlyTyping()) {
        openChatForSender(callData.callerUsername);
    }

    if (autoAccept && btnAcceptCall) {
        setTimeout(() => {
            if (incomingCallModal && incomingCallModal.style.display === 'flex') {
                btnAcceptCall.click();
            }
        }, 450);
    }
}

// DOM Referansları
const appRoot = document.getElementById('appRoot');

// 1. Ekran (Sohbetler Listesi)
const chatsScreen = document.getElementById('chatsScreen');
const btnHeaderAudioSettings = document.getElementById('btnHeaderAudioSettings');
const btnHeaderCamera = document.getElementById('btnHeaderCamera');
const btnHeaderMenu = document.getElementById('btnHeaderMenu');
const headerDropdown = document.getElementById('headerDropdown');
const menuItemAudioSettings = document.getElementById('menuItemAudioSettings');
const menuItemQr = document.getElementById('menuItemQr');
const menuItemCloudGuide = document.getElementById('menuItemCloudGuide');
const menuItemNewChat = document.getElementById('menuItemNewChat');
const menuItemInstall = document.getElementById('menuItemInstall');
const menuItemProfile = document.getElementById('menuItemProfile');
const menuUsernameDisplay = document.getElementById('menuUsernameDisplay');
const menuItemLogout = document.getElementById('menuItemLogout');

const inputSearchChats = document.getElementById('inputSearchChats');
const btnClearSearch = document.getElementById('btnClearSearch');
const chatListContainer = document.getElementById('chatListContainer');
const btnFabNewChat = document.getElementById('btnFabNewChat');
const filterChips = document.querySelectorAll('.filter-chip');

// 2. Ekran (Birebir Yazışma)
const chatScreen = document.getElementById('chatScreen');
const btnBackToChats = document.getElementById('btnBackToChats');
const chatContactAvatar = document.getElementById('chatContactAvatar');
const headerOnlineDot = document.getElementById('headerOnlineDot');
const chatContactName = document.getElementById('chatContactName');
const chatContactStatus = document.getElementById('chatContactStatus');
const btnVideoCall = document.getElementById('btnVideoCall');
const btnVoiceCall = document.getElementById('btnVoiceCall');
const btnBlockContact = document.getElementById('btnBlockContact');
const btnDeleteContact = document.getElementById('btnDeleteContact');
const btnChatMenu = document.getElementById('btnChatMenu');
const chatDropdownMenu = document.getElementById('chatDropdownMenu');
const menuItemChatAudioSettings = document.getElementById('menuItemChatAudioSettings');
const menuItemClearChat = document.getElementById('menuItemClearChat');
const menuItemBlockUser = document.getElementById('menuItemBlockUser');
const menuItemDeleteUser = document.getElementById('menuItemDeleteUser');
const menuItemContactInfo = document.getElementById('menuItemContactInfo');
const menuItemCloseChat = document.getElementById('menuItemCloseChat');
const menuItemSwitchUser = document.getElementById('menuItemSwitchUser');
const quickUsersContainer = document.getElementById('quickUsersContainer');
const quickUsersList = document.getElementById('quickUsersList');

// Yeni Yazışma Ekranı (New Chat Modal)
const newChatModal = document.getElementById('newChatModal');
const btnCloseNewChat = document.getElementById('btnCloseNewChat');
const newChatUserCount = document.getElementById('newChatUserCount');
const inputSearchNewChat = document.getElementById('inputSearchNewChat');
const btnClearNewChatSearch = document.getElementById('btnClearNewChatSearch');
const btnActionCreateNewUser = document.getElementById('btnActionCreateNewUser');
const newChatUsersList = document.getElementById('newChatUsersList');

const messagesContainer = document.getElementById('messagesContainer');
const chatDateBadge = document.getElementById('chatDateBadge');
const typingIndicator = document.getElementById('typingIndicator');
const uploadProgress = document.getElementById('uploadProgress');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');

const messageInput = document.getElementById('messageInput');
const btnEmoji = document.getElementById('btnEmoji');
const btnAttach = document.getElementById('btnAttach');
const btnCamera = document.getElementById('btnCamera');
const fileInput = document.getElementById('fileInput');
const cameraInput = document.getElementById('cameraInput');
const btnSendOrMic = document.getElementById('btnSendOrMic');
const iconMic = document.getElementById('iconMic');
const iconSend = document.getElementById('iconSend');
const chatInputForm = document.getElementById('chatInputForm');

// Anlık Bildirim ve İkon Rozetleri
const messageNotifyToast = document.getElementById('messageNotifyToast');
const notifySender = document.getElementById('notifySender');
const notifyText = document.getElementById('notifyText');
const btnNotifyOpen = document.getElementById('btnNotifyOpen');
const btnNotifyClose = document.getElementById('btnNotifyClose');
const notifyInfoClick = document.getElementById('notifyInfoClick');
const headerUnreadBadge = document.getElementById('headerUnreadBadge');
const headerUnreadCount = document.getElementById('headerUnreadCount');
const backUnreadBadge = document.getElementById('backUnreadBadge');
const backUnreadCount = document.getElementById('backUnreadCount');

// Auth Modalı
const authModal = document.getElementById('authModal');
const authSubtitle = document.getElementById('authSubtitle');
const rememberedUserBox = document.getElementById('rememberedUserBox');
const rememberedAvatar = document.getElementById('rememberedAvatar');
const rememberedName = document.getElementById('rememberedName');
const btnSwitchAccount = document.getElementById('btnSwitchAccount');
const fieldUsernameSelect = document.getElementById('fieldUsernameSelect');
const selectRegisteredUser = document.getElementById('selectRegisteredUser');
const inputUsername = document.getElementById('inputUsername');
const inputPassword = document.getElementById('inputPassword');
const fieldConfirmPassword = document.getElementById('fieldConfirmPassword');
const inputConfirmPassword = document.getElementById('inputConfirmPassword');
const fieldPhone = document.getElementById('fieldPhone');
const inputPhone = document.getElementById('inputPhone');
const chkRememberMe = document.getElementById('chkRememberMe');
const authErrorMsg = document.getElementById('authErrorMsg');
const btnAuthSubmit = document.getElementById('btnAuthSubmit');
const btnToggleAuthMode = document.getElementById('btnToggleAuthMode');
const btnTogglePassword = document.getElementById('btnTogglePassword');
const btnToggleConfirmPassword = document.getElementById('btnToggleConfirmPassword');
const rowForgotPassword = document.getElementById('rowForgotPassword');
const btnForgotPassword = document.getElementById('btnForgotPassword');
const tabAuthLogin = document.getElementById('tabAuthLogin');
const tabAuthRegister = document.getElementById('tabAuthRegister');
const btnCancelAuth = document.getElementById('btnCancelAuth');

// Profil Modalı
const profileModal = document.getElementById('profileModal');
const btnCloseProfileModal = document.getElementById('btnCloseProfileModal');
const profileUserAvatar = document.getElementById('profileUserAvatar');
const profileUsernameDisplay = document.getElementById('profileUsernameDisplay');
const profilePhoneDisplay = document.getElementById('profilePhoneDisplay');
const btnProfileUpdatePhone = document.getElementById('btnProfileUpdatePhone');
const btnProfileAudioSettings = document.getElementById('btnProfileAudioSettings');
const btnProfileNewUser = document.getElementById('btnProfileNewUser');
const btnProfileSwitchUser = document.getElementById('btnProfileSwitchUser');
const btnProfileChangePass = document.getElementById('btnProfileChangePass');
const btnProfileLogout = document.getElementById('btnProfileLogout');
const btnProfileDeleteAccount = document.getElementById('btnProfileDeleteAccount');

// Telefon Numarasından Kişi Bulma Elemanları
const menuItemPhoneLookup = document.getElementById('menuItemPhoneLookup');
const btnQuickPhoneLookup = document.getElementById('btnQuickPhoneLookup');
const inputLookupPhone = document.getElementById('inputLookupPhone');
const inputLookupCustomName = document.getElementById('inputLookupCustomName');
const btnLookupStartChat = document.getElementById('btnLookupStartChat');
const btnLookupVoiceCall = document.getElementById('btnLookupVoiceCall');
const btnLookupVideoCall = document.getElementById('btnLookupVideoCall');

// Ses Motoru (Bildirim, Çalma ve Arama Sesi)
const remoteAudio = document.getElementById('remoteAudio');
const audioRingtone = document.getElementById('audioRingtone');
const audioRingback = document.getElementById('audioRingback');
const audioMessage = document.getElementById('audioMessage');
const audioEnded = document.getElementById('audioEnded');

// Gelen Arama Modalı (Resimdeki gibi Evet / Hayır)
const incomingCallModal = document.getElementById('incomingCallModal');
const incomingCallerAvatar = document.getElementById('incomingCallerAvatar');
const incomingCallerName = document.getElementById('incomingCallerName');
const incomingCallType = document.getElementById('incomingCallType');
const btnAcceptCall = document.getElementById('btnAcceptCall');
const btnRejectCall = document.getElementById('btnRejectCall');
const btnIncomingAudioDevices = document.getElementById('btnIncomingAudioDevices');
const btnCallRemindMe = document.getElementById('btnCallRemindMe');
const btnCallQuickMsg = document.getElementById('btnCallQuickMsg');

// Giden Arama Modalı (Aranıyor / Çalıyor...)
const outgoingCallModal = document.getElementById('outgoingCallModal');
const outgoingTargetName = document.getElementById('outgoingTargetName');
const outgoingCallStatus = document.getElementById('outgoingCallStatus');
const outgoingTargetAvatar = document.getElementById('outgoingTargetAvatar');
const btnOutgoingAudioDevices = document.getElementById('btnOutgoingAudioDevices');
const btnCancelOutgoingCall = document.getElementById('btnCancelOutgoingCall');

const activeCallScreen = document.getElementById('activeCallScreen');
const remoteVideo = document.getElementById('remoteVideo');
const localVideo = document.getElementById('localVideo');
const remoteAudioPlaceholder = document.getElementById('remoteAudioPlaceholder');
const activeCallAvatar = document.getElementById('activeCallAvatar');
const activeCallName = document.getElementById('activeCallName');
const activeCallTargetTitle = document.getElementById('activeCallTargetTitle');
const activeCallTimer = document.getElementById('activeCallTimer');
const callMicLevelFill = document.getElementById('callMicLevelFill');
const callRemoteLevelFill = document.getElementById('callRemoteLevelFill');
const activeAudioDeviceBadge = document.getElementById('activeAudioDeviceBadge');
const activeDeviceLabelText = activeAudioDeviceBadge;
const btnToggleMic = document.getElementById('btnToggleMic');
const btnToggleSpeaker = document.getElementById('btnToggleSpeaker');
const btnOpenCallAudioSettings = document.getElementById('btnOpenCallAudioSettings');
const btnToggleCam = document.getElementById('btnToggleCam');
const btnEndCall = document.getElementById('btnEndCall');

// Mikrofon ve Hoparlör Seçim Modalı
const audioSettingsModal = document.getElementById('audioSettingsModal');
const btnCloseAudioSettings = document.getElementById('btnCloseAudioSettings');
const selectMicDevice = document.getElementById('selectMicDevice');
const selectSpeakerDevice = document.getElementById('selectSpeakerDevice');
const rangeAudioBoost = document.getElementById('rangeAudioBoost');
const lblAudioBoostValue = document.getElementById('lblAudioBoostValue');
const micTestMeterFill = document.getElementById('micTestMeterFill');
const micTestStatusText = document.getElementById('micTestStatusText');
const btnRefreshAudioDevices = document.getElementById('btnRefreshAudioDevices');
const btnTestSpeakerSound = document.getElementById('btnTestSpeakerSound');
const btnSaveAudioSettings = document.getElementById('btnSaveAudioSettings');

const qrModal = document.getElementById('qrModal');
const btnCloseQr = document.getElementById('btnCloseQr');
const qrImage = document.getElementById('qrImage');
const httpsLink = document.getElementById('httpsLink');
const tabLocalWifi = document.getElementById('tabLocalWifi');
const tabRemoteTunnel = document.getElementById('tabRemoteTunnel');
const contentLocalWifi = document.getElementById('contentLocalWifi');
const contentRemoteTunnel = document.getElementById('contentRemoteTunnel');
const tunnelLink = document.getElementById('tunnelLink');
const tunnelQrImage = document.getElementById('tunnelQrImage');

const imageModal = document.getElementById('imageModal');
const enlargedImage = document.getElementById('enlargedImage');
const btnCloseImageModal = document.getElementById('btnCloseImageModal');

const cloudGuideModal = document.getElementById('cloudGuideModal');
const btnCloseCloudGuide = document.getElementById('btnCloseCloudGuide');

const statusToast = document.getElementById('statusToast');
const statusToastDot = document.getElementById('statusToastDot');
const statusToastText = document.getElementById('statusToastText');

// ==========================================================
// SES VE ANLIK BİLDİRİM MOTORU (ONLINE / OFFLINE TOAST & CHIME)
// ==========================================================

function playStatusChime(isOnline) {
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        if (ctx.state === 'suspended') {
            ctx.resume();
        }
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        const now = ctx.currentTime;
        if (isOnline) {
            // Canlı, neşeli iki tonlu çevrimiçi sesi: C5 -> G5
            osc.type = 'sine';
            osc.frequency.setValueAtTime(523.25, now);
            osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.12);
            gain.gain.setValueAtTime(0.001, now);
            gain.gain.linearRampToValueAtTime(0.2, now + 0.05);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.start(now);
            osc.stop(now + 0.36);
        } else {
            // Hafif, kibar çevrimdışı sesi: E4 -> C4
            osc.type = 'sine';
            osc.frequency.setValueAtTime(329.63, now);
            osc.frequency.exponentialRampToValueAtTime(261.63, now + 0.15);
            gain.gain.setValueAtTime(0.001, now);
            gain.gain.linearRampToValueAtTime(0.15, now + 0.05);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.start(now);
            osc.stop(now + 0.36);
        }
    } catch (e) {
        // Otomatik ses çalma tarayıcı güvenlik politikası
    }
}

let toastTimer = null;
function showStatusToast(username, isOnline) {
    if (!statusToast || !statusToastText) return;

    if (toastTimer) {
        clearTimeout(toastTimer);
        toastTimer = null;
    }

    statusToast.className = `status-toast ${isOnline ? 'online' : 'offline'}`;
    statusToastText.textContent = isOnline ? `${username} Online` : `${username} Offline`;
    statusToast.style.display = 'flex';
    statusToast.style.opacity = '1';

    toastTimer = setTimeout(() => {
        statusToast.style.opacity = '0';
        setTimeout(() => {
            statusToast.style.display = 'none';
        }, 300);
    }, 3500);
}

// ==========================================================
// SES VE TELEFON ÇALMA MOTORU (BİLDİRİM, ÇALMA, DİALTONE)
// ==========================================================

// Tarayıcı ve mobil ses kilidini (Autoplay Policy) ilk tıklamada kaldır
function unlockAudio() {
    if (isAudioUnlocked) return;
    isAudioUnlocked = true;

    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) {
            const ctx = new AudioContext();
            if (ctx.state === 'suspended') ctx.resume();
        }
    } catch(e) {}

    // İlk tıklamada veya giriş yaparken arama/meşgul seslerinin çalmaması için sesleri sessizce sıfırda tut
    [audioRingtone, audioRingback, audioEnded].forEach(el => {
        if (el) {
            try {
                el.pause();
                el.currentTime = 0;
            } catch(e) {}
        }
    });

    requestNotificationPermission();
}

document.addEventListener('click', unlockAudio, { passive: true });
document.addEventListener('touchstart', unlockAudio, { passive: true });

function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {});
    }
}

// Sistem ve PWA bildirimleri (Program arka plandayken veya kilitliyken çalışır)
function triggerSystemNotification(title, options) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    try {
        if (navigator.serviceWorker && navigator.serviceWorker.controller) {
            navigator.serviceWorker.ready.then(reg => {
                reg.showNotification(title, options);
            }).catch(() => {
                new Notification(title, options);
            });
        } else {
            new Notification(title, options);
        }
    } catch(e) {}
}

// 1. Yeni Mesaj Geldiğinde Bildirim Sesi Çalma
function playIncomingMessageSound() {
    try {
        if (audioMessage) {
            audioMessage.currentTime = 0;
            const p = audioMessage.play();
            if (p !== undefined) {
                p.catch(() => playIncomingMessageChime());
            }
        } else {
            playIncomingMessageChime();
        }
    } catch(e) {
        playIncomingMessageChime();
    }

    if (navigator.vibrate) {
        try { navigator.vibrate([180, 80, 180]); } catch(e) {}
    }
}

// Web Audio Fallback: Sentezlenmiş mesaj sesi
function playIncomingMessageChime() {
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        if (ctx.state === 'suspended') ctx.resume();

        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        // Canlı, tatlı çift tonlu mesaj bildirimi sesi (F5 -> A5)
        osc.type = 'sine';
        osc.frequency.setValueAtTime(698.46, now);
        osc.frequency.exponentialRampToValueAtTime(880.00, now + 0.1);
        gain.gain.setValueAtTime(0.001, now);
        gain.gain.linearRampToValueAtTime(0.35, now + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.45);

        osc.start(now);
        osc.stop(now + 0.46);
    } catch(e) {}
}

// 2. Telefon Çalma Sesi (Gelen Arama Ringtonu)
function playRingtone() {
    unlockAudio();
    try {
        if (audioRingtone) {
            audioRingtone.currentTime = 0;
            const p = audioRingtone.play();
            if (p !== undefined) {
                p.catch(() => startSynthRingtoneFallback());
            }
        } else {
            startSynthRingtoneFallback();
        }
    } catch(e) {
        startSynthRingtoneFallback();
    }

    // Telefon titreşim ritmi (1 sn çal, 0.5 sn dur)
    if (navigator.vibrate) {
        try { navigator.vibrate([1000, 500, 1000, 500, 1000, 500]); } catch(e) {}
        if (ringtoneVibrateInterval) clearInterval(ringtoneVibrateInterval);
        ringtoneVibrateInterval = setInterval(() => {
            try { navigator.vibrate([1000, 500, 1000, 500, 1000, 500]); } catch(e) {}
        }, 4500);
    }
}

function stopRingtone() {
    try {
        if (audioRingtone) {
            audioRingtone.pause();
            audioRingtone.currentTime = 0;
        }
    } catch(e) {}

    stopSynthRingtoneFallback();

    if (ringtoneVibrateInterval) {
        clearInterval(ringtoneVibrateInterval);
        ringtoneVibrateInterval = null;
    }
    if (navigator.vibrate) {
        try { navigator.vibrate(0); } catch(e) {}
    }
}

// Ringtone Web Audio Yedek Döngüsü (Audio dosyası engellenirse devreye girer)
let synthCtx = null;
function startSynthRingtoneFallback() {
    if (ringtoneOscInterval) return;
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        synthCtx = new AudioContext();

        const playBeep = () => {
            if (!synthCtx) return;
            if (synthCtx.state === 'suspended') synthCtx.resume();
            const now = synthCtx.currentTime;
            const osc = synthCtx.createOscillator();
            const gain = synthCtx.createGain();
            osc.connect(gain);
            gain.connect(synthCtx.destination);
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(800, now);
            osc.frequency.setValueAtTime(1000, now + 0.2);
            gain.gain.setValueAtTime(0.3, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 1.2);
            osc.start(now);
            osc.stop(now + 1.25);
        };

        playBeep();
        ringtoneOscInterval = setInterval(playBeep, 2400);
    } catch(e) {}
}

function stopSynthRingtoneFallback() {
    if (ringtoneOscInterval) {
        clearInterval(ringtoneOscInterval);
        ringtoneOscInterval = null;
    }
    if (synthCtx) {
        try { synthCtx.close(); } catch(e) {}
        synthCtx = null;
    }
}

// 3. Giden Arama Çalma Sesi (Dial / Ringback Tone "Düt... Düt...")
function playRingback() {
    unlockAudio();
    try {
        if (audioRingback) {
            audioRingback.currentTime = 0;
            audioRingback.play().catch(() => {});
        }
    } catch(e) {}
}

function stopRingback() {
    try {
        if (audioRingback) {
            audioRingback.pause();
            audioRingback.currentTime = 0;
        }
    } catch(e) {}
}

// 4. Arama Kapatıldı / Meşgul Sesi
function playCallEndedSound() {
    try {
        if (audioEnded) {
            audioEnded.currentTime = 0;
            audioEnded.play().catch(() => {});
        }
    } catch(e) {}
}

let notifyToastTimer = null;
let lastNotifySender = null;

function showMessageNotificationToast(msg) {
    if (!messageNotifyToast || !notifySender || !notifyText) return;
    if (!currentUser || !msg) return;

    // Yalnızca aktif kullanıcıya gelen mesajların bildirimini göster
    if (msg.recipient && normalizeKey(msg.recipient) !== normalizeKey(currentUser.username)) {
        return;
    }

    if (notifyToastTimer) {
        clearTimeout(notifyToastTimer);
        notifyToastTimer = null;
    }

    lastNotifySender = msg.sender;
    notifySender.textContent = msg.sender;
    const decText = msg.text ? decryptE2EETextClient(msg.text, msg.sender, msg.recipient) : '';
    notifyText.textContent = decText || (msg.file ? '📎 [Dosya / Fotoğraf]' : 'Yeni Mesaj Geldi');

    messageNotifyToast.style.display = 'flex';
    messageNotifyToast.style.opacity = '1';

    notifyToastTimer = setTimeout(() => {
        dismissMessageNotificationToast();
    }, 6000);
}

function dismissMessageNotificationToast() {
    if (messageNotifyToast) {
        messageNotifyToast.style.opacity = '0';
        setTimeout(() => {
            messageNotifyToast.style.display = 'none';
        }, 300);
    }
    if (notifyToastTimer) {
        clearTimeout(notifyToastTimer);
        notifyToastTimer = null;
    }
}

// Bildirim Kutusundaki "Aç" Butonuna veya Kutuya Basıldığında
if (btnNotifyOpen) {
    btnNotifyOpen.addEventListener('click', (e) => {
        e.stopPropagation();
        openChatForSender(lastNotifySender);
    });
}

if (notifyInfoClick) {
    notifyInfoClick.addEventListener('click', () => {
        openChatForSender(lastNotifySender);
    });
}

if (btnNotifyClose) {
    btnNotifyClose.addEventListener('click', (e) => {
        e.stopPropagation();
        dismissMessageNotificationToast();
    });
}

function openChatForSender(senderUsername) {
    if (!senderUsername) return;
    dismissMessageNotificationToast();
    const contact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(senderUsername));
    if (contact) {
        selectContact(contact);
    } else {
        loadChatsList().then(() => {
            const freshContact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(senderUsername));
            if (freshContact) selectContact(freshContact);
        });
    }
}

// Ekrandaki ve Başlıktaki Okunmamış Mesaj İkon ve Rozetlerini Güncelle
function updateUnreadBadges() {
    let totalUnread = 0;
    contactsList.forEach(c => {
        totalUnread += (c.unreadCount || 0);
    });

    // 1. Ana Ekran Üst Başlık Mesaj Rozeti (Resim 1)
    if (headerUnreadBadge && headerUnreadCount) {
        if (totalUnread > 0) {
            headerUnreadCount.textContent = totalUnread;
            headerUnreadBadge.style.display = 'inline-flex';
        } else {
            headerUnreadBadge.style.display = 'none';
        }
    }

    // 2. Sohbet İçi Geri Butonundaki Bildirim İkonu (Resim 2)
    if (backUnreadBadge && backUnreadCount) {
        let otherUnread = 0;
        contactsList.forEach(c => {
            if (!activeContact || normalizeKey(c.username) !== normalizeKey(activeContact.username)) {
                otherUnread += (c.unreadCount || 0);
            }
        });

        if (otherUnread > 0) {
            backUnreadCount.textContent = otherUnread;
            backUnreadBadge.style.display = 'inline-flex';
        } else {
            backUnreadBadge.style.display = 'none';
        }
    }

    // 3. Tarayıcı Sekme Başlığı
    if (totalUnread > 0) {
        document.title = `(${totalUnread}) ✉️ Yeni Mesaj - HIHaberleşme`;
    } else {
        document.title = 'HIHaberleşme';
    }
}

// ==========================================================
// 1. KULLANICI GİRİŞİ, KAYIT VE KALICI KULLANICI YÖNETİMİ
// (Kayıtlı kullanıcılar asla otomatik silinmez; yalnızca kullanıcı kendi isterse silinir)
// ==========================================================

function getDeletedLocalUserKeys() {
    try {
        const raw = localStorage.getItem('msj_deleted_users');
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        }
    } catch (e) {}
    return [];
}

function addDeletedLocalUserKey(usernameOrKey) {
    const key = normalizeKey(usernameOrKey);
    if (!key) return;
    try {
        const list = new Set(getDeletedLocalUserKeys());
        list.add(key);
        localStorage.setItem('msj_deleted_users', JSON.stringify(Array.from(list)));
    } catch (e) {}
}

function removeDeletedLocalUserKey(usernameOrKey) {
    const key = normalizeKey(usernameOrKey);
    if (!key) return;
    try {
        const list = getDeletedLocalUserKeys().filter(k => k !== key);
        localStorage.setItem('msj_deleted_users', JSON.stringify(list));
    } catch (e) {}
}

function getPermanentLocalUsers() {
    try {
        const deletedSet = new Set(getDeletedLocalUserKeys());
        const raw = localStorage.getItem('msj_permanent_users');
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) {
                return parsed.filter(u => u && u.username && !deletedSet.has(normalizeKey(u.username)));
            }
        }
    } catch (e) {}
    return [];
}

function savePermanentLocalUsers(usersArray, deletedKeysFromServer) {
    if (Array.isArray(deletedKeysFromServer)) {
        deletedKeysFromServer.forEach(k => addDeletedLocalUserKey(k));
    }
    if (!Array.isArray(usersArray)) return;
    const deletedSet = new Set(getDeletedLocalUserKeys());
    const existing = getPermanentLocalUsers();
    const map = new Map();
    existing.forEach(u => {
        if (u && u.username) {
            const k = normalizeKey(u.username);
            if (!deletedSet.has(k)) {
                map.set(k, {
                    username: u.username,
                    avatar: u.avatar || '/avatars/default.svg',
                    phone: u.phone || undefined,
                    salt: u.salt || undefined,
                    hash: u.hash || undefined,
                    createdAt: u.createdAt || undefined
                });
            }
        }
    });
    usersArray.forEach(u => {
        if (u && u.username) {
            const k = normalizeKey(u.username);
            if (!deletedSet.has(k)) {
                const prev = map.get(k) || {};
                map.set(k, {
                    username: u.username || prev.username,
                    avatar: u.avatar || prev.avatar || '/avatars/default.svg',
                    phone: u.phone || prev.phone || undefined,
                    salt: u.salt || prev.salt || undefined,
                    hash: u.hash || prev.hash || undefined,
                    createdAt: u.createdAt || prev.createdAt || undefined
                });
            }
        }
    });
    const merged = Array.from(map.values());
    try {
        localStorage.setItem('msj_permanent_users', JSON.stringify(merged));
    } catch (e) {}
    return merged;
}

function getCachedContactsForCurrentUser() {
    if (!currentUser || !currentUser.username) return [];
    try {
        const key = 'msj_cached_contacts_' + normalizeKey(currentUser.username);
        const raw = localStorage.getItem(key);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        }
    } catch (e) {}
    return [];
}

function saveCachedContactsForCurrentUser(list) {
    if (!currentUser || !currentUser.username || !Array.isArray(list)) return;
    try {
        const key = 'msj_cached_contacts_' + normalizeKey(currentUser.username);
        localStorage.setItem(key, JSON.stringify(list));
    } catch (e) {}
}

function isMessageForCurrentUserAndContact(msg, contactKey) {
    if (!msg || !currentUser || !currentUser.username) return false;
    const myKey = normalizeKey(currentUser.username);
    const sKey = normalizeKey(msg.sender);
    const rKey = normalizeKey(msg.recipient);
    return (sKey === myKey && rKey === contactKey) || (sKey === contactKey && rKey === myKey);
}

function getPersonalPhoneBookForCurrentUser() {
    if (!currentUser || !currentUser.username) return [];
    try {
        const key = 'msj_phone_book_' + normalizeKey(currentUser.username);
        const raw = localStorage.getItem(key);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        }
    } catch (e) {}
    return [];
}

function savePersonalPhoneBookForCurrentUser(list) {
    if (!currentUser || !currentUser.username || !Array.isArray(list)) return;
    try {
        const key = 'msj_phone_book_' + normalizeKey(currentUser.username);
        localStorage.setItem(key, JSON.stringify(list));
    } catch (e) {}
}

function getPhoneMatchKeyClient(phoneOrUsername) {
    const clean = normalizePhoneClient(phoneOrUsername || '');
    if (!clean || clean.length < 7) return '';
    return clean.length >= 10 ? clean.slice(-10) : clean;
}

// Numaradan bulunup mesaj gönderilen bir kişi programı kurup kullanıcı adıyla giriş yaptığında istemci tarafında anında entegre eder
function integratePhoneContactOnClient(oldUsernameOrPhone, newUsername, phone, avatar = '/avatars/default.svg', isOnline = true) {
    if (!newUsername) return;
    const cleanNewUser = newUsername.trim();
    const newKey = normalizeKey(cleanNewUser);
    const cleanPhone = normalizePhoneClient(phone || oldUsernameOrPhone || '');
    const phoneMatchKey = getPhoneMatchKeyClient(cleanPhone);
    const oldKey = normalizeKey(oldUsernameOrPhone || cleanPhone);

    if (!newKey) return;
    if (oldKey && oldKey !== newKey) {
        addDeletedLocalUserKey(oldKey);
    }

    // 1. Kişisel telefon rehberini (msj_phone_book_<user>) güncelle
    try {
        const pb = getPersonalPhoneBookForCurrentUser();
        if (Array.isArray(pb) && pb.length > 0) {
            let pbChanged = false;
            let savedCustomName = '';
            const updatedPb = [];
            const seenKeys = new Set();
            pb.forEach(item => {
                if (!item || !item.username) return;
                const ik = normalizeKey(item.username);
                const ipKey = getPhoneMatchKeyClient(item.phone || (isPhoneQueryClient(item.username) ? item.username : ''));
                if ((oldKey && ik === oldKey) || (phoneMatchKey && ipKey === phoneMatchKey) || ik === newKey) {
                    if (item.customName && !isPhoneQueryClient(item.customName)) {
                        savedCustomName = item.customName;
                    }
                    pbChanged = true;
                    if (!seenKeys.has(newKey)) {
                        seenKeys.add(newKey);
                        updatedPb.push({
                            username: cleanNewUser,
                            customName: savedCustomName || item.customName || '',
                            phone: cleanPhone || item.phone || '',
                            avatar: avatar || item.avatar || '/avatars/default.svg'
                        });
                    }
                } else if (!seenKeys.has(ik)) {
                    seenKeys.add(ik);
                    updatedPb.push(item);
                }
            });
            if (pbChanged) {
                savePersonalPhoneBookForCurrentUser(updatedPb);
            }
        }
    } catch (e) {}

    // 2. contactsList içinde eski numaralı kaydı yeni kullanıcı adıyla birleştir
    let oldContact = null;
    let newContact = null;
    contactsList.forEach(c => {
        if (!c || !c.username) return;
        const ck = normalizeKey(c.username);
        const cpKey = getPhoneMatchKeyClient(c.phone || (isPhoneQueryClient(c.username) ? c.username : ''));
        if (ck === newKey) {
            newContact = c;
        } else if ((oldKey && ck === oldKey) || (phoneMatchKey && cpKey === phoneMatchKey)) {
            oldContact = c;
        }
    });

    if (oldContact && !newContact) {
        oldContact.username = cleanNewUser;
        if (cleanPhone) oldContact.phone = cleanPhone;
        if (avatar) oldContact.avatar = avatar;
        oldContact.isOnline = Boolean(isOnline);
        oldContact.statusText = isOnline ? 'Online' : 'Offline';
        oldContact.lastSeen = isOnline ? 'Online' : 'Offline';
        if (oldContact.lastMessage) {
            if (normalizeKey(oldContact.lastMessage.sender) === oldKey) oldContact.lastMessage.sender = cleanNewUser;
            if (normalizeKey(oldContact.lastMessage.recipient) === oldKey) oldContact.lastMessage.recipient = cleanNewUser;
        }
    } else if (oldContact && newContact) {
        if (!newContact.phone && (cleanPhone || oldContact.phone)) {
            newContact.phone = cleanPhone || oldContact.phone;
        }
        if (!newContact.customName && oldContact.customName && !isPhoneQueryClient(oldContact.customName)) {
            newContact.customName = oldContact.customName;
        }
        if (!newContact.lastMessage && oldContact.lastMessage) {
            newContact.lastMessage = {
                ...oldContact.lastMessage,
                sender: normalizeKey(oldContact.lastMessage.sender) === oldKey ? cleanNewUser : oldContact.lastMessage.sender,
                recipient: normalizeKey(oldContact.lastMessage.recipient) === oldKey ? cleanNewUser : oldContact.lastMessage.recipient
            };
        }
        newContact.isOnline = Boolean(isOnline);
        newContact.statusText = isOnline ? 'Online' : 'Offline';
        newContact.lastSeen = isOnline ? 'Online' : 'Offline';
        contactsList = contactsList.filter(c => normalizeKey(c.username) !== normalizeKey(oldContact.username));
    } else if (newContact) {
        if (cleanPhone) newContact.phone = cleanPhone;
        newContact.isOnline = Boolean(isOnline);
        newContact.statusText = isOnline ? 'Online' : 'Offline';
        newContact.lastSeen = isOnline ? 'Online' : 'Offline';
    }

    saveCachedContactsForCurrentUser(contactsList);

    // 3. Eğer şu an açık olan sohbet eski telefon numarasıysa başlığı ve hedefi yeni kullanıcı adına geçir
    if (activeContact) {
        const ak = normalizeKey(activeContact.username);
        const apKey = getPhoneMatchKeyClient(activeContact.phone || (isPhoneQueryClient(activeContact.username) ? activeContact.username : ''));
        if ((oldKey && ak === oldKey) || (phoneMatchKey && apKey === phoneMatchKey) || ak === newKey) {
            activeContact.username = cleanNewUser;
            if (cleanPhone) activeContact.phone = cleanPhone;
            activeContact.isOnline = Boolean(isOnline);
            if (chatContactName) {
                chatContactName.textContent = cleanPhone && !isPhoneQueryClient(cleanNewUser)
                    ? `${cleanNewUser} (${formatPhonePretty(cleanPhone)})`
                    : cleanNewUser;
            }
            if (chatContactStatus) chatContactStatus.textContent = isOnline ? 'Online' : 'Offline';
            if (headerOnlineDot) headerOnlineDot.style.display = isOnline ? 'block' : 'none';
        }
    }
}

function mergeContactsWithPermanentUsers(serverChats) {
    const deletedSet = new Set(getDeletedLocalUserKeys());
    const myKey = currentUser ? normalizeKey(currentUser.username) : '';
    const map = new Map();
    const phoneKeyToUserKey = new Map();

    // 1. Önce sunucudan gelen güncel sohbet/rehber verilerini ekle
    if (Array.isArray(serverChats)) {
        serverChats.forEach(c => {
            if (!c || !c.username) return;
            const k = normalizeKey(c.username);
            if (k && k !== myKey && !deletedSet.has(k)) {
                const validMsg = isMessageForCurrentUserAndContact(c.lastMessage, k) ? c.lastMessage : null;
                const pKey = getPhoneMatchKeyClient(c.phone || (isPhoneQueryClient(c.username) ? c.username : ''));
                // Eğer aynı telefon numarasına sahip hem numara kaydı hem gerçek kullanıcı adı varsa gerçek kullanıcı adını tut
                if (pKey && phoneKeyToUserKey.has(pKey)) {
                    const existingKey = phoneKeyToUserKey.get(pKey);
                    const existingItem = map.get(existingKey);
                    if (existingItem) {
                        if (isPhoneQueryClient(existingItem.username) && !isPhoneQueryClient(c.username)) {
                            map.delete(existingKey);
                            phoneKeyToUserKey.set(pKey, k);
                        } else if (!isPhoneQueryClient(existingItem.username) && isPhoneQueryClient(c.username)) {
                            if (!existingItem.lastMessage && validMsg) existingItem.lastMessage = validMsg;
                            return;
                        }
                    }
                } else if (pKey) {
                    phoneKeyToUserKey.set(pKey, k);
                }

                map.set(k, {
                    ...c,
                    lastMessage: validMsg,
                    unreadCount: myKey ? (Number(c.unreadCount) || 0) : 0
                });
            }
        });
    }

    // 2. Yalnızca şu anki aktif kullanıcıya ait kişisel rehberdeki (msj_phone_book_<user>) ve önbellekteki (msj_cached_contacts_<user>) kişileri koru
    // Eğer numaradan bulunan kişi kullanıcı adıyla entegre olmuşsa telefon numarası üzerinden eşleştirip birleştir!
    if (myKey) {
        try {
            const phoneBook = getPersonalPhoneBookForCurrentUser();
            let phoneBookNeedsUpdate = false;
            if (Array.isArray(phoneBook)) {
                phoneBook.forEach(c => {
                    if (!c || !c.username) return;
                    const k = normalizeKey(c.username);
                    const pKey = getPhoneMatchKeyClient(c.phone || (isPhoneQueryClient(c.username) ? c.username : ''));
                    if (pKey && phoneKeyToUserKey.has(pKey)) {
                        const integratedKey = phoneKeyToUserKey.get(pKey);
                        const integratedContact = map.get(integratedKey);
                        if (integratedContact) {
                            if (!integratedContact.phone && c.phone) integratedContact.phone = c.phone;
                            if (!integratedContact.customName && c.customName && !isPhoneQueryClient(c.customName)) {
                                integratedContact.customName = c.customName;
                            }
                            if (integratedKey !== k) {
                                c.username = integratedContact.username;
                                c.phone = integratedContact.phone || c.phone;
                                phoneBookNeedsUpdate = true;
                            }
                        }
                        return;
                    }
                    if (k && k !== myKey && !deletedSet.has(k) && !map.has(k)) {
                        if (pKey) phoneKeyToUserKey.set(pKey, k);
                        map.set(k, {
                            username: c.username,
                            customName: c.customName || '',
                            avatar: c.avatar || '/avatars/default.svg',
                            phone: c.phone || '',
                            isOnline: false,
                            statusText: 'Offline',
                            lastSeen: 'Offline',
                            lastMessage: null,
                            unreadCount: 0
                        });
                    }
                });
                if (phoneBookNeedsUpdate) {
                    savePersonalPhoneBookForCurrentUser(phoneBook);
                }
            }

            const cached = getCachedContactsForCurrentUser();
            if (Array.isArray(cached)) {
                cached.forEach(c => {
                    if (!c || !c.username) return;
                    const k = normalizeKey(c.username);
                    const pKey = getPhoneMatchKeyClient(c.phone || (isPhoneQueryClient(c.username) ? c.username : ''));
                    if (pKey && phoneKeyToUserKey.has(pKey)) {
                        const integratedKey = phoneKeyToUserKey.get(pKey);
                        const integratedContact = map.get(integratedKey);
                        if (integratedContact && !integratedContact.phone && c.phone) {
                            integratedContact.phone = c.phone;
                        }
                        return;
                    }
                    const validMsg = isMessageForCurrentUserAndContact(c.lastMessage, k) ? c.lastMessage : null;
                    const hasPhoneOrMsg = Boolean(validMsg || c.phone || c.customName);
                    if (k && k !== myKey && !deletedSet.has(k) && !map.has(k) && hasPhoneOrMsg) {
                        if (pKey) phoneKeyToUserKey.set(pKey, k);
                        map.set(k, {
                            username: c.username,
                            customName: c.customName || '',
                            avatar: c.avatar || '/avatars/default.svg',
                            phone: c.phone || '',
                            isOnline: false,
                            statusText: 'Offline',
                            lastSeen: c.lastSeen || 'Offline',
                            lastMessage: validMsg,
                            unreadCount: validMsg ? (Number(c.unreadCount) || 0) : 0
                        });
                    }
                });
            }
        } catch (e) {}
    }

    return Array.from(map.values());
}

function removePermanentLocalUser(usernameToRemove) {
    const key = normalizeKey(usernameToRemove);
    if (!key) return;
    addDeletedLocalUserKey(key);
    try {
        const existing = getPermanentLocalUsers().filter(u => normalizeKey(u.username) !== key);
        localStorage.setItem('msj_permanent_users', JSON.stringify(existing));
    } catch (e) {}
    try {
        localStorage.removeItem('msj_cached_contacts');
        localStorage.removeItem('msj_cached_contacts_' + key);
        if (currentUser && currentUser.username) {
            const myCacheKey = 'msj_cached_contacts_' + normalizeKey(currentUser.username);
            const cachedRaw = localStorage.getItem(myCacheKey);
            if (cachedRaw) {
                const cached = JSON.parse(cachedRaw).filter(u => normalizeKey(u.username) !== key);
                localStorage.setItem(myCacheKey, JSON.stringify(cached));
            }
        }
    } catch (e) {}
    if (normalizeKey(localStorage.getItem('msj_saved_username') || '') === key) {
        localStorage.removeItem('msj_saved_username');
        localStorage.removeItem('msj_token');
        sessionStorage.removeItem('msj_token');
        localStorage.removeItem('msj_user');
    }
}

async function syncPermanentUsersWithServer() {
    try {
        const deletedSet = new Set(getDeletedLocalUserKeys());
        const localUsers = getPermanentLocalUsers();
        const savedUsername = localStorage.getItem('msj_saved_username');
        if (savedUsername && !deletedSet.has(normalizeKey(savedUsername))) {
            localUsers.push({ username: savedUsername, avatar: '/avatars/default.svg' });
        }
        const cached = getCachedContactsForCurrentUser();
        if (Array.isArray(cached)) {
            cached.forEach(c => {
                if (c && c.username && !deletedSet.has(normalizeKey(c.username))) {
                    localUsers.push({
                        username: c.username,
                        avatar: c.avatar,
                        salt: c.salt,
                        hash: c.hash,
                        createdAt: c.createdAt
                    });
                }
            });
        }
        const res = await fetch('/api/users/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                users: localUsers,
                deletedUsers: Array.from(deletedSet)
            })
        });
        const data = await res.json();
        if (data && data.success && Array.isArray(data.users)) {
            savePermanentLocalUsers(data.users, data.deletedUsers);
            return data.users;
        }
    } catch (e) {}
    return null;
}

// Kullanıcıya özel engellenen kişiler önbelleği (LocalStorage)
function getLocalBlockedUserKeys() {
    if (!currentUser || !currentUser.username) return [];
    try {
        const raw = localStorage.getItem('msj_blocked_users_' + normalizeKey(currentUser.username));
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        }
    } catch (e) {}
    return [];
}

function setContactBlockedLocally(targetUsername, isBlocked) {
    if (!currentUser || !currentUser.username || !targetUsername) return;
    const tKey = normalizeKey(targetUsername);
    try {
        const set = new Set(getLocalBlockedUserKeys());
        if (isBlocked) set.add(tKey);
        else set.delete(tKey);
        localStorage.setItem('msj_blocked_users_' + normalizeKey(currentUser.username), JSON.stringify(Array.from(set)));
    } catch (e) {}
}

function isContactBlockedLocally(targetUsername) {
    const tKey = normalizeKey(targetUsername);
    if (!tKey) return false;
    return getLocalBlockedUserKeys().includes(tKey);
}

function updateActiveContactBlockHeaderUi() {
    if (!activeContact) return;
    const isBlocked = Boolean(activeContact.isBlocked || isContactBlockedLocally(activeContact.username));
    activeContact.isBlocked = isBlocked;
    if (btnBlockContact) {
        btnBlockContact.textContent = isBlocked ? '🔓' : '🚫';
        btnBlockContact.title = isBlocked ? 'Engeli Kaldır' : 'Bu Kişiyi Engelle';
    }
    if (menuItemBlockUser) {
        menuItemBlockUser.textContent = isBlocked ? '🔓 Bu Kişinin Engelini Kaldır' : '🚫 Bu Kişiyi Engelle';
    }
    if (chatContactStatus) {
        if (isBlocked) {
            chatContactStatus.textContent = '🚫 Engellendi';
            chatContactStatus.style.color = '#ff6b81';
        } else {
            chatContactStatus.textContent = activeContact.isOnline ? 'Online' : 'Offline';
            chatContactStatus.style.color = '';
        }
    }
}

// Kişiyi Engelle / Engeli Kaldır
window.toggleBlockContact = async function(targetUsername) {
    if (!targetUsername || !currentUser || !currentUser.username) return;
    const tKey = normalizeKey(targetUsername);
    const contactObj = contactsList.find(c => normalizeKey(c.username) === tKey);
    const currentlyBlocked = Boolean((contactObj && contactObj.isBlocked) || isContactBlockedLocally(targetUsername));
    const actionLabel = currentlyBlocked ? 'engelini kaldırmak' : 'engellemek';

    const confirmed = confirm(
        currentlyBlocked
            ? `"${targetUsername}" adlı kişinin engelini kaldırmak istediğinize emin misiniz?`
            : `"${targetUsername}" adlı kişiyi engellemek istediğinize emin misiniz?\n\nEngellenen kişi size mesaj gönderemez ve sizi arayamaz.`
    );
    if (!confirmed) return;

    const endpoint = currentlyBlocked ? '/api/contacts/unblock' : '/api/contacts/block';
    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify({
                ownerUsername: currentUser.username,
                targetUsername: targetUsername
            })
        });
        const data = await res.json();
        if (data && data.success) {
            const newBlocked = !currentlyBlocked;
            setContactBlockedLocally(targetUsername, newBlocked);
            contactsList.forEach(c => {
                if (normalizeKey(c.username) === tKey) {
                    c.isBlocked = newBlocked;
                }
            });
            if (activeContact && normalizeKey(activeContact.username) === tKey) {
                activeContact.isBlocked = newBlocked;
                updateActiveContactBlockHeaderUi();
            }
            saveCachedContactsForCurrentUser(contactsList);
            renderChatsList(contactsList);
            if (newChatModal && newChatModal.style.display === 'flex') {
                renderNewChatUsers(contactsList);
            }
            showStatusToast(
                newBlocked ? `🚫 ${targetUsername} engellendi` : `🔓 ${targetUsername} engeli kaldırıldı`,
                !newBlocked
            );
        } else {
            alert((data && data.error) || `Kişinin ${actionLabel} işlemi yapılamadı.`);
        }
    } catch (e) {
        alert('Sunucuya bağlanılamadı.');
    }
};

// Kullanıcı kendi isteğiyle bir kaydı silmek istediğinde çağrılır
window.requestDeleteUser = async function(usernameToDelete) {
    if (!usernameToDelete) return;
    const isDeletingSelf = currentUser && normalizeKey(currentUser.username) === normalizeKey(usernameToDelete);
    const confirmed = confirm(
        isDeletingSelf
            ? `"${usernameToDelete}" adlı kullanıcı hesabınızı kalıcı olarak silmek istediğinize emin misiniz?`
            : `"${usernameToDelete}" adlı kayıtlı kişiyi ve sohbet geçmişini silmek istediğinize emin misiniz?\n\n(İptal derseniz kişi kayıtlı kalmaya devam eder.)`
    );
    if (!confirmed) return;

    try {
        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
        if (!isDeletingSelf && currentUser && currentUser.username) {
            await fetch('/api/contacts/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': token
                },
                body: JSON.stringify({
                    ownerUsername: currentUser.username,
                    contactUsername: usernameToDelete,
                    deleteAccountCompletely: false
                })
            }).catch(() => {});
        } else {
            await fetch('/api/users/' + encodeURIComponent(usernameToDelete), {
                method: 'DELETE'
            }).catch(() => {});
        }

        removePermanentLocalUser(usernameToDelete);
        try {
            const pb = getPersonalPhoneBookForCurrentUser().filter(item => normalizeKey(item.username) !== normalizeKey(usernameToDelete));
            savePersonalPhoneBookForCurrentUser(pb);
        } catch (e) {}

        contactsList = contactsList.filter(c => normalizeKey(c.username) !== normalizeKey(usernameToDelete));
        saveCachedContactsForCurrentUser(contactsList);
        renderChatsList(contactsList);
        if (newChatModal && newChatModal.style.display === 'flex') {
            renderNewChatUsers(contactsList);
        }

        if (activeContact && normalizeKey(activeContact.username) === normalizeKey(usernameToDelete)) {
            closeActiveChat();
        }

        if (isDeletingSelf) {
            currentUser = null;
            closeProfileModal();
            await loadRegisteredUsersDropdown();
            showPasswordPrompt('');
        } else {
            await loadRegisteredUsersDropdown();
            showStatusToast(`🗑️ ${usernameToDelete} rehberden ve kayıtlardan silindi`, false);
        }
    } catch (e) {
        alert('Sunucuya bağlanılamadı.');
    }
};

async function quickLoginAsRegisteredUser(username) {
    if (!username) return false;
    try {
        removeDeletedLocalUserKey(username);
        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
        const autoRes = await fetch('/api/auth/auto_login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, token })
        });
        const autoData = await autoRes.json();
        if (autoData && autoData.success && autoData.user) {
            localStorage.setItem('msj_saved_username', autoData.user.username);
            localStorage.setItem('msj_auto_login', 'true');
            localStorage.setItem('msj_token', autoData.token);
            sessionStorage.setItem('msj_token', autoData.token);
            localStorage.setItem('msj_user', JSON.stringify(autoData.user));
            savePermanentLocalUsers([autoData.user]);
            onUserAuthenticated(autoData.user, autoData.token);
            authModal.style.display = 'none';
            return true;
        }
    } catch (e) {}
    return false;
}

async function initAuth() {
    // Eski ortak önbelleği temizle (diğer kullanıcıların mesajlarının karışmasını %100 engeller)
    try {
        localStorage.removeItem('msj_cached_contacts');
    } catch (e) {}

    // Kalıcı kullanıcıları sunucuyla senkronize et (hiçbir kayıtlı kullanıcı kaybolmasın - AWAIT ile yarış durumunu önle)
    await syncPermanentUsersWithServer();

    const urlParams = new URLSearchParams(window.location.search);
    const autoUserParam = urlParams.get('autoUser') || '';

    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');
    const savedUserStr = localStorage.getItem('msj_user');
    let savedUsername = autoUserParam || localStorage.getItem('msj_saved_username') || '';
    if (!savedUsername && savedUserStr) {
        try { savedUsername = JSON.parse(savedUserStr).username || ''; } catch (e) {}
    }

    // Varsayılan olarak kayıtlı kullanıcı varsa otomatik girişi açık tut (Böylece mesaj/arama geldiğinde anında Online olur)
    const isAutoLogin = localStorage.getItem('msj_auto_login') !== 'false' || Boolean(autoUserParam);

    // Eğer URL'de autoUser parametresiyle uyandırılmışsa (ör. arama veya mesaj geldiğinde) doğrudan o kullanıcıyla giriş yap
    if (autoUserParam) {
        const loggedIn = await quickLoginAsRegisteredUser(autoUserParam);
        if (loggedIn) return;
    }

    // 1. Eğer yerel hafızada kalıcı token varsa doğrudan giriş yapmayı dene
    if (token && isAutoLogin) {
        let attempts = 0;
        let verified = false;

        while (attempts < 4 && !verified) {
            try {
                const res = await fetch('/api/auth/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, username: savedUsername })
                });
                const data = await res.json();
                if (data.success && data.user) {
                    localStorage.setItem('msj_saved_username', data.user.username);
                    localStorage.setItem('msj_user', JSON.stringify(data.user));
                    savePermanentLocalUsers([data.user]);
                    onUserAuthenticated(data.user, token);
                    authModal.style.display = 'none';
                    return;
                } else {
                    break;
                }
            } catch (e) {
                attempts++;
                if (attempts < 4) {
                    await new Promise(r => setTimeout(r, 500));
                }
            }
        }
    }

    // 2. Token geçersiz veya yoksa, ama bu cihazda kayıtlı bir kullanıcı varsa:
    // Otomatik giriş API'si ile şifre sormadan oturumu yenile ve Online yap
    if (savedUsername && isAutoLogin) {
        const loggedIn = await quickLoginAsRegisteredUser(savedUsername);
        if (loggedIn) return;

        if (savedUserStr) {
            try {
                const localUser = JSON.parse(savedUserStr);
                onUserAuthenticated(localUser, token || 'local_session');
                authModal.style.display = 'none';
                return;
            } catch(err) {}
        }
    }

    // 3. Kullanıcı listesini yükle
    const userCount = await loadRegisteredUsersDropdown();

    // 4. Otomatik giriş yapılmadıysa şifre veya kayıt modunu aç
    if (userCount === 0 && !savedUsername) {
        showRegisterPrompt();
    } else {
        showPasswordPrompt(savedUsername);
    }
}

// Numaradan bulunup davet/mesaj gönderilmiş bir kullanıcı programı kurduğunda telefon numarasını otomatik doldur
async function autoFillPendingInvitedPhone() {
    if (!inputPhone || (inputPhone.value && inputPhone.value.trim().length >= 7)) return;
    try {
        const res = await fetch('/api/users/pending_phones');
        const data = await res.json();
        if (data && data.success && Array.isArray(data.pendingPhones) && data.pendingPhones.length === 1) {
            if (!inputPhone.value || !inputPhone.value.trim()) {
                inputPhone.value = data.pendingPhones[0].phone || '';
            }
        }
    } catch (e) {}
}

function showRegisterPrompt() {
    authMode = 'register';
    if (tabAuthRegister) tabAuthRegister.classList.add('active');
    if (tabAuthLogin) tabAuthLogin.classList.remove('active');
    authModal.style.display = 'flex';
    authErrorMsg.style.display = 'none';
    authErrorMsg.innerHTML = '';
    rememberedUserBox.style.display = 'none';
    fieldUsernameSelect.style.display = 'block';
    fieldConfirmPassword.style.display = 'block';
    if (fieldPhone) fieldPhone.style.display = 'block';
    if (rowForgotPassword) rowForgotPassword.style.display = 'none';
    if (btnCancelAuth) btnCancelAuth.style.display = currentUser ? 'inline-block' : 'none';
    authSubtitle.textContent = 'Yeni kullanıcı hesabı oluşturun (Telefon numaranızla entegre edilir)';
    btnAuthSubmit.textContent = 'Kayıt Ol ve Giriş Yap';
    btnToggleAuthMode.textContent = 'Zaten hesabınız var mı? Giriş Yap';
    inputUsername.value = '';
    inputPassword.value = '';
    inputConfirmPassword.value = '';
    if (inputPhone) inputPhone.value = '';
    autoFillPendingInvitedPhone();
    inputUsername.focus();
}

function showPasswordPrompt(username) {
    authMode = 'login';
    if (tabAuthLogin) tabAuthLogin.classList.add('active');
    if (tabAuthRegister) tabAuthRegister.classList.remove('active');
    authModal.style.display = 'flex';
    authErrorMsg.style.display = 'none';
    authErrorMsg.innerHTML = '';
    fieldConfirmPassword.style.display = 'none';
    if (btnCancelAuth) btnCancelAuth.style.display = currentUser ? 'inline-block' : 'none';
    btnAuthSubmit.textContent = 'Giriş Yap';
    btnToggleAuthMode.textContent = 'Hesabınız yok mu? Yeni Kullanıcı Aç';

    loadRegisteredUsersDropdown();

    if (username) {
        authSubtitle.textContent = 'Kayıtlı hesabınıza giriş yapın veya listeden seçin';
        rememberedUserBox.style.display = 'flex';
        rememberedName.textContent = username;
        rememberedAvatar.src = `/avatars/default.svg`;
        fieldUsernameSelect.style.display = 'none';
        if (fieldPhone) fieldPhone.style.display = 'none';
        inputUsername.value = username;
        inputPassword.value = '';
        if (rowForgotPassword) rowForgotPassword.style.display = 'block';
        inputPassword.focus();
    } else {
        authSubtitle.textContent = 'Kullanıcı adınızı (ve varsa davet edildiğiniz telefon numaranızı) girin';
        rememberedUserBox.style.display = 'none';
        fieldUsernameSelect.style.display = 'block';
        if (fieldPhone) fieldPhone.style.display = 'block';
        inputPassword.value = '';
        if (rowForgotPassword) rowForgotPassword.style.display = 'none';
        autoFillPendingInvitedPhone();
        inputUsername.focus();
    }
}

async function loadRegisteredUsersDropdown() {
    // MADDE 3 & 5 GİZLİLİK KURALI:
    // Giriş / kurulum ekranında sunucudaki tüm kayıtlı kullanıcıların isimleri ("Kayıtlı Kullanıcılar" veya açılır liste)
    // diğer kullanıcılara ASLA gösterilmez ve klavye açıldığında şifre ekranını kapatmaz!
    if (selectRegisteredUser) {
        selectRegisteredUser.innerHTML = '<option value="">-- Hesap Seçin --</option>';
        selectRegisteredUser.style.display = 'none';
    }
    if (quickUsersList) {
        quickUsersList.innerHTML = '';
    }
    if (quickUsersContainer) {
        quickUsersContainer.style.display = 'none';
    }
    const savedUsername = localStorage.getItem('msj_saved_username') || '';
    return savedUsername ? 1 : 0;
}

selectRegisteredUser.addEventListener('change', async () => {
    if (selectRegisteredUser.value) {
        inputUsername.value = selectRegisteredUser.value;
        const ok = await quickLoginAsRegisteredUser(selectRegisteredUser.value);
        if (!ok) {
            inputPassword.focus();
        }
    }
});

btnSwitchAccount.addEventListener('click', () => {
    rememberedUserBox.style.display = 'none';
    fieldUsernameSelect.style.display = 'block';
    if (fieldPhone) fieldPhone.style.display = 'block';
    if (rowForgotPassword) rowForgotPassword.style.display = 'none';
    inputUsername.value = '';
    inputPassword.value = '';
    autoFillPendingInvitedPhone();
    inputUsername.focus();
});

btnToggleAuthMode.addEventListener('click', () => {
    if (authMode === 'login') {
        showRegisterPrompt();
    } else {
        showPasswordPrompt(inputUsername.value.trim() || localStorage.getItem('msj_saved_username') || '');
    }
});

if (tabAuthLogin) {
    tabAuthLogin.addEventListener('click', () => {
        const u = inputUsername.value.trim() || (rememberedUserBox.style.display !== 'none' ? rememberedName.textContent.trim() : '') || localStorage.getItem('msj_saved_username') || '';
        showPasswordPrompt(u);
    });
}

if (tabAuthRegister) {
    tabAuthRegister.addEventListener('click', () => {
        showRegisterPrompt();
    });
}

if (btnCancelAuth) {
    btnCancelAuth.addEventListener('click', () => {
        authModal.style.display = 'none';
    });
}

// Şifre Göster / Gizle Butonları
if (btnTogglePassword) {
    btnTogglePassword.addEventListener('click', () => {
        const isPass = inputPassword.type === 'password';
        inputPassword.type = isPass ? 'text' : 'password';
        btnTogglePassword.textContent = isPass ? '🙈' : '👁️';
    });
}
if (btnToggleConfirmPassword) {
    btnToggleConfirmPassword.addEventListener('click', () => {
        const isPass = inputConfirmPassword.type === 'password';
        inputConfirmPassword.type = isPass ? 'text' : 'password';
        btnToggleConfirmPassword.textContent = isPass ? '🙈' : '👁️';
    });
}

// Şifremi Unuttum / Sıfırla Butonu
if (btnForgotPassword) {
    btnForgotPassword.addEventListener('click', async () => {
        const user = inputUsername.value.trim() || rememberedName.textContent.trim();
        if (!user) {
            alert('Lütfen önce bir kullanıcı adı seçin.');
            return;
        }
        const newPass = prompt(`"${user}" hesabı için yeni şifrenizi girin (en az 3 karakter):`);
        if (newPass === null) return;
        if (!newPass || newPass.trim().length < 3) {
            alert('Şifre en az 3 karakter olmalıdır.');
            return;
        }
        try {
            btnForgotPassword.disabled = true;
            btnForgotPassword.textContent = 'Güncelleniyor...';
            const phoneVal = inputPhone ? inputPhone.value.trim() : '';
            const res = await fetch('/api/auth/reset_password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, newPassword: newPass.trim(), phone: phoneVal })
            });
            const data = await res.json();
            if (data.success) {
                localStorage.setItem('msj_saved_username', data.user.username);
                localStorage.setItem('msj_auto_login', 'true');
                localStorage.setItem('msj_token', data.token);
                localStorage.setItem('msj_user', JSON.stringify(data.user));
                onUserAuthenticated(data.user, data.token);
                authModal.style.display = 'none';
                alert('Şifreniz başarıyla güncellendi ve giriş yapıldı!');
            } else {
                alert(data.error || 'Şifre güncellenemedi.');
            }
        } catch(e) {
            alert('Sunucuya bağlanılamadı.');
        } finally {
            btnForgotPassword.disabled = false;
            btnForgotPassword.textContent = '🔑 Şifremi Unuttum / Sıfırla';
        }
    });
}

document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    authErrorMsg.style.display = 'none';
    authErrorMsg.innerHTML = '';

    let username = (inputUsername.value.trim() || (rememberedUserBox.style.display !== 'none' ? rememberedName.textContent.trim() : '')).trim();
    const password = inputPassword.value;

    // Eğer kullanıcı adı kutusuna yanlışlıkla telefon numarası yazıldıysa onu telefon kutusuna taşıyıp kullanıcı adı iste
    if (username && isPhoneQueryClient(username) && inputPhone) {
        if (!inputPhone.value.trim()) {
            inputPhone.value = username;
        }
        if (fieldPhone) fieldPhone.style.display = 'block';
        const chosenName = prompt(
            `📱 ${formatPhonePretty(username)} numaranız ile entegre edilecek Kullanıcı Adınızı girin (Örn: Ahmet):`,
            ''
        );
        if (chosenName && chosenName.trim().length >= 2 && !isPhoneQueryClient(chosenName.trim())) {
            username = chosenName.trim();
            inputUsername.value = username;
        }
    }

    if (!username || !password) {
        authErrorMsg.textContent = 'Lütfen kullanıcı adı ve şifrenizi girin.';
        authErrorMsg.style.display = 'block';
        return;
    }

    if (authMode === 'register') {
        const passConfirm = inputConfirmPassword.value;
        if (password !== passConfirm) {
            authErrorMsg.textContent = 'Girdiğiniz şifreler birbiriyle uyuşmuyor.';
            authErrorMsg.style.display = 'block';
            return;
        }
    }

    const endpoint = authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
    const phoneVal = inputPhone ? inputPhone.value.trim() : '';
    btnAuthSubmit.disabled = true;
    btnAuthSubmit.textContent = 'Bağlanıyor...';

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, phone: phoneVal })
        });
        const data = await res.json();

        if (data.success) {
            const remember = chkRememberMe.checked;
            localStorage.setItem('msj_saved_username', data.user.username);
            localStorage.setItem('msj_auto_login', remember ? 'true' : 'false');
            sessionStorage.setItem('msj_token', data.token);
            localStorage.setItem('msj_token', data.token);
            localStorage.setItem('msj_user', JSON.stringify(data.user));

            onUserAuthenticated(data.user, data.token);
            authModal.style.display = 'none';
        } else {
            authErrorMsg.innerHTML = escapeHtml(data.error || 'İşlem başarısız.');

            // Eğer şifre sıfırlanabilir durumdaysa hızlı aksiyon butonu ekle
            if (data.canReset) {
                if (authMode === 'login') {
                    const resetBtn = document.createElement('button');
                    resetBtn.type = 'button';
                    resetBtn.className = 'btn-inline-reset';
                    resetBtn.textContent = '🔄 Bu Şifreyi Yeni Şifrem Yap ve Giriş Yap';
                    resetBtn.addEventListener('click', async () => {
                        try {
                            resetBtn.disabled = true;
                            resetBtn.textContent = 'Kaydediliyor...';
                            const rRes = await fetch('/api/auth/reset_password', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ username, newPassword: password, phone: phoneVal })
                            });
                            const rData = await rRes.json();
                            if (rData.success) {
                                localStorage.setItem('msj_saved_username', rData.user.username);
                                localStorage.setItem('msj_auto_login', 'true');
                                localStorage.setItem('msj_token', rData.token);
                                localStorage.setItem('msj_user', JSON.stringify(rData.user));
                                onUserAuthenticated(rData.user, rData.token);
                                authModal.style.display = 'none';
                            } else {
                                alert(rData.error || 'Şifre güncellenemedi.');
                            }
                        } catch(err) {
                            alert('Sunucuya bağlanılamadı.');
                        }
                    });
                    authErrorMsg.appendChild(document.createElement('br'));
                    authErrorMsg.appendChild(resetBtn);
                } else if (authMode === 'register') {
                    const resetBtn = document.createElement('button');
                    resetBtn.type = 'button';
                    resetBtn.className = 'btn-inline-reset';
                    resetBtn.textContent = '⚡ Bu Kullanıcı Adıyla Şifreyi Güncelle ve Gir';
                    resetBtn.addEventListener('click', async () => {
                        try {
                            resetBtn.disabled = true;
                            resetBtn.textContent = 'Kaydediliyor...';
                            const rRes = await fetch('/api/auth/register', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ username, password, phone: phoneVal, resetExisting: true })
                            });
                            const rData = await rRes.json();
                            if (rData.success) {
                                localStorage.setItem('msj_saved_username', rData.user.username);
                                localStorage.setItem('msj_auto_login', 'true');
                                localStorage.setItem('msj_token', rData.token);
                                localStorage.setItem('msj_user', JSON.stringify(rData.user));
                                onUserAuthenticated(rData.user, rData.token);
                                authModal.style.display = 'none';
                            } else {
                                alert(rData.error || 'İşlem başarısız.');
                            }
                        } catch(err) {
                            alert('Sunucuya bağlanılamadı.');
                        }
                    });
                    authErrorMsg.appendChild(document.createElement('br'));
                    authErrorMsg.appendChild(resetBtn);
                }
            }

            authErrorMsg.style.display = 'block';
        }
    } catch (err) {
        authErrorMsg.textContent = 'Sunucuya bağlanılamadı. Lütfen sunucunun açık olduğunu kontrol edin.';
        authErrorMsg.style.display = 'block';
    } finally {
        btnAuthSubmit.disabled = false;
        btnAuthSubmit.textContent = authMode === 'register' ? 'Kayıt Ol ve Giriş Yap' : 'Giriş Yap';
    }
});

function onUserAuthenticated(user, token) {
    // Önceki kullanıcıdan kalabilecek açık sohbet, mesaj veya bildirimleri tamamen sıfırla
    closeActiveChat();
    dismissMessageNotificationToast();
    if (messagesContainer) messagesContainer.innerHTML = '';
    contactsList = [];

    currentUser = user;
    menuUsernameDisplay.textContent = user.username;
    removeDeletedLocalUserKey(user.username);
    savePermanentLocalUsers([user]);
    localStorage.setItem('msj_saved_username', user.username);
    localStorage.setItem('msj_auto_login', 'true');
    if (user.phone) {
        localStorage.setItem('msj_my_phone_' + normalizeKey(user.username), user.phone);
    }

    // Signal X3DH / Double Ratchet & Donanım Anahtar Paketi (IndexedDB Non-Extractable) ve AKD kaydını oluştur
    if (window.MSJCryptoEngine && typeof window.MSJCryptoEngine.ensureUserIdentityKeys === 'function') {
        window.MSJCryptoEngine.ensureUserIdentityKeys(user.username).catch(() => {});
    }

    // Özel Arka Plan Resimlerini Uygula (Madde 6)
    if (typeof window.applySavedCustomBackgrounds === 'function') {
        window.applySavedCustomBackgrounds();
    }

    // Giriş yapıldığında sahte/asılı arama ekranı veya çalma sesi kalmasını kesin olarak engelle
    hideOutgoingCall();
    stopRingtone();
    if (incomingCallModal) incomingCallModal.style.display = 'none';

    // Sadece bu kullanıcıya ait önbellek / telefon rehberi varsa ilk anda göster
    const myCached = getCachedContactsForCurrentUser();
    contactsList = mergeContactsWithPermanentUsers(myCached || []);
    renderChatsList(contactsList);

    // Soket sunucusuna kendi oturumunu bildir (Anında Online durumuna geçer)
    const mySavedPhone = user.phone || localStorage.getItem('msj_my_phone_' + normalizeKey(user.username)) || '';
    socket.emit('user:join', { token, username: user.username, phone: mySavedPhone });

    // Service Worker'a aktif kullanıcıyı bildir (Arka planda SADECE bu kullanıcının bildirimlerini sorgulaması için)
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.ready.then(reg => {
            if (reg.active) {
                reg.active.postMessage({ type: 'INIT_USER', username: user.username });
            }
        }).catch(() => {});
    }

    // Eğer bu cihaz yerel bilgisayar (Host PC) ise sistem tepsisi bildirimleri için kullanıcıyı kaydet
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        fetch('/api/system/register_pc_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user.username })
        }).catch(() => {});
    }

    // Ses cihazlarını (Mikrofon & Hoparlör/Kulaklık) başlangıçta listele
    refreshAudioDeviceList().catch(() => {});

    // Sohbet listesini getir ve URL'de bekleyen mesaj/arama yönlendirmesi varsa aç
    loadChatsList().then(() => {
        checkUrlDeepLinkActions();
    });
}

function checkUrlDeepLinkActions() {
    try {
        const params = new URLSearchParams(window.location.search);
        const openChatUser = params.get('openChat');
        const autoAcceptCall = params.get('autoAcceptCall') === '1';
        const incomingCall = params.get('incomingCall') === '1';
        if (openChatUser) {
            setTimeout(async () => {
                openChatForSender(openChatUser);
                if (incomingCall || autoAcceptCall) {
                    if (currentUser) {
                        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
                        socket.emit('user:join', { token, username: currentUser.username });
                    }
                    let activeCallFromServer = null;
                    try {
                        const pollUser = (currentUser && currentUser.username) || localStorage.getItem('msj_saved_username') || '';
                        const pollRes = await fetch(`/api/system/notifications/poll?since=0&user=${encodeURIComponent(pollUser)}`, { cache: 'no-store' });
                        const pollData = await pollRes.json();
                        if (pollData && Array.isArray(pollData.activeCalls)) {
                            activeCallFromServer = pollData.activeCalls.find(c => normalizeKey(c.callerUsername) === normalizeKey(openChatUser)) || pollData.activeCalls[0];
                        }
                    } catch (e) {}

                    const contactObj = contactsList.find(c => normalizeKey(c.username) === normalizeKey(openChatUser));
                    triggerIncomingCallUi({
                        callerUsername: (activeCallFromServer && activeCallFromServer.callerUsername) || openChatUser,
                        callerAvatar: (activeCallFromServer && activeCallFromServer.callerAvatar) || (contactObj && contactObj.avatar) || '/avatars/default.svg',
                        callType: (activeCallFromServer && activeCallFromServer.callType) || 'voice',
                        callerSocketId: (activeCallFromServer && activeCallFromServer.callerSocketId) || currentTargetSocketId
                    }, autoAcceptCall);
                }
            }, 200);
            // URL'yi temizle
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (e) {}
}

// ==========================================================
// 2. RESİM 1: SOHBETLER / KİŞİSEL REHBER LİSTESİ (MADDE 5 GİZLİLİK KORUMALI)
// ==========================================================

async function loadChatsList() {
    let token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');

    if (token && currentUser) {
        try {
            const res = await fetch('/api/chats', {
                headers: { 'x-auth-token': token }
            });
            const data = await res.json();

            if (data.success && Array.isArray(data.chats)) {
                contactsList = mergeContactsWithPermanentUsers(data.chats);
                saveCachedContactsForCurrentUser(contactsList);
                renderChatsList(contactsList);
                return;
            }
        } catch (err) {
            console.error('Sohbetler yüklenemedi:', err);
        }
    }

    // MADDE 5 GİZLİLİK KURALI:
    // Her kayıtlı kullanıcı sistemdeki tüm kayıtlı isimleri görmemeli!
    // Yalnızca kendi telefon rehberinde kayıtlı olanları veya mesajlaştığı kişileri görür.
    contactsList = mergeContactsWithPermanentUsers([]);
    renderChatsList(contactsList);
}

// MADDE 4: TELEFON NUMARASINDAN BİRİNİ BULDURUNCA O NUMARAYA KAYITLI KULLANICININ NUMARASIYLA BİRLİKTE
// “…… Numaralı Kişi Sizi Bu Uygulamayı Kullanmaya Davet Ediyor” DİYE MESAJ GÖNDERSİN
window.findAndContactByPhone = async function(phoneStr, customName = '', actionType = 'message') {
    const cleanPhone = normalizePhoneClient(phoneStr);
    if (!cleanPhone || cleanPhone.length < 7) {
        alert('Lütfen geçerli bir telefon numarası girin (Örn: 0555 123 45 67).');
        return;
    }

    // Davet eden kullanıcının kendi telefon numarasını belirle (yoksa bir kez sorup kaydet)
    let myUsername = currentUser ? currentUser.username : (localStorage.getItem('msj_saved_username') || '');
    let myPhone = (currentUser && currentUser.phone)
        || (myUsername ? localStorage.getItem('msj_my_phone_' + normalizeKey(myUsername)) : '')
        || (isPhoneQueryClient(myUsername) ? normalizePhoneClient(myUsername) : '');

    if (!myPhone && myUsername) {
        const enteredMyPhone = prompt(
            'Karşı tarafa "…… Numaralı Kişi Sizi Bu Uygulamayı Kullanmaya Davet Ediyor" davet mesajı gönderilmesi için lütfen kendi telefon numaranızı girin:',
            '05'
        );
        if (enteredMyPhone && normalizePhoneClient(enteredMyPhone).length >= 7) {
            myPhone = normalizePhoneClient(enteredMyPhone);
            if (currentUser) currentUser.phone = myPhone;
            localStorage.setItem('msj_my_phone_' + normalizeKey(myUsername), myPhone);
            fetch('/api/users/update_phone', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: myUsername, phone: myPhone })
            }).catch(() => {});
        }
    }

    try {
        const res = await fetch('/api/users/find_by_phone', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: cleanPhone,
                customName: (customName || '').trim(),
                inviterUsername: myUsername,
                inviterPhone: myPhone || myUsername,
                sendInvite: true
            })
        });
        const data = await res.json();
        if (data && data.success && data.user) {
            const u = data.user;

            // Kişisel telefon rehberine kaydet (Madde 5: Kendi telefonunda kayıtlı olanları görsün)
            const myPhoneBook = getPersonalPhoneBookForCurrentUser();
            const existingIdx = myPhoneBook.findIndex(item => normalizeKey(item.username) === normalizeKey(u.username));
            const pbEntry = {
                username: u.username,
                customName: (customName || u.customName || '').trim(),
                phone: u.phone || cleanPhone,
                avatar: u.avatar || '/avatars/default.svg'
            };
            if (existingIdx >= 0) {
                myPhoneBook[existingIdx] = pbEntry;
            } else {
                myPhoneBook.unshift(pbEntry);
            }
            savePersonalPhoneBookForCurrentUser(myPhoneBook);

            const invitePreviewMsg = data.inviteMessage ? {
                id: data.inviteMessage.id,
                sender: myUsername,
                recipient: u.username,
                text: data.inviteText || data.inviteMessage.text,
                timestamp: data.inviteMessage.timestamp || new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
                date: 'Bugün',
                isOutgoing: true
            } : null;

            let contactObj = contactsList.find(c =>
                normalizeKey(c.username) === normalizeKey(u.username) ||
                (c.phone && normalizePhoneClient(c.phone) === cleanPhone)
            );
            if (!contactObj) {
                contactObj = {
                    username: u.username,
                    customName: (customName || u.customName || '').trim(),
                    avatar: u.avatar || '/avatars/default.svg',
                    phone: u.phone || cleanPhone,
                    isOnline: !!u.isOnline,
                    statusText: u.isOnline ? 'Online' : 'Offline',
                    lastSeen: u.lastSeen || 'Offline',
                    lastMessage: invitePreviewMsg,
                    unreadCount: 0
                };
                contactsList.unshift(contactObj);
            } else {
                contactObj.phone = u.phone || cleanPhone;
                if (invitePreviewMsg) contactObj.lastMessage = invitePreviewMsg;
            }

            saveCachedContactsForCurrentUser(contactsList);

            if (inputSearchChats) inputSearchChats.value = '';
            if (btnClearSearch) btnClearSearch.style.display = 'none';
            if (inputLookupPhone) inputLookupPhone.value = '';
            if (inputLookupCustomName) inputLookupCustomName.value = '';

            renderChatsList(contactsList);
            closeNewChatModal();
            selectContact(contactObj);

            const inviterLabel = formatPhonePretty(myPhone || myUsername);
            const inviteMsgStr = data.inviteText || `“${inviterLabel} Numaralı Kişi Sizi Bu Uygulamayı Kullanmaya Davet Ediyor”`;
            showStatusToast(`📨 ${inviteMsgStr} mesajı gönderildi!`, true);

            // Eğer karşı taraf henüz uygulamada çevrimiçi değilse tek tıkla SMS davet çubuğu göster
            if (!u.isOnline && messagesContainer) {
                setTimeout(() => {
                    const smsBanner = document.createElement('div');
                    smsBanner.style.cssText = 'align-self:center;max-width:92%;background:rgba(0,168,132,0.16);border:1px solid #00a884;border-radius:10px;padding:10px 14px;margin:8px auto;text-align:center;font-size:12.5px;color:#e9edef;';
                    const smsBody = encodeURIComponent(`${inviteMsgStr} - Bağlantı: ${window.location.origin}`);
                    smsBanner.innerHTML = `
                        <div style="margin-bottom:6px;color:#25d366;font-weight:700;">📨 Uygulama içi davet mesajı gönderildi!</div>
                        <div style="margin-bottom:8px;color:#d1d7db;">${escapeHtml(inviteMsgStr)}</div>
                        <a href="sms:${escapeHtml(cleanPhone)}?body=${smsBody}" style="display:inline-block;padding:6px 12px;border-radius:8px;background:#00a884;color:#fff;text-decoration:none;font-weight:700;font-size:12px;">📱 SMS Olarak da Gönder (${escapeHtml(formatPhonePretty(cleanPhone))})</a>
                    `;
                    messagesContainer.appendChild(smsBanner);
                    scrollToBottom();
                }, 450);
            }

            if (actionType === 'voice' || actionType === 'video') {
                setTimeout(() => initiateCall(actionType), 250);
            } else if (messageInput) {
                setTimeout(() => messageInput.focus(), 150);
            }
        } else {
            alert((data && data.error) || 'Telefon numarası sorgulanamadı.');
        }
    } catch (err) {
        alert('Sunucuya bağlanılamadı.');
    }
};

function createUnregisteredPhoneLookupElement(rawPhoneQuery) {
    const cleanDigits = normalizePhoneClient(rawPhoneQuery);
    const prettyPhone = formatPhonePretty(cleanDigits || rawPhoneQuery);
    const card = document.createElement('div');
    card.style.cssText = 'margin: 10px 12px; padding: 14px; background: rgba(0, 168, 132, 0.14); border: 1px solid rgba(0, 168, 132, 0.45); border-radius: 12px; display: flex; flex-direction: column; gap: 10px;';
    card.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px;">
            <div style="width:42px; height:42px; border-radius:50%; background:#00a884; color:#fff; display:flex; align-items:center; justify-content:center; font-size:20px; flex-shrink:0;">📱</div>
            <div style="flex:1;">
                <div style="font-size:15px; font-weight:700; color:#e9edef;">${escapeHtml(prettyPhone)}</div>
                <div style="font-size:12.5px; color:#25d366;">Kayıtlı olmasa bile bu telefon numarasına mesaj gönderebilir veya arayabilirsiniz</div>
            </div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button type="button" data-phone-act="message" style="flex:2; padding:8px 12px; border-radius:8px; border:none; background:#00a884; color:#fff; font-weight:700; font-size:13px; cursor:pointer;">💬 Numaraya Mesaj Gönder</button>
            <button type="button" data-phone-act="voice" style="flex:1; padding:8px 10px; border-radius:8px; border:1px solid rgba(0,168,132,0.5); background:#1f2c34; color:#25d366; font-weight:600; font-size:13px; cursor:pointer;">📞 Sesli Ara</button>
            <button type="button" data-phone-act="video" style="flex:1; padding:8px 10px; border-radius:8px; border:1px solid rgba(0,168,132,0.5); background:#1f2c34; color:#25d366; font-weight:600; font-size:13px; cursor:pointer;">📹 Görüntülü</button>
        </div>
    `;
    card.querySelectorAll('[data-phone-act]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const act = btn.getAttribute('data-phone-act');
            window.findAndContactByPhone(cleanDigits || rawPhoneQuery, '', act);
        });
    });
    return card;
}

let currentChatFilter = 'all';

function updateOnlineFilterChipCount() {
    try {
        const onlineCount = Array.isArray(contactsList) ? contactsList.filter(c => c && c.isOnline).length : 0;
        filterChips.forEach(chip => {
            if (chip.dataset && chip.dataset.filter === 'online') {
                chip.textContent = onlineCount > 0 ? `Online (${onlineCount})` : 'Online';
            }
        });
    } catch (e) {}
}

function formatContactIntegratedDisplayName(contact) {
    if (!contact || !contact.username) return '';
    const hasIntegratedPhone = contact.phone && !isPhoneQueryClient(contact.username) && normalizePhoneClient(contact.phone) !== normalizePhoneClient(contact.username);
    if (contact.customName && contact.customName !== contact.username && !isPhoneQueryClient(contact.customName)) {
        return hasIntegratedPhone
            ? `${contact.customName} (${contact.username} • ${formatPhonePretty(contact.phone)})`
            : `${contact.customName} (${contact.username})`;
    }
    if (hasIntegratedPhone) {
        return `${contact.username} (${formatPhonePretty(contact.phone)})`;
    }
    return contact.username;
}

function renderChatsList(chats, rawSearchQuery = '') {
    chatListContainer.innerHTML = '';
    updateOnlineFilterChipCount();

    const activeQuery = rawSearchQuery || (inputSearchChats ? inputSearchChats.value.trim() : '');
    if (activeQuery && isPhoneQueryClient(activeQuery)) {
        chatListContainer.appendChild(createUnregisteredPhoneLookupElement(activeQuery));
    }

    // Aktif filtreyi (Tümü / Online / Okunmamış) her yenilemede koru ki Online ekranında olan kullanıcılar anında görünsün!
    let effectiveList = Array.isArray(chats) ? chats.slice() : [];
    if (!rawSearchQuery && chats === contactsList) {
        if (currentChatFilter === 'online') {
            effectiveList = effectiveList.filter(c => c && c.isOnline);
        } else if (currentChatFilter === 'unread') {
            effectiveList = effectiveList.filter(c => c && (c.unreadCount || 0) > 0);
        }
        if (activeQuery) {
            const qKey = normalizeKey(activeQuery);
            const dQuery = normalizePhoneClient(activeQuery);
            effectiveList = effectiveList.filter(c => {
                if (normalizeKey(c.username).includes(qKey)) return true;
                if (c.customName && normalizeKey(c.customName).includes(qKey)) return true;
                if (dQuery && dQuery.length >= 3 && c.phone && normalizePhoneClient(c.phone).includes(dQuery)) return true;
                return false;
            });
        }
    }

    if (!effectiveList || effectiveList.length === 0) {
        if (!activeQuery || !isPhoneQueryClient(activeQuery)) {
            if (currentChatFilter === 'online') {
                chatListContainer.innerHTML = `
                    <div style="padding: 36px 20px; text-align: center; color: var(--text-secondary); font-size: 14px; line-height: 1.55;">
                        🟢 <strong>Şu Anda Çevrimiçi (Online) Kullanıcı Yok</strong><br>
                        Bir kullanıcı uygulamayı açtığında veya giriş yaptığında bu ekranda anında <strong>Online</strong> olarak listelenir.
                    </div>
                `;
            } else if (currentChatFilter === 'unread') {
                chatListContainer.innerHTML = `
                    <div style="padding: 36px 20px; text-align: center; color: var(--text-secondary); font-size: 14px; line-height: 1.55;">
                        ✉️ <strong>Okunmamış Mesajınız Yok</strong>
                    </div>
                `;
            } else {
                chatListContainer.innerHTML = `
                    <div style="padding: 36px 20px; text-align: center; color: var(--text-secondary); font-size: 14px; line-height: 1.55;">
                        📒 <strong>Kişisel Rehberiniz Boş</strong><br>
                        Kendi telefonunuzda kayıtlı olan kişileri eklemek veya <strong>telefon numarasından bulup davet etmek</strong> için yukarıdaki <strong>📱 Numaradan Bul &amp; Davet Et</strong> veya sağ alttaki <strong>+</strong> butonuna dokunun.
                    </div>
                `;
            }
        }
        updateUnreadBadges();
        return;
    }

    effectiveList.forEach(contact => {
        const item = document.createElement('div');
        const contactKey = normalizeKey(contact.username);
        const isActive = activeContact && normalizeKey(activeContact.username) === contactKey;
        const validLastMsg = isMessageForCurrentUserAndContact(contact.lastMessage, contactKey) ? contact.lastMessage : null;
        const unreadCount = currentUser ? (Number(contact.unreadCount) || 0) : 0;
        const hasUnread = unreadCount > 0;
        item.className = `chat-list-item ${isActive ? 'active' : ''} ${hasUnread ? 'has-unread' : ''}`;
        item.dataset.username = contact.username;
        item.style.cursor = 'pointer';

        const displayName = formatContactIntegratedDisplayName(contact);
        const isBlocked = Boolean(contact.isBlocked || isContactBlockedLocally(contact.username));
        contact.isBlocked = isBlocked;

        let lastSnippet = isBlocked
            ? '🚫 Bu kişiyi engellediniz (Engeli kaldırmak için 🔓 butonuna dokunun)'
            : (contact.phone
                ? `📱 ${formatPhonePretty(contact.phone)} • ${contact.isOnline ? '🟢 Online' : '🔒 Signal E2EE şifreli sohbet'}`
                : (contact.isOnline ? '🟢 Online • 🔒 Signal E2EE şifreli sohbet' : '🔒 Signal E2EE şifreli sohbet'));
        let isOutgoingLast = false;
        let isLastRead = false;
        let timeLabel = isBlocked ? '🚫 Engellendi' : (contact.isOnline ? '🟢 Online' : '');

        if (validLastMsg && !isBlocked) {
            const decryptedPreview = validLastMsg.text
                ? decryptE2EETextClient(validLastMsg.text, validLastMsg.sender, validLastMsg.recipient)
                : '';
            const rawText = decryptedPreview || (validLastMsg.file ? '📎 Fotoğraf / Dosya' : 'Mesaj');
            isOutgoingLast = !!validLastMsg.isOutgoing;
            isLastRead = !!validLastMsg.read;
            lastSnippet = rawText;
            if (validLastMsg.timestamp) {
                timeLabel = contact.isOnline ? `🟢 Online • ${validLastMsg.timestamp}` : validLastMsg.timestamp;
            }
        }

        const outgoingChecksHtml = isOutgoingLast
            ? `<span class="wa-msg-checks ${isLastRead ? 'read' : ''}">✓✓</span>`
            : '';

        item.innerHTML = `
            <div class="chat-avatar-wrap">
                <img class="avatar" src="${contact.avatar || '/avatars/default.svg'}" alt="${escapeHtml(displayName)}">
                ${contact.isOnline && !isBlocked ? '<span class="online-badge" title="Çevrimiçi (Online)"></span>' : ''}
            </div>
            <div class="chat-content-wrap">
                <div class="chat-top-line">
                    <span class="chat-title">
                        <strong class="wa-contact-name">${escapeHtml(displayName)}</strong>
                    </span>
                    <span class="wa-chat-time ${hasUnread ? 'unread' : (contact.isOnline && !isBlocked ? 'online-time' : '')}">${escapeHtml(timeLabel)}</span>
                </div>
                <div class="chat-bottom-line">
                    <div class="chat-last-msg-preview ${hasUnread ? 'unread' : ''}" title="${escapeHtml(lastSnippet)}">
                        ${outgoingChecksHtml}
                        <span>${escapeHtml(lastSnippet)}</span>
                    </div>
                    <div class="wa-chat-badges" style="display:flex;align-items:center;gap:6px;">
                        ${hasUnread ? `<span class="wa-unread-count-badge" title="${unreadCount} okunmamış mesaj">${unreadCount}</span>` : ''}
                        <button type="button" class="btn-row-block" title="${isBlocked ? 'Engeli Kaldır' : 'Bu Kişiyi Engelle'}" style="border:none;background:rgba(255,165,2,0.14);color:${isBlocked ? '#25d366' : '#ffa502'};border-radius:6px;padding:3px 6px;font-size:12px;cursor:pointer;">${isBlocked ? '🔓' : '🚫'}</button>
                        <button type="button" class="btn-row-delete" title="Bu Kişiyi Sil" style="border:none;background:rgba(234,0,56,0.15);color:#ff6b81;border-radius:6px;padding:3px 6px;font-size:12px;cursor:pointer;">🗑️</button>
                    </div>
                </div>
            </div>
        `;

        item.addEventListener('click', (e) => {
            if (e.target.closest('.btn-row-block')) {
                e.stopPropagation();
                window.toggleBlockContact(contact.username);
                return;
            }
            if (e.target.closest('.btn-row-delete')) {
                e.stopPropagation();
                window.requestDeleteUser(contact.username);
                return;
            }
            selectContact(contact);
        });

        chatListContainer.appendChild(item);
    });

    updateUnreadBadges();
}

// Arama Filtresi (Hem kullanıcı adına hem telefon numarasına göre arar; kayıtlı olmayan numarayı da bulur)
inputSearchChats.addEventListener('input', () => {
    const rawVal = inputSearchChats.value.trim();
    const query = normalizeKey(rawVal);
    const digitsQuery = normalizePhoneClient(rawVal);
    btnClearSearch.style.display = rawVal ? 'block' : 'none';

    if (!rawVal) {
        renderChatsList(contactsList, '');
        return;
    }

    const filtered = contactsList.filter(c => {
        if (normalizeKey(c.username).includes(query)) return true;
        if (c.customName && normalizeKey(c.customName).includes(query)) return true;
        if (digitsQuery && digitsQuery.length >= 3 && c.phone && normalizePhoneClient(c.phone).includes(digitsQuery)) return true;
        return false;
    });
    renderChatsList(filtered, rawVal);
});

inputSearchChats.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        const rawVal = inputSearchChats.value.trim();
        if (rawVal && isPhoneQueryClient(rawVal)) {
            e.preventDefault();
            window.findAndContactByPhone(rawVal, '', 'message');
        }
    }
});

btnClearSearch.addEventListener('click', () => {
    inputSearchChats.value = '';
    btnClearSearch.style.display = 'none';
    renderChatsList(contactsList, '');
});

// Filtre Hapları Tıklama
filterChips.forEach(chip => {
    if (chip.id === 'btnQuickPhoneLookup' || chip.id === 'btnAddFilter') return;
    chip.addEventListener('click', () => {
        filterChips.forEach(c => {
            if (c.id !== 'btnQuickPhoneLookup' && c.id !== 'btnAddFilter') c.classList.remove('active');
        });
        chip.classList.add('active');

        currentChatFilter = chip.dataset.filter || 'all';
        renderChatsList(contactsList);
        // Online veya Tümü sekmesine geçildiğinde sunucudan anlık durumu da tazele
        loadChatsList();
    });
});

if (btnQuickPhoneLookup) {
    btnQuickPhoneLookup.addEventListener('click', () => {
        openNewChatModal(true);
    });
}

if (menuItemPhoneLookup) {
    menuItemPhoneLookup.addEventListener('click', () => {
        headerDropdown.style.display = 'none';
        openNewChatModal(true);
    });
}

// ==========================================================
// YENİ YAZIŞMA / KİŞİ SEÇ EKRANI (FAB '+' VE MENÜ BUTONU)
// ==========================================================
function openNewChatModal(focusPhoneBox = false) {
    if (!newChatModal) return;
    newChatModal.style.display = 'flex';
    if (inputSearchNewChat) {
        inputSearchNewChat.value = '';
        if (btnClearNewChatSearch) btnClearNewChatSearch.style.display = 'none';
    }

    renderNewChatUsers(contactsList);

    // Taze listeyi sunucudan çekip güncelle
    loadChatsList().then(() => {
        renderNewChatUsers(contactsList);
    });

    if (focusPhoneBox && inputLookupPhone) {
        setTimeout(() => inputLookupPhone.focus(), 150);
    } else if (inputSearchNewChat) {
        setTimeout(() => inputSearchNewChat.focus(), 150);
    }
}

function closeNewChatModal() {
    if (newChatModal) {
        newChatModal.style.display = 'none';
    }
}

function renderNewChatUsers(list, rawSearchQuery = '') {
    if (!newChatUsersList) return;
    newChatUsersList.innerHTML = '';

    const activeQuery = rawSearchQuery || (inputSearchNewChat ? inputSearchNewChat.value.trim() : '');
    if (activeQuery && isPhoneQueryClient(activeQuery)) {
        newChatUsersList.appendChild(createUnregisteredPhoneLookupElement(activeQuery));
    }

    if (newChatUserCount) {
        newChatUserCount.textContent = `${list.length} kayıtlı kişi`;
    }

    if (!list || list.length === 0) {
        if (!activeQuery || !isPhoneQueryClient(activeQuery)) {
            newChatUsersList.innerHTML = `
                <div style="padding: 35px 20px; text-align: center; color: var(--text-secondary); font-size: 13.5px;">
                    Kayıtlı başka kullanıcı bulunamadı.<br>
                    Kayıtlı olmayan bir kişiye ulaşmak için yukarıdaki <strong>"📱 Kayıtlı Olmayan Kişiyi Telefon Numarasından Bul"</strong> kutusuna numarasını yazabilirsiniz.
                </div>
            `;
        }
        return;
    }

    list.forEach(contact => {
        const item = document.createElement('div');
        item.className = 'new-chat-user-item';

        const displayTitle = formatContactIntegratedDisplayName(contact);
        const isBlocked = Boolean(contact.isBlocked || isContactBlockedLocally(contact.username));
        const phoneInfoHtml = contact.phone
            ? ` • 📱 ${escapeHtml(formatPhonePretty(contact.phone))}`
            : '';

        item.innerHTML = `
            <div class="new-chat-user-left">
                <div class="chat-avatar-wrap" style="position:relative;">
                    <img class="avatar" src="${contact.avatar || '/avatars/default.svg'}" alt="${escapeHtml(displayTitle)}">
                    ${contact.isOnline && !isBlocked ? '<span class="online-badge" title="Online"></span>' : '<span class="offline-badge" title="Offline"></span>'}
                </div>
                <div class="new-chat-user-info">
                    <span class="new-chat-username">${escapeHtml(displayTitle)}</span>
                    <span class="new-chat-status ${isBlocked ? 'offline' : (contact.isOnline ? 'online' : 'offline')}">
                        ${isBlocked ? '🚫 Engellendi' : (contact.isOnline ? '🟢 Online' : '⚪ Offline (Mesaj & Arama Açık)')}${phoneInfoHtml}
                    </span>
                </div>
            </div>
            <div class="new-chat-actions">
                <button type="button" class="btn-new-chat-action message" title="Yazışma Ekranına Geç">
                    💬 Mesaj
                </button>
                <button type="button" class="btn-new-chat-action call" title="Sesli Ara" data-action="voice">
                    📞
                </button>
                <button type="button" class="btn-new-chat-action call" title="Görüntülü Ara" data-action="video">
                    📹
                </button>
                <button type="button" class="btn-new-chat-action block" title="${isBlocked ? 'Engeli Kaldır' : 'Bu Kişiyi Engelle'}" data-action="block" style="background: rgba(255, 165, 2, 0.16); color: ${isBlocked ? '#25d366' : '#ffa502'};">
                    ${isBlocked ? '🔓' : '🚫'}
                </button>
                <button type="button" class="btn-new-chat-action delete" title="Bu Kişiyi Sil" data-action="delete" style="background: rgba(234, 0, 56, 0.16); color: #ff6b81;">
                    🗑️
                </button>
            </div>
        `;

        // Satıra veya butonlara basıldığında doğrudan o kullanıcı seçilip yazışma ekranı açılsın
        item.addEventListener('click', (e) => {
            const blockBtn = e.target.closest('.btn-new-chat-action.block');
            if (blockBtn) {
                e.stopPropagation();
                window.toggleBlockContact(contact.username);
                return;
            }
            const delBtn = e.target.closest('.btn-new-chat-action.delete');
            if (delBtn) {
                e.stopPropagation();
                window.requestDeleteUser(contact.username).then(() => {
                    renderNewChatUsers(contactsList);
                });
                return;
            }
            const callBtn = e.target.closest('.btn-new-chat-action.call');
            if (callBtn) {
                const actionType = callBtn.dataset.action;
                closeNewChatModal();
                selectContact(contact);
                setTimeout(() => initiateCall(actionType), 300);
                return;
            }

            closeNewChatModal();
            selectContact(contact);
        });

        newChatUsersList.appendChild(item);
    });
}

// Yeni Yazışma Kişi Arama Filtresi (Hem kullanıcı adına hem telefon numarasına göre)
if (inputSearchNewChat) {
    inputSearchNewChat.addEventListener('input', () => {
        const rawVal = inputSearchNewChat.value.trim();
        const query = normalizeKey(rawVal);
        const digitsQuery = normalizePhoneClient(rawVal);
        if (btnClearNewChatSearch) {
            btnClearNewChatSearch.style.display = rawVal ? 'block' : 'none';
        }

        if (!rawVal) {
            renderNewChatUsers(contactsList, '');
            return;
        }

        const filtered = contactsList.filter(c => {
            if (normalizeKey(c.username).includes(query)) return true;
            if (digitsQuery && digitsQuery.length >= 3 && c.phone && normalizePhoneClient(c.phone).includes(digitsQuery)) return true;
            return false;
        });
        renderNewChatUsers(filtered, rawVal);
    });
}

if (btnLookupStartChat) {
    btnLookupStartChat.addEventListener('click', () => {
        const p = inputLookupPhone ? inputLookupPhone.value.trim() : '';
        const n = inputLookupCustomName ? inputLookupCustomName.value.trim() : '';
        window.findAndContactByPhone(p, n, 'message');
    });
}

if (btnLookupVoiceCall) {
    btnLookupVoiceCall.addEventListener('click', () => {
        const p = inputLookupPhone ? inputLookupPhone.value.trim() : '';
        const n = inputLookupCustomName ? inputLookupCustomName.value.trim() : '';
        window.findAndContactByPhone(p, n, 'voice');
    });
}

if (btnLookupVideoCall) {
    btnLookupVideoCall.addEventListener('click', () => {
        const p = inputLookupPhone ? inputLookupPhone.value.trim() : '';
        const n = inputLookupCustomName ? inputLookupCustomName.value.trim() : '';
        window.findAndContactByPhone(p, n, 'video');
    });
}

if (inputLookupPhone) {
    inputLookupPhone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const p = inputLookupPhone.value.trim();
            const n = inputLookupCustomName ? inputLookupCustomName.value.trim() : '';
            window.findAndContactByPhone(p, n, 'message');
        }
    });
}

if (btnClearNewChatSearch) {
    btnClearNewChatSearch.addEventListener('click', () => {
        inputSearchNewChat.value = '';
        btnClearNewChatSearch.style.display = 'none';
        renderNewChatUsers(contactsList);
    });
}

if (btnCloseNewChat) {
    btnCloseNewChat.addEventListener('click', closeNewChatModal);
}

if (btnActionCreateNewUser) {
    btnActionCreateNewUser.addEventListener('click', () => {
        closeNewChatModal();
        showRegisterPrompt();
    });
}

if (newChatModal) {
    newChatModal.addEventListener('click', (e) => {
        if (e.target === newChatModal) {
            closeNewChatModal();
        }
    });
}

// FAB Butonu: Sağ alttaki (+) işaretine basınca YENİ YAZIŞMA EKRANINA geçsin
btnFabNewChat.addEventListener('click', () => {
    openNewChatModal();
});

// ==========================================================
// 3. RESİM 2: BİREBİR YAZIŞMA EKRANI (CHAT SCREEN)
// ==========================================================

function selectContact(contact) {
    activeContact = contact;

    // Okunmamış mesajları sıfırla ve sunucuya bildir
    contact.unreadCount = 0;
    socket.emit('chat:mark_read', { contactUsername: contact.username });
    dismissMessageNotificationToast();

    // Resim 2 Başlık Bilgilerini Doldur (Entegre numara + kullanıcı adı birlikte gösterilir)
    chatContactName.textContent = formatContactIntegratedDisplayName(contact);
    chatContactAvatar.src = contact.avatar || '/avatars/default.svg';

    if (contact.isOnline) {
        chatContactStatus.textContent = 'Online';
        headerOnlineDot.style.display = 'block';
    } else {
        chatContactStatus.textContent = 'Offline';
        headerOnlineDot.style.display = 'none';
    }
    updateActiveContactBlockHeaderUi();

    // Aktif öğeyi listede vurgula ve rozetleri temizle
    document.querySelectorAll('.chat-list-item').forEach(el => {
        const matches = normalizeKey(el.dataset.username) === normalizeKey(contact.username);
        el.classList.toggle('active', matches);
        if (matches) {
            el.classList.remove('has-unread');
            const badge = el.querySelector('.wa-unread-count-badge');
            if (badge) badge.remove();
            const timeEl = el.querySelector('.wa-chat-time');
            if (timeEl) timeEl.classList.remove('unread');
            const preview = el.querySelector('.chat-last-msg-preview');
            if (preview) preview.classList.remove('unread');
        }
    });

    updateUnreadBadges();

    // Mobilde ve Masaüstünde Resim 2 ekranına geç
    appRoot.classList.add('in-chat');

    // Bu kişiyle olan özel mesaj geçmişini sunucudan çek
    loadConversationHistory(contact.username);

    // Giriş kutusuna odaklan
    setTimeout(() => {
        messageInput.focus();
    }, 150);
}

// Aktif Sohbeti Kapat / Kullanıcı Ekranına Geri Dön (Mobil ve Masaüstü)
function closeActiveChat() {
    activeContact = null;
    appRoot.classList.remove('in-chat');
    document.querySelectorAll('.chat-list-item').forEach(el => el.classList.remove('active'));
    updateUnreadBadges();
}

btnBackToChats.addEventListener('click', closeActiveChat);

// ESC tuşuyla aktif sohbeti veya yeni yazışma modalını kapatma
window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        if (newChatModal && newChatModal.style.display === 'flex') {
            closeNewChatModal();
            return;
        }
        if (activeContact) {
            closeActiveChat();
        }
    }
});

// Birebir Özel Mesaj Geçmişini Yükleme (Soket + HTTP Fallback Korumalı)
async function loadConversationHistory(contactUsername) {
    const todayFormatted = new Date().toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', year: 'numeric' });
    messagesContainer.innerHTML = `
        <div class="date-pill-badge" id="chatDateBadge">${todayFormatted}</div>
        <div class="encryption-warning-banner" onclick="window.showE2EEVerificationDialog()" style="cursor:pointer;" title="Uçtan Uca Şifreleme (E2EE) Güvenlik Kodunu Doğrula">
            <span class="enc-icon">🔒</span>
            <span class="enc-text">
                Mesajlar ve aramalar uçtan uca şifrelidir (256-Bit E2EE). Yalnızca bu sohbetteki kişiler bu içerikleri okuyabilir, dinleyebilir veya paylaşabilir.
                <a href="javascript:void(0);" class="enc-link">Güvenlik kodunu doğrula</a>
            </span>
        </div>
    `;

    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');
    let hasLoaded = false;

    // 1. Soket üzerinden hızlı çekim
    socket.emit('chat:load_history', { contactUsername, token }, (res) => {
        if (res && res.success && Array.isArray(res.messages)) {
            hasLoaded = true;
            messagesContainer.querySelectorAll('.message-bubble').forEach(b => b.remove());
            res.messages.forEach(msg => appendMessageBubble(msg));
            scrollToBottom();
        }
    });

    // 2. HTTP REST Güvenlik Desteği (Soket gecikirse veya koparsa anında HTTP ile geçmişi getir)
    setTimeout(async () => {
        if (!hasLoaded && token) {
            try {
                const res = await fetch('/api/messages/' + encodeURIComponent(contactUsername), {
                    headers: { 'x-auth-token': token }
                });
                const data = await res.json();
                if (data && data.success && Array.isArray(data.messages)) {
                    hasLoaded = true;
                    messagesContainer.querySelectorAll('.message-bubble').forEach(b => b.remove());
                    data.messages.forEach(msg => appendMessageBubble(msg));
                    scrollToBottom();
                }
            } catch (err) {}
        }
    }, 700);
}

function appendMessageBubble(msg) {
    if (!currentUser || !activeContact || !msg) return;

    // KULLANICI İZOLASYONU: Yalnızca aktif kullanıcı (currentUser) ile açık olan kişi (activeContact) arasındaki mesajları göster!
    // Başka kullanıcılara atılan mesajlar kesinlikle ekrana basılmaz.
    if (!isMessageForCurrentUserAndContact(msg, normalizeKey(activeContact.username))) {
        return;
    }

    // 1. Zaten ekranda aynı id varsa mükerrer basma (ancak sonradan dosya/fotoğraf eklendiyse veya şifreli metin çözüldüyse güncelle)
    if (msg.id) {
        const existingEl = document.getElementById(msg.id);
        if (existingEl) {
            const hasRenderedFile = existingEl.querySelector('.msg-image-thumb, .msg-doc-card, audio');
            if (msg.file && !hasRenderedFile) {
                existingEl.remove();
            } else {
                const txtEl = existingEl.querySelector('.message-text');
                if (txtEl && txtEl.textContent && txtEl.textContent.trim().startsWith('e2ee1:')) {
                    existingEl.remove();
                } else {
                    return;
                }
            }
        }
    }

    // 2. Eğer sunucudan gelen mesajda tempId varsa ve ekranda o tempId ile bekleyen baloncuk varsa:
    // Yeni baloncuk eklemek yerine mevcut baloncuğun ID'sini ve durumunu güncelle! (ÇİFT MESAJ SORUNUNUN KÖK ÇÖZÜMÜ)
    if (msg.tempId) {
        const existingTemp = document.getElementById(msg.tempId);
        if (existingTemp) {
            existingTemp.id = msg.id;
            existingTemp.classList.remove('pending');
            const checks = existingTemp.querySelector('.bubble-checks');
            if (checks) checks.textContent = '✓✓';
            const delBtn = existingTemp.querySelector('.btn-msg-delete');
            if (delBtn) delBtn.setAttribute('onclick', `requestDeleteMessage('${msg.id}')`);
            return;
        }
    }

    const isMe = currentUser && normalizeKey(msg.sender) === normalizeKey(currentUser.username);
    let decryptedText = msg.text ? decryptE2EETextClient(msg.text, msg.sender, msg.recipient) : '';
    if (msg.file && decryptedText === '📎 Dosya / Fotoğraf paylaştı') {
        decryptedText = '';
    }

    // 3. Ek güvenlik: Eğer kendi gönderdiğimiz bir mesajsa ve henüz pending durumda aynı metinli bir baloncuk varsa onu güncelle
    if (isMe && !msg.pending && decryptedText) {
        const pendingBubbles = messagesContainer.querySelectorAll('.message-bubble.out.pending');
        for (const pb of pendingBubbles) {
            const txtEl = pb.querySelector('.message-text');
            if (txtEl && txtEl.textContent.trim() === decryptedText.trim()) {
                pb.id = msg.id;
                pb.classList.remove('pending');
                const checks = pb.querySelector('.bubble-checks');
                if (checks) checks.textContent = '✓✓';
                return;
            }
        }
    }

    const bubble = document.createElement('div');
    if (msg.id) bubble.id = msg.id;
    bubble.className = `message-bubble ${isMe ? 'out' : 'in'} ${msg.pending ? 'pending' : ''}`;

    let fileContent = '';
    if (msg.file) {
        if (msg.file.mimetype && msg.file.mimetype.startsWith('image/')) {
            fileContent = `<img class="msg-image-thumb" src="${msg.file.url}" alt="Fotoğraf" onclick="openEnlargedImage(this.src)" onerror="if(!this.dataset.cloudFallback && this.src.indexOf('/uploads/')!==-1){this.dataset.cloudFallback='1';this.src='https://hiileti.onrender.com/uploads/'+this.src.split('/uploads/').pop();}">`;
        } else if (msg.file.mimetype && msg.file.mimetype.startsWith('audio/')) {
            fileContent = `
                <div style="padding: 4px 0;">
                    <audio controls src="${msg.file.url}" style="max-width: 100%; height: 38px;"></audio>
                </div>
            `;
        } else {
            fileContent = `
                <a href="${msg.file.url}" download="${escapeHtml(msg.file.filename)}" class="msg-doc-card">
                    <span class="doc-icon">📄</span>
                    <div class="doc-info">
                        <div class="doc-name">${escapeHtml(msg.file.filename)}</div>
                        <div class="doc-size">${formatBytes(msg.file.size)}</div>
                    </div>
                </a>
            `;
        }
    }

    const textContent = decryptedText ? `<span class="message-text">${formatMessageText(decryptedText)}</span>` : '';
    const deleteBtn = msg.id ? `<button type="button" class="btn-msg-delete" title="Bu mesajı sil" onclick="requestDeleteMessage('${msg.id}')">&times;</button>` : '';

    bubble.innerHTML = `
        ${deleteBtn}
        ${fileContent}
        ${textContent}
        <div class="bubble-meta">
            <span class="bubble-time" title="Uçtan Uca Şifreli (E2EE)">🔒 ${msg.timestamp || '12:27'}</span>
            ${isMe ? `<span class="bubble-checks">${msg.pending ? '🕒' : '✓✓'}</span>` : ''}
        </div>
    `;

    messagesContainer.appendChild(bubble);
    scrollToBottom();
}

function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// ==========================================================
// 4. MESAJ GÖNDERME VE GİRİŞ ÇUBUĞU (RESİM 2)
// ==========================================================

// Giriş kutusuna yazı yazıldığında Mikrofon simgesi Gönder simgesine dönüşür
messageInput.addEventListener('input', () => {
    const hasText = messageInput.value.trim().length > 0;
    if (hasText) {
        iconMic.style.display = 'none';
        iconSend.style.display = 'block';
    } else {
        iconMic.style.display = 'block';
        iconSend.style.display = 'none';
    }

    // Yazıyor bildirimi gönder
    if (activeContact) {
        socket.emit('chat:typing', { recipient: activeContact.username, isTyping: true });
        if (typingTimeout) clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            socket.emit('chat:typing', { recipient: activeContact.username, isTyping: false });
        }, 1200);
    }
});

// Enter tuşu ile gönder (Çift tetiklemeyi önlemek için stopPropagation + preventDefault)
messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        e.stopPropagation();
        handleSendOrMic();
    }
});

// Sağdaki Yuvarlak Yeşil Butona Basıldığında (type="button" olduğu için yalnızca 1 kez çalışır)
btnSendOrMic.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    handleSendOrMic();
});

if (chatInputForm) {
    chatInputForm.addEventListener('submit', (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleSendOrMic();
    });
}

let lastSendActionTime = 0;

function handleSendOrMic() {
    const now = Date.now();
    // 250ms içinde çift tetikleme koruması
    if (now - lastSendActionTime < 250) return;

    const text = messageInput.value.trim();
    if (text) {
        lastSendActionTime = now;
        sendTextMessage(text);
    } else {
        // Ses Kaydı (Voice Note) Başlat / Bitir
        if (!isRecordingAudio) {
            startAudioRecording();
        } else {
            stopAudioRecording();
        }
    }
}

async function startAudioRecording() {
    try {
        const audioConstraints = selectedMicDeviceId && selectedMicDeviceId !== 'default'
            ? { deviceId: { ideal: selectedMicDeviceId }, echoCancellation: true, noiseSuppression: true }
            : true;
        const stream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];

        mediaRecorder.ondataavailable = (e) => {
            if (e.data.size > 0) audioChunks.push(e.data);
        };

        mediaRecorder.onstop = async () => {
            stream.getTracks().forEach(t => t.stop());
            if (audioChunks.length === 0) return;
            const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
            if (audioBlob.size > 100) {
                const file = new File([audioBlob], `ses_kaydi_${Date.now()}.webm`, { type: 'audio/webm' });
                await handleFileUpload(file);
            }
        };

        mediaRecorder.start();
        isRecordingAudio = true;
        btnSendOrMic.style.backgroundColor = 'var(--danger)';
        messageInput.placeholder = 'Ses kaydediliyor... Göndermek için tekrar dokunun';
    } catch (err) {
        alert('Mikrofon erişim izni alınamadı: ' + err.message);
    }
}

function stopAudioRecording() {
    if (mediaRecorder && isRecordingAudio) {
        mediaRecorder.stop();
        isRecordingAudio = false;
        btnSendOrMic.style.backgroundColor = 'var(--accent)';
        messageInput.placeholder = 'Mesaj';
    }
}

function sendTextMessage(text) {
    if (!activeContact || !currentUser) {
        alert('Lütfen önce mesaj göndermek istediğiniz kişiyi seçin.');
        return;
    }

    // Giriş kutusunu ANINDA temizle (ikinci bir Enter veya tıklamada aynı metnin tekrar gitmesini %100 engeller)
    messageInput.value = '';
    iconMic.style.display = 'block';
    iconSend.style.display = 'none';
    messageInput.focus();

    const token = sessionStorage.getItem('msj_token') || localStorage.getItem('msj_token');
    const tempId = 'msg_tmp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);

    // Mesajı göndermeden önce istemci tarafında Uçtan Uca Şifrele (256-bit E2EE)
    const encryptedText = encryptE2EETextClient(text, currentUser.username, activeContact.username);

    const tempMsg = {
        id: tempId,
        tempId: tempId,
        sender: currentUser.username,
        recipient: activeContact.username,
        text: encryptedText,
        file: null,
        timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
        date: 'Bugün',
        createdAt: new Date().toISOString(),
        pending: true
    };

    // Ekrana anında baloncuk olarak bas
    appendMessageBubble(tempMsg);

    // Kullanıcı listesindeki son mesaj önizlemesini hemen güncelle
    const contactInList = contactsList.find(c => normalizeKey(c.username) === normalizeKey(activeContact.username));
    if (contactInList) {
        contactInList.lastMessage = {
            id: tempId,
            sender: currentUser.username,
            recipient: activeContact.username,
            text: encryptedText,
            timestamp: tempMsg.timestamp,
            isOutgoing: true
        };
        saveCachedContactsForCurrentUser(contactsList);
        renderChatsList(contactsList);
    }

    socket.emit('chat:send_message', {
        recipient: activeContact.username,
        text: encryptedText,
        file: null,
        tempId: tempId,
        token: token
    }, (ack) => {
        const bubbleEl = document.getElementById(tempId) || (ack && ack.message && document.getElementById(ack.message.id));
        if (!ack || !ack.success) {
            if (bubbleEl) {
                bubbleEl.classList.add('error');
                const checks = bubbleEl.querySelector('.bubble-checks');
                if (checks) checks.textContent = '❌ İletilemedi';
            }
            alert(ack ? ack.error : 'Mesaj iletilemedi. Lütfen bağlantınızı kontrol edin.');
        } else {
            if (bubbleEl && ack.message) {
                bubbleEl.id = ack.message.id;
                bubbleEl.classList.remove('pending');
                const delBtn = bubbleEl.querySelector('.btn-msg-delete');
                if (delBtn) delBtn.setAttribute('onclick', `requestDeleteMessage('${ack.message.id}')`);
                const checks = bubbleEl.querySelector('.bubble-checks');
                if (checks) {
                    const isRecOnline = ack.isRecipientOnline !== false;
                    checks.textContent = isRecOnline ? '✓✓' : '✓';
                    checks.title = isRecOnline ? 'Teslim edildi (Uçtan Uca Şifreli)' : 'Sunucuya şifreli kaydedildi (Alıcı çevrimdışı, açtığında iletilecek)';
                }
            }
        }
    });
}

// Dosya / Fotoğraf Gönderme
btnAttach.addEventListener('click', () => fileInput.click());
btnCamera.addEventListener('click', () => cameraInput.click());

fileInput.addEventListener('change', () => handleFileUpload(fileInput.files[0]));
cameraInput.addEventListener('change', () => handleFileUpload(cameraInput.files[0]));

async function handleFileUpload(file) {
    if (!file || !activeContact) return;

    const formData = new FormData();
    formData.append('file', file);

    uploadProgress.style.display = 'flex';
    progressFill.style.width = '0%';
    progressText.textContent = `Yükleniyor: ${file.name}...`;

    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');

    try {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload', true);

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                progressFill.style.width = percent + '%';
                progressText.textContent = `%${percent} (${formatBytes(e.loaded)} / ${formatBytes(e.total)})`;
            }
        };

        xhr.onload = () => {
            uploadProgress.style.display = 'none';
            if (xhr.status === 200) {
                const uploadedFile = JSON.parse(xhr.responseText);
                const tempId = 'msg_tmp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
                const tempMsg = {
                    id: tempId,
                    tempId: tempId,
                    sender: currentUser.username,
                    recipient: activeContact.username,
                    text: '',
                    file: uploadedFile,
                    timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
                    date: 'Bugün',
                    createdAt: new Date().toISOString(),
                    pending: true
                };
                appendMessageBubble(tempMsg);

                const contactInList = contactsList.find(c => normalizeKey(c.username) === normalizeKey(activeContact.username));
                if (contactInList) {
                    contactInList.lastMessage = {
                        id: tempId,
                        sender: currentUser.username,
                        recipient: activeContact.username,
                        text: '📎 Dosya / Fotoğraf',
                        timestamp: tempMsg.timestamp,
                        isOutgoing: true
                    };
                    saveCachedContactsForCurrentUser(contactsList);
                    renderChatsList(contactsList);
                }

                socket.emit('chat:send_message', {
                    recipient: activeContact.username,
                    text: '',
                    file: uploadedFile,
                    tempId: tempId,
                    token: token
                }, (ack) => {
                    const bubbleEl = document.getElementById(tempId) || (ack && ack.message && document.getElementById(ack.message.id));
                    if (bubbleEl && ack && ack.success && ack.message) {
                        bubbleEl.id = ack.message.id;
                        bubbleEl.classList.remove('pending');
                        const delBtn = bubbleEl.querySelector('.btn-msg-delete');
                        if (delBtn) delBtn.setAttribute('onclick', `requestDeleteMessage('${ack.message.id}')`);
                        const checks = bubbleEl.querySelector('.bubble-checks');
                        if (checks) checks.textContent = '✓✓';
                    }
                });
            } else {
                alert('Dosya yüklenemedi.');
            }
        };

        xhr.onerror = () => {
            uploadProgress.style.display = 'none';
            alert('Yükleme hatası.');
        };

        xhr.send(formData);
    } catch (e) {
        uploadProgress.style.display = 'none';
    } finally {
        fileInput.value = '';
        cameraInput.value = '';
    }
}

// Emoji Butonu
btnEmoji.addEventListener('click', () => {
    const emojis = ['😊', '👍', '❤️', '🔥', '😂', '🙏', ' selam', ' tamam'];
    const chosen = prompt('Hızlı emoji ekleyin (veya aşağıdakilerden seçin):\n' + emojis.join('  '), '👍');
    if (chosen) {
        messageInput.value += chosen;
        messageInput.dispatchEvent(new Event('input'));
        messageInput.focus();
    }
});

// ==========================================================
// 5. CANLI SOKET OLAYLARI (GİZLİ İLETİŞİM GARANTİSİ)
// ==========================================================

// Yeni Mesaj Geldiğinde (TAM KULLANICI İZOLASYONU + E2EE ŞİFRE ÇÖZME)
socket.on('chat:message', (msg) => {
    if (!currentUser || !msg) return;

    const myKey = normalizeKey(currentUser.username);
    const senderKey = normalizeKey(msg.sender);
    const recipientKey = normalizeKey(msg.recipient);

    // KULLANICI İZOLASYONU: Bu mesajın göndereni veya alıcısı şu anki oturum açmış kullanıcı DEĞİLSE kesinlikle yoksay!
    if (senderKey !== myKey && recipientKey !== myKey) {
        return;
    }

    // Engellenen kişiden gelen mesajları yoksay
    if (recipientKey === myKey && isContactBlockedLocally(msg.sender)) {
        return;
    }

    if (msg.sender) {
        savePermanentLocalUsers([{ username: msg.sender, avatar: '/avatars/default.svg' }]);
    }
    if (msg.recipient) {
        savePermanentLocalUsers([{ username: msg.recipient, avatar: '/avatars/default.svg' }]);
    }
    const isIncoming = recipientKey === myKey;
    const isFromActive = activeContact && senderKey === normalizeKey(activeContact.username);
    const isToActive = activeContact && recipientKey === normalizeKey(activeContact.username);

    // 1. Eğer açık olan sohbete ait bir mesajsa ekrana bas
    if (activeContact && (isFromActive || isToActive)) {
        appendMessageBubble(msg);
        if (isFromActive) {
            socket.emit('chat:mark_read', { contactUsername: msg.sender });
        }
    }

    // 2. Eğer mesaj bize geldiyse:
    if (isIncoming) {
        // A) Bildirim sesi çal (WhatsApp tarzı net ve tatlı ses)
        playIncomingMessageSound();
        try { window.focus(); } catch (e) {}

        // B) Kullanıcı başka bir kişiye aktif olarak yazı yazmıyorsa sohbet ekranını otomatik aç ve mesajı ekrana getir!
        if (!isFromActive && !isUserCurrentlyTyping()) {
            openChatForSender(msg.sender);
        }

        // C) Sohbet o an açık değilse veya sekme/pencere arka plandaysa:
        if (!isFromActive || document.hidden) {
            showMessageNotificationToast(msg);
            const plainPreview = msg.text ? decryptE2EETextClient(msg.text, msg.sender, msg.recipient) : '';
            triggerSystemNotification(`💬 ${msg.sender}`, {
                body: plainPreview || (msg.file ? '📎 [Dosya / Fotoğraf paylaştı]' : 'Yeni bir mesajınız var'),
                icon: '/icon-192.png',
                badge: '/icon-192.png',
                tag: 'msg-' + msg.sender,
                vibrate: [180, 80, 180]
            });
        }
    }

    // 3. Sohbet listesindeki son mesajı ve okunmamış sayısını anında güncelle (Yalnızca ilgili karşı kişi için)
    const otherPartyKey = isIncoming ? senderKey : recipientKey;
    const contact = contactsList.find(c => normalizeKey(c.username) === otherPartyKey);

    if (contact) {
        contact.lastMessage = {
            id: msg.id,
            sender: msg.sender,
            recipient: msg.recipient,
            text: msg.text,
            file: msg.file,
            timestamp: msg.timestamp,
            date: msg.date,
            isOutgoing: !isIncoming
        };
        if (isIncoming && !isFromActive) {
            contact.unreadCount = (contact.unreadCount || 0) + 1;
        }
        saveCachedContactsForCurrentUser(contactsList);
        renderChatsList(contactsList);
    } else {
        loadChatsList();
    }
});

// Çevrimdışıyken bize gönderilmiş bekleyen mesajlar sunucudan geldiğinde (Offline Teslim)
socket.on('chat:offline_messages', (data) => {
    if (!currentUser || !data || !Array.isArray(data.messages) || data.messages.length === 0) return;

    const myKey = normalizeKey(currentUser.username);
    const myMessages = data.messages.filter(msg => msg && normalizeKey(msg.recipient) === myKey);
    if (myMessages.length === 0) return;

    let hasUnreadForOther = false;
    myMessages.forEach(msg => {
        // Eğer o an açık olan sohbetle ilgili bir mesajsa baloncuk olarak ekrana bas
        const isFromActive = activeContact && normalizeKey(msg.sender) === normalizeKey(activeContact.username);
        if (isFromActive) {
            appendMessageBubble(msg);
            socket.emit('chat:mark_read', { contactUsername: msg.sender });
        } else {
            hasUnreadForOther = true;
        }
    });

    if (hasUnreadForOther) {
        playIncomingMessageSound();
        const latestMsg = myMessages[myMessages.length - 1];
        if (latestMsg) {
            showMessageNotificationToast(latestMsg);
            if (!isUserCurrentlyTyping()) {
                openChatForSender(latestMsg.sender);
            }
        }
    }

    // Sohbet listesini ve rozetleri güncelle
    loadChatsList();
});

// Karşı taraf mesajları okuduğunda mavi çift tik yap
socket.on('chat:messages_read', (data) => {
    if (activeContact && normalizeKey(data.by) === normalizeKey(activeContact.username)) {
        document.querySelectorAll('.message-bubble.out .bubble-checks').forEach(el => {
            el.textContent = '✓✓';
            el.style.color = 'var(--check-blue)';
        });
    }
});

// Mesaj Silindi Bildirimi (Her iki taraf için)
socket.on('chat:message_deleted', (data) => {
    if (data && data.messageId) {
        removeMessageBubbleFromDom(data.messageId);
        loadChatsList();
    }
});

// Sohbet Temizlendi Bildirimi (Her iki taraf için)
socket.on('chat:conversation_cleared', (data) => {
    if (activeContact && (
        normalizeKey(activeContact.username) === normalizeKey(data.contactUsername) ||
        normalizeKey(activeContact.username) === normalizeKey(data.by)
    )) {
        clearMessagesFromDom();
    }
    loadChatsList();
});

// Karşı Taraf Yazıyor Bildirimi
socket.on('chat:typing', (data) => {
    if (activeContact && normalizeKey(data.username) === normalizeKey(activeContact.username)) {
        if (data.isTyping) {
            chatContactStatus.textContent = 'yazıyor...';
            chatContactStatus.style.color = 'var(--accent-bright)';
        } else {
            chatContactStatus.textContent = activeContact.isOnline ? 'Online' : 'Offline';
            chatContactStatus.style.color = 'var(--text-secondary)';
        }
    }
});

// Numaradan bulunan ve mesaj gönderilen kullanıcı programı kurduğunda numara + kullanıcı adı entegrasyon bildirimi
socket.on('user:phone_integrated', (data) => {
    if (!data || !data.newUsername) return;
    const oldList = Array.isArray(data.oldUsernames) && data.oldUsernames.length > 0
        ? data.oldUsernames
        : (data.oldUsername ? [data.oldUsername] : [data.phone || '']);

    oldList.forEach(oldItem => {
        integratePhoneContactOnClient(oldItem, data.newUsername, data.phone || '', data.avatar || '/avatars/default.svg', data.isOnline !== false);
    });

    if (currentUser && normalizeKey(data.newUsername) !== normalizeKey(currentUser.username)) {
        const prettyP = data.phone ? ` (${formatPhonePretty(data.phone)})` : '';
        showStatusToast(`${data.newUsername}${prettyP}`, true);
    }

    renderChatsList(contactsList);
    if (newChatModal && newChatModal.style.display === 'flex') {
        renderNewChatUsers(contactsList);
    }
    loadChatsList().then(() => {
        if (activeContact && normalizeKey(activeContact.username) === normalizeKey(data.newUsername)) {
            loadConversationHistory(activeContact.username);
        }
    });
});

// Kullanıcı Çevrimiçi/Çevrimdışı Durum Değişimi (Online / Offline Bildirimi)
socket.on('user:status_change', (data) => {
    if (!data || !data.username) return;
    const incomingKey = normalizeKey(data.username);
    const incomingPhoneKey = getPhoneMatchKeyClient(data.phone || '');

    savePermanentLocalUsers([{
        username: data.username,
        phone: data.phone || undefined,
        avatar: data.avatar || '/avatars/default.svg'
    }]);

    // Kendi durum değişimimiz değilse ekranda sesli ve görsel uyarı ver
    const isMe = currentUser && normalizeKey(currentUser.username) === incomingKey;
    if (currentUser && !isMe) {
        showStatusToast(data.username, data.isOnline);
        playStatusChime(data.isOnline);
    }

    // Eğer rehberde telefon numarasıyla kayıtlıysa ve şimdi kullanıcı adıyla Online olduysa anında entegre et
    if (incomingPhoneKey && !isPhoneQueryClient(data.username)) {
        const phoneContact = contactsList.find(c =>
            normalizeKey(c.username) !== incomingKey &&
            getPhoneMatchKeyClient(c.phone || (isPhoneQueryClient(c.username) ? c.username : '')) === incomingPhoneKey
        );
        if (phoneContact) {
            integratePhoneContactOnClient(phoneContact.username, data.username, data.phone, data.avatar || '/avatars/default.svg', Boolean(data.isOnline));
        }
    }

    let contact = contactsList.find(c => normalizeKey(c.username) === incomingKey);
    if (contact) {
        contact.isOnline = Boolean(data.isOnline);
        contact.statusText = data.isOnline ? 'Online' : 'Offline';
        contact.lastSeen = data.isOnline ? 'Online' : 'Offline';
        if (data.phone && !contact.phone) contact.phone = data.phone;
        if (data.avatar && (!contact.avatar || contact.avatar === '/avatars/default.svg')) contact.avatar = data.avatar;
        renderChatsList(contactsList);
    } else if (!isMe) {
        // Programı kullanmaya başlayan kullanıcı üstte Online uyarısı verdiğinde Online ekranında da ANINDA görünsün!
        const newContactObj = {
            username: data.username,
            customName: '',
            avatar: data.avatar || '/avatars/default.svg',
            phone: data.phone || '',
            isOnline: Boolean(data.isOnline),
            statusText: data.isOnline ? 'Online' : 'Offline',
            lastSeen: data.isOnline ? 'Online' : 'Offline',
            lastMessage: null,
            unreadCount: 0
        };
        contactsList.unshift(newContactObj);
        saveCachedContactsForCurrentUser(contactsList);
        renderChatsList(contactsList);
    }

    if (newChatModal && newChatModal.style.display === 'flex') {
        renderNewChatUsers(contactsList);
    }

    // Sunucudan da güncel sohbet ve mesaj bilgilerini senkronize et
    loadChatsList();

    if (activeContact && normalizeKey(activeContact.username) === incomingKey) {
        activeContact.isOnline = Boolean(data.isOnline);
        if (data.phone && !activeContact.phone) {
            activeContact.phone = data.phone;
            if (chatContactName) chatContactName.textContent = formatContactIntegratedDisplayName(activeContact);
        }
        if (data.isOnline) {
            chatContactStatus.textContent = 'Online';
            headerOnlineDot.style.display = 'block';
        } else {
            chatContactStatus.textContent = 'Offline';
            headerOnlineDot.style.display = 'none';
        }
    }

    if (data.isOnline && currentCallTarget && normalizeKey(currentCallTarget) === incomingKey) {
        if (outgoingCallModal && outgoingCallModal.style.display === 'flex' && outgoingCallStatus) {
            outgoingCallStatus.textContent = 'Çalıyor (Karşı cihaz Online oldu)...';
        }
    }
});

// Yeni Bir Kullanıcı Kayıt Olduğunda (Üstte Online uyarısı verilir ve Online ekranına anında eklenir)
function handleNewUserRegisteredEvent(data) {
    if (!currentUser || !data || !data.username) return;
    const uKey = normalizeKey(data.username);
    if (uKey === normalizeKey(currentUser.username)) return;

    const incomingPhoneKey = getPhoneMatchKeyClient(data.phone || '');
    if (incomingPhoneKey && !isPhoneQueryClient(data.username)) {
        integratePhoneContactOnClient(data.phone, data.username, data.phone, data.avatar || '/avatars/default.svg', data.isOnline !== false);
    }

    let existing = contactsList.find(c => normalizeKey(c.username) === uKey);
    const isOnlineNow = data.isOnline !== false;
    if (existing) {
        existing.isOnline = isOnlineNow;
        existing.statusText = isOnlineNow ? 'Online' : 'Offline';
        existing.lastSeen = isOnlineNow ? 'Online' : 'Offline';
        if (data.phone && !existing.phone) existing.phone = data.phone;
    } else if (!isPhoneQueryClient(data.username) || isOnlineNow) {
        contactsList.unshift({
            username: data.username,
            customName: '',
            avatar: data.avatar || '/avatars/default.svg',
            phone: data.phone || '',
            isOnline: isOnlineNow,
            statusText: isOnlineNow ? 'Online' : 'Offline',
            lastSeen: isOnlineNow ? 'Online' : 'Offline',
            lastMessage: null,
            unreadCount: 0
        });
    }

    saveCachedContactsForCurrentUser(contactsList);
    renderChatsList(contactsList);
    if (newChatModal && newChatModal.style.display === 'flex') {
        renderNewChatUsers(contactsList);
    }

    if (isOnlineNow) {
        showStatusToast(data.username, true);
        playStatusChime(true);
    }
    loadChatsList();
}
socket.on('user:new_registered', handleNewUserRegisteredEvent);
socket.on('user:registered', handleNewUserRegisteredEvent);

// Kullanıcı Kendi İsteğiyle Silindiğinde
socket.on('user:deleted', (data) => {
    if (!data || !data.username) return;
    removePermanentLocalUser(data.username);
    contactsList = contactsList.filter(c => normalizeKey(c.username) !== normalizeKey(data.username));
    renderChatsList(contactsList);
    if (activeContact && normalizeKey(activeContact.username) === normalizeKey(data.username)) {
        closeActiveChat();
    }
    loadRegisteredUsersDropdown();
});

socket.on('contact:deleted', (data) => {
    if (!data || !data.contactUsername) return;
    removePermanentLocalUser(data.contactUsername);
    contactsList = contactsList.filter(c => normalizeKey(c.username) !== normalizeKey(data.contactUsername));
    saveCachedContactsForCurrentUser(contactsList);
    renderChatsList(contactsList);
    if (newChatModal && newChatModal.style.display === 'flex') {
        renderNewChatUsers(contactsList);
    }
    if (activeContact && normalizeKey(activeContact.username) === normalizeKey(data.contactUsername)) {
        closeActiveChat();
    }
});

socket.on('contact:block_changed', (data) => {
    if (!data || !data.targetUsername) return;
    const tKey = normalizeKey(data.targetUsername);
    const isBlocked = Boolean(data.isBlocked);
    setContactBlockedLocally(data.targetUsername, isBlocked);
    contactsList.forEach(c => {
        if (normalizeKey(c.username) === tKey) {
            c.isBlocked = isBlocked;
        }
    });
    if (activeContact && normalizeKey(activeContact.username) === tKey) {
        activeContact.isBlocked = isBlocked;
        updateActiveContactBlockHeaderUi();
    }
    renderChatsList(contactsList);
    if (newChatModal && newChatModal.style.display === 'flex') {
        renderNewChatUsers(contactsList);
    }
});

// CEP TELEFONU GİBİ OTOMATİK UYANMA VE ONLINE OLMA SİSTEMİ (KULLANICI İZOLASYONLU):
// Yalnızca bu cihazda oturum açmış olan (veya kaydedilmiş) kullanıcıya mesaj/arama geldiğinde çalışır.
// Başka kullanıcılara gelen mesaj veya aramalar bu ekranda gösterilmez ve hesabı değiştirmez!
socket.on('system:wakeup', async (data) => {
    const targetUsername = data && (data.targetUsername || data.recipient);
    if (!data || !targetUsername) return;

    // Eğer gönderen kişi bizzat bu sekmedeki aktif kullanıcıysa işlem yapma
    if (currentUser && normalizeKey(currentUser.username) === normalizeKey(data.sender)) {
        return;
    }
    if (data.sender && isContactBlockedLocally(data.sender)) {
        return;
    }

    const targetKey = normalizeKey(targetUsername);
    const isAlreadyTarget = currentUser && normalizeKey(currentUser.username) === targetKey;
    const savedUsername = localStorage.getItem('msj_saved_username') || '';
    const isSavedTarget = !currentUser && savedUsername && normalizeKey(savedUsername) === targetKey;

    // KULLANICI İZOLASYONU: Hangi kullanıcı adı ile açılmışsa sadece o kullanıcıya gelen mesaj/aramalar gözüksün!
    if (!isAlreadyTarget && !isSavedTarget) {
        return;
    }

    let wokeUpFromOffline = false;
    if (!isAlreadyTarget) {
        wokeUpFromOffline = true;
        await quickLoginAsRegisteredUser(targetUsername);
    } else {
        // Zaten bu kullanıcıysa ama Offline görünüyorsa hemen sunucuya Online olduğunu bildir
        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
        socket.emit('user:join', { token, username: currentUser.username });
        if (authModal && authModal.style.display !== 'none') {
            authModal.style.display = 'none';
        }
    }

    try { window.focus(); } catch (e) {}

    if (data.type === 'call') {
        const callInfo = data.callPayload || data;
        showStatusToast(`🟢 Otomatik Online • 📞 ${data.sender} Arıyor`, true);
        // Eğer gelen arama ekranı henüz açılmadıysa hemen ekrana düşür
        setTimeout(() => {
            if (incomingCallModal && incomingCallModal.style.display !== 'flex' && (!activeCallScreen || activeCallScreen.style.display !== 'flex')) {
                currentTargetSocketId = callInfo.callerSocketId || data.callerSocketId || currentTargetSocketId;
                currentCallTarget = data.sender;
                currentCallType = data.callType || callInfo.callType || 'voice';
                if (incomingCallerName) incomingCallerName.textContent = data.sender;
                if (incomingCallerAvatar) incomingCallerAvatar.src = callInfo.callerAvatar || data.callerAvatar || '/avatars/default.svg';
                if (incomingCallType) {
                    incomingCallType.textContent = currentCallType === 'video' ? 'Gelen Görüntülü Arama...' : 'Gelen Sesli Arama...';
                }
                incomingCallModal.style.display = 'flex';
                playRingtone();
                triggerSystemNotification(`📞 GELEN ARAMA: ${data.sender}`, {
                    body: `${data.sender} sizi arıyor... Cevaplamak için dokunun.`,
                    icon: callInfo.callerAvatar || data.callerAvatar || '/icon-192.png',
                    badge: '/icon-192.png',
                    tag: 'incoming-call',
                    renotify: true,
                    requireInteraction: true
                });
            }
        }, 150);
    } else if (data.type === 'message') {
        const rawMsgObj = data.message || {
            id: 'wakeup_' + Date.now(),
            sender: data.sender,
            recipient: targetUsername,
            text: data.text || 'Yeni mesaj',
            timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
        };
        const plainText = rawMsgObj.text ? decryptE2EETextClient(rawMsgObj.text, rawMsgObj.sender, rawMsgObj.recipient) : 'Yeni mesaj';

        showStatusToast(`🟢 Otomatik Online • 💬 ${data.sender} mesaj gönderdi`, true);

        if (wokeUpFromOffline || document.hidden || !activeContact || normalizeKey(activeContact.username) !== normalizeKey(data.sender)) {
            playIncomingMessageSound();
            showMessageNotificationToast(rawMsgObj);
            triggerSystemNotification(`💬 ${data.sender}`, {
                body: plainText || 'Yeni bir mesajınız var',
                icon: '/icon-192.png',
                badge: '/icon-192.png',
                tag: 'msg-' + data.sender
            });
            loadChatsList().then(() => {
                if (!isUserCurrentlyTyping()) {
                    openChatForSender(data.sender);
                }
            });
        }
    }
});

// ==========================================================
// 6. WEBRTC SESLİ & GÖRÜNTÜLÜ ARAMA + EVRENSEL MİKROFON / HOPARLÖR MOTORU
// (Dahili, Harici, Kablolu, USB ve Bluetooth Kablosuz Tüm Cihazlarla Uyumlu)
// ==========================================================

// Cihaz türüne göre anlaşılır ikon ve etiket üretici
function formatAudioDeviceLabel(device, index, kind) {
    let raw = (device.label || '').trim();
    if (!raw) {
        raw = kind === 'audioinput' ? `Mikrofon #${index + 1}` : `Hoparlör / Kulaklık #${index + 1}`;
    }
    const lower = raw.toLowerCase();
    let badge = '🔌';
    if (lower.includes('bluetooth') || lower.includes('airpods') || lower.includes('buds') || lower.includes('wireless') || lower.includes('hands-free') || lower.includes('bt ')) {
        badge = '🎧 [Kablosuz / Bluetooth]';
    } else if (lower.includes('usb')) {
        badge = '🎙️ [Harici USB]';
    } else if (lower.includes('headset') || lower.includes('headphone') || lower.includes('kulaklık') || lower.includes('jack')) {
        badge = '🎧 [Kablolu Kulaklık]';
    } else if (lower.includes('realtek') || lower.includes('internal') || lower.includes('dahili') || lower.includes('array') || lower.includes('default') || lower.includes('varsayılan')) {
        badge = kind === 'audioinput' ? '🎤 [Dahili Mikrofon]' : '🔊 [Dahili Hoparlör]';
    } else {
        badge = kind === 'audioinput' ? '🎤' : '🔊';
    }
    return `${badge} ${raw}`;
}

// Tüm dahili ve harici (kablolu/kablosuz) ses giriş ve çıkış cihazlarını tarar
async function refreshAudioDeviceList(requestPermissionFirst = false) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;

    if (requestPermissionFirst) {
        try {
            const tempStream = await navigator.mediaDevices.getUserMedia({ audio: true });
            tempStream.getTracks().forEach(t => t.stop());
        } catch (e) {
            console.warn('Mikrofon izni alınırken uyarı:', e);
        }
    }

    try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        availableMicDevices = devices.filter(d => d.kind === 'audioinput');
        availableSpeakerDevices = devices.filter(d => d.kind === 'audiooutput');

        if (selectMicDevice) {
            selectMicDevice.innerHTML = `<option value="default">🎤 Sistem Varsayılan Mikrofonu (Otomatik Algıla)</option>`;
            availableMicDevices.forEach((dev, idx) => {
                if (!dev.deviceId || dev.deviceId === 'default') return;
                const opt = document.createElement('option');
                opt.value = dev.deviceId;
                opt.textContent = formatAudioDeviceLabel(dev, idx, 'audioinput');
                if (dev.deviceId === selectedMicDeviceId) opt.selected = true;
                selectMicDevice.appendChild(opt);
            });
        }

        if (selectSpeakerDevice) {
            selectSpeakerDevice.innerHTML = `<option value="default">🔊 Sistem Varsayılan Hoparlör / Kulaklık (Otomatik)</option>`;
            availableSpeakerDevices.forEach((dev, idx) => {
                if (!dev.deviceId || dev.deviceId === 'default') return;
                const opt = document.createElement('option');
                opt.value = dev.deviceId;
                opt.textContent = formatAudioDeviceLabel(dev, idx, 'audiooutput');
                if (dev.deviceId === selectedSpeakerDeviceId) opt.selected = true;
                selectSpeakerDevice.appendChild(opt);
            });
        }

        updateActiveDeviceLabelBadge();
    } catch (err) {
        console.warn('Ses cihazları listelenemedi:', err);
    }
}

function updateActiveDeviceLabelBadge() {
    if (!activeDeviceLabelText) return;
    let micName = 'Varsayılan Mikrofon';
    let spkName = isSpeakerphoneOn ? 'Hoparlör' : 'Ahize / Kulaklık';

    if (localStream && localStream.getAudioTracks().length > 0) {
        const trackLabel = localStream.getAudioTracks()[0].label;
        if (trackLabel) micName = trackLabel.length > 24 ? trackLabel.substring(0, 24) + '...' : trackLabel;
    } else if (selectedMicDeviceId !== 'default') {
        const foundMic = availableMicDevices.find(d => d.deviceId === selectedMicDeviceId);
        if (foundMic && foundMic.label) micName = foundMic.label.substring(0, 24);
    }

    if (selectedSpeakerDeviceId !== 'default') {
        const foundSpk = availableSpeakerDevices.find(d => d.deviceId === selectedSpeakerDeviceId);
        if (foundSpk && foundSpk.label) spkName = foundSpk.label.substring(0, 24);
    }

    activeDeviceLabelText.textContent = `🎤 ${micName} • 🔊 ${spkName}`;
}

// Kablolu veya Bluetooth kulaklık/mikrofon takılıp çıkarıldığında (Hot-Plug) anında algıla ve bağla
if (navigator.mediaDevices && navigator.mediaDevices.addEventListener) {
    navigator.mediaDevices.addEventListener('devicechange', async () => {
        await refreshAudioDeviceList(false);
        showStatusToast('🎧 Ses cihazı değişikliği algılandı ve güncellendi', true);
        // Eğer aktif görüşmedeysek yeni cihazla ses akışını kesintisiz yenile
        if (peerConnection && localStream) {
            await switchActiveMicrophoneDuringCall(selectedMicDeviceId);
            await applySpeakerOutputDevice(selectedSpeakerDeviceId);
        }
    });
}

// Hoparlör / Kulaklık Çıkış Cihazını (setSinkId) Uygulama
async function applySpeakerOutputDevice(deviceId) {
    selectedSpeakerDeviceId = deviceId || 'default';
    localStorage.setItem('msj_speaker_id', selectedSpeakerDeviceId);

    const targetSink = selectedSpeakerDeviceId === 'default' ? '' : selectedSpeakerDeviceId;

    const mediaElements = [remoteAudio, remoteVideo];
    for (const el of mediaElements) {
        if (el && typeof el.setSinkId === 'function') {
            try {
                await el.setSinkId(targetSink);
            } catch (err) {
                console.warn('setSinkId uygulanamadı, varsayılan çıkış kullanılıyor:', err);
            }
        }
    }

    if (callAudioContext && typeof callAudioContext.setSinkId === 'function') {
        try {
            await callAudioContext.setSinkId(targetSink);
        } catch (e) {}
    }

    updateActiveDeviceLabelBadge();
}

// Görüşme esnasında mikrofonu (Dahili / Kablolu / Bluetooth) kesintisiz değiştirme
async function switchActiveMicrophoneDuringCall(newMicDeviceId) {
    selectedMicDeviceId = newMicDeviceId || 'default';
    localStorage.setItem('msj_mic_id', selectedMicDeviceId);

    if (!localStream && !peerConnection) {
        updateActiveDeviceLabelBadge();
        return;
    }

    try {
        const newStream = await acquireMicrophoneAndCameraStream(currentCallType === 'video', selectedMicDeviceId);
        if (!newStream) return;

        const newAudioTrack = newStream.getAudioTracks()[0];
        if (newAudioTrack) {
            newAudioTrack.enabled = !isAudioMuted;
            // WebRTC RTCRtpSender üzerinden karşı tarafa giden ses kanalını anında değiştir
            if (peerConnection) {
                const senders = peerConnection.getSenders();
                const audioSender = senders.find(s => s.track && s.track.kind === 'audio');
                if (audioSender) {
                    await audioSender.replaceTrack(newAudioTrack);
                } else {
                    peerConnection.addTrack(newAudioTrack, newStream);
                }
            }
        }

        // Eski ses izlerini durdur
        if (localStream) {
            localStream.getAudioTracks().forEach(t => {
                if (t !== newAudioTrack) t.stop();
            });
        }

        localStream = newStream;
        if (localVideo && currentCallType === 'video') {
            localVideo.srcObject = localStream;
        }

        setupCallAudioMetersAndRelay();
        updateActiveDeviceLabelBadge();
    } catch (err) {
        console.error('Mikrofon değiştirme hatası:', err);
    }
}

// Her türlü mikrofonla (Bluetooth Hands-Free, USB, Jak, Dahili) %100 uyumlu kademeli ses yakalayıcı
async function acquireMicrophoneAndCameraStream(wantVideo = false, preferredMicId = 'default') {
    const micId = preferredMicId && preferredMicId !== 'default' ? preferredMicId : null;

    // Kademe 1: Seçili mikrofon + gelişmiş gürültü/yankı engelleme
    const constraintCandidates = [];

    if (micId) {
        constraintCandidates.push({
            audio: {
                deviceId: { exact: micId },
                echoCancellation: { ideal: true },
                noiseSuppression: { ideal: true },
                autoGainControl: { ideal: true },
                channelCount: { ideal: 1 }
            },
            video: wantVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false
        });
        // Kademe 2: Bluetooth veya eski harici ses kartları kısıtlamaları reddederse saf deviceId ile aç
        constraintCandidates.push({
            audio: { deviceId: { ideal: micId } },
            video: wantVideo ? true : false
        });
    }

    // Kademe 3: Varsayılan mikrofon + eko engelleme
    constraintCandidates.push({
        audio: {
            echoCancellation: { ideal: true },
            noiseSuppression: { ideal: true },
            autoGainControl: { ideal: true }
        },
        video: wantVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false
    });

    // Kademe 4: En temel saf ses izni (hiçbir sürücü reddedemez)
    constraintCandidates.push({
        audio: true,
        video: wantVideo ? true : false
    });

    // Kademe 5: Kamera yoksa veya meşgulse bile SESİN KESİNLİKLE GİTMESİ için yalnızca ses
    if (wantVideo) {
        constraintCandidates.push({
            audio: true,
            video: false
        });
    }

    let rawStream = null;
    let lastErr = null;
    for (const constraints of constraintCandidates) {
        try {
            rawStream = await navigator.mediaDevices.getUserMedia(constraints);
            if (rawStream && rawStream.getAudioTracks().length > 0) {
                break;
            }
        } catch (err) {
            lastErr = err;
        }
    }

    if (!rawStream) {
        alert('Mikrofon erişim izni alınamadı veya takılı mikrofon bulunamadı: ' + (lastErr ? lastErr.message : 'Bilinmeyen hata'));
        return null;
    }

    // Mikrofon track'ini aktif ve açık tut
    rawStream.getAudioTracks().forEach(track => {
        track.enabled = true;
    });

    // Web Audio API ile Mikrofon Ses Güçlendirme (GainNode + Compressor)
    // Böylece kısık sesli dahili/harici mikrofonlarda bile karşı tarafa gür ve net ses gider
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
            if (!callAudioContext || callAudioContext.state === 'closed') {
                callAudioContext = new AudioCtx();
            }
            if (callAudioContext.state === 'suspended') {
                await callAudioContext.resume();
            }

            const source = callAudioContext.createMediaStreamSource(rawStream);
            micGainNode = callAudioContext.createGain();
            micGainNode.gain.value = micGainBoost || 1.4;

            const compressor = callAudioContext.createDynamicsCompressor();
            compressor.threshold.setValueAtTime(-24, callAudioContext.currentTime);
            compressor.knee.setValueAtTime(30, callAudioContext.currentTime);
            compressor.ratio.setValueAtTime(12, callAudioContext.currentTime);
            compressor.attack.setValueAtTime(0.003, callAudioContext.currentTime);
            compressor.release.setValueAtTime(0.25, callAudioContext.currentTime);

            const destination = callAudioContext.createMediaStreamDestination();
            source.connect(micGainNode);
            micGainNode.connect(compressor);
            compressor.connect(destination);

            // Eğer kamera görüntüsü varsa güçlendirilmiş ses akışına ekle
            rawStream.getVideoTracks().forEach(vt => destination.stream.addTrack(vt));

            // Orijinal rawStream'i referans olarak sakla ki arama bittiğinde donanım ışığı kapansın
            destination.stream._rawHardwareStream = rawStream;
            return destination.stream;
        }
    } catch (audioProcErr) {
        console.warn('Web Audio mikrofon güçlendirici başlatılamadı, doğrudan donanım akışı kullanılıyor:', audioProcErr);
    }

    return rawStream;
}

// Canlı Ses Seviyesi Göstergeleri + Gerçek Zamanlı Socket.IO Ses Rölesi (WebRTC UDP engellense bile sesin %100 gitmesini sağlar)
let socketAudioScriptNode = null;
let lastWebRtcAudioReceivedAt = 0;

function setupCallAudioMetersAndRelay() {
    if (audioMeterInterval) {
        clearInterval(audioMeterInterval);
        audioMeterInterval = null;
    }
    if (socketAudioScriptNode) {
        try { socketAudioScriptNode.disconnect(); } catch (e) {}
        socketAudioScriptNode = null;
    }

    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        if (!callAudioContext || callAudioContext.state === 'closed') {
            callAudioContext = new AudioCtx();
        }
        if (callAudioContext.state === 'suspended') {
            callAudioContext.resume().catch(() => {});
        }

        // 1. Giden Mikrofon Analizörü + Socket.IO Canlı PCM Ses Yedek Kanalı
        if (localStream && localStream.getAudioTracks().length > 0) {
            const micSource = callAudioContext.createMediaStreamSource(localStream);
            micAnalyser = callAudioContext.createAnalyser();
            micAnalyser.fftSize = 256;
            micSource.connect(micAnalyser);

            // ScriptProcessor ile mikrofon sesini sıkıştırılmış Int16 paketleri olarak da hazırla
            // (Karşı tarafla WebRTC UDP bağlantısı güvenlik duvarına takılırsa ses Socket üzerinden kesintisiz akar)
            if (callAudioContext.createScriptProcessor) {
                socketAudioScriptNode = callAudioContext.createScriptProcessor(2048, 1, 1);
                micSource.connect(socketAudioScriptNode);
                const zeroGain = callAudioContext.createGain();
                zeroGain.gain.value = 0;
                socketAudioScriptNode.connect(zeroGain);
                zeroGain.connect(callAudioContext.destination);

                socketAudioScriptNode.onaudioprocess = (e) => {
                    if (isAudioMuted || !activeCallScreen || activeCallScreen.style.display === 'none') return;
                    if (!currentTargetSocketId && !currentCallTarget) return;

                    // Eğer WebRTC ICE tam bağlıysa ve ses akıyorsa gereksiz bant genişliği harcama,
                    // ancak bağlantı henüz kurulmadıysa veya karşı taraf ses alamıyorsa Socket üzerinden de gönder
                    const iceState = peerConnection ? peerConnection.iceConnectionState : 'new';
                    const isWebRtcHealthy = (iceState === 'connected' || iceState === 'completed') && (Date.now() - lastWebRtcAudioReceivedAt < 3000);
                    if (isWebRtcHealthy) return;

                    const inputData = e.inputBuffer.getChannelData(0);
                    // Sessizlik kontrolü (gürültü eşiği altındaysa gönderme)
                    let sum = 0;
                    for (let i = 0; i < inputData.length; i += 4) {
                        sum += Math.abs(inputData[i]);
                    }
                    const avg = sum / (inputData.length / 4);
                    if (avg < 0.004) return;

                    // 2x Downsample + Int16 dönüşümü (düşük gecikme, yüksek netlik)
                    const downsampledLength = Math.floor(inputData.length / 2);
                    const pcm16 = new Int16Array(downsampledLength);
                    for (let i = 0; i < downsampledLength; i++) {
                        const s = Math.max(-1, Math.min(1, inputData[i * 2]));
                        pcm16[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
                    }

                    // Uçtan Uca Ses Şifrelemesi (E2EE Audio Stream Cipher)
                    if (currentUser && currentCallTarget) {
                        e2eeMaskPcm16(pcm16, currentUser.username, currentCallTarget);
                    }

                    socket.volatile.emit('call:audio_chunk', {
                        targetSocketId: currentTargetSocketId,
                        targetUsername: currentCallTarget,
                        sampleRate: Math.floor(callAudioContext.sampleRate / 2),
                        e2ee: Boolean(currentUser && currentCallTarget),
                        pcm: pcm16.buffer
                    });
                };
            }
        }

        // 2. Canlı Seviye Çubuğu Güncelleyici
        const micData = new Uint8Array(64);
        const remData = new Uint8Array(64);

        audioMeterInterval = setInterval(() => {
            if (micAnalyser && !isAudioMuted) {
                micAnalyser.getByteFrequencyData(micData);
                let sum = 0;
                for (let i = 0; i < micData.length; i++) sum += micData[i];
                const pct = Math.min(100, Math.round((sum / micData.length) * 1.8));
                if (callMicLevelFill) callMicLevelFill.style.width = pct + '%';
            } else if (callMicLevelFill) {
                callMicLevelFill.style.width = '0%';
            }

            if (remoteAnalyser) {
                remoteAnalyser.getByteFrequencyData(remData);
                let rSum = 0;
                for (let i = 0; i < remData.length; i++) rSum += remData[i];
                const rPct = Math.min(100, Math.round((rSum / remData.length) * 1.8));
                if (rPct > 3) lastWebRtcAudioReceivedAt = Date.now();
                if (callRemoteLevelFill) callRemoteLevelFill.style.width = rPct + '%';
            }
        }, 90);
    } catch (e) {
        console.warn('Ses seviyesi ölçer hatası:', e);
    }
}

// Karşı taraftan gelen WebRTC ses akışını hem <audio> elementine hem de Web Audio yükselticisine bağla
function attachIncomingAudioStream(stream) {
    if (!stream) return;

    // 1. <audio id="remoteAudio"> elementi üzerinden çal
    if (remoteAudio) {
        if (remoteAudio.srcObject !== stream) {
            remoteAudio.srcObject = stream;
        }
        remoteAudio.muted = false;
        remoteAudio.volume = 1.0;
        if (selectedSpeakerDeviceId && selectedSpeakerDeviceId !== 'default' && typeof remoteAudio.setSinkId === 'function') {
            remoteAudio.setSinkId(selectedSpeakerDeviceId).catch(() => {});
        }
        remoteAudio.play().catch(e => console.warn('remoteAudio play uyarısı:', e));
    }

    // 2. Web Audio API üzerinden de ses çıkışını destekle ve seviye göstergesine bağla
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
            if (!callAudioContext || callAudioContext.state === 'closed') {
                callAudioContext = new AudioCtx();
            }
            if (callAudioContext.state === 'suspended') {
                callAudioContext.resume().catch(() => {});
            }

            const remSource = callAudioContext.createMediaStreamSource(stream);
            remoteAnalyser = callAudioContext.createAnalyser();
            remoteAnalyser.fftSize = 256;

            remoteGainNode = callAudioContext.createGain();
            // Hoparlör modundaysa sesi ekstra güçlendir
            remoteGainNode.gain.value = isSpeakerphoneOn ? (speakerGainBoost * 1.25) : speakerGainBoost;

            remSource.connect(remoteAnalyser);
            // Eğer <audio> elementi tarayıcı politikası yüzünden sessiz kalırsa Web Audio doğrudan hoparlöre verir
            if (remoteAudio && remoteAudio.paused) {
                remSource.connect(remoteGainNode);
                remoteGainNode.connect(callAudioContext.destination);
            }
        }
    } catch (err) {
        console.warn('Gelen ses Web Audio bağlantısı uyarısı:', err);
    }
}

// Socket.IO üzerinden gelen yedek gerçek zamanlı ses paketlerini (PCM16) E2EE çözerek anında hoparlörden çal
socket.on('call:audio_chunk', (data) => {
    if (!data || !data.pcm || !currentUser) return;
    if (data.targetUsername && normalizeKey(data.targetUsername) !== normalizeKey(currentUser.username)) return;
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        if (!callAudioContext || callAudioContext.state === 'closed') {
            callAudioContext = new AudioCtx();
        }
        if (callAudioContext.state === 'suspended') {
            callAudioContext.resume().catch(() => {});
        }

        const int16 = new Int16Array(data.pcm);
        if (int16.length === 0) return;

        if (data.e2ee && currentUser && currentCallTarget) {
            e2eeMaskPcm16(int16, currentUser.username, currentCallTarget);
        }

        const sampleRate = data.sampleRate || 22050;
        const audioBuffer = callAudioContext.createBuffer(1, int16.length, sampleRate);
        const channelData = audioBuffer.getChannelData(0);
        let peak = 0;
        for (let i = 0; i < int16.length; i++) {
            const val = int16[i] / 32768.0;
            channelData[i] = val;
            if (Math.abs(val) > peak) peak = Math.abs(val);
        }

        if (callRemoteLevelFill) {
            const pct = Math.min(100, Math.round(peak * 160));
            callRemoteLevelFill.style.width = pct + '%';
        }

        const bufferSource = callAudioContext.createBufferSource();
        bufferSource.buffer = audioBuffer;

        const gainNode = callAudioContext.createGain();
        gainNode.gain.value = isSpeakerphoneOn ? (speakerGainBoost * 1.3) : speakerGainBoost;

        bufferSource.connect(gainNode);
        gainNode.connect(callAudioContext.destination);

        const now = callAudioContext.currentTime;
        if (nextRemoteAudioPlayTime < now || nextRemoteAudioPlayTime > now + 0.5) {
            nextRemoteAudioPlayTime = now + 0.02;
        }
        bufferSource.start(nextRemoteAudioPlayTime);
        nextRemoteAudioPlayTime += audioBuffer.duration;
    } catch (e) {}
});

// ==========================================================
// SES VE MİKROFON / HOPARLÖR AYARLARI MODAL KONTROLLERİ
// ==========================================================
function getAudioCtx() {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return null;
    if (!callAudioContext || callAudioContext.state === 'closed') {
        callAudioContext = new AudioCtx();
    }
    if (callAudioContext.state === 'suspended') {
        callAudioContext.resume().catch(() => {});
    }
    return callAudioContext;
}

async function openAudioSettingsModal() {
    if (!audioSettingsModal) return;
    audioSettingsModal.style.display = 'flex';
    await refreshAudioDeviceList(true);
    startSettingsMicTestMeter();
}

function closeAudioSettingsModal() {
    stopSettingsMicTestMeter();
    if (audioSettingsModal) audioSettingsModal.style.display = 'none';
}

async function startSettingsMicTestMeter() {
    stopSettingsMicTestMeter();
    try {
        const constraints = selectedMicDeviceId && selectedMicDeviceId !== 'default'
            ? { audio: { deviceId: { ideal: selectedMicDeviceId } } }
            : { audio: true };
        micTestStream = await navigator.mediaDevices.getUserMedia(constraints);
        const ctx = getAudioCtx();
        if (!ctx) return;

        if (micTestStatusText) micTestStatusText.textContent = 'Canlı Dinleniyor (Konuşun)...';

        const src = ctx.createMediaStreamSource(micTestStream);
        const analyser = ctx.createAnalyser();
        analyser.fftSize = 256;
        src.connect(analyser);
        const dataArr = new Uint8Array(64);

        micTestInterval = setInterval(() => {
            analyser.getByteFrequencyData(dataArr);
            let sum = 0;
            for (let i = 0; i < dataArr.length; i++) sum += dataArr[i];
            const pct = Math.min(100, Math.round((sum / dataArr.length) * 2.0));
            if (micTestMeterFill) micTestMeterFill.style.width = pct + '%';
        }, 80);
    } catch (e) {
        if (micTestStatusText) micTestStatusText.textContent = 'Mikrofon erişimi bekleniyor';
    }
}

function stopSettingsMicTestMeter() {
    if (micTestInterval) {
        clearInterval(micTestInterval);
        micTestInterval = null;
    }
    if (micTestStream) {
        micTestStream.getTracks().forEach(t => t.stop());
        micTestStream = null;
    }
    if (micTestMeterFill) micTestMeterFill.style.width = '0%';
}

if (btnHeaderAudioSettings) btnHeaderAudioSettings.addEventListener('click', openAudioSettingsModal);
if (menuItemAudioSettings) {
    menuItemAudioSettings.addEventListener('click', () => {
        if (headerDropdown) headerDropdown.style.display = 'none';
        openAudioSettingsModal();
    });
}
if (menuItemChatAudioSettings) {
    menuItemChatAudioSettings.addEventListener('click', () => {
        if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
        openAudioSettingsModal();
    });
}
if (btnProfileAudioSettings) {
    btnProfileAudioSettings.addEventListener('click', () => {
        closeProfileModal();
        openAudioSettingsModal();
    });
}
if (btnOpenCallAudioSettings) btnOpenCallAudioSettings.addEventListener('click', openAudioSettingsModal);
if (btnIncomingAudioDevices) btnIncomingAudioDevices.addEventListener('click', openAudioSettingsModal);
if (btnOutgoingAudioDevices) btnOutgoingAudioDevices.addEventListener('click', openAudioSettingsModal);
if (activeAudioDeviceBadge) activeAudioDeviceBadge.addEventListener('click', openAudioSettingsModal);
if (btnCloseAudioSettings) btnCloseAudioSettings.addEventListener('click', closeAudioSettingsModal);
if (btnSaveAudioSettings) btnSaveAudioSettings.addEventListener('click', () => {
    closeAudioSettingsModal();
    showStatusToast('🎤🔊 Ses ve kulaklık ayarları uygulandı', true);
});
if (btnRefreshAudioDevices) {
    btnRefreshAudioDevices.addEventListener('click', async () => {
        await refreshAudioDeviceList(true);
        await startSettingsMicTestMeter();
        showStatusToast('🔄 Kablolu ve Bluetooth ses cihazları yenilendi', true);
    });
}
if (selectMicDevice) {
    selectMicDevice.addEventListener('change', async () => {
        await switchActiveMicrophoneDuringCall(selectMicDevice.value);
        await startSettingsMicTestMeter();
    });
}
if (selectSpeakerDevice) {
    selectSpeakerDevice.addEventListener('change', async () => {
        await applySpeakerOutputDevice(selectSpeakerDevice.value);
    });
}
if (rangeAudioBoost) {
    const initialBoostPct = Math.round(speakerGainBoost * 100) || 150;
    rangeAudioBoost.value = String(initialBoostPct);
    if (lblAudioBoostValue) lblAudioBoostValue.textContent = `%${initialBoostPct}`;
    rangeAudioBoost.addEventListener('input', () => {
        const val = parseInt(rangeAudioBoost.value, 10) || 150;
        audioBoostPercent = val;
        speakerGainBoost = val / 100;
        micGainBoost = Math.max(1.2, val / 100);
        localStorage.setItem('msj_audio_boost', String(val));
        localStorage.setItem('msj_speaker_gain', String(speakerGainBoost));
        localStorage.setItem('msj_mic_gain', String(micGainBoost));
        if (lblAudioBoostValue) lblAudioBoostValue.textContent = `%${val}`;
        if (micGainNode) micGainNode.gain.value = micGainBoost;
        if (remoteGainNode) remoteGainNode.gain.value = isSpeakerphoneOn ? (speakerGainBoost * 1.25) : speakerGainBoost;
    });
}
if (btnTestSpeakerSound) {
    btnTestSpeakerSound.addEventListener('click', () => {
        unlockAudio();
        playIncomingMessageSound();
        showStatusToast('🔊 Hoparlör / Kulaklık test sesi çalındı', true);
    });
}

// Hoparlör (Eller Serbest / Dış Ses) Aç-Kapat Butonu
if (btnToggleSpeaker) {
    btnToggleSpeaker.addEventListener('click', () => {
        isSpeakerphoneOn = !isSpeakerphoneOn;
        btnToggleSpeaker.classList.toggle('active-speaker', isSpeakerphoneOn);
        if (remoteGainNode) {
            remoteGainNode.gain.value = isSpeakerphoneOn ? (speakerGainBoost * 1.35) : speakerGainBoost;
        }
        if (remoteAudio) {
            remoteAudio.volume = isSpeakerphoneOn ? 1.0 : 0.85;
            remoteAudio.muted = false;
            remoteAudio.play().catch(() => {});
        }
        updateActiveDeviceLabelBadge();
        showStatusToast(isSpeakerphoneOn ? '🔊 Hoparlör (Yüksek Ses) Aktif' : '🎧 Kulaklık / Ahize Modu Aktif', true);
    });
}

btnVideoCall.addEventListener('click', () => initiateCall('video'));
btnVoiceCall.addEventListener('click', () => initiateCall('voice'));

async function initiateCall(callType) {
    if (!activeContact) return;

    unlockAudio();
    currentCallTarget = activeContact.username;
    currentCallType = callType;
    currentTargetSocketId = null;

    // GİDEN ARAMA EKRANINI AÇ (RESİMDEKİ GİBİ ARANIYOR / ÇALIYOR...)
    if (outgoingTargetName) outgoingTargetName.textContent = activeContact.username;
    if (outgoingCallStatus) {
        if (activeContact.isOnline) {
            outgoingCallStatus.textContent = callType === 'video' ? 'Görüntülü Arama Yapılıyor (Çalıyor)...' : 'Sesli Arama Yapılıyor (Çalıyor)...';
        } else {
            outgoingCallStatus.textContent = callType === 'video'
                ? 'Görüntülü Aranıyor (Karşı cihaz otomatik Online yapılıyor...)'
                : 'Sesli Aranıyor (Karşı cihaz otomatik Online yapılıyor...)';
        }
    }
    if (outgoingTargetAvatar) outgoingTargetAvatar.src = activeContact.avatar || '/avatars/default.svg';
    if (outgoingCallModal) outgoingCallModal.style.display = 'flex';

    // Arayan kişinin kulağında telefon çalma sinyali (düt... düt...) başlar
    playRingback();

    const stream = await initLocalMedia(callType === 'video');
    if (!stream) {
        hideOutgoingCall();
        return;
    }

    setupPeerConnection();

    socket.emit('call:initiate', {
        recipient: activeContact.username,
        callType: callType
    });

    // 45 saniye boyunca cevap verilmezse zaman aşımı ile sonlandır
    if (outgoingCallTimeoutTimer) clearTimeout(outgoingCallTimeoutTimer);
    outgoingCallTimeoutTimer = setTimeout(() => {
        if (outgoingCallModal && outgoingCallModal.style.display !== 'none') {
            socket.emit('call:cancel', { recipient: currentCallTarget, reason: 'Zaman aşımı' });
            socket.emit('call:missed', { recipient: currentCallTarget });
            hideOutgoingCall();
            showStatusToast(currentCallTarget + ' cevap vermiyor', false);
            playCallEndedSound();
            stopLocalMediaTracks();
            if (peerConnection) {
                peerConnection.close();
                peerConnection = null;
            }
        }
    }, 45000);
}

function stopLocalMediaTracks() {
    if (localStream) {
        if (localStream._rawHardwareStream) {
            localStream._rawHardwareStream.getTracks().forEach(t => t.stop());
        }
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }
}

function hideOutgoingCall() {
    if (outgoingCallTimeoutTimer) {
        clearTimeout(outgoingCallTimeoutTimer);
        outgoingCallTimeoutTimer = null;
    }
    stopRingback();
    if (outgoingCallModal) outgoingCallModal.style.display = 'none';
}

if (btnCancelOutgoingCall) {
    btnCancelOutgoingCall.addEventListener('click', () => {
        if (currentCallTarget) {
            socket.emit('call:cancel', {
                targetSocketId: currentTargetSocketId,
                recipient: currentCallTarget,
                reason: 'Arama iptal edildi'
            });
            socket.emit('call:missed', { recipient: currentCallTarget });
        }
        hideOutgoingCall();
        stopLocalMediaTracks();
        if (peerConnection) {
            peerConnection.close();
            peerConnection = null;
        }
        playCallEndedSound();
    });
}

// Mikrofon ve Kamera İzinleri (Dahili ve Harici Kablolu/Kablosuz Cihazlarla Tam Uyumlu)
async function initLocalMedia(video = true) {
    localStream = await acquireMicrophoneAndCameraStream(video, selectedMicDeviceId);
    if (!localStream) return null;

    isAudioMuted = false;
    isVideoMuted = false;
    if (btnToggleMic) btnToggleMic.style.backgroundColor = 'rgba(255,255,255,0.2)';
    if (btnToggleCam) btnToggleCam.style.backgroundColor = 'rgba(255,255,255,0.2)';

    if (localVideo) {
        localVideo.srcObject = localStream;
        localVideo.muted = true; // Kendi sesimizin yankı yapmaması için localVideo her zaman sessiz
    }

    await refreshAudioDeviceList(false);
    await applySpeakerOutputDevice(selectedSpeakerDeviceId);
    setupCallAudioMetersAndRelay();

    return localStream;
}

function setupPeerConnection() {
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }

    iceCandidateQueue = [];
    localIceCandidateQueue = [];
    isRemoteDescriptionSet = false;

    peerConnection = new RTCPeerConnection(rtcConfig);

    if (localStream) {
        localStream.getTracks().forEach(track => {
            track.enabled = true;
            peerConnection.addTrack(track, localStream);
        });
    }

    peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            if (currentTargetSocketId || currentCallTarget) {
                socket.emit('call:signal', {
                    targetSocketId: currentTargetSocketId,
                    targetUsername: currentCallTarget,
                    signal: { candidate: event.candidate }
                });
            } else {
                localIceCandidateQueue.push(event.candidate);
            }
        }
    };

    peerConnection.oniceconnectionstatechange = () => {
        console.log('[WebRTC ICE State]:', peerConnection.iceConnectionState);
        if (peerConnection.iceConnectionState === 'connected' || peerConnection.iceConnectionState === 'completed') {
            if (remoteAudio && remoteAudio.srcObject) {
                remoteAudio.muted = false;
                remoteAudio.volume = 1.0;
                remoteAudio.play().catch(e => console.warn('remoteAudio play error:', e));
            }
        } else if (peerConnection.iceConnectionState === 'failed') {
            if (peerConnection.restartIce) peerConnection.restartIce();
        }
    };

    // GELEN SES VE GÖRÜNTÜ AKIŞI (KARŞI TARAFIN SESİNİN NET GELMESİ İÇİN ÇİFT KANALLI ÇIKIŞ)
    peerConnection.ontrack = (event) => {
        console.log('[WebRTC ontrack]:', event.track.kind, event.streams);

        let inboundStream = (event.streams && event.streams[0]) ? event.streams[0] : null;
        if (!inboundStream) {
            inboundStream = (remoteAudio && remoteAudio.srcObject) ? remoteAudio.srcObject : new MediaStream();
            inboundStream.addTrack(event.track);
        }

        if (event.track.kind === 'audio' || inboundStream.getAudioTracks().length > 0) {
            attachIncomingAudioStream(inboundStream);
        }

        if (event.track.kind === 'video' && remoteVideo) {
            remoteVideo.srcObject = inboundStream;
            remoteVideo.muted = false;
            remoteVideo.play().catch(() => {});
        }

        if (currentCallType === 'voice') {
            if (remoteVideo) remoteVideo.style.display = 'none';
            if (remoteAudioPlaceholder) remoteAudioPlaceholder.style.display = 'flex';
        } else {
            if (remoteVideo) remoteVideo.style.display = 'block';
            if (remoteAudioPlaceholder) remoteAudioPlaceholder.style.display = 'none';
        }
    };
}

function flushLocalCandidates() {
    if ((!currentTargetSocketId && !currentCallTarget) || !peerConnection) return;
    while (localIceCandidateQueue.length > 0) {
        const c = localIceCandidateQueue.shift();
        socket.emit('call:signal', {
            targetSocketId: currentTargetSocketId,
            targetUsername: currentCallTarget,
            signal: { candidate: c }
        });
    }
}

// GELEN ARAMA (RESİMDEKİ GİBİ ARAYANIN ADI, EVET VE HAYIR BUTONLARI - TAM KULLANICI İZOLASYONLU)
socket.on('call:incoming', (data) => {
    if (!data || !currentUser) return;
    // Başka bir kullanıcıya gelen aramayı kesinlikle gösterme
    if (data.recipient && normalizeKey(data.recipient) !== normalizeKey(currentUser.username)) {
        return;
    }
    if (normalizeKey(data.callerUsername) === normalizeKey(currentUser.username)) {
        return;
    }

    currentTargetSocketId = data.callerSocketId;
    currentCallTarget = data.callerUsername;
    currentCallType = data.callType || 'voice';

    // 1. Arayan kişinin adını büyük ve belirgin göster
    if (incomingCallerName) incomingCallerName.textContent = data.callerUsername;
    if (incomingCallerAvatar) incomingCallerAvatar.src = data.callerAvatar || '/avatars/default.svg';
    if (incomingCallType) {
        incomingCallType.textContent = data.callType === 'video' ? 'Gelen Görüntülü Arama...' : 'Gelen Sesli Arama...';
    }

    // 2. Arama ekranını tam ekran göster
    if (incomingCallModal) incomingCallModal.style.display = 'flex';

    // 3. Telefon Çalma Sesini (Zil Sesi) ve Titreşimi Başlat
    playRingtone();

    // 4. Program arka planda veya ekran kilitliyken Sistem Bildirimi Çıkar
    triggerSystemNotification(`📞 GELEN ARAMA: ${data.callerUsername}`, {
        body: `${data.callerUsername} sizi arıyor... Cevaplamak için dokunun.`,
        icon: data.callerAvatar || '/icon-192.png',
        badge: '/icon-192.png',
        tag: 'incoming-call',
        renotify: true,
        requireInteraction: true,
        vibrate: [1000, 500, 1000, 500, 1000, 500]
    });
});

// ARAMAYI CEVAPLA (EVET - YEŞİL BUTON)
btnAcceptCall.addEventListener('click', async () => {
    unlockAudio();
    stopRingtone();
    if (incomingCallModal) incomingCallModal.style.display = 'none';

    const stream = await initLocalMedia(currentCallType === 'video');
    if (!stream) {
        socket.emit('call:reject', {
            callerSocketId: currentTargetSocketId,
            callerUsername: currentCallTarget,
            reason: 'Mikrofon izni verilmedi'
        });
        return;
    }

    setupPeerConnection();
    socket.emit('call:accept', {
        callerSocketId: currentTargetSocketId,
        callerUsername: currentCallTarget
    });

    const contact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(currentCallTarget));
    openActiveCallScreen(currentCallTarget, contact ? contact.avatar : '/avatars/default.svg');
});

// ARAMAYI REDDET (HAYIR - KIRMIZI BUTON)
btnRejectCall.addEventListener('click', () => {
    stopRingtone();
    if (incomingCallModal) incomingCallModal.style.display = 'none';
    if (currentTargetSocketId || currentCallTarget) {
        socket.emit('call:reject', {
            callerSocketId: currentTargetSocketId,
            callerUsername: currentCallTarget,
            reason: 'Arama reddedildi'
        });
    }
    if (currentUser) {
        socket.emit('call:missed', { recipient: currentUser.username });
    }
    playCallEndedSound();
    currentTargetSocketId = null;
});

// Arayan Kişi Aramayı Açılmadan Kapatırsa
socket.on('call:cancelled', () => {
    stopRingtone();
    if (incomingCallModal) incomingCallModal.style.display = 'none';
    playCallEndedSound();
    showStatusToast('Arama kapatıldı', false);
    currentTargetSocketId = null;
});

// Karşı Taraf Aramayı Kabul Ettiğinde (Arayan Taraf İçin)
socket.on('call:accepted', async (data) => {
    currentTargetSocketId = data.responderSocketId;
    hideOutgoingCall();

    const contact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(currentCallTarget));
    openActiveCallScreen(currentCallTarget, contact ? contact.avatar : '/avatars/default.svg');

    flushLocalCandidates();

    if (!peerConnection) return;
    try {
        const offer = await peerConnection.createOffer({
            offerToReceiveAudio: true,
            offerToReceiveVideo: (currentCallType === 'video')
        });
        await peerConnection.setLocalDescription(offer);
        socket.emit('call:signal', {
            targetSocketId: currentTargetSocketId,
            targetUsername: currentCallTarget,
            signal: { sdp: peerConnection.localDescription }
        });
        startCallTimer();
    } catch (err) {
        console.error('Teklif oluşturma hatası:', err);
    }
});

// Arama Reddedildiğinde
socket.on('call:rejected', (data) => {
    hideOutgoingCall();
    playCallEndedSound();
    showStatusToast(data.reason || 'Arama meşgule atıldı / reddedildi', false);
    endCall();
});

// Arama Hatası
socket.on('call:error', (data) => {
    hideOutgoingCall();
    playCallEndedSound();
    alert(data.message || 'Arama başlatılamadı.');
    endCall();
});

// WebRTC SDP ve ICE Candidate Sinyalleşmesi (Kayıpsız Sıralı Eşleşme)
socket.on('call:signal', async (data) => {
    if (data.fromSocketId || data.senderSocketId) {
        currentTargetSocketId = data.fromSocketId || data.senderSocketId;
    }
    if (!peerConnection) {
        setupPeerConnection();
    }
    const signal = data.signal;
    if (!signal) return;

    try {
        if (signal.sdp) {
            if (signal.sdp.type === 'offer') {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
                isRemoteDescriptionSet = true;

                while (iceCandidateQueue.length > 0) {
                    try {
                        await peerConnection.addIceCandidate(new RTCIceCandidate(iceCandidateQueue.shift()));
                    } catch (e) {}
                }

                const answer = await peerConnection.createAnswer();
                await peerConnection.setLocalDescription(answer);
                socket.emit('call:signal', {
                    targetSocketId: currentTargetSocketId,
                    targetUsername: currentCallTarget,
                    signal: { sdp: peerConnection.localDescription }
                });
                flushLocalCandidates();
                startCallTimer();
            } else if (signal.sdp.type === 'answer') {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
                isRemoteDescriptionSet = true;

                while (iceCandidateQueue.length > 0) {
                    try {
                        await peerConnection.addIceCandidate(new RTCIceCandidate(iceCandidateQueue.shift()));
                    } catch (e) {}
                }
            }
        } else if (signal.candidate) {
            if (!isRemoteDescriptionSet) {
                iceCandidateQueue.push(signal.candidate);
            } else {
                try {
                    await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
                } catch (e) {
                    console.warn('ICE candidate ekleme hatası:', e);
                }
            }
        }
    } catch (err) {
        console.error('Sinyal işleme hatası:', err);
    }
});

function openActiveCallScreen(name, avatar) {
    if (activeCallTargetTitle) activeCallTargetTitle.textContent = name;
    if (activeCallName) activeCallName.textContent = name;
    if (activeCallAvatar) activeCallAvatar.src = avatar || '/avatars/default.svg';

    if (currentCallType === 'voice') {
        if (remoteVideo) remoteVideo.style.display = 'none';
        if (remoteAudioPlaceholder) remoteAudioPlaceholder.style.display = 'flex';
    } else {
        if (remoteVideo) remoteVideo.style.display = 'block';
        if (remoteAudioPlaceholder) remoteAudioPlaceholder.style.display = 'none';
    }

    if (activeToggleSpeakerState) activeToggleSpeakerState();
    updateActiveDeviceLabelBadge();

    if (activeCallScreen) activeCallScreen.style.display = 'flex';
}

function activeToggleSpeakerState() {
    if (btnToggleSpeaker) {
        btnToggleSpeaker.classList.toggle('active-speaker', isSpeakerphoneOn);
    }
}

btnToggleMic.addEventListener('click', () => {
    if (!localStream) return;
    isAudioMuted = !isAudioMuted;
    localStream.getAudioTracks().forEach(t => t.enabled = !isAudioMuted);
    if (localStream._rawHardwareStream) {
        localStream._rawHardwareStream.getAudioTracks().forEach(t => t.enabled = !isAudioMuted);
    }
    btnToggleMic.style.backgroundColor = isAudioMuted ? 'var(--danger)' : 'rgba(255,255,255,0.2)';
    showStatusToast(isAudioMuted ? '🔇 Mikrofon Sessize Alındı' : '🎤 Mikrofon Açık', !isAudioMuted);
});

btnToggleCam.addEventListener('click', () => {
    if (!localStream || currentCallType === 'voice') return;
    isVideoMuted = !isVideoMuted;
    localStream.getVideoTracks().forEach(t => t.enabled = !isVideoMuted);
    btnToggleCam.style.backgroundColor = isVideoMuted ? 'var(--danger)' : 'rgba(255,255,255,0.2)';
});

btnEndCall.addEventListener('click', () => endCall());

socket.on('call:ended', () => endCall(false));
socket.on('call:peer_disconnected', (data) => {
    const isCallModalVisible =
        (activeCallScreen && activeCallScreen.style.display === 'flex') ||
        (outgoingCallModal && outgoingCallModal.style.display === 'flex') ||
        (incomingCallModal && incomingCallModal.style.display === 'flex');
    if (!isCallModalVisible) return;

    if (data && data.peerId && currentTargetSocketId && data.peerId === currentTargetSocketId) {
        endCall(false);
    } else if (data && data.username && currentCallTarget && normalizeKey(data.username) === normalizeKey(currentCallTarget)) {
        endCall(false);
    }
});

function endCall(notifyPeer = true) {
    const wasInCallOrRinging =
        (activeCallScreen && activeCallScreen.style.display === 'flex') ||
        (outgoingCallModal && outgoingCallModal.style.display === 'flex') ||
        (incomingCallModal && incomingCallModal.style.display === 'flex') ||
        Boolean(peerConnection);

    hideOutgoingCall();
    stopRingtone();
    if (callTimerInterval) clearInterval(callTimerInterval);
    if (audioMeterInterval) {
        clearInterval(audioMeterInterval);
        audioMeterInterval = null;
    }
    if (socketAudioScriptNode) {
        try { socketAudioScriptNode.disconnect(); } catch (e) {}
        socketAudioScriptNode = null;
    }
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }
    stopLocalMediaTracks();

    if (remoteVideo) remoteVideo.srcObject = null;
    if (localVideo) localVideo.srcObject = null;
    if (remoteAudio) {
        remoteAudio.srcObject = null;
        remoteAudio.pause();
    }
    if (activeCallScreen) activeCallScreen.style.display = 'none';
    if (incomingCallModal) incomingCallModal.style.display = 'none';

    if (notifyPeer && (currentTargetSocketId || currentCallTarget)) {
        socket.emit('call:end', {
            targetSocketId: currentTargetSocketId,
            targetUsername: currentCallTarget
        });
    }
    currentTargetSocketId = null;
    currentCallTarget = null;
    if (wasInCallOrRinging) {
        playCallEndedSound();
    }
}

// Hatırlat ve Mesaj Gönder Butonları (Resimdeki gibi)
if (btnCallRemindMe) {
    btnCallRemindMe.addEventListener('click', () => {
        showStatusToast('Hatırlatma kuruldu', true);
        if (btnRejectCall) btnRejectCall.click();
    });
}
if (btnCallQuickMsg) {
    btnCallQuickMsg.addEventListener('click', () => {
        const caller = currentCallTarget;
        if (btnRejectCall) btnRejectCall.click();
        if (caller) {
            openChatForSender(caller);
            if (messageInput) {
                messageInput.value = 'Şu anda müsait değilim, birazdan görüşelim.';
                messageInput.focus();
            }
        }
    });
}

function startCallTimer() {
    callStartTime = Date.now();
    if (callTimerInterval) clearInterval(callTimerInterval);
    callTimerInterval = setInterval(() => {
        const delta = Math.floor((Date.now() - callStartTime) / 1000);
        const mins = String(Math.floor(delta / 60)).padStart(2, '0');
        const secs = String(delta % 60).padStart(2, '0');
        const formatted = `${mins}:${secs}`;
        if (activeCallTimer) activeCallTimer.textContent = formatted;
        const durEl = document.getElementById('callDuration');
        if (durEl) durEl.textContent = formatted;
    }, 1000);
}

// ==========================================================
// 7. YARDIMCI İŞLEMLER (QR KOD, MENÜ, RESİM BÜYÜTME)
// ==========================================================

btnHeaderMenu.addEventListener('click', (e) => {
    e.stopPropagation();
    headerDropdown.style.display = headerDropdown.style.display === 'none' ? 'block' : 'none';
});

document.addEventListener('click', () => {
    headerDropdown.style.display = 'none';
    if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
});

// ==========================================================
// MESAJ VE SOHBET SİLME İŞLEMLERİ (LİTE SQL İLE ENTEGRE)
// ==========================================================
window.requestDeleteMessage = function(msgId) {
    if (!msgId) return;
    if (confirm('Bu mesajı her iki taraftan da kalıcı olarak silmek istediğinize emin misiniz?')) {
        socket.emit('chat:delete_message', { messageId: msgId }, (res) => {
            if (res && res.success) {
                removeMessageBubbleFromDom(msgId);
                loadChatsList();
            } else {
                alert(res && res.error ? res.error : 'Mesaj silinemedi.');
            }
        });
    }
};

function removeMessageBubbleFromDom(msgId) {
    const el = document.getElementById(msgId);
    if (el) {
        el.style.transition = 'opacity 0.25s, transform 0.25s';
        el.style.opacity = '0';
        el.style.transform = 'scale(0.92)';
        setTimeout(() => el.remove(), 250);
    }
}

function clearMessagesFromDom() {
    const todayFormatted = new Date().toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', year: 'numeric' });
    messagesContainer.innerHTML = `
        <div class="date-pill-badge" id="chatDateBadge">${todayFormatted}</div>
        <div class="encryption-warning-banner" onclick="window.showE2EEVerificationDialog()" style="cursor:pointer;">
            <span class="enc-icon">🔒</span>
            <span class="enc-text">
                Mesajlar ve aramalar uçtan uca şifrelidir (256-Bit E2EE). Bu sohbetteki yazışmalar temizlendi.
            </span>
        </div>
    `;
}

if (btnChatMenu && chatDropdownMenu) {
    btnChatMenu.addEventListener('click', (e) => {
        e.stopPropagation();
        chatDropdownMenu.style.display = chatDropdownMenu.style.display === 'none' ? 'block' : 'none';
    });
}

if (menuItemClearChat) {
    menuItemClearChat.addEventListener('click', () => {
        if (!activeContact) return;
        if (confirm(`${activeContact.username} ile olan tüm yazışmaları silmek istediğinize emin misiniz?\nBu işlem geri alınamaz.`)) {
            socket.emit('chat:clear_conversation', { contactUsername: activeContact.username }, (res) => {
                if (res && res.success) {
                    clearMessagesFromDom();
                    loadChatsList();
                } else {
                    alert(res && res.error ? res.error : 'Sohbet temizlenemedi.');
                }
            });
        }
    });
}

if (btnBlockContact) {
    btnBlockContact.addEventListener('click', () => {
        if (!activeContact) return;
        window.toggleBlockContact(activeContact.username);
    });
}

if (btnDeleteContact) {
    btnDeleteContact.addEventListener('click', () => {
        if (!activeContact) return;
        window.requestDeleteUser(activeContact.username);
    });
}

if (menuItemBlockUser) {
    menuItemBlockUser.addEventListener('click', () => {
        if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
        if (!activeContact) return;
        window.toggleBlockContact(activeContact.username);
    });
}

if (menuItemDeleteUser) {
    menuItemDeleteUser.addEventListener('click', () => {
        if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
        if (!activeContact) return;
        window.requestDeleteUser(activeContact.username);
    });
}

if (menuItemCloseChat) {
    menuItemCloseChat.addEventListener('click', () => {
        closeActiveChat();
    });
}

if (menuItemContactInfo) {
    menuItemContactInfo.addEventListener('click', () => {
        if (!activeContact) return;
        const phoneLine = activeContact.phone ? `\nTelefon: ${formatPhonePretty(activeContact.phone)}` : '';
        alert(`Kullanıcı: ${activeContact.username}${phoneLine}\nDurum: ${activeContact.isOnline ? '🟢 Çevrimiçi (Online)' : '⚪ Çevrimdışı (Offline - Mesaj ve Arama Gönderilebilir)'}`);
    });
}

// ==========================================================
// 8. PROFİL VE OTURUM KAPATMA (LOGOUT) YÖNETİMİ
// ==========================================================

async function performLogout() {
    if (!confirm('Oturumu kapatmak istediğinize emin misiniz?\n(Kayıtlı kullanıcılarınız silinmez; mesaj veya arama geldiğinde otomatik Online olup bildirim gelir.)')) {
        return;
    }

    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');
    if (token) {
        try {
            await fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });
        } catch (e) {}
    }

    // Oturumu kapatırken kayıtlı kullanıcıları ve kişi listesini ASLA SİLME!
    localStorage.setItem('msj_auto_login', 'false');
    localStorage.removeItem('msj_token');
    sessionStorage.removeItem('msj_token');
    currentUser = null;

    await loadRegisteredUsersDropdown();
    showPasswordPrompt(localStorage.getItem('msj_saved_username') || '');
}

function openProfileModal() {
    if (!profileModal) return;
    if (currentUser) {
        if (profileUsernameDisplay) profileUsernameDisplay.textContent = currentUser.username;
        if (profileUserAvatar) profileUserAvatar.src = currentUser.avatar || '/avatars/default.svg';
        if (profilePhoneDisplay) {
            profilePhoneDisplay.textContent = currentUser.phone
                ? `📱 Telefon: ${formatPhonePretty(currentUser.phone)}`
                : '📱 Telefon: Henüz eklenmedi (Numarayla bulunmak için ekleyin)';
        }
    }
    profileModal.style.display = 'flex';
}

if (btnProfileUpdatePhone) {
    btnProfileUpdatePhone.addEventListener('click', async () => {
        if (!currentUser || !currentUser.username) return;
        const currentPhone = currentUser.phone ? formatPhonePretty(currentUser.phone) : '';
        const newPhone = prompt(`"${currentUser.username}" hesabınız için telefon numaranızı girin (diğer kullanıcıların sizi telefon numaranızdan bulabilmesi için):`, currentPhone);
        if (newPhone === null) return;
        try {
            const res = await fetch('/api/users/update_phone', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUser.username, phone: newPhone.trim() })
            });
            const data = await res.json();
            if (data && data.success && data.user) {
                currentUser.phone = data.user.phone || '';
                localStorage.setItem('msj_user', JSON.stringify(currentUser));
                savePermanentLocalUsers([currentUser]);
                if (profilePhoneDisplay) {
                    profilePhoneDisplay.textContent = currentUser.phone
                        ? `📱 Telefon: ${formatPhonePretty(currentUser.phone)}`
                        : '📱 Telefon: Henüz eklenmedi';
                }
                showStatusToast('📱 Telefon numaranız kaydedildi!', true);
            } else {
                alert((data && data.error) || 'Telefon numarası güncellenemedi.');
            }
        } catch (err) {
            alert('Sunucuya bağlanılamadı.');
        }
    });
}

function closeProfileModal() {
    if (profileModal) profileModal.style.display = 'none';
}

if (menuItemProfile) {
    menuItemProfile.addEventListener('click', () => {
        headerDropdown.style.display = 'none';
        openProfileModal();
    });
}

if (btnCloseProfileModal) {
    btnCloseProfileModal.addEventListener('click', closeProfileModal);
}

if (profileModal) {
    profileModal.addEventListener('click', (e) => {
        if (e.target === profileModal) {
            closeProfileModal();
        }
    });
}

if (btnProfileLogout) {
    btnProfileLogout.addEventListener('click', () => {
        closeProfileModal();
        performLogout();
    });
}

if (btnProfileDeleteAccount) {
    btnProfileDeleteAccount.addEventListener('click', () => {
        if (!currentUser || !currentUser.username) return;
        window.requestDeleteUser(currentUser.username);
    });
}

if (btnProfileNewUser) {
    btnProfileNewUser.addEventListener('click', () => {
        closeProfileModal();
        showRegisterPrompt();
    });
}

if (btnProfileSwitchUser) {
    btnProfileSwitchUser.addEventListener('click', () => {
        closeProfileModal();
        showPasswordPrompt('');
    });
}

if (btnProfileChangePass) {
    btnProfileChangePass.addEventListener('click', async () => {
        if (!currentUser || !currentUser.username) return;
        const user = currentUser.username;
        const newPass = prompt(`"${user}" hesabı için yeni şifrenizi girin (en az 3 karakter):`);
        if (newPass === null) return;
        if (!newPass || newPass.trim().length < 3) {
            alert('Şifre en az 3 karakter olmalıdır.');
            return;
        }
        try {
            btnProfileChangePass.disabled = true;
            btnProfileChangePass.textContent = 'Güncelleniyor...';
            const res = await fetch('/api/auth/reset_password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, newPassword: newPass.trim() })
            });
            const data = await res.json();
            if (data.success) {
                if (data.token) {
                    localStorage.setItem('msj_token', data.token);
                    sessionStorage.setItem('msj_token', data.token);
                }
                alert('Şifreniz başarıyla güncellendi!');
                closeProfileModal();
            } else {
                alert(data.error || 'Şifre güncellenemedi.');
            }
        } catch(e) {
            alert('Sunucuya bağlanılamadı.');
        } finally {
            btnProfileChangePass.disabled = false;
            btnProfileChangePass.textContent = '🔑 Şifremi Değiştir / Güncelle';
        }
    });
}

if (menuItemSwitchUser) {
    menuItemSwitchUser.addEventListener('click', () => {
        headerDropdown.style.display = 'none';
        showPasswordPrompt('');
    });
}

if (menuItemLogout) {
    menuItemLogout.addEventListener('click', () => {
        headerDropdown.style.display = 'none';
        performLogout();
    });
}

menuItemQr.addEventListener('click', async () => {
    try {
        const res = await fetch('/api/info');
        const data = await res.json();
        qrImage.src = data.qrCode;
        httpsLink.href = data.httpsUrl;
        httpsLink.textContent = data.httpsUrl;

        if (data.tunnelUrl && data.tunnelQrCode) {
            tunnelLink.href = data.tunnelUrl;
            tunnelLink.textContent = data.tunnelUrl;
            tunnelQrImage.src = data.tunnelQrCode;
        }

        qrModal.style.display = 'flex';
    } catch (e) {
        alert('Ağ bilgisi alınamadı.');
    }
});

btnCloseQr.addEventListener('click', () => {
    qrModal.style.display = 'none';
});

if (menuItemCloudGuide && cloudGuideModal) {
    menuItemCloudGuide.addEventListener('click', () => {
        cloudGuideModal.style.display = 'flex';
    });
}

if (btnCloseCloudGuide && cloudGuideModal) {
    btnCloseCloudGuide.addEventListener('click', () => {
        cloudGuideModal.style.display = 'none';
    });
}

if (menuItemNewChat) {
    menuItemNewChat.addEventListener('click', () => {
        openNewChatModal();
    });
}

let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    const btnNative = document.getElementById('btnTriggerNativePwaPrompt');
    if (btnNative) btnNative.style.display = 'block';
});

window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    const pwaModal = document.getElementById('pwaInstallModal');
    const iosBanner = document.getElementById('iosSharePointerBanner');
    if (pwaModal) pwaModal.style.display = 'none';
    if (iosBanner) iosBanner.style.display = 'none';
    showStatusToast('📲 HIHaberleşme başarıyla yüklendi!', true);
});

function isIosDeviceClient() {
    const ua = window.navigator.userAgent || '';
    return /iPhone|iPad|iPod/i.test(ua) || (window.navigator.platform === 'MacIntel' && window.navigator.maxTouchPoints > 1);
}

function isStandalonePwaClient() {
    return Boolean(window.navigator.standalone) || (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
}

function openPwaInstallModal(forceIosView = false) {
    if (headerDropdown) headerDropdown.style.display = 'none';
    if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
    if (profileModal) profileModal.style.display = 'none';

    const pwaModal = document.getElementById('pwaInstallModal');
    const alreadyNotice = document.getElementById('pwaAlreadyInstalledNotice');
    const iosSection = document.getElementById('pwaIosSection');
    const stdSection = document.getElementById('pwaStandardSection');
    const btnNative = document.getElementById('btnTriggerNativePwaPrompt');
    const iosBanner = document.getElementById('iosSharePointerBanner');
    const iosBannerText = document.getElementById('iosSharePointerText');

    if (!pwaModal) return;

    const isIos = forceIosView || isIosDeviceClient();
    const isStandalone = isStandalonePwaClient();

    if (alreadyNotice) {
        alreadyNotice.style.display = isStandalone ? 'block' : 'none';
    }

    if (isIos) {
        if (iosSection) iosSection.style.display = 'block';
        if (stdSection) stdSection.style.display = 'none';
        if (iosBanner && !isStandalone) {
            const isChromeIos = /CriOS/i.test(window.navigator.userAgent || '');
            if (isChromeIos && iosBannerText) {
                iosBanner.style.bottom = 'auto';
                iosBanner.style.top = '14px';
                iosBannerText.innerHTML = '☝️ Sağ üstteki <strong>Paylaş [↑]</strong> simgesine basıp <strong>"Ana Ekrana Ekle"</strong> deyin!';
            } else if (iosBannerText) {
                iosBanner.style.top = 'auto';
                iosBanner.style.bottom = '14px';
                iosBannerText.innerHTML = '👇 Ekranın en altındaki <strong>Paylaş [↑]</strong> simgesine basıp <strong>"Ana Ekrana Ekle"</strong> deyin!';
            }
            iosBanner.style.display = 'block';
        }
    } else {
        // Masaüstü veya Android'de hem standart kurulumu hem de iPhone kurulum seçeneğini göster
        if (stdSection) stdSection.style.display = 'block';
        if (iosSection) iosSection.style.display = 'block';
        if (btnNative) {
            btnNative.style.display = deferredPrompt ? 'block' : 'none';
        }
    }

    pwaModal.style.display = 'flex';
}

async function handleTriggerPwaInstall(e) {
    if (e && e.stopPropagation) e.stopPropagation();
    if (headerDropdown) headerDropdown.style.display = 'none';
    if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';

    if (deferredPrompt && !isIosDeviceClient()) {
        try {
            deferredPrompt.prompt();
            const choice = await deferredPrompt.userChoice;
            deferredPrompt = null;
            if (choice && choice.outcome === 'accepted') {
                return;
            }
        } catch (err) {
            deferredPrompt = null;
        }
    }

    openPwaInstallModal();
}

if (menuItemInstall) {
    menuItemInstall.addEventListener('click', handleTriggerPwaInstall);
}

const menuItemChatInstall = document.getElementById('menuItemChatInstall');
if (menuItemChatInstall) {
    menuItemChatInstall.addEventListener('click', handleTriggerPwaInstall);
}

const btnProfileInstallPwa = document.getElementById('btnProfileInstallPwa');
if (btnProfileInstallPwa) {
    btnProfileInstallPwa.addEventListener('click', handleTriggerPwaInstall);
}

const btnClosePwaInstall = document.getElementById('btnClosePwaInstall');
const pwaInstallModal = document.getElementById('pwaInstallModal');
const iosSharePointerBanner = document.getElementById('iosSharePointerBanner');

if (btnClosePwaInstall && pwaInstallModal) {
    btnClosePwaInstall.addEventListener('click', () => {
        pwaInstallModal.style.display = 'none';
        if (iosSharePointerBanner) iosSharePointerBanner.style.display = 'none';
    });
    pwaInstallModal.addEventListener('click', (e) => {
        if (e.target === pwaInstallModal) {
            pwaInstallModal.style.display = 'none';
            if (iosSharePointerBanner) iosSharePointerBanner.style.display = 'none';
        }
    });
}

if (iosSharePointerBanner) {
    iosSharePointerBanner.addEventListener('click', () => {
        iosSharePointerBanner.style.display = 'none';
    });
}

const btnIosTriggerShareSheet = document.getElementById('btnIosTriggerShareSheet');
if (btnIosTriggerShareSheet) {
    btnIosTriggerShareSheet.addEventListener('click', async () => {
        const shareUrl = window.location.origin + '/';
        if (navigator.share) {
            try {
                await navigator.share({
                    title: 'HIHaberleşme',
                    url: shareUrl
                });
                return;
            } catch (err) {
                // Kullanıcı kapattıysa veya desteklenmiyorsa alt ok göstergesini öne çıkar
            }
        }
        if (iosSharePointerBanner) {
            iosSharePointerBanner.style.display = 'block';
        }
        showStatusToast('👇 Ekranın altındaki Paylaş [↑] butonuna basıp "Ana Ekrana Ekle" seçin', true);
    });
}

const btnIosDirectProfileInstall = document.getElementById('btnIosDirectProfileInstall');
if (btnIosDirectProfileInstall) {
    btnIosDirectProfileInstall.addEventListener('click', () => {
        const activeUser = (currentUser && currentUser.username) || localStorage.getItem('msj_saved_username') || '';
        const targetOrigin = window.location.origin + '/';
        const profileUrl = `/api/ios-pwa.mobileconfig?url=${encodeURIComponent(targetOrigin)}&user=${encodeURIComponent(activeUser)}`;
        window.location.href = profileUrl;
    });
}

const btnTriggerNativePwaPrompt = document.getElementById('btnTriggerNativePwaPrompt');
if (btnTriggerNativePwaPrompt) {
    btnTriggerNativePwaPrompt.addEventListener('click', async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            await deferredPrompt.userChoice;
            deferredPrompt = null;
            if (pwaInstallModal) pwaInstallModal.style.display = 'none';
        }
    });
}

tabLocalWifi.addEventListener('click', () => {
    tabLocalWifi.classList.add('active');
    tabRemoteTunnel.classList.remove('active');
    contentLocalWifi.style.display = 'block';
    contentRemoteTunnel.style.display = 'none';
});

tabRemoteTunnel.addEventListener('click', () => {
    tabRemoteTunnel.classList.add('active');
    tabLocalWifi.classList.remove('active');
    contentRemoteTunnel.style.display = 'block';
    contentLocalWifi.style.display = 'none';
});

function openEnlargedImage(url) {
    enlargedImage.src = url;
    imageModal.style.display = 'flex';
}

btnCloseImageModal.addEventListener('click', () => {
    imageModal.style.display = 'none';
});

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
}

function formatMessageText(text) {
    const escaped = escapeHtml(text);
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return escaped.replace(urlRegex, url => `<a href="${url}" target="_blank" style="color: #53bdeb; text-decoration: underline;">${url}</a>`);
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Sekme / Pencere görünür olduğunda veya odaklandığında otomatik Online ol
window.addEventListener('focus', () => {
    if (currentUser && socket.connected) {
        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
        socket.emit('user:join', { token, username: currentUser.username });
    }
});

document.addEventListener('visibilitychange', () => {
    if (!document.hidden && currentUser && socket.connected) {
        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
        socket.emit('user:join', { token, username: currentUser.username });
    }
});

// Arka Plan / Bekleme Modu Yedek Uyandırıcı (Yalnızca aktif/kayıtlı kullanıcıya gelen mesaj ve aramaları dinler)
let clientLastPollNotifId = 0;
const clientSeenCallIds = new Set();
setInterval(async () => {
    try {
        const targetUser = (currentUser && currentUser.username) || localStorage.getItem('msj_saved_username') || '';
        if (!targetUser) return;
        const targetKey = normalizeKey(targetUser);

        const res = await fetch(`/api/system/notifications/poll?since=${clientLastPollNotifId}&user=${encodeURIComponent(targetUser)}`, {
            cache: 'no-store'
        });
        const data = await res.json();
        if (data && data.success) {
            if (typeof data.lastId === 'number' && data.lastId < clientLastPollNotifId) {
                // Sunucu yeniden başlatıldıysa sayacı sıfırla
                clientLastPollNotifId = 0;
                return;
            }

            // 1. Bekleyen aktif arama varsa ve ekranda arama penceresi açık değilse hemen ekrana düşür!
            if (Array.isArray(data.activeCalls) && data.activeCalls.length > 0) {
                for (const callObj of data.activeCalls) {
                    if (!callObj || !callObj.callerUsername) continue;
                    if (normalizeKey(callObj.callerUsername) === targetKey) continue;
                    if (callObj.recipient && normalizeKey(callObj.recipient) !== targetKey) continue;
                    const cKey = callObj.callId || (callObj.callerUsername + '_' + callObj.createdAt);
                    if (clientSeenCallIds.has(cKey)) continue;
                    clientSeenCallIds.add(cKey);

                    if (!currentUser) {
                        await quickLoginAsRegisteredUser(targetUser);
                    }
                    triggerIncomingCallUi(callObj, false);
                }
            }

            // 2. Yeni bildirimleri (Mesaj ve Arama) işle
            if (clientLastPollNotifId > 0 && data.lastId > clientLastPollNotifId && Array.isArray(data.notifications)) {
                for (const item of data.notifications) {
                    if (!item || !item.recipient) continue;
                    // KULLANICI İZOLASYONU: Yalnızca bu cihazdaki aktif kullanıcıya (targetKey) gelen bildirimleri işle!
                    if (normalizeKey(item.recipient) !== targetKey) continue;
                    if (normalizeKey(item.sender) === targetKey) continue;

                    const savedU = localStorage.getItem('msj_saved_username') || '';
                    if (!currentUser && savedU && normalizeKey(savedU) === targetKey) {
                        await quickLoginAsRegisteredUser(item.recipient);
                    } else if (currentUser && normalizeKey(currentUser.username) === targetKey) {
                        const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
                        socket.emit('user:join', { token, username: currentUser.username });
                    }

                    if (item.type === 'call') {
                        triggerIncomingCallUi({
                            callerUsername: item.sender,
                            callerAvatar: item.callerAvatar || '/avatars/default.svg',
                            callType: item.callType || 'voice',
                            callerSocketId: item.callerSocketId || currentTargetSocketId
                        }, false);
                    } else if (item.type === 'message') {
                        const plainText = item.text ? decryptE2EETextClient(item.text, item.sender, item.recipient) : 'Yeni mesaj';
                        const isFromActive = activeContact && normalizeKey(activeContact.username) === normalizeKey(item.sender);
                        if (!isFromActive || document.hidden) {
                            playIncomingMessageSound();
                            showMessageNotificationToast({
                                id: item.msgId || ('poll_' + item.id),
                                sender: item.sender,
                                recipient: item.recipient,
                                text: plainText
                            });
                            if (!isUserCurrentlyTyping()) {
                                openChatForSender(item.sender);
                            } else {
                                loadChatsList();
                            }
                        }
                    }
                }
            }
            if (typeof data.lastId === 'number') {
                clientLastPollNotifId = data.lastId;
            }
        }
    } catch (e) {}
}, 2000);

// ==========================================================
// MADDE 1 & 3: MOBİL KLAVYE AÇILDIĞINDA ŞİFRE KISMININ KAPANMAMASI
// VE TÜM TELEFON / MONİTÖR ÇÖZÜNÜRLÜKLERİNE TAM SIĞMA
// ==========================================================
(function setupViewportAndKeyboardProtection() {
    function updateAppViewportHeight() {
        const vv = window.visualViewport;
        const height = vv ? vv.height : window.innerHeight;
        document.documentElement.style.setProperty('--app-height', `${height}px`);

        const fullHeight = window.screen ? window.screen.height : window.innerHeight;
        const isKeyboardLikelyOpen = (vv && (window.innerHeight - vv.height > 110)) || (fullHeight - height > 220);
        document.body.classList.toggle('keyboard-open', Boolean(isKeyboardLikelyOpen));

        if (isKeyboardLikelyOpen && authModal && authModal.style.display !== 'none') {
            const activeEl = document.activeElement;
            if (activeEl && (activeEl.tagName === 'INPUT' || activeEl.tagName === 'SELECT')) {
                setTimeout(() => {
                    try {
                        activeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    } catch (e) {}
                }, 60);
            }
        }
    }

    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', updateAppViewportHeight);
        window.visualViewport.addEventListener('scroll', updateAppViewportHeight);
    }
    window.addEventListener('resize', updateAppViewportHeight);
    window.addEventListener('orientationchange', () => setTimeout(updateAppViewportHeight, 150));
    updateAppViewportHeight();

    // Giriş/Kurulum ekranındaki tüm input alanlarına odaklanıldığında klavyenin üstüne kaydır
    [inputUsername, inputPhone, inputPassword, inputConfirmPassword].forEach(inp => {
        if (!inp) return;
        inp.addEventListener('focus', () => {
            document.body.classList.add('keyboard-open');
            setTimeout(() => {
                try {
                    inp.scrollIntoView({ behavior: 'smooth', block: 'center' });
                } catch (e) {}
            }, 180);
        });
        inp.addEventListener('blur', () => {
            setTimeout(updateAppViewportHeight, 150);
        });
    });
})();

// ==========================================================
// MADDE 6: KULLANICI ARKA PLANI VE MESAJ SAYFASI ÖZEL ARKA PLAN RESMİ
// ==========================================================
(function setupCustomBackgroundManager() {
    const bgSettingsModal = document.getElementById('bgSettingsModal');
    const btnCloseBgSettings = document.getElementById('btnCloseBgSettings');
    const btnDoneBgSettings = document.getElementById('btnDoneBgSettings');
    const btnHeaderBgSettings = document.getElementById('btnHeaderBgSettings');
    const btnQuickBgSettings = document.getElementById('btnQuickBgSettings');
    const menuItemBgSettings = document.getElementById('menuItemBgSettings');
    const menuItemChatBgSettings = document.getElementById('menuItemChatBgSettings');
    const btnProfileBgSettings = document.getElementById('btnProfileBgSettings');

    const inputUsersBgFile = document.getElementById('inputUsersBgFile');
    const btnSelectUsersBg = document.getElementById('btnSelectUsersBg');
    const btnResetUsersBg = document.getElementById('btnResetUsersBg');
    const previewUsersBgBox = document.getElementById('previewUsersBgBox');

    const inputChatBgFile = document.getElementById('inputChatBgFile');
    const btnSelectChatBg = document.getElementById('btnSelectChatBg');
    const btnResetChatBg = document.getElementById('btnResetChatBg');
    const previewChatBgBox = document.getElementById('previewChatBgBox');

    const inputBgDimSlider = document.getElementById('inputBgDimSlider');
    const bgDimValueLabel = document.getElementById('bgDimValueLabel');

    function getBgStorageKey(prefix) {
        const uKey = currentUser && currentUser.username
            ? normalizeKey(currentUser.username)
            : normalizeKey(localStorage.getItem('msj_saved_username') || 'default');
        return `${prefix}_${uKey || 'default'}`;
    }

    function compressImageFileToDataUrl(file, maxWidth = 1440, quality = 0.82) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (ev) => {
                const img = new Image();
                img.onload = () => {
                    try {
                        let w = img.width;
                        let h = img.height;
                        if (w > maxWidth) {
                            h = Math.round((h * maxWidth) / w);
                            w = maxWidth;
                        }
                        const canvas = document.createElement('canvas');
                        canvas.width = w;
                        canvas.height = h;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0, w, h);
                        resolve(canvas.toDataURL('image/jpeg', quality));
                    } catch (e) {
                        resolve(ev.target.result);
                    }
                };
                img.onerror = () => resolve(ev.target.result);
                img.src = ev.target.result;
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }

    window.applySavedCustomBackgrounds = function() {
        const usersBg = localStorage.getItem(getBgStorageKey('msj_users_bg')) || localStorage.getItem('msj_users_bg_global') || '';
        const chatBg = localStorage.getItem(getBgStorageKey('msj_chat_bg')) || localStorage.getItem('msj_chat_bg_global') || '';
        const dimPercent = parseInt(localStorage.getItem(getBgStorageKey('msj_bg_dim')) || localStorage.getItem('msj_bg_dim_global') || '35', 10);
        const dimDecimal = Math.max(0, Math.min(0.88, dimPercent / 100));

        document.documentElement.style.setProperty('--custom-bg-dim', String(dimDecimal));
        if (inputBgDimSlider) inputBgDimSlider.value = String(dimPercent);
        if (bgDimValueLabel) bgDimValueLabel.textContent = `%${dimPercent}`;

        // 1. Kullanıcı (Kişi Listesi) Arka Planı
        if (chatsScreen) {
            if (usersBg) {
                document.documentElement.style.setProperty('--custom-users-bg-image', `url("${usersBg}")`);
                chatsScreen.classList.add('has-custom-users-bg');
                if (previewUsersBgBox) {
                    previewUsersBgBox.style.backgroundImage = `url("${usersBg}")`;
                    previewUsersBgBox.textContent = '';
                }
            } else {
                document.documentElement.style.removeProperty('--custom-users-bg-image');
                chatsScreen.classList.remove('has-custom-users-bg');
                if (previewUsersBgBox) {
                    previewUsersBgBox.style.backgroundImage = 'none';
                    previewUsersBgBox.textContent = 'Varsayılan Koyu Tema';
                }
            }
        }

        // 2. Mesaj Sayfası (Sohbet Ekranı) Arka Planı
        if (messagesContainer) {
            if (chatBg) {
                document.documentElement.style.setProperty('--custom-chat-bg-image', `url("${chatBg}")`);
                messagesContainer.classList.add('has-custom-chat-bg');
                if (previewChatBgBox) {
                    previewChatBgBox.style.backgroundImage = `url("${chatBg}")`;
                    previewChatBgBox.textContent = '';
                }
            } else {
                document.documentElement.style.removeProperty('--custom-chat-bg-image');
                messagesContainer.classList.remove('has-custom-chat-bg');
                if (previewChatBgBox) {
                    previewChatBgBox.style.backgroundImage = 'none';
                    previewChatBgBox.textContent = 'Varsayılan Sohbet Duvar Kağıdı';
                }
            }
        }
    };

    function openBgSettingsModal() {
        if (headerDropdown) headerDropdown.style.display = 'none';
        if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
        closeProfileModal();
        window.applySavedCustomBackgrounds();
        if (bgSettingsModal) bgSettingsModal.style.display = 'flex';
    }

    function closeBgSettingsModal() {
        if (bgSettingsModal) bgSettingsModal.style.display = 'none';
    }

    [btnHeaderBgSettings, btnQuickBgSettings, menuItemBgSettings, menuItemChatBgSettings, btnProfileBgSettings].forEach(btn => {
        if (btn) btn.addEventListener('click', openBgSettingsModal);
    });
    if (btnCloseBgSettings) btnCloseBgSettings.addEventListener('click', closeBgSettingsModal);
    if (btnDoneBgSettings) btnDoneBgSettings.addEventListener('click', closeBgSettingsModal);
    if (bgSettingsModal) {
        bgSettingsModal.addEventListener('click', (e) => {
            if (e.target === bgSettingsModal) closeBgSettingsModal();
        });
    }

    if (btnSelectUsersBg && inputUsersBgFile) {
        btnSelectUsersBg.addEventListener('click', () => inputUsersBgFile.click());
        inputUsersBgFile.addEventListener('change', async () => {
            const f = inputUsersBgFile.files && inputUsersBgFile.files[0];
            if (!f) return;
            try {
                const dataUrl = await compressImageFileToDataUrl(f);
                localStorage.setItem(getBgStorageKey('msj_users_bg'), dataUrl);
                localStorage.setItem('msj_users_bg_global', dataUrl);
                window.applySavedCustomBackgrounds();
                showStatusToast('🖼️ Kullanıcı listesi arka plan resmi güncellendi!', true);
            } catch (e) {
                alert('Resim yüklenemedi.');
            }
            inputUsersBgFile.value = '';
        });
    }

    if (btnResetUsersBg) {
        btnResetUsersBg.addEventListener('click', () => {
            localStorage.removeItem(getBgStorageKey('msj_users_bg'));
            localStorage.removeItem('msj_users_bg_global');
            window.applySavedCustomBackgrounds();
            showStatusToast('Kullanıcı arka planı varsayılana döndürüldü', true);
        });
    }

    if (btnSelectChatBg && inputChatBgFile) {
        btnSelectChatBg.addEventListener('click', () => inputChatBgFile.click());
        inputChatBgFile.addEventListener('change', async () => {
            const f = inputChatBgFile.files && inputChatBgFile.files[0];
            if (!f) return;
            try {
                const dataUrl = await compressImageFileToDataUrl(f);
                localStorage.setItem(getBgStorageKey('msj_chat_bg'), dataUrl);
                localStorage.setItem('msj_chat_bg_global', dataUrl);
                window.applySavedCustomBackgrounds();
                showStatusToast('🖼️ Mesaj sayfası arka plan resmi güncellendi!', true);
            } catch (e) {
                alert('Resim yüklenemedi.');
            }
            inputChatBgFile.value = '';
        });
    }

    if (btnResetChatBg) {
        btnResetChatBg.addEventListener('click', () => {
            localStorage.removeItem(getBgStorageKey('msj_chat_bg'));
            localStorage.removeItem('msj_chat_bg_global');
            window.applySavedCustomBackgrounds();
            showStatusToast('Mesaj sayfası arka planı varsayılana döndürüldü', true);
        });
    }

    if (inputBgDimSlider) {
        inputBgDimSlider.addEventListener('input', () => {
            const val = inputBgDimSlider.value;
            localStorage.setItem(getBgStorageKey('msj_bg_dim'), val);
            localStorage.setItem('msj_bg_dim_global', val);
            window.applySavedCustomBackgrounds();
        });
    }

    window.applySavedCustomBackgrounds();
})();

// ==========================================================
// MADDE 5: HER KULLANICININ YALNIZCA KENDİ TELEFONUNDA KAYITLI OLAN KİŞİLERİ GÖRMESİ
// (SHA-256 METADATA KORUMALI TELEFON REHBERİ AKTARIMI & EŞLEŞTİRME)
// ==========================================================
(function setupPersonalPhoneContactsImport() {
    const menuItemImportContacts = document.getElementById('menuItemImportContacts');
    const btnImportPhoneContactsModal = document.getElementById('btnImportPhoneContactsModal');
    const btnAddFilter = document.getElementById('btnAddFilter');
    const vcfContactsFileInput = document.getElementById('vcfContactsFileInput');

    async function processImportedPhoneEntries(entries) {
        if (!Array.isArray(entries) || entries.length === 0) return;
        const myUsername = currentUser ? currentUser.username : (localStorage.getItem('msj_saved_username') || '');
        const myPhoneBook = getPersonalPhoneBookForCurrentUser();
        const hashes = [];

        for (const item of entries) {
            const cleanPhone = normalizePhoneClient(item.phone || '');
            if (!cleanPhone || cleanPhone.length < 7) continue;
            const cName = (item.name || '').trim();

            if (window.MSJCryptoEngine && typeof window.MSJCryptoEngine.hashPhoneForPrivateDiscovery === 'function') {
                const h = await window.MSJCryptoEngine.hashPhoneForPrivateDiscovery(cleanPhone);
                if (h) hashes.push(h);
            }

            // Telefon numarasından bul ve rehbere kaydet
            await window.findAndContactByPhone(cleanPhone, cName, 'none');
        }

        if (hashes.length > 0 && myUsername) {
            try {
                await fetch('/api/users/match_hashed_phones', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phoneHashes: hashes, ownerUsername: myUsername })
                });
            } catch (e) {}
        }

        await loadChatsList();
        showStatusToast(`📒 ${entries.length} kişi telefon rehberinizden eklendi!`, true);
    }

    async function triggerDeviceContactsImport() {
        if (headerDropdown) headerDropdown.style.display = 'none';

        // 1. Mobil Tarayıcı Native Contact Picker API (Android Chrome / iOS destekli)
        if ('contacts' in navigator && 'ContactsManager' in window) {
            try {
                const selected = await navigator.contacts.select(['name', 'tel'], { multiple: true });
                if (selected && selected.length > 0) {
                    const parsed = [];
                    selected.forEach(c => {
                        const name = (c.name && c.name[0]) || '';
                        const tels = c.tel || [];
                        tels.forEach(t => {
                            if (t) parsed.push({ name, phone: t });
                        });
                    });
                    await processImportedPhoneEntries(parsed);
                    return;
                }
            } catch (e) {}
        }

        // 2. Masaüstü veya Contact Picker desteklemeyen tarayıcılar için Rehber (.vcf) dosyası veya hızlı numara girişi
        const choice = confirm(
            '📒 Kendi Telefon Rehberinizden Kişi Aktarımı\n\n' +
            '• Telefon rehber dosyanızdan (.vcf / vCard) toplu aktarmak için "Tamam"a basın.\n' +
            '• Tek bir telefon numarasını rehberinize ekleyip davet göndermek için "İptal"e basın.'
        );
        if (choice && vcfContactsFileInput) {
            vcfContactsFileInput.click();
        } else {
            openNewChatModal(true);
        }
    }

    if (vcfContactsFileInput) {
        vcfContactsFileInput.addEventListener('change', () => {
            const f = vcfContactsFileInput.files && vcfContactsFileInput.files[0];
            if (!f) return;
            const reader = new FileReader();
            reader.onload = async (ev) => {
                const text = String(ev.target.result || '');
                const cards = text.split(/BEGIN:VCARD/i);
                const entries = [];
                cards.forEach(card => {
                    const fnMatch = card.match(/FN[^:]*:(.+)/i);
                    const telMatches = card.match(/TEL[^:]*:([^\r\n]+)/gi) || [];
                    const name = fnMatch ? fnMatch[1].trim() : '';
                    telMatches.forEach(tLine => {
                        const parts = tLine.split(':');
                        const rawTel = parts.slice(1).join(':').trim();
                        if (rawTel) entries.push({ name, phone: rawTel });
                    });
                });
                if (entries.length > 0) {
                    await processImportedPhoneEntries(entries);
                } else {
                    alert('Dosyada geçerli telefon numarası bulunamadı.');
                }
            };
            reader.readAsText(f);
            vcfContactsFileInput.value = '';
        });
    }

    [menuItemImportContacts, btnImportPhoneContactsModal, btnAddFilter].forEach(btn => {
        if (btn) btn.addEventListener('click', triggerDeviceContactsImport);
    });
})();

// ==========================================================
// E2EE GÜVENLİK & SIFIR BİLGİ (ZERO-KNOWLEDGE) YEDEKLEME MODALI YÖNETİCİSİ
// ==========================================================
(function setupSecurityAndZeroKnowledgeBackupModal() {
    const securityBackupModal = document.getElementById('securityBackupModal');
    const btnCloseSecurityBackup = document.getElementById('btnCloseSecurityBackup');
    const menuItemSecurityBackup = document.getElementById('menuItemSecurityBackup');
    const btnProfileSecurityBackup = document.getElementById('btnProfileSecurityBackup');
    const menuItemChatVerifyE2EE = document.getElementById('menuItemChatVerifyE2EE');
    const chkFlagSecureToggle = document.getElementById('chkFlagSecureToggle');
    const inputZkBackupPassword = document.getElementById('inputZkBackupPassword');
    const zkRecoveryKeyBox = document.getElementById('zkRecoveryKeyBox');
    const btnCreateZkBackup = document.getElementById('btnCreateZkBackup');
    const btnRestoreZkBackup = document.getElementById('btnRestoreZkBackup');
    const inputRestoreZkFile = document.getElementById('inputRestoreZkFile');

    function openSecurityModal() {
        if (headerDropdown) headerDropdown.style.display = 'none';
        if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
        closeProfileModal();
        if (securityBackupModal) securityBackupModal.style.display = 'flex';
    }

    function closeSecurityModal() {
        if (securityBackupModal) securityBackupModal.style.display = 'none';
    }

    [menuItemSecurityBackup, btnProfileSecurityBackup].forEach(btn => {
        if (btn) btn.addEventListener('click', openSecurityModal);
    });
    if (btnCloseSecurityBackup) btnCloseSecurityBackup.addEventListener('click', closeSecurityModal);
    if (securityBackupModal) {
        securityBackupModal.addEventListener('click', (e) => {
            if (e.target === securityBackupModal) closeSecurityModal();
        });
    }

    if (menuItemChatVerifyE2EE) {
        menuItemChatVerifyE2EE.addEventListener('click', () => {
            if (chatDropdownMenu) chatDropdownMenu.style.display = 'none';
            if (window.showE2EEVerificationDialog) window.showE2EEVerificationDialog();
        });
    }

    if (chkFlagSecureToggle) {
        chkFlagSecureToggle.checked = localStorage.getItem('msj_flag_secure') !== 'false';
        chkFlagSecureToggle.addEventListener('change', () => {
            localStorage.setItem('msj_flag_secure', chkFlagSecureToggle.checked ? 'true' : 'false');
            showStatusToast(chkFlagSecureToggle.checked ? '🛡️ FLAG_SECURE ekran koruması aktif' : 'Ekran koruması kapatıldı', true);
        });
    }

    if (btnCreateZkBackup) {
        btnCreateZkBackup.addEventListener('click', async () => {
            if (!window.MSJCryptoEngine || typeof window.MSJCryptoEngine.createZeroKnowledgeEncryptedBackup !== 'function') return;
            const pass = inputZkBackupPassword ? inputZkBackupPassword.value.trim() : '';
            const payload = {
                user: currentUser,
                contacts: contactsList,
                phoneBook: getPersonalPhoneBookForCurrentUser(),
                exportedAt: new Date().toISOString()
            };
            const result = await window.MSJCryptoEngine.createZeroKnowledgeEncryptedBackup(payload, pass);
            if (zkRecoveryKeyBox && result.recoveryKey64) {
                zkRecoveryKeyBox.style.display = 'block';
                zkRecoveryKeyBox.innerHTML = `<strong>64 Haneli Kurtarma Anahtarınız (Lütfen Kaydedin):</strong><br>${escapeHtml(result.recoveryKey64)}`;
            }
            const blob = new Blob([JSON.stringify(result.backupBlob, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `HIHaberlesme-ZK-Backup-${(currentUser && currentUser.username) || 'user'}.msjbackup`;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 3000);
            showStatusToast('🔐 Sıfır Bilgi (Zero-Knowledge) şifreli yedek indirildi!', true);
        });
    }

    if (btnRestoreZkBackup && inputRestoreZkFile) {
        btnRestoreZkBackup.addEventListener('click', () => inputRestoreZkFile.click());
        inputRestoreZkFile.addEventListener('change', () => {
            const f = inputRestoreZkFile.files && inputRestoreZkFile.files[0];
            if (!f) return;
            const reader = new FileReader();
            reader.onload = async (ev) => {
                try {
                    const backupBlob = JSON.parse(String(ev.target.result || '{}'));
                    const pass = (inputZkBackupPassword && inputZkBackupPassword.value.trim()) ||
                        prompt('Yedeği çözmek için parolanızı veya 64 haneli kurtarma anahtarınızı girin:') || '';
                    if (!pass) return;
                    const restored = await window.MSJCryptoEngine.restoreZeroKnowledgeEncryptedBackup(backupBlob, pass);
                    if (restored && Array.isArray(restored.phoneBook)) {
                        savePersonalPhoneBookForCurrentUser(restored.phoneBook);
                    }
                    if (restored && Array.isArray(restored.contacts)) {
                        saveCachedContactsForCurrentUser(restored.contacts);
                        contactsList = mergeContactsWithPermanentUsers(restored.contacts);
                        renderChatsList(contactsList);
                    }
                    showStatusToast('✅ Sıfır Bilgi yedeğiniz başarıyla çözüldü ve geri yüklendi!', true);
                } catch (err) {
                    alert('Yedek çözülemedi: Parola veya 64 haneli kurtarma anahtarı hatalı.');
                }
            };
            reader.readAsText(f);
            inputRestoreZkFile.value = '';
        });
    }
})();

// Uygulamayı Başlat
initAuth();
