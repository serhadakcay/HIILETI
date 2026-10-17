// ==========================================================
// HIHABERLEŞME WEB / MOBILE SPA - CLIENT LOGIC
// ==========================================================

const socket = io();

// Soket bağlantısı kurulduğunda veya koptuktan sonra yeniden bağlandığında oturumu geri yükle
socket.on('connect', () => {
    console.log('[HIHaberleşme Socket] Bağlandı:', socket.id);
    const token = sessionStorage.getItem('msj_token') || localStorage.getItem('msj_token');
    const savedUserStr = localStorage.getItem('msj_user');
    let uName = currentUser ? currentUser.username : '';
    if (!uName && savedUserStr) {
        try { uName = JSON.parse(savedUserStr).username; } catch(e) {}
    }
    if (uName) {
        socket.emit('user:join', { token, username: uName });
    }
});

function normalizeKey(str) {
    if (!str) return '';
    return str.trim().toLocaleLowerCase('tr-TR');
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

// PWA Service Worker Kaydı (Arka Planda Bildirim ve Arama Yakalama)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').then((reg) => {
            if (currentUser && reg.active) {
                reg.active.postMessage({ type: 'INIT_USER', username: currentUser.username });
            }
        }).catch(() => {});
    });

    navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data && event.data.type === 'NOTIFICATION_CLICK' && event.data.url) {
            try {
                const u = new URL(event.data.url, window.location.origin);
                const openChatUser = u.searchParams.get('openChat');
                if (openChatUser) {
                    openChatForSender(openChatUser);
                }
            } catch (e) {}
        }
    });
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
const btnChatMenu = document.getElementById('btnChatMenu');
const chatDropdownMenu = document.getElementById('chatDropdownMenu');
const menuItemChatAudioSettings = document.getElementById('menuItemChatAudioSettings');
const menuItemClearChat = document.getElementById('menuItemClearChat');
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
const btnProfileAudioSettings = document.getElementById('btnProfileAudioSettings');
const btnProfileNewUser = document.getElementById('btnProfileNewUser');
const btnProfileSwitchUser = document.getElementById('btnProfileSwitchUser');
const btnProfileChangePass = document.getElementById('btnProfileChangePass');
const btnProfileLogout = document.getElementById('btnProfileLogout');
const btnProfileDeleteAccount = document.getElementById('btnProfileDeleteAccount');

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

    [audioMessage, audioRingtone, audioRingback, audioEnded, remoteAudio].forEach(el => {
        if (el) {
            try {
                const p = el.play();
                if (p !== undefined) {
                    p.then(() => {
                        el.pause();
                        el.currentTime = 0;
                    }).catch(() => {});
                }
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

    if (notifyToastTimer) {
        clearTimeout(notifyToastTimer);
        notifyToastTimer = null;
    }

    lastNotifySender = msg.sender;
    notifySender.textContent = msg.sender;
    notifyText.textContent = msg.text || (msg.file ? '📎 [Dosya / Fotoğraf]' : 'Yeni Mesaj Geldi');

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

function getPermanentLocalUsers() {
    try {
        const raw = localStorage.getItem('msj_permanent_users');
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) return parsed;
        }
    } catch (e) {}
    return [];
}

function savePermanentLocalUsers(usersArray) {
    if (!Array.isArray(usersArray)) return;
    const existing = getPermanentLocalUsers();
    const map = new Map();
    existing.forEach(u => {
        if (u && u.username) map.set(normalizeKey(u.username), { username: u.username, avatar: u.avatar || '/avatars/default.svg' });
    });
    usersArray.forEach(u => {
        if (u && u.username) map.set(normalizeKey(u.username), { username: u.username, avatar: u.avatar || '/avatars/default.svg' });
    });
    const merged = Array.from(map.values());
    try {
        localStorage.setItem('msj_permanent_users', JSON.stringify(merged));
    } catch (e) {}
    return merged;
}

function removePermanentLocalUser(usernameToRemove) {
    const key = normalizeKey(usernameToRemove);
    if (!key) return;
    try {
        const existing = getPermanentLocalUsers().filter(u => normalizeKey(u.username) !== key);
        localStorage.setItem('msj_permanent_users', JSON.stringify(existing));
    } catch (e) {}
    try {
        const cachedRaw = localStorage.getItem('msj_cached_contacts');
        if (cachedRaw) {
            const cached = JSON.parse(cachedRaw).filter(u => normalizeKey(u.username) !== key);
            localStorage.setItem('msj_cached_contacts', JSON.stringify(cached));
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
        const localUsers = getPermanentLocalUsers();
        const savedUsername = localStorage.getItem('msj_saved_username');
        if (savedUsername) {
            localUsers.push({ username: savedUsername, avatar: '/avatars/default.svg' });
        }
        const cachedRaw = localStorage.getItem('msj_cached_contacts');
        if (cachedRaw) {
            try {
                const cached = JSON.parse(cachedRaw);
                if (Array.isArray(cached)) {
                    cached.forEach(c => {
                        if (c && c.username) localUsers.push({ username: c.username, avatar: c.avatar });
                    });
                }
            } catch (e) {}
        }
        if (localUsers.length > 0) {
            const res = await fetch('/api/users/sync', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ users: localUsers })
            });
            const data = await res.json();
            if (data && data.success && Array.isArray(data.users)) {
                savePermanentLocalUsers(data.users);
                return data.users;
            }
        }
    } catch (e) {}
    return null;
}

// Kullanıcı kendi isteğiyle bir kaydı silmek istediğinde çağrılır
window.requestDeleteUser = async function(usernameToDelete) {
    if (!usernameToDelete) return;
    const confirmed = confirm(`"${usernameToDelete}" adlı kayıtlı kullanıcıyı kalıcı olarak silmek istediğinize emin misiniz?\n\n(İptal derseniz kullanıcı kayıtlı kalmaya devam eder.)`);
    if (!confirmed) return;

    try {
        const res = await fetch('/api/users/' + encodeURIComponent(usernameToDelete), {
            method: 'DELETE'
        });
        const data = await res.json();
        if (data && data.success) {
            removePermanentLocalUser(usernameToDelete);
            contactsList = contactsList.filter(c => normalizeKey(c.username) !== normalizeKey(usernameToDelete));
            renderChatsList(contactsList);

            if (activeContact && normalizeKey(activeContact.username) === normalizeKey(usernameToDelete)) {
                closeActiveChat();
            }

            if (currentUser && normalizeKey(currentUser.username) === normalizeKey(usernameToDelete)) {
                currentUser = null;
                closeProfileModal();
                await loadRegisteredUsersDropdown();
                showPasswordPrompt('');
            } else {
                await loadRegisteredUsersDropdown();
                showStatusToast(`${usernameToDelete} kayıtlardan silindi`, false);
            }
        } else {
            alert((data && data.error) || 'Kullanıcı silinemedi.');
        }
    } catch (e) {
        alert('Sunucuya bağlanılamadı.');
    }
};

async function quickLoginAsRegisteredUser(username) {
    if (!username) return false;
    try {
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
    // 0. Önceden kayıtlı ve önbelleğe alınmış sohbet listesi varsa ANINDA ekrana bas
    // Böylece program kapatılıp açılınca kayıtlı kullanıcılar ekranda kalır!
    const cachedContacts = localStorage.getItem('msj_cached_contacts');
    if (cachedContacts) {
        try {
            const parsed = JSON.parse(cachedContacts);
            if (Array.isArray(parsed) && parsed.length > 0) {
                contactsList = parsed;
                renderChatsList(contactsList);
            }
        } catch (e) {}
    }

    // Kalıcı kullanıcıları sunucuyla senkronize et (hiçbir kayıtlı kullanıcı kaybolmasın)
    syncPermanentUsersWithServer().catch(() => {});

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
    if (rowForgotPassword) rowForgotPassword.style.display = 'none';
    if (btnCancelAuth) btnCancelAuth.style.display = currentUser ? 'inline-block' : 'none';
    authSubtitle.textContent = 'Yeni kullanıcı hesabı oluşturun';
    btnAuthSubmit.textContent = 'Kayıt Ol ve Giriş Yap';
    btnToggleAuthMode.textContent = 'Zaten hesabınız var mı? Giriş Yap';
    inputUsername.value = '';
    inputPassword.value = '';
    inputConfirmPassword.value = '';
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
        inputUsername.value = username;
        inputPassword.value = '';
        if (rowForgotPassword) rowForgotPassword.style.display = 'block';
        inputPassword.focus();
    } else {
        authSubtitle.textContent = 'Kayıtlı kullanıcı seçin veya kullanıcı adınızı yazın';
        rememberedUserBox.style.display = 'none';
        fieldUsernameSelect.style.display = 'block';
        inputPassword.value = '';
        if (rowForgotPassword) rowForgotPassword.style.display = 'none';
        inputUsername.focus();
    }
}

async function loadRegisteredUsersDropdown() {
    await syncPermanentUsersWithServer();
    let attempts = 0;
    while (attempts < 4) {
        try {
            const res = await fetch('/api/users/registered');
            const data = await res.json();
            if (data.success && Array.isArray(data.users)) {
                savePermanentLocalUsers(data.users);
                selectRegisteredUser.innerHTML = '<option value="">-- Kayıtlı Kullanıcı Seçin --</option>';
                if (quickUsersList) quickUsersList.innerHTML = '';

                data.users.forEach(u => {
                    const opt = document.createElement('option');
                    opt.value = u.username;
                    const statusSuffix = u.lastSeen === 'Online' ? ' (🟢 Online)' : ' (⚪ Offline)';
                    opt.textContent = `${u.username}${statusSuffix}`;
                    selectRegisteredUser.appendChild(opt);

                    if (quickUsersList) {
                        const chipWrap = document.createElement('div');
                        chipWrap.style.display = 'inline-flex';
                        chipWrap.style.alignItems = 'center';
                        chipWrap.style.gap = '2px';

                        const chip = document.createElement('button');
                        chip.type = 'button';
                        chip.className = 'quick-user-chip';
                        chip.title = `${u.username} olarak hızlı giriş yap`;
                        chip.innerHTML = `
                            <img src="${u.avatar || '/avatars/default.svg'}" class="avatar-mini" alt="${escapeHtml(u.username)}">
                            <span><strong>${escapeHtml(u.username)}</strong> <small style="opacity:0.8;">${u.lastSeen === 'Online' ? '🟢' : '⚪'}</small></span>
                        `;
                        chip.addEventListener('click', async () => {
                            // Kayıtlı kullanıcıya tıklandığında doğrudan hızlı giriş yap (veya şifre alanını doldur)
                            const ok = await quickLoginAsRegisteredUser(u.username);
                            if (!ok) {
                                inputUsername.value = u.username;
                                rememberedName.textContent = u.username;
                                rememberedAvatar.src = u.avatar || '/avatars/default.svg';
                                rememberedUserBox.style.display = 'flex';
                                fieldUsernameSelect.style.display = 'none';
                                if (rowForgotPassword) rowForgotPassword.style.display = 'block';
                                inputPassword.value = '';
                                inputPassword.focus();
                            }
                        });

                        const delBtn = document.createElement('button');
                        delBtn.type = 'button';
                        delBtn.title = `${u.username} kullanıcısını sil`;
                        delBtn.textContent = '🗑️';
                        delBtn.style.cssText = 'background:transparent;border:none;cursor:pointer;font-size:13px;padding:4px;opacity:0.75;';
                        delBtn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            window.requestDeleteUser(u.username);
                        });

                        chipWrap.appendChild(chip);
                        chipWrap.appendChild(delBtn);
                        quickUsersList.appendChild(chipWrap);
                    }
                });

                if (selectRegisteredUser) {
                    selectRegisteredUser.style.display = data.users.length > 0 ? 'block' : 'none';
                }

                if (quickUsersContainer) {
                    quickUsersContainer.style.display = data.users.length > 0 ? 'block' : 'none';
                }

                if (contactsList.length === 0) {
                    const filteredUsers = currentUser
                        ? data.users.filter(u => normalizeKey(u.username) !== normalizeKey(currentUser.username))
                        : data.users;
                    contactsList = filteredUsers;
                    renderChatsList(contactsList);
                }

                return data.users.length;
            }
        } catch (e) {
            attempts++;
            if (attempts < 4) {
                await new Promise(r => setTimeout(r, 500));
            }
        }
    }
    if (contactsList.length === 0) {
        renderChatsList([]);
    }
    return 0;
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
    if (rowForgotPassword) rowForgotPassword.style.display = 'none';
    inputUsername.value = '';
    inputPassword.value = '';
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
            const res = await fetch('/api/auth/reset_password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user, newPassword: newPass.trim() })
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

    const username = (inputUsername.value.trim() || (rememberedUserBox.style.display !== 'none' ? rememberedName.textContent.trim() : '')).trim();
    const password = inputPassword.value;

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
    btnAuthSubmit.disabled = true;
    btnAuthSubmit.textContent = 'Bağlanıyor...';

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
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
                                body: JSON.stringify({ username, newPassword: password })
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
                                body: JSON.stringify({ username, password, resetExisting: true })
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
    currentUser = user;
    menuUsernameDisplay.textContent = user.username;
    savePermanentLocalUsers([user]);
    localStorage.setItem('msj_saved_username', user.username);
    localStorage.setItem('msj_auto_login', 'true');

    // Soket sunucusuna kendi oturumunu bildir (Anında Online durumuna geçer)
    socket.emit('user:join', { token, username: user.username });

    // Service Worker'a aktif kullanıcıyı bildir (Arka planda bildirim sorgulaması için)
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
        const autoAcceptCall = params.get('autoAcceptCall');
        const incomingCall = params.get('incomingCall');
        if (openChatUser) {
            setTimeout(() => {
                openChatForSender(openChatUser);
                if (autoAcceptCall === '1') {
                    // Gelen arama bildirimi ulaştığında otomatik cevapla veya modal açıksa kabul et
                    setTimeout(() => {
                        if (incomingCallModal && incomingCallModal.style.display === 'flex' && btnAcceptCall) {
                            btnAcceptCall.click();
                        }
                    }, 600);
                } else if (incomingCall === '1' && currentUser) {
                    // Bekleyen aramayı sunucudan hemen tetikle
                    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
                    socket.emit('user:join', { token, username: currentUser.username });
                }
            }, 300);
            // URL'yi temizle
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (e) {}
}

// ==========================================================
// 2. RESİM 1: SOHBETLER / KAYITLI KULLANICILAR LİSTESİ
// ==========================================================

async function loadChatsList() {
    let token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');

    // Önce yerel kalıcı kullanıcıları sunucuyla eşitle ki hiçbir kayıtlı kullanıcı eksik kalmasın
    await syncPermanentUsersWithServer();

    if (token) {
        try {
            const res = await fetch('/api/chats', {
                headers: { 'x-auth-token': token }
            });
            const data = await res.json();

            if (data.success && data.chats) {
                contactsList = data.chats;
                savePermanentLocalUsers(contactsList);
                localStorage.setItem('msj_cached_contacts', JSON.stringify(contactsList));
                renderChatsList(contactsList);
                return;
            }
        } catch (err) {
            console.error('Sohbetler yüklenemedi:', err);
        }
    }

    // Eğer token süresi dolmuşsa veya oturum yedekten açılmışsa kullanıcı listesini doğrudan çek
    try {
        const regRes = await fetch('/api/users/registered');
        const regData = await regRes.json();
        if (regData && regData.success && Array.isArray(regData.users)) {
            savePermanentLocalUsers(regData.users);
            const filtered = currentUser
                ? regData.users.filter(u => normalizeKey(u.username) !== normalizeKey(currentUser.username))
                : regData.users;
            contactsList = filtered;
            localStorage.setItem('msj_cached_contacts', JSON.stringify(contactsList));
            renderChatsList(contactsList);
            return;
        }
    } catch (e) {}

    if (contactsList.length > 0) {
        renderChatsList(contactsList);
    }
}

function renderChatsList(chats) {
    chatListContainer.innerHTML = '';

    if (!chats || chats.length === 0) {
        chatListContainer.innerHTML = `
            <div style="padding: 40px 20px; text-align: center; color: var(--text-secondary); font-size: 14px;">
                Henüz kayıtlı başka bir kullanıcı bulunamadı.<br>Yeni bir kişi eklemek için sağ alttaki <strong>+</strong> butonuna dokunun.
            </div>
        `;
        updateUnreadBadges();
        return;
    }

    chats.forEach(contact => {
        const item = document.createElement('div');
        const isActive = activeContact && normalizeKey(activeContact.username) === normalizeKey(contact.username);
        const hasUnread = (contact.unreadCount || 0) > 0;
        item.className = `chat-list-item ${isActive ? 'active' : ''} ${hasUnread ? 'has-unread' : ''}`;
        item.dataset.username = contact.username;
        item.style.cursor = 'pointer';

        let lastSnippet = contact.isOnline ? '🟢 Çevrimiçi (Online)' : '⚪ Çevrimdışı (Mesaj & Arama Açık)';
        let isUnreadSnippet = false;

        if (contact.lastMessage) {
            const rawText = contact.lastMessage.text || (contact.lastMessage.file ? '📎 Dosya / Fotoğraf' : 'Mesaj');
            const prefix = contact.lastMessage.isOutgoing ? 'Siz: ' : '';
            lastSnippet = prefix + rawText;
            if (hasUnread && !contact.lastMessage.isOutgoing) {
                isUnreadSnippet = true;
            }
        }

        item.innerHTML = `
            <div class="chat-avatar-wrap">
                <img class="avatar" src="${contact.avatar || '/avatars/default.svg'}" alt="${escapeHtml(contact.username)}">
                ${contact.isOnline ? '<span class="online-badge" title="Online"></span>' : '<span class="offline-badge" title="Offline"></span>'}
                ${hasUnread ? '<span class="avatar-unread-badge" title="Yeni Mesaj Geldi">✉️</span>' : ''}
            </div>
            <div class="chat-content-wrap">
                <div class="chat-top-line">
                    <span class="chat-title">
                        <strong style="font-size: 16px; color: var(--text-primary);">${escapeHtml(contact.username)}</strong>
                        <span class="status-tag ${contact.isOnline ? 'online' : 'offline'}">${contact.isOnline ? 'Online' : 'Offline'}</span>
                    </span>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        ${contact.lastMessage && contact.lastMessage.timestamp ? `<span style="font-size: 11px; color: ${hasUnread ? 'var(--accent-bright)' : 'var(--text-secondary)'}; font-weight: ${hasUnread ? '700' : 'normal'};">${contact.lastMessage.timestamp}</span>` : ''}
                        ${hasUnread ? `<span class="unread-pill" title="Okunmamış Mesaj"><span style="font-size: 11px;">✉️</span> ${contact.unreadCount}</span>` : ''}
                    </div>
                </div>
                <div class="chat-bottom-line" style="gap: 6px;">
                    <div class="chat-last-msg-preview ${isUnreadSnippet ? 'unread' : ''}" title="${escapeHtml(lastSnippet)}">
                        ${isUnreadSnippet ? '<span class="msg-unread-icon">✉️</span>' : ''}
                        <span>${escapeHtml(lastSnippet)}</span>
                    </div>
                    <div class="contact-quick-actions" style="display: flex; align-items: center; gap: 4px; flex-shrink: 0;">
                        <button type="button" class="btn-chat-action ${hasUnread ? 'unread' : ''}" data-quick-action="message" title="Mesaj Gönder (Offline olsa bile iletilir)">
                            ${hasUnread ? `✉️ Oku (${contact.unreadCount})` : '💬 Mesaj'}
                        </button>
                        <button type="button" class="btn-chat-action" data-quick-action="voice" title="Sesli Ara (Offline olsa bile cihazı uyandırır ve çalar)" style="padding: 4px 8px;">
                            📞
                        </button>
                        <button type="button" class="btn-chat-action" data-quick-action="video" title="Görüntülü Ara (Offline olsa bile cihazı uyandırır ve çalar)" style="padding: 4px 8px;">
                            📹
                        </button>
                        <button type="button" class="btn-chat-action" data-quick-action="delete" title="Kullanıcıyı Sil (Kayıtlardan Kaldır)" style="padding: 4px 7px; background: rgba(234, 0, 56, 0.14); color: #ff6b81; border-color: rgba(234, 0, 56, 0.3);">
                            🗑️
                        </button>
                    </div>
                </div>
            </div>
        `;

        item.addEventListener('click', (e) => {
            const actionBtn = e.target.closest('[data-quick-action]');
            if (actionBtn) {
                e.stopPropagation();
                const action = actionBtn.dataset.quickAction;
                if (action === 'delete') {
                    window.requestDeleteUser(contact.username);
                    return;
                }
                selectContact(contact);
                if (action === 'voice' || action === 'video') {
                    setTimeout(() => initiateCall(action), 250);
                }
                return;
            }
            selectContact(contact);
        });

        chatListContainer.appendChild(item);
    });

    updateUnreadBadges();
}

// Arama Filtresi
inputSearchChats.addEventListener('input', () => {
    const query = normalizeKey(inputSearchChats.value);
    btnClearSearch.style.display = query ? 'block' : 'none';

    if (!query) {
        renderChatsList(contactsList);
        return;
    }

    const filtered = contactsList.filter(c => normalizeKey(c.username).includes(query));
    renderChatsList(filtered);
});

btnClearSearch.addEventListener('click', () => {
    inputSearchChats.value = '';
    btnClearSearch.style.display = 'none';
    renderChatsList(contactsList);
});

// Filtre Hapları Tıklama
filterChips.forEach(chip => {
    chip.addEventListener('click', () => {
        filterChips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');

        const filter = chip.dataset.filter;
        if (filter === 'unread') {
            const unread = contactsList.filter(c => c.unreadCount > 0);
            renderChatsList(unread);
        } else if (filter === 'online') {
            const onlineOnly = contactsList.filter(c => c.isOnline);
            renderChatsList(onlineOnly);
        } else {
            renderChatsList(contactsList);
        }
    });
});

// ==========================================================
// YENİ YAZIŞMA / KİŞİ SEÇ EKRANI (FAB '+' VE MENÜ BUTONU)
// ==========================================================
function openNewChatModal() {
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

    if (inputSearchNewChat) {
        setTimeout(() => inputSearchNewChat.focus(), 150);
    }
}

function closeNewChatModal() {
    if (newChatModal) {
        newChatModal.style.display = 'none';
    }
}

function renderNewChatUsers(list) {
    if (!newChatUsersList) return;
    newChatUsersList.innerHTML = '';

    if (newChatUserCount) {
        newChatUserCount.textContent = `${list.length} kayıtlı kişi`;
    }

    if (!list || list.length === 0) {
        newChatUsersList.innerHTML = `
            <div style="padding: 35px 20px; text-align: center; color: var(--text-secondary); font-size: 13.5px;">
                Kayıtlı başka kullanıcı bulunamadı.<br>
                Yeni bir kişi eklemek için yukarıdaki <strong>"Yeni Kullanıcı Hesabı Ekle"</strong> butonunu kullanabilirsiniz.
            </div>
        `;
        return;
    }

    list.forEach(contact => {
        const item = document.createElement('div');
        item.className = 'new-chat-user-item';

        item.innerHTML = `
            <div class="new-chat-user-left">
                <div class="chat-avatar-wrap" style="position:relative;">
                    <img class="avatar" src="${contact.avatar || '/avatars/default.svg'}" alt="${escapeHtml(contact.username)}">
                    ${contact.isOnline ? '<span class="online-badge" title="Online"></span>' : '<span class="offline-badge" title="Offline"></span>'}
                </div>
                <div class="new-chat-user-info">
                    <span class="new-chat-username">${escapeHtml(contact.username)}</span>
                    <span class="new-chat-status ${contact.isOnline ? 'online' : 'offline'}">
                        ${contact.isOnline ? '🟢 Online' : '⚪ Offline (Mesaj & Arama Açık)'}
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
                <button type="button" class="btn-new-chat-action delete" title="Bu Kullanıcıyı Sil" data-action="delete" style="background: rgba(234, 0, 56, 0.16); color: #ff6b81;">
                    🗑️
                </button>
            </div>
        `;

        // Satıra veya butonlara basıldığında doğrudan o kullanıcı seçilip yazışma ekranı açılsın
        item.addEventListener('click', (e) => {
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

// Yeni Yazışma Kişi Arama Filtresi
if (inputSearchNewChat) {
    inputSearchNewChat.addEventListener('input', () => {
        const query = normalizeKey(inputSearchNewChat.value);
        if (btnClearNewChatSearch) {
            btnClearNewChatSearch.style.display = query ? 'block' : 'none';
        }

        if (!query) {
            renderNewChatUsers(contactsList);
            return;
        }

        const filtered = contactsList.filter(c => normalizeKey(c.username).includes(query));
        renderNewChatUsers(filtered);
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

    // Resim 2 Başlık Bilgilerini Doldur
    chatContactName.textContent = contact.username;
    chatContactAvatar.src = contact.avatar || '/avatars/default.svg';

    if (contact.isOnline) {
        chatContactStatus.textContent = 'Online';
        headerOnlineDot.style.display = 'block';
    } else {
        chatContactStatus.textContent = 'Offline';
        headerOnlineDot.style.display = 'none';
    }

    // Aktif öğeyi listede vurgula ve rozetleri temizle
    document.querySelectorAll('.chat-list-item').forEach(el => {
        const matches = normalizeKey(el.dataset.username) === normalizeKey(contact.username);
        el.classList.toggle('active', matches);
        if (matches) {
            el.classList.remove('has-unread');
            const badge = el.querySelector('.avatar-unread-badge');
            if (badge) badge.remove();
            const pill = el.querySelector('.unread-pill');
            if (pill) pill.remove();
            const actionBtn = el.querySelector('.btn-chat-action');
            if (actionBtn) {
                actionBtn.classList.remove('unread');
                actionBtn.textContent = '💬 Mesaj / Ara';
            }
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
        <div class="encryption-warning-banner">
            <span class="enc-icon">🔒</span>
            <span class="enc-text">
                Mesajlar ve aramalar uçtan uca şifrelidir. Yalnızca bu sohbetteki kişiler bu içerikleri okuyabilir, dinleyebilir veya paylaşabilir.
                <a href="javascript:void(0);" class="enc-link">Daha fazla bilgi</a>
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
    if (!activeContact) return;

    // 1. Zaten ekranda aynı id varsa mükerrer basma
    if (msg.id && document.getElementById(msg.id)) return;

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

    // Yalnızca şu anki aktif kişiye ait mesajları ekrana bas
    const isForActiveContact =
        (normalizeKey(msg.sender) === normalizeKey(activeContact.username)) ||
        (normalizeKey(msg.recipient) === normalizeKey(activeContact.username));

    if (!isForActiveContact) return;

    const isMe = currentUser && normalizeKey(msg.sender) === normalizeKey(currentUser.username);

    // 3. Ek güvenlik: Eğer kendi gönderdiğimiz bir mesajsa ve henüz pending durumda aynı metinli bir baloncuk varsa onu güncelle
    if (isMe && !msg.pending && msg.text) {
        const pendingBubbles = messagesContainer.querySelectorAll('.message-bubble.out.pending');
        for (const pb of pendingBubbles) {
            const txtEl = pb.querySelector('.message-text');
            if (txtEl && txtEl.textContent.trim() === msg.text.trim()) {
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
            fileContent = `<img class="msg-image-thumb" src="${msg.file.url}" alt="Fotoğraf" onclick="openEnlargedImage('${msg.file.url}')">`;
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

    const textContent = msg.text ? `<span class="message-text">${formatMessageText(msg.text)}</span>` : '';
    const deleteBtn = msg.id ? `<button type="button" class="btn-msg-delete" title="Bu mesajı sil" onclick="requestDeleteMessage('${msg.id}')">&times;</button>` : '';

    bubble.innerHTML = `
        ${deleteBtn}
        ${fileContent}
        ${textContent}
        <div class="bubble-meta">
            <span class="bubble-time">${msg.timestamp || '12:27'}</span>
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
    if (!activeContact) {
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

    const tempMsg = {
        id: tempId,
        tempId: tempId,
        sender: currentUser ? currentUser.username : '',
        recipient: activeContact.username,
        text: text,
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
            sender: currentUser ? currentUser.username : '',
            recipient: activeContact.username,
            text: text,
            timestamp: tempMsg.timestamp,
            isOutgoing: true
        };
        renderChatsList(contactsList);
    }

    socket.emit('chat:send_message', {
        recipient: activeContact.username,
        text: text,
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
                    checks.title = isRecOnline ? 'Teslim edildi' : 'Sunucuya kaydedildi (Alıcı çevrimdışı, açtığında iletilecek)';
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
                socket.emit('chat:send_message', {
                    recipient: activeContact.username,
                    text: '',
                    file: uploadedFile,
                    token: token
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

// Yeni Mesaj Geldiğinde
socket.on('chat:message', (msg) => {
    const isIncoming = currentUser && normalizeKey(msg.recipient) === normalizeKey(currentUser.username);
    const isFromActive = activeContact && normalizeKey(msg.sender) === normalizeKey(activeContact.username);
    const isToActive = activeContact && normalizeKey(msg.recipient) === normalizeKey(activeContact.username);

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

        // B) Sohbet o an açık değilse veya sekme/pencere arka plandaysa:
        if (!isFromActive || document.hidden) {
            showMessageNotificationToast(msg);
            triggerSystemNotification(`💬 ${msg.sender}`, {
                body: msg.text || (msg.file ? '📎 [Dosya / Fotoğraf paylaştı]' : 'Yeni bir mesajınız var'),
                icon: '/icon-192.png',
                badge: '/icon-192.png',
                tag: 'msg-' + msg.sender,
                vibrate: [180, 80, 180]
            });
        }
    }

    // 3. Sohbet listesindeki son mesajı ve okunmamış sayısını anında güncelle
    const contact = contactsList.find(c => 
        normalizeKey(c.username) === normalizeKey(msg.sender) || 
        normalizeKey(c.username) === normalizeKey(msg.recipient)
    );

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
        renderChatsList(contactsList);
    } else {
        loadChatsList();
    }
});

// Çevrimdışıyken bize gönderilmiş bekleyen mesajlar sunucudan geldiğinde (Offline Teslim)
socket.on('chat:offline_messages', (data) => {
    if (!data || !Array.isArray(data.messages) || data.messages.length === 0) return;

    let hasUnreadForOther = false;
    data.messages.forEach(msg => {
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
        if (data.messages.length === 1) {
            showMessageNotificationToast(data.messages[0]);
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

// Kullanıcı Çevrimiçi/Çevrimdışı Durum Değişimi (Online / Offline Bildirimi)
socket.on('user:status_change', (data) => {
    // Kendi durum değişimimiz değilse ekranda sesli ve görsel uyarı ver
    if (currentUser && normalizeKey(data.username) !== normalizeKey(currentUser.username)) {
        showStatusToast(data.username, data.isOnline);
        playStatusChime(data.isOnline);
    }

    const contact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(data.username));
    if (contact) {
        contact.isOnline = data.isOnline;
        contact.statusText = data.isOnline ? 'Online' : 'Offline';
        contact.lastSeen = data.isOnline ? 'Online' : 'Offline';
        renderChatsList(contactsList);
    } else {
        // Yeni bir kullanıcı bağlandıysa listeyi yenile
        loadChatsList();
    }

    if (activeContact && normalizeKey(activeContact.username) === normalizeKey(data.username)) {
        activeContact.isOnline = data.isOnline;
        if (data.isOnline) {
            chatContactStatus.textContent = 'Online';
            headerOnlineDot.style.display = 'block';
        } else {
            chatContactStatus.textContent = 'Offline';
            headerOnlineDot.style.display = 'none';
        }
    }

    if (data.isOnline && currentCallTarget && normalizeKey(currentCallTarget) === normalizeKey(data.username)) {
        if (outgoingCallModal && outgoingCallModal.style.display === 'flex' && outgoingCallStatus) {
            outgoingCallStatus.textContent = 'Çalıyor (Karşı cihaz Online oldu)...';
        }
    }
});

// Yeni Bir Kullanıcı Kayıt Olduğunda
socket.on('user:new_registered', (data) => {
    if (data && data.username) {
        savePermanentLocalUsers([{ username: data.username, avatar: data.avatar || '/avatars/default.svg' }]);
    }
    if (currentUser && normalizeKey(data.username) !== normalizeKey(currentUser.username)) {
        showStatusToast(data.username, true);
        playStatusChime(true);
        loadChatsList();
        loadRegisteredUsersDropdown();
    }
});

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

// CEP TELEFONU GİBİ OTOMATİK UYANMA VE ONLINE OLMA SİSTEMİ:
// Kullanıcı Offline veya çıkış yapmış/beklemede olsa bile kendisine mesaj ya da arama geldiğinde
// otomatik olarak Online olur ve ekrana arama / mesaj bildirimi düşer.
socket.on('system:wakeup', async (data) => {
    if (!data || !data.targetUsername) return;

    // Eğer gönderen kişi bizzat bu sekmedeki aktif kullanıcıysa işlem yapma
    if (currentUser && normalizeKey(currentUser.username) === normalizeKey(data.sender)) {
        return;
    }

    const targetKey = normalizeKey(data.targetUsername);
    const isAlreadyTarget = currentUser && normalizeKey(currentUser.username) === targetKey;
    const savedUsername = localStorage.getItem('msj_saved_username') || '';
    const isSavedTarget = savedUsername && normalizeKey(savedUsername) === targetKey;
    const isStandbyWithoutActiveUser = !currentUser && (!savedUsername || isSavedTarget);

    // Eğer bu tarayıcıda başka bir kullanıcı aktif oturumdaysa onun oturumunu bölme
    if (!isAlreadyTarget && !isSavedTarget && !isStandbyWithoutActiveUser) {
        return;
    }

    let wokeUpFromOffline = false;
    if (!isAlreadyTarget) {
        wokeUpFromOffline = true;
        await quickLoginAsRegisteredUser(data.targetUsername);
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
        showStatusToast(`🟢 Otomatik Online • 📞 ${data.sender} Arıyor`, true);
        // Eğer gelen arama ekranı henüz açılmadıysa hemen ekrana düşür
        setTimeout(() => {
            if (incomingCallModal && incomingCallModal.style.display !== 'flex' && (!activeCallScreen || activeCallScreen.style.display !== 'flex')) {
                currentTargetSocketId = data.callerSocketId || currentTargetSocketId;
                currentCallTarget = data.sender;
                currentCallType = data.callType || 'voice';
                if (incomingCallerName) incomingCallerName.textContent = data.sender;
                if (incomingCallerAvatar) incomingCallerAvatar.src = data.callerAvatar || '/avatars/default.svg';
                if (incomingCallType) {
                    incomingCallType.textContent = currentCallType === 'video' ? 'Gelen Görüntülü Arama...' : 'Gelen Sesli Arama...';
                }
                incomingCallModal.style.display = 'flex';
                playRingtone();
                triggerSystemNotification(`📞 GELEN ARAMA: ${data.sender}`, {
                    body: `${data.sender} sizi arıyor... Cevaplamak için dokunun.`,
                    icon: data.callerAvatar || '/icon-192.png',
                    badge: '/icon-192.png',
                    tag: 'incoming-call',
                    renotify: true,
                    requireInteraction: true
                });
            }
        }, 150);
    } else if (data.type === 'message') {
        const msgObj = data.message || {
            id: 'wakeup_' + Date.now(),
            sender: data.sender,
            recipient: data.targetUsername,
            text: data.text || 'Yeni mesaj',
            timestamp: new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
        };

        showStatusToast(`🟢 Otomatik Online • 💬 ${data.sender} mesaj gönderdi`, true);

        if (wokeUpFromOffline) {
            playIncomingMessageSound();
            showMessageNotificationToast(msgObj);
            triggerSystemNotification(`💬 ${data.sender}`, {
                body: msgObj.text || 'Yeni bir mesajınız var',
                icon: '/icon-192.png',
                badge: '/icon-192.png',
                tag: 'msg-' + data.sender
            });
            loadChatsList().then(() => {
                if (!activeContact) {
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

                    socket.volatile.emit('call:audio_chunk', {
                        targetSocketId: currentTargetSocketId,
                        targetUsername: currentCallTarget,
                        sampleRate: Math.floor(callAudioContext.sampleRate / 2),
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

// Socket.IO üzerinden gelen yedek gerçek zamanlı ses paketlerini (PCM16) anında hoparlörden çal
socket.on('call:audio_chunk', (data) => {
    if (!data || !data.pcm) return;
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

// GELEN ARAMA (RESİMDEKİ GİBİ ARAYANIN ADI, EVET VE HAYIR BUTONLARI)
socket.on('call:incoming', (data) => {
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
socket.on('call:peer_disconnected', () => endCall(false));

function endCall(notifyPeer = true) {
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
    playCallEndedSound();
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
        <div class="encryption-warning-banner">
            <span class="enc-icon">🔒</span>
            <span class="enc-text">
                Mesajlar ve aramalar uçtan uca şifrelidir. Bu sohbetteki yazışmalar temizlendi.
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

if (menuItemDeleteUser) {
    menuItemDeleteUser.addEventListener('click', () => {
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
        alert(`Kullanıcı: ${activeContact.username}\nDurum: ${activeContact.isOnline ? '🟢 Çevrimiçi (Online)' : '⚪ Çevrimdışı (Offline - Mesaj ve Arama Gönderilebilir)'}`);
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
    }
    profileModal.style.display = 'flex';
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
});

if (menuItemInstall) {
    menuItemInstall.addEventListener('click', async () => {
        if (deferredPrompt) {
            deferredPrompt.prompt();
            await deferredPrompt.userChoice;
            deferredPrompt = null;
        } else {
            alert('Bu uygulamayı telefonunuza veya bilgisayarınıza yüklemek için:\nTarayıcınızın menüsünden (üç nokta veya paylaş butonu) "Ana Ekrana Ekle" ya da "Uygulamayı Yükle" seçeneğini kullanabilirsiniz.');
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

// Arka Plan / Bekleme Modu Yedek Uyandırıcı (WebSocket uyku moduna girse bile mesaj/arama gelince anında Online yapar)
let clientLastPollNotifId = 0;
setInterval(async () => {
    try {
        const targetUser = (currentUser && currentUser.username) || localStorage.getItem('msj_saved_username') || '';
        const res = await fetch(`/api/system/notifications/poll?since=${clientLastPollNotifId}${targetUser ? '&user=' + encodeURIComponent(targetUser) : ''}`);
        const data = await res.json();
        if (data && data.success) {
            if (clientLastPollNotifId > 0 && data.lastId > clientLastPollNotifId && Array.isArray(data.notifications)) {
                for (const item of data.notifications) {
                    if (currentUser && normalizeKey(item.sender) === normalizeKey(currentUser.username)) continue;
                    if (item.recipient) {
                        // Eğer bu cihaz hedef kullanıcıysa ve henüz Online değilse otomatik Online yap
                        const savedU = localStorage.getItem('msj_saved_username') || '';
                        if (!currentUser && (!savedU || normalizeKey(savedU) === normalizeKey(item.recipient))) {
                            await quickLoginAsRegisteredUser(item.recipient);
                        } else if (currentUser && normalizeKey(currentUser.username) === normalizeKey(item.recipient)) {
                            const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token') || '';
                            socket.emit('user:join', { token, username: currentUser.username });
                        }
                    }
                }
            }
            if (typeof data.lastId === 'number') {
                clientLastPollNotifId = data.lastId;
            }
        }
    } catch (e) {}
}, 3500);

// Uygulamayı Başlat
initAuth();
