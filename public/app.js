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

// WebRTC Değişkenleri
let peerConnection = null;
let localStream = null;
let currentCallTarget = null;
let currentCallType = 'video';
let currentCallerSocketId = null;
let callTimerInterval = null;
let callStartTime = null;
let isAudioMuted = false;
let isVideoMuted = false;

const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
    ]
};

// DOM Referansları
const appRoot = document.getElementById('appRoot');

// 1. Ekran (Sohbetler Listesi)
const chatsScreen = document.getElementById('chatsScreen');
const btnHeaderCamera = document.getElementById('btnHeaderCamera');
const btnHeaderMenu = document.getElementById('btnHeaderMenu');
const headerDropdown = document.getElementById('headerDropdown');
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
const menuItemClearChat = document.getElementById('menuItemClearChat');
const menuItemContactInfo = document.getElementById('menuItemContactInfo');
const menuItemCloseChat = document.getElementById('menuItemCloseChat');
const menuItemSwitchUser = document.getElementById('menuItemSwitchUser');
const quickUsersContainer = document.getElementById('quickUsersContainer');
const quickUsersList = document.getElementById('quickUsersList');

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

// Arama & Önizleme Modalları
const incomingCallModal = document.getElementById('incomingCallModal');
const incomingCallerAvatar = document.getElementById('incomingCallerAvatar');
const incomingCallerName = document.getElementById('incomingCallerName');
const incomingCallType = document.getElementById('incomingCallType');
const btnAcceptCall = document.getElementById('btnAcceptCall');
const btnRejectCall = document.getElementById('btnRejectCall');

const activeCallScreen = document.getElementById('activeCallScreen');
const remoteVideo = document.getElementById('remoteVideo');
const localVideo = document.getElementById('localVideo');
const remoteAudioPlaceholder = document.getElementById('remoteAudioPlaceholder');
const activeCallAvatar = document.getElementById('activeCallAvatar');
const activeCallName = document.getElementById('activeCallName');
const activeCallTargetTitle = document.getElementById('activeCallTargetTitle');
const activeCallTimer = document.getElementById('activeCallTimer');
const btnToggleMic = document.getElementById('btnToggleMic');
const btnToggleCam = document.getElementById('btnToggleCam');
const btnEndCall = document.getElementById('btnEndCall');

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
// YENİ GELEN MESAJ SES VE AÇILIR BİLDİRİM MOTORU
// ==========================================================

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
        gain.gain.linearRampToValueAtTime(0.25, now + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.38);

        osc.start(now);
        osc.stop(now + 0.4);
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
// 1. KULLANICI GİRİŞİ, KAYIT VE KALICI OTURUM YÖNETİMİ
// ==========================================================

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

    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');
    const savedUserStr = localStorage.getItem('msj_user');
    const savedUsername = localStorage.getItem('msj_saved_username') || '';

    // Kayıtlı kullanıcı listesini Lite SQL veritabanından çek
    const userCount = await loadRegisteredUsersDropdown();

    // 1. Eğer yerel hafızada kayıtlı kullanıcı ve kalıcı token varsa doğrudan giriş yap
    if (token) {
        try {
            const res = await fetch('/api/auth/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });
            const data = await res.json();
            if (data.success && data.user) {
                onUserAuthenticated(data.user, token);
                return;
            }
        } catch (e) {
            if (savedUserStr) {
                try {
                    const localUser = JSON.parse(savedUserStr);
                    onUserAuthenticated(localUser, token);
                    return;
                } catch(err) {}
            }
        }
    }

    // 2. Token yoksa veya oturum açılmamışsa:
    if (userCount === 0 && !savedUsername) {
        showRegisterPrompt();
    } else {
        showPasswordPrompt(savedUsername);
    }
}

function showRegisterPrompt() {
    authMode = 'register';
    authModal.style.display = 'flex';
    authErrorMsg.style.display = 'none';
    rememberedUserBox.style.display = 'none';
    fieldUsernameSelect.style.display = 'block';
    fieldConfirmPassword.style.display = 'block';
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
    authModal.style.display = 'flex';
    authErrorMsg.style.display = 'none';
    fieldConfirmPassword.style.display = 'none';
    btnAuthSubmit.textContent = 'Giriş Yap';
    btnToggleAuthMode.textContent = 'Hesabınız yok mu? Yeni Kullanıcı Aç';

    if (username) {
        rememberedUserBox.style.display = 'flex';
        rememberedName.textContent = username;
        rememberedAvatar.src = `/avatars/default.svg`;
        fieldUsernameSelect.style.display = 'none';
        inputUsername.value = username;
        inputPassword.value = '';
        inputPassword.focus();
    } else {
        rememberedUserBox.style.display = 'none';
        fieldUsernameSelect.style.display = 'block';
        inputPassword.value = '';
    }
}

async function loadRegisteredUsersDropdown() {
    try {
        const res = await fetch('/api/users/registered');
        const data = await res.json();
        if (data.success && data.users) {
            selectRegisteredUser.innerHTML = '<option value="">-- Kayıtlı Kullanıcı Seçin --</option>';
            if (quickUsersList) quickUsersList.innerHTML = '';

            data.users.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.username;
                const statusSuffix = u.lastSeen === 'Online' ? ' (Online)' : ' (Offline)';
                opt.textContent = `${u.username}${statusSuffix}`;
                selectRegisteredUser.appendChild(opt);

                if (quickUsersList) {
                    const chip = document.createElement('button');
                    chip.type = 'button';
                    chip.className = 'quick-user-chip';
                    chip.innerHTML = `
                        <img src="${u.avatar || '/avatars/default.svg'}" class="avatar-mini" alt="${escapeHtml(u.username)}">
                        <span><strong>${escapeHtml(u.username)}</strong></span>
                    `;
                    chip.addEventListener('click', () => {
                        inputUsername.value = u.username;
                        inputPassword.value = '';
                        inputPassword.focus();
                    });
                    quickUsersList.appendChild(chip);
                }
            });

            if (quickUsersContainer) {
                quickUsersContainer.style.display = data.users.length > 0 ? 'block' : 'none';
            }

            return data.users.length;
        }
    } catch (e) {}
    return 0;
}

selectRegisteredUser.addEventListener('change', () => {
    if (selectRegisteredUser.value) {
        inputUsername.value = selectRegisteredUser.value;
        inputPassword.focus();
    }
});

btnSwitchAccount.addEventListener('click', () => {
    rememberedUserBox.style.display = 'none';
    fieldUsernameSelect.style.display = 'block';
    inputUsername.value = '';
    inputPassword.value = '';
    inputUsername.focus();
});

btnToggleAuthMode.addEventListener('click', () => {
    if (authMode === 'login') {
        showRegisterPrompt();
    } else {
        showPasswordPrompt('');
    }
});

document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    authErrorMsg.style.display = 'none';

    const username = inputUsername.value.trim();
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
            if (remember) {
                localStorage.setItem('msj_saved_username', data.user.username);
            }
            sessionStorage.setItem('msj_token', data.token);
            localStorage.setItem('msj_token', data.token);
            localStorage.setItem('msj_user', JSON.stringify(data.user));

            onUserAuthenticated(data.user, data.token);
            authModal.style.display = 'none';
        } else {
            authErrorMsg.textContent = data.error || 'İşlem başarısız.';
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

    // Soket sunucusuna kendi oturumunu bildir
    socket.emit('user:join', { token, username: user.username });

    // Sohbet listesini getir
    loadChatsList();
}

// ==========================================================
// 2. RESİM 1: SOHBETLER / KAYITLI KULLANICILAR LİSTESİ
// ==========================================================

async function loadChatsList() {
    const token = localStorage.getItem('msj_token') || sessionStorage.getItem('msj_token');
    if (!token) return;

    try {
        const res = await fetch('/api/chats', {
            headers: { 'x-auth-token': token }
        });
        const data = await res.json();

        if (data.success && data.chats) {
            contactsList = data.chats;
            localStorage.setItem('msj_cached_contacts', JSON.stringify(contactsList));
            renderChatsList(contactsList);
        }
    } catch (err) {
        console.error('Sohbetler yüklenemedi:', err);
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

        let lastSnippet = contact.isOnline ? '🟢 Çevrimiçi' : '⚪ Çevrimdışı';
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
                <div class="chat-bottom-line">
                    <div class="chat-last-msg-preview ${isUnreadSnippet ? 'unread' : ''}" title="${escapeHtml(lastSnippet)}">
                        ${isUnreadSnippet ? '<span class="msg-unread-icon">✉️</span>' : ''}
                        <span>${escapeHtml(lastSnippet)}</span>
                    </div>
                    <button type="button" class="btn-chat-action ${hasUnread ? 'unread' : ''}">
                        ${hasUnread ? `✉️ Oku (${contact.unreadCount})` : '💬 Mesaj / Ara'}
                    </button>
                </div>
            </div>
        `;

        item.addEventListener('click', () => {
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

// FAB Butonu: Yeni Kullanıcı Kaydet / Sohbet Başlat
btnFabNewChat.addEventListener('click', () => {
    showRegisterPrompt();
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

// ESC tuşuyla da aktif sohbeti kapatıp kullanıcı ekranına dönme
window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && activeContact) {
        closeActiveChat();
    }
});

// Birebir Özel Mesaj Geçmişini Yükleme
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

    socket.emit('chat:load_history', { contactUsername }, (res) => {
        if (res && res.success && res.messages) {
            res.messages.forEach(msg => appendMessageBubble(msg));
            scrollToBottom();
        }
    });
}

function appendMessageBubble(msg) {
    if (!activeContact) return;

    // Zaten ekranda aynı id varsa mükerrer basma
    if (msg.id && document.getElementById(msg.id)) return;

    // Yalnızca şu anki aktif kişiye ait mesajları ekrana bas
    const isForActiveContact =
        (normalizeKey(msg.sender) === normalizeKey(activeContact.username)) ||
        (normalizeKey(msg.recipient) === normalizeKey(activeContact.username));

    if (!isForActiveContact) return;

    const isMe = currentUser && normalizeKey(msg.sender) === normalizeKey(currentUser.username);
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

// Enter tuşu ile gönder
messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSendOrMic();
    }
});

// Sağdaki Yuvarlak Yeşil Butona veya Form Gönderimine Basıldığında
btnSendOrMic.addEventListener('click', (e) => {
    // Eğer form içinde submit tetiklenmiyorsa doğrudan çağır
    if (!chatInputForm) {
        handleSendOrMic();
    }
});

if (chatInputForm) {
    chatInputForm.addEventListener('submit', (e) => {
        e.preventDefault();
        handleSendOrMic();
    });
}

function handleSendOrMic() {
    const text = messageInput.value.trim();
    if (text) {
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
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
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

    const token = sessionStorage.getItem('msj_token') || localStorage.getItem('msj_token');
    const tempId = 'msg_tmp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);

    const tempMsg = {
        id: tempId,
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
        token: token
    }, (ack) => {
        const bubbleEl = document.getElementById(tempId);
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
                const checks = bubbleEl.querySelector('.bubble-checks');
                if (checks) checks.textContent = '✓✓';
            }
        }
    });

    messageInput.value = '';
    iconMic.style.display = 'block';
    iconSend.style.display = 'none';
    messageInput.focus();
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
                    file: uploadedFile
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

    // 2. Eğer mesaj bize geldiyse ve o kişinin penceresi açık DEĞİLSE:
    if (isIncoming && !isFromActive) {
        // A) Bildirim sesi çal
        playIncomingMessageChime();

        // B) Ekranın tepesinde zengin açılır bildirim kutusu göster (Küçük ikon ile)
        showMessageNotificationToast(msg);

        // C) Mobil titreşim
        if (navigator.vibrate) {
            try { navigator.vibrate([120, 50, 120]); } catch(e) {}
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
});

// Yeni Bir Kullanıcı Kayıt Olduğunda
socket.on('user:new_registered', (data) => {
    if (currentUser && normalizeKey(data.username) !== normalizeKey(currentUser.username)) {
        showStatusToast(data.username, true);
        playStatusChime(true);
        loadChatsList();
        loadRegisteredUsersDropdown();
    }
});

// ==========================================================
// 6. WEBRTC SESLİ VE GÖRÜNTÜLÜ ARAMA MOTORU
// ==========================================================

btnVideoCall.addEventListener('click', () => initiateCall('video'));
btnVoiceCall.addEventListener('click', () => initiateCall('voice'));

async function initiateCall(callType) {
    if (!activeContact) return;

    currentCallTarget = activeContact.username;
    currentCallType = callType;

    const stream = await initLocalMedia(callType === 'video');
    if (!stream) return;

    setupPeerConnection();

    socket.emit('call:initiate', {
        recipient: activeContact.username,
        callType: callType
    });

    openActiveCallScreen(activeContact.username, activeContact.avatar);
}

async function initLocalMedia(video = true) {
    try {
        localStream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: video ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false
        });
        localVideo.srcObject = localStream;
        return localStream;
    } catch (err) {
        alert('Kamera veya mikrofon erişim izni alınamadı: ' + err.message);
        return null;
    }
}

function setupPeerConnection() {
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }

    peerConnection = new RTCPeerConnection(rtcConfig);

    if (localStream) {
        localStream.getTracks().forEach(track => {
            peerConnection.addTrack(track, localStream);
        });
    }

    peerConnection.onicecandidate = (event) => {
        if (event.candidate && currentCallerSocketId) {
            socket.emit('call:signal', {
                targetSocketId: currentCallerSocketId,
                signal: { candidate: event.candidate }
            });
        }
    };

    peerConnection.ontrack = (event) => {
        remoteVideo.srcObject = event.streams[0];
        if (currentCallType === 'voice') {
            remoteVideo.style.display = 'none';
            remoteAudioPlaceholder.style.display = 'flex';
        } else {
            remoteVideo.style.display = 'block';
            remoteAudioPlaceholder.style.display = 'none';
        }
    };
}

// Gelen Arama
socket.on('call:incoming', (data) => {
    currentCallerSocketId = data.callerSocketId;
    currentCallTarget = data.callerUsername;
    currentCallType = data.callType;

    incomingCallerName.textContent = data.callerUsername;
    incomingCallerAvatar.src = data.callerAvatar || '/avatars/default.svg';
    incomingCallType.textContent = data.callType === 'video' ? 'Görüntülü Arama Geliyor...' : 'Sesli Arama Geliyor...';
    incomingCallModal.style.display = 'flex';
});

btnAcceptCall.addEventListener('click', async () => {
    incomingCallModal.style.display = 'none';
    const stream = await initLocalMedia(currentCallType === 'video');
    if (!stream) {
        socket.emit('call:reject', { callerSocketId: currentCallerSocketId, reason: 'İzin reddedildi' });
        return;
    }

    setupPeerConnection();
    socket.emit('call:accept', { callerSocketId: currentCallerSocketId });

    const contact = contactsList.find(c => normalizeKey(c.username) === normalizeKey(currentCallTarget));
    openActiveCallScreen(currentCallTarget, contact ? contact.avatar : '/avatars/default.svg');
});

btnRejectCall.addEventListener('click', () => {
    incomingCallModal.style.display = 'none';
    socket.emit('call:reject', { callerSocketId: currentCallerSocketId });
    currentCallerSocketId = null;
});

socket.on('call:accepted', async (data) => {
    currentCallerSocketId = data.responderSocketId;
    if (!peerConnection) return;
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    socket.emit('call:signal', {
        targetSocketId: currentCallerSocketId,
        signal: { sdp: peerConnection.localDescription }
    });
    startCallTimer();
});

socket.on('call:rejected', (data) => {
    alert(data.reason || 'Arama reddedildi.');
    endCall();
});

socket.on('call:error', (data) => {
    alert(data.message || 'Arama başlatılamadı.');
    endCall();
});

socket.on('call:signal', async (data) => {
    if (!peerConnection) return;
    const signal = data.signal;

    if (signal.sdp) {
        if (signal.sdp.type === 'offer') {
            await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            socket.emit('call:signal', {
                targetSocketId: currentCallerSocketId,
                signal: { sdp: peerConnection.localDescription }
            });
            startCallTimer();
        } else if (signal.sdp.type === 'answer') {
            await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
        }
    } else if (signal.candidate) {
        try {
            await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate));
        } catch (e) {}
    }
});

function openActiveCallScreen(name, avatar) {
    activeCallTargetTitle.textContent = name;
    activeCallName.textContent = name;
    activeCallAvatar.src = avatar;

    if (currentCallType === 'voice') {
        remoteVideo.style.display = 'none';
        remoteAudioPlaceholder.style.display = 'flex';
    } else {
        remoteVideo.style.display = 'block';
        remoteAudioPlaceholder.style.display = 'none';
    }

    activeCallScreen.style.display = 'flex';
}

btnToggleMic.addEventListener('click', () => {
    if (!localStream) return;
    isAudioMuted = !isAudioMuted;
    localStream.getAudioTracks().forEach(t => t.enabled = !isAudioMuted);
    btnToggleMic.style.backgroundColor = isAudioMuted ? 'var(--danger)' : 'rgba(255,255,255,0.2)';
});

btnToggleCam.addEventListener('click', () => {
    if (!localStream || currentCallType === 'voice') return;
    isVideoMuted = !isVideoMuted;
    localStream.getVideoTracks().forEach(t => t.enabled = !isVideoMuted);
    btnToggleCam.style.backgroundColor = isVideoMuted ? 'var(--danger)' : 'rgba(255,255,255,0.2)';
});

btnEndCall.addEventListener('click', () => endCall());

socket.on('call:ended', () => endCall());
socket.on('call:peer_disconnected', () => endCall());

function endCall() {
    if (callTimerInterval) clearInterval(callTimerInterval);
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        localStream = null;
    }

    remoteVideo.srcObject = null;
    localVideo.srcObject = null;
    activeCallScreen.style.display = 'none';
    incomingCallModal.style.display = 'none';

    if (currentCallerSocketId) {
        socket.emit('call:end', { targetSocketId: currentCallerSocketId });
        currentCallerSocketId = null;
    }
}

function startCallTimer() {
    callStartTime = Date.now();
    if (callTimerInterval) clearInterval(callTimerInterval);
    callTimerInterval = setInterval(() => {
        const delta = Math.floor((Date.now() - callStartTime) / 1000);
        const mins = String(Math.floor(delta / 60)).padStart(2, '0');
        const secs = String(delta % 60).padStart(2, '0');
        const formatted = `${mins}:${secs}`;
        activeCallTimer.textContent = formatted;
        document.getElementById('callDuration').textContent = formatted;
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

if (menuItemCloseChat) {
    menuItemCloseChat.addEventListener('click', () => {
        closeActiveChat();
    });
}

if (menuItemContactInfo) {
    menuItemContactInfo.addEventListener('click', () => {
        if (!activeContact) return;
        alert(`Kullanıcı: ${activeContact.username}\nDurum: ${activeContact.isOnline ? 'Çevrimiçi (Online)' : 'Çevrimdışı (Offline)'}`);
    });
}

if (menuItemSwitchUser) {
    menuItemSwitchUser.addEventListener('click', () => {
        showPasswordPrompt('');
    });
}

menuItemLogout.addEventListener('click', () => {
    if (confirm('Oturumu kapatmak istediğinize emin misiniz?')) {
        const token = localStorage.getItem('msj_token');
        if (token) {
            fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            });
        }
        sessionStorage.removeItem('msj_token');
        localStorage.removeItem('msj_token');
        localStorage.removeItem('msj_user');
        location.reload();
    }
});

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
        showRegisterPrompt();
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

// Uygulamayı Başlat
initAuth();
