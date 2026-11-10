// MSJ Service Worker - Arka Plan Mesaj ve Arama Bildirimleri (WhatsApp / Signal / Telegram Tarzı Kalıcı Uyandırma)
const CACHE_NAME = 'msj-cache-v24';
const SW_DB_NAME = 'msj_sw_state_db';
const SW_STORE_NAME = 'sw_kv';

let swLastNotificationId = 0;
let swCurrentUser = '';
let swPollTimer = null;
const swSeenCallIds = new Set();

// IndexedDB üzerinden kullanıcı adını ve son bildirim ID'sini kalıcı sakla (Uygulama kapatılsa bile silinmez)
function openSwDb() {
    return new Promise((resolve, reject) => {
        try {
            const req = indexedDB.open(SW_DB_NAME, 1);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(SW_STORE_NAME)) {
                    db.createObjectStore(SW_STORE_NAME);
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        } catch (e) {
            reject(e);
        }
    });
}

async function swSetKv(key, val) {
    try {
        const db = await openSwDb();
        return new Promise((resolve) => {
            const tx = db.transaction(SW_STORE_NAME, 'readwrite');
            tx.objectStore(SW_STORE_NAME).put(val, key);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => resolve(false);
        });
    } catch (e) {
        return false;
    }
}

async function swGetKv(key) {
    try {
        const db = await openSwDb();
        return new Promise((resolve) => {
            const tx = db.transaction(SW_STORE_NAME, 'readonly');
            const req = tx.objectStore(SW_STORE_NAME).get(key);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(undefined);
        });
    } catch (e) {
        return undefined;
    }
}

async function ensureSwUserLoaded() {
    if (!swCurrentUser) {
        const savedUser = await swGetKv('swCurrentUser');
        if (savedUser && typeof savedUser === 'string') {
            swCurrentUser = savedUser;
        }
    }
    if (!swLastNotificationId) {
        const savedId = await swGetKv('swLastNotificationId');
        if (typeof savedId === 'number' && savedId > 0) {
            swLastNotificationId = savedId;
        }
    }
}

async function notifyAndWakeClients(item, targetUrl) {
    try {
        const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        if (clientList.length === 0 && self.clients.openWindow && targetUrl) {
            try {
                await self.clients.openWindow(targetUrl);
                return;
            } catch (e) {}
        }
        for (const client of clientList) {
            try {
                client.postMessage({
                    type: 'SW_WAKEUP_EVENT',
                    item,
                    url: targetUrl
                });
                if ('focus' in client) {
                    client.focus().catch(() => {});
                }
            } catch (e) {}
        }
    } catch (e) {}
}

async function runSwPollCycle() {
    try {
        await ensureSwUserLoaded();

        const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        const hasFocusedClient = clientList.some(c => c.focused && c.visibilityState === 'visible');

        const url = `/api/system/notifications/poll?since=${swLastNotificationId}&user=${encodeURIComponent(swCurrentUser || '')}`;
        const res = await fetch(url, { cache: 'no-store' });
        const data = await res.json();
        if (!data || !data.success) return;

        if (!swCurrentUser && data.localPcUser) {
            swCurrentUser = data.localPcUser;
            await swSetKv('swCurrentUser', swCurrentUser);
        }

        if (typeof data.lastId === 'number' && data.lastId < swLastNotificationId) {
            swLastNotificationId = 0;
            await swSetKv('swLastNotificationId', 0);
            return;
        }

        const effectiveUser = swCurrentUser || data.localPcUser || '';
        const autoUserSuffix = effectiveUser ? `&autoUser=${encodeURIComponent(effectiveUser)}` : '';

        // 1. Bekleyen aktif arama varsa (uygulama kapalıyken gelen arama)
        if (Array.isArray(data.activeCalls) && data.activeCalls.length > 0 && !hasFocusedClient) {
            for (const callObj of data.activeCalls) {
                if (!callObj || !callObj.callerUsername) continue;
                const callKey = callObj.callId || (callObj.callerUsername + '_' + callObj.createdAt);
                if (swSeenCallIds.has(callKey)) continue;
                swSeenCallIds.add(callKey);

                const callUrl = `/?openChat=${encodeURIComponent(callObj.callerUsername)}&incomingCall=1${autoUserSuffix}`;
                const acceptUrl = `/?openChat=${encodeURIComponent(callObj.callerUsername)}&incomingCall=1&autoAcceptCall=1${autoUserSuffix}`;

                await notifyAndWakeClients({
                    type: 'call',
                    sender: callObj.callerUsername,
                    recipient: swCurrentUser,
                    callType: callObj.callType || 'voice',
                    callPayload: callObj
                }, callUrl);

                await self.registration.showNotification(`📞 GELEN ARAMA: ${callObj.callerUsername}`, {
                    body: `${callObj.callerUsername} sizi ${callObj.callType === 'video' ? 'görüntülü' : 'sesli'} arıyor! Cevaplamak için dokunun.`,
                    icon: callObj.callerAvatar || '/icon-192.png',
                    badge: '/icon-192.png',
                    tag: 'incoming-call',
                    renotify: true,
                    requireInteraction: true,
                    vibrate: [1000, 400, 1000, 400, 1000, 400, 1000],
                    actions: [
                        { action: 'accept', title: '📞 Cevapla (Evet)' },
                        { action: 'reject', title: '❌ Reddet (Hayır)' }
                    ],
                    data: {
                        url: callUrl,
                        acceptUrl: acceptUrl,
                        caller: callObj.callerUsername,
                        recipient: swCurrentUser,
                        type: 'call'
                    }
                });
            }
        }

        // 2. Yeni mesaj ve arama bildirimleri
        const isFirstPoll = swLastNotificationId === 0;
        if (data.lastId > swLastNotificationId && Array.isArray(data.notifications)) {
            for (const item of data.notifications) {
                if (!item || !item.recipient) continue;
                if (isFirstPoll && item.timestamp && (Date.now() - item.timestamp > 90000)) continue;
                if (swCurrentUser && item.recipient.toLowerCase() !== swCurrentUser.toLowerCase()) continue;
                if (swCurrentUser && item.sender && item.sender.toLowerCase() === swCurrentUser.toLowerCase()) continue;
                const itemAutoUserSuffix = `&autoUser=${encodeURIComponent(item.recipient || effectiveUser)}`;

                if (item.type === 'call') {
                    const callKey = item.callId || (item.sender + '_' + item.id);
                    swSeenCallIds.add(callKey);
                    const callUrl = `/?openChat=${encodeURIComponent(item.sender)}&incomingCall=1${itemAutoUserSuffix}`;
                    const acceptUrl = `/?openChat=${encodeURIComponent(item.sender)}&incomingCall=1&autoAcceptCall=1${itemAutoUserSuffix}`;

                    await notifyAndWakeClients(item, callUrl);

                    if (!hasFocusedClient) {
                        await self.registration.showNotification(`📞 GELEN ARAMA: ${item.sender}`, {
                            body: `${item.sender} sizi arıyor! Cevaplamak için dokunun.`,
                            icon: item.callerAvatar || '/icon-192.png',
                            badge: '/icon-192.png',
                            tag: 'incoming-call',
                            renotify: true,
                            requireInteraction: true,
                            vibrate: [1000, 400, 1000, 400, 1000, 400, 1000],
                            actions: [
                                { action: 'accept', title: '📞 Cevapla (Evet)' },
                                { action: 'reject', title: '❌ Reddet (Hayır)' }
                            ],
                            data: {
                                url: callUrl,
                                acceptUrl: acceptUrl,
                                caller: item.sender,
                                recipient: swCurrentUser,
                                type: 'call'
                            }
                        });
                    }
                } else if (item.type === 'message') {
                    const msgUrl = `/?openChat=${encodeURIComponent(item.sender)}${itemAutoUserSuffix}`;
                    const previewText = (item.text && !String(item.text).startsWith('e2ee1:'))
                        ? item.text
                        : '🔒 Yeni bir mesajınız var';

                    await notifyAndWakeClients(item, msgUrl);

                    if (!hasFocusedClient) {
                        await self.registration.showNotification(`💬 ${item.sender}`, {
                            body: previewText,
                            icon: '/icon-192.png',
                            badge: '/icon-192.png',
                            tag: 'msg-' + item.sender,
                            renotify: true,
                            requireInteraction: true,
                            vibrate: [200, 100, 200],
                            actions: [
                                { action: 'open', title: '💬 Sohbeti Aç & Yanıtla' }
                            ],
                            data: {
                                url: msgUrl,
                                sender: item.sender,
                                recipient: swCurrentUser,
                                type: 'message'
                            }
                        });
                    }
                }
            }
        }

        if (typeof data.lastId === 'number' && data.lastId !== swLastNotificationId) {
            swLastNotificationId = data.lastId;
            await swSetKv('swLastNotificationId', swLastNotificationId);
        }
    } catch (e) {}
}

function startSwBackgroundPoll() {
    if (swPollTimer) return;
    runSwPollCycle();
    swPollTimer = setInterval(runSwPollCycle, 2000);
}

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'INIT_USER') {
        const newU = (event.data.username || '').trim();
        if (newU) {
            swCurrentUser = newU;
            swSetKv('swCurrentUser', newU);
        }
        startSwBackgroundPoll();
    } else if (event.data && event.data.type === 'POLL_NOW') {
        runSwPollCycle();
    }
});

self.addEventListener('push', (event) => {
    event.waitUntil(runSwPollCycle());
});

self.addEventListener('sync', (event) => {
    event.waitUntil(runSwPollCycle());
});

self.addEventListener('periodicsync', (event) => {
    event.waitUntil(runSwPollCycle());
});

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        Promise.all([
            caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k)))),
            ensureSwUserLoaded()
        ])
    );
    self.clients.claim();
    startSwBackgroundPoll();
});

// PWA Kurulumu için zorunlu fetch dinleyicisi (Ağ-öncelikli passthrough)
self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (!req || req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.pathname.startsWith('/socket.io/') || url.pathname.startsWith('/api/')) return;
    event.respondWith(
        fetch(req).catch(() => caches.match(req))
    );
});

// Bildirime veya Cevapla / Reddet / Sohbeti Aç butonlarına dokunulduğunda uygulamayı otomatik aç ve ekrana getir
self.addEventListener('notificationclick', (event) => {
    const notifData = event.notification.data || {};
    const action = event.action;
    event.notification.close();

    if (action === 'reject' && notifData.caller) {
        event.waitUntil(
            fetch('/api/system/call/reject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    callerUsername: notifData.caller,
                    recipient: notifData.recipient || swCurrentUser,
                    reason: 'Bildirimden reddedildi'
                })
            }).catch(() => {})
        );
        return;
    }

    const targetUrl = (action === 'accept' && notifData.acceptUrl)
        ? notifData.acceptUrl
        : (notifData.url || '/');

    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                client.postMessage({
                    type: 'NOTIFICATION_CLICK',
                    url: targetUrl,
                    action: action || 'open',
                    data: notifData
                });
                if ('focus' in client) {
                    return client.focus();
                }
            }
            if (self.clients.openWindow) {
                return self.clients.openWindow(targetUrl);
            }
        })
    );
});
