// MSJ Service Worker - PWA Kurulabilirlik, Çevrimdışı Önbellek, Arka Plan Mesaj ve Arama Bildirimleri
const CACHE_NAME = 'msj-cache-v9';
const ASSETS = [
    '/',
    '/index.html',
    '/style.css',
    '/app.js',
    '/manifest.json',
    '/icon.svg',
    '/icon-192.png',
    '/icon-512.png',
    '/apple-touch-icon.png',
    '/sounds/message.wav',
    '/sounds/ringtone.wav',
    '/sounds/ringback.wav',
    '/sounds/ended.wav'
];

let swLastNotificationId = 0;
let swCurrentUser = '';
let swPollTimer = null;

function startSwBackgroundPoll() {
    if (swPollTimer) return;
    swPollTimer = setInterval(async () => {
        try {
            const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
            const hasFocusedClient = clientList.some(c => c.focused);
            if (hasFocusedClient) return;

            const url = `/api/system/notifications/poll?since=${swLastNotificationId}${swCurrentUser ? '&user=' + encodeURIComponent(swCurrentUser) : ''}`;
            const res = await fetch(url);
            const data = await res.json();
            if (data && data.success) {
                if (data.lastId > swLastNotificationId && swLastNotificationId > 0 && Array.isArray(data.notifications)) {
                    for (const item of data.notifications) {
                        if (swCurrentUser && item.sender && item.sender.toLowerCase() === swCurrentUser.toLowerCase()) continue;
                        if (item.type === 'call') {
                            self.registration.showNotification(`📞 GELEN ARAMA: ${item.sender}`, {
                                body: `${item.sender} sizi arıyor! Cevaplamak için dokunun.`,
                                icon: '/icon-192.png',
                                badge: '/icon-192.png',
                                tag: 'incoming-call',
                                renotify: true,
                                requireInteraction: true,
                                vibrate: [1000, 500, 1000, 500, 1000, 500],
                                data: { url: `/?openChat=${encodeURIComponent(item.sender)}&incomingCall=1` }
                            });
                        } else if (item.type === 'message') {
                            self.registration.showNotification(`💬 ${item.sender}`, {
                                body: item.text || 'Yeni bir mesajınız var',
                                icon: '/icon-192.png',
                                badge: '/icon-192.png',
                                tag: 'msg-' + item.sender,
                                renotify: true,
                                vibrate: [180, 80, 180],
                                data: { url: `/?openChat=${encodeURIComponent(item.sender)}` }
                            });
                        }
                    }
                }
                if (typeof data.lastId === 'number') {
                    swLastNotificationId = data.lastId;
                }
            }
        } catch (e) {}
    }, 3000);
}

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'INIT_USER') {
        swCurrentUser = event.data.username || '';
        startSwBackgroundPoll();
    }
});

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS).catch(() => {});
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.map((key) => {
                    if (key !== CACHE_NAME) {
                        return caches.delete(key);
                    }
                })
            );
        })
    );
    self.clients.claim();
    startSwBackgroundPoll();
});

self.addEventListener('fetch', (event) => {
    // API, socket.io veya upload isteklerini cache'e alma, doğrudan ağa ilet
    const url = event.request.url;
    if (url.includes('/socket.io/') || url.includes('/api/') || url.includes('/uploads/')) {
        return;
    }

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                if (response && response.status === 200 && response.type === 'basic') {
                    const responseToCache = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseToCache);
                    });
                }
                return response;
            })
            .catch(() => caches.match(event.request).then(cached => cached || caches.match('/index.html')))
    );
});

// Bildirime dokunulduğunda / tıklandığında uygulamayı ön plana getir ve ilgili sohbeti/aramayı aç
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    const targetUrl = (event.notification.data && event.notification.data.url) || '/';

    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if ('focus' in client) {
                    client.postMessage({ type: 'NOTIFICATION_CLICK', url: targetUrl });
                    return client.focus();
                }
            }
            if (self.clients.openWindow) {
                return self.clients.openWindow(targetUrl);
            }
        })
    );
});

