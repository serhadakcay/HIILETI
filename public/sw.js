// MSJ Service Worker - PWA Kurulabilirlik, Çevrimdışı Önbellek ve Bildirimler
const CACHE_NAME = 'msj-cache-v8';
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
                // Başarılı yanıtı önbelleğe al
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

// Bildirime dokunulduğunda / tıklandığında uygulamayı ön plana getir
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if ('focus' in client) {
                    return client.focus();
                }
            }
            if (self.clients.openWindow) {
                return self.clients.openWindow('/');
            }
        })
    );
});
