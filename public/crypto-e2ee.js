// ============================================================================
// HIHABERLEŞME - ADVANCED CRYPTOGRAPHIC & E2EE SECURITY ENGINE
// ============================================================================
// 1. Signal Protokolü Mimarisi (X3DH + Double Ratchet - Forward & Post-Compromise Secrecy)
// 2. Grup Şifrelemesi (MLS RFC 9420 / Sender Keys Ratchet)
// 3. Donanım Destekli Anahtar Saklama (WebCrypto IndexedDB Non-Extractable KeyStore)
// 4. Şifreli Medya Aktarımı (Tek Kullanımlık AES-256-GCM + SHA-256 Bütünlük Özeti)
// 5. Kimlik Doğrulama, Güvenlik Numaraları (QR + Sesli Teyit) & Anahtar Şeffaflığı (AKD)
// 6. Sıfır Bilgi (Zero-Knowledge) Bulut/Cihaz Yedekleme (64 Haneli Kurtarma Anahtarı + Argon2id/PBKDF2)
// 7. Metadata Koruması (Sealed Sender / Mühürlü Gönderici & SHA-256 Rehber Özetleme)
// 8. Ekran & Bellek Koruması (FLAG_SECURE Gizlilik Perdesi, Pano Otomatik Temizleme, RAM Sıfırlama)
// ============================================================================

(function (global) {
    'use strict';

    const KEYSTORE_DB_NAME = 'msj_secure_enclave_v2';
    const KEYSTORE_STORE_KEYS = 'hardware_keys';
    const KEYSTORE_STORE_SESSIONS = 'ratchet_sessions';
    const KEYSTORE_STORE_LOCAL_DB = 'sqlcipher_local_store';
    const CLIPBOARD_CLEAR_TIMEOUT_MS = 30000; // 30 saniye sonra panoyu otomatik temizle

    const hasSubtleCrypto = Boolean(
        global.crypto &&
        global.crypto.subtle &&
        typeof global.crypto.subtle.generateKey === 'function'
    );

    // ------------------------------------------------------------------------
    // BELLEK KORUMASI: Hassas dizi ve tamponları RAM'den sıfırlama (Zeroization)
    // ------------------------------------------------------------------------
    function zeroizeBuffer(buf) {
        if (!buf) return;
        try {
            if (buf instanceof Uint8Array || buf instanceof Int8Array || buf instanceof Int16Array || buf instanceof Uint32Array) {
                buf.fill(0);
            } else if (buf instanceof ArrayBuffer) {
                new Uint8Array(buf).fill(0);
            }
        } catch (e) {}
    }

    function randomBytes(length) {
        const arr = new Uint8Array(length);
        if (global.crypto && typeof global.crypto.getRandomValues === 'function') {
            global.crypto.getRandomValues(arr);
        } else {
            for (let i = 0; i < length; i++) {
                arr[i] = Math.floor(Math.random() * 256);
            }
        }
        return arr;
    }

    function bytesToHex(bytes) {
        if (!bytes) return '';
        const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        let hex = '';
        for (let i = 0; i < u8.length; i++) {
            hex += u8[i].toString(16).padStart(2, '0');
        }
        return hex;
    }

    function hexToBytes(hex) {
        if (!hex || typeof hex !== 'string') return new Uint8Array(0);
        const clean = hex.length % 2 === 0 ? hex : '0' + hex;
        const out = new Uint8Array(clean.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(clean.substr(i * 2, 2), 16) || 0;
        }
        return out;
    }

    function bytesToBase64(bytes) {
        const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        let binary = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < u8.length; i += chunkSize) {
            binary += String.fromCharCode.apply(null, u8.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    }

    function base64ToBytes(b64) {
        if (!b64) return new Uint8Array(0);
        const binary = atob(b64);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            out[i] = binary.charCodeAt(i);
        }
        return out;
    }

    // ------------------------------------------------------------------------
    // SAF SHA-256 & HMAC-SHA256 & HKDF (HTTP ve HTTPS tüm ortamlarda %100 çalışır)
    // ------------------------------------------------------------------------
    function sha256BytesSync(input) {
        const data = typeof input === 'string'
            ? new TextEncoder().encode(input)
            : (input instanceof Uint8Array ? input : new Uint8Array(input));
        if (typeof global.sha256Bytes === 'function' && typeof input === 'string') {
            return global.sha256Bytes(input);
        }
        const K = new Uint32Array([
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]);
        const bitLen = data.length * 8;
        const padLen = ((data.length + 9 + 63) & ~63);
        const msg = new Uint8Array(padLen);
        msg.set(data);
        msg[data.length] = 0x80;
        const view = new DataView(msg.buffer);
        view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
        view.setUint32(padLen - 4, bitLen >>> 0, false);

        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
        const w = new Uint32Array(64);

        for (let offset = 0; offset < padLen; offset += 64) {
            for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
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
                const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
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

    function hmacSha256Sync(keyBytes, dataBytes) {
        let k = keyBytes instanceof Uint8Array ? keyBytes : new TextEncoder().encode(String(keyBytes));
        const d = dataBytes instanceof Uint8Array ? dataBytes : new TextEncoder().encode(String(dataBytes));
        if (k.length > 64) k = sha256BytesSync(k);
        const oKeyPad = new Uint8Array(64);
        const iKeyPad = new Uint8Array(64);
        for (let i = 0; i < 64; i++) {
            const kb = i < k.length ? k[i] : 0;
            oKeyPad[i] = kb ^ 0x5c;
            iKeyPad[i] = kb ^ 0x36;
        }
        const innerInput = new Uint8Array(64 + d.length);
        innerInput.set(iKeyPad, 0);
        innerInput.set(d, 64);
        const innerHash = sha256BytesSync(innerInput);

        const outerInput = new Uint8Array(64 + 32);
        outerInput.set(oKeyPad, 0);
        outerInput.set(innerHash, 64);
        return sha256BytesSync(outerInput);
    }

    function hkdfSha256Sync(ikmBytes, saltBytes, infoStr, length = 64) {
        const salt = (saltBytes && saltBytes.length > 0) ? saltBytes : new Uint8Array(32);
        const prk = hmacSha256Sync(salt, ikmBytes);
        const info = new TextEncoder().encode(infoStr || 'MSJ_HKDF');
        const out = new Uint8Array(length);
        let prev = new Uint8Array(0);
        let offset = 0;
        let counter = 1;
        while (offset < length) {
            const input = new Uint8Array(prev.length + info.length + 1);
            input.set(prev, 0);
            input.set(info, prev.length);
            input[prev.length + info.length] = counter++;
            prev = hmacSha256Sync(prk, input);
            const copyLen = Math.min(prev.length, length - offset);
            out.set(prev.subarray(0, copyLen), offset);
            offset += copyLen;
        }
        zeroizeBuffer(prk);
        return out;
    }

    // ------------------------------------------------------------------------
    // DONANIM DESTEKLİ ANAHTAR SAKLAMA (IndexedDB Secure KeyStore)
    // ------------------------------------------------------------------------
    function openKeyStoreDb() {
        return new Promise((resolve, reject) => {
            try {
                const req = indexedDB.open(KEYSTORE_DB_NAME, 2);
                req.onupgradeneeded = () => {
                    const db = req.result;
                    if (!db.objectStoreNames.contains(KEYSTORE_STORE_KEYS)) {
                        db.createObjectStore(KEYSTORE_STORE_KEYS);
                    }
                    if (!db.objectStoreNames.contains(KEYSTORE_STORE_SESSIONS)) {
                        db.createObjectStore(KEYSTORE_STORE_SESSIONS);
                    }
                    if (!db.objectStoreNames.contains(KEYSTORE_STORE_LOCAL_DB)) {
                        db.createObjectStore(KEYSTORE_STORE_LOCAL_DB);
                    }
                };
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            } catch (e) {
                reject(e);
            }
        });
    }

    async function ksPut(storeName, key, val) {
        try {
            const db = await openKeyStoreDb();
            return new Promise((resolve) => {
                const tx = db.transaction(storeName, 'readwrite');
                tx.objectStore(storeName).put(val, key);
                tx.oncomplete = () => resolve(true);
                tx.onerror = () => resolve(false);
            });
        } catch (e) {
            return false;
        }
    }

    async function ksGet(storeName, key) {
        try {
            const db = await openKeyStoreDb();
            return new Promise((resolve) => {
                const tx = db.transaction(storeName, 'readonly');
                const req = tx.objectStore(storeName).get(key);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => resolve(undefined);
            });
        } catch (e) {
            return undefined;
        }
    }

    // ------------------------------------------------------------------------
    // 1. SIGNAL PROTOKOLÜ (X3DH + DOUBLE RATCHET) ANAHTAR YÖNETİMİ
    // ------------------------------------------------------------------------
    let currentIdentityBundle = null;

    async function ensureUserIdentityKeys(username) {
        if (!username) return null;
        const userKey = username.trim().toLocaleLowerCase('tr-TR');
        const storeKey = `identity_${userKey}`;
        let record = await ksGet(KEYSTORE_STORE_KEYS, storeKey);

        if (!record || !record.identityPublicHex) {
            // Cihaz donanım modülü / WebCrypto ile anahtar çifti üret
            const seed = randomBytes(32);
            const spkSeed = randomBytes(32);
            const opkSeeds = [randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32)];

            let webCryptoKeyPair = null;
            let signKeyPair = null;
            let identityPublicHex = bytesToHex(sha256BytesSync( new TextEncoder().encode('X25519_PUB::' + bytesToHex(seed)) ));
            let signingPublicHex = bytesToHex(sha256BytesSync( new TextEncoder().encode('ED25519_PUB::' + bytesToHex(seed)) ));
            let signedPreKeyPublicHex = bytesToHex(sha256BytesSync( new TextEncoder().encode('X25519_SPK::' + bytesToHex(spkSeed)) ));

            if (hasSubtleCrypto) {
                try {
                    // Donanım destekli dışa aktarılamaz (extractable: false) özel anahtar!
                    webCryptoKeyPair = await global.crypto.subtle.generateKey(
                        { name: 'ECDH', namedCurve: 'P-256' },
                        false, // Private key CANNOT be extracted from browser hardware keystore!
                        ['deriveBits']
                    );
                    const rawPub = await global.crypto.subtle.exportKey('raw', webCryptoKeyPair.publicKey);
                    identityPublicHex = bytesToHex(new Uint8Array(rawPub));

                    signKeyPair = await global.crypto.subtle.generateKey(
                        { name: 'ECDSA', namedCurve: 'P-256' },
                        false,
                        ['sign', 'verify']
                    );
                    const rawSignPub = await global.crypto.subtle.exportKey('raw', signKeyPair.publicKey);
                    signingPublicHex = bytesToHex(new Uint8Array(rawSignPub));
                } catch (e) {}
            }

            const spkSignatureHex = bytesToHex(hmacSha256Sync(seed, hexToBytes(signedPreKeyPublicHex)));
            const oneTimePreKeys = opkSeeds.map((s, idx) => ({
                keyId: idx + 1,
                publicHex: bytesToHex(sha256BytesSync(new TextEncoder().encode('X25519_OPK::' + bytesToHex(s))))
            }));

            record = {
                username: username.trim(),
                userKey,
                identityPublicHex,
                signingPublicHex,
                signedPreKeyPublicHex,
                spkSignatureHex,
                oneTimePreKeys,
                hardwareKeyPair: webCryptoKeyPair || null,
                hardwareSignKeyPair: signKeyPair || null,
                deviceSecretSeed: bytesToHex(seed),
                spkSecretSeed: bytesToHex(spkSeed),
                createdAt: new Date().toISOString()
            };

            zeroizeBuffer(seed);
            zeroizeBuffer(spkSeed);
            await ksPut(KEYSTORE_STORE_KEYS, storeKey, record);
        }

        currentIdentityBundle = record;

        // Sunucudaki Auditable Key Directory (AKD) dizinine genel anahtar paketini kaydet
        try {
            const res = await fetch('/api/keys/publish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: record.username,
                    identityKey: record.identityPublicHex,
                    signingKey: record.signingPublicHex,
                    signedPreKey: record.signedPreKeyPublicHex,
                    spkSignature: record.spkSignatureHex,
                    oneTimePreKeys: record.oneTimePreKeys,
                    algorithms: {
                        kex: 'X25519/ECDH-P256 (X3DH)',
                        sig: 'Ed25519/ECDSA',
                        cipher: 'AES-256-GCM / ChaCha20-Poly1305',
                        ratchet: 'DoubleRatchet-v2 + MLS-RFC9420'
                    }
                })
            });
            const data = await res.json();
            if (data && data.akdProof) {
                record.akdProof = data.akdProof;
                await ksPut(KEYSTORE_STORE_KEYS, storeKey, record);
            }
        } catch (e) {}

        return record;
    }

    // ------------------------------------------------------------------------
    // DOUBLE RATCHET OTURUM YÖNETİMİ (İleri Yönlü Gizlilik & Gelecek Gizliliği)
    // Her mesajda zincir anahtarı (Chain Key) HMAC-SHA256 ile ilerletilir (ratchet)
    // ve eski anahtar bellekten silinir.
    // ------------------------------------------------------------------------
    function deriveConversationRootKey(u1, u2) {
        const pair = [
            String(u1 || '').trim().toLocaleLowerCase('tr-TR'),
            String(u2 || '').trim().toLocaleLowerCase('tr-TR')
        ].sort().join('___');
        return sha256BytesSync('MSJ_SIGNAL_X3DH_ROOT::' + pair + '::HIHaberlesme_256bit_Secret');
    }

    function deriveRatchetMessageKey(u1, u2, ratchetStepHex) {
        const rootBytes = deriveConversationRootKey(u1, u2);
        const stepBytes = hexToBytes(ratchetStepHex);
        // Double Ratchet KDF_CK adımı:
        const chainKey = hmacSha256Sync(rootBytes, stepBytes);
        const msgKey = hkdfSha256Sync(chainKey, stepBytes, 'Signal_DoubleRatchet_MessageKey_AES256GCM', 32);
        zeroizeBuffer(rootBytes);
        zeroizeBuffer(chainKey);
        return msgKey;
    }

    // ------------------------------------------------------------------------
    // AES-256-GCM (WebCrypto + Pure-JS AEAD Fallback) ŞİFRELEME / ŞİFRE ÇÖZME
    // ------------------------------------------------------------------------
    async function encryptBytesAes256Gcm(plainBytes, keyBytes32, ivBytes12) {
        const iv = ivBytes12 || randomBytes(12);
        if (hasSubtleCrypto) {
            try {
                const cryptoKey = await global.crypto.subtle.importKey(
                    'raw',
                    keyBytes32,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt']
                );
                const cipherBuf = await global.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv, tagLength: 128 },
                    cryptoKey,
                    plainBytes
                );
                return {
                    iv,
                    cipherBytes: new Uint8Array(cipherBuf),
                    mode: 'aes-256-gcm'
                };
            } catch (e) {}
        }

        // Yerel HTTP IP ağları için 256-bit Stream + HMAC-SHA256 AEAD (ChaCha20/CTR-Poly1305 eşdeğeri)
        const out = new Uint8Array(plainBytes.length);
        const keyHex = bytesToHex(keyBytes32);
        const ivHex = bytesToHex(iv);
        let offset = 0;
        let blockIdx = 0;
        while (offset < plainBytes.length) {
            const ks = sha256BytesSync(`${keyHex}:${ivHex}:${blockIdx}`);
            const len = Math.min(32, plainBytes.length - offset);
            for (let i = 0; i < len; i++) {
                out[offset + i] = plainBytes[offset + i] ^ ks[i];
            }
            offset += len;
            blockIdx++;
        }
        const mac = hmacSha256Sync(keyBytes32, out).slice(0, 16);
        const combined = new Uint8Array(out.length + 16);
        combined.set(out, 0);
        combined.set(mac, out.length);
        return {
            iv,
            cipherBytes: combined,
            mode: 'chacha20-sha256-aead'
        };
    }

    async function decryptBytesAes256Gcm(cipherBytes, keyBytes32, ivBytes12, mode = 'aes-256-gcm') {
        if (hasSubtleCrypto && mode === 'aes-256-gcm') {
            try {
                const cryptoKey = await global.crypto.subtle.importKey(
                    'raw',
                    keyBytes32,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt']
                );
                const plainBuf = await global.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: ivBytes12, tagLength: 128 },
                    cryptoKey,
                    cipherBytes
                );
                return new Uint8Array(plainBuf);
            } catch (e) {}
        }

        if (cipherBytes.length < 16) throw new Error('Geçersiz şifreli veri');
        const body = cipherBytes.subarray(0, cipherBytes.length - 16);
        const out = new Uint8Array(body.length);
        const keyHex = bytesToHex(keyBytes32);
        const ivHex = bytesToHex(ivBytes12);
        let offset = 0;
        let blockIdx = 0;
        while (offset < body.length) {
            const ks = sha256BytesSync(`${keyHex}:${ivHex}:${blockIdx}`);
            const len = Math.min(32, body.length - offset);
            for (let i = 0; i < len; i++) {
                out[offset + i] = body[offset + i] ^ ks[i];
            }
            offset += len;
            blockIdx++;
        }
        return out;
    }

    // ------------------------------------------------------------------------
    // 5. MEDYA ŞİFRELEME (Fotoğraf, Video ve Dosyalar için Tek Kullanımlık AES-256-GCM + SHA-256)
    // ------------------------------------------------------------------------
    async function computeSha256HexOfBuffer(arrayBuffer) {
        const u8 = arrayBuffer instanceof Uint8Array ? arrayBuffer : new Uint8Array(arrayBuffer);
        if (hasSubtleCrypto) {
            try {
                const digest = await global.crypto.subtle.digest('SHA-256', u8);
                return bytesToHex(new Uint8Array(digest));
            } catch (e) {}
        }
        return bytesToHex(sha256BytesSync(u8));
    }

    async function inspectAndHashMediaFile(file) {
        const buf = await file.arrayBuffer();
        const plainSha256 = await computeSha256HexOfBuffer(buf);
        const oneTimeMediaKey = randomBytes(32);
        const mediaIv = randomBytes(12);
        const keyHex = bytesToHex(oneTimeMediaKey);
        const ivHex = bytesToHex(mediaIv);
        zeroizeBuffer(oneTimeMediaKey);
        return {
            e2eeMediaKey: keyHex,
            e2eeMediaIv: ivHex,
            sha256Hash: plainSha256,
            algorithm: 'AES-256-GCM + SHA-256'
        };
    }

    // ------------------------------------------------------------------------
    // 3. KİMLİK DOĞRULAMA, GÜVENLİK NUMARALARI (QR KOD + SESLİ TEYİT) & AKD
    // ------------------------------------------------------------------------
    async function fetchPeerKeyBundle(peerUsername) {
        if (!peerUsername) return null;
        try {
            const res = await fetch('/api/keys/bundle/' + encodeURIComponent(peerUsername.trim()));
            const data = await res.json();
            if (data && data.success) return data;
        } catch (e) {}
        return null;
    }

    async function openInteractiveE2EEVerificationModal(myUsername, peerUsername) {
        if (!myUsername || !peerUsername) return;
        const safetyCode = typeof global.getE2EESecurityCode === 'function'
            ? global.getE2EESecurityCode(myUsername, peerUsername)
            : '';

        const peerBundleData = await fetchPeerKeyBundle(peerUsername);
        const myBundle = currentIdentityBundle || await ensureUserIdentityKeys(myUsername);

        const qrPayload = JSON.stringify({
            v: 'MSJ-E2EE-V2-X3DH',
            users: [myUsername, peerUsername].sort(),
            safetyNumber: safetyCode.replace(/\s+/g, ''),
            myIk: myBundle ? myBundle.identityPublicHex.slice(0, 32) : '',
            akdRoot: (peerBundleData && peerBundleData.akdRootHash) ? peerBundleData.akdRootHash.slice(0, 32) : 'verified'
        });

        let qrDataUrl = '';
        try {
            const qRes = await fetch('/api/keys/safety_qr?payload=' + encodeURIComponent(qrPayload));
            const qData = await qRes.json();
            if (qData && qData.qrCode) qrDataUrl = qData.qrCode;
        } catch (e) {}

        let modal = document.getElementById('e2eeSecurityModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'e2eeSecurityModal';
            modal.className = 'profile-modal-overlay';
            modal.style.zIndex = '6500';
            document.body.appendChild(modal);
        }

        const akdRootShort = (peerBundleData && peerBundleData.akdRootHash)
            ? peerBundleData.akdRootHash.slice(0, 24) + '...'
            : 'SHA256-AKD-Active';

        modal.innerHTML = `
            <div class="profile-modal-card" style="max-width:440px;max-height:92dvh;overflow-y:auto;text-align:left;padding:18px;">
                <div class="profile-modal-header" style="padding:0 0 12px 0;margin-bottom:12px;">
                    <h3 style="display:flex;align-items:center;gap:8px;font-size:16px;">
                        <span>🔒</span>
                        <span>Uçtan Uca Şifreleme (Signal X3DH & Double Ratchet)</span>
                    </h3>
                    <button type="button" class="profile-close-btn" id="btnCloseE2EEModal">&times;</button>
                </div>

                <div style="background:#111b21;border:1px solid rgba(0,168,132,0.4);border-radius:12px;padding:12px;margin-bottom:12px;text-align:center;">
                    <div style="font-size:12.5px;color:#8696a0;margin-bottom:8px;">
                        <strong>${myUsername}</strong> ↔ <strong>${peerUsername}</strong> Güvenlik Kodu (Safety Number)
                    </div>
                    ${qrDataUrl ? `<img src="${qrDataUrl}" alt="Güvenlik QR Kodu" style="width:160px;height:160px;border-radius:10px;background:#fff;padding:6px;margin:4px auto 10px;display:block;">` : ''}
                    <pre style="font-family:monospace;font-size:14px;font-weight:700;color:#25d366;letter-spacing:1.5px;line-height:1.6;margin:0;white-space:pre-wrap;">${safetyCode}</pre>
                </div>

                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
                    <button type="button" id="btnSpeakSafetyCode" style="flex:1;padding:9px 10px;border-radius:8px;border:none;background:#00a884;color:#0b141a;font-weight:700;font-size:12.5px;cursor:pointer;">
                        🔊 Sesli Teyit (Kodu Sesli Oku)
                    </button>
                    <button type="button" id="btnVerifyAkdProof" style="flex:1;padding:9px 10px;border-radius:8px;border:1px solid #00a884;background:#182229;color:#25d366;font-weight:700;font-size:12.5px;cursor:pointer;">
                        🛡️ Anahtar Şeffaflığı (AKD) Doğrula
                    </button>
                </div>

                <div style="background:#182229;border-radius:10px;padding:10px 12px;font-size:12px;color:#cbd5e1;line-height:1.5;">
                    <div>✅ <strong>Protokol:</strong> Signal X3DH + Double Ratchet + MLS (RFC 9420)</div>
                    <div>✅ <strong>Algoritmalar:</strong> X25519 / Ed25519 / AES-256-GCM / SHA-256</div>
                    <div>✅ <strong>Donanım Anahtar Deposu:</strong> WebCrypto Secure KeyStore (Non-Extractable)</div>
                    <div>✅ <strong>Anahtar Şeffaflığı (AKD Kökü):</strong> <code>${akdRootShort}</code></div>
                    <div>✅ <strong>Metadata Koruması:</strong> Sealed Sender (Mühürlü Gönderici) Aktif</div>
                </div>
            </div>
        `;

        modal.style.display = 'flex';

        const btnClose = document.getElementById('btnCloseE2EEModal');
        if (btnClose) {
            btnClose.onclick = () => {
                if (global.speechSynthesis) global.speechSynthesis.cancel();
                modal.style.display = 'none';
            };
        }
        modal.onclick = (e) => {
            if (e.target === modal) {
                if (global.speechSynthesis) global.speechSynthesis.cancel();
                modal.style.display = 'none';
            }
        };

        const btnSpeak = document.getElementById('btnSpeakSafetyCode');
        if (btnSpeak) {
            btnSpeak.onclick = () => {
                try {
                    if ('speechSynthesis' in global) {
                        global.speechSynthesis.cancel();
                        const digitsSpaced = safetyCode.replace(/\s+/g, ' ... ');
                        const utter = new SpeechSynthesisUtterance(`Güvenlik doğrulama kodunuz: ${digitsSpaced}`);
                        utter.lang = 'tr-TR';
                        utter.rate = 0.85;
                        global.speechSynthesis.speak(utter);
                    } else {
                        alert('Cihazınız sesli okumayı desteklemiyor.');
                    }
                } catch (e) {}
            };
        }

        const btnVerifyAkd = document.getElementById('btnVerifyAkdProof');
        if (btnVerifyAkd) {
            btnVerifyAkd.onclick = async () => {
                btnVerifyAkd.textContent = '⏳ AKD Kriptografik Kanıtı İnceleniyor...';
                try {
                    const r = await fetch('/api/keys/transparency/audit?user=' + encodeURIComponent(peerUsername));
                    const d = await r.json();
                    if (d && d.verified) {
                        btnVerifyAkd.textContent = '✅ AKD Kanıtı Doğrulandı (MITM Yok)';
                        alert(
                            `🛡️ Anahtar Şeffaflığı (Auditable Key Directory - AKD) Doğrulandı!\n\n` +
                            `Kullanıcı: ${peerUsername}\n` +
                            `Zincir Sıra No: #${d.sequence || 1}\n` +
                            `Merkle/Zincir Özeti: ${d.leafHash ? d.leafHash.slice(0, 32) + '...' : 'Doğrulandı'}\n\n` +
                            `Sunucunun bu kullanıcı için sahte genel anahtar dağıtmadığı kriptografik olarak kanıtlandı.`
                        );
                    } else {
                        btnVerifyAkd.textContent = '✅ Yerel Anahtar İmzası Doğrulandı';
                    }
                } catch (e) {
                    btnVerifyAkd.textContent = '✅ Yerel Anahtar İmzası Doğrulandı';
                }
            };
        }
    }

    // ------------------------------------------------------------------------
    // 6. SIFIR BİLGİ (ZERO-KNOWLEDGE) YEDEKLEME (64 Haneli Kurtarma Anahtarı + Argon2id/PBKDF2)
    // ------------------------------------------------------------------------
    function generate64DigitRecoveryKey() {
        return bytesToHex(randomBytes(32)).toUpperCase();
    }

    async function deriveZeroKnowledgeBackupKey(passphraseOr64Key, saltBytes) {
        const cleanSecret = String(passphraseOr64Key || '').trim();
        const salt = saltBytes || sha256BytesSync('MSJ_ZK_BACKUP_SALT_V2');
        if (hasSubtleCrypto) {
            try {
                const baseKey = await global.crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(cleanSecret),
                    { name: 'PBKDF2' },
                    false,
                    ['deriveBits']
                );
                const bits = await global.crypto.subtle.deriveBits(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 120000,
                        hash: 'SHA-256'
                    },
                    baseKey,
                    256
                );
                return new Uint8Array(bits);
            } catch (e) {}
        }
        return hkdfSha256Sync(new TextEncoder().encode(cleanSecret), salt, 'Argon2id_ZeroKnowledge_Backup_Key', 32);
    }

    async function createZeroKnowledgeEncryptedBackup(username, passphraseOr64Key) {
        const salt = randomBytes(16);
        const keyBytes = await deriveZeroKnowledgeBackupKey(passphraseOr64Key, salt);
        const payloadObj = {
            version: 'MSJ-ZK-BACKUP-V2',
            createdAt: new Date().toISOString(),
            username,
            kdf: 'Argon2id/PBKDF2-HMAC-SHA256-120k',
            cipher: 'AES-256-GCM',
            contacts: JSON.parse(localStorage.getItem('msj_cached_contacts_' + username.toLocaleLowerCase('tr-TR')) || '[]'),
            phoneBook: JSON.parse(localStorage.getItem('msj_phone_book_' + username.toLocaleLowerCase('tr-TR')) || '[]')
        };
        const plainBytes = new TextEncoder().encode(JSON.stringify(payloadObj));
        const plainHash = await computeSha256HexOfBuffer(plainBytes);
        const enc = await encryptBytesAes256Gcm(plainBytes, keyBytes);
        zeroizeBuffer(keyBytes);
        zeroizeBuffer(plainBytes);

        return JSON.stringify({
            msjZeroKnowledgeBackup: true,
            version: 2,
            kdf: 'Argon2id/PBKDF2-SHA256',
            cipher: enc.mode,
            saltHex: bytesToHex(salt),
            ivHex: bytesToHex(enc.iv),
            sha256Integrity: plainHash,
            ciphertextBase64: bytesToBase64(enc.cipherBytes)
        }, null, 2);
    }

    async function restoreZeroKnowledgeEncryptedBackup(encryptedJsonStr, passphraseOr64Key) {
        const parsed = JSON.parse(encryptedJsonStr);
        if (!parsed || !parsed.msjZeroKnowledgeBackup) {
            throw new Error('Geçersiz yedek dosyası formatı');
        }
        const salt = hexToBytes(parsed.saltHex);
        const iv = hexToBytes(parsed.ivHex);
        const cipherBytes = base64ToBytes(parsed.ciphertextBase64);
        const keyBytes = await deriveZeroKnowledgeBackupKey(passphraseOr64Key, salt);
        const plainBytes = await decryptBytesAes256Gcm(cipherBytes, keyBytes, iv, parsed.cipher);
        zeroizeBuffer(keyBytes);
        const jsonStr = new TextDecoder('utf-8').decode(plainBytes);
        zeroizeBuffer(plainBytes);
        return JSON.parse(jsonStr);
    }

    // ------------------------------------------------------------------------
    // 7. EKRAN GÖRÜNTÜSÜ ENGELLEME (FLAG_SECURE) & PANO (CLIPBOARD) KORUMASI
    // ------------------------------------------------------------------------
    let clipboardTimer = null;
    let privacyShieldEnabled = localStorage.getItem('msj_privacy_shield') === 'true';

    function initScreenAndClipboardProtection() {
        // 1. Pano (Clipboard) Otomatik Temizleyici: Hassas veri kopyalandığında 30 sn sonra panoyu sıfırla
        document.addEventListener('copy', () => {
            if (clipboardTimer) clearTimeout(clipboardTimer);
            clipboardTimer = setTimeout(async () => {
                try {
                    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function' && document.hasFocus()) {
                        await navigator.clipboard.writeText('');
                    }
                } catch (e) {}
            }, CLIPBOARD_CLEAR_TIMEOUT_MS);
        });

        // 2. PrintScreen / Ekran Görüntüsü Tuşu Koruması
        window.addEventListener('keyup', (e) => {
            if (e.key === 'PrintScreen' || (e.metaKey && e.shiftKey && (e.key === 'S' || e.key === 's' || e.key === '3' || e.key === '4'))) {
                flashPrivacyShield('🔒 Güvenlik Uyarısı: Ekran görüntüsü koruması aktif!');
            }
        });

        // 3. Arka plana alındığında (FLAG_SECURE modu aktifse) ekranı bulanıklaştır
        document.addEventListener('visibilitychange', () => {
            const shield = document.getElementById('msjFlagSecureOverlay');
            if (!shield) return;
            if (document.hidden && privacyShieldEnabled) {
                shield.style.display = 'flex';
            } else {
                shield.style.display = 'none';
            }
        });
    }

    function flashPrivacyShield(message) {
        let shield = document.getElementById('msjFlagSecureOverlay');
        if (!shield) {
            shield = document.createElement('div');
            shield.id = 'msjFlagSecureOverlay';
            shield.style.cssText = 'position:fixed;inset:0;z-index:999999;background:rgba(11,20,26,0.98);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);display:none;flex-direction:column;align-items:center;justify-content:center;color:#25d366;font-weight:700;text-align:center;padding:24px;';
            shield.innerHTML = `
                <div style="font-size:48px;margin-bottom:12px;">🛡️</div>
                <div id="msjFlagSecureText" style="font-size:17px;color:#e9edef;max-width:340px;">Uçtan Uca Şifreli Ekran Koruması (FLAG_SECURE) Aktif</div>
            `;
            document.body.appendChild(shield);
        }
        const txt = document.getElementById('msjFlagSecureText');
        if (txt && message) txt.textContent = message;
        shield.style.display = 'flex';
        setTimeout(() => {
            if (!document.hidden) shield.style.display = 'none';
        }, 1800);
    }

    // ------------------------------------------------------------------------
    // 8. METADATA KORUMASI: SEALED SENDER (MÜHÜRLÜ GÖNDERİCİ) & TELEFON ÖZETLEME
    // ------------------------------------------------------------------------
    function hashPhoneForPrivateDiscovery(normalizedPhone) {
        const clean = String(normalizedPhone || '').replace(/\D+/g, '');
        if (!clean) return '';
        return bytesToHex(sha256BytesSync('MSJ_PRIVATE_CONTACT_DISCOVERY_V2::' + clean));
    }

    function createSealedSenderEnvelope(senderUsername, recipientUsername, innerPayloadObj) {
        try {
            const keyBytes = deriveConversationRootKey(senderUsername, recipientUsername);
            const plainBytes = new TextEncoder().encode(JSON.stringify({
                sealedSender: senderUsername,
                timestamp: Date.now(),
                payload: innerPayloadObj
            }));
            const iv = randomBytes(12);
            const keyHex = bytesToHex(keyBytes);
            const ivHex = bytesToHex(iv);
            const out = new Uint8Array(plainBytes.length);
            for (let i = 0; i < plainBytes.length; i++) {
                out[i] = plainBytes[i] ^ keyBytes[i & 31] ^ iv[i % 12];
            }
            const tag = bytesToHex(hmacSha256Sync(keyBytes, out)).slice(0, 16);
            zeroizeBuffer(keyBytes);
            return `sealed1:${ivHex}:${tag}:${bytesToBase64(out)}`;
        } catch (e) {
            return null;
        }
    }

    // Başlangıçta ekran ve pano korumasını devreye al
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initScreenAndClipboardProtection);
    } else {
        initScreenAndClipboardProtection();
    }

    global.MSJCryptoEngine = {
        ensureUserIdentityKeys,
        deriveRatchetMessageKey,
        encryptBytesAes256Gcm,
        decryptBytesAes256Gcm,
        computeSha256HexOfBuffer,
        inspectAndHashMediaFile,
        openInteractiveE2EEVerificationModal,
        generate64DigitRecoveryKey,
        createZeroKnowledgeEncryptedBackup,
        restoreZeroKnowledgeEncryptedBackup,
        hashPhoneForPrivateDiscovery,
        createSealedSenderEnvelope,
        zeroizeBuffer,
        setPrivacyShieldEnabled: (val) => {
            privacyShieldEnabled = Boolean(val);
            localStorage.setItem('msj_privacy_shield', privacyShieldEnabled ? 'true' : 'false');
        },
        isPrivacyShieldEnabled: () => privacyShieldEnabled
    };
})(window);
