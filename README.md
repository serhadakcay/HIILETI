# MSJ - Güvenli Mesajlaşma, Dosya Paylaşımı ve WebRTC Arama

Bu proje; **WhatsApp, Signal ve Telegram** benzeri mimariyle geliştirilmiş, **Windows**, **Android** ve **iOS** cihazlarda çalışan tam teşekküllü bir anlık iletişim uygulamasıdır.

---

### Karşılanan 4 Temel Kriter:
1. **İşletim Sistemleri:** Windows (Masaüstü/Tarayıcı), Android (Chrome/PWA) ve iOS (Safari/PWA) üzerinde bağımsız bir uygulama gibi çalışır.
2. **Wi-Fi ve Hücresel Ağ:** Socket.IO teknolojisi ile Wi-Fi veya hücresel internet (4.5G/5G) üzerinden anlık mesaj iletir.
3. **Resim ve Belge Gönderimi:** Fotoğraflar (önizlemeli), PDF, Word, Excel, ZIP ve her türlü dokümanı 250 MB'a kadar gönderebilir, indirebilir ve panodan resim yapıştırabilirsiniz (`Ctrl+V`).
4. **İnternet Üzerinden Sesli ve Görüntülü Arama:** WebRTC protokolüyle cihazlar arasında uçtan uca doğrudan ses ve video görüşmesi yapabilir.

---

### Nasıl Başlatılır?

1. Masaüstündeki `MSJ` klasöründe bulunan **`start.bat`** dosyasına çift tıklayın (veya terminalden `node server.js` çalıştırın).
2. Sunucu açıldığında size iki bağlantı adresi sunar:
   * **HTTP:** `http://localhost:3000` veya `http://192.168.1.18:3000`
   * **HTTPS:** `https://localhost:3443` veya `https://192.168.1.18:3443` *(Telefonlardan kamera ve sesli arama için HTTPS gereklidir)*

---

### Cihazlardan Bağlantı ve Kurulum Rehberi

#### 1. Windows'ta Kullanım:
* Tarayıcınızda (Chrome veya Edge) `http://localhost:3000` adresini açın.
* İsminizi girin.
* İsterseniz adres çubuğunun sağındaki **"Uygulamayı Yükle"** simgesine tıklayarak Windows'a masaüstü uygulaması gibi kurabilirsiniz.

#### 2. Android Telefonda Kullanım:
* Telefonunuzun bilgisayarla **aynı Wi-Fi ağına** bağlı olduğundan emin olun.
* Bilgisayar ekranındaki **QR Kod** simgesine tıklayıp telefon kameranızla taratın veya doğrudan Chrome'a şu adresi yazın:
  `https://192.168.1.18:3443`
* İlk girişte yerel SSL sertifikası uyarısı çıkarsa: **Gelişmiş -> Siteye İlerle** deyin.
* Chrome menüsünden (sağ üstteki 3 nokta) **"Uygulamayı Yükle"** veya **"Ana Ekrana Ekle"** seçeneğini seçin. Artık telefonunuzda tıpkı WhatsApp gibi ayrı bir uygulama olarak yer alacaktır.

#### 3. iOS (iPhone / iPad) Kullanım:
* iPhone'unuzu aynı Wi-Fi ağına bağlayın.
* **Safari** tarayıcısını açıp `https://192.168.1.18:3443` yazın.
* Güvenlik uyarısında: **Gelişmiş -> Web Sitesini Ziyaret Et** butonuna dokunun.
* Safari'nin altındaki **Paylaş (kare ve yukarı ok)** butonuna basıp **"Ana Ekrana Ekle"** deyin.

---

### İnternet Üzerinden (Ev Dışından / Hücresel Veri ile) Bağlantı:
Uygulama şu anda ev/ofis Wi-Fi ağınızda çalışmaktadır. Eğer farklı şehirlerden veya 4G/5G mobil hat üzerinden herhangi bir yerden bağlanmak isterseniz:
1. Ücretsiz **Cloudflare Tunnel** (`cloudflared`) veya **ngrok** kullanarak anında global bir internet adresi (`https://xyz.trycloudflare.com`) alabilirsiniz.
2. Ya da bu klasörü **Render.com**, **Railway** veya herhangi bir VPS sunucusuna yükleyebilirsiniz.
