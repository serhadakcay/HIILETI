const path = require('path');

module.exports = {
    // Aktif Veritabanı Türü: 'sqlite' veya 'mysql'
    // Varsayılan olarak Lite SQL (SQLite) kullanılır.
    // İleride MySQL'e geçmek isterseniz bu değeri 'mysql' yapıp
    // aşağıdaki mysql ayarlarını doldurmanız yeterlidir.
    type: process.env.DB_TYPE || 'sqlite',

    // ==========================================
    // 1. LITE SQL (SQLITE) AYARLARI
    // ==========================================
    sqlite: {
        filename: process.env.SQLITE_PATH || path.join(__dirname, 'data', 'msj.sqlite')
    },

    // ==========================================
    // 2. MYSQL AYARLARI (GEÇİŞ İÇİN HAZIR)
    // ==========================================
    // MySQL geçişi için:
    // 1) Yukarıdaki type: 'mysql' yapın
    // 2) Aşağıdaki MySQL bağlantı bilgilerinizi girin
    mysql: {
        host: process.env.MYSQL_HOST || '127.0.0.1',
        port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT) : 3306,
        user: process.env.MYSQL_USER || 'root',
        password: process.env.MYSQL_PASSWORD || '',
        database: process.env.MYSQL_DATABASE || 'msj_db',
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    }
};
