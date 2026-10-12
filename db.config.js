const path = require('path');

// Ortam değişkenlerinden veya DATABASE_URL'den MySQL yapılandırması
let mysqlConfig = {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT) : 3306,
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'msj_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: (process.env.MYSQL_SSL === 'true' || process.env.DB_SSL === 'true') ? { rejectUnauthorized: false } : undefined
};

// Cloud Database URL desteği (Render, Railway, TiDB Cloud, Aiven, Supabase vb.)
const dbUrl = process.env.DATABASE_URL || process.env.MYSQL_URL;
let detectedType = process.env.DB_TYPE;

if (dbUrl) {
    try {
        const parsed = new URL(dbUrl);
        if (parsed.protocol.startsWith('mysql')) {
            mysqlConfig.host = parsed.hostname;
            mysqlConfig.port = parsed.port ? parseInt(parsed.port) : 3306;
            mysqlConfig.user = decodeURIComponent(parsed.username);
            mysqlConfig.password = decodeURIComponent(parsed.password);
            mysqlConfig.database = parsed.pathname.replace(/^\//, '');
            if (!detectedType) detectedType = 'mysql';
        }
    } catch (e) {
        console.error('[db.config] DATABASE_URL ayrıştırılamadı:', e.message);
    }
}

module.exports = {
    // Aktif Veritabanı Türü: 'sqlite' veya 'mysql'
    // Varsayılan olarak Lite SQL (SQLite) kullanılır.
    // Eğer MYSQL_HOST veya DATABASE_URL tanımlıysa otomatik 'mysql' olur.
    type: detectedType || (process.env.MYSQL_HOST ? 'mysql' : 'sqlite'),

    // ==========================================
    // 1. LITE SQL (SQLITE) AYARLARI
    // ==========================================
    sqlite: {
        filename: process.env.SQLITE_PATH || path.join(__dirname, 'data', 'msj.sqlite')
    },

    // ==========================================
    // 2. MYSQL AYARLARI (Bulut / Uzak Sunucu Desteği)
    // ==========================================
    mysql: mysqlConfig
};
