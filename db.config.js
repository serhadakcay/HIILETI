const path = require('path');
const fs = require('fs');

// 0. Yerel .env dosyası varsa ortam değişkenlerini yükle
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
    try {
        const envContent = fs.readFileSync(envPath, 'utf8');
        envContent.split(/\r?\n/).forEach(line => {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const eqIdx = trimmed.indexOf('=');
                if (eqIdx > 0) {
                    const key = trimmed.substring(0, eqIdx).trim();
                    let val = trimmed.substring(eqIdx + 1).trim();
                    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                        val = val.slice(1, -1);
                    }
                    if (key && !process.env[key]) {
                        process.env[key] = val;
                    }
                }
            }
        });
    } catch (e) {}
}

// 1. MySQL Ayar Şablonu
let mysqlConfig = {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT) : 3306,
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: process.env.MYSQL_DATABASE || 'msj_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: (process.env.MYSQL_SSL === 'true' || process.env.DB_SSL === 'true') ? { rejectUnauthorized: true } : undefined
};

// 2. Cloud Database URL Desteği (TiDB Cloud, Render, Railway, Aiven, Supabase vb.)
const dbUrl = process.env.DATABASE_URL || process.env.TIDB_URL || process.env.MYSQL_URL;
let detectedType = process.env.DB_TYPE;

if (dbUrl) {
    try {
        const parsed = new URL(dbUrl);
        if (parsed.protocol.startsWith('mysql')) {
            mysqlConfig.host = parsed.hostname;
            mysqlConfig.port = parsed.port ? parseInt(parsed.port) : 3306;
            mysqlConfig.user = decodeURIComponent(parsed.username);
            mysqlConfig.password = decodeURIComponent(parsed.password);
            mysqlConfig.database = parsed.pathname.replace(/^\//, '') || 'test';
            if (!detectedType) detectedType = 'mysql';

            // TiDB Cloud ve uzaktaki bulut sunucuları SSL (TLS) şifrelemesi şart koşar
            const isRemote = !['localhost', '127.0.0.1'].includes(parsed.hostname);
            if (isRemote || parsed.hostname.includes('tidbcloud.com') || parsed.searchParams.get('ssl')) {
                mysqlConfig.ssl = {
                    minVersion: 'TLSv1.2',
                    rejectUnauthorized: true
                };
            }
        }
    } catch (e) {
        console.error('[db.config] DATABASE_URL ayrıştırılamadı:', e.message);
    }
}

// TiDB Cloud ortam değişkenleri tek tek girildiyse (host, user, pass):
if (mysqlConfig.host && (mysqlConfig.host.includes('tidbcloud.com') || (mysqlConfig.port === 4000))) {
    if (!mysqlConfig.ssl) {
        mysqlConfig.ssl = {
            minVersion: 'TLSv1.2',
            rejectUnauthorized: true
        };
    }
    if (!detectedType) detectedType = 'mysql';
}

module.exports = {
    // Aktif Veritabanı Türü: 'sqlite' veya 'mysql'
    // DATABASE_URL veya MYSQL_HOST varsa otomatik 'mysql' olur.
    type: detectedType || (process.env.MYSQL_HOST ? 'mysql' : 'sqlite'),

    // ==========================================
    // 1. LITE SQL (SQLITE) AYARLARI
    // ==========================================
    sqlite: {
        filename: process.env.SQLITE_PATH || path.join(__dirname, 'data', 'msj.sqlite')
    },

    // ==========================================
    // 2. MYSQL / TIDB CLOUD AYARLARI
    // ==========================================
    mysql: mysqlConfig
};
