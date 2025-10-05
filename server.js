const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const fetch = require('node-fetch');
const readline = require('readline');
const FormData = require('form-data');

const app = express();
const port = process.env.PORT || 3000;

// System untuk menangkal DOS (disederhanakan)
const dosProtection = {
    requests: new Map(),
    blocklist: new Set(),
    config: {
        maxRequestsPerMinute: 100, // Naikkan batas untuk development
        blockDuration: 5 * 60 * 1000, // Blokir 5 menit saja
        checkInterval: 30000 // Periksa setiap 30 detik
    }
};

// Middleware DOS Protection yang lebih ringan
app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    // Skip DOS protection untuk static files dan health check
    if (req.path === '/health' || req.path === '/favicon.ico' || req.path.includes('.')) {
        return next();
    }

    // Cek jika IP diblokir
    if (dosProtection.blocklist.has(clientIP)) {
        console.log(`🚫 Request diblokir dari IP: ${clientIP} - Path: ${req.path}`);
        
        // Untuk IP yang diblokir, tetap berikan response sederhana
        if (req.path === '/') {
            return res.send(`
                <html>
                    <head><title>Access Blocked</title></head>
                    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                        <h1>🚫 Access Temporarily Blocked</h1>
                        <p>Too many requests from your IP address. Please try again later.</p>
                        <p>IP: ${clientIP}</p>
                    </body>
                </html>
            `);
        } else {
            return res.status(429).json({
                error: 'Terlalu banyak request. Silakan coba lagi nanti.',
                blocked: true
            });
        }
    }

    // Tracking request hanya untuk API endpoints
    if (req.path.startsWith('/api/')) {
        if (!dosProtection.requests.has(clientIP)) {
            dosProtection.requests.set(clientIP, []);
        }

        const requests = dosProtection.requests.get(clientIP);
        requests.push(now);

        // Filter request dalam 1 menit terakhir
        const recentRequests = requests.filter(time => now - time < 60000);
        dosProtection.requests.set(clientIP, recentRequests);

        // Cek jika melebihi batas
        if (recentRequests.length > dosProtection.config.maxRequestsPerMinute) {
            console.log(`🚨 DOS terdeteksi dari IP: ${clientIP}, Request: ${recentRequests.length}`);
            dosProtection.blocklist.add(clientIP);
            
            // Hapus dari blocklist setelah waktu tertentu
            setTimeout(() => {
                dosProtection.blocklist.delete(clientIP);
                dosProtection.requests.delete(clientIP);
                console.log(`✅ IP ${clientIP} di-unblock`);
            }, dosProtection.config.blockDuration);

            // Tetap berikan response untuk halaman utama
            if (req.path === '/api/telegram' || req.path === '/api/send-message') {
                return res.status(429).json({
                    error: 'Terlalu banyak request. IP Anda diblokir sementara.',
                    blocked: true,
                    retryAfter: Math.floor(dosProtection.config.blockDuration / 1000)
                });
            }
        }
    }

    next();
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files dari directory public
app.use(express.static(path.join(__dirname, 'public')));

// Konfigurasi multer untuk file upload
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // Maksimal 10MB
    }
});

// Root route - arahkan ke public/index.html
app.get('/', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Cek jika IP diblokir
    if (dosProtection.blocklist.has(clientIP)) {
        console.log(`🚫 IP diblokir mengakses halaman utama: ${clientIP}`);
        return res.send(`
            <html>
                <head>
                    <title>Access Blocked</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f6fa; color: #2d3436; }
                        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        h1 { color: #e84393; }
                        .ip { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🚫 Access Temporarily Blocked</h1>
                        <p>Too many requests from your IP address. Please try again in a few minutes.</p>
                        <div class="ip">IP Address: ${clientIP}</div>
                        <p><small>If you believe this is an error, please contact the administrator.</small></p>
                    </div>
                </body>
            </html>
        `);
    }

    console.log(`📄 Melayani index.html dari public/ untuk IP: ${clientIP}`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Fallback route untuk SPA - arahkan semua route yang tidak dikenal ke index.html
app.get('*', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Skip untuk API routes
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint tidak ditemukan' });
    }
    
    // Skip untuk file static
    if (req.path.includes('.')) {
        return res.status(404).send('File tidak ditemukan');
    }
    
    // Cek jika IP diblokir
    if (dosProtection.blocklist.has(clientIP)) {
        console.log(`🚫 IP diblokir mengakses route: ${req.path}`);
        return res.send(`
            <html>
                <head><title>Access Blocked</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h1>🚫 Access Temporarily Blocked</h1>
                    <p>Too many requests from your IP address. Please try again later.</p>
                    <p>IP: ${clientIP}</p>
                </body>
            </html>
        `);
    }

    console.log(`🔄 Redirect route ${req.path} ke index.html untuk IP: ${clientIP}`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API endpoint untuk proxy request ke Telegram
app.post('/api/telegram', async (req, res) => {
    const { token, endpoint, method, params } = req.body;
    
    try {
        const telegramUrl = `https://api.telegram.org/bot${token}/${endpoint}`;
        
        const options = {
            method: method || 'GET',
            headers: {}
        };
        
        if (method === 'POST' && params) {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            options.body = new URLSearchParams(params).toString();
        }
        
        const response = await fetch(telegramUrl, options);
        const data = await response.json();
        
        console.log(`🤖 API Telegram: ${endpoint} - ${data.ok ? 'SUCCESS' : 'FAILED'}`);
        
        res.json(data);
    } catch (error) {
        console.error(`❌ Error API Telegram: ${error.message}`);
        res.status(500).json({
            ok: false,
            description: error.message
        });
    }
});

// Endpoint untuk mengirim pesan dengan file - FIXED
app.post('/api/send-message', upload.single('photo'), async (req, res) => {
    const { token, chatId, text } = req.body;
    const file = req.file;
    
    try {
        let telegramUrl;
        
        if (file && file.buffer) {
            // Jika ada foto, kirim sebagai photo menggunakan FormData
            telegramUrl = `https://api.telegram.org/bot${token}/sendPhoto`;
            
            const formData = new FormData();
            formData.append('chat_id', chatId);
            formData.append('caption', text || '');
            
            // Append file buffer dengan nama file yang benar
            formData.append('photo', file.buffer, {
                filename: file.originalname || 'photo.jpg',
                contentType: file.mimetype || 'image/jpeg'
            });
            
            const response = await fetch(telegramUrl, {
                method: 'POST',
                body: formData,
                headers: formData.getHeaders()
            });
            
            const data = await response.json();
            
            if (data.ok) {
                console.log(`📨 Foto terkirim ke: ${chatId}`);
            } else {
                console.log(`❌ Gagal kirim foto ke: ${chatId} - ${data.description}`);
            }
            
            res.json(data);
            
        } else {
            // Jika tidak ada foto, kirim sebagai text message
            telegramUrl = `https://api.telegram.org/bot${token}/sendMessage`;
            
            const params = new URLSearchParams();
            params.append('chat_id', chatId);
            params.append('text', text || 'Test message');
            
            const response = await fetch(telegramUrl, {
                method: 'POST',
                body: params,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });
            
            const data = await response.json();
            
            if (data.ok) {
                console.log(`📨 Teks terkirim ke: ${chatId}`);
            } else {
                console.log(`❌ Gagal kirim teks ke: ${chatId} - ${data.description}`);
            }
            
            res.json(data);
        }
        
    } catch (error) {
        console.error(`💥 Error kirim pesan: ${error.message}`);
        res.status(500).json({
            ok: false,
            description: error.message
        });
    }
});

// Endpoint untuk mengirim pesan massal (spam) - FIXED
app.post('/api/send-bulk', upload.single('photo'), async (req, res) => {
    const { token, chatId, text, count } = req.body;
    const file = req.file;
    const messageCount = parseInt(count) || 1;
    
    try {
        const results = {
            success: 0,
            failed: 0,
            errors: []
        };
        
        for (let i = 0; i < messageCount; i++) {
            try {
                let response;
                
                if (file && file.buffer) {
                    // Kirim foto dengan caption
                    const telegramUrl = `https://api.telegram.org/bot${token}/sendPhoto`;
                    const formData = new FormData();
                    formData.append('chat_id', chatId);
                    formData.append('caption', text || '');
                    formData.append('photo', file.buffer, {
                        filename: file.originalname || 'photo.jpg',
                        contentType: file.mimetype || 'image/jpeg'
                    });
                    
                    response = await fetch(telegramUrl, {
                        method: 'POST',
                        body: formData,
                        headers: formData.getHeaders()
                    });
                } else {
                    // Kirim teks saja
                    const telegramUrl = `https://api.telegram.org/bot${token}/sendMessage`;
                    const params = new URLSearchParams();
                    params.append('chat_id', chatId);
                    params.append('text', text || `Message ${i + 1}`);
                    
                    response = await fetch(telegramUrl, {
                        method: 'POST',
                        body: params,
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }
                    });
                }
                
                const data = await response.json();
                
                if (data.ok) {
                    results.success++;
                    console.log(`📨 Pesan ${i + 1} terkirim ke: ${chatId}`);
                } else {
                    results.failed++;
                    results.errors.push(`Pesan ${i + 1}: ${data.description}`);
                    console.log(`❌ Gagal pesan ${i + 1} ke: ${chatId} - ${data.description}`);
                }
                
                // Delay antar pesan untuk menghindari rate limit
                await new Promise(resolve => setTimeout(resolve, 100));
                
            } catch (error) {
                results.failed++;
                results.errors.push(`Pesan ${i + 1}: ${error.message}`);
                console.error(`💥 Error pesan ${i + 1}: ${error.message}`);
            }
        }
        
        console.log(`📊 Hasil pengiriman: ${results.success} sukses, ${results.failed} gagal`);
        res.json({
            success: true,
            results: results
        });
        
    } catch (error) {
        console.error(`💥 Error bulk send: ${error.message}`);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Endpoint untuk menyimpan koneksi
let chatConnections = [];

app.get('/api/connections', (req, res) => {
    res.json(chatConnections);
});

app.post('/api/connections', (req, res) => {
    const connection = req.body;
    
    const existingConnection = chatConnections.find(conn => conn.id === connection.id);
    
    if (!existingConnection) {
        chatConnections.push({
            ...connection,
            firstSeen: new Date().toISOString(),
            lastSeen: new Date().toISOString(),
            messageCount: 1
        });
    } else {
        existingConnection.lastSeen = new Date().toISOString();
        existingConnection.messageCount = (existingConnection.messageCount || 0) + 1;
        if (connection.name && !existingConnection.name) {
            existingConnection.name = connection.name;
        }
        if (connection.type && existingConnection.type === 'unknown') {
            existingConnection.type = connection.type;
        }
    }
    
    res.json({ success: true });
});

app.delete('/api/connections', (req, res) => {
    chatConnections = [];
    console.log('🗑️  Semua koneksi dihapus');
    res.json({ success: true });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        connections: chatConnections.length,
        activeIPs: dosProtection.requests.size,
        blockedIPs: dosProtection.blocklist.size,
        server: 'Telegram Bot Manager',
        staticDir: 'public/'
    });
});

// Admin endpoint untuk melihat status protection
app.get('/admin/protection', (req, res) => {
    const status = {
        activeIPs: Array.from(dosProtection.requests.entries()).map(([ip, requests]) => ({
            ip,
            requestCount: requests.length,
            lastRequest: new Date(Math.max(...requests)).toISOString()
        })),
        blockedIPs: Array.from(dosProtection.blocklist),
        config: dosProtection.config
    };
    
    res.json(status);
});

// Endpoint untuk unblock IP manual
app.post('/admin/unblock-ip', (req, res) => {
    const { ip } = req.body;
    
    if (ip) {
        dosProtection.blocklist.delete(ip);
        dosProtection.requests.delete(ip);
        console.log(`✅ IP ${ip} di-unblock manual`);
        res.json({ success: true, message: `IP ${ip} telah di-unblock` });
    } else {
        res.status(400).json({ success: false, error: 'IP tidak diberikan' });
    }
});

// Start server
const server = app.listen(port, () => {
    console.log(`🚀 Server berjalan di http://localhost:${port}`);
    console.log('📱 Telegram Bot Manager siap digunakan!');
    console.log('📁 Static files dilayani dari: public/');
    console.log('🛡️  DOS Protection aktif (100 requests/minute)');
    console.log('⚡ by GALIRUS OFFICIAL');
    console.log(`\nUntuk cloudflared, gunakan: cloudflared tunnel --url http://localhost:${port}`);
    console.log('Tekan "q" lalu Enter untuk menghentikan server\n');
});

// Fungsi untuk graceful shutdown
function gracefulShutdown() {
    console.log('\n\n🛑 Menghentikan server...');
    console.log('📊 Statistik terakhir:');
    console.log(`   - Koneksi aktif: ${chatConnections.length}`);
    console.log(`   - IP aktif: ${dosProtection.requests.size}`);
    console.log(`   - IP diblokir: ${dosProtection.blocklist.size}`);
    
    server.close(() => {
        console.log('✅ Server berhasil dihentikan');
        process.exit(0);
    });

    setTimeout(() => {
        console.log('❌ Force shutting down');
        process.exit(1);
    }, 5000);
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.on('line', (input) => {
    if (input.trim().toLowerCase() === 'q') {
        rl.close();
        gracefulShutdown();
    }
});

if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
    process.stdin.on('data', (key) => {
        if (key.toString().toLowerCase() === 'q') {
            console.log('\n[q] ditekan, menghentikan server...');
            gracefulShutdown();
        }
    });
}