// V21 PROFESYONEL PROXY SİSTEMİ - Production Ready
// Betpuan859.com için özelleştirilmiş, asla çökmeyen proxy sunucusu

const express = require('express');
const http = require('http');
const config = require('./config');
const logger = require('./utils/logger');
const MiddlewareManager = require('./middleware');
const HttpHandler = require('./handlers/http');
const WebSocketHandler = require('./handlers/websocket');
const healthRoutes = require('./routes/health');

class ProxyServer {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.httpHandler = new HttpHandler();
        this.wsHandler = new WebSocketHandler(this.server);
        
        this.setupErrorHandlers();
        this.setupMiddlewares();
        this.setupRoutes();
    }

    // Kritik hata yakalayıcıları - Sunucunun çökmesini engeller
    setupErrorHandlers() {
        // Yakalanmamış exception'ları yakala
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception - Sunucu çalışmaya devam ediyor', error);
            // Sunucuyu kapatma, sadece log'la ve devam et
        });

        // Yakalanmamış promise rejection'ları yakala
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection - Sunucu çalışmaya devam ediyor', {
                reason: reason?.message || reason,
                stack: reason?.stack
            });
            // Sunucuyu kapatma, sadece log'la ve devam et
        });

        // Graceful shutdown sinyalleri
        process.on('SIGTERM', () => this.gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => this.gracefulShutdown('SIGINT'));
    }

    // Middleware'leri kur
    setupMiddlewares() {
        MiddlewareManager.setupMiddlewares(this.app);
    }

    // Route'ları kur
    setupRoutes() {
        // Health check route'ları
        this.app.use('/api', healthRoutes);

        // 🚀 KRİTİK: EVRENSEL API PROXY MIDDLEWARE - TÜM external domain'ler desteklenir
        // Format: /api-proxy/{host}/{path}?{query}
        // Whitelist YOK - Tüm domain'ler geçer
        this.app.use((req, res, next) => {
            if (req.path.startsWith('/api-proxy/')) {
                (async () => {
                    try {
                        // /api-proxy/go.cmsbetconstruct.com/api/... -> https://go.cmsbetconstruct.com/api/...
                        const pathParts = req.path.replace('/api-proxy/', '').split('/');
                        const domain = pathParts[0];
                        const apiPath = '/' + pathParts.slice(1).join('/');
                        const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
                        
                        // 🚀 KRİTİK FIX: HTTPS protokolü zorla (CERT hatası çözümü)
                        const fullUrl = `https://${domain}${apiPath}${queryString}`;
                        
                        logger.info('🔄 Universal API proxy', { 
                            domain, 
                            path: apiPath,
                            query: queryString,
                            fullUrl: fullUrl.substring(0, 150)
                        });
                        
                        // Yeni request URL'i ayarla ve handleRequest'e geç
                        req.url = fullUrl;
                        req.originalUrl = fullUrl;
                        await this.httpHandler.handleRequest(req, res);
                    } catch (error) {
                        logger.error('Universal API proxy hatası', error);
                        if (!res.headersSent) {
                            // Boş JSON fallback döndür (React çökmesin)
                            res.status(200).json({ 
                                data: [], 
                                items: [], 
                                status: 'error',
                                message: 'API temporarily unavailable' 
                            });
                        }
                    }
                })();
            } else {
                next();
            }
        });

        // Yerel HTML dosyaları için static serving (clear-cache.html gibi)
        this.app.get('/clear-cache.html', (req, res) => {
            res.sendFile(__dirname + '/clear-cache.html');
        });

        // 🚀 KRİTİK: Runtime Interceptor Script'ini serve et
        this.app.get('/interceptor.js', (req, res) => {
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.sendFile(__dirname + '/public/interceptor.js');
        });

        // Ana proxy handler - Tüm diğer istekleri yakalar
        this.app.use(async (req, res) => {
            try {
                await this.httpHandler.handleRequest(req, res);
            } catch (error) {
                logger.error('Ana proxy handler hatası', error);
                
                // Error sayacını artır
                if (healthRoutes.incrementErrorCount) {
                    healthRoutes.incrementErrorCount();
                    healthRoutes.setLastError(error);
                }

                // Response gönderilmemişse hata response'u gönder
                if (!res.headersSent) {
                    res.status(500).json({
                        error: 'Proxy Error',
                        message: 'İstek işlenirken hata oluştu',
                        timestamp: new Date().toISOString()
                    });
                }
            }
        });

        // Global error handler
        this.app.use(MiddlewareManager.errorHandler);
    }

    // Sunucuyu başlat
    async start() {
        try {
            // Port'u dinlemeye başla
            await new Promise((resolve, reject) => {
                this.server.listen(config.PORT, '0.0.0.0', (error) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve();
                    }
                });
            });

            // Başarılı başlatma mesajı
            logger.info(`🚀 V21 PROFESYONEL PROXY AKTİF!`);
            logger.info(`📡 Hedef Site: ${config.TARGET_URL}`);
            logger.info(`🌐 Proxy URL: http://localhost:${config.PORT}`);
            logger.info(`🔧 Environment: ${config.NODE_ENV}`);
            logger.info(`📊 Health Check: http://localhost:${config.PORT}/api/health`);
            logger.info(`📈 Status: http://localhost:${config.PORT}/api/status`);
            
            // Hedef site bağlantısını test et
            await this.testTargetConnection();

        } catch (error) {
            logger.error('Sunucu başlatma hatası', error);
            process.exit(1);
        }
    }

    // Hedef site bağlantısını test et
    async testTargetConnection() {
        try {
            const axios = require('axios');
            const response = await axios.get(config.TARGET_URL, {
                timeout: 10000,
                validateStatus: () => true,
                headers: { 'User-Agent': 'V21-Proxy-Startup-Test' }
            });

            if (response.status < 500) {
                logger.info(`✅ Hedef site erişilebilir (${response.status})`);
            } else {
                logger.warn(`⚠️ Hedef site sorunlu (${response.status})`);
            }
        } catch (error) {
            logger.warn('⚠️ Hedef site bağlantı testi başarısız', {
                error: error.message,
                code: error.code
            });
        }
    }

    // Graceful shutdown
    async gracefulShutdown(signal) {
        logger.info(`${signal} sinyali alındı, sunucu kapatılıyor...`);
        
        try {
            // Yeni bağlantıları kabul etmeyi durdur
            this.server.close(() => {
                logger.info('HTTP sunucusu kapatıldı');
            });

            // Aktif bağlantıların bitmesini bekle (max 30 saniye)
            setTimeout(() => {
                logger.info('Graceful shutdown tamamlandı');
                process.exit(0);
            }, 30000);

        } catch (error) {
            logger.error('Graceful shutdown hatası', error);
            process.exit(1);
        }
    }
}

// Sunucuyu başlat
const proxyServer = new ProxyServer();
proxyServer.start().catch((error) => {
    logger.error('Kritik başlatma hatası', error);
    process.exit(1);
});
