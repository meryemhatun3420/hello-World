// WebSocket proxy handler - Canlı bahis bağlantıları için kritik
const WebSocket = require('ws');
const config = require('../config');
const logger = require('../utils/logger');

class WebSocketHandler {
    constructor(server) {
        this.server = server;
        this.wss = new WebSocket.Server({ noServer: true });
        this.setupUpgradeHandler();
    }

    // WebSocket upgrade handler'ı kur
    setupUpgradeHandler() {
        this.server.on('upgrade', (req, socket, head) => {
            try {
                const url = new URL(req.url, `http://${req.headers.host}`);
                
                // 🚀 EVRENSEL WEBSOCKET PROXY - /api-proxy/ ile başlayan tüm WS istekleri
                if (url.pathname.startsWith('/api-proxy/')) {
                    this.handleUniversalWebSocketProxy(req, socket, head, url);
                } else if (url.pathname === '/ws-proxy') {
                    // Eski format için backward compatibility
                    this.handleWebSocketProxy(req, socket, head, url);
                } else {
                    logger.warn('Bilinmeyen WebSocket upgrade isteği', { path: url.pathname });
                    socket.destroy();
                }
            } catch (error) {
                logger.error('WebSocket upgrade hatası', error);
                socket.destroy();
            }
        });
    }

    // 🚀 YENİ: Evrensel WebSocket proxy handler
    // Format: ws://localhost:3000/api-proxy/{host}/{path}
    handleUniversalWebSocketProxy(req, socket, head, url) {
        try {
            // /api-proxy/eu-swarm-newm.betpuan859.com/path -> wss://eu-swarm-newm.betpuan859.com/path
            const pathParts = url.pathname.replace('/api-proxy/', '').split('/');
            const targetHost = pathParts[0];
            const targetPath = '/' + pathParts.slice(1).join('/');
            const targetUrl = `wss://${targetHost}${targetPath}${url.search}`;

            logger.info('🔌 Universal WebSocket proxy başlatılıyor', { 
                targetUrl,
                targetHost,
                targetPath,
                clientIp: req.socket.remoteAddress
            });

            // WebSocket bağlantısını kur
            this.connectWebSocket(req, socket, head, targetUrl, targetHost);
        } catch (error) {
            logger.error('❌ Universal WebSocket proxy hatası', {
                error: error.message,
                path: url.pathname
            });
            socket.destroy();
        }
    }

    // WebSocket bağlantısını kur (ortak fonksiyon)
    connectWebSocket(req, socket, head, targetUrl, targetHost) {
        try {
            const targetUrlObj = new URL(targetUrl);
            
            // Güvenlik kontrolü
            if (!this.isAllowedWebSocketTarget(targetUrlObj.host)) {
                logger.warn('WebSocket proxy - izin verilmeyen hedef', { host: targetUrlObj.host });
                socket.destroy();
                return;
            }

            // Hedef WebSocket'e bağlan
            const headers = this.buildWebSocketHeaders(req, targetUrlObj);
            
            logger.debug('🔌 WebSocket handshake header\'ları', {
                targetUrl: targetUrl.substring(0, 100),
                headers: {
                    Origin: headers.Origin,
                    Cookie: headers.Cookie ? 'present' : 'none',
                    'Sec-WebSocket-Key': headers['Sec-WebSocket-Key'],
                    'Sec-WebSocket-Version': headers['Sec-WebSocket-Version']
                }
            });
            
            const targetWs = new WebSocket(targetUrl, { 
                rejectUnauthorized: false, 
                headers,
                timeout: config.PROXY_TIMEOUT,
                handshakeTimeout: 10000 // 10 saniye handshake timeout
            });

            // WebSocket upgrade işlemi
            this.wss.handleUpgrade(req, socket, head, (clientWs) => {
                this.setupWebSocketBridge(clientWs, targetWs, targetUrl);
            });

        } catch (error) {
            logger.error('❌ WebSocket bağlantı kurulum hatası', {
                error: error.message,
                targetUrl: targetUrl.substring(0, 100),
                stack: error.stack
            });
            socket.destroy();
        }
    }

    // WebSocket proxy işlemi (eski format - backward compatibility)
    handleWebSocketProxy(req, socket, head, url) {
        let targetUrl = url.searchParams.get('url');
        
        if (!targetUrl) {
            logger.warn('WebSocket proxy - target URL eksik');
            socket.destroy();
            return;
        }

        // 🚀 KRİTİK: WebSocket URL'deki İngilizce parametreleri Türkçe'ye çevir
        targetUrl = this.forceWebSocketUrlToTurkish(targetUrl);

        logger.info('🔌 WebSocket proxy bağlantısı başlatılıyor (legacy format)', { 
            targetUrl: targetUrl.substring(0, 100),
            clientIp: req.socket.remoteAddress
        });

        const targetUrlObj = new URL(targetUrl);
        this.connectWebSocket(req, socket, head, targetUrl, targetUrlObj.host);
    }

    // WebSocket URL'deki dil parametrelerini Türkçe'ye zorla
    forceWebSocketUrlToTurkish(url) {
        if (!url || typeof url !== 'string') return url;

        try {
            const urlObj = new URL(url);
            const params = urlObj.searchParams;
            
            // Query parametrelerini düzenle
            if (params.has('lang')) {
                const langValue = params.get('lang');
                if (langValue === 'en' || langValue === 'eng') {
                    params.set('lang', 'tur');
                }
            }
            
            if (params.has('language')) {
                const langValue = params.get('language');
                if (langValue === 'en' || langValue === 'eng') {
                    params.set('language', 'tur');
                }
            }
            
            if (params.has('locale')) {
                const localeValue = params.get('locale');
                if (localeValue === 'en' || localeValue === 'en-US') {
                    params.set('locale', 'tr');
                }
            }
            
            const finalUrl = urlObj.toString();
            
            if (finalUrl !== url) {
                logger.info('🔄 WebSocket URL Türkçe\'ye zorlandı', { original: url, turkish: finalUrl });
            }
            
            return finalUrl;
        } catch (error) {
            logger.debug('WebSocket URL parse hatası', { url, error: error.message });
            return url;
        }
    }

    // WebSocket header'larını hazırla
    buildWebSocketHeaders(req, targetUrlObj) {
        const headers = {};

        // 🚀 KRİTİK: Orijinal WebSocket header'larını koru
        // Sec-WebSocket-* header'ları handshake için gerekli
        if (req.headers['sec-websocket-key']) {
            headers['Sec-WebSocket-Key'] = req.headers['sec-websocket-key'];
        }
        if (req.headers['sec-websocket-version']) {
            headers['Sec-WebSocket-Version'] = req.headers['sec-websocket-version'];
        }
        if (req.headers['sec-websocket-extensions']) {
            headers['Sec-WebSocket-Extensions'] = req.headers['sec-websocket-extensions'];
        }
        if (req.headers['sec-websocket-protocol']) {
            headers['Sec-WebSocket-Protocol'] = req.headers['sec-websocket-protocol'];
        }

        // Origin'i target domain'e yeniden yaz
        headers['Origin'] = `https://${targetUrlObj.host}`;
        
        // Host header'ı
        headers['Host'] = targetUrlObj.host;
        
        // User-Agent
        headers['User-Agent'] = req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
        
        // 🚀 KRİTİK: Türkçe dil header'larını ekle
        headers['Accept-Language'] = 'tr-TR,tr;q=0.9';
        headers['x-lang'] = 'tr';
        headers['x-language'] = 'tur';
        headers['x-locale'] = 'tr-TR';

        // 🚀 KRİTİK: Orijinal cookie'leri aktar (dil değişimiyle)
        if (req.headers.cookie) {
            // Cookie'lerdeki İngilizce dil değerlerini Türkçe'ye çevir
            let cookies = req.headers.cookie;
            cookies = cookies.replace(/language=eng/g, 'language=tur')
                            .replace(/language=en/g, 'language=tur')
                            .replace(/lang=eng/g, 'lang=tur')
                            .replace(/lang=en/g, 'lang=tur')
                            .replace(/locale=en/g, 'locale=tr');
            
            // Türkçe dil cookie'lerini ekle
            cookies += '; language=tur; lang=tr; locale=tr';
            
            headers['Cookie'] = cookies;
            
            logger.debug('🍪 WebSocket cookie\'leri aktarıldı', {
                originalLength: req.headers.cookie.length,
                modifiedLength: cookies.length
            });
        } else {
            // Cookie yoksa Türkçe dil cookie'lerini ekle
            headers['Cookie'] = 'language=tur; lang=tr; locale=tr';
        }

        // Authorization header'ı varsa aktar
        if (req.headers.authorization) {
            headers['Authorization'] = req.headers.authorization;
        }

        return headers;
    }

    // İzin verilen WebSocket hedefleri - EVRENSEL MOD (Tüm domain'ler izinli)
    isAllowedWebSocketTarget(host) {
        // 🚀 KRİTİK: Whitelist kaldırıldı - TÜM domain'ler izinli
        // Sadece localhost ve private IP'leri engelle (güvenlik)
        const blockedPatterns = [
            /^localhost$/i,
            /^127\./,
            /^192\.168\./,
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./
        ];

        const isBlocked = blockedPatterns.some(pattern => pattern.test(host));
        
        if (isBlocked) {
            logger.warn('🚫 WebSocket - Private IP/localhost engellendi', { host });
            return false;
        }

        // Tüm public domain'ler izinli
        logger.debug('✅ WebSocket - Domain izinli', { host });
        return true;
    }

    // WebSocket köprüsünü kur
    setupWebSocketBridge(clientWs, targetWs, targetUrl) {
        let isConnected = false;
        let messageCount = { clientToTarget: 0, targetToClient: 0 };

        // Target WebSocket açıldığında
        targetWs.on('open', () => {
            isConnected = true;
            logger.info('✅ WebSocket bağlantısı kuruldu', { 
                targetUrl,
                readyState: targetWs.readyState 
            });
        });

        // Client'tan target'a mesaj aktar
        clientWs.on('message', (message) => {
            if (targetWs.readyState === WebSocket.OPEN) {
                try {
                    targetWs.send(message);
                    messageCount.clientToTarget++;
                    logger.debug('📤 Client -> Target mesaj', { 
                        size: message.length,
                        count: messageCount.clientToTarget
                    });
                } catch (error) {
                    logger.error('❌ Client -> Target mesaj hatası', {
                        error: error.message,
                        targetUrl
                    });
                }
            }
        });

        // Target'tan client'a mesaj aktar
        targetWs.on('message', (message) => {
            if (clientWs.readyState === WebSocket.OPEN) {
                try {
                    clientWs.send(message);
                    messageCount.targetToClient++;
                    logger.debug('📥 Target -> Client mesaj', { 
                        size: message.length,
                        count: messageCount.targetToClient
                    });
                } catch (error) {
                    logger.error('❌ Target -> Client mesaj hatası', {
                        error: error.message,
                        targetUrl
                    });
                }
            }
        });

        // Bağlantı kapanma işlemleri
        clientWs.on('close', (code, reason) => {
            const reasonStr = reason ? reason.toString() : 'No reason';
            logger.info('🔌 Client WebSocket kapandı', { 
                code, 
                reason: reasonStr,
                targetUrl,
                messageStats: messageCount
            });
            if (targetWs.readyState === WebSocket.OPEN) {
                targetWs.close(code, reasonStr);
            }
        });

        targetWs.on('close', (code, reason) => {
            const reasonStr = reason ? reason.toString() : 'No reason';
            logger.info('🔌 Target WebSocket kapandı', { 
                code, 
                reason: reasonStr,
                targetUrl,
                messageStats: messageCount
            });
            if (clientWs.readyState === WebSocket.OPEN) {
                clientWs.close(code, reasonStr);
            }
        });

        // Hata işleme
        clientWs.on('error', (error) => {
            logger.error('❌ Client WebSocket hatası', {
                error: error.message,
                code: error.code,
                targetUrl,
                messageStats: messageCount
            });
            if (targetWs.readyState === WebSocket.OPEN) {
                targetWs.close(1011, 'Client error');
            }
        });

        targetWs.on('error', (error) => {
            logger.error('❌ Target WebSocket hatası', {
                error: error.message,
                code: error.code,
                targetUrl,
                messageStats: messageCount
            });
            if (clientWs.readyState === WebSocket.OPEN) {
                clientWs.close(1011, 'Target error');
            }
        });

        // Timeout kontrolü
        setTimeout(() => {
            if (!isConnected) {
                logger.warn('⏱️ WebSocket bağlantı timeout', { 
                    targetUrl,
                    elapsed: config.PROXY_TIMEOUT + 'ms'
                });
                clientWs.close(1008, 'Connection timeout');
                targetWs.close(1008, 'Connection timeout');
            }
        }, config.PROXY_TIMEOUT);
    }
}

module.exports = WebSocketHandler;