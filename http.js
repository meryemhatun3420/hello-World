// HTTP proxy handler - Ana proxy işlemleri
const axios = require('axios');
const cheerio = require('cheerio');
const https = require('https');
const config = require('../config');
const logger = require('../utils/logger');
const ProxyUtils = require('../utils/proxy');

class HttpHandler {
    constructor() {
        // HTTPS agent - performans için connection pooling
        this.httpsAgent = new https.Agent({
            rejectUnauthorized: false,
            keepAlive: true,
            maxSockets: 500,
            timeout: config.PROXY_TIMEOUT,
            family: 4 // 🚀 KRİTİK EKLENTİ: Sadece IPv4 kullan (Timeout'ları kökten çözer!)
        });

        // Axios instance oluştur - otomatik decompression ile
        this.axiosInstance = axios.create({
            httpsAgent: this.httpsAgent,
            decompress: true,
            maxRedirects: config.MAX_REDIRECTS,
            validateStatus: () => true
        });
    }

    // Ana proxy middleware
    async handleRequest(req, res) {
        const startTime = Date.now();

        try {
            // OPTIONS request'leri için CORS
            if (req.method === 'OPTIONS') {
                return this.handleCorsOptions(res);
            }

            // Translation dosyası override - ENG isteklerini TUR'a çevir
            if (req.url.includes('/translations/') && req.url.includes('.json')) {
                if (req.url.includes('eng.json') || req.url.includes('en.json')) {
                    const turkishUrl = req.url.replace(/eng\.json/gi, 'tur.json').replace(/en\.json/gi, 'tur.json');
                    logger.info('🔄 Translation dosyası zorla Türkçe\'ye çevrildi', {
                        original: req.url,
                        turkish: turkishUrl
                    });
                    req.url = turkishUrl;
                }
            }

            // Türkçe yönlendirme kontrolü - Güçlendirilmiş versiyon
            if (req.url === '/' || req.url === '' || req.url === '/en' || req.url === '/en/' || req.url.startsWith('/en/') || req.url.includes('lang=en') || req.url.includes('language=en')) {
                logger.info('🔄 Türkçe sayfaya yönlendiriliyor', {
                    originalUrl: req.url,
                    userAgent: req.headers['user-agent']?.substring(0, 100),
                    ip: req.ip || req.connection.remoteAddress
                });

                // URL'yi Türkçe'ye çevir
                let redirectUrl = req.url;
                // Ana sayfa kontrolü - Sonsuz döngüyü kır
                if (req.url === '/' || req.url === '') {
                    redirectUrl = '/tr/';
                } else if (req.url === '/en' || req.url === '/en/') {
                    redirectUrl = '/tr/';
                } else if (req.url.startsWith('/en/')) {
                    redirectUrl = req.url.replace('/en/', '/tr/');
                }

                if (redirectUrl !== req.url || req.url.includes('lang=e')) {
                    let finalUrl = redirectUrl;

                    if (req.url.includes('?')) {
                        const [path, query] = req.url.split('?');
                        const translatedPath = redirectUrl.split('?')[0];

                        let queryString = query
                            .replace(/lang=en/gi, 'lang=tur')
                            .replace(/language=en/gi, 'language=tur')
                            .replace(/locale=en/gi, 'locale=tr');

                        finalUrl = translatedPath + '?' + queryString;
                    }

                    redirectUrl = finalUrl;
                }

                // Güçlü redirect header'ları - Browser cache'ini bypass et
                res.writeHead(302, {
                    'Location': redirectUrl,
                    'Cache-Control': 'no-cache, no-store, must-revalidate, private',
                    'Pragma': 'no-cache',
                    'Expires': '0',
                    'Set-Cookie': [
                        'language=tur; Path=/; Max-Age=31536000; SameSite=Lax',
                        'selectedLanguage=tur; Path=/; Max-Age=31536000; SameSite=Lax',
                        'lang=tur; Path=/; Max-Age=31536000; SameSite=Lax',
                        'locale=tr; Path=/; Max-Age=31536000; SameSite=Lax',
                        'i18n_language=tur; Path=/; Max-Age=31536000; SameSite=Lax'
                    ]
                });
                return res.end();
            }

            // Target URL'yi belirle
            const targetUrl = this.determineTargetUrl(req);

            // Özel endpoint'leri kontrol et
            if (this.handleSpecialEndpoints(req, res, targetUrl)) {
                return;
            }

            // go. subdomain'ini düzelt (go.localhost:3000 -> localhost:3000)
            if (req.headers.host && req.headers.host.startsWith('go.')) {
                req.headers.host = req.headers.host.replace('go.', '');
                logger.debug('🔄 go. subdomain düzeltildi', { host: req.headers.host });
            }

            // Ana proxy işlemi
            await this.proxyRequest(req, res, targetUrl, startTime);

        } catch (error) {
            // Headers zaten gönderilmişse hiçbir şey yapma
            if (res.headersSent) {
                logger.debug('Headers zaten gönderilmiş, genel error handling atlanıyor', { url: req.url });
                return;
            }

            logger.error('HTTP handler genel hatası', error);
            this.sendErrorResponse(res, 500, 'Internal Server Error');
        }
    }

    // CORS OPTIONS handler
    handleCorsOptions(res) {
        ProxyUtils.cleanHeaders({}, res, null);
        res.status(200).end();
    }

    // Target URL'yi belirle
    determineTargetUrl(req) {
        // Her URL için debug log
        logger.debug('🔍 URL analizi', { url: req.url });

        if (req.url.startsWith('/v21-proxy/')) {
            const decodedUrl = ProxyUtils.decodeProxyUrl(req.url);
            // Decoded URL'de de İngilizce parametreleri Türkçe'ye çevir
            return this.convertApiUrlToTurkish(decodedUrl);
        }

        // İngilizce translation dosyalarını Türkçe'ye çevir - Güçlendirilmiş
        if (req.url.includes('/translations/eng.json') || req.url.includes('/translations/en.json')) {
            const turkishUrl = config.TARGET_ORIGIN + req.url.replace('/translations/eng.json', '/translations/tur.json').replace('/translations/en.json', '/translations/tur.json');
            logger.info('🔄 İngilizce çeviri dosyası Türkçe\'ye çevrildi', {
                original: req.url,
                turkish: turkishUrl
            });
            return turkishUrl;
        }

        // Tüm translation dosyalarını Türkçe'ye zorla - Güçlendirilmiş
        if (req.url.includes('/translations/') && req.url.includes('.json')) {
            let turkishUrl = config.TARGET_ORIGIN + req.url;

            // Herhangi bir dil kodunu tur.json ile değiştir
            turkishUrl = turkishUrl.replace(/\/translations\/[a-z]{2,3}\.json/gi, '/translations/tur.json');

            if (turkishUrl !== config.TARGET_ORIGIN + req.url) {
                logger.info('🔄 Translation dosyası Türkçe\'ye zorlandı', {
                    original: req.url,
                    turkish: turkishUrl
                });
            }
            return turkishUrl;
        }

        // İngilizce menü dosyalarını Türkçe'ye çevir - Güçlendirilmiş
        if (req.url.includes('_eng.json') || req.url.includes('_en.json') || req.url.includes('eng.json') || req.url.includes('/eng/')) {
            let turkishUrl = config.TARGET_ORIGIN + req.url;
            turkishUrl = turkishUrl.replace('_eng.json', '_tur.json')
                .replace('_en.json', '_tur.json')
                .replace('/eng.json', '/tur.json')
                .replace('/eng/', '/tur/');
            
            // Menü dosyaları için özel log
            if (req.url.includes('menu')) {
                logger.info('🔄 Menü dosyası Türkçe\'ye çevrildi', {
                    original: req.url,
                    turkish: turkishUrl
                });
            }
            
            return turkishUrl;
        }

        // 🚀 KRİTİK: /menus/ klasöründeki TÜM dosyaları Türkçe'ye zorla
        if (req.url.includes('/menus/')) {
            let turkishUrl = config.TARGET_ORIGIN + req.url;
            // Dosya adındaki herhangi bir dil kodunu tur ile değiştir
            turkishUrl = turkishUrl.replace(/menu_([0-9]+)_[a-z]{2,3}\.json/gi, 'menu_$1_tur.json')
                .replace(/header_menu_([0-9]+)_[a-z]{2,3}\.json/gi, 'header_menu_$1_tur.json')
                .replace(/app_menu_([0-9]+)_[a-z]{2,3}\.json/gi, 'app_menu_$1_tur.json')
                .replace(/footer_menu_([0-9]+)_[a-z]{2,3}\.json/gi, 'footer_menu_$1_tur.json');
            
            if (turkishUrl !== config.TARGET_ORIGIN + req.url) {
                logger.info('🔄 Menü klasörü dosyası Türkçe\'ye zorlandı', {
                    original: req.url,
                    turkish: turkishUrl
                });
            }
            return turkishUrl;
        }

        // URL'yi Türkçe'ye çevir - Güçlendirilmiş versiyon
        let targetPath = req.url;

        // /en/ ile başlayan URL'leri /tr/ ile değiştir
        if (targetPath.startsWith('/en/')) {
            targetPath = targetPath.replace('/en/', '/tr/');
            logger.info('🔄 Target URL Türkçe\'ye çevrildi', {
                original: req.url,
                converted: targetPath
            });
        }

        // Ana site URL'si
        const baseUrl = config.TARGET_ORIGIN + targetPath;

        try {
            new URL(baseUrl); // URL geçerliliğini kontrol et
            return baseUrl;
        } catch (error) {
            logger.warn('Geçersiz URL, Türkçe ana sayfaya yönlendiriliyor', { url: req.url });
            return config.TARGET_ORIGIN + '/tr/';
        }
    }

    // API URL'lerindeki dış domainleri ana domaine yönlendir (Cloudflare bypass için)
    convertApiUrlToTurkish(url) {
        // ARTIK URL'LERİ ZORLA TÜRKÇE YAPMIYORUZ ÇÜNKÜ API BOZUK!
        // Sadece dış domainleri ana domaine (Betpuan'a) yönlendiriyoruz ki Cloudflare banlamasın.
        try {
            if (url.includes('cmsbetconstruct.com') || url.includes('betconstruct.com') || url.includes('btcoservice')) {
                let safeUrl = url;
                safeUrl = safeUrl.replace(/https?:\/\/go\.cmsbetconstruct\.com/gi, config.TARGET_ORIGIN);
                safeUrl = safeUrl.replace(/https?:\/\/cms\.btcoservice[0-9]*\.com/gi, config.TARGET_ORIGIN);
                return safeUrl;
            }
            return url;
        } catch (error) {
            return url;
        }
    }

    // Özel endpoint'leri handle et
    handleSpecialEndpoints(req, res, targetUrl) {
        const path = require('path');
        const fs = require('fs');

        // SPA Asset'leri için özel handling - /assets/ klasörü
        if (req.url.startsWith('/assets/')) {
            logger.debug('📦 SPA Asset isteği tespit edildi', { url: req.url });
            // Normal proxy işlemine devam et, özel handling yapma
            return false;
        }

        // Target URL objesi oluştur
        let url;
        try {
            if (!targetUrl || typeof targetUrl !== 'string' || !targetUrl.startsWith('http')) {
                // Eğer targetUrl geçerli bir mutlak URL değilse, local redirect olabilir
                return false;
            }
            url = new URL(targetUrl);
        } catch (e) {
            logger.warn('Special endpoints URL parse hatası', { targetUrl, error: e.message });
            return false;
        }

        // --- YENİ: Yerel dosya sistemi kontrolü (betpuan859 klasörü) ---
        // Eğer targetUrl external bir domain ise ve yerelde dosyası varsa onu kullan
        if (targetUrl.startsWith('http')) {
            const betpuanDir = path.join(__dirname, '../betpuan859');
            const localFilePath = path.join(betpuanDir, url.hostname, url.pathname);

            if (fs.existsSync(localFilePath) && fs.statSync(localFilePath).isFile()) {
                const firstBytes = fs.readFileSync(localFilePath, { encoding: 'utf8', flag: 'r' }).substring(0, 10);
                if (firstBytes.startsWith('No Content')) {
                    logger.debug('📄 Yerel dosya "No Content" placeholder, proxy\'e devam ediliyor', { url: targetUrl });
                } else {
                    logger.info('📂 Yerel dosya bulundu ve servis ediliyor', {
                        url: targetUrl,
                        localPath: localFilePath
                    });

                    // Content-Type belirle
                    if (localFilePath.endsWith('.css')) res.setHeader('Content-Type', 'text/css; charset=utf-8');
                    else if (localFilePath.endsWith('.js')) res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
                    else if (localFilePath.endsWith('.json')) res.setHeader('Content-Type', 'application/json; charset=utf-8');
                    else if (localFilePath.endsWith('.png')) res.setHeader('Content-Type', 'image/png');
                    else if (localFilePath.endsWith('.jpg') || localFilePath.endsWith('.jpeg')) res.setHeader('Content-Type', 'image/jpeg');
                    else if (localFilePath.endsWith('.gif')) res.setHeader('Content-Type', 'image/gif');

                    return res.sendFile(localFilePath);
                }
            }
        }

        // Cloudflare beacon ve tracking scriptlerini engelle
        if (this.isBlockedEndpoint(url.pathname) || this.isBlockedEndpoint(req.url)) {
            logger.debug('🚫 Tracking/Analytics script engellendi', { url: req.url });

            // JavaScript dosyaları için boş script döndür
            if (req.url.includes('.js') || url.pathname.includes('.js')) {
                res.status(200).type('application/javascript').send('// Tracking script blocked by V21 Proxy');
                return true;
            }

            // Diğer dosyalar için boş response
            res.status(200).send('');
            return true;
        }

        // Bilinen sorunlu external dosyalar için fallback
        if (targetUrl.includes('talep-paneli.netlify.app')) {
            if (targetUrl.includes('.css') || targetUrl.includes('custom.css')) {
                const fallbackCSS = `
                /* V21 Proxy - External CSS Fallback */
                body { font-family: Arial, sans-serif; }
                .container { max-width: 1200px; margin: 0 auto; }
                `;
                res.status(200).type('text/css; charset=utf-8').send(fallbackCSS);
                logger.info('🎨 External CSS fallback gönderildi', { url: req.url });
                return true;
            }
        }

        // 🚀 KRİTİK JSON FALLBACK - Orijinal JSON'u koru, dil zorlaması yapma!
        // Bu fallback'ler sadece dosya tamamen erişilemezse devreye girer
        // Normal proxy akışında processJsonContent() dil değişimini yapar
        
        // NOT: Bu fallback'ler SADECE dosya 404/timeout olduğunda devreye girer
        // Eğer dosya başarıyla gelirse, processJsonContent() içinde işlenir
        // Bu yüzden burada minimal fallback yeterli, dil zorlaması YAPMA!

        // Yavaş API'ler için timeout kontrolü
        if (url.hostname.includes('cmsbetconstruct.com') || url.hostname.includes('go.cmsbetconstruct.com')) {
            // Bu API'ler için özel timeout handling yapılacak
            logger.debug('🐌 Yavaş API tespit edildi', { url: targetUrl });
        }

        // Analytics ve tracking engellemeleri
        if (this.isBlockedEndpoint(url.pathname)) {
            if (url.pathname.includes('geoapi2') || url.pathname.includes('geoapi') || url.pathname.includes('geolocation') || url.pathname.includes('location')) {
                // Sahte Türkiye geo API response - IP olmadan
                const turkeyGeoResponse = {
                    country_code: "TR",
                    country_name: "Turkey",
                    country: "Turkey",
                    city: "Istanbul",
                    region: "Istanbul",
                    timezone: "Europe/Istanbul",
                    latitude: 41.0082,
                    longitude: 28.9784,
                    currency: "TRY",
                    language: "tr",
                    locale: "tr-TR"
                };

                logger.info('🌍 Sahte Türkiye geo API response gönderildi', {
                    endpoint: url.pathname,
                    response: turkeyGeoResponse
                });

                res.json(turkeyGeoResponse);
                return true;
            }

            // Diğer engellenen endpoint'ler için boş response
            res.status(200).send('');
            return true;
        }

        // GeoAPI için özel handling - bcapps.org
        if (url.hostname.includes('bcapps.org') || url.hostname.includes('geoapi')) {
            const turkeyGeoResponse = {
                country_code: "TR",
                country_name: "Turkey",
                country: "Turkey",
                city: "Istanbul",
                region: "Istanbul",
                timezone: "Europe/Istanbul",
                latitude: 41.0082,
                longitude: 28.9784,
                currency: "TRY",
                language: "tr",
                locale: "tr-TR"
            };

            logger.info('🌍 GeoAPI Türkiye response', { url: url.hostname });
            res.json(turkeyGeoResponse);
            return true;
        }

        // icons.cmsbetconstruct.com için transparent PNG fallback - GENİŞLETİLMİŞ
        if (url.hostname.includes('icons.cmsbetconstruct.com') || url.hostname.includes('cmsbetconstruct.com')) {
            // Sadece resim dosyaları için fallback
            if (url.pathname.includes('.png') || url.pathname.includes('.jpg') || 
                url.pathname.includes('.jpeg') || url.pathname.includes('.gif') || 
                url.pathname.includes('.svg') || url.pathname.includes('/storage/') ||
                url.pathname.includes('/medias/')) {
                logger.debug('🖼️ CMS BetConstruct image fallback PNG', { url: url.pathname });
                const transparentPng = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==', 'base64');
                res.status(200).type('image/png').send(transparentPng);
                return true;
            }
        }

        return false;
    }

    // Engellenen endpoint kontrolü
    isBlockedEndpoint(pathname) {
        const blockedPaths = [
            'cloudflareinsights',
            'beacon.min.js',
            'cf-beacon',
            'google-analytics',
            'googletagmanager',
            'facebook.com/tr',
            'doubleclick.net',
            'geoapi2',
            'geoapi',
            'geolocation',
            'location',
            'ipapi',
            'ip-api',
            'freegeoip',
            'geoip',
            'maxmind',
            'analytics',
            'tracking',
            'metrics'
        ];

        return blockedPaths.some(blocked => pathname.includes(blocked));
    }

    // Dinamik timeout belirleme - URL'ye göre
    getTimeoutForUrl(url) {
        try {
            const urlObj = new URL(url);

            // Yavaş API'ler için çok uzun timeout
            if (urlObj.hostname.includes('cmsbetconstruct.com') ||
                urlObj.hostname.includes('go.cmsbetconstruct.com') ||
                urlObj.hostname.includes('btcoservice')) {
                return 60000; // 60 saniye (1 dakika)
            }

            // External domain'ler için uzun timeout
            if (urlObj.hostname.includes('netlify.app') ||
                urlObj.hostname.includes('cloudflare')) {
                return 30000; // 30 saniye
            }

            // Ana site için normal timeout
            return config.PROXY_TIMEOUT; // 15 saniye
        } catch (error) {
            return config.PROXY_TIMEOUT;
        }
    }

    // Ana proxy request işlemi
    async proxyRequest(req, res, targetUrl, startTime) {
        try {
            // 🚀 DEBUG LOGGING: Original URL → Proxied URL
            logger.info('🔄 Proxy Request', {
                original: req.originalUrl || req.url,
                proxied: targetUrl.substring(0, 150),
                method: req.method,
                clientIp: req.ip || req.connection.remoteAddress
            });

            // 🚀 KRİTİK: URL'deki İngilizce parametreleri Türkçe'ye çevir
            targetUrl = this.forceUrlToTurkish(targetUrl);

            const url = new URL(targetUrl);
            const isExternal = ProxyUtils.isExternalDomain(targetUrl);

            // Request header'larını hazırla
            const headers = this.buildRequestHeaders(req, url, isExternal);

            // Axios request konfigürasyonu
            const axiosConfig = {
                method: req.method,
                url: targetUrl,
                headers,
                responseType: 'arraybuffer',
                timeout: this.getTimeoutForUrl(targetUrl),
                validateStatus: () => true // Tüm status code'ları kabul et
            };

            // POST/PUT data varsa ekle
            if (req.body && (req.method === 'POST' || req.method === 'PUT')) {
                axiosConfig.data = req.body;
            }

            // Request'i gönder (retry ile) - Axios instance kullan
            const response = await this.fetchWithRetry(axiosConfig);

            // 🚀 DEBUG LOGGING: Upstream response code
            logger.info('📊 Upstream Response', {
                url: targetUrl.substring(0, 100),
                status: response.status,
                contentType: response.headers['content-type'],
                size: response.data ? response.data.length : 0
            });

            // Response'u işle
            await this.processResponse(req, res, response, startTime);

        } catch (error) {
            // Headers zaten gönderilmişse hiçbir şey yapma
            if (res.headersSent) {
                logger.debug('Headers zaten gönderilmiş, error handling atlanıyor', { url: targetUrl });
                return;
            }

            logger.error('Proxy request hatası', {
                url: targetUrl.substring(0, 100),
                error: error.message,
                code: error.code,
                status: error.response?.status
            });

            // 403 Forbidden özel handling
            if (error.response && error.response.status === 403) {
                logger.warn('403 Forbidden - Fallback response kullanılıyor', { url: targetUrl });

                // JSON dosyaları için boş obje
                if (req.url.includes('.json')) {
                    res.status(200).type('application/json').send('{}');
                    return;
                }

                // Diğer dosya tipleri için normal fallback
                return this.handleProxyError(req, res, error);
            }

            this.handleProxyError(req, res, error);
        }
    }

    // URL'deki tüm İngilizce parametreleri Türkçe'ye zorla
    forceUrlToTurkish(url) {
        if (!url || typeof url !== 'string') return url;

        try {
            const urlObj = new URL(url);
            
            // Query parametrelerini düzenle
            const params = urlObj.searchParams;
            
            // lang parametresi
            if (params.has('lang')) {
                const langValue = params.get('lang');
                if (langValue === 'en' || langValue === 'eng' || langValue === 'english') {
                    params.set('lang', 'tur');
                }
            }
            
            // language parametresi
            if (params.has('language')) {
                const langValue = params.get('language');
                if (langValue === 'en' || langValue === 'eng' || langValue === 'english') {
                    params.set('language', 'tur');
                }
            }
            
            // locale parametresi
            if (params.has('locale')) {
                const localeValue = params.get('locale');
                if (localeValue === 'en' || localeValue === 'en-US' || localeValue === 'en-GB') {
                    params.set('locale', 'tr');
                }
            }
            
            // Path'deki /en/ ve /eng/ segmentlerini değiştir
            let pathname = urlObj.pathname;
            pathname = pathname.replace(/\/en\//g, '/tr/').replace(/\/eng\//g, '/tur/');
            urlObj.pathname = pathname;
            
            const finalUrl = urlObj.toString();
            
            if (finalUrl !== url) {
                logger.debug('🔄 URL Türkçe\'ye zorlandı', { original: url, turkish: finalUrl });
            }
            
            return finalUrl;
        } catch (error) {
            logger.debug('URL parse hatası, orijinal döndürülüyor', { url, error: error.message });
            return url;
        }
    }

    // Request header'larını hazırla
    buildRequestHeaders(req, url, isExternal) {
        const headers = { ...req.headers };

        // Cloudflare IP kontrolünü şaşırtmak için sahte ama gerçekçi bir IP ekle
        const randomIp = `176.234.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        headers['X-Forwarded-For'] = randomIp;
        headers['X-Real-IP'] = randomIp;

        // Host başlıklarını sil (Axios hedef URL'ye göre kendisi en doğru şekilde eklesin)
        delete headers['host'];
        delete headers['Host'];

        if (!isExternal) {
            headers.Origin = config.TARGET_ORIGIN;
            headers.Referer = config.TARGET_ORIGIN + '/';
        } else {
            headers.Origin = `https://${url.host}`;
            headers.Referer = `https://${url.host}/`;
        }

        // Proxy olduğunu ele veren ve sıkıştırma (bozuk karakter) yapan başlıkları sil
        const toRemove = ['cf-connecting-ip', 'cf-ipcountry', 'accept-encoding'];
        toRemove.forEach(h => delete headers[h]);

        // 🚀 KRİTİK: Dil header'larını ZORLA Türkçe yap
        headers['Accept-Language'] = 'tr-TR,tr;q=0.9';
        headers['x-lang'] = 'tr';
        headers['x-language'] = 'tur';
        headers['x-locale'] = 'tr-TR';
        
        // 🚀 KRİTİK: Türkçe dil cookie'lerini request'e ekle
        // Mevcut cookie'leri koru, Türkçe dil cookie'lerini ekle
        const turkishCookies = 'language=tur; lang=tr; locale=tr';
        if (headers['cookie']) {
            // Mevcut cookie'lerde dil cookie'leri varsa üzerine yaz
            let existingCookies = headers['cookie'];
            
            // İngilizce dil cookie'lerini temizle
            existingCookies = existingCookies.replace(/language=eng?[^;]*/gi, '');
            existingCookies = existingCookies.replace(/lang=eng?[^;]*/gi, '');
            existingCookies = existingCookies.replace(/locale=eng?[^;]*/gi, '');
            
            // Türkçe cookie'leri ekle
            headers['Cookie'] = `${existingCookies}; ${turkishCookies}`.replace(/^;\s*/, '').replace(/;\s*;/g, ';');
        } else {
            headers['Cookie'] = turkishCookies;
        }

        return headers;
    }


    // Retry mekanizması ile fetch - Gelişmiş versiyon (Production-ready)
    async fetchWithRetry(config, retries = 3) {
        const originalTimeout = config.timeout;
        let lastError = null;

        for (let i = 0; i < retries; i++) {
            try {
                // Her retry'da timeout'u artır (exponential backoff)
                config.timeout = originalTimeout + (i * 5000);

                logger.debug(`🔄 Fetch attempt ${i + 1}/${retries}`, {
                    url: config.url.substring(0, 100),
                    timeout: config.timeout
                });

                const response = await this.axiosInstance(config);

                // Başarılı response için log
                if (i > 0) {
                    logger.info(`✅ Request başarılı (${i + 1}. deneme)`, {
                        url: config.url.substring(0, 100),
                        status: response.status,
                        timeout: config.timeout
                    });
                }

                // Response code'u logla
                logger.debug(`📊 Upstream response`, {
                    url: config.url.substring(0, 100),
                    status: response.status,
                    contentType: response.headers['content-type'],
                    contentLength: response.headers['content-length']
                });

                return response;
            } catch (error) {
                lastError = error;
                const isLastRetry = i === retries - 1;

                // Timeout veya connection error'ları için özel handling
                if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT' || 
                    error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED' ||
                    error.code === 'ECONNRESET') {
                    
                    if (!isLastRetry) {
                        logger.warn(`⏱️ Connection Error - Retry ${i + 1}/${retries}`, {
                            url: config.url.substring(0, 100),
                            timeout: config.timeout,
                            error: error.code
                        });

                        // Exponential backoff (daha uzun bekleme)
                        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
                        continue;
                    }
                }

                // 5xx hatalar için retry
                if (error.response && error.response.status >= 500 && !isLastRetry) {
                    logger.warn(`🔄 Server Error - Retry ${i + 1}/${retries}`, {
                        url: config.url.substring(0, 100),
                        status: error.response.status,
                        error: error.message
                    });

                    await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
                    continue;
                }

                if (isLastRetry) {
                    logger.error('❌ Tüm retry denemeleri başarısız', {
                        url: config.url.substring(0, 100),
                        error: error.message,
                        code: error.code,
                        status: error.response?.status,
                        retries: retries
                    });
                    throw error;
                }
            }
        }

        // Bu noktaya gelmemeli ama safety için
        throw lastError || new Error('Fetch failed after retries');
    }

    // Response'u işle
    async processResponse(req, res, response, startTime) {
        // --- Headers Sent Hatasını Çözer (ERR_HTTP_HEADERS_SENT) ---
        if (res.headersSent) return;

        const responseTime = Date.now() - startTime;
        
        // Content-Type'ı al (bir kere tanımla)
        const contentType = (response.headers['content-type'] || '').toLowerCase();

        // ⚠️ FALLBACK SİSTEMİ DEVRE DIŞI - Orijinal response'u olduğu gibi ilet
        // API response'u boş olsa bile (status 200 ise) olduğu gibi gönder
        // SPA runtime orijinal yapıyı bekliyor, fallback objeleri runtime'ı bozuyor
        if (contentType.includes('application/json') && response.data) {
            try {
                const jsonStr = response.data.toString('utf8');
                const jsonData = JSON.parse(jsonStr);
                
                // Boş response'u logla ama FALLBACK GÖNDERME
                if (!jsonData || 
                    jsonData === null || 
                    Object.keys(jsonData).length === 0 ||
                    (Object.keys(jsonData).length === 1 && jsonData.status)) {
                    
                    logger.info('📭 API boş response döndü (olduğu gibi iletiliyor)', { 
                        url: req.url,
                        status: response.status,
                        keys: jsonData ? Object.keys(jsonData) : [],
                        rawResponse: jsonStr.substring(0, 200)
                    });
                    
                    // ❌ FALLBACK GÖNDERME - Orijinal response'u ilet
                    // SPA kendi fallback mantığını kullanacak
                }
            } catch (e) {
                // JSON parse hatası, normal akışa devam et
                logger.debug('JSON parse hatası, normal akışa devam', { error: e.message });
            }
        }

        // Header'ları temizle ve ayarla
        ProxyUtils.cleanHeaders(response.headers, res, req);
        res.status(response.status);

        // 🚀 KRİTİK: Türkçe dil cookie'lerini ZORLA ayarla - TÜM RESPONSE'LARDA
        const turkishCookies = [
            'language=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'selectedLanguage=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'lang=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'locale=tr; Path=/; Max-Age=31536000; SameSite=Lax',
            'i18n_language=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'currentLanguage=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'userLanguage=tur; Path=/; Max-Age=31536000; SameSite=Lax',
            'defaultLanguage=tur; Path=/; Max-Age=31536000; SameSite=Lax'
        ];

        // Mevcut Set-Cookie header'ları varsa koru, yoksa yeni ekle
        const existingCookies = res.getHeader('Set-Cookie') || [];
        const allCookies = Array.isArray(existingCookies) ? [...existingCookies, ...turkishCookies] : [existingCookies, ...turkishCookies];
        res.setHeader('Set-Cookie', allCookies);

        // Base64 şifreli URL'leri çöz ki dosya uzantısını görebilelim
        let targetPath = req.url;
        if (req.url.startsWith('/v21-proxy/')) {
            targetPath = ProxyUtils.decodeProxyUrl(req.url);
        }

        // CSS dosyaları için MIME type düzeltmesi (Artık targetPath kullanıyoruz)
        if (targetPath.includes('.css') || req.url.includes('custom.css')) {
            res.setHeader('Content-Type', 'text/css; charset=utf-8');
            logger.debug('🎨 CSS MIME type düzeltildi', { url: targetPath, originalType: contentType });
        }
        // JS dosyaları için MIME type düzeltmesi
        else if (targetPath.includes('.js')) {
            res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
            // JS dosyaları için ekstra anti-cache
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
            logger.debug('📜 JS MIME type ve anti-cache düzeltildi', { url: targetPath, originalType: contentType });
        }
        // JSON dosyaları için MIME type düzeltmesi
        else if (targetPath.includes('.json')) {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            logger.debug('📄 JSON MIME type düzeltildi', { url: targetPath, originalType: contentType });
        }
        // Text/plain olan CSS dosyalarını düzelt - Güçlendirilmiş
        else if (contentType.includes('text/plain')) {
            // URL'de css geçiyor veya content CSS benzeri ise
            if (req.url.includes('css') || req.url.includes('style')) {
                res.setHeader('Content-Type', 'text/css; charset=utf-8');
                logger.debug('🎨 Text/plain CSS düzeltildi', { url: req.url });
            }
            // Content'te CSS syntax'ı varsa
            else if (response.data && response.data.toString().includes('body') &&
                (response.data.toString().includes('{') || response.data.toString().includes('color'))) {
                res.setHeader('Content-Type', 'text/css; charset=utf-8');
                logger.debug('🎨 Content-based CSS düzeltildi', { url: req.url });
            }
        }
        // External domain'lerden gelen CSS dosyaları için özel handling
        else if (req.url.includes('v21-proxy') && (req.url.includes('css') || req.url.includes('style'))) {
            res.setHeader('Content-Type', 'text/css; charset=utf-8');
            logger.debug('🎨 External CSS MIME type düzeltildi', { url: req.url });
        }

        // JavaScript ve CSS dosyalarını ASLA işleme - Direkt gönder (SPA için kritik)
        if (contentType.includes('javascript') || contentType.includes('application/json') || 
            req.url.includes('.js') || req.url.includes('.mjs') || 
            targetPath.includes('.js') || targetPath.includes('.mjs')) {
            // JS dosyalarını direkt gönder, hiçbir işlem yapma
            res.send(response.data);
            logger.debug('📜 JS dosyası direkt gönderildi (işlenmedi)', { url: req.url });
        } else if (ProxyUtils.isTextContent(contentType) || req.url.includes('.css') || req.url.includes('.json')) {
            // Sadece HTML ve CSS içeriğini işle
            await this.processTextContent(req, res, response, contentType);
        } else {
            // Binary içeriği direkt gönder
            res.send(response.data);
        }

        // HTML dosyaları için ekstra anti-cache
        if (contentType.includes('text/html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }

        // Log kaydı
        logger.proxyRequest(req.method, req.url, response.status, responseTime);
    }

    // Text içeriğini işle (SADECE HTML ve CSS - JS ASLA İŞLENMEZ)
    async processTextContent(req, res, response, contentType) {
        let content = response.data.toString('utf8');
        const hostHeader = req.headers.host;

        // İçerik tipine göre işle
        if (contentType.includes('text/html')) {
            // 🚀 KRİTİK: HTML için Content-Type'ı zorla UTF-8 yap
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            content = await this.processHtmlContent(content, hostHeader);
        } else if (contentType.includes('application/json')) {
            content = this.processJsonContent(content, hostHeader);
        }

        // Global domain replacements (CMS images, vb.)
        content = content.replace(/cms\.btcoservice[0-9]{1,2}\.com/gi, 'cmsbetconstruct.com');

        // İngilizce içeriği Türkçe'ye çevir - SADECE JSON dosyalarında ve SADECE SPESIFIK PATTERN'LER
        if (req.url.includes('.json') && contentType.includes('application/json')) {
            // SADECE language key'lerini değiştir, genel string replacement yapma
            content = content.replace(/\"language\"\s*:\s*\"eng\"/gi, '"language":"tur"')
                .replace(/\"language\"\s*:\s*\"en\"/gi, '"language":"tr"')
                .replace(/\"selectedLanguage\"\s*:\s*\"eng\"/gi, '"selectedLanguage":"tur"')
                .replace(/\"selectedLanguage\"\s*:\s*\"en\"/gi, '"selectedLanguage":"tr"')
                .replace(/\"locale\"\s*:\s*\"en\"/gi, '"locale":"tr"')
                .replace(/\"defaultLanguage\"\s*:\s*\"eng\"/gi, '"defaultLanguage":"tur"')
                .replace(/\"defaultLanguage\"\s*:\s*\"en\"/gi, '"defaultLanguage":"tr"');

            logger.debug('🔄 JSON içeriğinde dil bilgileri Türkçe\'ye çevrildi', { url: req.url });
        }

        // URL'leri yeniden yaz
        content = ProxyUtils.rewriteContent(content, hostHeader);

        res.send(content);
    }

    // HTML içeriğini işle
    async processHtmlContent(content, hostHeader) {
        try {
            // 🚀 KRİTİK: HTML'i doğru decode et
            let html = content;
            
            // Buffer ise string'e çevir
            if (Buffer.isBuffer(html)) {
                html = Buffer.from(html).toString('utf-8');
                logger.debug('📄 HTML Buffer\'dan UTF-8 string\'e çevrildi');
            }
            
            // HTML çok küçükse veya boşsa Cheerio parsing'i atla
            if (!html || html.length < 100) {
                logger.warn('⚠️ HTML çok küçük veya boş, Cheerio parsing atlanıyor', { 
                    length: html ? html.length : 0 
                });
                return html;
            }
            
            // Cheerio load'u try-catch içinde yap
            let $;
            try {
                $ = cheerio.load(html);
                logger.debug('✅ Cheerio HTML parse başarılı', { htmlLength: html.length });
            } catch (cheerioError) {
                logger.error('❌ Cheerio HTML parse hatası, string replace fallback kullanılıyor', {
                    error: cheerioError.message,
                    htmlLength: html.length,
                    htmlPreview: html.substring(0, 200)
                });
                
                // Cheerio başarısız olursa string replace ile script inject et
                return this.injectScriptsWithStringReplace(html, hostHeader);
            }

            // Güvenlik header'larını kaldır
            $('script[integrity], link[integrity]').removeAttr('integrity');
            $('meta[http-equiv*="Content-Security-Policy"]').remove();

            // Cloudflare ve tracking scriptlerini tamamen kaldır
            $('script[src*="cloudflareinsights"]').remove();
            $('script[src*="beacon.min.js"]').remove();
            $('script[src*="cf-beacon"]').remove();
            $('script[data-cf-beacon]').remove();
            $('script[src*="google-analytics"]').remove();
            $('script[src*="googletagmanager"]').remove();
            $('script[src*="analytics"]').remove();
            $('script[src*="tracking"]').remove();

            // Service Worker scriptlerini tamamen engelle - Cache sorunlarını önler
            $('script:contains("serviceWorker")').remove();
            content = content.replace(/navigator\.serviceWorker\.register/g, 'console.log("SW disabled by V21 Proxy")');
            content = content.replace(/navigator\.serviceWorker/g, 'null');

            // Service Worker registration'ı tamamen devre dışı bırak
            const disableServiceWorkerScript = `
            <script>
            // Service Worker'ı tamamen devre dışı bırak
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.getRegistrations().then(function(registrations) {
                    for(let registration of registrations) {
                        registration.unregister();
                        console.log('🚫 Service Worker unregistered by V21 Proxy');
                    }
                });
            }
            // Service Worker API'sini override et
            Object.defineProperty(navigator, 'serviceWorker', {
                get: function() { return undefined; }
            });
            
            // 🚀 KRİTİK: RUNTIME DİL ZORLAMA SİSTEMİ - EN ERKEN AŞAMADA
            (function() {
                // 1. COOKIE ENFORCEMENT - Türkçe cookie'leri zorla
                document.cookie = 'language=tur; path=/; max-age=31536000; SameSite=Lax';
                document.cookie = 'selectedLanguage=tur; path=/; max-age=31536000; SameSite=Lax';
                document.cookie = 'lang=tur; path=/; max-age=31536000; SameSite=Lax';
                document.cookie = 'locale=tr; path=/; max-age=31536000; SameSite=Lax';
                document.cookie = 'i18n_language=tur; path=/; max-age=31536000; SameSite=Lax';
                document.cookie = 'currentLanguage=tur; path=/; max-age=31536000; SameSite=Lax';
                
                // 2. LOCALSTORAGE OVERRIDE - Dil değişkenlerini zorla Türkçe yap
                const o = Storage.prototype;
                const oSet = o.setItem, oGet = o.getItem;
                const keys = ['language','selectedLanguage','locale','i18n_language','currentLanguage','lang','userLanguage','defaultLanguage'];
                
                o.setItem = function(k,v) {
                    if(keys.includes(k) && (v==='eng'||v==='en'||v==='english')) {
                        v = (k==='locale')?'tr':'tur';
                    }
                    return oSet.call(this,k,v);
                };
                
                o.getItem = function(k) {
                    if(keys.includes(k)) {
                        const v = oGet.call(this,k);
                        if(v==='eng'||v==='en'||v==='english') { 
                            const t=(k==='locale')?'tr':'tur'; 
                            oSet.call(this,k,t); 
                            return t; 
                        }
                        if(!v||v===null||v==='null') { 
                            const t=(k==='locale')?'tr':'tur'; 
                            oSet.call(this,k,t); 
                            return t; 
                        }
                        return v;
                    }
                    return oGet.call(this,k);
                };
                
                // LocalStorage'ı hemen Türkçe'ye zorla
                try { 
                    keys.forEach(k => localStorage.setItem(k, (k==='locale')?'tr':'tur')); 
                } catch(e) {}
                
                // 3. URL ÇEVİRİCİ FONKSİYON - İngilizce parametreleri Türkçe'ye çevir
                const tr = (u) => {
                    if(!u||typeof u!=='string') return u;
                    
                    // External API'leri proxy'den geçir
                    if(u.indexOf('https://go.cmsbetconstruct.com') === 0) {
                        u = u.replace('https://go.cmsbetconstruct.com', '/api-proxy/go.cmsbetconstruct.com');
                    }
                    if(u.indexOf('https://cmsbetconstruct.com') === 0) {
                        u = u.replace('https://cmsbetconstruct.com', '/api-proxy/cmsbetconstruct.com');
                    }
                    if(u.indexOf('https://icons.cmsbetconstruct.com') === 0) {
                        u = u.replace('https://icons.cmsbetconstruct.com', '/api-proxy/icons.cmsbetconstruct.com');
                    }
                    if(u.indexOf('https://cms.btcoservice') !== -1) {
                        u = u.split('https://cms.btcoservice').join('/api-proxy/cms.btcoservice');
                    }
                    
                    // Dosya yollarını ve query parametrelerini Türkçe'ye çevir
                    return u.split('_eng.json').join('_tur.json')
                            .split('_en.json').join('_tur.json')
                            .split('/eng.json').join('/tur.json')
                            .split('/en.json').join('/tur.json')
                            .split('/eng/').join('/tur/')
                            .split('/en/').join('/tr/')
                            .split('lang=eng').join('lang=tur')
                            .split('lang=en').join('lang=tur')
                            .split('language=eng').join('language=tur')
                            .split('language=en').join('language=tur')
                            .split('locale=en').join('locale=tr')
                            .split('&eng&').join('&tur&')
                            .split('&en&').join('&tr&');
                };
                
                // 4. FETCH INTERCEPTOR - Tüm API çağrılarını yakala ve Türkçe'ye çevir
                if(window.fetch) { 
                    const f=window.fetch; 
                    window.fetch=function(u,o){
                        u = tr(u);
                        o = o || {};
                        o.timeout = o.timeout || 60000;
                        
                        // Header'lara Türkçe dil bilgisi ekle
                        o.headers = o.headers || {};
                        if(typeof o.headers.set === 'function') {
                            o.headers.set('Accept-Language', 'tr-TR,tr;q=0.9');
                            o.headers.set('x-lang', 'tr');
                            o.headers.set('x-language', 'tur');
                        } else {
                            o.headers['Accept-Language'] = 'tr-TR,tr;q=0.9';
                            o.headers['x-lang'] = 'tr';
                            o.headers['x-language'] = 'tur';
                        }
                        
                        return f.call(this,u,o).catch(err => {
                            console.warn('Fetch failed, returning empty data:', err);
                            return { ok: false, json: () => Promise.resolve({ data: [], items: [] }) };
                        });
                    }; 
                }
                
                // 5. XMLHttpRequest INTERCEPTOR - Eski API çağrılarını yakala
                if(window.XMLHttpRequest) { 
                    const x=XMLHttpRequest.prototype.open;
                    const xSetHeader=XMLHttpRequest.prototype.setRequestHeader;
                    
                    XMLHttpRequest.prototype.open=function(m,u){
                        this._url = tr(u);
                        this.timeout = 60000;
                        return x.call(this,m,this._url,arguments[2],arguments[3],arguments[4]);
                    };
                    
                    XMLHttpRequest.prototype.setRequestHeader=function(k,v){
                        xSetHeader.call(this,k,v);
                        // Türkçe header'ları ekle
                        if(!this._turkishHeadersSet) {
                            xSetHeader.call(this,'Accept-Language','tr-TR,tr;q=0.9');
                            xSetHeader.call(this,'x-lang','tr');
                            xSetHeader.call(this,'x-language','tur');
                            this._turkishHeadersSet = true;
                        }
                    };
                }
                
                // 6. AXIOS INTERCEPTOR - Axios kullanıyorsa onu da yakala
                setTimeout(function() {
                    if(window.axios) {
                        // Request interceptor
                        window.axios.interceptors.request.use(function(config) {
                            config.url = tr(config.url);
                            config.timeout = config.timeout || 60000;
                            config.headers = config.headers || {};
                            config.headers['Accept-Language'] = 'tr-TR,tr;q=0.9';
                            config.headers['x-lang'] = 'tr';
                            config.headers['x-language'] = 'tur';
                            return config;
                        });
                        console.log('🚀 Axios interceptor kuruldu');
                    }
                }, 100);
                
                console.log('🇹🇷 V21 Turkish Force RUNTIME loaded - REQUEST LEVEL enforcement active');
            })();
            </script>`;

            if (content.includes('<head>')) {
                content = content.replace('<head>', '<head>' + disableServiceWorkerScript);
            }

            // İngilizce dil referanslarını Türkçe'ye çevir - HTML içinde
            content = content.replace(/lang="en"/gi, 'lang="tr"')
                .replace(/language="en"/gi, 'language="tr"')
                .replace(/locale="en"/gi, 'locale="tr"')
                .replace(/hreflang="en"/gi, 'hreflang="tr"')
                .replace(/lang=en/gi, 'lang=tr')
                .replace(/language=en/gi, 'language=tr')
                .replace(/locale=en/gi, 'locale=tr');

            // 🚀 KRİTİK: HTML içindeki /en/ URL'lerini /tr/ yap - GÜÇLENDİRİLMİŞ
            content = content.replace(/href="\/en\/"/gi, 'href="/tr/"')
                .replace(/href='\/en\/'/gi, "href='/tr/'")
                .replace(/href="\/en"/gi, 'href="/tr"')
                .replace(/href='\/en'/gi, "href='/tr'")
                .replace(/href="([^"]*?)\/en\/([^"]*)"/gi, 'href="$1/tr/$2"')
                .replace(/href='([^']*?)\/en\/([^']*)'/gi, "href='$1/tr/$2'")
                .replace(/content="([^"]*?)\/en\/([^"]*)"/gi, 'content="$1/tr/$2"')
                .replace(/content='([^']*?)\/en\/([^']*)'/gi, "content='$1/tr/$2'");

            // Meta tag'lerdeki English kelimesini Turkish yap
            content = content.replace(/content="English"/gi, 'content="Turkish"')
                .replace(/content='English'/gi, "content='Turkish'");

            // Dil seçici dropdown'daki ENG yazısını TUR yap
            content = content.replace(/<span class="ellipsis">ENG<\/span>/gi, '<span class="ellipsis">TUR</span>')
                .replace(/<span class="ellipsis">EN<\/span>/gi, '<span class="ellipsis">TR</span>');

            // Flag icon'unu Türk bayrağı yap
            content = content.replace(/flag-bc unitedkingdom/gi, 'flag-bc turkey')
                .replace(/flag-bc uk/gi, 'flag-bc tr');

            // 🚀 KRİTİK: Menü dosyalarını Türkçe'ye çevir (HTML içinde hardcoded olanlar)
            content = content.replace(/header_menu_([0-9]+)_eng\.json/gi, 'header_menu_$1_tur.json')
                .replace(/app_menu_([0-9]+)_eng\.json/gi, 'app_menu_$1_tur.json')
                .replace(/footer_menu_([0-9]+)_eng\.json/gi, 'footer_menu_$1_tur.json')
                .replace(/menu_([0-9]+)_eng\.json/gi, 'menu_$1_tur.json')
                .replace(/_eng\.json/gi, '_tur.json')
                .replace(/_en\.json/gi, '_tur.json');

            // Translation dosyalarını Türkçe'ye çevir - HTML içinde
            content = content.replace(/\/translations\/[a-z]{2,3}\.json/gi, '/translations/tur.json');
            content = content.replace(/translations\/eng\.json/gi, 'translations/tur.json');
            content = content.replace(/translations\/en\.json/gi, 'translations/tur.json');

            // 🚀 KRİTİK: External API URL'lerini proxy'den geçir (HTML içinde)
            content = content.replace(/https:\/\/go\.cmsbetconstruct\.com/gi, '/api-proxy/go.cmsbetconstruct.com');
            content = content.replace(/https:\/\/cms\.btcoservice[0-9]+\.com/gi, '/api-proxy/cms.btcoservice.com');
            content = content.replace(/https:\/\/cmsbetconstruct\.com/gi, '/api-proxy/cmsbetconstruct.com');
            content = content.replace(/https:\/\/icons\.cmsbetconstruct\.com/gi, '/api-proxy/icons.cmsbetconstruct.com');

            // API URL'lerindeki İngilizce parametreleri Türkçe'ye çevir - HTML içinde
            content = content.replace(/\/api\/public\/v1\/eng\//gi, '/api/public/v1/tur/')
                .replace(/cmsbetconstruct\.com\/api\/public\/v1\/eng\//gi, 'cmsbetconstruct.com/api/public/v1/tur/')
                .replace(/casino\/getRecommendedGames\?([^"']*?)lang=eng/gi, 'casino/getRecommendedGames?$1lang=tur')
                .replace(/partners\/0\/components\/([^"']*?)\/eng\//gi, 'partners/0/components/$1/tur/')
                .replace(/partners\/0\/menus\/([^"']*?)\?([^"']*?)eng/gi, 'partners/0/menus/$1?$2tur');

            // 🚀 KRİTİK EKLENTİ: JavaScript içinde dil değişkenlerini KÖKTEN Türkçe yap (Fabrika ayarını boz)
            content = content.replace(/window\.language\s*=\s*["'][a-zA-Z]+["']/gi, 'window.language = "tur"')
                .replace(/window\.locale\s*=\s*["'][a-zA-Z]+["']/gi, 'window.locale = "tr"')
                .replace(/defaultLanguage\s*:\s*["'][a-zA-Z]+["']/gi, 'defaultLanguage: "tur"')
                .replace(/selectedLanguage\s*:\s*["'][a-zA-Z]+["']/gi, 'selectedLanguage: "tur"')
                .replace(/currentLanguage\s*:\s*["'][a-zA-Z]+["']/gi, 'currentLanguage: "tur"')
                .replace(/lang(uage)?\s*:\s*["']eng?["']/gi, 'language: "tur"');

            // Cloudflare beacon scriptlerini kaldır - Regex ile
            content = content.replace(/<script[^>]*cloudflareinsights[^>]*>.*?<\/script>/gis, '');
            content = content.replace(/<script[^>]*beacon\.min\.js[^>]*>.*?<\/script>/gis, '');
            content = content.replace(/<script[^>]*data-cf-beacon[^>]*>.*?<\/script>/gis, '');
            content = content.replace(/<script[^>]*cf-beacon[^>]*>.*?<\/script>/gis, '');

            // External script src'leri proxy'den geçir
            content = content.replace(/<script([^>]*)\ssrc=["']([^"']*service\.23i88jgks\.com[^"']*)["']([^>]*)>/gi,
                (match, before, src, after) => {
                    const encodedSrc = Buffer.from(src).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                    return `<script${before} src="/v21-proxy/${encodedSrc}"${after}>`;
                });

            content = content.replace(/<script([^>]*)\ssrc=["']([^"']*gstatic\.com[^"']*)["']([^>]*)>/gi,
                (match, before, src, after) => {
                    const encodedSrc = Buffer.from(src).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                    return `<script${before} src="/v21-proxy/${encodedSrc}"${after}>`;
                });

            content = content.replace(/<script([^>]*)\ssrc=["']([^"']*recaptcha\.net[^"']*)["']([^>]*)>/gi,
                (match, before, src, after) => {
                    const encodedSrc = Buffer.from(src).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                    return `<script${before} src="/v21-proxy/${encodedSrc}"${after}>`;
                });

            // 🚀 KRİTİK: icons.cmsbetconstruct.com resimlerini proxy'den geçir
            content = content.replace(/src="https:\/\/icons\.cmsbetconstruct\.com([^"]*)"/gi, (match, path) => {
                const fullUrl = 'https://icons.cmsbetconstruct.com' + path;
                const encodedSrc = Buffer.from(fullUrl).toString('base64')
                    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                return `src="/v21-proxy/${encodedSrc}"`;
            });

            content = content.replace(/src='https:\/\/icons\.cmsbetconstruct\.com([^']*)'/gi, (match, path) => {
                const fullUrl = 'https://icons.cmsbetconstruct.com' + path;
                const encodedSrc = Buffer.from(fullUrl).toString('base64')
                    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                return `src='/v21-proxy/${encodedSrc}'`;
            });


            // 🚀 KRİTİK: Runtime Interceptor Script'ini inject et
            const interceptorScript = `
            <script src="/interceptor.js"></script>
            `;

            // Script'i HTML'in EN BAŞINA ekle - <head> içine
            if (content.includes('<head>')) {
                content = content.replace('<head>', '<head>' + turkishForceScript + interceptorScript);
            } else if (content.includes('<html>')) {
                content = content.replace('<html>', '<html><head>' + turkishForceScript + interceptorScript + '</head>');
            } else {
                // DOCTYPE varsa ondan sonra değil, <head> yoksa en başa
                content = turkishForceScript + interceptorScript + content;
            }

            return content;
        } catch (error) {
            logger.warn('HTML işleme hatası', error);
            return content;
        }
    }

    // JavaScript içeriğini işle
    processJavaScriptContent(content) {
        // Translation dosyalarını Türkçe'ye çevir - EN ÖNEMLİ
        content = content.replace(/\/translations\/[a-z]{2,3}\.json/gi, '/translations/tur.json');
        content = content.replace(/translations\/eng\.json/gi, 'translations/tur.json');
        content = content.replace(/translations\/en\.json/gi, 'translations/tur.json');
        content = content.replace(/"translations\/eng\.json"/gi, '"translations/tur.json"');
        content = content.replace(/"translations\/en\.json"/gi, '"translations/tur.json"');
        content = content.replace(/'translations\/eng\.json'/gi, "'translations/tur.json'");
        content = content.replace(/'translations\/en\.json'/gi, "'translations/tur.json'");

        // Dil değişkenlerini Türkçe'ye zorla - SADECE SPESIFIK PATTERN'LER
        content = content.replace(/language\s*:\s*["']eng["']/gi, 'language: "tur"');
        content = content.replace(/selectedLanguage\s*:\s*["']eng["']/gi, 'selectedLanguage: "tur"');
        content = content.replace(/locale\s*:\s*["']en["']/gi, 'locale: "tr"');
        content = content.replace(/defaultLanguage\s*:\s*["']eng["']/gi, 'defaultLanguage: "tur"');

        // API URL'lerindeki İngilizce parametreleri Türkçe'ye çevir
        content = content.replace(/\/api\/public\/v1\/eng\//gi, '/api/public/v1/tur/')
            .replace(/lang=eng/gi, 'lang=tur')
            .replace(/language=eng/gi, 'language=tur')
            .replace(/locale=en/gi, 'locale=tr')
            .replace(/lang:\s*["']eng["']/gi, 'lang: "tur"')
            .replace(/language:\s*["']eng["']/gi, 'language: "tur"')
            .replace(/locale:\s*["']en["']/gi, 'locale: "tr"');

        // CMS BetConstruct API çağrılarını yakala ve değiştir
        content = content.replace(/cmsbetconstruct\.com\/api\/public\/v1\/eng\//gi, 'cmsbetconstruct.com/api/public/v1/tur/')
            .replace(/casino\/getRecommendedGames\?([^"']*?)lang=eng/gi, 'casino/getRecommendedGames?$1lang=tur')
            .replace(/partners\/0\/components\/([^"']*?)\/eng\//gi, 'partners/0/components/$1/tur/')
            .replace(/partners\/0\/menus\/([^"']*?)\?([^"']*?)eng/gi, 'partners/0/menus/$1?$2tur');

        // Integrity attribute'larını kaldır (SRI bypass)
        content = content.replace(/\.integrity\s*=\s*["'][^"']*["']/g, '.integrity = ""');
        content = content.replace(/integrity\s*:\s*["'][^"']*["']/g, 'integrity: ""');

        // TEHLİKELİ GLOBAL REPLACEMENT'LAR KALDIRILDI
        // .replace(/"eng"/gi, '"tur"') - Bu "length" gibi kelimeleri bozuyor!
        // .replace(/'eng'/gi, "'tur'") - Bu "length" gibi kelimeleri bozuyor!


        return content;
    }

    // JSON içeriğini işle (conf.json gibi)
    processJsonContent(content, hostHeader) {
        try {
            // Orijinal JSON'u parse et
            let jsonData = JSON.parse(content);
            
            // Orijinal JSON'u loglayalım (debugging için)
            const originalJson = JSON.stringify(jsonData);
            
            // Derin JSON taraması ve dil değişimi yapan recursive fonksiyon
            const forceTurkishInJson = (obj) => {
                for (let key in obj) {
                    if (typeof obj[key] === 'object' && obj[key] !== null) {
                        forceTurkishInJson(obj[key]);
                    } else if (typeof obj[key] === 'string') {
                        // SADECE tam eşleşmelerde değiştir
                        if (obj[key] === 'eng' || obj[key] === 'en') {
                            obj[key] = obj[key] === 'eng' ? 'tur' : 'tr';
                        }
                    }
                }
            };

            // Tüm JSON yapısında ingilizceleri türkçeye zorla
            forceTurkishInJson(jsonData);

            // ⚠️ SADECE MEVCUT ALANLARI DEĞİŞTİR, YENİ ALAN EKLEME!
            // Config JSON'larında ekstra zorlama - SADECE ALAN VARSA
            if (jsonData.hasOwnProperty('language') && (jsonData.language === 'eng' || jsonData.language === 'en')) {
                jsonData.language = "tur";
            }
            if (jsonData.hasOwnProperty('defaultLanguage') && (jsonData.defaultLanguage === 'eng' || jsonData.defaultLanguage === 'en')) {
                jsonData.defaultLanguage = "tur";
            }
            if (jsonData.hasOwnProperty('locale') && (jsonData.locale === 'en' || jsonData.locale === 'en-US' || jsonData.locale === 'en-GB')) {
                jsonData.locale = "tr-TR";
            }
            if (jsonData.hasOwnProperty('selectedLanguage') && (jsonData.selectedLanguage === 'eng' || jsonData.selectedLanguage === 'en')) {
                jsonData.selectedLanguage = "tur";
            }
            if (jsonData.hasOwnProperty('currentLanguage') && (jsonData.currentLanguage === 'eng' || jsonData.currentLanguage === 'en')) {
                jsonData.currentLanguage = "tur";
            }

            // 🚀 KRİTİK: Boş veya eksik array'leri doldur (React map hatalarını önler)
            const ensureArrays = (obj) => {
                const arrayKeys = ['data', 'items', 'contents', 'games', 'menus', 'list', 'results', 'widgets', 'components'];
                arrayKeys.forEach(key => {
                    if (obj.hasOwnProperty(key) && (!obj[key] || !Array.isArray(obj[key]))) {
                        obj[key] = [];
                    }
                });
                
                // Nested result objesi varsa onu da kontrol et
                if (obj.result && typeof obj.result === 'object') {
                    ensureArrays(obj.result);
                }
            };
            
            ensureArrays(jsonData);

            // WebSocket URL'lerini düzelt
            if (jsonData.swarm && jsonData.swarm.socketUrl) {
                const originalUrl = jsonData.swarm.socketUrl;
                // btcoservice domain'lerini proxy'den geçir
                if (originalUrl.includes('btcoservice')) {
                    const wsProxyUrl = `ws://${hostHeader}/ws-proxy?url=${encodeURIComponent(originalUrl)}`;
                    jsonData.swarm.socketUrl = wsProxyUrl;
                    logger.info('WebSocket URL düzeltildi', { original: originalUrl, new: wsProxyUrl });
                }
            }

            // Değişiklik varsa logla (debugging için)
            const modifiedJson = JSON.stringify(jsonData);
            if (originalJson !== modifiedJson) {
                logger.debug('📝 JSON içeriği değiştirildi', {
                    originalLength: originalJson.length,
                    modifiedLength: modifiedJson.length,
                    diff: {
                        language: jsonData.language,
                        locale: jsonData.locale,
                        defaultLanguage: jsonData.defaultLanguage
                    }
                });
            }

            return modifiedJson;
        } catch (error) {
            logger.debug('JSON parse hatası (Regex fallback kullanılıyor)', error);
            return content; // Parse edilemezse orijinal içeriği döndür, text process regex'i halletsin
        }
    }

    // Proxy hatalarını handle et - SADECE NETWORK ERROR'LARDA FALLBACK
    handleProxyError(req, res, error) {
        if (res.headersSent) return;

        // Base64 decode edilmiş URL'yi bul
        let targetUrl = req.url;
        if (req.url.startsWith('/v21-proxy/')) {
            targetUrl = ProxyUtils.decodeProxyUrl(req.url);
        }

        // Error tipini belirle
        const isNetworkError = error.code === 'ECONNABORTED' || 
                               error.code === 'ETIMEDOUT' || 
                               error.code === 'ENOTFOUND' || 
                               error.code === 'ECONNREFUSED' ||
                               error.code === 'ECONNRESET';
        
        const is5xxError = error.response && error.response.status >= 500;
        
        logger.error('⚠️ Proxy Hatası:', { 
            url: targetUrl, 
            error: error.message,
            code: error.code,
            status: error.response?.status,
            isNetworkError,
            is5xxError
        });

        // ⚠️ SADECE NETWORK ERROR veya 5xx HATALARDA FALLBACK KULLAN
        // 404, 403 gibi valid HTTP response'ları olduğu gibi ilet
        if (!isNetworkError && !is5xxError) {
            logger.info('📭 Valid HTTP error, fallback kullanılmıyor', { 
                status: error.response?.status,
                url: targetUrl 
            });
            
            // Orijinal error response'u ilet
            if (error.response) {
                res.status(error.response.status).send(error.response.data || '');
                return;
            }
        }

        // SADECE NETWORK ERROR/TIMEOUT/5xx İÇİN FALLBACK
        logger.warn('🔄 Network error/5xx tespit edildi, minimal fallback kullanılıyor', {
            url: targetUrl,
            errorType: isNetworkError ? 'network' : '5xx'
        });

        // Geo API için Türkiye fallback (sadece network error'da)
        if (targetUrl.includes('geo') || targetUrl.includes('location') || targetUrl.includes('ip')) {
            const geoFallback = {
                country_code: "TR",
                country_name: "Turkey",
                country: "Turkey",
                city: "Istanbul",
                region: "Istanbul",
                timezone: "Europe/Istanbul",
                latitude: 41.0082,
                longitude: 28.9784,
                currency: "TRY",
                language: "tr",
                locale: "tr-TR"
            };
            return res.status(200).json(geoFallback);
        }

        // CSS dosyaları için minimal fallback
        if (targetUrl.includes('.css')) {
            return res.status(200).type('text/css').send('/* V21 Fallback CSS - Network Error */');
        }

        // JSON/API istekleri için minimal boş obje (SPA kendi fallback'ini kullanacak)
        if (targetUrl.includes('.json') || targetUrl.includes('/api/')) {
            logger.info('📭 Minimal boş JSON fallback gönderiliyor (network error)', { url: targetUrl });
            return res.status(200).json({});
        }

        // Diğer dosyalar için boş response
        res.status(200).send('');
    }

    // Error response gönder
    sendErrorResponse(res, status, message) {
        if (!res.headersSent) {
            res.status(status).json({ error: message, timestamp: new Date().toISOString() });
        }
    }

    // Cheerio başarısız olduğunda string replace ile script inject et
    injectScriptsWithStringReplace(html, hostHeader) {
        logger.info('🔧 String replace fallback ile script injection yapılıyor');
        
        // Service Worker devre dışı bırakma scripti
        const disableServiceWorkerScript = `
        <script>
        // Service Worker'ı tamamen devre dışı bırak
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.getRegistrations().then(function(registrations) {
                for(let registration of registrations) {
                    registration.unregister();
                    console.log('🚫 Service Worker unregistered by V21 Proxy');
                }
            });
        }
        // Service Worker API'sini override et
        Object.defineProperty(navigator, 'serviceWorker', {
            get: function() { return undefined; }
        });
        
        // 🚀 KRİTİK: RUNTIME DİL ZORLAMA SİSTEMİ - EN ERKEN AŞAMADA
        (function() {
            // 1. COOKIE ENFORCEMENT - Türkçe cookie'leri zorla
            document.cookie = 'language=tur; path=/; max-age=31536000; SameSite=Lax';
            document.cookie = 'selectedLanguage=tur; path=/; max-age=31536000; SameSite=Lax';
            document.cookie = 'lang=tur; path=/; max-age=31536000; SameSite=Lax';
            document.cookie = 'locale=tr; path=/; max-age=31536000; SameSite=Lax';
            document.cookie = 'i18n_language=tur; path=/; max-age=31536000; SameSite=Lax';
            document.cookie = 'currentLanguage=tur; path=/; max-age=31536000; SameSite=Lax';
            
            // 2. LOCALSTORAGE OVERRIDE - Dil değişkenlerini zorla Türkçe yap
            const o = Storage.prototype;
            const oSet = o.setItem, oGet = o.getItem;
            const keys = ['language','selectedLanguage','locale','i18n_language','currentLanguage','lang','userLanguage','defaultLanguage'];
            
            o.setItem = function(k,v) {
                if(keys.includes(k) && (v==='eng'||v==='en'||v==='english')) {
                    v = (k==='locale')?'tr':'tur';
                }
                return oSet.call(this,k,v);
            };
            
            o.getItem = function(k) {
                if(keys.includes(k)) {
                    const v = oGet.call(this,k);
                    if(v==='eng'||v==='en'||v==='english') { 
                        const t=(k==='locale')?'tr':'tur'; 
                        oSet.call(this,k,t); 
                        return t; 
                    }
                    if(!v||v===null||v==='null') { 
                        const t=(k==='locale')?'tr':'tur'; 
                        oSet.call(this,k,t); 
                        return t; 
                    }
                    return v;
                }
                return oGet.call(this,k);
            };
            
            // LocalStorage'ı hemen Türkçe'ye zorla
            try { 
                keys.forEach(k => localStorage.setItem(k, (k==='locale')?'tr':'tur')); 
            } catch(e) {}
            
            console.log('🇹🇷 V21 Turkish Force RUNTIME loaded (String Replace Fallback)');
        })();
        </script>`;
        
        // <head> tag'i varsa içine inject et
        if (html.includes('<head>')) {
            html = html.replace('<head>', '<head>' + disableServiceWorkerScript);
        } 
        // <html> tag'i varsa yeni head oluştur
        else if (html.includes('<html>')) {
            html = html.replace('<html>', '<html><head>' + disableServiceWorkerScript + '</head>');
        } 
        // Hiçbiri yoksa en başa ekle
        else {
            html = disableServiceWorkerScript + html;
        }
        
        // Temel temizlik işlemleri
        html = html.replace(/<script[^>]*cloudflareinsights[^>]*>.*?<\/script>/gis, '');
        html = html.replace(/<script[^>]*beacon\.min\.js[^>]*>.*?<\/script>/gis, '');
        html = html.replace(/<script[^>]*data-cf-beacon[^>]*>.*?<\/script>/gis, '');
        
        // Dil değiştirmeleri
        html = html.replace(/lang="en"/gi, 'lang="tr"');
        html = html.replace(/language="en"/gi, 'language="tr"');
        html = html.replace(/href="\/en\/"/gi, 'href="/tr/"');
        html = html.replace(/href='\/en\/'/gi, "href='/tr/'");
        
        logger.info('✅ String replace fallback tamamlandı');
        return html;
    }
}

module.exports = HttpHandler;
