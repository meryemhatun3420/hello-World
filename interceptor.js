// 🚀 V21 UNIVERSAL RUNTIME INTERCEPTOR - Production Ready
// TÜM external domain'leri /api-proxy/{host}/{path} formatında proxy'den geçirir
// Domain whitelist YOK - Evrensel proxy sistemi

(function() {
    'use strict';

    // ============================================
    // KONFİGÜRASYON
    // ============================================
    const CONFIG = {
        PROXY_PREFIX: '/api-proxy/',
        DEBUG: true, // Production'da false yapılabilir
        IGNORE_PATTERNS: [
            /^data:/,
            /^blob:/,
            /^chrome-extension:/,
            /^moz-extension:/,
            /^about:/,
            /^javascript:/
        ]
    };

    // Debug logger
    const log = {
        info: (...args) => CONFIG.DEBUG && console.log('🔵 [Interceptor]', ...args),
        warn: (...args) => CONFIG.DEBUG && console.warn('⚠️ [Interceptor]', ...args),
        error: (...args) => console.error('🔴 [Interceptor]', ...args),
        success: (...args) => CONFIG.DEBUG && console.log('✅ [Interceptor]', ...args),
        proxy: (original, proxied) => CONFIG.DEBUG && console.log('🔄 [Proxy]', original, '→', proxied)
    };

    // ============================================
    // URL İŞLEME FONKSİYONLARI
    // ============================================

    // URL'nin external olup olmadığını kontrol et (EVRENSEL - Whitelist yok)
    function isExternalUrl(url) {
        if (!url || typeof url !== 'string') return false;

        // Ignore pattern'leri kontrol et
        if (CONFIG.IGNORE_PATTERNS.some(pattern => pattern.test(url))) {
            return false;
        }

        // Relative URL'ler external değil
        if (url.startsWith('/') && !url.startsWith('//')) {
            return false;
        }

        try {
            // 🚀 KRİTİK FIX: Absolute URL'leri yakalamak için location.href base kullan
            const urlObj = new URL(url, window.location.href);
            const currentHost = window.location.host;

            // Aynı host ise external değil
            if (urlObj.host === currentHost) {
                return false;
            }

            // 🚀 KRİTİK: TÜM external domain'ler proxy'den geçecek (whitelist yok)
            // Absolute HTTPS/HTTP URL'leri de yakalıyoruz
            return true;
        } catch (e) {
            log.warn('URL parse hatası:', url, e);
            return false;
        }
    }

    // URL'yi evrensel proxy formatına çevir: /api-proxy/{host}/{path}
    function rewriteUrl(url) {
        if (!url || typeof url !== 'string') return url;

        // Zaten proxy'den geçiyorsa dokunma
        if (url.includes(CONFIG.PROXY_PREFIX)) {
            return url;
        }

        // External değilse dokunma
        if (!isExternalUrl(url)) {
            return url;
        }

        try {
            // 🚀 KRİTİK FIX: Absolute URL'leri yakalamak için location.href base kullan
            let absoluteUrl = url;
            if (url.startsWith('//')) {
                absoluteUrl = window.location.protocol + url;
            } else if (!url.startsWith('http://') && !url.startsWith('https://')) {
                absoluteUrl = new URL(url, window.location.href).href;
            }

            const urlObj = new URL(absoluteUrl);
            
            // 🚀 EVRENSEL PROXY FORMAT: /api-proxy/{host}/{path}?{query}#{hash}
            const proxyUrl = `${CONFIG.PROXY_PREFIX}${urlObj.host}${urlObj.pathname}${urlObj.search}${urlObj.hash}`;
            
            log.proxy(url, proxyUrl);
            return proxyUrl;
        } catch (e) {
            log.error('URL rewrite hatası:', url, e);
            return url;
        }
    }

    // ============================================
    // FETCH OVERRIDE
    // ============================================
    const originalFetch = window.fetch;
    window.fetch = function(resource, options = {}) {
        try {
            // URL'yi al (Request object veya string olabilir)
            let url = typeof resource === 'string' ? resource : resource.url;
            const rewrittenUrl = rewriteUrl(url);

            // URL değiştiyse yeni request oluştur
            if (rewrittenUrl !== url) {
                log.success('Fetch intercepted:', url, '→', rewrittenUrl);
                
                // Request object ise clone et ve URL'yi değiştir
                if (resource instanceof Request) {
                    resource = new Request(rewrittenUrl, resource);
                } else {
                    resource = rewrittenUrl;
                }
            }

            // Timeout ekle (yoksa)
            if (!options.signal) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 saniye
                options.signal = controller.signal;
                
                // Cleanup
                const originalThen = Promise.prototype.then;
                return originalFetch.call(this, resource, options)
                    .then(response => {
                        clearTimeout(timeoutId);
                        return response;
                    })
                    .catch(error => {
                        clearTimeout(timeoutId);
                        throw error;
                    });
            }

            // Original fetch'i çağır
            return originalFetch.call(this, resource, options)
                .catch(error => {
                    log.error('Fetch error:', url, error);
                    
                    // Network hatası - boş response döndür (SPA çökmesin)
                    if (error.name === 'TypeError' || error.name === 'AbortError') {
                        return new Response(JSON.stringify({ 
                            data: [], 
                            items: [],
                            status: 'error',
                            message: 'Network error',
                            error: error.message
                        }), {
                            status: 200,
                            headers: { 'Content-Type': 'application/json' }
                        });
                    }
                    
                    throw error;
                });
        } catch (e) {
            log.error('Fetch override hatası:', e);
            return originalFetch.apply(this, arguments);
        }
    };

    // ============================================
    // XMLHttpRequest OVERRIDE
    // ============================================
    const OriginalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
        const xhr = new OriginalXHR();
        const originalOpen = xhr.open;

        xhr.open = function(method, url, ...args) {
            try {
                const rewrittenUrl = rewriteUrl(url);
                
                if (rewrittenUrl !== url) {
                    log.success('XHR intercepted:', url, '→', rewrittenUrl);
                    return originalOpen.call(this, method, rewrittenUrl, ...args);
                }
                
                return originalOpen.call(this, method, url, ...args);
            } catch (e) {
                log.error('XHR open hatası:', e);
                return originalOpen.apply(this, arguments);
            }
        };

        // Error handling - XHR çökmesin
        const originalSend = xhr.send;
        xhr.send = function(...args) {
            try {
                // Timeout ekle (30 saniye)
                if (!xhr.timeout) {
                    xhr.timeout = 30000;
                }

                // Error handler ekle
                const originalOnError = xhr.onerror;
                xhr.onerror = function(e) {
                    log.error('XHR error:', xhr.responseURL, e);
                    if (originalOnError) {
                        originalOnError.call(this, e);
                    }
                };

                // Timeout handler ekle
                const originalOnTimeout = xhr.ontimeout;
                xhr.ontimeout = function(e) {
                    log.error('XHR timeout:', xhr.responseURL, e);
                    if (originalOnTimeout) {
                        originalOnTimeout.call(this, e);
                    }
                };

                return originalSend.apply(this, args);
            } catch (e) {
                log.error('XHR send hatası:', e);
                return originalSend.apply(this, arguments);
            }
        };

        return xhr;
    };

    // XHR prototype'ı koru
    window.XMLHttpRequest.prototype = OriginalXHR.prototype;

    // ============================================
    // WEBSOCKET OVERRIDE
    // ============================================
    const OriginalWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        try {
            // 🚀 KRİTİK FIX: WebSocket URL'lerini de proxy'den geçir
            let wsUrl = url;
            
            // External WebSocket URL'leri tespit et
            if (isExternalUrl(url)) {
                log.success('WebSocket intercepted:', url);
                
                // WebSocket URL'yi proxy formatına çevir
                const rewrittenUrl = rewriteUrl(url);
                
                // Proxy URL'yi WebSocket formatına çevir
                // /api-proxy/host/path -> ws://localhost/api-proxy/host/path
                wsUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + 
                        window.location.host + rewrittenUrl;
                
                log.proxy('WebSocket URL rewritten:', url, '→', wsUrl);
            }
            
            const ws = protocols 
                ? new OriginalWebSocket(wsUrl, protocols)
                : new OriginalWebSocket(wsUrl);

            // Error handling
            ws.addEventListener('error', (e) => {
                log.error('WebSocket error:', url, e);
            });

            ws.addEventListener('close', (e) => {
                log.warn('WebSocket closed:', url, 'code:', e.code, 'reason:', e.reason);
            });

            ws.addEventListener('open', () => {
                log.success('WebSocket connected:', url);
            });

            return ws;
        } catch (e) {
            log.error('WebSocket override hatası:', e);
            return new OriginalWebSocket(url, protocols);
        }
    };

    // WebSocket prototype'ı koru
    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;

    // ============================================
    // DOM MUTATION OBSERVER - Runtime URL Rewrite
    // ============================================
    let observerActive = false;
    const processedElements = new WeakSet();

    function rewriteDomUrls(element) {
        // Zaten işlenmişse atla (memory leak önleme)
        if (processedElements.has(element)) return;
        processedElements.add(element);

        try {
            // <img src="...">
            if (element.tagName === 'IMG' && element.src) {
                const rewritten = rewriteUrl(element.src);
                if (rewritten !== element.src) {
                    log.info('IMG src rewrite:', element.src, '→', rewritten);
                    element.src = rewritten;
                }
            }

            // <script src="...">
            if (element.tagName === 'SCRIPT' && element.src) {
                const rewritten = rewriteUrl(element.src);
                if (rewritten !== element.src) {
                    log.info('SCRIPT src rewrite:', element.src, '→', rewritten);
                    element.src = rewritten;
                }
            }

            // <link href="...">
            if (element.tagName === 'LINK' && element.href) {
                const rewritten = rewriteUrl(element.href);
                if (rewritten !== element.href) {
                    log.info('LINK href rewrite:', element.href, '→', rewritten);
                    element.href = rewritten;
                }
            }

            // <iframe src="...">
            if (element.tagName === 'IFRAME' && element.src) {
                const rewritten = rewriteUrl(element.src);
                if (rewritten !== element.src) {
                    log.info('IFRAME src rewrite:', element.src, '→', rewritten);
                    element.src = rewritten;
                }
            }

            // <video>, <audio>, <source>
            if ((element.tagName === 'VIDEO' || element.tagName === 'AUDIO' || element.tagName === 'SOURCE') && element.src) {
                const rewritten = rewriteUrl(element.src);
                if (rewritten !== element.src) {
                    log.info(`${element.tagName} src rewrite:`, element.src, '→', rewritten);
                    element.src = rewritten;
                }
            }

            // Background image (inline style)
            if (element.style && element.style.backgroundImage) {
                const bgImage = element.style.backgroundImage;
                const urlMatch = bgImage.match(/url\(['"]?([^'"]+)['"]?\)/);
                if (urlMatch && urlMatch[1]) {
                    const rewritten = rewriteUrl(urlMatch[1]);
                    if (rewritten !== urlMatch[1]) {
                        log.info('Background image rewrite:', urlMatch[1], '→', rewritten);
                        element.style.backgroundImage = `url('${rewritten}')`;
                    }
                }
            }

            // srcset attribute (responsive images)
            if (element.srcset) {
                const srcsetParts = element.srcset.split(',').map(part => {
                    const [url, descriptor] = part.trim().split(/\s+/);
                    const rewritten = rewriteUrl(url);
                    return descriptor ? `${rewritten} ${descriptor}` : rewritten;
                });
                const newSrcset = srcsetParts.join(', ');
                if (newSrcset !== element.srcset) {
                    log.info('SRCSET rewrite:', element.srcset, '→', newSrcset);
                    element.srcset = newSrcset;
                }
            }
        } catch (e) {
            log.error('DOM rewrite hatası:', element, e);
        }
    }

    // MutationObserver - DOM değişikliklerini izle
    function startDomObserver() {
        if (observerActive) return;
        observerActive = true;

        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                // Yeni eklenen node'ları işle
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        rewriteDomUrls(node);
                        
                        // Alt element'leri de işle
                        node.querySelectorAll('img, script, link, iframe, video, audio, source').forEach(rewriteDomUrls);
                    }
                });

                // Attribute değişikliklerini işle
                if (mutation.type === 'attributes' && mutation.target.nodeType === Node.ELEMENT_NODE) {
                    rewriteDomUrls(mutation.target);
                }
            });
        });

        // Observer'ı başlat
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['src', 'href', 'style', 'srcset']
        });

        log.success('DOM Observer aktif');
    }

    // ============================================
    // BAŞLATMA
    // ============================================
    function initialize() {
        log.success('🚀 V21 Universal Interceptor yüklendi');
        log.info('Proxy prefix:', CONFIG.PROXY_PREFIX);
        log.info('Mode: UNIVERSAL (tüm external domain\'ler proxy\'den geçer)');

        // Mevcut DOM'u tara
        document.querySelectorAll('img, script, link, iframe, video, audio, source').forEach(rewriteDomUrls);

        // DOM Observer'ı başlat
        startDomObserver();

        // Performance monitoring
        if (CONFIG.DEBUG) {
            let stats = { fetch: 0, xhr: 0, ws: 0, dom: 0 };

            // Stats'ı periyodik olarak göster
            setInterval(() => {
                if (stats.fetch > 0 || stats.xhr > 0 || stats.ws > 0 || stats.dom > 0) {
                    log.info('📊 Interceptor Stats:', stats);
                    stats = { fetch: 0, xhr: 0, ws: 0, dom: 0 };
                }
            }, 30000); // Her 30 saniyede bir

            // Global window'a stats ekle (debug için)
            window.__v21InterceptorStats = stats;
        }
    }

    // DOM hazır olduğunda başlat
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

    // Global error handler - Uncaught errors'ı yakala
    window.addEventListener('error', (e) => {
        if (e.message && (e.message.includes('fetch') || e.message.includes('network'))) {
            log.error('Global network error:', e.message);
            e.preventDefault(); // Hatayı yut, sayfa çökmesin
        }
    }, true);

    // Unhandled promise rejection handler
    window.addEventListener('unhandledrejection', (e) => {
        if (e.reason && e.reason.message && 
            (e.reason.message.includes('fetch') || e.reason.message.includes('network'))) {
            log.error('Unhandled network rejection:', e.reason.message);
            e.preventDefault(); // Hatayı yut, sayfa çökmesin
        }
    });

    // Global API - Debug ve test için
    window.__v21Interceptor = {
        version: '2.0.0',
        config: CONFIG,
        rewriteUrl: rewriteUrl,
        isExternalUrl: isExternalUrl,
        stats: window.__v21InterceptorStats || {}
    };

    log.success('🚀 Universal Interceptor hazır - TÜM external istekler proxy\'den geçecek');
})();
