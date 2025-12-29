/**
 * Jenalizers v3.1
 * Advanced Endpoint & Secret Extractor for Bug Bounty
 * Author: 0xV0RT3X (Cy-S3c)
 * GitHub: https://github.com/Cy-S3c/Jenalizers
 *
 * CHANGELOG v3.1:
 * - FIXED: Endpoint regex was capturing numeric literals (10, 11, 12...)
 * - FIXED: Domain regex was matching JS property access (n.gm.setTimeout, Object.values)
 * - FIXED: Minified variable patterns (r.d, e.o, s.i) filtered out
 * - Added comprehensive JS pattern exclusion
 * - Endpoints must now start with / or be valid URL-like patterns
 * - Better filtering of array indices and numeric values
 * - Added path length minimum (3+ chars after /)
 *
 * CHANGELOG v3.0:
 * - Fixed domain enumeration (was matching JS object paths)
 * - Added TLD validation for domains
 * - Better deduplication
 * - Added subdomain grouping
 * - Improved secret detection with context
 * - Added path normalization
 * - Better filtering of false positives
 * - Added interesting endpoints highlighting
 * - Export improvements
 */

(function() {
    'use strict';

    console.log('[Jenalizers v3.1] Starting...');

    // Valid TLDs for domain validation (common ones)
    const VALID_TLDS = new Set([
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
        'co', 'io', 'ai', 'app', 'dev', 'cloud', 'tech', 'online',
        'au', 'uk', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'ru', 'ca',
        'com.au', 'co.uk', 'co.jp', 'com.br', 'co.in', 'com.cn',
        'info', 'biz', 'me', 'tv', 'cc', 'xyz', 'site', 'store',
        'blog', 'shop', 'club', 'live', 'pro', 'name', 'mobi'
    ]);

    // Known JS/code patterns to exclude from domains (comprehensive list)
    const JS_PATTERNS = new Set([
        // Core JS objects
        'module.exports', 'window.location', 'document.location',
        'console.log', 'console.error', 'console.warn', 'console.info', 'console.debug',
        'object.keys', 'object.values', 'object.entries', 'object.assign', 'object.create',
        'array.prototype', 'array.from', 'array.isarray',
        'string.prototype', 'string.fromcharcode',
        'function.prototype', 'function.call', 'function.apply', 'function.bind',
        'promise.resolve', 'promise.reject', 'promise.all', 'promise.race',
        'number.isnan', 'number.isfinite', 'number.parseint', 'number.parsefloat',
        'math.random', 'math.floor', 'math.ceil', 'math.round', 'math.max', 'math.min',
        'json.parse', 'json.stringify',
        'date.now', 'date.parse',
        'error.captureStackTrace',
        'symbol.iterator', 'symbol.for',
        'regexp.prototype',
        'map.prototype', 'set.prototype', 'weakmap.prototype', 'weakset.prototype',
        // Framework patterns
        'react.component', 'react.createelement', 'react.fragment', 'react.memo',
        'react.usestate', 'react.useeffect', 'react.usecontext', 'react.usememo',
        'vue.component', 'vue.directive', 'vue.mixin',
        'angular.module', 'angular.component', 'angular.service',
        'jquery.fn', 'jquery.ajax', 'jquery.get', 'jquery.post',
        // Context/this patterns
        'this.props', 'this.state', 'this.context', 'this.refs',
        'this.setstate', 'this.forceupdate', 'this.render',
        // Event patterns
        'e.target', 'e.preventdefault', 'e.stoppropagation', 'e.currenttarget',
        'event.target', 'event.preventdefault', 'event.stoppropagation',
        // Environment
        'node.env', 'process.env', 'webpack.config', 'babel.config',
        // New Relic (common in the target)
        'window.nreum', 'nreum.info', 'nreum.loader', 'nreum.init',
        // Analytics patterns
        'gtag.config', 'ga.create', 'fbq.track', 'analytics.track'
    ]);

    // Pattern to detect minified JS variable access (a.b, r.d, n.gm.x patterns)
    const MINIFIED_PATTERN = /^[a-z](?:\.[a-z]{1,3})+$/i;

    // Pattern to detect JS built-in access
    const JS_BUILTIN_PATTERN = /^(window|document|console|object|array|string|function|promise|number|math|json|date|error|symbol|regexp|map|set|weakmap|weakset|reflect|proxy|intl|atomics|sharedarraybuffer|dataview|arraybuffer|typedarray|uint8array|int8array|uint16array|int16array|uint32array|int32array|float32array|float64array|bigint64array|biguint64array)\./i;

    // Results storage
    const results = {
        endpoints: new Map(),
        apiEndpoints: new Set(),
        adminPaths: new Set(),
        interestingPaths: new Set(),
        parameters: new Map(),
        jsFiles: new Set(),
        secrets: [],
        domains: new Map(),  // Changed to Map for grouping by root domain
        subdomains: new Map(),
        emails: new Set(),
        ipAddresses: new Set(),
        urls: new Set(),
        timestamps: {
            start: new Date().toISOString(),
            end: null
        },
        stats: {
            scriptsAnalyzed: 0,
            fetchErrors: 0,
            totalBytesAnalyzed: 0
        },
        target: window.location.origin,
        targetDomain: window.location.hostname
    };

    // Regex patterns - IMPROVED v3.1
    const PATTERNS = {
        // Endpoints - FIXED: Must start with /, have 3+ chars, exclude numeric-only paths
        // Matches: /api, /users/123, /api/v1/users but NOT: 10, abc, 123
        endpoint: /(?:["'`])(\/[a-zA-Z][a-zA-Z0-9_\-]*(?:\/[a-zA-Z0-9_\-\.:@\[\]{}]*)*(?:\?[^"'`\s]*)?)(?:["'`])/g,

        // API Endpoints
        apiEndpoint: /(?:["'`])(\/api\/v?\d*\/?[a-zA-Z0-9_\-\.\/:\[\]{}?&=]*)(?:["'`])/gi,
        graphql: /(?:["'`])(\/graphql[a-zA-Z0-9_\-\.\/]*)(?:["'`])/gi,

        // REST patterns
        restEndpoint: /(?:["'`])(\/(?:users?|posts?|comments?|articles?|products?|orders?|items?|messages?|notifications?|settings?|profiles?|accounts?|auth|login|logout|register|signup|password|reset|verify|confirm|upload|download|export|import|search|filter|sort|paginate)(?:\/[a-zA-Z0-9_\-\.:]*)*(?:\?[^"'`]*)?)(?:["'`])/gi,

        // JS Files
        jsFile: /(?:["'`])((?:https?:\/\/[^"'`\s]+\/|\/)?[a-zA-Z0-9_\-\.\/]+\.(?:js|mjs|jsx|ts|tsx)(?:\?[^"'`\s]*)?)(?:["'`])/gi,

        // IMPROVED Domain detection - requires protocol or proper context
        domainInUrl: /https?:\/\/([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})/gi,

        // Standalone domain (more strict - must have valid TLD pattern)
        standaloneDomain: /(?:^|[\s"'`<>@])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(?:com|org|net|edu|gov|io|co|ai|app|dev|cloud|au|uk|de|fr|jp|cn|in|br|ru|ca|info|biz|me|tv|xyz|site|store|blog|shop|club|live|pro|tech|online)(?:\.[a-z]{2})?)(?:[\s"'`<>:/]|$)/gi,

        // Full URLs
        fullUrl: /https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+(?::[0-9]+)?(?:\/[^\s"'`<>]*)?/gi,

        // Secrets & Keys - improved with context
        awsAccessKey: /(?:aws_access_key_id|aws_key|access_key)[\s]*[=:]["']?\s*(AKIA[A-Z0-9]{16})/gi,
        awsAccessKeyRaw: /(AKIA[A-Z0-9]{16})/g,
        awsSecretKey: /(?:aws_secret_access_key|aws_secret|secret_key)[\s]*[=:]["']?\s*([a-zA-Z0-9+\/]{40})/gi,
        googleApiKey: /(AIza[0-9A-Za-z_-]{35})/g,
        googleOAuth: /([0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com)/gi,
        githubToken: /((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})/g,
        githubOAuth: /(?:client_secret|oauth)[\s]*[=:][\s]*["']?([a-f0-9]{40})/gi,
        jwtToken: /(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
        privateKey: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
        genericApiKey: /(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?key|app[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)[\s]*[=:]["'\s]*([a-zA-Z0-9_\-]{20,})/gi,
        genericPassword: /(?:password|passwd|pwd|pass)[\s]*[=:]["'\s]*([^\s"']{8,50})/gi,
        genericSecret: /(?:secret|token|credential|auth)[\s]*[=:]["'\s]*([a-zA-Z0-9_\-]{16,})/gi,
        firebaseUrl: /(https:\/\/[a-z0-9-]+\.firebaseio\.com)/gi,
        firebaseConfig: /(https:\/\/[a-z0-9-]+\.firebaseapp\.com)/gi,
        s3Bucket: /((?:https?:\/\/)?[a-zA-Z0-9.-]+\.s3(?:\.[a-zA-Z0-9-]+)?\.amazonaws\.com)/gi,
        s3BucketPath: /(s3:\/\/[a-zA-Z0-9.\-_]+)/gi,
        slackWebhook: /(https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+)/gi,
        slackToken: /(xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+)/gi,
        stripeKey: /(sk_live_[a-zA-Z0-9]{24,})/gi,
        stripePubKey: /(pk_live_[a-zA-Z0-9]{24,})/gi,
        herokuApiKey: /(heroku_api_key[\s]*[=:][\s]*["']?[a-f0-9-]{36})/gi,
        twilioSid: /(AC[a-f0-9]{32})/gi,
        twilioToken: /(?:twilio.*token|auth_token)[\s]*[=:][\s]*["']?([a-f0-9]{32})/gi,
        sendgridKey: /(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})/gi,
        mailgunKey: /(key-[a-f0-9]{32})/gi,

        // Sensitive data
        email: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
        ipv4: /(?:^|[^0-9.])([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9.]|$)/g,
        ipv4Private: /(?:^|[^0-9.])((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})(?:[^0-9.]|$)/g,

        // Admin/sensitive paths
        adminPath: /(?:["'`])(\/(?:admin|dashboard|manage|internal|config|debug|test|staging|dev|backup|console|portal|cms|wp-admin|phpmyadmin|_?admin|cpanel|webadmin|sysadmin|superadmin)[a-zA-Z0-9_\-\.\/]*)(?:["'`])/gi,

        // Interesting paths for bug bounty
        interestingPath: /(?:["'`])(\/(?:upload|file|download|export|import|backup|log|logs|error|errors|debug|trace|stack|dump|sql|database|db|conf|config|setting|secret|private|internal|hidden|temp|tmp|cache|session|token|auth|oauth|sso|saml|jwt|api-?key|webhook|callback|redirect|return|next|continue|url|link|path|file|src|source|include|require|eval|exec|system|shell|cmd|command|run|process)[a-zA-Z0-9_\-\.\/]*)(?:["'`])/gi
    };

    // Path categorization
    const PATH_CATEGORIES = {
        api: ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/gql'],
        auth: ['/auth', '/login', '/logout', '/signup', '/register', '/oauth', '/sso', '/saml', '/password', '/session', '/token', '/jwt', '/verify', '/confirm', '/activate'],
        admin: ['/admin', '/dashboard', '/manage', '/internal', '/console', '/portal', '/control', '/panel', '/cms', '/backoffice'],
        user: ['/user', '/profile', '/account', '/settings', '/member', '/me', '/self', '/my'],
        payment: ['/pay', '/checkout', '/billing', '/subscription', '/invoice', '/order', '/cart', '/stripe', '/paypal', '/purchase', '/transaction'],
        upload: ['/upload', '/file', '/media', '/image', '/asset', '/attachment', '/document', '/storage', '/s3', '/cdn'],
        sensitive: ['/config', '/debug', '/test', '/backup', '/log', '/error', '/status', '/health', '/metrics', '/trace', '/dump', '/export', '/download'],
        data: ['/data', '/json', '/xml', '/csv', '/feed', '/rss', '/atom', '/export', '/report']
    };

    // Validate if a string is likely a real domain
    function isValidDomain(domain) {
        if (!domain || domain.length < 4 || domain.length > 253) return false;

        const lower = domain.toLowerCase();

        // Quick reject: Check if it's a known JS pattern
        if (JS_PATTERNS.has(lower)) return false;

        // Quick reject: Check if it matches minified JS pattern (a.b, r.d, n.gm.x)
        if (MINIFIED_PATTERN.test(lower)) return false;

        // Quick reject: Check if it's a JS built-in access
        if (JS_BUILTIN_PATTERN.test(lower)) return false;

        // Must contain at least one dot
        if (!domain.includes('.')) return false;

        // Split and check parts
        const parts = lower.split('.');
        if (parts.length < 2) return false;

        // Quick reject: If first part is a single letter (minified var like a.something.com)
        // But allow real subdomains like m.facebook.com (has valid TLD)
        if (parts[0].length === 1 && parts.length === 2) return false;

        // Check TLD - must be a valid TLD
        const tld = parts.length > 2 ? parts.slice(-2).join('.') : parts[parts.length - 1];
        const simpleTld = parts[parts.length - 1];

        if (!VALID_TLDS.has(tld) && !VALID_TLDS.has(simpleTld)) return false;

        // Each part should be valid domain label
        for (const part of parts) {
            if (part.length === 0 || part.length > 63) return false;
            if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(part)) return false;
        }

        // Reject version number patterns (1.2.3, v1.0.0)
        if (/^\d+\.\d+(\.\d+)?$/.test(lower)) return false;
        if (/^v?\d+\.\d+/.test(lower)) return false;

        // Reject common code patterns that slip through
        const codePatterns = [
            /^(module|exports|window|document|console|object|array|string|function|promise|react|vue|angular|jquery|this|self|global|process|require|import|export|default|prototype|constructor|super)\./i,
            /\.(prototype|constructor|call|apply|bind|then|catch|finally|resolve|reject)$/i,
            /^[a-z]\d*\.[a-z]/i,  // Patterns like "a1.b", "r2.x"
            /^[a-z]+\.(log|warn|error|info|debug|trace)$/i,  // console.log etc
            /^[a-z]+\.(get|set|has|delete|add|remove|update|create|find|filter|map|reduce|forEach)$/i,  // Method patterns
        ];

        for (const pattern of codePatterns) {
            if (pattern.test(lower)) return false;
        }

        // Reject if looks like a file extension pattern (file.js, style.css)
        if (/\.(js|jsx|ts|tsx|css|scss|less|html|json|xml|txt|md|yml|yaml|ini|cfg|conf|log|pid|lock|tmp|bak)$/i.test(lower)) {
            return false;
        }

        return true;
    }

    // Get root domain from full domain
    function getRootDomain(domain) {
        const parts = domain.toLowerCase().split('.');
        if (parts.length <= 2) return domain.toLowerCase();

        // Handle compound TLDs like .com.au, .co.uk
        const lastTwo = parts.slice(-2).join('.');
        if (VALID_TLDS.has(lastTwo)) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    }

    // Categorize endpoint
    function categorizeEndpoint(path) {
        const lowerPath = path.toLowerCase();
        for (const [category, patterns] of Object.entries(PATH_CATEGORIES)) {
            if (patterns.some(p => lowerPath.includes(p))) {
                return category;
            }
        }
        return 'general';
    }

    // Normalize path
    function normalizePath(path) {
        // Remove leading ./
        path = path.replace(/^\.\//, '/');
        // Ensure starts with /
        if (!path.startsWith('/') && !path.startsWith('http')) {
            path = '/' + path;
        }
        // Remove duplicate slashes
        path = path.replace(/\/+/g, '/');
        // Remove trailing slash except for root
        if (path.length > 1 && path.endsWith('/')) {
            path = path.slice(0, -1);
        }
        return path;
    }

    // Check if path should be filtered out
    function shouldFilterPath(path) {
        const lower = path.toLowerCase();

        // Minimum length check - paths should be meaningful
        if (path.length < 2) return true;

        // Filter out common non-endpoint patterns
        const filters = [
            /^\.+$/,                          // Just dots
            /^\d+$/,                          // Just numbers
            /^\/\d+$/,                        // Just /number
            /^[a-z]$/i,                       // Single letter
            /^\/[a-z]$/i,                     // Single letter path
            /^(true|false|null|undefined)$/i, // JS values
            /^\.(js|jsx|ts|tsx|css|scss|less|json|html|xml|svg|png|jpg|gif|ico|woff|ttf|eot)$/i, // Extensions only
            /^(http|https|ftp|mailto|tel|data|javascript|blob|chrome|about):?$/i, // Protocols
            /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i, // HTTP methods
            /^[A-Z_]+$/,                      // All caps (constants)
            /^\$\{/,                          // Template literals
            /^<%/,                            // Server-side templates
            /^\{\{/,                          // Template syntax
            /^\/[0-9]+$/,                     // Pure numeric paths like /10, /123
            /^\/[a-z]$/i,                     // Single char paths like /a, /b
            /^#/,                             // Hash fragments
            /^\?/,                            // Query only
            /^\/$/,                           // Root only
            /^[a-z]{1,2}$/i,                  // 1-2 char strings (likely minified vars)
        ];

        if (filters.some(f => f.test(lower) || f.test(path))) return true;

        // Additional checks for JS-like patterns in paths
        if (/^[a-z]+\.[a-z]+$/i.test(path) && !path.startsWith('/')) return true;  // object.property patterns

        return false;
    }

    // Extract from content
    function extractFromContent(content, source) {
        if (!content || typeof content !== 'string') return;

        results.stats.totalBytesAnalyzed += content.length;

        // Endpoints
        let match;
        const endpointRegex = new RegExp(PATTERNS.endpoint);
        while ((match = endpointRegex.exec(content)) !== null) {
            let path = match[1];
            if (path && path.length > 1 && path.length < 500) {
                path = normalizePath(path);
                if (!shouldFilterPath(path) && !results.endpoints.has(path)) {
                    const category = categorizeEndpoint(path);
                    results.endpoints.set(path, {
                        type: category,
                        source: source,
                        fullUrl: path.startsWith('http') ? path : window.location.origin + path
                    });
                }
            }
        }

        // API Endpoints
        const apiRegex = new RegExp(PATTERNS.apiEndpoint);
        while ((match = apiRegex.exec(content)) !== null) {
            const path = normalizePath(match[1]);
            if (!shouldFilterPath(path)) {
                results.apiEndpoints.add(path);
            }
        }

        // GraphQL
        const graphqlRegex = new RegExp(PATTERNS.graphql);
        while ((match = graphqlRegex.exec(content)) !== null) {
            results.apiEndpoints.add(normalizePath(match[1]));
        }

        // REST endpoints
        const restRegex = new RegExp(PATTERNS.restEndpoint);
        while ((match = restRegex.exec(content)) !== null) {
            const path = normalizePath(match[1]);
            if (!shouldFilterPath(path)) {
                results.apiEndpoints.add(path);
            }
        }

        // Admin paths
        const adminRegex = new RegExp(PATTERNS.adminPath);
        while ((match = adminRegex.exec(content)) !== null) {
            results.adminPaths.add(normalizePath(match[1]));
        }

        // Interesting paths
        const interestingRegex = new RegExp(PATTERNS.interestingPath);
        while ((match = interestingRegex.exec(content)) !== null) {
            results.interestingPaths.add(normalizePath(match[1]));
        }

        // JS Files
        const jsRegex = new RegExp(PATTERNS.jsFile);
        while ((match = jsRegex.exec(content)) !== null) {
            const jsPath = match[1];
            if (jsPath && !jsPath.includes('node_modules')) {
                results.jsFiles.add(jsPath);
            }
        }

        // Parameters from URLs
        const urlMatches = content.match(/[?&]([a-zA-Z_][a-zA-Z0-9_-]{0,50})=/g);
        if (urlMatches) {
            urlMatches.forEach(m => {
                const param = m.replace(/[?&=]/g, '');
                if (param && param.length > 0 && !/^\d+$/.test(param)) {
                    if (!results.parameters.has(param)) {
                        results.parameters.set(param, []);
                    }
                    const sources = results.parameters.get(param);
                    if (!sources.includes(source) && sources.length < 5) {
                        sources.push(source);
                    }
                }
            });
        }

        // IMPROVED Domain extraction
        // First, extract domains from URLs (most reliable)
        const urlDomainRegex = new RegExp(PATTERNS.domainInUrl);
        while ((match = urlDomainRegex.exec(content)) !== null) {
            const domain = match[1].toLowerCase();
            if (isValidDomain(domain)) {
                const root = getRootDomain(domain);
                if (!results.subdomains.has(root)) {
                    results.subdomains.set(root, new Set());
                }
                results.subdomains.get(root).add(domain);
                results.domains.set(domain, { root, source });
            }
        }

        // Then extract standalone domains (more strict)
        const standaloneDomainRegex = new RegExp(PATTERNS.standaloneDomain);
        while ((match = standaloneDomainRegex.exec(content)) !== null) {
            const domain = match[1].toLowerCase();
            if (isValidDomain(domain) && !results.domains.has(domain)) {
                const root = getRootDomain(domain);
                if (!results.subdomains.has(root)) {
                    results.subdomains.set(root, new Set());
                }
                results.subdomains.get(root).add(domain);
                results.domains.set(domain, { root, source });
            }
        }

        // Full URLs
        const fullUrlMatches = content.match(PATTERNS.fullUrl);
        if (fullUrlMatches) {
            fullUrlMatches.forEach(url => results.urls.add(url));
        }

        // Secrets detection
        detectSecrets(content, source);

        // Emails
        const emailMatches = content.match(PATTERNS.email);
        if (emailMatches) {
            emailMatches.forEach(e => {
                // Filter out obvious false positives
                if (!e.includes('example.com') && !e.includes('test.com') && !e.includes('@types/')) {
                    results.emails.add(e.toLowerCase());
                }
            });
        }

        // IP Addresses (only non-private by default)
        const ipRegex = new RegExp(PATTERNS.ipv4);
        while ((match = ipRegex.exec(content)) !== null) {
            const ip = match[1];
            // Validate IP ranges
            const parts = ip.split('.').map(Number);
            if (parts.every(p => p >= 0 && p <= 255) &&
                !ip.startsWith('0.') &&
                !ip.startsWith('127.') &&
                !ip.startsWith('255.') &&
                ip !== '0.0.0.0') {
                results.ipAddresses.add(ip);
            }
        }
    }

    // Detect secrets with improved patterns
    function detectSecrets(content, source) {
        const secretPatterns = [
            { name: 'AWS Access Key', pattern: PATTERNS.awsAccessKeyRaw, severity: 'critical' },
            { name: 'Google API Key', pattern: PATTERNS.googleApiKey, severity: 'high' },
            { name: 'Google OAuth', pattern: PATTERNS.googleOAuth, severity: 'high' },
            { name: 'GitHub Token', pattern: PATTERNS.githubToken, severity: 'critical' },
            { name: 'JWT Token', pattern: PATTERNS.jwtToken, severity: 'high' },
            { name: 'Private Key', pattern: PATTERNS.privateKey, severity: 'critical' },
            { name: 'Firebase URL', pattern: PATTERNS.firebaseUrl, severity: 'medium' },
            { name: 'Firebase App', pattern: PATTERNS.firebaseConfig, severity: 'low' },
            { name: 'S3 Bucket', pattern: PATTERNS.s3Bucket, severity: 'medium' },
            { name: 'S3 Path', pattern: PATTERNS.s3BucketPath, severity: 'medium' },
            { name: 'Slack Webhook', pattern: PATTERNS.slackWebhook, severity: 'high' },
            { name: 'Slack Token', pattern: PATTERNS.slackToken, severity: 'critical' },
            { name: 'Stripe Secret Key', pattern: PATTERNS.stripeKey, severity: 'critical' },
            { name: 'Stripe Public Key', pattern: PATTERNS.stripePubKey, severity: 'low' },
            { name: 'Twilio SID', pattern: PATTERNS.twilioSid, severity: 'medium' },
            { name: 'SendGrid Key', pattern: PATTERNS.sendgridKey, severity: 'critical' },
            { name: 'Mailgun Key', pattern: PATTERNS.mailgunKey, severity: 'high' },
        ];

        secretPatterns.forEach(({ name, pattern, severity }) => {
            const regex = new RegExp(pattern);
            let match;
            while ((match = regex.exec(content)) !== null) {
                const value = match[1] || match[0];
                // Deduplicate
                const exists = results.secrets.some(s => s.value === value);
                if (!exists) {
                    results.secrets.push({
                        type: name,
                        value: value.substring(0, 100),
                        source,
                        severity,
                        context: content.substring(Math.max(0, match.index - 20), match.index + value.length + 20).replace(/\n/g, ' ')
                    });
                }
            }
        });

        // Generic secrets (less reliable, mark as potential)
        const genericPatterns = [
            { pattern: PATTERNS.genericApiKey, name: 'Potential API Key' },
            { pattern: PATTERNS.genericSecret, name: 'Potential Secret' },
        ];

        genericPatterns.forEach(({ pattern, name }) => {
            const regex = new RegExp(pattern);
            let match;
            while ((match = regex.exec(content)) !== null) {
                const value = match[1] || match[0];
                // Extra validation for generic patterns
                if (value.length >= 16 && !/^[A-Z_]+$/.test(value) && !/^(true|false|null|undefined|function|return|const|let|var)$/i.test(value)) {
                    const exists = results.secrets.some(s => s.value === value);
                    if (!exists) {
                        results.secrets.push({
                            type: name,
                            value: value.substring(0, 100),
                            source,
                            severity: 'potential',
                            context: content.substring(Math.max(0, match.index - 30), match.index + value.length + 30).replace(/\n/g, ' ')
                        });
                    }
                }
            }
        });
    }

    // Fetch and process scripts
    async function processScripts() {
        const scripts = document.getElementsByTagName('script');
        const fetchPromises = [];

        for (let i = 0; i < scripts.length; i++) {
            const script = scripts[i];
            if (script.src && !script.src.includes('google') && !script.src.includes('facebook') && !script.src.includes('analytics')) {
                results.jsFiles.add(script.src);
                fetchPromises.push(
                    fetch(script.src)
                        .then(r => {
                            if (!r.ok) throw new Error(`HTTP ${r.status}`);
                            return r.text();
                        })
                        .then(text => {
                            extractFromContent(text, script.src);
                            results.stats.scriptsAnalyzed++;
                        })
                        .catch(e => {
                            results.stats.fetchErrors++;
                            console.debug('[EE] Fetch error:', script.src, e.message);
                        })
                );
            } else if (script.textContent) {
                extractFromContent(script.textContent, 'inline-script');
                results.stats.scriptsAnalyzed++;
            }
        }

        // Process page HTML
        extractFromContent(document.documentElement.outerHTML, 'page-html');

        // Wait for fetches with timeout
        await Promise.race([
            Promise.allSettled(fetchPromises),
            new Promise(resolve => setTimeout(resolve, 10000))
        ]);
    }

    // Generate JSON export
    function generateJSON() {
        // Convert Maps and Sets for JSON
        const domainsArray = [];
        results.subdomains.forEach((subs, root) => {
            domainsArray.push({
                rootDomain: root,
                subdomains: Array.from(subs),
                count: subs.size
            });
        });

        return JSON.stringify({
            meta: {
                tool: 'Jenalizers v3.1',
                target: results.target,
                url: window.location.href,
                timestamp: results.timestamps,
                stats: {
                    ...results.stats,
                    totalEndpoints: results.endpoints.size,
                    apiEndpoints: results.apiEndpoints.size,
                    adminPaths: results.adminPaths.size,
                    interestingPaths: results.interestingPaths.size,
                    parameters: results.parameters.size,
                    jsFiles: results.jsFiles.size,
                    secrets: results.secrets.length,
                    uniqueDomains: results.domains.size,
                    rootDomains: results.subdomains.size,
                    emails: results.emails.size,
                    ips: results.ipAddresses.size,
                    urls: results.urls.size
                }
            },
            findings: {
                secrets: results.secrets.sort((a, b) => {
                    const order = { critical: 0, high: 1, medium: 2, low: 3, potential: 4 };
                    return (order[a.severity] || 5) - (order[b.severity] || 5);
                }),
                adminPaths: Array.from(results.adminPaths).sort(),
                interestingPaths: Array.from(results.interestingPaths).sort()
            },
            endpoints: {
                all: Object.fromEntries(results.endpoints),
                api: Array.from(results.apiEndpoints).sort(),
                byCategory: (() => {
                    const cats = {};
                    results.endpoints.forEach((data, path) => {
                        if (!cats[data.type]) cats[data.type] = [];
                        cats[data.type].push(path);
                    });
                    return cats;
                })()
            },
            parameters: Object.fromEntries(results.parameters),
            jsFiles: Array.from(results.jsFiles).sort(),
            domains: domainsArray.sort((a, b) => b.count - a.count),
            emails: Array.from(results.emails).sort(),
            ipAddresses: Array.from(results.ipAddresses).sort(),
            urls: Array.from(results.urls).sort()
        }, null, 2);
    }

    // Generate CSV export
    function generateCSV() {
        let csv = 'Type,Value,Category/Severity,Source,Full URL\n';

        // Secrets first (most important)
        results.secrets.forEach(s => {
            csv += `Secret,${s.type}: "${s.value.replace(/"/g, '""')}",${s.severity},"${s.source}",\n`;
        });

        // Admin paths
        results.adminPaths.forEach(path => {
            csv += `Admin Path,"${path}",admin,detected,"${window.location.origin}${path}"\n`;
        });

        // Interesting paths
        results.interestingPaths.forEach(path => {
            csv += `Interesting,"${path}",sensitive,detected,"${window.location.origin}${path}"\n`;
        });

        // API endpoints
        results.apiEndpoints.forEach(ep => {
            csv += `API Endpoint,"${ep}",api,detected,"${window.location.origin}${ep}"\n`;
        });

        // All endpoints
        results.endpoints.forEach((data, path) => {
            csv += `Endpoint,"${path}",${data.type},"${data.source}","${data.fullUrl}"\n`;
        });

        // Parameters
        results.parameters.forEach((sources, param) => {
            csv += `Parameter,"${param}",param,"${sources.join('; ')}",\n`;
        });

        // Domains
        results.domains.forEach((data, domain) => {
            csv += `Domain,"${domain}",${data.root},"${data.source}",\n`;
        });

        return csv;
    }

    // Generate Markdown report
    function generateMarkdown() {
        let md = `# Jenalizers Report v3.1\n\n`;
        md += `**Target:** ${results.target}\n`;
        md += `**URL:** ${window.location.href}\n`;
        md += `**Timestamp:** ${new Date().toISOString()}\n\n`;

        md += `## Summary\n\n`;
        md += `| Metric | Count |\n|--------|-------|\n`;
        md += `| Total Endpoints | ${results.endpoints.size} |\n`;
        md += `| API Endpoints | ${results.apiEndpoints.size} |\n`;
        md += `| Admin Paths | ${results.adminPaths.size} |\n`;
        md += `| Interesting Paths | ${results.interestingPaths.size} |\n`;
        md += `| Parameters | ${results.parameters.size} |\n`;
        md += `| JS Files | ${results.jsFiles.size} |\n`;
        md += `| Secrets | ${results.secrets.length} |\n`;
        md += `| Unique Domains | ${results.domains.size} |\n`;
        md += `| Root Domains | ${results.subdomains.size} |\n`;
        md += `| Emails | ${results.emails.size} |\n\n`;

        if (results.secrets.length > 0) {
            md += `## SECRETS FOUND\n\n`;
            results.secrets.forEach(s => {
                md += `### ${s.type} (${s.severity})\n`;
                md += `- **Value:** \`${s.value}\`\n`;
                md += `- **Source:** ${s.source}\n`;
                if (s.context) md += `- **Context:** \`${s.context}\`\n`;
                md += `\n`;
            });
        }

        if (results.adminPaths.size > 0) {
            md += `## Admin Paths\n\n`;
            results.adminPaths.forEach(p => md += `- ${p}\n`);
            md += `\n`;
        }

        if (results.interestingPaths.size > 0) {
            md += `## Interesting Paths\n\n`;
            results.interestingPaths.forEach(p => md += `- ${p}\n`);
            md += `\n`;
        }

        if (results.apiEndpoints.size > 0) {
            md += `## API Endpoints\n\n`;
            results.apiEndpoints.forEach(ep => md += `- ${ep}\n`);
            md += `\n`;
        }

        md += `## Domains by Root\n\n`;
        results.subdomains.forEach((subs, root) => {
            md += `### ${root} (${subs.size} subdomains)\n`;
            subs.forEach(s => md += `- ${s}\n`);
            md += `\n`;
        });

        if (results.emails.size > 0) {
            md += `## Emails\n\n`;
            results.emails.forEach(e => md += `- ${e}\n`);
            md += `\n`;
        }

        return md;
    }

    // Copy to clipboard
    function copyToClipboard(text, format) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification(`${format} copied to clipboard!`);
        }).catch(err => {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            showNotification(`${format} copied to clipboard!`);
        });
    }

    // Show notification
    function showNotification(message) {
        const notif = document.createElement('div');
        notif.textContent = message;
        notif.style.cssText = `
            position: fixed; bottom: 20px; right: 20px;
            background: #27ae60; color: white; padding: 15px 25px;
            border-radius: 5px; z-index: 100001; font-family: Arial;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        `;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 2000);
    }

    // Render UI
    function renderUI() {
        results.timestamps.end = new Date().toISOString();

        const overlay = document.createElement('div');
        overlay.id = 'jenalizers-overlay';
        overlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: #1a1a2e; color: #eee; overflow: auto; z-index: 99999;
            font-family: 'Segoe UI', Arial, sans-serif; padding: 20px;
        `;

        // Sort secrets by severity
        const sortedSecrets = results.secrets.sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3, potential: 4 };
            return (order[a.severity] || 5) - (order[b.severity] || 5);
        });

        // Header
        let html = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h1 style="color: #e94560; margin: 0;">Jenalizers v3.1</h1>
                <div>
                    <button onclick="document.getElementById('jenalizers-overlay').remove()"
                            style="background: #e94560; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 5px; font-size: 14px;">
                        Close
                    </button>
                </div>
            </div>
            <div style="background: #16213e; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Target:</strong> ${results.target}<br>
                <strong>Analyzed:</strong> ${results.stats.scriptsAnalyzed} scripts |
                <strong>Errors:</strong> ${results.stats.fetchErrors} |
                <strong>Data:</strong> ${(results.stats.totalBytesAnalyzed / 1024 / 1024).toFixed(2)} MB
            </div>
        `;

        // Export buttons
        html += `
            <div style="margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap;">
                <button id="btn-copy-json" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy JSON
                </button>
                <button id="btn-copy-csv" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy CSV
                </button>
                <button id="btn-copy-md" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy Markdown
                </button>
                <button id="btn-copy-endpoints" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy Endpoints
                </button>
                <button id="btn-copy-params" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy Parameters
                </button>
                <button id="btn-copy-domains" style="background: #4a69bd; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px;">
                    Copy Domains
                </button>
            </div>
        `;

        // Stats cards
        html += `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: #e94560;">${results.endpoints.size}</div>
                    <div>Endpoints</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: #3498db;">${results.apiEndpoints.size}</div>
                    <div>API</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: ${results.adminPaths.size > 0 ? '#f39c12' : '#e94560'};">${results.adminPaths.size}</div>
                    <div>Admin</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: #9b59b6;">${results.parameters.size}</div>
                    <div>Params</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: ${sortedSecrets.length > 0 ? '#e74c3c' : '#e94560'};">${sortedSecrets.length}</div>
                    <div>Secrets</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: #1abc9c;">${results.subdomains.size}</div>
                    <div>Root Domains</div>
                </div>
                <div style="background: #16213e; padding: 15px; border-radius: 5px; text-align: center;">
                    <div style="font-size: 24px; color: #1abc9c;">${results.domains.size}</div>
                    <div>Subdomains</div>
                </div>
            </div>
        `;

        // Secrets section (if any)
        if (sortedSecrets.length > 0) {
            html += `
                <div style="background: #e74c3c; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                    <h2 style="margin: 0 0 10px 0; color: white;">SECRETS FOUND!</h2>
                    <div style="max-height: 200px; overflow-y: auto;">
            `;
            sortedSecrets.forEach(s => {
                const severityColors = { critical: '#ff0000', high: '#ff6600', medium: '#ffcc00', low: '#99cc00', potential: '#888' };
                html += `<div style="background: rgba(0,0,0,0.2); padding: 10px; margin: 5px 0; border-radius: 3px; border-left: 4px solid ${severityColors[s.severity] || '#888'};">
                    <strong>${s.type}</strong> <span style="background: ${severityColors[s.severity]}; padding: 2px 6px; border-radius: 3px; font-size: 10px;">${s.severity.toUpperCase()}</span><br>
                    <code style="word-break: break-all;">${s.value}</code><br>
                    <small style="color: #ccc;">Source: ${s.source}</small>
                </div>`;
            });
            html += `</div></div>`;
        }

        // Tabs
        html += `
            <div style="display: flex; gap: 5px; margin-bottom: 10px; flex-wrap: wrap;">
                <button class="tab-btn active" data-tab="endpoints" style="background: #e94560; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    Endpoints (${results.endpoints.size})
                </button>
                <button class="tab-btn" data-tab="api" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    API (${results.apiEndpoints.size})
                </button>
                <button class="tab-btn" data-tab="admin" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    Admin (${results.adminPaths.size})
                </button>
                <button class="tab-btn" data-tab="interesting" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    Interesting (${results.interestingPaths.size})
                </button>
                <button class="tab-btn" data-tab="params" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    Params (${results.parameters.size})
                </button>
                <button class="tab-btn" data-tab="js" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    JS (${results.jsFiles.size})
                </button>
                <button class="tab-btn" data-tab="domains" style="background: #16213e; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 5px 5px 0 0;">
                    Domains (${results.subdomains.size})
                </button>
            </div>
        `;

        // Tab contents
        // Endpoints tab
        html += `<div id="tab-endpoints" class="tab-content" style="background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        const sortedEndpoints = Array.from(results.endpoints.entries()).sort((a, b) => {
            const order = ['admin', 'sensitive', 'api', 'auth', 'payment', 'upload', 'user', 'data', 'general'];
            return order.indexOf(a[1].type) - order.indexOf(b[1].type);
        });
        sortedEndpoints.slice(0, 500).forEach(([path, data]) => {
            const colors = {
                admin: '#f39c12', api: '#3498db', auth: '#9b59b6', payment: '#27ae60',
                upload: '#e74c3c', sensitive: '#ff6b6b', user: '#00cec9', data: '#a29bfe', general: '#636e72'
            };
            const color = colors[data.type] || '#636e72';
            html += `<div style="background: #0f3460; padding: 8px; margin: 3px 0; border-left: 4px solid ${color}; border-radius: 3px; display: flex; justify-content: space-between; align-items: center;">
                <div style="overflow: hidden;">
                    <span style="background: ${color}; padding: 2px 8px; border-radius: 3px; font-size: 10px; margin-right: 10px;">${data.type.toUpperCase()}</span>
                    <code style="font-size: 12px;">${path}</code>
                </div>
                <a href="${data.fullUrl}" target="_blank" style="color: #3498db; text-decoration: none; white-space: nowrap; margin-left: 10px;">Open →</a>
            </div>`;
        });
        if (results.endpoints.size > 500) {
            html += `<div style="text-align: center; padding: 10px; color: #888;">Showing 500 of ${results.endpoints.size} endpoints. Export JSON for full list.</div>`;
        }
        html += `</div>`;

        // API tab
        html += `<div id="tab-api" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        Array.from(results.apiEndpoints).sort().forEach(ep => {
            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid #3498db; border-radius: 3px;">
                <code>${ep}</code>
                <a href="${window.location.origin}${ep}" target="_blank" style="color: #3498db; text-decoration: none; float: right;">Open →</a>
            </div>`;
        });
        html += `</div>`;

        // Admin tab
        html += `<div id="tab-admin" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        Array.from(results.adminPaths).sort().forEach(path => {
            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid #f39c12; border-radius: 3px;">
                <code>${path}</code>
                <a href="${window.location.origin}${path}" target="_blank" style="color: #f39c12; text-decoration: none; float: right;">Open →</a>
            </div>`;
        });
        html += `</div>`;

        // Interesting tab
        html += `<div id="tab-interesting" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        Array.from(results.interestingPaths).sort().forEach(path => {
            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid #ff6b6b; border-radius: 3px;">
                <code>${path}</code>
                <a href="${window.location.origin}${path}" target="_blank" style="color: #ff6b6b; text-decoration: none; float: right;">Open →</a>
            </div>`;
        });
        html += `</div>`;

        // Parameters tab
        html += `<div id="tab-params" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        Array.from(results.parameters.entries()).sort().forEach(([param, sources]) => {
            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid #9b59b6; border-radius: 3px;">
                <strong>${param}</strong>
                <div style="font-size: 11px; color: #888; margin-top: 5px;">Sources: ${sources.slice(0, 3).join(', ')}${sources.length > 3 ? '...' : ''}</div>
            </div>`;
        });
        html += `</div>`;

        // JS Files tab
        html += `<div id="tab-js" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;
        Array.from(results.jsFiles).sort().forEach(file => {
            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; border-radius: 3px; word-break: break-all;">
                <a href="${file}" target="_blank" style="color: #3498db; text-decoration: none;">${file}</a>
            </div>`;
        });
        html += `</div>`;

        // Domains tab (IMPROVED - grouped by root domain)
        html += `<div id="tab-domains" class="tab-content" style="display: none; background: #16213e; padding: 15px; border-radius: 0 5px 5px 5px; max-height: 400px; overflow-y: auto;">`;

        // Sort by subdomain count
        const sortedDomains = Array.from(results.subdomains.entries()).sort((a, b) => b[1].size - a[1].size);

        sortedDomains.forEach(([root, subs]) => {
            const isTargetDomain = root.includes(results.targetDomain.split('.').slice(-2).join('.'));
            const borderColor = isTargetDomain ? '#27ae60' : '#1abc9c';

            html += `<div style="background: #0f3460; padding: 10px; margin: 5px 0; border-left: 4px solid ${borderColor}; border-radius: 3px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: ${borderColor};">${root}</strong>
                    <span style="background: #16213e; padding: 2px 8px; border-radius: 10px; font-size: 11px;">${subs.size} subdomain${subs.size > 1 ? 's' : ''}</span>
                </div>
                <div style="margin-top: 5px; font-size: 12px; color: #888;">`;

            Array.from(subs).slice(0, 5).forEach(sub => {
                html += `<div style="padding: 2px 0;">${sub}</div>`;
            });

            if (subs.size > 5) {
                html += `<div style="color: #666;">... and ${subs.size - 5} more</div>`;
            }

            html += `</div></div>`;
        });

        if (results.emails.size > 0) {
            html += `<h3 style="color: #e94560; margin-top: 20px;">Emails Found (${results.emails.size})</h3>`;
            Array.from(results.emails).sort().forEach(email => {
                html += `<div style="background: #0f3460; padding: 8px; margin: 3px 0; border-left: 4px solid #e74c3c; border-radius: 3px;">
                    <code>${email}</code>
                </div>`;
            });
        }
        html += `</div>`;

        overlay.innerHTML = html;
        document.body.appendChild(overlay);

        // Event listeners
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.tab-btn').forEach(b => {
                    b.style.background = '#16213e';
                    b.classList.remove('active');
                });
                this.style.background = '#e94560';
                this.classList.add('active');

                document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
                document.getElementById('tab-' + this.dataset.tab).style.display = 'block';
            });
        });

        document.getElementById('btn-copy-json').addEventListener('click', () => copyToClipboard(generateJSON(), 'JSON'));
        document.getElementById('btn-copy-csv').addEventListener('click', () => copyToClipboard(generateCSV(), 'CSV'));
        document.getElementById('btn-copy-md').addEventListener('click', () => copyToClipboard(generateMarkdown(), 'Markdown'));
        document.getElementById('btn-copy-endpoints').addEventListener('click', () => {
            copyToClipboard(Array.from(results.endpoints.keys()).join('\n'), 'Endpoints');
        });
        document.getElementById('btn-copy-params').addEventListener('click', () => {
            copyToClipboard(Array.from(results.parameters.keys()).join('\n'), 'Parameters');
        });
        document.getElementById('btn-copy-domains').addEventListener('click', () => {
            copyToClipboard(Array.from(results.domains.keys()).join('\n'), 'Domains');
        });
    }

    // Main execution
    async function main() {
        await processScripts();
        console.log('[Jenalizers v3.1] Analysis complete.');
        console.log(`[Stats] Endpoints: ${results.endpoints.size}, API: ${results.apiEndpoints.size}, Admin: ${results.adminPaths.size}, Domains: ${results.domains.size}`);
        renderUI();
    }

    main();
})();
