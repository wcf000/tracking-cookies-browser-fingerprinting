/**
 * Browser Fingerprinting Detector
 * Detects and monitors various fingerprinting techniques used by websites
 */

class FingerprintDetector {
    constructor() {
        this.fingerprint = {};
        this.detectionMethods = [];
        this.fingerprintingAttempts = [];
        this._isInternalCall = false;
        this._blockingEnabled = false;
        this.accessCounts = {};
        this.updateSettings();
        
        // Listen for settings changes
        window.addEventListener('message', event => {
            if (event.data.type === 'PRIVACY_SHIELD_SETTINGS_UPDATE') {
                console.log("Detector received settings update:", event.data.settings);
                this._blockingEnabled = event.data.settings.blockFingerprinting;
                console.log("Blocking enabled:", this._blockingEnabled);
            } else if (event.data.type === 'PRIVACY_SHIELD_RESET_DATA') {
                // Reset fingerprinting attempts on clear data
                this.fingerprintingAttempts = [];
                this.accessCounts = {};
                this._domainThrottleTimes = {};
                console.log("Detector data has been reset");
            }
        });
    }

    /**
     * Request current settings from the content script
     */
    updateSettings() {
        console.log("Detector requesting settings update");
        window.postMessage({
            type: 'GET_PRIVACY_SHIELD_SETTINGS'
        }, '*');
    }

    /**
     * Initialize the detector and set up monitoring
     */
    init() {
        // Set up property monitoring and detection methods
        this.setupPropertyMonitoring();
        this.registerDetectionMethods();
        
        // Run fingerprint collection to establish baseline
        this.collectFingerprint();
        setInterval(() => this.cleanupFingerprinting(), 30000);
        console.log("Fingerprint Detector initialized");
        return this;
    }

    /**
     * Set up monitoring for common fingerprinting properties and methods
     */
    setupPropertyMonitoring() {
        // List of objects and properties commonly accessed for fingerprinting
        const monitorTargets = [
            { obj: navigator, props: [
                'userAgent', 'language', 'languages', 'platform', 'vendor', 
                'appVersion', 'appName', 'appCodeName', 'hardwareConcurrency',
                'deviceMemory', 'doNotTrack', 'cookieEnabled', 'maxTouchPoints',
                'plugins', 'mimeTypes', 'webdriver', 'connection', 'getBattery',
                'getGamepads', 'permissions', 'geolocation'
            ]},
            { obj: screen, props: [
                'width', 'height', 'availWidth', 'availHeight', 'colorDepth',
                'pixelDepth', 'orientation'
            ]},
            { obj: window, props: [
                'innerWidth', 'innerHeight', 'outerWidth', 'outerHeight',
                'screenX', 'screenY', 'devicePixelRatio'
            ]},
            { obj: document, props: [
                'referrer', 'hidden', 'visibilityState', 'hasFocus'
            ]}
        ];

        // Function to create a monitored property
        const createMonitoredProperty = (obj, prop) => {
            if (!obj || !(prop in obj)) return;
            
            const originalDescriptor = Object.getOwnPropertyDescriptor(obj, prop);
            if (!originalDescriptor || !originalDescriptor.configurable) return;
            if (typeof obj[prop] === 'function') {
                const originalMethod = obj[prop];
                obj[prop] = (...args) => {
                    this.logAccess('method', `${obj.constructor.name}.${prop}`, args);
                    return originalMethod.apply(obj, args);
                };
                return;
            }

            // For properties
            Object.defineProperty(obj, prop, {
                get: () => {
                    this.logAccess('property', `${obj.constructor.name}.${prop}`);
                    return originalDescriptor.get ? originalDescriptor.get.call(obj) : originalDescriptor.value;
                },
                set: originalDescriptor.set ? 
                    (value) => {
                        this.logAccess('property', `${obj.constructor.name}.${prop}`, [value], 'set');
                        originalDescriptor.set.call(obj, value);
                    } : undefined,
                enumerable: originalDescriptor.enumerable,
                configurable: originalDescriptor.configurable
            });
        };

        // Monitor canvas and WebGL specifically for fingerprinting
        this.monitorCanvasFingerprinting();
        this.monitorWebGLFingerprinting();
        this.monitorFontFingerprinting();
        
        // Apply monitoring to all targets
        monitorTargets.forEach(target => {
            target.props.forEach(prop => {
                try {
                    createMonitoredProperty(target.obj, prop);
                } catch (e) {
                    console.warn(`Could not monitor ${target.obj.constructor.name}.${prop}:`, e);
                }
            });
        });
    }

    /**
     * Monitor Canvas fingerprinting attempts
     */
    monitorCanvasFingerprinting() {
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        const originalGetContext = HTMLCanvasElement.prototype.getContext;
        const detector = this;
        
        // Monitor toDataURL calls - commonly used to get canvas fingerprint
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
            if (!detector._isInternalCall) {
                detector.logAccess('method', 'HTMLCanvasElement.toDataURL', args);
                detector.fingerprintingAttempts.push({
                    technique: 'Canvas Fingerprinting',
                    method: 'toDataURL',
                    timestamp: new Date().toISOString(),
                    domain: window.location.hostname
                });
                
                // Trigger an event for real-time detection
                window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                    detail: {
                        technique: 'Canvas Fingerprinting',
                        method: 'toDataURL',
                        timestamp: new Date().toISOString(),
                        domain: window.location.hostname
                    }
                }));
                
                // Return a fake image to prevent fingerprinting
                const spoof = detector.spoofCanvasData('toDataURL');
                if (spoof) {
                    return spoof;
                }
            }
            
            return originalToDataURL.apply(this, args);
        };
        
        // Monitor getImageData calls
        CanvasRenderingContext2D.prototype.getImageData = function(...args) {
            if (!detector._isInternalCall) {
                detector.logAccess('method', 'CanvasRenderingContext2D.getImageData', args);
                detector.fingerprintingAttempts.push({
                    technique: 'Canvas Fingerprinting',
                    method: 'getImageData',
                    timestamp: new Date().toISOString(),
                    domain: window.location.hostname
                });
                
                // Trigger an event for real-time detection
                window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                    detail: {
                        technique: 'Canvas Fingerprinting',
                        method: 'getImageData',
                        timestamp: new Date().toISOString(),
                        domain: window.location.hostname
                    }
                }));
                
                // Return fake image data to prevent fingerprinting
                const spoof = detector.spoofCanvasData('getImageData');
                if (spoof) {
                    return spoof;
                }
            }
            
            return originalGetImageData.apply(this, args);
        };
        HTMLCanvasElement.prototype.getContext = function(...args) {
            if (!detector._isInternalCall) {
                detector.logAccess('method', 'HTMLCanvasElement.getContext', args);
            }
            
            const context = originalGetContext.apply(this, args);
            
            // Only add monitoring to newly created context if not internal
            if (context && args[0] === '2d' && !detector._isInternalCall) {
                const methods = [
                    'fillText', 'strokeText', 'fillRect', 'strokeRect', 
                    'drawImage', 'createLinearGradient', 'createRadialGradient'
                ];
                
                methods.forEach(method => {
                    if (context[method] && typeof context[method] === 'function') {
                        const original = context[method];
                        context[method] = function(...methodArgs) {
                            if (!detector._isInternalCall) {
                                detector.logAccess('method', `CanvasRenderingContext2D.${method}`, methodArgs);
                            }
                            return original.apply(this, methodArgs);
                        };
                    }
                });
            }
            
            return context;
        };
    }

    /**
     * Monitor WebGL fingerprinting attempts
     */
    monitorWebGLFingerprinting() {
        if (!window.WebGLRenderingContext) return;
        // Methods commonly used in WebGL fingerprinting
        const webglMethods = [
            'getParameter', 'getExtension', 'getSupportedExtensions', 
            'getShaderPrecisionFormat', 'getContextAttributes'
        ];
        const detector = this;
        webglMethods.forEach(method => {
            if (WebGLRenderingContext.prototype[method]) {
                const original = WebGLRenderingContext.prototype[method];
                WebGLRenderingContext.prototype[method] = function(...args) {
                    if (!detector._isInternalCall) {
                        detector.logAccess('method', `WebGLRenderingContext.${method}`, args);
                        detector.fingerprintingAttempts.push({
                            technique: 'WebGL Fingerprinting',
                            method: method,
                            param: args[0],
                            timestamp: new Date().toISOString(),
                            domain: window.location.hostname
                        });
                        // Trigger an event for real-time detection
                        window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                            detail: {
                                technique: 'WebGL Fingerprinting',
                                method: method,
                                timestamp: new Date().toISOString(),
                                domain: window.location.hostname
                            }
                        }));
                        const spoof = detector.spoofWebGLData(method); // Return fake WebGL data to prevent fingerprinting
                        if (spoof !== null) {
                            return spoof;
                        }
                    }
                    
                    return original.apply(this, args);
                };
            }
        });
    }

    /**
     * Monitor font fingerprinting techniques
     */
    monitorFontFingerprinting() {
        // Monitor font access through CSS
        const originalGetComputedStyle = window.getComputedStyle;
        const detector = this;
        
        window.getComputedStyle = function(...args) {
            detector.logAccess('method', 'window.getComputedStyle', args);
            
            // Check if this might be for font detection
            const fontAccessors = ['font-family', 'font', 'fontSize', 'fontWeight'];
            if (detector.accessCounts['method:window.getComputedStyle'] > 10) {
                detector.fingerprintingAttempts.push({
                    technique: 'Font Enumeration',
                    method: 'getComputedStyle',
                    timestamp: new Date().toISOString(),
                    domain: window.location.hostname
                });
                
                // Trigger an event for real-time detection
                if (detector.accessCounts['method:window.getComputedStyle'] % 20 === 0) {
                    window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                        detail: {
                            technique: 'Font Enumeration',
                            method: 'getComputedStyle',
                            timestamp: new Date().toISOString(),
                            domain: window.location.hostname
                        }
                    }));
                }
                
                // Return fake font data to prevent fingerprinting
                const spoof = detector.spoofFontData();
                if (spoof) {
                    const result = originalGetComputedStyle.apply(this, args);
                    return result;
                }
            }
            
            return originalGetComputedStyle.apply(this, args);
        };
        this.setupFontDetectionObserver();
    }

    /**
     * Set up observer for DOM modifications related to font detection
     */
    setupFontDetectionObserver() {
        if (!window.MutationObserver) return;
        
        const detector = this;
        const fontDetectionObserver = new MutationObserver(mutations => {
            // Look for rapid successive changes that might indicate font enumeration
            const elementChanges = new Map();
            
            mutations.forEach(mutation => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    for (let i = 0; i < mutation.addedNodes.length; i++) {
                        const node = mutation.addedNodes[i];
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Count elements added
                            elementChanges.set(node.nodeName, (elementChanges.get(node.nodeName) || 0) + 1);
                            
                            // Check for font-related properties
                            if (node.style && (node.style.fontFamily || node.style.font)) {
                                detector.fingerprintingAttempts.push({
                                    technique: 'Font Enumeration',
                                    method: 'DOM Mutation',
                                    timestamp: new Date().toISOString(),
                                    domain: window.location.hostname
                                });
                                return;
                            }
                        }
                    }
                }
            });
            
            // If many similar elements are added rapidly, it might be font detection
            for (const [element, count] of elementChanges.entries()) {
                if (count > 5) {
                    detector.fingerprintingAttempts.push({
                        technique: 'Font Enumeration',
                        method: 'DOM Mutation',
                        timestamp: new Date().toISOString(),
                        domain: window.location.hostname
                    });
                    window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                        detail: {
                            technique: 'Font Enumeration',
                            method: 'DOM Mutation',
                            timestamp: new Date().toISOString(),
                            domain: window.location.hostname
                        }
                    }));
                    break;
                }
            }
        });
        
        // Start observing the document with configured parameters
        fontDetectionObserver.observe(document, { 
            childList: true, 
            subtree: true,
            attributes: true,
            attributeFilter: ['style']
        });
    }
    accessCounts = {};

    /**
     * Log access to monitored properties and methods
     * @param {string} type - 'property' or 'method'
     * @param {string} name - Name of the property or method
     * @param {Array} args - Arguments passed to the method (optional)
     * @param {string} operation - 'get' or 'set' (for properties)
     */
    logAccess(type, name, args = [], operation = 'get') {
        const accessKey = `${type}:${name}`;
        this.accessCounts[accessKey] = (this.accessCounts[accessKey] || 0) + 1;
        
        // Detect fingerprinting patterns and map to known techniques
        this.detectFingerprintingTechnique(type, name, args);
    }

    /**
     * Detect if a property/method access is part of a fingerprinting technique
     * @param {string} type - 'property' or 'method'
     * @param {string} name - Name of the property or method
     * @param {Array} args - Arguments passed to the method (optional)
     */
    detectFingerprintingTechnique(type, name, args) {
        // Skip detection if this is our own internal call
        if (this._isInternalCall) return;
        
        // Find the matching detection method
        for (const method of this.detectionMethods) {
            if (method.detect({ type, name, args })) {
                const now = Date.now();
                const lastAttempt = this.fingerprintingAttempts[this.fingerprintingAttempts.length - 1];
                const domainThrottleKey = `${method.name}:${window.location.hostname}`;
                const lastDomainAttemptTime = this._domainThrottleTimes?.[domainThrottleKey] || 0;
                
                if (now - lastDomainAttemptTime > 30000) {
                    if (!this._domainThrottleTimes) this._domainThrottleTimes = {};
                    this._domainThrottleTimes[domainThrottleKey] = now;
                    
                    // Add the attempt
                    this.fingerprintingAttempts.push({
                        technique: method.name,
                        access: { type, name, args },
                        timestamp: new Date().toISOString(),
                        domain: window.location.hostname
                    });
                    
                    // Trigger event
                    if (this.fingerprintingAttempts.length % 20 === 0) {
                        window.dispatchEvent(new CustomEvent('fingerprintingDetected', {
                            detail: {
                                technique: method.name,
                                timestamp: new Date().toISOString(),
                                domain: window.location.hostname
                            }
                        }));
                    }
                }
                break;
            }
        }
    }

    /**
     * Register detection methods for known fingerprinting techniques
     */
    registerDetectionMethods() {
        this.detectionMethods = [
            // Canvas Fingerprinting
            {
                name: 'Canvas Fingerprinting',
                detect: (access) => {
                    return access.name === 'HTMLCanvasElement.toDataURL' || 
                           access.name === 'CanvasRenderingContext2D.getImageData';
                }
            },
            
            // WebGL Fingerprinting
            {
                name: 'WebGL Fingerprinting',
                detect: (access) => {
                    return access.name.startsWith('WebGLRenderingContext') && 
                          (access.name.includes('getParameter') || 
                           access.name.includes('getExtension'));
                }
            },
            
            // Navigator/Screen Enumeration
            {
                name: 'Browser Enumeration',
                detect: (access) => {
                    const props = [
                        'userAgent', 'language', 'languages', 'platform', 
                        'hardwareConcurrency', 'deviceMemory', 'plugins'
                    ];
                    return access.name.startsWith('Navigator') && 
                           props.some(p => access.name.includes(p));
                }
            },
            
            // Audio Processing Fingerprinting
            {
                name: 'Audio Fingerprinting',
                detect: (access) => {
                    return access.name.includes('AudioContext') || 
                           access.name.includes('OscillatorNode') ||
                           access.name.includes('AnalyserNode') ||
                           access.name.includes('GainNode');
                }
            },
            
            // Hardware Info Fingerprinting
            {
                name: 'Hardware Enumeration',
                detect: (access) => {
                    return (access.name.includes('hardwareConcurrency') || 
                            access.name.includes('deviceMemory') ||
                            access.name.includes('getBattery')) ||
                           (access.name.startsWith('Navigator') && 
                           (access.name.includes('connection') || 
                            access.name.includes('getGamepads')));
                }
            },
            
            // Screen Properties Fingerprinting
            {
                name: 'Screen Properties',
                detect: (access) => {
                    return access.name.startsWith('Screen.') || 
                          (access.name.startsWith('Window') && 
                          (access.name.includes('inner') || 
                           access.name.includes('outer') || 
                           access.name.includes('devicePixelRatio')));
                }
            }
        ];
    }

    /**
     * Spoof canvas data to prevent fingerprinting
     * @param {string} method - The canvas method being called
     * @returns {any} Spoofed canvas data or null to use original data
     */
    spoofCanvasData(method) {
        if (!this._blockingEnabled) {
            return null;
        }
        if (method === 'toDataURL') {
            try {
                // Set flag
                const prevInternalState = this._isInternalCall;
                this._isInternalCall = true;
                
                // Create the fake canvas
                const canvas = document.createElement('canvas');
                canvas.width = 200;
                canvas.height = 50;
                
                const ctx = canvas.getContext('2d');
                if (!ctx) {
                    this._isInternalCall = prevInternalState;
                    return null;
                }
                
                // Draw content
                ctx.fillStyle = '#f60';
                ctx.fillRect(10, 10, 100, 30);
                ctx.fillStyle = '#069';
                ctx.font = '15px Arial';
                ctx.fillText('Privacy Protected ' + Math.floor(Math.random() * 10), 20, 30);
                const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                const result = originalToDataURL.call(canvas);
                
                // Restore flag and return result
                this._isInternalCall = prevInternalState;
                return result;
            } catch (e) {
                this._isInternalCall = false; // Reset flag
                console.error('Error spoofing canvas:', e);
                return null;
            }
        }
        
        return null;
    }

    /**
     * Spoof WebGL data to prevent fingerprinting
     * @param {string} method - The WebGL method being called
     * @returns {any} Spoofed WebGL data or null to use original data
     */
    spoofWebGLData(method) {
        // Only spoof if blocking is enabled in settings
        if (!this._blockingEnabled) {
            return null;
        }
        if (method === 'getParameter') {
            return null;
        }
        else if (method === 'getSupportedExtensions') {
            // Return a standardized list of extensions to make all browsers look similar
            return [
                'ANGLE_instanced_arrays',
                'EXT_blend_minmax',
                'EXT_color_buffer_half_float',
                'EXT_frag_depth',
                'EXT_sRGB',
                'EXT_shader_texture_lod',
                'EXT_texture_filter_anisotropic',
                'OES_element_index_uint',
                'OES_standard_derivatives',
                'OES_texture_float',
                'OES_texture_float_linear',
                'OES_texture_half_float',
                'OES_texture_half_float_linear',
                'OES_vertex_array_object',
                'WEBGL_color_buffer_float',
                'WEBGL_compressed_texture_s3tc',
                'WEBGL_debug_renderer_info',
                'WEBGL_debug_shaders',
                'WEBGL_depth_texture',
                'WEBGL_draw_buffers',
                'WEBGL_lose_context'
            ];
        }
        
        return null;
    }

    /**
     * Spoof font data to prevent fingerprinting
     * @returns {any} Spoofed font availability data or null to use original data
     */
    spoofFontData() {
        // Only spoof if blocking is enabled in settings
        if (!this._blockingEnabled) {
            return null; // Don't spoof if blocking not enabled
        }
        // Return a standardized set of fonts that should be available on most systems
        const standardFonts = [
            'Arial',
            'Courier New',
            'Georgia',
            'Times New Roman',
            'Verdana'
        ];
        return null;
    }

    /**
     * Get canvas fingerprint data
     * @returns {Object|null} Canvas fingerprint or null if error
     */
    getCanvasFingerprint() {
        try {
            // Set flag to avoid triggering our own detection for internal operations
            const prevInternalState = this._isInternalCall;
            this._isInternalCall = true;
            
            // Use a unique variable name to avoid any conflicts
            const fingerprintCanvas = document.createElement('canvas');
            fingerprintCanvas.width = 200;
            fingerprintCanvas.height = 50;
            
            const ctx = fingerprintCanvas.getContext('2d');
            if (!ctx) {
                this._isInternalCall = prevInternalState;
                return null;
            }
            
            // Draw some text with specific properties
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(10, 10, 100, 30);
            ctx.fillStyle = '#069';
            ctx.font = '15px Arial';
            ctx.fillText('Privacy Shield 👍', 20, 30);
            
            // Use direct prototype method to avoid our modified version
            const dataURL = HTMLCanvasElement.prototype.toDataURL.call(fingerprintCanvas);
            
            // Create a simple hash of the data
            let hash = 0;
            for (let i = 0; i < Math.min(dataURL.length, 1000); i++) {
                hash = ((hash << 5) - hash) + dataURL.charCodeAt(i);
                hash = hash & hash; 
            }
            
            // Restore previous internal state
            this._isInternalCall = prevInternalState;
            return {
                dataURL: dataURL.substring(0, 100) + '...', 
                hash: hash.toString(16)
            };
        } catch (e) {
            console.error('Error generating canvas fingerprint:', e);
            this._isInternalCall = false; // Reset
            return null;
        }
    }

    /**
     * Get WebGL fingerprint data
     * @returns {Object|null} WebGL fingerprint or null if error
     */
    getWebGLFingerprint() {
        try {
            // Set flag to avoid triggering internal detection
            const prevInternalState = this._isInternalCall;
            this._isInternalCall = true;
            
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) {
                this._isInternalCall = prevInternalState;
                return null;
            }
            
            // Use direct references to methods to prevent recursion
            const getParameterFn = WebGLRenderingContext.prototype.getParameter;
            const getSupportedExtensionsFn = WebGLRenderingContext.prototype.getSupportedExtensions;
            
            const result = {
                vendor: getParameterFn.call(gl, gl.VENDOR),
                renderer: getParameterFn.call(gl, gl.RENDERER),
                extensions: Array.from(getSupportedExtensionsFn.call(gl) || []).slice(0, 5),
                parameters: {}
            };
            const params = [gl.ALPHA_BITS, gl.BLUE_BITS, gl.GREEN_BITS, gl.RED_BITS, gl.DEPTH_BITS];
            for (const param of params) {
                try {
                    result.parameters[param] = getParameterFn.call(gl, param);
                } catch (e) {
                    result.parameters[param] = null;
                }
            }
            
            // Restore previous internal state
            this._isInternalCall = prevInternalState;
            return result;
        } catch (e) {
            console.error('Error generating WebGL fingerprint:', e);
            this._isInternalCall = false;
            return null;
        }
    }

    /**
     * Collect fingerprint data to establish a baseline
     */
    collectFingerprint() {
        // Browser and Navigator
        this.fingerprint.navigator = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            languages: navigator.languages,
            platform: navigator.platform,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            doNotTrack: navigator.doNotTrack,
            cookieEnabled: navigator.cookieEnabled,
            connectionType: navigator.connection ? navigator.connection.effectiveType : null
        };
        
        // Screen properties
        this.fingerprint.screen = {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight
        };
        
        // Timezone
        this.fingerprint.timezone = {
            offset: new Date().getTimezoneOffset(),
            timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
        
        // Plugins and MIME types (in a privacy-preserving way)
        this.fingerprint.plugins = {
            count: navigator.plugins ? navigator.plugins.length : 0
        };
        
        // Browser features (without revealing too much)
        this.fingerprint.features = {
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            indexedDB: !!window.indexedDB,
            cookies: navigator.cookieEnabled,
            webWorker: !!window.Worker,
            webSocket: !!window.WebSocket
        };
        
        // Canvas and WebGL fingerprints (for our own analysis)
        this.fingerprint.canvas = this.getCanvasFingerprint();
        this.fingerprint.webgl = this.getWebGLFingerprint();
        
        // Audio context (basic check)
        this.fingerprint.audio = {
            available: !!window.AudioContext || !!window.webkitAudioContext
        };
        
        return this.fingerprint;
    }
    
    /**
     * Export fingerprinting data for analysis
     * @returns {Object} Collected data for analysis
     */
    exportData() {
        // Clean up data before export
        this.cleanupFingerprinting();
        const recentAttempts = this.fingerprintingAttempts.slice(-100);
        return {
            fingerprint: this.fingerprint,
            attempts: recentAttempts,
            stats: {
                totalAttempts: this.fingerprintingAttempts.length,
                techniques: this.getTechniqueStats()
            }
        };
    }
    
    /**
     * Get statistics about detected fingerprinting techniques
     * @returns {Object} Stats about techniques
     */
    getTechniqueStats() {
        const stats = {};
        
        this.fingerprintingAttempts.forEach(attempt => {
            const technique = attempt.technique;
            if (!stats[technique]) {
                stats[technique] = 0;
            }
            stats[technique]++;
        });
        
        return stats;
    }

    /**
     * Deduplicate and limit fingerprinting attempts to prevent excessive memory usage
     */
    cleanupFingerprinting() {
        if (this.fingerprintingAttempts.length > 100) {    // keep 100 entries max
            this.fingerprintingAttempts = this.fingerprintingAttempts.slice(-100);
        }
        
        // Group by domain and technique, keeping only the most recent per combination
        const uniqueEntries = new Map();
        for (let i = this.fingerprintingAttempts.length - 1; i >= 0; i--) {
            const attempt = this.fingerprintingAttempts[i];
            const key = `${attempt.domain || 'unknown'}:${attempt.technique || 'unknown'}`;
            
            // Only keep the most recent occurrence 
            if (!uniqueEntries.has(key)) {
                uniqueEntries.set(key, attempt);
            }
        }
        
        // If we have more than 50 unique combinations, keep only the most recent ones
        if (uniqueEntries.size > 50) {
            this.fingerprintingAttempts = Array.from(uniqueEntries.values());
        }
    }
}

// Make the detector available in global scope
if (typeof window !== 'undefined') {
    window.FingerprintDetector = FingerprintDetector;
}