class JadeClient {
    constructor(backendUrl) {
        this.backend = backendUrl.replace(/\/$/, '');
        this.config = null;
        this.swRegistered = false;
    }
    
    async init() {
        this.config = await fetch(`${this.backend}/config`).then(r => r.json());
        
        if ('serviceWorker' in navigator) {
            try {
                const reg = await navigator.serviceWorker.register(
                    `${this.backend}/sw.js`,
                    { scope: '/', updateViaCache: 'none' }
                );
                await navigator.serviceWorker.ready;
                this.swRegistered = true;
                console.log('jade sw active');
            } catch(e) {
                console.log('sw failed, using xhr mode');
            }
        }
        
        this.injectRuntime();
        return this;
    }
    
    async seal(url) {
        const res = await fetch(`${this.backend}/seal?url=${encodeURIComponent(url)}`);
        return res.text();
    }
    
    async go(url) {
        const sealed = await this.seal(url);
        return `${this.backend}/go/${sealed}`;
    }
    
    async navigate(url) {
        location.href = await this.go(url);
    }
    
    async fetch(url, options = {}) {
        if (!this.config) await this.init();
        
        if (this.swRegistered && url.startsWith('http')) {
            return fetch(url, options);
        }
        
        const sealed = await this.seal(url);
        return fetch(`${this.backend}/go/${sealed}`, options);
    }
    
    ws(url) {
        if (!this.config) throw new Error('init first');
        
        const wsUrl = url.replace(/^wss?:/, m => m === 'ws:' ? 'http:' : 'https:');
        return new WebSocket(`${this.backend}/ws/${this.seal(wsUrl)}`);
    }
    
    injectRuntime() {
        if (window.__jadeRuntime) return;
        window.__jadeRuntime = true;
        
        const backend = this.backend;
        const seal = this.seal.bind(this);
        
        const orig = {
            fetch: window.fetch,
            xhr: XMLHttpRequest.prototype.open,
            ws: window.WebSocket,
            es: window.EventSource,
            location: Object.getOwnPropertyDescriptor(window, 'location'),
            history: {
                pushState: window.history.pushState,
                replaceState: window.history.replaceState
            }
        };
        
        window.fetch = async (url, opts) => {
            if (typeof url === 'string' && url.startsWith('http')) {
                const sealed = await seal(url);
                return orig.fetch(`${backend}/go/${sealed}`, opts);
            }
            return orig.fetch(url, opts);
        };
        
        XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
            if (typeof url === 'string' && url.startsWith('http')) {
                seal(url).then(s => orig.xhr.call(this, method, `${backend}/go/${s}`, async, user, password));
            } else {
                orig.xhr.call(this, method, url, async, user, password);
            }
        };
        
        window.WebSocket = class extends WebSocket {
            constructor(url, protocols) {
                const wsBackend = backend.replace(/^http/, 'ws');
                seal(url.replace(/^wss?:/, m => m === 'ws:' ? 'http:' : 'https:')).then(s => {
                    super(`${wsBackend}/ws/${s}`, protocols);
                });
            }
        };
        
        window.EventSource = class extends EventSource {
            constructor(url, options) {
                seal(url).then(s => super(`${backend}/go/${s}`, options));
            }
        };
        
        Object.defineProperty(window, 'location', {
            get: () => orig.location.get.call(window),
            set: (v) => seal(v).then(s => orig.location.set.call(window, `${backend}/go/${s}`))
        });
        
        window.history.pushState = (state, title, url) => {
            if (url) seal(url).then(s => orig.history.pushState.call(window.history, state, title, `${backend}/go/${s}`));
            else orig.history.pushState.call(window.history, state, title, url);
        };
        
        window.history.replaceState = (state, title, url) => {
            if (url) seal(url).then(s => orig.history.replaceState.call(window.history, state, title, `${backend}/go/${s}`));
            else orig.history.replaceState.call(window.history, state, title, url);
        };
    }
}

if (typeof window !== 'undefined') window.JadeClient = JadeClient;
if (typeof module !== 'undefined') module.exports = { JadeClient };