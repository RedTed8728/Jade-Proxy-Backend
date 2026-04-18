const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { parse } = require('url');
const zlib = require('zlib');

const CONFIG = {
    PORT: process.env.PORT || 8080,
    DNS: '1.1.1.1',
    DNS_HTTPS: 'https://cloudflare-dns.com/dns-query',
    KEY: process.env.JADE_KEY || crypto.randomBytes(32).toString('hex'),
    WS_PATH: '/ws/',
    GO_PATH: '/go/',
    SW_PATH: '/sw.js',
    CONFIG_PATH: '/config',
    ISOLATION: 'jade-' + crypto.randomBytes(4).toString('hex'),
    BLOCKED_HEADERS: ['cf-ray', 'cf-cache-status', 'x-forwarded-for', 'x-real-ip']
};

class CryptoEngine {
    constructor(key) {
        this.key = crypto.scryptSync(key, 'jade-salt-v2', 32);
    }
    
    seal(url) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        const enc = Buffer.concat([cipher.update(url, 'utf8'), cipher.final()]);
        const auth = cipher.getAuthTag();
        return Buffer.concat([iv, auth, enc]).toString('base64url');
    }
    
    unseal(token) {
        try {
            const buf = Buffer.from(token, 'base64url');
            const iv = buf.slice(0, 16);
            const auth = buf.slice(16, 32);
            const data = buf.slice(32);
            const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
            decipher.setAuthTag(auth);
            return decipher.update(data) + decipher.final('utf8');
        } catch { return null; }
    }
}

class DnsResolver {
    async resolve(hostname) {
        try {
            const res = await fetch(`${CONFIG.DNS_HTTPS}?name=${hostname}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            const data = await res.json();
            return data.Answer?.[0]?.data || null;
        } catch { return null; }
    }
}

class Rewriter {
    constructor(crypto, base) {
        this.crypto = crypto;
        this.base = base;
        this.isolation = CONFIG.ISOLATION;
    }
    
    url(u) {
        try {
            if (u.startsWith('data:') || u.startsWith('javascript:') || u.startsWith('blob:')) return u;
            if (u.startsWith('//')) u = 'https:' + u;
            const abs = new URL(u, this.base).href;
            return CONFIG.GO_PATH + this.crypto.seal(abs);
        } catch { return u; }
    }
    
    html(content) {
        return content
            .replace(/(href|src|action|poster|data-src|srcset)=["']([^"']+)["']/gi, (m, a, u) => `${a}="${this.url(u)}"`)
            .replace(/url\((["']?)([^"')]+)\1\)/gi, (m, q, u) => `url("${this.url(u)}")`)
            .replace(/import\s+["']([^"']+)["']/gi, (m, u) => `import "${this.url(u)}"`)
            .replace(/import\((["'])([^"']+)\1\)/gi, (m, q, u) => `import("${this.url(u)}")`)
            .replace(/fetch\((["'])([^"']+)\1/gi, (m, q, u) => `fetch(${q}${this.url(u)}${q}`)
            .replace(/XMLHttpRequest\.prototype\.open\([^,]+,\s*(["'])([^"']+)\1/gi, (m, q, u) => `XMLHttpRequest.prototype.open(arguments[0], ${q}${this.url(u)}${q}`)
            .replace(/new\s+(?:WebSocket|EventSource)\((["'])([^"']+)\1/gi, (m, q, u) => `new (window.WebSocket||window.EventSource)(${q}${this.wsUrl(u)}${q}`)
            .replace(/window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/gi, (m, u) => `window.location="${this.url(u)}"`)
            .replace(/history\.(pushState|replaceState)\([^,]+,\s*[^,]+,\s*["']([^"']+)["']/gi, (m, fn, u) => `history.${fn}(arguments[0], arguments[1], "${this.url(u)}")`)
            .replace(/document\.cookie/gi, `document['${this.isolation}-cookie']`)
            .replace(/localStorage/gi, `${this.isolation}_localStorage`)
            .replace(/sessionStorage/gi, `${this.isolation}_sessionStorage`)
            .replace(/indexedDB/gi, `${this.isolation}_indexedDB`)
            .replace(/new\s+BroadcastChannel\(([^)]+)\)/gi, `new BroadcastChannel(${this.isolation} + ${1})`)
            .replace(/navigator\.sendBeacon\((["'])([^"']+)\1/gi, (m, q, u) => `navigator.sendBeacon(${q}${this.url(u)}${q}`)
            .replace(/<head>/i, `<head><script>window.${this.isolation}=1;${this.injectRuntime()}</script>`);
    }
    
    css(content) {
        return content.replace(/url\((["']?)([^"')]+)\1\)/gi, (m, q, u) => `url("${this.url(u)}")`);
    }
    
    js(content) {
        return this.html(content);
    }
    
    wsUrl(u) {
        const abs = u.replace(/^wss?:/, m => m === 'ws:' ? 'http:' : 'https:');
        return CONFIG.WS_PATH + this.crypto.seal(abs);
    }
    
    injectRuntime() {
        return `
(function(){
const iso='${this.isolation}';
const seal=u=>fetch('/seal?url='+encodeURIComponent(u)).then(r=>r.text());
const orig={fetch:window.fetch,ws:window.WebSocket,es:window.EventSource,xhr:XMLHttpRequest.prototype.open,loc:Object.getOwnPropertyDescriptor(window,'location'),hist:window.history};
window.fetch=(u,o)=>typeof u==='string'&&u.startsWith('http')?seal(u).then(s=>orig.fetch('/go/'+s,o)):orig.fetch(u,o);
window.WebSocket=class extends WebSocket{constructor(u,p){seal(u.replace(/^wss?:/,'http:')).then(s=>super((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+'/ws/'+s,p))}};
window.EventSource=class extends EventSource{constructor(u,o){seal(u).then(s=>super('/go/'+s,o))}};
XMLHttpRequest.prototype.open=function(m,u,a,u2,p){if(typeof u==='string'&&u.startsWith('http')){seal(u).then(s=>orig.xhr.call(this,m,'/go/'+s,a,u2,p))}else{orig.xhr.call(this,m,u,a,u2,p)}};
Object.defineProperty(window,'location',{get:()=>orig.loc.get.call(window),set:v=>{seal(v).then(s=>orig.loc.set.call(window,'/go/'+s))}});
const storageFactory=n=>{const k=iso+'_'+n;return{getItem:k=>localStorage.getItem(k+'@'+n),setItem:(k,v)=>localStorage.setItem(k+'@'+n,v),removeItem:k=>localStorage.removeItem(k+'@'+n),clear:()=>{for(let i=localStorage.length-1;i>=0;i--){const k=localStorage.key(i);if(k&&k.endsWith('@'+n))localStorage.removeItem(k)}},get length(){let c=0;for(let j=0;j<localStorage.length;j++)if(localStorage.key(j)?.endsWith('@'+n))c++;return c},key:i=>{for(let j=0;j<localStorage.length;j++)if(localStorage.key(j)?.endsWith('@'+n)&&i--===0)return localStorage.key(j).slice(0,-n.length-1)}}};
Object.defineProperty(window,'localStorage',{get:()=>storageFactory('local')});
Object.defineProperty(window,'sessionStorage',{get:()=>storageFactory('session')});
const idb=window.indexedDB;window.indexedDB={open:(n,v)=>idb.open(iso+'_'+n,v),deleteDatabase:n=>idb.deleteDatabase(iso+'_'+n),cmp:idb.cmp};
const bc=window.BroadcastChannel;window.BroadcastChannel=class extends bc{constructor(n){super(iso+'_'+n)}};
document.cookie='';Object.defineProperty(document,'cookie',{get:()=>'',set:()=>{}});
window.postMessage=(m,t,o)=>orig.postMessage.call(window,m,'*',o);
window.addEventListener('message',e=>{if(e.origin!==location.origin)e.stopImmediatePropagation()},true);
})();
        `.replace(/\s+/g, ' ');
    }
}

const crypto = new CryptoEngine(CONFIG.KEY);
const dns = new DnsResolver();

const server = http.createServer({
    maxHeaderSize: 32768,
    requestTimeout: 30000
});

server.on('request', async (req, res) => {
    const url = parse(req.url, true);
    
    if (url.pathname === '/health') return res.end('jade-v2');
    if (url.pathname === '/key') return res.end(crypto.seal('https://test.com').slice(0, 16));
    
    if (url.pathname === CONFIG.CONFIG_PATH) {
        res.writeHead(200, {'content-type': 'application/json'});
        return res.end(JSON.stringify({
            prefix: CONFIG.GO_PATH,
            ws: CONFIG.WS_PATH,
            sw: CONFIG.SW_PATH,
            isolation: CONFIG.ISOLATION,
            version: 'jade-v2'
        }));
    }
    
    if (url.pathname === CONFIG.SW_PATH) {
        res.writeHead(200, {'content-type': 'application/javascript', 'service-worker-allowed': '/'});
        return res.end(`
const CFG={prefix:'${CONFIG.GO_PATH}',ws:'${CONFIG.WS_PATH}',iso:'${CONFIG.ISOLATION}'};
self.addEventListener('fetch',e=>{
    if(e.request.url.includes(CFG.prefix)||e.request.url.includes(CFG.ws))return;
    const seal=u=>btoa(u).replace(/=/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');
    e.respondWith(fetch(CFG.prefix+seal(e.request.url),{method:e.request.method,headers:e.request.headers,body:e.request.body}));
});
self.addEventListener('message',e=>{if(e.data==='ping')e.source.postMessage('pong')});
        `);
    }
    
    if (url.pathname === '/seal') {
        if (!url.query.url) {
            res.writeHead(400);
            return res.end('missing url');
        }
        res.writeHead(200);
        return res.end(crypto.seal(url.query.url));
    }
    
    if (!url.pathname.startsWith(CONFIG.GO_PATH)) {
        res.writeHead(404);
        return res.end();
    }
    
    const target = crypto.unseal(url.pathname.slice(CONFIG.GO_PATH.length));
    if (!target) {
        res.writeHead(400);
        return res.end('invalid seal');
    }
    
    const targetUrl = parse(target);
    let ip = await dns.resolve(targetUrl.hostname);
    if (!ip) ip = targetUrl.hostname;
    
    const options = {
        hostname: ip,
        port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
        path: targetUrl.path + (url.search || ''),
        method: req.method,
        headers: {
            'host': targetUrl.host,
            'user-agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
            'accept': req.headers['accept'] || '*/*',
            'accept-language': req.headers['accept-language'] || 'en-US,en',
            'accept-encoding': 'identity',
            'cache-control': 'no-cache',
            'pragma': 'no-cache'
        },
        rejectUnauthorized: false,
        servername: targetUrl.hostname
    };
    
    ['content-type', 'content-length', 'authorization', 'cookie', 'origin', 'referer', 'x-requested-with'].forEach(h => {
        if (req.headers[h]) options.headers[h] = req.headers[h];
    });
    
    const rewriter = new Rewriter(crypto, target);
    
    const proxyReq = (targetUrl.protocol === 'https:' ? https : http).request(options, (proxyRes) => {
        const headers = {};
        Object.entries(proxyRes.headers).forEach(([k, v]) => {
            if (!CONFIG.BLOCKED_HEADERS.includes(k) && !['content-encoding', 'transfer-encoding'].includes(k)) {
                headers[k] = v;
            }
        });
        
        delete headers['content-security-policy'];
        delete headers['content-security-policy-report-only'];
        delete headers['x-frame-options'];
        delete headers['x-content-type-options'];
        headers['access-control-allow-origin'] = '*';
        
        const ct = (proxyRes.headers['content-type'] || '').toLowerCase();
        const isText = ct.includes('text') || ct.includes('json') || ct.includes('javascript') || ct.includes('xml') || ct.includes('html') || ct.includes('css');
        
        if (!isText || req.headers['x-raw']) {
            res.writeHead(proxyRes.statusCode, headers);
            return proxyRes.pipe(res);
        }
        
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => {
            let body = Buffer.concat(chunks);
            
            try {
                if (proxyRes.headers['content-encoding'] === 'gzip') body = zlib.gunzipSync(body);
                else if (proxyRes.headers['content-encoding'] === 'deflate') body = zlib.inflateSync(body);
                else if (proxyRes.headers['content-encoding'] === 'br') body = zlib.brotliDecompressSync(body);
            } catch {}
            
            let str = body.toString();
            
            if (ct.includes('html') || ct.includes('xhtml')) str = rewriter.html(str);
            else if (ct.includes('css')) str = rewriter.css(str);
            else if (ct.includes('javascript') || ct.includes('ecmascript')) str = rewriter.js(str);
            
            const out = Buffer.from(str);
            headers['content-length'] = out.length;
            delete headers['content-encoding'];
            
            res.writeHead(proxyRes.statusCode, headers);
            res.end(out);
        });
    });
    
    proxyReq.on('error', () => {
        res.writeHead(502);
        res.end();
    });
    
    req.pipe(proxyReq);
});

server.on('upgrade', (req, socket, head) => {
    const url = parse(req.url, true);
    if (!url.pathname.startsWith(CONFIG.WS_PATH)) return socket.end();
    
    const target = crypto.unseal(url.pathname.slice(CONFIG.WS_PATH.length));
    if (!target) return socket.end();
    
    const targetUrl = parse(target);
    const isSecure = targetUrl.protocol === 'wss:' || targetUrl.protocol === 'https:';
    
    const upstream = net.connect({
        host: targetUrl.hostname,
        port: targetUrl.port || (isSecure ? 443 : 80),
        lookup: (h, o, cb) => require('dns').lookup(h, {server: CONFIG.DNS}, cb)
    });
    
    upstream.on('connect', () => {
        if (isSecure) {
            const tlsSocket = tls.connect({
                socket: upstream,
                servername: targetUrl.hostname,
                rejectUnauthorized: false
            });
            
            tlsSocket.on('secureConnect', () => {
                const key = crypto.randomBytes(16).toString('base64');
                tlsSocket.write(
                    `GET ${targetUrl.path} HTTP/1.1\r\n` +
                    `Host: ${targetUrl.host}\r\n` +
                    `Upgrade: websocket\r\n` +
                    `Connection: Upgrade\r\n` +
                    `Sec-WebSocket-Key: ${key}\r\n` +
                    `Sec-WebSocket-Version: 13\r\n` +
                    `Origin: https://${targetUrl.host}\r\n\r\n`
                );
                tlsSocket.pipe(socket);
                socket.pipe(tlsSocket);
            });
        } else {
            const key = crypto.randomBytes(16).toString('base64');
            upstream.write(
                `GET ${targetUrl.path} HTTP/1.1\r\n` +
                `Host: ${targetUrl.host}\r\n` +
                `Upgrade: websocket\r\n` +
                `Connection: Upgrade\r\n` +
                `Sec-WebSocket-Key: ${key}\r\n` +
                `Sec-WebSocket-Version: 13\r\n\r\n`
            );
            upstream.pipe(socket);
            socket.pipe(upstream);
        }
    });
    
    upstream.on('error', () => socket.end());
    socket.on('close', () => upstream.destroy());
});

server.listen(CONFIG.PORT, () => {
    console.log(`jade-v2 on ${CONFIG.PORT}`);
    console.log(`isolation: ${CONFIG.ISOLATION}`);
    console.log(`key: ${CONFIG.KEY.slice(0, 16)}...`);
});