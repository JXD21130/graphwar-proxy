// Puente WebSocket <-> TCP para Graphwar web.
//
// El navegador abre:  wss://TU-PROXY/?host=www.graphwar.com&port=23761
// Cada mensaje WebSocket = una linea del protocolo de Graphwar (sin "\n").
//
// Variables de entorno:
//   PORT             puerto HTTP (por defecto 8080)
//   ALLOWED_ORIGINS  origenes permitidos, separados por coma (por defecto https://jxd21130.github.io). "*" = todos
//   TRUST_PROXY=1    usar X-Forwarded-For para la IP del cliente (Fly, Render, Caddy...)
//   ALLOW_PRIVATE=1  SOLO PARA PRUEBAS LOCALES: permite destinos en 127.0.0.1 / redes privadas

const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '8080', 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://jxd21130.github.io').split(',').map(s => s.trim());
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const MIN_PORT = 1024;
const MAX_PER_IP = 8;
const MAX_TOTAL = 500;
const MAX_LINE = 4096;           // bytes por mensaje
const CONNECT_TIMEOUT = 10000;   // ms
const IDLE_TIMEOUT = 120000;     // ms sin trafico TCP (el juego manda keepalive cada 5 s)

// Destinos prohibidos: evita que el proxy se use para atacar redes internas (SSRF)
const blocked = new net.BlockList();
for (const [net4, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blocked.addSubnet(net4, bits, 'ipv4');
for (const [net6, bits] of [['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]])
  blocked.addSubnet(net6, bits, 'ipv6');

const perIp = new Map();
let total = 0;

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function reject(socket, code, msg) {
  socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  socket.destroy();
}

const server = http.createServer((req, res) => {
  if (req.url === '/healthz') { res.writeHead(200); res.end('ok'); return; }
  res.writeHead(404); res.end();
});

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_LINE });

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});

  const origin = req.headers.origin || '';
  if (!ALLOWED_ORIGINS.includes('*') && !ALLOWED_ORIGINS.includes(origin)) return reject(socket, 403, 'Forbidden');

  let host, port;
  try {
    const u = new URL(req.url, 'http://x');
    host = u.searchParams.get('host') || '';
    port = parseInt(u.searchParams.get('port') || '', 10);
  } catch (e) { return reject(socket, 400, 'Bad Request'); }

  if (!/^[A-Za-z0-9.-]{1,253}$/.test(host) || !(port >= MIN_PORT && port <= 65535)) return reject(socket, 400, 'Bad Request');

  const ip = clientIp(req);
  if (total >= MAX_TOTAL || (perIp.get(ip) || 0) >= MAX_PER_IP) return reject(socket, 429, 'Too Many Requests');

  // Resolver nosotros y conectar a la IP resuelta (evita DNS rebinding)
  let address;
  try {
    address = net.isIP(host) ? host : (await dns.lookup(host)).address;
  } catch (e) { return reject(socket, 502, 'Bad Gateway'); }

  if (!ALLOW_PRIVATE && blocked.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4')) return reject(socket, 403, 'Forbidden');

  total++; perIp.set(ip, (perIp.get(ip) || 0) + 1);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    total--;
    const n = (perIp.get(ip) || 1) - 1;
    if (n <= 0) perIp.delete(ip); else perIp.set(ip, n);
  };

  const tcp = net.connect({ host: address, port });
  tcp.setNoDelay(true);
  const connectTimer = setTimeout(() => tcp.destroy(new Error('connect timeout')), CONNECT_TIMEOUT);

  // Lineas que llegan por TCP antes de que el WebSocket este listo
  let ws = null;
  const pending = [];
  let rest = '';
  const emit = (line) => { if (ws) { if (ws.readyState === 1) ws.send(line); } else pending.push(line); };

  tcp.on('data', (chunk) => {
    rest += chunk.toString('utf8');
    let i;
    while ((i = rest.indexOf('\n')) >= 0) {
      let line = rest.slice(0, i);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      rest = rest.slice(i + 1);
      emit(line);
    }
    if (rest.length > MAX_LINE * 4) tcp.destroy();
  });

  tcp.on('error', () => { clearTimeout(connectTimer); if (!ws) { reject(socket, 502, 'Bad Gateway'); release(); } else ws.close(); });
  tcp.on('close', () => { release(); if (ws) ws.close(); else socket.destroy(); });
  tcp.setTimeout(IDLE_TIMEOUT, () => tcp.destroy());

  tcp.on('connect', () => {
    clearTimeout(connectTimer);
    wss.handleUpgrade(req, socket, head, (w) => {
      ws = w;
      for (const l of pending) ws.send(l);
      pending.length = 0;

      // limitador simple: 20 mensajes/s con rafaga de 60
      let tokens = 60, last = Date.now();
      ws.on('message', (data, isBinary) => {
        const now = Date.now();
        tokens = Math.min(60, tokens + (now - last) * 0.02);
        last = now;
        if (--tokens < 0 || isBinary) return ws.close(1008);
        const line = data.toString('utf8').replace(/[\r\n]+/g, '');
        if (!tcp.destroyed) tcp.write(line + '\n');
      });
      ws.on('close', () => tcp.destroy());
      ws.on('error', () => tcp.destroy());
    });
  });
});

server.listen(PORT, () => console.log(`graphwar-ws-proxy escuchando en :${PORT} (origenes: ${ALLOWED_ORIGINS.join(', ')})`));
