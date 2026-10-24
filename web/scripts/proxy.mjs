// Plays Nginx Proxy Manager's part in development and tests (README 14): one origin, /api and /ws to
// `warden serve`, everything else to Next. Usage: node scripts/proxy.mjs PORT BACKEND_PORT NEXT_PORT
import http from "node:http";
import net from "node:net";

const [port, backend, next] = process.argv.slice(2).map(Number);
if (!port || !backend || !next) {
  console.error("usage: proxy.mjs PORT BACKEND_PORT NEXT_PORT");
  process.exit(2);
}
const upstream = (url) => (/^\/(api|ws|mcp)(\/|$|\?)/.test(url) ? backend : next);

const server = http.createServer((req, res) => {
  const up = http.request(
    { host: "127.0.0.1", port: upstream(req.url), method: req.method, path: req.url, headers: { ...req.headers, "x-forwarded-proto": "http" } },
    (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    },
  );
  up.on("error", () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  req.pipe(up);
});

// WebSocket upgrades: pass the raw bytes both ways.
server.on("upgrade", (req, socket, head) => {
  const up = net.connect(upstream(req.url), "127.0.0.1", () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`, ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`), "", ""];
    up.write(lines.join("\r\n"));
    if (head.length) up.write(head);
    up.pipe(socket);
    socket.pipe(up);
  });
  up.on("error", () => socket.destroy());
  socket.on("error", () => up.destroy());
});

server.listen(port, "127.0.0.1", () => console.log(`proxy on http://localhost:${port}`));
