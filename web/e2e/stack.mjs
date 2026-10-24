// A real Warden for the browser tests: temp config, `warden serve`, the built dashboard (`next start`)
// and scripts/proxy.mjs in front on one localhost origin. Writes e2e/.stack.json for the tests and runs
// until Playwright stops it. Nothing here leaves localhost.
import { execFileSync, spawn } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const web = new URL("..", import.meta.url).pathname;
const repo = join(web, "..");
const backend = join(repo, "backend");
const python = join(backend, ".venv/bin/python");
const PROXY = Number(process.env.WARDEN_E2E_PORT ?? 3900);

const freePort = () =>
  new Promise((ok) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => ok(port));
    });
  });

const root = mkdtempSync(join(tmpdir(), "warden-e2e-"));
const home = join(root, "home");
const cfg = join(root, "config");
cpSync(join(repo, "config/policy.example.yaml"), join(cfg, "policy.yaml"));
cpSync(join(repo, "config/targets.example.yaml"), join(cfg, "targets.yaml"));
const [httpPort, agentPort, nextPort] = [await freePort(), await freePort(), await freePort()];
writeFileSync(
  join(cfg, "settings.yaml"),
  `server: {public_url: "http://localhost:${PROXY}"}\n` +
    `http: {listen_host: 127.0.0.1, listen_port: ${httpPort}}\n` +
    `agents: {listen_host: 127.0.0.1, listen_port: ${agentPort}, server_names: [127.0.0.1]}\n`,
);

// One reviewer that can never answer (nothing listens on port 9), so the unavailable state is real.
writeFileSync(
  join(cfg, "gatekeeper.yaml"),
  "mode: strictest\ntimeout_s: 5\ninjection_scan: true\nreviewers:\n  - {name: local, provider: ollama, url: \"http://127.0.0.1:9\", model: qwen3:14b}\n",
);

const env = { ...process.env, PYTHONPATH: join(backend, "src") };
const warden = (...args) => execFileSync(python, ["-m", "warden.cli", "--home", home, "--config-dir", cfg, ...args], { env, encoding: "utf8" });
const procs = [];
const run = (cmd, args, opts) => {
  const p = spawn(cmd, args, { stdio: "inherit", ...opts });
  procs.push(p);
  p.on("exit", (code) => {
    if (code && !stopping) {
      console.error(`${cmd} exited with ${code}`);
      stop(1);
    }
  });
  return p;
};
let stopping = false;
const stop = (code = 0) => {
  stopping = true;
  for (const p of procs) p.kill("SIGTERM");
  setTimeout(() => process.exit(code), 300);
};
process.on("SIGTERM", () => stop());
process.on("SIGINT", () => stop());

warden("init");
// The operator's offline key (README 7A), on "another machine": here, a directory the tests can read.
const sign = join(root, "warden-sign");
execFileSync("go", ["build", "-o", sign, "./cmd/warden-sign"], { cwd: join(repo, "agent"), env: { ...process.env, CGO_ENABLED: "0" }, stdio: "inherit" });
const offlineKey = join(root, "offline.key");
const passphrase = join(root, "offline.pass");
writeFileSync(passphrase, "correct horse battery staple\n", { mode: 0o600 });
const keygen = execFileSync(sign, ["keygen", "--out", offlineKey, "--passphrase-file", passphrase], { encoding: "utf8" });
warden("keys", "offline", "register", "--public", keygen.match(/public: (\S+)/)[1]);
warden("policy", "publish"); // v1, as at installation
run(python, ["-m", "warden.cli", "--home", home, "--config-dir", cfg, "serve"], { env });
const until = async (check, what) => {
  for (let i = 0; i < 200; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for ${what}`);
};
await until(() => existsSync(join(home, "admin.sock")), "warden serve");
await until(() => fetch(`http://127.0.0.1:${httpPort}/api/auth/me`).then(() => true, () => false), "the dashboard API");

if (!existsSync(join(web, ".next/BUILD_ID"))) execFileSync("npx", ["next", "build"], { cwd: web, stdio: "inherit" });
// The production server (output: standalone), with its static files next to it as in the deployment.
cpSync(join(web, ".next/static"), join(web, ".next/standalone/.next/static"), { recursive: true });
run(process.execPath, [join(web, ".next/standalone/server.js")], {
  cwd: join(web, ".next/standalone"),
  env: { ...process.env, PORT: String(nextPort), HOSTNAME: "127.0.0.1", NEXT_TELEMETRY_DISABLED: "1" },
});
await until(() => fetch(`http://127.0.0.1:${nextPort}/sign-in`).then((r) => r.ok, () => false), "next start");
run(process.execPath, [join(web, "scripts/proxy.mjs"), String(PROXY), String(httpPort), String(nextPort)]);

writeFileSync(join(web, "e2e/.stack.json"), JSON.stringify({ root, home, cfg, python, backend, sign, offlineKey, passphrase, origin: `http://localhost:${PROXY}` }, null, 1));
console.log(`warden e2e stack ready at http://localhost:${PROXY}`);
