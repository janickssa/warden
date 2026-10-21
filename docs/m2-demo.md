# M2 checklist: the agent on your `dev` server

README section 15, M2 "Done when": *plan runs on `dev`, fails and revises; a tampered plan is refused*.

**Already proven automatically** (in this repo, with the real agent binary running as an unprivileged user):
`backend/tests/integration/` covers enroll → run → fail → revise, a tampered `run` message refused by the
agent, replay refused, a symlink escape refused by the agent, kill switch, disconnect, held plans,
read-only through the agent, revocation, and the whole CLI + `warden serve` flow. Run them with
`cd backend && sudo uv run pytest tests/integration` (they need Go and root, to start the agent as `nobody`).

**This checklist** repeats it on real machines. Takes about 30 min. Every step says what you should see.

## 0. What you need

- The `warden` guest (LXC or VM) with Python 3.12, `uv` and this repo at `/opt/warden`.
- The `dev` VM with Docker, reachable from the `warden` guest on your LAN (or over WireGuard).
- Go 1.24 anywhere, to build the agent once.
- Replace `10.0.20.5` below with the `warden` guest's address that `dev` can reach.

## 1. Warden guest

```bash
sudo useradd -r -m -d /var/lib/warden -s /usr/sbin/nologin warden
sudo mkdir -p /etc/warden && sudo cp /opt/warden/config/*.example.yaml /etc/warden/
cd /etc/warden && for f in policy targets settings; do sudo mv $f.example.yaml $f.yaml; done
sudoedit /etc/warden/settings.yaml     # agents.server_names: [10.0.20.5]   (every name/IP agents use)
sudoedit /etc/warden/targets.yaml      # keep `dev`, workspace_roots: [/srv/dev]
cd /opt/warden/backend && sudo uv sync --locked   # root-owned, read-only for the warden user
alias warden='sudo -u warden WARDEN_HOME=/var/lib/warden WARDEN_CONFIG=/etc/warden /opt/warden/backend/.venv/bin/warden'

warden init                # ✓ approval key, online policy key and internal CA created
warden policy publish      # ✓ "dev · initial", "dev2 · initial", "Published v1."
sudo cp /opt/warden/deploy/warden-backend.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now warden-backend
journalctl -u warden-backend -n 5   # ✓ "agent listener on :8443, admin socket …, policy v1"
```

Firewall (Proxmox): allow TCP 8443 into the `warden` guest only from `dev` (and later agents).
Don't put 8443 behind NPM: agents need mutual TLS end to end (DECISIONS D-20).

## 2. Build the agent

```bash
cd /opt/warden/agent && CGO_ENABLED=0 go build -o warden-agent ./cmd/warden-agent
scp warden-agent deploy/warden-agent.service deploy/target/* dev:/tmp/
```

## 3. `dev` VM

```bash
sudo useradd -r -m -s /usr/sbin/nologin warden
sudo install -d -o warden -g warden /srv/dev
sudo install -d -o warden -g warden -m 0700 /var/lib/warden-agent
sudo install -m 0755 /tmp/warden-agent /usr/local/bin/
sudo cp /tmp/warden-tmpfiles.conf /etc/tmpfiles.d/warden.conf && sudo systemd-tmpfiles --create
cd /tmp && WARDEN_GID=$(id -g warden) docker compose -f compose.yml up -d   # socket proxy
ls -l /run/warden/docker-proxy.sock   # ✓ srw-rw---- root warden
```

## 4. Enroll

On the `warden` guest:

```bash
warden agent add dev       # ✓ prints a one-time token and the exact enroll command
```

On `dev` (within 15 min):

```bash
sudo -u warden warden-agent enroll --state /var/lib/warden-agent \
  --server wss://10.0.20.5:8443 --token wdn_enr_…
# ✓ "This agent's fingerprint: SHA256:5f:2a:…" and "Waiting for confirmation of dev"
```

Back on the `warden` guest:

```bash
warden agent pending       # ✓ same fingerprint, source IP of dev
warden agent confirm dev --fingerprint SHA256:5f:2a:…   # ✓ "enrolled dev · agt_…"
```

`dev` prints `Enrolled as dev … policy v1`. Then on `dev`:

```bash
sudo cp /tmp/warden-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now warden-agent
```

Back on the `warden` guest: `warden agent list` → `dev ● online … policy v1`.

**Negative check:** `warden agent add dev2`, then on `dev` start
`sudo -u warden warden-agent enroll --state /tmp/wa-test --server wss://10.0.20.5:8443 --token …` and on the
`warden` guest run `warden agent confirm dev2 --fingerprint SHA256:00:00` → ✕ "fingerprints don't match;
enrollment rejected", and the agent side ends with "enrollment refused". Clean up with `sudo rm -r /tmp/wa-test`.

## 5. Run, fail, revise

Create `/tmp/p1.json` on the `warden` guest (any small repo works; this one fails at `npm ci` because the
repo has no lockfile, like the prototype's story):

```json
{"goal": "Deploy myapp on dev and verify HTTP health", "target": "dev", "steps": [
 {"n": 1, "kind": "git", "command": "git clone https://github.com/you/myapp /srv/dev/myapp", "purpose": "Get source code", "cwd": "/srv/dev", "timeout_s": 120},
 {"n": 2, "kind": "shell", "command": "npm ci", "purpose": "Install exact dependencies", "cwd": "/srv/dev/myapp", "timeout_s": 300},
 {"n": 3, "kind": "docker", "command": "docker compose -p dev-myapp up -d --build", "purpose": "Start it", "cwd": "/srv/dev/myapp", "timeout_s": 600},
 {"n": 4, "kind": "http_check", "command": "curl -I http://localhost:8080/health", "purpose": "Health check", "cwd": "/srv/dev/myapp", "timeout_s": 15}]}
```

```bash
warden plan propose --as claude-code --file /tmp/p1.json   # ✓ awaiting_approval, shows the hash
warden approve pln_… --hash <first 12 hex>                  # ✓ approved · signed ed25519:…
warden execute pln_…                                        # ✓ "failed at step 2 (exit_code)"
warden plan show pln_…                                      # ✓ step 1 succeeded, 2 failed, 3–4 [skipped]
```

Revise (`/tmp/p2.json`: same steps with `npm install --package-lock-only` inserted before `npm ci`,
renumbered, and `"revises": "pln_…"`):

```bash
warden plan propose --as claude-code --file /tmp/p2.json   # ✓ "revises: pln_…"
warden plan diff <old> <new>                               # ✓ "+ npm install --package-lock-only"
warden approve <new> --hash …  &&  warden execute <new>    # ✓ succeeded (if the app really starts)
```

## 6. The agent checks for itself

```bash
# On dev: a symlink inside the workspace that points out of it.
sudo -u warden ln -s /etc/passwd /srv/dev/myapp/innocent.txt
```

Read it through the read-only path (plan steps behave the same, but changing `commands.allow` to allow
`cat` needs M3's publish flow):

```bash
warden ro dev "cat /srv/dev/myapp/innocent.txt"
# ✓ "refused · denied_path · path … resolves to /etc/passwd, inside deny_paths /etc"
#   Warden's lexical check passed it; the agent's realpath caught it.
warden ro dev "ls -la /srv/dev/myapp"   # ✓ listing
```

Tampering with a plan after approval: `warden validate pln_…` refuses an edited database row
(`hash_mismatch`), and the agent refuses an edited `run` message even when the hashes are rewritten
(signature check). The second case needs a modified Warden, so it's covered by
`tests/integration/test_agent_e2e.py::test_tampered_run_message_refused_by_agent` and the Go tests in
`agent/internal/approval`.

## 7. Kill switch, offline agent, revoke

```bash
# Kill: a plan with `sleep 60` (add `sleep: {}` in a test policy) → warden execute in one terminal,
# warden kill pln_… in another → ✓ "cancelled".
sudo systemctl stop warden-agent        # on dev
warden execute <approved plan>          # ✓ "held · dev is offline"
sudo systemctl start warden-agent       # on dev → ✓ the held plan runs by itself (warden plan show)
warden agent revoke dev                 # ✓ dev drops off; `journalctl -u warden-agent` shows refused reconnects
warden audit verify                     # ✓ Hash chain verified
```

To use `dev` again after revoking: stop the agent, `sudo rm -r /var/lib/warden-agent`, and enroll again.
