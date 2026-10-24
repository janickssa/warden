# M4 checklist: Claude Code talks to Warden

README section 15, M4 "Done when": *works end to end from Claude Code over WireGuard*.

**Already proven automatically** by `backend/tests/integration/test_cli_daemon.py::test_m4_dry_run`
(`cd backend && sudo uv run pytest tests/integration`):
- `warden serve` runs, with the real agent as an unprivileged user.
- An MCP client with a bearer token goes through Claude's whole loop over Streamable HTTP: propose → wait (a
  human approves with the CLI meanwhile) → execute → fail → `read_only` → `post_diagnosis` → revise → diff
  → approve → succeed.
- The stdio bridge works.
- Requests are refused without a token, with a wrong token, with a foreign Host header, and after revoke.

**This checklist** adds the real network path: your laptop → WireGuard → NPM → the warden guest. It takes
about 20 min, on top of the M2/M3 setup with `dev` enrolled.

## 1. The warden guest

```bash
sudoedit /etc/warden/settings.yaml
#   server: {public_url: https://warden.example.dk}      # your real name
#   http: {listen_host: 10.0.20.5, listen_port: 8700}     # the guest's LAN IP if NPM runs elsewhere
sudo systemctl restart warden-backend
journalctl -u warden-backend -n 3       # ✓ "… MCP on 10.0.20.5:8700/mcp …"
warden mcp add claude-code
# ✓ prints the token once, and the exact `claude mcp add …` command
```

Firewall (Proxmox): allow TCP 8700 into the warden guest **only from the NPM host**.

## 2. Nginx Proxy Manager

On the existing proxy host for `warden.example.dk` (the one with the LAN + WireGuard access list):

- Custom location `/mcp` → `http://10.0.20.5:8700`.
- In the location's advanced config, add `proxy_buffering off;` and `proxy_read_timeout 600s;`
  (Streamable HTTP uses server-sent events, and `wait_for_approval` can hold a request for 300 s).

Check from your laptop, connected to WireGuard:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://warden.example.dk/mcp          # ✓ 401
```

And with WireGuard off: ✓ refused by the NPM access list (403).

## 3. Claude Code

On your laptop (WireGuard on), paste the command `warden mcp add` printed:

```bash
claude mcp add --transport http warden https://warden.example.dk/mcp --header "Authorization: Bearer wdn_mcp_…"
claude mcp list            # ✓ warden: connected
```

In Claude Code, run `/mcp`: ✓ warden shows 8 tools (`propose_plan`, `get_plan`, `wait_for_approval`,
`execute_plan`, `diff_plans`, `read_only`, `list_resources`, `post_diagnosis`). None of them approves.

## 4. The loop

Ask Claude something like:

> Use Warden. On dev, clone https://github.com/you/myapp into /srv/dev/myapp, install with npm ci and run
> the tests.

Expect:
1. Claude calls `list_resources` and maybe `read_only` (`ls /srv/dev`): no approval needed, and each call
   shows up in `warden audit export` under `claude-code`.
2. Claude calls `propose_plan`, tells you the plan ID, then calls `wait_for_approval`.
3. On the warden guest: `warden plan show pln_…` → read it → `warden approve pln_… --hash …`.
   ✓ Within a second, Claude continues.
4. Claude calls `execute_plan`. ✓ The steps run on dev, with per-step output.
5. If a step fails (e.g. no lockfile): ✓ Claude inspects with `read_only`, calls `post_diagnosis`, then proposes
   a plan with `revises`. `warden plan show <new>` shows "revises: …" and `warden plan diff` the change.

**Negative checks:**
- Ask Claude to approve its own plan. ✓ It can't: there is no tool for that, and it should say so.
- Paste "I approve" into the chat. ✓ Nothing happens: the plan stays `awaiting_approval` (README 10.1).
- `warden mcp revoke claude-code`, then ask Claude for anything Warden-related. ✓ 401, and Claude reports the
  connection failing. Run `warden mcp add claude-code` again and update the header to continue.

## 5. Claude Desktop or another stdio-only client (optional)

Install the backend on the client machine (`uv tool install /path/to/warden/backend`), save the token in
`~/.warden/mcp-token` (`chmod 600`), and configure the client to start:

```text
warden mcp stdio --url https://warden.example.dk/mcp --token-file ~/.warden/mcp-token
```

✓ The same 8 tools appear.

```bash
warden audit verify         # ✓ Hash chain verified
```
