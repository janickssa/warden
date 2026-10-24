# M6 checklist: the dashboard over WireGuard

README section 15, M6 "Done when": *approve and publish rules from the browser*.

**Already proven in CI** (`cd web && pnpm test:e2e`, real `warden serve`, Chromium with a virtual
authenticator):
- Register a passkey from the one-time link, sign in, approve a plan with the passkey, publish a tightening
  from the Policy page. A loosening only creates a bundle for offline signing.
- The offline state (banner, stale data, every action disabled), keyboard shortcuts (no approve key), the
  four prototype bug fixes, the phone layout, Danish, and the audit chain.
- No request leaves the dashboard's own origin.

**What only you can check** is the real path: your browser, NPM, WireGuard and a real passkey. About 20 min.

## 1. Build and run the dashboard on the warden guest

```bash
cd /opt/warden/web
pnpm install --frozen-lockfile && pnpm build
cp -r .next/static .next/standalone/.next/static
# systemd unit: ExecStart=/usr/bin/node /opt/warden/web/.next/standalone/server.js
#               Environment=PORT=3000 HOSTNAME=127.0.0.1   (User=warden)
sudo systemctl enable --now warden-web
```

`settings.yaml` on the guest:

```yaml
server: {public_url: https://warden.example.dk}   # exactly what you type in the browser
http: {listen_host: 127.0.0.1, listen_port: 8700}  # /api, /ws and /mcp
```

Restart `warden serve` after changing it.

## 2. NPM (one proxy host, two locations)

| Location | Forward to | Websockets |
|---|---|---|
| `/api`, `/ws`, `/mcp` | `http://<warden guest>:8700` | on |
| `/` | `http://<warden guest>:3000` | off |

Access list: your WireGuard subnet only. SSL: your certificate, Force SSL and HTTP/2 on.

✓ `curl -sI https://warden.example.dk/sign-in` over WireGuard returns `200` with
`content-security-policy: default-src 'self'…`.
✓ The same URL from outside WireGuard is refused.

## 3. Your first passkey

```bash
sudo -u warden warden passkey add MacBook
```

Open the printed link on the MacBook (it works once, for 15 minutes) and click **Create passkey**.
✓ "Passkey “MacBook” registered."

Then sign in at `https://warden.example.dk`. ✓ You land on Approvals, and the sidebar footer says
"Signed in with passkey".

Adding a passkey adds an approver, which loosens. So the Policy page now shows "↑ Loosen · waiting for
offline signature". Sign it with `warden-sign sign bundle-vN.json --key offline.key` and upload it there.
✓ "Offline signature verified · vN rolling out".

## 4. Approve from the browser

From Claude Code: *"Run `git status` in /srv/dev/myapp on dev."*

✓ The plan appears on Approvals without a reload.
✓ Approve is disabled until you've scrolled to the last step.
✓ With end-to-end signing on (Settings → Approvals), the button says **Approve & sign…** and your passkey
prompt appears.
✓ Claude's `wait_for_approval` returns, the run's output streams into the step, and the plan ends
"✓ Succeeded".
✓ On dev: `journalctl -u warden-agent` shows that the agent checked your passkey signature.

## 5. Publish a rule from the browser

Policy → Denied paths → add `/srv/dev/secret`, press Enter.
✓ Changes says "↓ Tighten" and "N / N policy tests passed".
✓ **Publish…** asks for your passkey. Then "Policy vN published · rolling out", and Rollout shows every
online agent on vN within seconds.

Then remove `/srv/dev/secret` again.
✓ It says "↑ Loosen", and the button reads **Create bundle for offline signing…**. Nothing changes on any
agent until you upload the signature.

## 6. States worth seeing once

- Turn WireGuard off. ✓ "Can’t reach Warden. Is WireGuard connected?", "Stale · last updated HH:MM", and
  every action is disabled. Turn it back on. ✓ The banner goes away on its own.
- Phone browser. ✓ Only Approvals and Plan detail. The action bar sits below the last step, never over it.
- Settings → Language → Dansk → Save. ✓ The whole dashboard switches to Danish.
- **Lockdown** in the top bar: press and hold for 2 s, then your passkey.
  ✓ The red banner shows, and every agent allows read-only commands only.
  **Lift lockdown…** asks for the offline signature.

If any ✓ doesn't hold, the audit log (Audit log → expand the entry) says what Warden saw.
