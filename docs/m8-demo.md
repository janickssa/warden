# M8 checklist: approve from the lock screen

README section 15, M8 "Done when": *approve from the lock screen*.

**Already proven without a phone:**
- `backend/tests/test_api_devices.py`: pair with the link, register the Face ID device key, sign in, register
  for push, approve a plan with the device key, and lose the device when the key is removed.
- `backend/tests/test_push.py`: which events notify (high risk is open-only) and what a push holds (titles and
  IDs, never commands). It also covers the APNs sender: a valid ES256 JWT, per-type switches, dead tokens,
  retries.
- `policy-fixtures/ios_webauthn_vectors.json`: py_webauthn and the Go agent accept the device key's bytes, and
  `WardenCore` rebuilds them exactly (`swift test`, 18 tests).

**What only you can check** is the phone itself: Face ID, the Secure Enclave, APNs and the lock screen. It
takes about 30 minutes once Forgejo is up.

## 0. Fill in what's missing

See `ios/README.md` → "MISSING" and the Apple-side checklist: the Forgejo host and user, your Team ID, the
App IDs, the App Group, the app record and the APNs key. Push to `main` on Forgejo.
✓ The `iOS` workflow passes `swift test`, the build and the offline validation, and uploads to TestFlight.

## 1. Push on the Warden guest

```bash
sudo install -o warden -m 0600 AuthKey_XXXXXXXXXX.p8 /etc/warden/secrets/apns.p8
sudoedit /etc/warden/settings.yaml   # push: {enabled: true, key_id: XXXXXXXXXX, team_id: YYYYYYYYYY}
sudo systemctl restart warden
```

The guest needs outbound HTTPS to `api.push.apple.com` (Apple only, no other internet).

## 2. Pair the iPhone

Install Warden from TestFlight. On the Mac: Dashboard → Settings → Passkeys & sessions → **Pair iPhone**, then
your passkey → **Copy**.

On the iPhone (WireGuard on), open Warden → **Paste** → **Pair with Face ID**, then allow notifications.
- ✓ Settings → Passkeys & sessions lists `Passkey "iPhone"`, and under it the iPhone with "Notifications".
- ✓ Policy shows "↑ Loosen · waiting for offline signature": the iPhone is a new approver. Sign it with the
  offline key and upload it. Until then agents refuse the iPhone's approvals when e2e is on (by design).

## 3. Approve from the lock screen (Done-when)

Lock the iPhone. From Claude Code: *"Run `git status` in /srv/dev/myapp on dev."*
- ✓ Within seconds: "Approval needed · dev", with the goal, the step count and the risk.
- ✓ Long-press it: every command, the verdicts and the target, fetched over WireGuard.
- ✓ **Approve (Face ID)** asks to unlock, then Face ID signs, and the notification goes away.
- ✓ The dashboard shows the plan approved by `dashboard:iPhone` with the passkey "iPhone", and Claude's
  `wait_for_approval` returns.
- ✓ On dev, `journalctl -u warden-agent` shows that the agent checked the signature.

If Face ID doesn't appear inside the notification (the one thing CI can't prove, PLAN M8), the action falls
back to opening the plan in the app, where you approve with Face ID as normal. Note it, and we'll switch the
action to always open the app.

## 4. The other notifications and states

- A high-risk plan: ✓ "■ High-risk plan · dev" offers no Approve; tapping it opens the plan, and Approve stays
  disabled until you've scrolled through every step.
- A failing plan: ✓ "✕ Failed at step 1 · dev", with no output in the notification.
- Settings → iPhone notifications → turn off "Plan failed", then fail a plan. ✓ No push, and the switch shows
  the same in the dashboard's Settings.
- Turn WireGuard off. ✓ The app shows "Can’t reach Warden" with the last update time, and the push still
  arrives (it goes through Apple).
- A running plan: ✓ the Kill switch needs a 2 s press-and-hold with haptics.
- Settings → Lockdown: ✓ press and hold, then Face ID; the dashboard shows "■ Lockdown active". Lift it in the
  dashboard with the offline key.
- Dashboard language Dansk: ✓ the app follows on its next refresh.
