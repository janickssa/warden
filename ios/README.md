# Warden for iPhone

The native app (README 10.3, 17.4; PLAN M8). SwiftPM + `xtool.yml`, no Xcode project. It is built, signed and
sent to TestFlight by the Forgejo `ios` runner (`ios-ship` → `ship.sh`). The Foundation-only `WardenCore`
package is tested with `swift test` on Linux.

## ⚠️ MISSING before the first build

| What | Where | Value |
|---|---|---|
| Forgejo host and user | `.forgejo/workflows/ios.yml`, the `uses:` line | `https://MISSING_FORGEJO_HOST/MISSING_FORGEJO_USER/ios-ship@v1` |
| Apple Team ID (10 characters, developer.apple.com → Membership) | `ios/App.entitlements`, `ios/Notify.entitlements` | `MISSING_TEAMID.dk.schwabejss.warden` |
| The repo on Forgejo | Mirror or push `janickssa/warden` to your Forgejo, and enable Actions in its settings | — |

Until these are filled in, nothing on the Forgejo side runs. GitHub runs `WardenCore`'s tests (`ios-core`).

## Apple-side checklist

Done once in the browser; code and CI can't do these.

- [ ] Identifiers: register `dk.schwabejss.warden` (app) and `dk.schwabejss.warden.notify` (notification
      extension).
- [ ] App ID `dk.schwabejss.warden`: enable **Push Notifications** and **App Groups**.
- [ ] App ID `dk.schwabejss.warden.notify`: enable **App Groups**.
- [ ] App Groups: create `group.dk.schwabejss.warden` and tick it on both App IDs.
- [ ] Keychain sharing needs no capability: the `keychain-access-groups` value (`<Team ID>.dk.schwabejss.warden`)
      is enough. The Team ID must match.
- [ ] App Store Connect: create the app record with bundle ID `dk.schwabejss.warden` (the API can't).
- [ ] TestFlight: an internal group with yourself, with automatic distribution.
- [ ] APNs key: developer.apple.com → Keys → "+" → Apple Push Notifications service. Download the `.p8`
      once and keep it out of the repo. Then, on the Warden guest:
      - `/etc/warden/secrets/apns.p8`, mode 0600, owned by `warden`;
      - in `settings.yaml`: `push: {enabled: true, key_id: <Key ID>, team_id: <Team ID>}`;
      - outbound HTTPS to `api.push.apple.com`.

## Layout

```
ios/
├── Package.swift          # products Warden (app) and WardenNotify (extension); targets + WardenKit
├── xtool.yml              # checked against xtool's PackSchema (07.11.2026)
├── Info.plist, Notify-Info.plist, App.entitlements, Notify.entitlements
├── Resources/AppIcon.png  # one 1024 px PNG
├── Sources/
│   ├── Warden/            # SwiftUI app: pairing, Approvals, Plan, Activity, Schedules, Settings
│   ├── WardenNotify/      # notification content extension: commands + Approve (Face ID) on the lock screen
│   └── WardenKit/         # iOS-only shared code: Secure Enclave key, session, App Group store, views, theme
├── Packages/WardenCore/   # Foundation only: models, API client, WebAuthn bytes, plan logic, formats, Danish
├── danish-app.json        # Danish for strings only the app has (the rest comes from the dashboard)
└── scripts/               # gen-danish.py, gen-theme.py (both have --check)
```

## How approvals are signed (DECISIONS M8-01)

- **Pairing:** pairing creates a P-256 key in the Secure Enclave that only Face ID with the currently
  enrolled faces can use (`.biometryCurrentSet`). It can't be exported.
- **Registration:** the app registers the key with Warden through the one-time link, as a WebAuthn "none"
  attestation it builds itself.
- **Signing:** sign-in and every approval are WebAuthn assertions over the same challenges the dashboard's
  passkeys sign, so Warden and the agents verify them the same way.
- **Tested bytes:** `policy-fixtures/ios_webauthn_vectors.json` pins every byte. `WardenCore`'s tests rebuild
  them, and py_webauthn and the Go agent accept them.

Nothing about this needs the dashboard to be reachable from the internet (an iCloud passkey would need a
public `apple-app-site-association` file).

## Local checks

```bash
swift test --package-path ios/Packages/WardenCore     # on Linux or a Mac
python3 ios/scripts/gen-danish.py --check             # after changing Danish in web/ or danish-app.json
python3 ios/scripts/gen-theme.py --check              # after changing design/tokens.json
```
