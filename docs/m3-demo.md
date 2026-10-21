# M3 checklist: publishing policy to your agents

README section 15, M3 "Done when": *tightening reaches all agents in < 5 s; loosening without the offline
key is rejected*.

**Already proven automatically** with real agent binaries running as an unprivileged user
(`cd backend && sudo uv run pytest tests/integration`):
- `test_policy_distribution.py`:
  - 5 agents receive and acknowledge a tightening within 5 s.
  - A loosening is held by Warden until a registered offline key signs it.
  - The same loosening labelled "tighten" and signed with the online key (a compromised Warden) is refused
    by every agent.
  - The real `warden-sign` binary signs end to end.
  - Lockdown kills runs, holds plans, and releases them after the lift.
- `test_cli_daemon.py::test_m3_dry_run`: this whole checklist through the CLI.

**This checklist** repeats it on your machines. It takes about 30 min. You need the M2 setup (`docs/m2-demo.md`)
with `dev` enrolled. The `warden` alias is the one from M2.

## 1. Offline key, on your laptop

```bash
cd agent && CGO_ENABLED=0 go build -o warden-sign ./cmd/warden-sign   # once, on any machine with Go 1.24
./warden-sign keygen --out ~/.warden/offline.key
# asks for a passphrase twice (12+ characters) · ✓ prints key_id and public
./warden-sign keygen --out /media/usb/offline-backup.key   # recommended: a backup key on another device
./warden-sign keygen --out ~/.warden/offline.key           # ✕ "file exists": keys are never overwritten
```

## 2. Register it on the `warden` guest

```bash
warden keys offline register --public <public from keygen>             # ✓ registered primary offline key ed25519:…
warden keys offline register --public <backup public> --backup         # ✓ registered backup …
warden keys offline list
```

Agents receive offline keys **only at enrollment**. `dev` was enrolled in M2 without one, so it refuses every
loosening until it is re-enrolled:

```bash
# on dev
sudo systemctl stop warden-agent && sudo rm -r /var/lib/warden-agent/*
# on warden
warden agent revoke dev && warden agent add dev
# on dev
sudo -u warden warden-agent enroll --state /var/lib/warden-agent --server wss://10.0.20.5:8443 --token …
# on warden
warden agent confirm dev --fingerprint …
# on dev: ✓ "Trusts offline key ed25519:… for loosening". Compare with `warden-sign pubkey --key ~/.warden/offline.key`
sudo systemctl start warden-agent
```

Enroll a second target the same way if you have one (`dev2` in `targets.yaml`).

## 3. Tighten: immediate

Add a deny path to `/etc/warden/policy.yaml`, e.g. `deny_paths: [..., /srv/dev/secrets]`, then:

```bash
warden policy publish
# ✓   dev · tighten
#       ↓ deny_paths add /srv/dev/secrets
#     Published v2.
#     Pushed to 2 connected agent(s).
warden policy status        # ✓ "dev ✓ v2 online" within a few seconds
journalctl -u warden-agent -n 3   # on dev: ✓ "installed policy v2 (tighten, classified tighten)"
warden ro dev "ls /srv/dev/secrets"   # ✓ refused · denied_path
```

Plans waiting for approval that now break policy show as `invalidated` (`warden plan list`).

## 4. Loosen: needs the offline key

Remove `/srv/dev/secrets` again, then:

```bash
warden policy publish
# ✓   dev · loosen
#       ↑ deny_paths remove /srv/dev/secrets
#     v3 loosens dev, dev2, so it needs the offline key. …
warden policy status                         # ✓ "policy v2" and "pending v3 (publish) waiting for the offline key"
warden policy pending --out /tmp/bundle-v3.json
scp warden:/tmp/bundle-v3.json .             # to your laptop
./warden-sign sign bundle-v3.json --key ~/.warden/offline.key
# ✓ shows "dev · loosen / loosen deny_paths remove /srv/dev/secrets", computed by warden-sign itself
#   Read it before you type y. Then the passphrase. ✓ writes bundle-v3.sig.json
scp bundle-v3.sig.json warden:/tmp/
warden policy sign-upload /tmp/bundle-v3.sig.json   # ✓ Published v3. Pushed to 2 connected agent(s).
```

**Negative checks:**
- `warden policy sign-upload /tmp/bundle-v3.json` (the unsigned file) → ✕ `bad_signature_file`.
- Sign with a key you didn't register (`warden-sign keygen --out /tmp/other.key`, then sign with it) →
  ✕ "not a valid signature from a registered offline key". The pending publish stays.
- While v3 is pending, publish an urgent tighten → it goes out at once as v4, and v3 is superseded.
- `warden policy discard` drops a pending publish you don't want.

The agent-side refusal of a mislabelled loosening needs a modified Warden, so the integration test
`test_loosening_without_offline_signature_refused_by_warden_and_agents` covers it.

## 5. Lockdown

Approve a plan (don't execute it), start a long one (`sleep 60`, with `sleep: {}` allowed) with
`warden execute` in another terminal, then:

```bash
warden lockdown
# ✓ held pln_… · LOCKDOWN · policy vN · killed pln_… (the running one is cancelled)
warden policy status        # ✓ "· LOCKDOWN (read-only only)", agents ✓ vN
warden ro dev "ls /srv/dev" # ✓ still works
warden plan propose …  &&  warden approve …  &&  warden execute …   # ✓ "held · lockdown"
warden lockdown lift        # ✓ "vN+1 loosens …": sign it as in step 4
warden policy sign-upload /tmp/bundle-vN+1.sig.json
warden plan list            # ✓ held plans run by themselves and succeed
warden audit verify         # ✓ Hash chain verified
```
