# Decisions

Rule of thumb from the brief: **the README wins on security and behaviour; the prototypes win on
visuals and copy.** Items marked **❓ needs your answer** are open; everything else is a decision I've
made and will follow unless you say otherwise. Nothing here weakens a §1 invariant. Items that would
have done so are raised as questions instead.

---

## A. Defaults for open questions (README §18 and the brief)

| ID | Topic | Decision |
|---|---|---|
| D-01 | Local gatekeeper model | Configurable in `gatekeeper.yaml`. Default `qwen2.5:14b-instruct` (12–16 GB VRAM row). **❓ What GPU/VRAM do you have?** I'll pick the size from the §9 table. |
| D-02 | Domain | `warden.lan`, configurable (`server.domain`); the agent endpoint is `wss://<domain>:8443/agent`. |
| D-03 | Public MCP OAuth (M9) | Not decided. **I'll stop and ask before starting M9.** |
| D-04 | Offline key | YubiKey 5C. The UI warns until a backup YubiKey is registered (README §17.3 Settings). |
| D-05 | Offline key algorithm | The README specifies ed25519 for bundle signatures. YubiKey PIV only supports Ed25519 from **firmware 5.7**; older 5C keys support only ECDSA P-256/P-384 and RSA. Plan: bundles carry `alg` per signature; `warden-sign` uses Ed25519 on firmware ≥ 5.7 and falls back to ECDSA P-256 otherwise; agents accept exactly the algorithm pinned for each key. **❓ Do you know your YubiKey firmware version?** (`ykman info`). If both are ≥ 5.7, everything stays pure ed25519. |
| D-06 | UI language | English by default, with a Dansk option per README §17.2. Units are always metric. |

## B. Refinements that make the spec stricter (README will be updated when the milestone lands)

| ID | Topic | Decision and why |
|---|---|---|
| D-07 | What the plan hash covers | README §1.2 says "SHA-256 over the canonical JSON of its **steps**". If the hash and signature cover only the steps, an approval for steps on `dev` could be replayed against `dev2` with identical steps. The hash will cover `{v, plan_id, target, goal, revises, steps}`. The approval signature covers `{plan_hash, plan_id, target, approved_at, expires_at}`. Agents also keep a persistent log of executed plan IDs, so one approval can't run twice. This is stricter and doesn't weaken invariant 2. |
| D-08 | Canonical JSON | Sorted keys, no insignificant whitespace, UTF-8, strings must already be NFC (otherwise refused rather than silently normalised), no floats (timeouts are integers), Python and Go implementations tested against the same vectors. |
| D-09 | Metacharacters in plan steps | §6 requires `read_only` to reject `; && || \` $()`, pipes and redirects. I apply the same rule to **plan steps too**, even inside quotes (argv never reaches a shell, but refusing is simpler and fails closed). Side effect: a step like `git commit -m "fix; typo"` is refused. Non-ASCII in binaries, flags and (for now) paths is refused as well, which defeats look-alike characters. Either can be relaxed later. |
| D-10 | How the CLI authenticates as a human (M1) | The CLI runs on the `warden` guest as the admin Unix user. The DB, keys and admin socket are mode 0600/0700, and the MCP/API process runs as a separate user without access. Approving requires typing the first 12 hex characters of the plan hash. Approvals carry `by: "cli:<unix-user>"`. |
| D-11 | CLI approvals and `approvals.e2e` | With `approvals.e2e` on (the default), agents only accept passkey-signed approvals, so from M3 on a CLI approval would be refused at the agent. The CLI will say so and point to the dashboard or app. (A FIDO2-on-CLI path via libfido2 is possible later.) In M1/M2, before e2e exists, CLI approvals are signed with the approval key. |
| D-12 | `approvals.e2e` is part of the signed bundle | The README lists `approvals.e2e` as an ordinary setting. Because agents enforce it, switching it **off** must be classed as *loosen* (offline key), otherwise a compromised Warden could flip it and sign approvals itself. Switching it on is *tighten*. The same applies to the approver passkey list (README already classes adding a passkey as loosen). |
| D-13 | Bootstrap trust root | At enrollment, an agent receives the CA certificate, the online and offline public keys and the current approver passkeys in its first bundle. Enrollment is gated by fingerprint comparison plus your passkey, and later changes only arrive through signed bundles. First-time setup (before any passkey exists) is `warden init` on the guest, which registers the first passkey and the offline public key. |
| D-14 | MCP tools beyond §6 | §4 says Claude "posts its findings to the plan" (the Diagnosis panel), but §6 has no tool for it. Plan: add `post_diagnosis(plan_id, findings)`. It only appends text to a **failed** plan and changes no state. The dashboard's "Diagnose & propose fix…" note from you reaches Claude through `get_plan` (field `human_note`). No other tools will be added. |
| D-15 | Shared policy corpus | The policy engine exists in Python (central) and Go (agent). Both run one YAML fixture corpus in `policy-fixtures/` so they can't drift. |
| D-16 | Docker deny extras | Beyond `--privileged` and `-v /:`, the matcher also refuses `--pid=host`, `--network=host`, `--cap-add`, `--device` and `--security-opt` unless policy explicitly allows them (safe default per §16 rule 8). |
| D-17 | Invalid deny regex | The prototype silently skips an invalid `deny_patterns` regex. The backend and agent instead refuse to load the policy, and the policy test suite blocks publishing (§7A step 2). |
| D-18 | Gatekeeper `</untrusted>` smuggling | Untrusted text has any `<untrusted>` / `</untrusted>` sequences escaped before wrapping, so content can't close the delimiter early. |
| D-19 | No gatekeepers configured | `final_verdict = escalate` with a row saying "No gatekeepers configured". Never `allow`. This applies to M1–M4, before M5 exists. |

## C. README ↔ prototype disagreements

| ID | Where | README says | Prototype does | Resolution |
|---|---|---|---|---|
| X-01 | Plan state `held` | A **status** (`approved → held → approved`) | A boolean `held` flag on an `approved` plan | README wins: it is a status. The UI shows it as "⏸ Approved · held" (prototype copy). |
| X-02 | Gatekeeper-unavailable copy | "Unavailable — counted as escalate" | "○ Unavailable · counted as escalate" in the warn colour | Prototype copy, as you asked (brief, bug 3). |
| X-03 | Sidebar items | Includes **Groups** (Approvals, Plans, Live feed, Schedules, Agents, Groups, Policy, Audit log, Settings) | The screenshot sidebar has no Groups entry, although a Groups page exists | README wins (navigation is behaviour); Groups sits between Agents and Policy, styled like the others. |
| X-04 | Sidebar highlight on plan pages | Not specified | Highlights the page you came from, including Policy/Groups/Agents | Fixed per brief bug 1: Approvals if the plan is `awaiting_approval`/`reviewing`, otherwise Plans. The back link uses the real referrer (Approvals, Plans, Live feed, Audit log, Agents, Schedules) and falls back to Approvals/Plans. It is never "Policy" or "Groups". |
| X-05 | Phone action bar | "single column … Plan detail (approve/reject)" | The sticky bar covers content; the hint squeezes into a narrow column (screenshot `03-web-narrow.jpg`) | Fixed per brief bug 2: bottom padding = bar height + `env(safe-area-inset-bottom)`; the hint gets its own full-width line; Reject and Approve are full-width side by side. |
| X-06 | iPhone gatekeeper unavailable | §17.6 applies to every screen | Implemented only on web; the iPhone prototype has no such state | Fixed per brief bug 3: same state in the app; final verdict computed in `WardenCore` and unit-tested. |
| X-07 | Replace offline key, no backup | "new key must be signed by the current offline key, or by the backup … if the current one is lost" | The "Backup offline key · none registered" option stays selectable | Fixed per brief bug 4: disabled and greyed with "Register a backup key first"; "Current offline key" preselected. |
| X-08 | Setting names | `approvals.passkey_medium`, `approvals.chat`, `approvals.e2e` | `approvals.passkey_medium_risk`, `approvals.chat_elicitation`, `approvals.passkey_signed` | README names. |
| X-09 | Status colours | `ok` / `warn` / `danger` in OKLCH, each with a 100–900 ramp (§17.2) | The same OKLCH values hard-coded in `warden-data.js`; `nocturne/styles.css` has no status tokens and no ramps for them | `tokens.json` = everything parsed from `styles.css` + a `status` group with the README values, plus generated OKLCH ramps on Nocturne's lightness scale. No hex in components. |
| X-10 | Code-block colour name | Plan detail says "`surface-2` block" | Uses `--color-neutral-900` | `surface-2` becomes a semantic alias to `neutral-900` in `tokens.json`. |
| X-11 | Fonts and icons | Self-hosted, works offline (§16 rule 15) | Loads Google Fonts and Phosphor from unpkg | Self-host via `next/font/local` and `@phosphor-icons/react`; a Playwright test blocks external requests. |
| X-12 | Approve button label | "Approve" (+ passkey per 10.0) | "Approve & sign…" when a passkey signature is needed | Prototype copy (it reflects e2e signing). |
| X-13 | Agent disconnect | "finishes or kills the current step (per its timeout)" | "step killed after its 60 s timeout" | Same behaviour: the running step may finish within its own timeout, after which it's killed; the remaining steps are aborted and the plan becomes `failed` with `agent_disconnected`. |
| X-14 | Policy refusal exit code | Not specified | Shows `126` for a step the agent refused | Use 126 in the UI/audit (the conventional "cannot execute"); the reason code `policy_violation` is the authoritative field. |
| X-15 | Repo layout | `design/screenshots/` next to `design/prototypes/` | The zip had `screenshots/` inside the prototype folder | Unpacked to README layout. `design/prototypes/_ds/` keeps a copy of Nocturne only so the prototype HTML still opens; `design/nocturne/` is the canonical copy. The original zip is untouched at the repo root. Delete it if you like. |

## D. Things I noticed but am not changing (FYI)

- **Prototype test count "148/148".** This is mock data. The real policy test suite will be the shared fixture corpus (target ≥ 150 cases at M1).
- **`main` commit message.** The README update on `main` has the subject "Update print statement from 'Hello' to 'Goodbye'". It's harmless, but worth knowing if you search history.
- **Swift isn't installed** in this cloud container. That only matters at M8, where the Forgejo `ios` runner builds the app and `WardenCore` tests can run in a Swift container.
