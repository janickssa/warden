# Warden — build plan

Source of truth: `README.md` (spec). Visual/behavioural reference: `design/prototypes/` (v2).
Disagreements and defaults: `DECISIONS.md`. Milestones follow README §15 strictly; each one
starts by re-reading §1 (Core invariants) and §16 (Agent rules) and refining its section below
before any code is written.

Status legend: ☐ not started · ◐ in progress · ☑ done (with the test or manual check that proves it)

---

## Cross-cutting rules (apply to every milestone)

- **Fail closed:** any error in parsing, policy, hashing, signature checks, gatekeepers or auth
  results in deny/escalate/refuse, never allow. Each module gets at least one test proving it.
- **No shells:** no `shell=True`, `os.system`, `sh -c`, or string-built commands. Python: argv lists;
  Go: `exec.Command(argv[0], argv[1:]...)`. A CI grep check fails the build if any of these appear.
- **No authority for Claude:** MCP tools never approve, edit policy, read or change settings, or bypass
  agent checks. A test enumerates the registered MCP tools and fails on any name outside the §6
  allowlist (plus the additions listed in DECISIONS.md D-14).
- **Shared policy fixtures:** the policy engine exists twice (Python centrally, Go in the agent). Both
  run the same fixture corpus in `policy-fixtures/*.yaml` (command, context, expected verdict and reason
  code), so the two can't drift.
- **Units/time:** metric/SI, 24-hour clock, Europe/Copenhagen in the UI, ISO 8601 with offset in the API.
- **Commits:** one per logical step, conventional subject line, tests in the same commit as the code.
- **Checks before every push:** `ruff check`, `ruff format --check`, `mypy --strict`, `pytest`;
  from M2, also `go vet`, `staticcheck` and `go test ./...`; from M6, also `pnpm lint`, `pnpm typecheck`,
  `vitest` and `playwright`.

---

## Milestone overview

| # | Milestone | Main deliverables | Done when (README §15) | Proven by |
|---|---|---|---|---|
| M1 ☑ | Core | Plan store, state machine, canonical hashing, policy engine, read-only checker, audit chain, CLI approval | Plans propose, approve and validate locally | `tests/e2e/test_m1_local_flow.py` + documented CLI session in `docs/m1-demo.md` |
| M2 | Agent | `warden-agent` (Go), enrollment + internal CA, mTLS WebSocket, dispatcher, per-step checks, baseline rules, streaming, kill, disconnect handling, docker-socket-proxy | Plan runs on `dev`, fails and revises; a tampered plan is refused | Go + pytest integration (agent in a container) and a manual run on `dev` documented in `docs/m2-demo.md` |
| M3 | Policy distribution | Bundle compiler, tighten/loosen classifier (default loosen), online/offline keys, `warden-sign`, groups, rollout tracking, lockdown, held/invalidated | Tightening reaches all agents in < 5 s; loosening without the offline key is rejected | `tests/integration/test_rollout.py` (5 agents, timed), plus classifier property tests |
| M4 | MCP | FastMCP tools (§6), Streamable HTTP + stdio, elicitation, MCP auth | Works end-to-end from Claude Code over WireGuard | MCP client test + manual Claude Code session in `docs/m4-demo.md` |
| M5 | Gatekeepers | Panel (strictest/unanimous), Ollama, OpenAI, Anthropic and OpenAI-compatible adapters, prompt, scrubbing, injection fixtures | Injection tests escalate or deny on every reviewer | Recorded-response tests for every adapter in CI + live opt-in run against real models |
| M6 | Dashboard | `design/tokens.json`, Next.js app, passkey auth, e2e approval signing, every §17.3 page, the 4 prototype bug fixes | Approve and publish rules from the browser | Playwright suite (states from §17.6 per page) + manual check over VPN |
| M7 | Schedules | Templates, APScheduler cron, expiry, pause/resume, failure notify | Nightly job runs and reports | Time-travel scheduler test + one real nightly run |
| M8 | iPhone app | SwiftUI app, `WardenCore` package, APNs, Face ID, lockdown, approve with edits | Approve from the lock screen | `swift test` on Linux (WardenCore + view models) + TestFlight manual check |
| M9 | Public MCP | Public NPM host for `/mcp` only, OAuth | Works from the Claude app without VPN | **Ask before starting** (OAuth design choice, §18) |
| M10 | Agent updates | Offline-signed binaries, canary rollout, auto-rollback | New agent version rolls out with no manual steps | Integration test: canary + rollback on missing heartbeat |

---

## M1 Core — detailed plan

**Goal:** everything that decides *whether* something may run, with no networking yet. "Execute" in
M1 means *validate for dispatch*: re-verify hash, approval signature, status and policy, and produce the
signed dispatch envelope that M2's agent will consume. Nothing runs commands in M1.

### Files

```
backend/
├── pyproject.toml                 # uv; deps: pydantic>=2, sqlmodel, pyyaml, python-ulid, cryptography
│                                  # dev: pytest, pytest-asyncio, hypothesis, ruff, mypy
├── src/warden/
│   ├── __init__.py
│   ├── config.py                  # loads policy.yaml / targets.yaml / settings (strict, extra=forbid)
│   ├── errors.py                  # typed errors; every one maps to deny/refuse
│   ├── timeutil.py                # aware datetimes, Europe/Copenhagen formatting helpers
│   ├── plans/
│   │   ├── models.py              # Plan, Step, StepKind, PlanStatus, Approval, PolicyResult (Pydantic)
│   │   ├── canonical.py           # canonical JSON (sorted keys, no whitespace, NFC check, no floats)
│   │   ├── hashing.py             # plan_hash() -> "sha256:<hex>"
│   │   ├── placeholders.py        # {{stepN.name}} / {{secret:NAME}} parsing + capture type validators
│   │   ├── state.py               # transition table (README §4) + guard functions
│   │   ├── diff.py                # structured step diff (LCS on normalised commands)
│   │   ├── store.py               # SQLModel tables, WAL, transactional transitions (compare-and-set)
│   │   └── service.py             # propose / approve / approve_with_edits / reject / expire / validate
│   ├── policy/
│   │   ├── schema.py              # policy.yaml model incl. groups (§7B), extra=forbid
│   │   ├── lexer.py               # input hygiene + shlex(posix) → argv
│   │   ├── paths.py               # lexical normalisation, workspace/deny_paths checks, PathResolver protocol
│   │   ├── matcher.py             # structural matcher: binary, subcommand, flags, hosts, docker names
│   │   ├── effective.py           # global + baseline + groups → effective rules (strictest wins)
│   │   ├── baseline.py            # non-overridable baseline rules (mirrors the agent's compiled-in set)
│   │   ├── readonly.py            # §8 read-only allowlist + group read_only modes
│   │   └── engine.py              # check_plan / check_step / check_read_only → PolicyResult with reason codes
│   ├── signing.py                 # ed25519 approval key (load 0600 file, sign/verify envelope)
│   ├── audit.py                   # append-only log with SHA-256 hash chain, verify(), JSONL export
│   └── cli.py                     # `warden` CLI (argparse): plan, approve, reject, validate, audit, policy check
├── tests/
│   ├── conftest.py                # tmp DB, tmp workspace tree with symlinks, fixed clock
│   ├── test_canonical_hashing.py
│   ├── test_state_machine.py
│   ├── test_lifecycle.py
│   ├── test_store_concurrency.py
│   ├── test_diff.py
│   ├── test_placeholders.py
│   ├── policy/
│   │   ├── test_lexer_adversarial.py
│   │   ├── test_paths_adversarial.py
│   │   ├── test_flags_adversarial.py
│   │   ├── test_matcher.py
│   │   ├── test_groups_never_widen.py
│   │   ├── test_baseline.py
│   │   ├── test_readonly.py
│   │   └── test_shared_fixtures.py   # runs ../../policy-fixtures/*.yaml
│   ├── test_signing.py
│   ├── test_audit_chain.py
│   ├── test_cli.py
│   ├── test_no_shell.py           # AST scan of src/ for shell=True / os.system / os.popen
│   └── e2e/test_m1_local_flow.py
config/
├── policy.example.yaml            # README §7 + §7B example
├── targets.example.yaml
└── settings.example.yaml          # approvals.expiry_min etc. (README §10.0 names)
policy-fixtures/                   # shared corpus for Python (M1) and Go (M2)
docs/m1-demo.md                    # recorded CLI session for the Done-when check
```

### Key interfaces

```python
# plans/hashing.py
def plan_hash(plan: PlanTemplate) -> str: ...
#   input = canonical JSON of {"v":1, "plan_id", "target", "goal", "revises", "steps":[...]}
#   (binds target, id and goal; see DECISIONS D-07). Steps keep placeholders unexpanded.

# plans/state.py
TRANSITIONS: Mapping[PlanStatus, frozenset[PlanStatus]]   # exactly README §4
def transition(plan: Plan, to: PlanStatus, *, reason: str, actor: Actor) -> Plan  # raises IllegalTransition

# plans/service.py
class PlanService:
    def propose(self, req: ProposeRequest, actor: Actor) -> Plan             # policy runs first; M1 panel = none → escalate
    def approve(self, plan_id: str, expected_hash: str, actor: HumanActor) -> Plan
    def approve_with_edits(self, plan_id: str, edits: list[StepEdit], actor: HumanActor) -> Plan  # → reviewing → awaiting_approval, new hash
    def reject(self, plan_id: str, reason: str | None, actor: HumanActor) -> Plan
    def expire_due(self, now: datetime) -> list[Plan]
    def invalidate_against(self, policy: EffectiveRules, version: int) -> list[Plan]   # used by M3
    def hold / release(...)                                                      # used by M2/M3
    def validate_for_dispatch(self, plan_id: str) -> DispatchEnvelope           # M1's "execute": all checks, no run

# policy/engine.py
def check_step(step: Step, rules: EffectiveRules, resolver: PathResolver) -> StepVerdict
def check_plan(plan: PlanTemplate, rules: EffectiveRules, resolver: PathResolver) -> PolicyResult
def check_read_only(command: str, rules: EffectiveRules, resolver: PathResolver) -> StepVerdict

class PathResolver(Protocol):            # central side: lexical only; agent side (M2): real realpath
    def resolve(self, path: str, cwd: str) -> ResolvedPath
```

`Actor` is a tagged type: `HumanActor(channel="cli"|"dashboard"|"iphone"|"chat", id=...)` vs.
`ClaudeActor(client=...)`. Every approval/reject/edit function only accepts `HumanActor`, so the type
checker rejects any MCP path that tries to call them. Tests also check this at runtime.

### Policy engine details (central side)

1. **Input hygiene (before shlex, D-09):** NFC-normalise once at intake (the stored, shown and hashed
   text is the normalised one). Refuse anywhere, quoted or not: `;` `|` `&` `` ` `` `$` `>` `<`, plus
   newline/CR/NUL/other control and format characters, zero-width characters and bidi controls. `{{` / `}}`
   are only allowed as an exact whole-element placeholder (`{{stepN.name}}`, `{{secret:NAME}}`).
2. **Unicode by argv position (after shlex, D-09):** ASCII-only for the program name, subcommands, flag
   names (before `=`), `cwd` and path-like arguments (`non_ascii_token`, e.g. Cyrillic `с` in `сurl`).
   Other values (`git commit -m "Tilføj login"`, `--message=Rettet fejl i søgning`) may also contain
   Latin-script letters (Latin-1 Supplement + Latin Extended-A); other scripts, look-alike punctuation
   such as fullwidth `；` and leftover combining marks are refused (`disallowed_char`, naming the argv
   position and code point).
3. **shlex(posix=True)** → argv; parse errors (unbalanced quotes) → deny.
4. **Structural match** per binary from `commands.allow`: subcommand allowlist (skipping global options
   like `git -C <dir>`, `docker compose -p <name>`), flag deny list matching `--flag`, `--flag=value`,
   `-fVALUE` and clustered short flags (`-sSo`), plus the `--` end-of-options marker.
5. **Kind ↔ binary:** `git` steps must run `git`, `docker` steps `docker`, `http_check` runs `curl`
   restricted to HEAD/GET with no output-writing flags; `shell` covers the remaining allowed binaries.
6. **Paths:** every path-like argument plus `cwd` is normalised lexically (`..` collapsed, relative
   paths joined to `cwd`) and must sit inside `workspace_roots` and outside `deny_paths`. The central
   side can't follow symlinks on the target, so the agent repeats this with real `realpath` (M2). In M1
   the `LocalPathResolver` used in tests runs real `os.path.realpath` on a temp tree to prove the logic
   (symlink out of the workspace, symlink loops, dangling symlinks, `..` after a symlink).
7. **Network:** `git clone` URLs must be `https://` with a host in `git_hosts` (no userinfo, no
   `ext::`/`file://`/`ssh://`, no `--upload-pack`, no `-c`); `curl` hosts must match `http_check_hosts`.
8. **Docker:** `-p/--project-name` must match `allowed_projects`; container args must not match
   `denied_containers`; refuse `run`/`exec` unless allowed, plus `--privileged`, `-v /:`,
   `--pid=host`, `--network=host`, `--cap-add`, and `--device`.
9. **deny_patterns** (regex backup layer) run on both the raw command and `shlex.join(argv)`.
   Invalid regex → policy load fails (never silently skipped, unlike the prototype).
10. **Baseline** (non-overridable, same list as the agent): `rm -rf /` variants, writes under `/etc`,
    `/usr`, `/boot`, `--privileged`, mounting `/`, and touching the agent's own binary, config or keys.
11. **Limits:** step count, `timeout_s ≤ step_timeout_s`, `expect_exit` integer 0–255.
12. **Groups → effective rules:** union of deny lists, minimum limits, strictest read-only mode,
    `passkey`/`unanimous` OR-ed. Implemented as a pure function whose output is *always* at least as
    strict as the global rules; enforced by Hypothesis property tests.

### State machine and lifecycle

Statuses and transitions exactly as in README §4, including `reviewing`, `held` and `invalidated`.
Store transitions use compare-and-set (`UPDATE … WHERE id=? AND status=?`) inside a transaction, so two
channels approving at the same moment can't both succeed (the loser gets "decided elsewhere").
Approval stores `{by, at, hash, signature}`; the hash is recomputed and compared at approval and again
at `validate_for_dispatch`. With no gatekeepers in M1, `final_verdict` is `escalate` with the reviewer
row "No gatekeepers configured", so nothing looks auto-allowed (fail closed).

### CLI (human channel for M1)

`warden plan propose --file plan.json` (test/dev input only; Claude proposes via MCP from M4) ·
`warden plan list|show <id>` (full commands, never truncated) · `warden approve <id> --hash <first 12 hex>`
(you must type the hash prefix shown by `show`: a deliberate action with no "approve all") ·
`warden approve-with-edits <id> --edit N=<command>` · `warden reject <id> [--reason]` ·
`warden validate <id>` · `warden audit verify|export` · `warden policy check <file>`.

The CLI authenticates as a human through local OS access: it runs on the `warden` guest as the admin
Unix user, and the DB, keys and an admin socket are mode 0600/0700. The MCP server process runs as a
different user and can't reach them. See DECISIONS D-10.

### Tests (M1 Done-when and the brief's minimums)

- **Hashing:** stable across key order and formatting; any change to target, id, goal or any step field
  changes the hash; unexpanded placeholders are hashed; text is NFC-normalised at intake and the hasher
  refuses non-NFC input; Hypothesis round-trip; shared test vectors for the Go agent.
- **State machine:** every legal transition in §4 succeeds; every other (from, to) pair raises
  (generated exhaustively); terminal states are final.
- **Lifecycle:** propose → policy deny → rejected (final, can't be approved); propose → awaiting → approve
  → approved; approve-with-edits → reviewing → awaiting with a **new hash**, `edited: true` and a
  before/after audit diff; an edit that policy denies → rejected; reject; expire at 30 min (fixed clock);
  awaiting/approved → invalidated by a stricter policy; approved → held → approved; approving with a stale
  hash fails; approving an expired plan fails; revise: `revises` links, diff output, and a failed plan
  can't be re-approved or resumed.
- **Stop-on-first-failure semantics:** a pure run-result reducer (exit ≠ expect, timeout,
  policy_violation → failed with the remaining steps `skipped`; kill → cancelled) is unit-tested now and
  reused by the M2 dispatcher.
- **Policy adversarial suite** (≥ 150 cases, shared YAML corpus): `../` traversal (plain, `cwd`-relative,
  `/srv/dev/../prod`, encoded variants), symlinks out of the workspace, symlink loops, `--output=x`,
  `-o x`, `-sSo x`, `--upload-file`, `-K`, `--config=`, `-c` / `--upload-pack` on git, Cyrillic and
  Greek look-alikes, fullwidth punctuation, zero-width and bidi characters, `;`, `&&`, `||`, `|`, `` ` ``,
  `$()`, `${IFS}`, newline injection, redirects, unbalanced quotes, Danish values that must **pass**
  (`-m "Tilføj login"`, `--message=Åbn ærlig øl`, decomposed `å` normalised), and æ/ø/å in a path or flag
  that must be refused, `--` tricks, denied containers via
  `name=` filters, and docker `--privileged` / `-v /:/host`.
- **Groups never widen:** a Hypothesis property test (for random global policies and random groups,
  effective ⊆ global), plus explicit cases for each row of the §7B table.
- **Read-only:** allowlist, refused metacharacters, group modes allowed/restricted/off with reasons
  naming the group.
- **Audit:** chain verifies; editing, deleting or reordering any row is detected; JSONL export
  round-trips.
- **No shell:** an AST scan fails on `shell=True`, `os.system`, `os.popen` and `subprocess` with a string.
- **E2E (Done when):** `test_m1_local_flow.py` drives the CLI in-process: propose → show → approve with
  the hash prefix → validate_for_dispatch OK → tamper with a step in the DB → validate refuses with
  `hash_mismatch` → simulated step failure via the reducer → propose a revision → diff shown → approve
  revision → validate OK → `audit verify` OK.

### M1 commit sequence

1. `chore: scaffold backend (uv, ruff, mypy strict, pytest) and config examples`
2. `feat(plans): models, canonical JSON and plan hashing` + tests
3. `feat(plans): lifecycle state machine` + exhaustive tests
4. `feat(audit): hash-chained append-only log` + tamper tests
5. `feat(policy): schema, lexer and input hygiene` + adversarial lexer tests
6. `feat(policy): paths, structural matcher, baseline` + adversarial suite + shared fixtures
7. `feat(policy): groups and effective rules` + never-widen property tests
8. `feat(policy): read-only allowlist`
9. `feat(plans): SQLite store and plan service (approve, edits, reject, expire, invalidate, hold)`
10. `feat(signing): approval key and dispatch envelope`
11. `feat(cli): warden CLI` + CLI tests
12. `test: M1 end-to-end local flow` + `docs/m1-demo.md`; mark M1 ☑ here

---

### M1 result ☑ (21.10.2026)

Done-when "plans propose, approve and validate locally" is proven by `backend/tests/e2e/test_m1_local_flow.py`
and the recorded session in `docs/m1-demo.md`. 749 tests pass; `ruff`, `ruff format` and `mypy --strict`
are clean. Refinements made along the way are listed in DECISIONS.md section B2 (M1-01 … M1-14).

Differences from the plan above:
- Commits 6–8 became two: the matcher/baseline/engine with the fixture corpus, then groups and read-only.
- The corpus has 276 cases (target was ≥ 150), plus 30 symlink tests on a real filesystem.
- `PlanService` also has `start_run` / `finish_run` with the stop-on-first-failure reducer, ready for the M2
  dispatcher. Nothing executes commands in M1.
- CI: `.github/workflows/backend.yml` runs the same checks on every push.

## M2 Agent — outline (detailed before starting)

Go module `agent/` with `cmd/warden-agent`, `cmd/warden-sign` (keygen only in M2), and `internal/{conn,
policy, exec, docker, baseline, enroll}`. Backend: `agents.py` (registry, internal CA via `cryptography`,
one-time 15-min tokens, fingerprint confirmation) and `dispatch/` (WSS on :8443 with mTLS, signed envelope,
output streaming, heartbeats every 15 s, kill = SIGTERM, then SIGKILL after 10 s, process-group kill,
`agent_disconnected` handling, replay protection: the agent keeps a persistent log of executed
plan IDs). The agent re-runs the shared fixture corpus in `go test`. Tests: tampered hash, unsigned or
invalid approval, replayed plan, wrong target, baseline violations, symlink escapes with real `realpath`,
output cap at 1 MB (truncated, step continues, exit code still counts), timeout and kill. Agents connect directly to the warden guest, not through NPM (D-20). Done-when demo
on `dev` in `docs/m2-demo.md`.

## M3 Policy distribution — outline

`policy_dist/`: compile per target (global + targets + groups + approver keys), classifier (field
direction table; anything unknown → loosen; Hypothesis tests), bundle schema with
`additionalProperties: false` on both sides, online-key signing, pending bundles for loosening,
`warden-sign keygen|bundle|trust-offline` with passphrase-encrypted ed25519 key files (D-04; YubiKey later behind the signer interface), signature upload, version monotonicity, atomic
swap + ack `{version, sha256}`, 60 s poll + push, rollout state, `held` for behind/offline agents, and
`invalidated` re-checks on publish. Policy test suite gate before publish. Lockdown/lift. Tests: 5
in-process Go agents (real binaries), timed tightening < 5 s; loosening without offline sig rejected by
backend *and* by agent; older/equal version, unsigned, unknown field and wrong target rejected; groups
can't widen (agent side too).

## M4 MCP — outline

FastMCP server with exactly the §6 tools (+ D-14), Streamable HTTP at `/mcp` and stdio, workflow-first
tool descriptions, elicitation for chat approval (falls back to a dashboard link; with `approvals.e2e`
on, it hands off to dashboard/app to sign), MCP client auth (bearer token per client, separate from
human auth). Tool-surface test (no approve/force/override/edit_policy/run). Manual Claude Code check.

## M5 Gatekeepers — outline

Panel with `strictest` mode and the group `unanimous` override; adapters for Ollama, OpenAI, Anthropic and
OpenAI-compatible endpoints (JSON mode, temperature 0, timeout → escalate, parse failure → escalate);
prompt with `<untrusted>` delimiting and escaping of any `</untrusted>` in content; secret scrubbing;
`send_untrusted_output`. Injection fixtures (README instructions, comments in package.json, ANSI-hidden
text, fake JSON verdicts in output, "the user already approved this", etc.). CI runs them against recorded
responses; `pytest -m live` runs them against the real configured models.

## M6 Dashboard — outline

1. `scripts/gen-tokens` parses `design/nocturne/styles.css` → `design/tokens.json` (+ status colours and
   their OKLCH ramps per README §17.2) → Tailwind theme and later `Theme.swift`.
2. Backend REST + WS + WebAuthn (py_webauthn), sessions of 12 h, settings API (human-only), e2e approval
   signing (WebAuthn assertion over the plan hash).
3. Next.js App Router pages from §17.3, `openapi-typescript` types, TanStack Query, native WS.
4. Prototype bug fixes, each with a Playwright test: (1) sidebar highlight + back link on plan pages,
   (2) phone action bar padding/layout, (3) gatekeeper unavailable (web parity check), (4) replace
   offline key dialog with no backup key.
5. Playwright: each page × §17.6 states (mocked API via MSW), keyboard shortcuts (no approve key), focus
   rings, < 768 px behaviour, offline (no external requests: test blocks all non-localhost traffic).

## M7 Schedules — outline
Template approval → hash-pinned schedule; APScheduler (Europe/Copenhagen); default expiry 90 days;
pause (no approval) / resume (re-approval if template changed); run through the normal dispatcher;
failure → notify and stop.

## M8 iPhone app — outline
Use the `iphone-app` skill and its Linux pipeline: SwiftPM + `xtool.yml`, Forgejo `ios` runner, `ship.sh`.
`WardenCore` (Foundation-only: models, decoding, formatters, verdict/state logic incl. gatekeeper-
unavailable and the final-verdict calculation) with `swift test` on Linux. Face ID-gated passkey
approval, actionable APNs notifications, press-and-hold 2 s kill switch and lockdown. Bug fix (3)
covered by a WardenCore unit test.

## M9 Public MCP — **stop and ask before starting** (OAuth inside Warden vs. an IdP such as Authentik).

## M10 Agent updates — outline
Offline-signed release manifests (version, sha256, min policy), canary agent first, systemd swap +
restart, automatic rollback if no heartbeat within 60 s, no downgrade.
