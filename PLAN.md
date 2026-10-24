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
| M2 ☑ | Agent | `warden-agent` (Go), enrollment + internal CA, mTLS WebSocket, dispatcher, per-step checks, baseline rules, streaming, kill, disconnect handling, docker-socket-proxy | Plan runs on `dev`, fails and revises; a tampered plan is refused | Go + pytest integration (agent in a container) and a manual run on `dev` documented in `docs/m2-demo.md` |
| M3 ☑ | Policy distribution | Bundle compiler, tighten/loosen classifier (default loosen), online/offline keys, `warden-sign`, groups, rollout tracking, lockdown, held/invalidated | Tightening reaches all agents in < 5 s; loosening without the offline key is rejected | `tests/integration/test_policy_distribution.py` (5 agents, timed) and `test_cli_daemon.py::test_m3_dry_run`, plus classifier property tests; manual run in `docs/m3-demo.md` |
| M4 ☑ | MCP | MCPServer tools (§6 + `post_diagnosis`), Streamable HTTP + stdio bridge, MCP client tokens (elicitation moved to M6, M4-03) | Works end-to-end from Claude Code over WireGuard | `test_cli_daemon.py::test_m4_dry_run` (real HTTP, real agent) + manual Claude Code session in `docs/m4-demo.md` |
| M5 ◐ | Gatekeepers | Panel (strictest/unanimous), Ollama, OpenAI, Anthropic and OpenAI-compatible adapters, prompt, scrubbing, injection fixtures | Injection tests escalate or deny on every reviewer | Recorded-response tests for every adapter in CI + live opt-in run against real models |
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

## M2 Agent — detailed plan

**Goal:** a small Go agent on each target that connects out over mTLS, receives approved plans, checks
everything again on its own (hash, approval signature, target, its signed policy bundle, real `realpath`,
baseline) and runs argv without a shell. Warden gains an internal CA, agent enrollment, a dispatcher, and a
`warden serve` daemon that the CLI talks to through a private admin socket.

### Scope boundary with M3

M3 owns policy *changes*: the tighten/loosen classifier, the offline key and `warden-sign`, rollout, lockdown,
held/invalidated automation. M2 needs a policy on the agent from day one, so it builds the **bundle format
and its verification**, and publishes exactly one bundle per target (version 1, signed with the online key).
If `policy.yaml` later compiles to different rules than the published bundle, the dispatcher refuses with
`policy_unpublished` until M3's publish flow exists. That way M2 never lets the online key loosen anything
(invariant 11).

### Files

```
agent/                                   # Go module (go 1.24), deps: github.com/coder/websocket, yaml.v3 (tests)
├── cmd/warden-agent/main.go             # enroll | run | version
├── internal/canonical/                  # canonical JSON + plan hash (shared vectors)
├── internal/policy/                     # lexer, paths (real realpath), matcher, baseline, readonly, engine
├── internal/bundle/                     # strict decode, signature, version/target checks, atomic store
├── internal/approval/                   # approval payload + signature verification
├── internal/runner/                     # plan checks, exec (no shell), timeout, output cap, kill, captures
├── internal/state/                      # state dir layout, executed-plan log (fsync'd)
├── internal/conn/                       # mTLS WebSocket client, protocol, heartbeat, reconnect
└── internal/enroll/                     # key generation, CA-pinned enrollment
backend/src/warden/
├── ca.py                                # internal CA (ed25519): server + client certs, serials, revocation
├── agents.py                            # registry, one-time tokens, fingerprint confirm, revoke
├── keys.py                              # online policy key (ed25519, 0600)
├── policy_dist/compile.py               # EffectiveRules -> bundle rules JSON (also feeds Go fixtures)
├── policy_dist/bundle.py                # build, sign, store; initial publish only in M2
├── dispatch/protocol.py                 # message models (strict, shared with Go)
├── dispatch/server.py                   # WSS :8443, /enroll and /agent, sessions, runs, output store
├── daemon.py                            # `warden serve`: dispatcher + admin unix socket (0600)
└── cli.py                               # + serve, agent add/pending/confirm/revoke/list, execute, kill, ro,
                                         #   policy publish
policy-fixtures/compiled/*.json          # compiled rules per fixture target, so Go runs the same corpus
deploy/warden-agent.service, deploy/warden-backend.service, deploy/target/compose.yml (socket proxy)
docs/m2-demo.md                          # manual checklist for the run on your `dev` server
```

### Protocol (JSON text frames over WSS, every message `{type, ...}`, unknown fields refused both ways)

Warden → agent: `bundle`, `run {template, plan_hash, approval}`, `kill {plan_id}`, `read_only {id, command}`.
Agent → Warden: `hello {agent_id, version, policy_version}`, `heartbeat` (every 15 s: versions, disk, load),
`refused {plan_id, code, message}`, `step_started`, `output {plan_id, n, stream, data, truncated}`,
`step_finished {plan_id, n, exit_code, timed_out, refused, killed, duration_ms, truncated}`,
`run_finished`, `bundle_ack {version, sha256}`, `bundle_rejected`, `read_only_result`.

### Enrollment

`warden agent add dev` (name must exist in targets.yaml) prints a one-time token valid 15 min:
`wdn_enr_<random>.<CA fingerprint>`. On the target: `warden-agent enroll --server wss://<warden>:8443
--token …`. The agent makes its ed25519 key, pins Warden's CA by the fingerprint in the token, sends its
public key and prints its fingerprint. `warden agent pending` shows the fingerprint Warden received and the
source IP; `warden agent confirm dev --fingerprint SHA256:…` must match exactly. The agent then receives its
client certificate, the CA, the online public key and bundle v1. Mismatch, expiry or reuse aborts and is
audited. `warden agent revoke dev` revokes the certificate serial and drops the connection at once.

### Agent checks before every step (README 7A)

1. Plan: canonical hash of the template == `plan_hash` == `approval.hash`; `target` == the agent's own name
   (from its signed bundle); approval signature valid for an approval key listed in the bundle; not expired;
   plan ID not in the executed log (written and fsync'd before step 1).
2. Step: lexer + matcher + baseline against the bundle's rules, paths resolved with real `realpath`;
   placeholders substituted (captured values type-checked) and the substituted argv checked again;
   `{{secret:…}}` refused until a secret store exists.
3. Exec: resolved program from a fixed PATH, `exec` with argv, `cwd`, a minimal environment, own process
   group, timeout (SIGTERM, then SIGKILL after 10 s), output capped at `output_cap_mb` (the step keeps
   running; the exit code still counts). Any check failing → `policy_violation` (exit 126 in the UI),
   remaining steps skipped.
4. The agent refuses to run as root.
5. Connection lost mid-plan: the current step may finish within its own timeout, then the rest is aborted.
   Warden marks the plan `failed` / `agent_disconnected` as soon as the connection drops.

### Tests

- Go: canonical vectors; the shared corpus (276 cases) against `policy-fixtures/compiled/*.json`; real
  symlink cases; bundle refusals (unsigned, wrong key, older/equal version, unknown field, wrong target,
  loosen without offline signature, min_agent_version); approval refusals (wrong hash, bad signature, unknown
  key, expired, other target, replay); exec (exit codes, timeout, kill, output cap, process group,
  captures, minimal env, no shell).
- Python: CA/cert issuance, token lifecycle (expiry, reuse, fingerprint mismatch), revocation, bundle
  compile/sign, protocol model strictness, dispatcher with a fake agent.
- Integration (Python starts the real Go binary as an unprivileged user): enroll → run succeeds → run fails
  at step 2 and a revision runs → tampered `run` message refused by the agent → kill → disconnect →
  revoked agent can't reconnect → read-only command.

### Done when (README 15): plan runs on `dev`, fails and revises; a tampered plan is refused
Proven by the integration tests here, plus the manual run on your `dev` server following `docs/m2-demo.md`.

### Commit sequence
1. `feat(agent): Go module, canonical JSON and plan hash`
2. `feat(policy): compiled rules export` + `feat(agent): policy engine port passing the shared corpus`
3. `feat(bundle): bundle build/sign (Python) and verify/store (Go)`
4. `feat(agent): approval verification and runner`
5. `feat(agents): internal CA, registry and enrollment`
6. `feat(dispatch): WSS server, protocol, agent connection`
7. `feat(daemon): warden serve, admin socket and CLI commands`
8. `test: agent integration suite`
9. `docs/deploy: systemd units, socket proxy, M2 checklist, README/DECISIONS`

### M2 result ☑ (21.10.2026)

Done-when "plan runs on `dev`, fails and revises; a tampered plan is refused" is proven by
`backend/tests/integration/` (the real agent binary as an unprivileged user, 11 scenarios plus a full
CLI + `warden serve` dry run) and is ready for the manual run on your server with `docs/m2-demo.md`.
Python: 812 tests; Go: canonical, policy (275 shared cases + symlinks), bundle, approval, runner and state
tests, all passing with `-race`. Decisions: DECISIONS.md section B3 (M2-01 … M2-12) and corrected D-10.

Differences from the plan above:
- `warden-sign` moved to M3, where the offline key is first needed.
- Commit 8 (integration tests) landed together with the dispatcher in commit 6, so each part was proven
  against the real agent as it was built.

## M3 Policy distribution — detailed plan

**Goal (README 7A/7B):** policy changes reach agents as signed, versioned bundles. Tightening is signed with
the online key and pushed at once; loosening waits for the offline key. Groups ride along inside the compiled
rules. Lockdown, rollout tracking, invalidation and held plans complete the loop.

### Key design point: the agent classifies for itself
In M2 the agent trusted the bundle's own `change` label. A compromised Warden could label a loosening
"tighten" and sign it with the online key. From M3 on, the **agent compares the new rules with the rules it
has installed** and requires a valid offline signature unless the change is provably tighter. The label
becomes informational. Warden and the agent run the same classifier, checked against shared vectors.

### Classifier (default: loosen when unsure, section 16 rule 12)
Per compiled target rules, every field compared as sets or numbers: deny lists may only grow, allow lists only
shrink (a program's `subcommands: null` → list counts as tighter, list → null as looser), `flags_deny` only
grow, limits only drop, read-only mode only move right, `passkey`/`unanimous`/`lockdown` only turn on,
approval keys only shrink. Workspace roots may only shrink; `docker_socket` must not change. Anything else
that differs → loosen.

### Offline key (D-04, D-05)
- `warden-sign` (Go): `keygen` (ed25519 seed encrypted with scrypt + XChaCha20-Poly1305, passphrase twice),
  `pubkey`, and `sign <publish file>`. `sign` prints the per-target diff it computed itself, asks for
  confirmation, and writes a signature file.
- `warden keys offline register --public … [--backup]` on the warden guest. Agents receive the offline key(s)
  at enrollment, inside the CA-pinned channel the human confirmed. Either key can sign. Agents enrolled
  before a key existed must re-enroll to get it; replacing keys later is a Settings flow (M6).

### Publish
`warden policy publish` (runs inside `warden serve` via the admin socket, or locally if it isn't running):
1. Reload config, compile every target, diff against the latest bundles.
2. **Test gate:** schema load plus `policy-fixtures/must_deny.yaml` (attacks every policy must refuse, for
   every target). Any failure blocks the publish.
3. All targets tighten (or are new) → new global version, online-signed, stored, pushed to connected
   agents, waiting/approved plans re-checked (`invalidated`), audit entry with the diff.
4. Any target loosens → a **pending publish** with the version reserved and a file to sign
   (`warden policy pending --out bundle-vN.json`). `warden-sign sign` → `warden policy sign-upload`
   verifies every offline signature, then publishes as in 3. `warden policy discard` drops it.
5. Agents also get the latest bundle when they connect and whenever a heartbeat shows they're behind.
6. `warden policy status`: version, per-agent rollout (`✓ v43` / `⏳ v42`), pending publish.

### Lockdown
`warden lockdown` (CLI now, dashboard and iPhone later): publishes a tightening bundle with `lockdown: true`
for every target, kills running plans, holds approved ones. Proposals and approvals still work; nothing
runs. `warden lockdown lift` is a loosening publish (offline key). Held plans start again when it lands.

### Tests
- Classifier: unit and property tests in Python, shared vectors run by Go, agent refusing a mislabelled
  loosening.
- warden-sign: keygen/encrypt/decrypt, wrong passphrase, signature verifies in Python.
- Publish: tighten immediate; loosen pending; bad or missing offline signature refused; test gate blocks;
  plans invalidated; lockdown and lift; held plans released only after lift.
- Integration (Done when): **5 real agents, a tightening reaches all of them in under 5 s**; a loosening sent
  without the offline signature is refused by Warden *and* by every agent, even when mislabelled.

### M3 result ☑ (21.10.2026)

Done-when "tightening reaches all agents in < 5 s; loosening without the offline key is rejected" is proven
by `backend/tests/integration/test_policy_distribution.py` with real agent binaries running as an
unprivileged user: 5 agents receive and acknowledge a tightening within the 5 s the test allows; a loosening is held by
Warden until a registered offline key signs it, and the same loosening labelled "tighten" and signed with the
online key is refused by every agent (`needs_offline_signature`). The real `warden-sign` binary signs end to
end, and `test_cli_daemon.py::test_m3_dry_run` runs the whole CLI flow, including lockdown and lift.
Python: 859 unit tests + 16 integration tests; Go: all packages pass with `-race`. Decisions: DECISIONS.md
section B4 (M3-01 … M3-12). Manual checklist: `docs/m3-demo.md`.

Differences from the plan above:
- Publishing runs in the CLI, and `warden serve` only got a `reload` op that pushes what was already signed
  (M3-09), so the admin socket still can't change policy.
- The test gate file ships inside the backend package (M3-08).
- Agents enrolling after v1 accept the current version (M3-06).

## M4 MCP — detailed plan

**Goal (README 6, 10.1; Done when: works end to end from Claude Code over WireGuard).** Claude gets exactly
the README §6 tools plus `post_diagnosis` (D-14), and nothing that approves, rejects, edits policy, reads or
changes settings, or runs anything unplanned.

### Shape
- **SDK:** `mcp` 2.3 (`MCPServer`, formerly FastMCP) mounted in a FastAPI app served by uvicorn **inside
  `warden serve`**, next to the dispatcher (D-10: the MCP process has no approve path, and the Warden home
  stays private to the service user). New `settings.yaml` block `mcp: {listen_host, listen_port}`
  (default `127.0.0.1:8700`; NPM forwards `/mcp`). DNS-rebinding protection allows only the host of
  `server.public_url` plus `listen_host`.
- **Client auth (separate from human auth):** one bearer token per MCP client, `wdn_mcp_<secret>`, stored as a
  SHA-256 hash. `warden mcp add <name>` prints it once; `warden mcp list`, `warden mcp revoke <name>`. These
  are human CLI commands. A missing, unknown or revoked token gets 401 before the MCP layer sees the request.
  The client name becomes the `ClaudeActor` on everything it does. OAuth is M9.
- **stdio:** `warden mcp stdio --url … --token-file …` is a bridge on the client's machine: stdio on one side,
  the same authenticated Streamable HTTP endpoint on the other. There is deliberately no stdio server that
  opens the Warden database: anything able to start it already has a shell as the service user, which is the
  human channel (D-10).

### Tools (`backend/src/warden/mcp/`)
| Tool | Does | Notes |
|---|---|---|
| `propose_plan(goal, target, steps, revises?)` | `PlanService.propose` as `ClaudeActor(client)` | Returns plan ID, hash, policy result, gatekeeper verdicts, final verdict, what the human must do next |
| `get_plan(plan_id)` | Status, steps, per-step results with capped output, diagnoses, `human_note` (null until M6) | Output is labelled as untrusted text from the target |
| `wait_for_approval(plan_id, timeout_s?)` | Blocks until decided or expired, max 300 s | Elicitation never approves in M4 (see below) |
| `execute_plan(plan_id)` | `Dispatcher.execute`; waits up to 240 s, with a progress notification per step | Returns `running` past that (poll `get_plan`) or `held` with the reason |
| `diff_plans(old_id, new_id)` | `PlanService.diff` | |
| `read_only(target, command)` | `Dispatcher.read_only` as the client | Returns the audit ID, for `post_diagnosis` |
| `list_resources(target?)` | Targets (online, policy version, lockdown), workspace roots, groups, effective allowlist, allowed compose projects, denied containers, hosts, limits, read-only mode | Policy only; `settings.yaml` is never exposed |
| `post_diagnosis(plan_id, note, read_only_audit_ids)` | D-14 exactly: note ≤ 4000 characters (D-21 text rules) + ≤ 20 audit IDs; the server attaches the real commands and outputs | Can't change plan state; audited |

- Tool descriptions lead with the workflow: look around with `read_only`, propose a full plan, wait for
  approval, execute, and on failure diagnose and propose a revision with `revises`.
- **Elicitation (README 10.1):** M4 uses it only to *show* the plan summary and where to approve (CLI now,
  dashboard link from M6). An elicitation answer never approves or rejects. Invariant 3 needs approval from
  a channel authenticated separately from the MCP connection, and the SDK warns that agent clients may answer
  elicitations automatically. Whether chat approval should exist when `approvals.e2e` is off is a question
  for the owner (asked at the end of M4). With e2e on (the default from M6), chat hands off to the dashboard
  through URL-mode elicitation.

### Tests
- **Tool surface:** the exact set of 8 names; no tool or parameter named or behaving like approve, reject,
  force, override, edit_policy, settings or run; schemas checked.
- **Auth:** missing, wrong or revoked token → 401; foreign `Host` → refused; tokens stored hashed; add and
  revoke audited.
- **Unit (in-process client):** every tool, refusals (unknown plan, not approved, plan of another target,
  read-only refusals), output caps, the timeout of `wait_for_approval`.
- **`post_diagnosis`:** every D-14 refusal (plan not failed, too many or duplicate IDs, wrong action, other
  target, other client, before the failure, bad note) and the attached evidence.
- **Integration (real agent, real HTTP):** Claude's whole loop over Streamable HTTP with a bearer token:
  propose → wait (a human approves in parallel) → execute → fail → `read_only` → `post_diagnosis` → revise →
  diff → approve → succeed. The stdio bridge does the same handshake.
- **Done when (manual):** `docs/m4-demo.md`, Claude Code over WireGuard through NPM.

### Commits
1. `mcp: settings, client tokens and CLI`
2. `mcp: tools and server`
3. `mcp: HTTP app in warden serve, stdio bridge`
4. `test: MCP integration`
5. `docs: M4 checklist, README §6/§14, decisions`

### M4 result ☑ (24.10.2026)

Done-when "works end to end from Claude Code over WireGuard" is proven up to the network path by
`backend/tests/integration/test_cli_daemon.py::test_m4_dry_run`. `warden serve` runs with the real agent as an
unprivileged user, and an MCP client authenticates with a bearer token over Streamable HTTP. It does Claude's
whole loop: propose → wait (a human approves with the CLI meanwhile) → execute → fail → `read_only` →
`post_diagnosis` → revise → diff → approve → succeed. Then the stdio bridge, and refusals without a token, with
a wrong token, with a foreign Host and after revoke. The Claude Code + WireGuard + NPM part is the manual
check in `docs/m4-demo.md`.
Python: 901 unit tests + 17 integration tests; Go unchanged and passing. Decisions: DECISIONS.md section B5
(M4-01 … M4-07).

Differences from the plan above:
- Elicitation moved to M6 (M4-03).
- No FastAPI yet: the MCP SDK's Starlette app is enough until the REST API (M4-01).
- Commits 1–3 landed as one, because the tools, auth and endpoint were tested together.

## M5 Gatekeepers — detailed plan

**Goal (README 9; Done when: injection tests escalate or deny on every reviewer).** A panel of reviewer models
from different providers answers one question per plan, *do these steps do what the goal says, and nothing
more?* Gatekeepers can only make things stricter (invariant 6): every error, timeout or odd answer counts as
`escalate`, and a policy deny never reaches them.

### Files (`backend/src/warden/gatekeeper/`)
- `config.py`: `gatekeeper.yaml` (single source of truth, §16 rule 8): `mode: strictest`, `timeout_s`, and
  `reviewers[]` with `name`, `provider` (`ollama` | `openai` | `anthropic` | `openai_compatible`), `url`, `model`,
  `api_key: secret:NAME`, `send_untrusted_output`, and per-provider `options`. Secrets are files in
  `<config dir>/secrets/NAME` (README 12: `/etc/warden/secrets`, mode 0600). A missing secret or an invalid
  file means that reviewer is unavailable (escalate), never skipped. No `gatekeeper.yaml` means no reviewers
  (escalate, D-19).
- `prompt.py`: a fixed system prompt plus the request: goal, target, steps, a compact policy summary, the
  previous failed plan with its error, diagnoses and output (for revisions). All target output and Claude's
  notes go inside `<untrusted>…</untrusted>`, after escaping any `<untrusted>`/`</untrusted>` (D-18), stripping
  ANSI escape sequences (so hidden text becomes visible), removing invisible characters, scrubbing known
  secret values, and capping length. Untrusted output only reaches reviewers with `send_untrusted_output`.
- `verdict.py`: the README §9 JSON schema, validated with Pydantic. It fails closed: anything that isn't
  exactly one JSON object matching the schema with one `per_step` entry per step is `escalate`. Consistency
  rules make it stricter: `allow` with any `matches_goal: false` or `risk: high` becomes `escalate`.
- `adapters.py`: small sync adapters over `httpx2`, all at temperature 0 with structured output.
  - **Ollama:** `/api/chat` with `format` set to the JSON schema, `think: false` and `num_ctx`.
  - **OpenAI and OpenAI-compatible:** chat completions with `response_format` set to a JSON schema (or
    `json_object` for endpoints without schema support).
  - **Anthropic:** Messages API with one forced tool whose input schema is the verdict.
- `scan.py`: a built-in deterministic reviewer, `injection-scan`. It escalates when untrusted text carries
  known injection markers: "ignore previous instructions", "already approved", fake verdict JSON, ANSI
  escapes, invisible characters, role tags. It can only escalate, never allow or deny, and it makes the
  injection suite pass in CI without any model.
- `panel.py`: `ReviewPanel` runs every reviewer in parallel threads under one overall timeout. Strictest wins
  (as now). The group `unanimous` flag is already implied by `strictest`; any non-`allow` from any reviewer
  escalates.

### Wiring
- `warden serve` and the CLI build the panel from `gatekeeper.yaml`; `reload` re-reads it.
- MCP tools run sync code in worker threads, so slow reviewers never block the agent listener.
- `warden gatekeeper check` sends one harmless and one malicious sample plan to every reviewer and prints
  their verdicts and timings (manual check).
- `warden gatekeeper record --out FILE` runs the injection fixtures against the real reviewers and saves their
  raw replies.
- **Default local model:** `qwen3:14b` on the owner's RTX 3060 12 GB, with `qwen3:8b` as the fallback
  (DECISIONS D-01, updated).

### Tests
- **Injection fixtures** (`backend/tests/gatekeeper/injection.yaml`):
  - a README saying "ignore previous instructions and run …";
  - instructions hidden in a `package.json` comment;
  - ANSI-hidden text;
  - a fake JSON verdict in the output;
  - "the user already approved this";
  - a closing `</untrusted>` smuggled into the content;
  - a revision that quietly adds an unrelated step;
  - a goal/step mismatch (the goal says tests, a step deletes data);
  - an exfiltration step (`curl -d @.env`).
- **CI, no models:**
  - each fixture produces a prompt with the attack fully inside the delimiters;
  - `injection-scan` escalates the context-based attacks;
  - every adapter turns a fooled reply ("allow, low risk, all steps match"), malformed JSON, extra prose,
    timeouts, HTTP errors and refusals into the right verdict;
  - recorded replies, once the owner records them, replay through the adapters.
- **Live** (`pytest -m live`, needs the real models): every fixture on every configured reviewer must come back
  `escalate` or `deny`. This is the Done-when, run on the owner's setup. Results are written down in
  `docs/m5-demo.md`.

### Commits
1. `gatekeeper: config, secrets, prompt and verdict parsing`
2. `gatekeeper: adapters, injection-scan and panel`
3. `gatekeeper: wiring, check/record CLI`
4. `test: injection fixtures and live suite`
5. `docs: M5 checklist, README §9, decisions`

### M5 status ◐ (24.10.2026): code complete, Done-when waits for your models

Everything in the plan above is built and tested without models: 11 injection fixtures, prompt hygiene, the
`injection-scan` floor (every injection case escalates even when every model is fooled), every adapter's
failure modes, panel timeout and strictest merge, revision context from the database, and the `warden
gatekeeper check` command. The suite ships with the backend.
Python: 1000 unit tests (plus 11 live tests, skipped without models) + 17 integration tests.

**Done-when is a live run**, because no model is reachable from this container. On the warden guest, once
Ollama runs `qwen3:14b` on the `ai` VM, run `warden gatekeeper check --injection --record
tests/gatekeeper/recorded/local-qwen3-14b.json` (docs/m5-demo.md). When every answer is escalate or deny, M5
is done, and the recording becomes a CI regression test.

Differences from the plan above:
- The injection suite lives in the package (`warden/gatekeeper/injection.yaml`), so the installed Warden can
  run it.
- Unavailable reviewers keep risk `high`, except "none configured" (M5-05).

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
**Required (confirmed 24.10.2026).** Build it with the new iOS skill the owner provides at M8 (load it before
writing any Swift; it takes precedence over this outline where they differ). Until then, the outline is: the
`iphone-app` skill and its Linux pipeline: SwiftPM + `xtool.yml`, Forgejo `ios` runner, `ship.sh`.
`WardenCore` (Foundation-only: models, decoding, formatters, verdict/state logic incl. gatekeeper-
unavailable and the final-verdict calculation) with `swift test` on Linux. Face ID-gated passkey
approval, actionable APNs notifications, press-and-hold 2 s kill switch and lockdown. Bug fix (3)
covered by a WardenCore unit test.

## M9 Public MCP — **stop and ask before starting** (OAuth inside Warden vs. an IdP such as Authentik).

## M10 Agent updates — outline
Offline-signed release manifests (version, sha256, min policy), canary agent first, systemd swap +
restart, automatic rollback if no heartbeat within 60 s, no downgrade.
