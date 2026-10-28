# Shared policy fixtures

One corpus, two engines: the Python policy engine (central) and the Go agent (M2) both run every case
here and must agree. Paths are checked lexically; symlink cases need a real filesystem and live in each
engine's own tests.

- `policy.yaml`, `targets.yaml`: the rules the cases run against.
- `cases/*.yaml`: lists of cases.
  - `id`: unique within the file
  - `mode`: `step` (plan step) or `read_only`
  - `target`: default `dev`
  - `kind`: step kind (default `shell`)
  - `cwd`: default `/srv/dev/myapp` (`/srv/app` for `sec-auth`)
  - `command`: the command
  - `expect`: `allow` or `deny`
  - `code`: for `deny`, a violation code that must be among the reasons
- `canonical_vectors.json`: canonical JSON + SHA-256 vectors for plan hashing.
- `cron_vectors.json`: schedule cron slots in Europe/Copenhagen (incl. DST days) and refused expressions (M7).
- `schedule_vectors.json`: a schedule run signed in Python (approval key + passkey) that the agent must accept, and refuse when mutated (M7).
