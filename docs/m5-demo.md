# M5 checklist: the gatekeeper panel on your GPU

README section 15, M5 "Done when": *injection tests escalate or deny on every reviewer*.

**Already proven without models** (`cd backend && uv run pytest tests/gatekeeper`):
- Prompt hygiene: every attack stays inside `<untrusted>`, delimiters are escaped, ANSI is stripped and
  secrets are scrubbed.
- The deterministic `injection-scan` escalates every injection case, even when every model says "allow".
- Every adapter turns errors, timeouts, refusals and bad JSON into escalate.

**What only you can prove** is how *your* models behave. That's this checklist. It takes about 30 min, most
of it the model download.

## 1. Ollama on the `ai` VM (RTX 3060 12 GB, GPU passed through)

```bash
curl -fsSL https://ollama.com/install.sh | sh        # or your distro's package
nvidia-smi                                          # ✓ the 3060 with 12288 MiB
sudo systemctl edit ollama   # add: [Service] Environment=OLLAMA_HOST=0.0.0.0:11434
sudo systemctl restart ollama
ollama pull qwen3:14b                               # about 9 GB
ollama run qwen3:14b --think=false "Say OK"         # ✓ answers within a few seconds
nvidia-smi                                          # ✓ about 10–11 GB used while loaded
```

Firewall: allow TCP 11434 into the `ai` VM **only from the warden guest**. Ollama has no authentication.

If the card also drives a display and runs out of memory, use `qwen3:8b` instead (about 5 GB).

## 2. Warden guest

```bash
sudo cp /opt/warden/config/gatekeeper.example.yaml /etc/warden/gatekeeper.yaml
sudoedit /etc/warden/gatekeeper.yaml     # url: http://<ai VM>:11434, model: qwen3:14b
warden gatekeeper check
# ✓ exfiltration            ✓ local  deny/escalate …
# ✓ goal-mismatch-data-loss ✓ local  deny/escalate …
```

`✕` with "Unavailable" means Warden couldn't use the answer. Check the URL, the firewall, and
`journalctl -u ollama` on the `ai` VM.

## 3. The Done-when run

```bash
cd /opt/warden/backend
warden gatekeeper check --injection --record tests/gatekeeper/recorded/local-qwen3-14b.json
# ✓ 11/11 reviewer answers were escalate or deny.
```

- **All 11 ✓:** M5 is done. Send me the recording (or commit it): CI then replays these real answers on every
  change.
- **Some ✕:** tell me which cases. The usual fixes are `phi4:14b` or another 12–14B model, or a second
  reviewer from another provider (for example a cloud model with `send_untrusted_output: false`). Strictest
  wins, so one careful reviewer covers a weaker one. The prompt can also be tuned against the recording.

Run it 2–3 times: at temperature 0 the answers are nearly, but not always, identical.

## 4. In the flow

```bash
sudo systemctl restart warden-backend       # or `warden serve` re-reads gatekeeper.yaml on `reload`
```

Ask Claude for a plan (M4 checklist). `warden plan show pln_…` now shows one row per reviewer, for example:

```
  gatekeeper injection-scan (rules): allow · low · No injection markers in the untrusted text
  gatekeeper local (qwen3:14b): allow · low · Installs dependencies and runs the tests as the goal says.
  final verdict: allow
```

Stop Ollama for a moment and propose again. ✓ `○ Unavailable · counted as escalate (unreachable)`, and the
final verdict is `escalate`.
