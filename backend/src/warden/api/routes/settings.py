"""Settings, passkeys, sessions and signing keys (README 17.3 Settings). Human sessions only; no MCP path."""

from __future__ import annotations

from fastapi import APIRouter
from sqlmodel import Session

from warden import settings_store
from warden.actors import HumanActor
from warden.api import schemas as sc
from warden.api.auth import Ctx, Human, SessionDep
from warden.api.context import ApiContext
from warden.api.routes import policy as policy_routes
from warden.config import load_settings
from warden.errors import WardenError
from warden.gatekeeper.config import load_gatekeeper
from warden.passkeys import active
from warden.policy.effective import effective_rules
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing

router = APIRouter(tags=["settings"])


def _values(c: Ctx) -> dict[str, object]:
    s = c.config().settings.model_dump()
    return {k: s[k.split(".")[0]][k.split(".")[1]] for k in settings_store.EDITABLE}


@router.get("/settings")
def get_settings(c: Ctx, _: Human) -> sc.SettingsView:
    cfg = c.config()
    gk = load_gatekeeper(c.config_dir / "gatekeeper.yaml")
    with Session(c.engine) as s:
        offline = offline_keys.active(s)
    t = cfg.targets.targets[0] if cfg.targets.targets else None
    limits = {}
    if t is not None:
        r = effective_rules(cfg.policy, t)
        limits = {
            "step_timeout_s": r.step_timeout_s.value,
            "plan_max_steps": r.plan_max_steps.value,
            "output_cap_mb": r.output_cap_mb.value,
            "kill": "SIGTERM, then SIGKILL after 10 s",
        }
    keys = [
        sc.KeyView(name="Approval key", key_id=c.approval.key_id, public=c.approval.public_b64),
        sc.KeyView(name="Online policy key", key_id=c.online.key_id, public=c.online.public_b64),
    ] + [
        sc.KeyView(name=f"Offline policy key ({k.role})", key_id=k.key_id, public=k.public, role=k.role)
        for k in offline
    ]
    ca = c.registry.ca
    return sc.SettingsView(
        values=_values(c),
        editable=list(settings_store.EDITABLE),
        gatekeepers={
            "mode": gk.mode,
            "timeout_s": gk.timeout_s,
            "injection_scan": gk.injection_scan,
            "reviewers": [
                {
                    "name": r.name,
                    "provider": r.provider,
                    "model": r.model,
                    "send_untrusted_output": r.sends_untrusted,
                }
                for r in gk.reviewers
            ],
            "scrub_secrets": True,
            "source": "gatekeeper.yaml",
        },
        limits=limits,
        keys=keys,
        ca={"fingerprint": ca.fingerprint, "expires_at": ca.cert.not_valid_after_utc.isoformat()},
        e2e=cfg.e2e,
        time={"zone": "Europe/Copenhagen", "date": "dd.mm.yyyy", "time": "24-hour", "units": "metric"},
    )


@router.put("/settings")
async def put_settings(body: sc.SettingsIn, c: Ctx, human: Human) -> sc.SettingsView:
    base = load_settings(c.config_dir / "settings.yaml")
    settings_store.change(c.engine, base, body.changes, actor=human, now=c.now())
    await c.reload()
    return get_settings(c, human)


async def publish_trust_now(
    c: ApiContext, actor: HumanActor, *, e2e: bool | None = None
) -> sc.PublishResultView | None:
    """Ship the current passkeys (and e2e flag) to agents when they differ from what's published."""
    r = publishing.publish_trust_if_changed(
        c.engine, c.passkeys.rp, e2e=e2e, online=c.online, approval=c.approval, now=c.now(), actor=actor.label
    )
    return None if r is None else policy_routes.result_view(r, await c.reload())


@router.post("/e2e")
async def set_e2e(body: sc.E2EIn, c: Ctx, human: Human) -> sc.PublishResultView:
    """Turn end-to-end signing on (tighten, at once) or off (loosen, waits for the offline key)."""
    c.passkeys.verify(body.challenge_id, body.credential, "settings", "e2e", now=c.now())
    r = await publish_trust_now(c, human, e2e=body.enabled)
    if r is None:
        raise WardenError("nothing to change: agents already have this", code="unchanged")
    return r


@router.get("/passkeys")
def passkeys(c: Ctx, _: Human) -> list[sc.PasskeyView]:
    return [
        sc.PasskeyView(
            credential_id=p.credential_id,
            name=p.name,
            alg=p.alg,
            created_at=p.created_at,
            last_used_at=p.last_used_at,
        )
        for p in active(c.engine)
    ]


@router.post("/passkeys/{credential_id}/remove")
async def remove_passkey(credential_id: str, body: sc.ConfirmIn, c: Ctx, human: Human) -> sc.Ok:
    c.passkeys.verify(body.challenge_id, body.credential, "remove_passkey", credential_id, now=c.now())
    c.passkeys.remove(credential_id, actor=human, now=c.now())
    r = await publish_trust_now(c, human)
    return sc.Ok(message="passkey removed" + (f" · approver list published as v{r.version}" if r else ""))


@router.get("/sessions")
def sessions(c: Ctx, me: SessionDep) -> list[sc.SessionView]:
    return [
        sc.SessionView(
            id=r.token_hash[:16],
            name=r.name,
            created_at=r.created_at,
            expires_at=r.expires_at,
            last_seen_at=r.last_seen_at,
            ip=r.ip,
            user_agent=r.user_agent,
            current=r.token_hash == me.token_hash,
        )
        for r in c.passkeys.sessions(now=c.now())
    ]


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, c: Ctx, human: Human) -> sc.Ok:
    match = [
        r
        for r in c.passkeys.sessions(now=c.now())
        if r.token_hash.startswith(session_id) and len(session_id) >= 16
    ]
    if len(match) != 1:
        raise WardenError("no such session", code="not_found")
    c.passkeys.revoke_session(match[0].token_hash, actor=human, now=c.now())
    return sc.Ok(message="session signed out")
