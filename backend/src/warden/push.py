"""APNs delivery for the iPhone app (README 10.3, 17.4; M8).

The outbox (`notify.py`) is filled in the same transaction as each event; this loop sends it to every paired
iPhone. Off until `settings.push.enabled` with a key ID, team ID and the `.p8` in the secrets directory.

- One HTTP/2 request per device (`POST /3/device/<token>`), authenticated with an ES256 JWT that is
  re-made every 50 minutes (Apple accepts 20–60).
- `settings.notifications` decides per kind; a switched-off kind is marked delivered without sending.
- 410 Unregistered and 400 BadDeviceToken drop that device. Other failures leave the row pending and
  are retried on the next pass, at most five times.
- The payload is title, body, category, kind and the plan or schedule ID. Commands and output never go
  through Apple: the app and its notification extension fetch them from Warden over WireGuard.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select
from ulid import ULID

from warden import audit
from warden.config import PushSettings, Settings
from warden.errors import InputRefused, NotFound
from warden.gatekeeper.config import SECRET_PREFIX, Secrets
from warden.notify import PREFERENCE, NotificationRow

log = logging.getLogger("warden.push")
MAX_ATTEMPTS = 5
JWT_TTL_S = 50 * 60

# (url, headers, body) -> (status, response body)
Transport = Callable[[str, dict[str, str], bytes], Awaitable[tuple[int, bytes]]]


class DeviceRow(SQLModel, table=True):
    __tablename__ = "devices"

    id: str = Field(primary_key=True)
    credential_id: str = Field(index=True)  # the passkey (or Face ID device key) that paired it
    name: str
    token: str = Field(unique=True)
    created_at: str
    last_ok_at: str | None = None


def _check_token(token: str) -> str:
    token = token.strip().lower()
    if not (16 <= len(token) <= 200) or any(c not in "0123456789abcdef" for c in token):
        raise InputRefused("an APNs device token is hex, 16–200 characters", code="bad_token")
    return token


def register(
    engine: Engine, *, credential_id: str, name: str, token: str, now: datetime, actor: str
) -> DeviceRow:
    """Store (or move) a device token for the signed-in passkey. One token belongs to one passkey."""
    token = _check_token(token)
    name = " ".join(name.split())[:60] or "iPhone"
    with Session(engine, expire_on_commit=False) as s, s.begin():
        row = s.exec(select(DeviceRow).where(col(DeviceRow.token) == token)).first()
        if row is None:
            row = DeviceRow(
                id=f"dev_{ULID()}",
                credential_id=credential_id,
                name=name,
                token=token,
                created_at=now.isoformat(),
            )
        else:
            row.credential_id, row.name = credential_id, name
        s.add(row)
        audit.append(
            s, ts=now, actor=actor, action="device_registered", subject=row.id, detail={"name": name}
        )
    return row


def devices(engine: Engine) -> list[DeviceRow]:
    with Session(engine) as s:
        return list(s.exec(select(DeviceRow).order_by(col(DeviceRow.created_at))))


def remove(engine: Engine, device_id: str, *, now: datetime, actor: str) -> None:
    with Session(engine) as s, s.begin():
        row = s.get(DeviceRow, device_id)
        if row is None:
            raise NotFound(f"no device {device_id}")
        s.delete(row)
        audit.append(
            s, ts=now, actor=actor, action="device_removed", subject=device_id, detail={"name": row.name}
        )


def remove_for_credential(engine: Engine, credential_id: str) -> int:
    """A removed passkey takes its iPhones with it."""
    with Session(engine) as s, s.begin():
        rows = list(s.exec(select(DeviceRow).where(col(DeviceRow.credential_id) == credential_id)))
        for r in rows:
            s.delete(r)
        return len(rows)


def payload(row: NotificationRow) -> dict[str, Any]:
    return {
        "aps": {
            "alert": {"title": row.title, "body": row.body},
            "sound": "default",
            "category": row.category,
            "thread-id": row.kind,
            "mutable-content": 1,
        },
        "kind": row.kind,
        "subject": row.subject,
    }


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(key_pem: bytes, *, key_id: str, team_id: str, now: float) -> str:
    """ES256 provider token (header kid, claims iss + iat), signature as raw r||s."""
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise InputRefused("the APNs key must be a P-256 .p8 key", code="bad_push_key")
    header = _b64(json.dumps({"alg": "ES256", "kid": key_id}, separators=(",", ":")).encode())
    claims = _b64(json.dumps({"iss": team_id, "iat": int(now)}, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode()
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return f"{header}.{claims}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


async def http2_transport(url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
    import httpx2  # noqa: PLC0415 - only needed when push is on

    async with httpx2.AsyncClient(http2=True, timeout=15) as client:
        r = await client.post(url, headers=headers, content=body)
        return r.status_code, r.content


@dataclass
class Pusher:
    engine: Engine
    settings: Callable[[], Settings]
    secrets_dir: Path
    transport: Transport = http2_transport
    clock: Callable[[], float] = time.time
    _jwt: tuple[str, float] | None = None
    _attempts: dict[int, int] = field(default_factory=dict)

    def _token(self, cfg: PushSettings) -> str:
        now = self.clock()
        if self._jwt is None or now - self._jwt[1] > JWT_TTL_S:
            if not (cfg.key_id and cfg.team_id):
                raise InputRefused("push needs settings.push.key_id and team_id", code="push_not_configured")
            pem = Secrets(self.secrets_dir).get(SECRET_PREFIX + cfg.key_secret).encode()
            self._jwt = (make_jwt(pem, key_id=cfg.key_id, team_id=cfg.team_id, now=now), now)
        return self._jwt[0]

    async def deliver_once(self) -> int:
        """Send what's pending. Returns how many notifications were finished (sent or skipped)."""
        settings = self.settings()
        cfg = settings.push
        with Session(self.engine) as s:
            rows = list(
                s.exec(
                    select(NotificationRow)
                    .where(col(NotificationRow.delivered_at).is_(None))
                    .order_by(col(NotificationRow.id))
                    .limit(50)
                )
            )
        if not rows:
            return 0
        prefs = settings.notifications.model_dump()
        done = 0
        targets = devices(self.engine) if cfg.enabled else []
        for row in rows:
            wanted = cfg.enabled and prefs.get(PREFERENCE.get(row.kind, row.kind), True) and targets
            ok = True
            if wanted:
                ok = await self._send(row, targets, cfg)
            if ok:
                self._finish(row)
                done += 1
        return done

    async def _send(self, row: NotificationRow, targets: list[DeviceRow], cfg: PushSettings) -> bool:
        row_id = row.id or 0
        try:
            bearer = self._token(cfg)
        except Exception as exc:  # misconfiguration: say it once per pass, keep the rows
            log.warning("push not sent: %s", exc)
            return False
        body = json.dumps(payload(row), ensure_ascii=False).encode()
        headers = {
            "authorization": f"bearer {bearer}",
            "apns-topic": cfg.topic,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-expiration": "0",
            "content-type": "application/json",
        }
        failed = False
        for d in targets:
            try:
                status, resp = await self.transport(f"https://{cfg.host}/3/device/{d.token}", headers, body)
            except Exception as exc:
                log.warning("push to %s failed: %s", d.name, exc)
                failed = True
                continue
            reason = ""
            if status != 200:
                try:
                    reason = str(json.loads(resp or b"{}").get("reason", ""))
                except ValueError:
                    reason = ""
            if status == 200:
                self._ok(d)
            elif status == 410 or reason in ("BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic"):
                self._drop(d, reason or str(status))
            else:
                log.warning("push to %s refused: %s %s", d.name, status, reason)
                if status in (403,) and reason in ("ExpiredProviderToken", "InvalidProviderToken"):
                    self._jwt = None
                failed = True
        if failed:
            n = self._attempts.get(row_id, 0) + 1
            self._attempts[row_id] = n
            return n >= MAX_ATTEMPTS  # give up after five passes rather than piling up
        return True

    def _ok(self, d: DeviceRow) -> None:
        with Session(self.engine) as s, s.begin():
            row = s.get(DeviceRow, d.id)
            if row is not None:
                row.last_ok_at = datetime.now(UTC).isoformat()
                s.add(row)

    def _drop(self, d: DeviceRow, reason: str) -> None:
        with Session(self.engine) as s, s.begin():
            row = s.get(DeviceRow, d.id)
            if row is not None:
                s.delete(row)
                audit.append(
                    s,
                    ts=datetime.now(UTC),
                    actor="warden",
                    action="device_dropped",
                    subject=d.id,
                    detail={"name": d.name, "reason": reason},
                )

    def _finish(self, row: NotificationRow) -> None:
        with Session(self.engine) as s, s.begin():
            r = s.get(NotificationRow, row.id)
            if r is not None:
                r.delivered_at = datetime.now(UTC).isoformat()
                s.add(r)
        if row.id is not None:
            self._attempts.pop(row.id, None)
