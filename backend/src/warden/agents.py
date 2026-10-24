"""Agent registry and enrollment (README 7A).

1. A human creates a one-time token for a target in targets.yaml (valid 15 min): `wdn_enr_<secret>.<CA fp>`.
2. The agent connects to /enroll (pinning Warden's CA by the fingerprint in the token), sends its public
   key, and prints its fingerprint. The token is used up at this point.
3. A human compares fingerprints and confirms with the exact fingerprint. Only then is a client certificate
   issued. A mismatch rejects the enrollment. Every step is audited.
4. Revoking marks the certificate serial revoked; the dispatcher refuses it and drops the connection.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select
from ulid import ULID

from warden import audit
from warden.actors import HumanActor
from warden.ca import CA, fingerprint, new_token_secret
from warden.errors import NotFound, WardenError
from warden.keys import unb64url
from warden.policy.schema import Targets

TOKEN_TTL = timedelta(minutes=15)
TOKEN_PREFIX = "wdn_enr_"  # noqa: S105 - a prefix, not a secret


class EnrollmentRefused(WardenError):
    code = "enrollment_refused"


class AgentRow(SQLModel, table=True):
    __tablename__ = "agents"

    id: str = Field(primary_key=True)
    name: str = Field(index=True)
    kind: str
    fingerprint: str
    public_key: str
    cert_serial: str = Field(index=True)
    status: str = Field(index=True)  # active | revoked
    enrolled_at: str
    revoked_at: str | None = None
    last_seen: str | None = None
    agent_version: str | None = None
    policy_version: int | None = None
    remote_addr: str | None = None


class EnrollmentRow(SQLModel, table=True):
    __tablename__ = "enrollments"

    id: str = Field(primary_key=True)
    name: str = Field(index=True)
    token_hash: str = Field(index=True)
    created_at: str
    expires_at: str
    status: str  # open | submitted | confirmed | rejected | expired
    public_key: str | None = None
    fingerprint: str | None = None
    source_ip: str | None = None
    agent_version: str | None = None
    agent_id: str | None = None
    cert_pem: str | None = None


@dataclass(frozen=True)
class Submission:
    enrollment_id: str
    name: str
    fingerprint: str
    source_ip: str


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


def split_token(token: str) -> tuple[str, str]:
    """(secret, CA fingerprint prefix)."""
    if not token.startswith(TOKEN_PREFIX) or "." not in token:
        raise EnrollmentRefused("that isn't a Warden enrollment token")
    secret, ca_fp = token[len(TOKEN_PREFIX) :].rsplit(".", 1)
    return secret, ca_fp


class Registry:
    def __init__(
        self,
        engine: Engine,
        ca: CA,
        *,
        targets: Callable[[], Targets],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._ca = ca
        self._targets = targets
        self._clock = clock

    @property
    def ca(self) -> CA:
        return self._ca

    def _audit(self, s: Session, actor: str, action: str, subject: str, **detail: object) -> None:
        audit.append(s, ts=self._clock(), actor=actor, action=action, subject=subject, detail=detail)

    # --- human side ------------------------------------------------------------------------------------

    def create_token(self, name: str, actor: HumanActor) -> str:
        if not isinstance(actor, HumanActor):
            raise EnrollmentRefused("only a human can create enrollment tokens")
        if self._targets().get(name) is None:
            raise EnrollmentRefused(f"{name} isn't in targets.yaml; add it there first")
        now = self._clock()
        secret = new_token_secret()
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            if self._active(s, name) is not None:
                raise EnrollmentRefused(
                    f"{name} already has an active agent; revoke it before enrolling a new one"
                )
            for old in s.exec(
                select(EnrollmentRow).where(
                    col(EnrollmentRow.name) == name, col(EnrollmentRow.status).in_(["open", "submitted"])
                )
            ):
                old.status = "expired"
                s.add(old)
            row = EnrollmentRow(
                id=f"enr_{ULID()}",
                name=name,
                token_hash=_hash(secret),
                created_at=_iso(now),
                expires_at=_iso(now + TOKEN_TTL),
                status="open",
            )
            s.add(row)
            self._audit(
                s, actor.label, "agent_token_created", name, enrollment=row.id, expires_at=row.expires_at
            )
        return f"{TOKEN_PREFIX}{secret}.{self._ca.fingerprint[:32]}"

    def pending(self) -> list[EnrollmentRow]:
        with Session(self._engine, expire_on_commit=False) as s:
            return list(s.exec(select(EnrollmentRow).where(col(EnrollmentRow.status) == "submitted")))

    def confirm(self, name: str, fingerprint_: str, actor: HumanActor) -> AgentRow:
        if not isinstance(actor, HumanActor):
            raise EnrollmentRefused("only a human can confirm an enrollment")
        now = self._clock()
        refusal: str | None = None
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            row = s.exec(
                select(EnrollmentRow).where(
                    col(EnrollmentRow.name) == name, col(EnrollmentRow.status) == "submitted"
                )
            ).first()
            if row is None or row.public_key is None or row.fingerprint is None:
                raise EnrollmentRefused(f"no agent for {name} is waiting to be confirmed")
            if _parse(row.expires_at) <= now:
                row.status = "expired"
                s.add(row)
                refusal = "that enrollment expired; create a new token"
            elif not hmac.compare_digest(row.fingerprint.lower(), fingerprint_.strip().lower()):
                row.status = "rejected"
                s.add(row)
                self._audit(
                    s,
                    actor.label,
                    "agent_enroll_mismatch",
                    name,
                    expected=fingerprint_,
                    received=row.fingerprint,
                    source_ip=row.source_ip,
                )
                refusal = (
                    "fingerprints don't match; enrollment rejected. Create a new token and check you're "
                    "talking to the right server"
                )
            else:
                return self._issue(s, row, name, now, actor)
        # Committed (status + audit) before refusing.
        raise EnrollmentRefused(refusal)

    def reject(self, name: str, actor: HumanActor) -> int:
        """Withdraw open or submitted enrollments for `name` ("Revoke token" / "Doesn't match")."""
        if not isinstance(actor, HumanActor):
            raise EnrollmentRefused("only a human can reject an enrollment")
        n = 0
        with Session(self._engine) as s, s.begin():
            for row in s.exec(
                select(EnrollmentRow).where(
                    col(EnrollmentRow.name) == name, col(EnrollmentRow.status).in_(["open", "submitted"])
                )
            ):
                row.status = "rejected"
                s.add(row)
                n += 1
            if n:
                self._audit(s, actor.label, "agent_enroll_rejected", name)
        return n

    def enrollment_for(self, name: str) -> EnrollmentRow | None:
        """The latest enrollment for a name, for the Add agent dialog's progress."""
        with Session(self._engine, expire_on_commit=False) as s:
            return s.exec(
                select(EnrollmentRow)
                .where(col(EnrollmentRow.name) == name)
                .order_by(col(EnrollmentRow.created_at).desc())
            ).first()

    def _issue(self, s: Session, row: EnrollmentRow, name: str, now: datetime, actor: HumanActor) -> AgentRow:
        if row.public_key is None or row.fingerprint is None:
            raise EnrollmentRefused("enrollment has no public key")
        target = self._targets().get(name)
        public = Ed25519PublicKey.from_public_bytes(unb64url(row.public_key))
        agent_id = f"agt_{ULID()}"
        cert = self._ca.issue_client(agent_id=agent_id, name=name, public=public, now=now)
        agent = AgentRow(
            id=agent_id,
            name=name,
            kind=target.kind if target else "VM",
            fingerprint=row.fingerprint,
            public_key=row.public_key,
            cert_serial=format(cert.serial_number, "x"),
            status="active",
            enrolled_at=_iso(now),
            remote_addr=row.source_ip,
            agent_version=row.agent_version,
        )
        s.add(agent)
        row.status = "confirmed"
        row.agent_id = agent_id
        row.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        s.add(row)
        self._audit(
            s,
            actor.label,
            "agent_enroll",
            f"{name} · {agent_id}",
            fingerprint=row.fingerprint,
            source_ip=row.source_ip,
            serial=agent.cert_serial,
        )
        return agent

    def revoke(self, name: str, actor: HumanActor) -> AgentRow:
        if not isinstance(actor, HumanActor):
            raise EnrollmentRefused("only a human can revoke an agent")
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            agent = self._active(s, name)
            if agent is None:
                raise NotFound(f"no active agent for {name}")
            agent.status = "revoked"
            agent.revoked_at = _iso(self._clock())
            s.add(agent)
            self._audit(s, actor.label, "agent_revoke", f"{name} · {agent.id}", serial=agent.cert_serial)
            return agent

    def list(self) -> list[AgentRow]:
        with Session(self._engine, expire_on_commit=False) as s:
            return list(s.exec(select(AgentRow).order_by(col(AgentRow.name))))

    # --- agent side ------------------------------------------------------------------------------------

    def submit(self, token: str, public_key_b64: str, source_ip: str, agent_version: str) -> Submission:
        """An agent presents a token and its public key. The token can't be used again."""
        now = self._clock()
        try:
            secret, ca_fp = split_token(token)
            public = Ed25519PublicKey.from_public_bytes(unb64url(public_key_b64))
        except (ValueError, EnrollmentRefused) as exc:
            raise EnrollmentRefused("invalid enrollment request") from exc
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            row = s.exec(select(EnrollmentRow).where(col(EnrollmentRow.token_hash) == _hash(secret))).first()
            ok = (
                row is not None
                and row.status == "open"
                and _parse(row.expires_at) > now
                and hmac.compare_digest(ca_fp, self._ca.fingerprint[:32])
            )
            if ok and row is not None:
                row.status = "submitted"
                row.public_key = public_key_b64
                row.fingerprint = fingerprint(public)
                row.source_ip = source_ip
                row.agent_version = agent_version
                s.add(row)
                self._audit(
                    s,
                    "warden",
                    "agent_enroll_submitted",
                    row.name,
                    fingerprint=row.fingerprint,
                    source_ip=source_ip,
                )
                return Submission(row.id, row.name, row.fingerprint, source_ip)
            self._audit(
                s, "warden", "agent_enroll_failed", source_ip, reason="invalid, used or expired token"
            )
        # Committed (audit) before refusing.
        raise EnrollmentRefused("invalid, used or expired token")

    def enrollment(self, enrollment_id: str) -> EnrollmentRow:
        with Session(self._engine, expire_on_commit=False) as s:
            row = s.get(EnrollmentRow, enrollment_id)
            if row is None:
                raise NotFound(enrollment_id)
            return row

    def _active(self, s: Session, name: str) -> AgentRow | None:
        return s.exec(
            select(AgentRow).where(col(AgentRow.name) == name, col(AgentRow.status) == "active")
        ).first()

    def by_serial(self, serial: str) -> AgentRow | None:
        """The active agent holding this certificate serial, or None (unknown or revoked)."""
        with Session(self._engine, expire_on_commit=False) as s:
            return s.exec(
                select(AgentRow).where(col(AgentRow.cert_serial) == serial, col(AgentRow.status) == "active")
            ).first()

    def seen(
        self,
        agent_id: str,
        *,
        version: str | None = None,
        policy_version: int | None = None,
        remote_addr: str | None = None,
    ) -> None:
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            agent = s.get(AgentRow, agent_id)
            if agent is None:
                return
            agent.last_seen = _iso(self._clock())
            if version is not None:
                agent.agent_version = version
            if policy_version is not None:
                agent.policy_version = policy_version
            if remote_addr is not None:
                agent.remote_addr = remote_addr
            s.add(agent)
