"""Passkeys (WebAuthn) for the human dashboard (README 10.0, 10.2, 17.3; PLAN M6).

- The first passkey is registered with a one-time link from `warden passkey add <name>` (the CLI is a human
  channel, D-10). Later ones are added from Settings by a signed-in human who confirms with an existing
  passkey.
- Every assertion must have user verification (`UV`) and comes from a challenge Warden issued for one purpose
  and one subject: login, an approval of one plan, a publish of one policy preview, adding a passkey. A
  challenge is used once and expires after 2 minutes.
- Only ES256 and Ed25519 keys are accepted, because agents verify approval assertions themselves (e2e).
- Sessions are random tokens stored as SHA-256 hashes, valid 12 hours, revocable.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    decode_credential_public_key,
    decoded_public_key_to_cryptography,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from warden import audit
from warden.actors import HumanActor
from warden.errors import WardenError

ENROLL_TTL = timedelta(minutes=15)
CHALLENGE_TTL = timedelta(minutes=2)
SESSION_TTL = timedelta(hours=12)
ALGS = [COSEAlgorithmIdentifier.EDDSA, COSEAlgorithmIdentifier.ECDSA_SHA_256]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
USER_ID = b"warden-owner"

Purpose = Literal[
    "login", "approve", "approve_schedule", "publish", "add_passkey", "remove_passkey", "settings", "lockdown"
]


class PasskeyRefused(WardenError):
    code = "passkey_refused"


class PasskeyRow(SQLModel, table=True):
    __tablename__ = "passkeys"

    credential_id: str = Field(primary_key=True)  # base64url
    name: str
    cose_key: str  # base64url COSE key, for py_webauthn
    spki: str  # base64url DER SubjectPublicKeyInfo, for agents
    alg: int
    sign_count: int = 0
    created_at: str
    created_by: str
    last_used_at: str | None = None
    removed_at: str | None = None


class PasskeyEnrollmentRow(SQLModel, table=True):
    __tablename__ = "passkey_enrollments"

    token_hash: str = Field(primary_key=True)
    name: str
    expires_at: str
    created_by: str
    used_at: str | None = None


class WebSessionRow(SQLModel, table=True):
    __tablename__ = "web_sessions"

    token_hash: str = Field(primary_key=True)
    credential_id: str = Field(index=True)
    name: str
    created_at: str
    expires_at: str
    last_seen_at: str
    ip: str
    user_agent: str
    revoked_at: str | None = None


@dataclass(frozen=True)
class RelyingParty:
    rp_id: str
    origin: str

    @classmethod
    def from_url(cls, public_url: str) -> RelyingParty:
        u = urlsplit(public_url)
        if not u.hostname or u.scheme not in ("https", "http"):
            raise PasskeyRefused("server.public_url must be an http(s) URL")
        if u.scheme == "http" and u.hostname not in ("localhost", "127.0.0.1"):
            raise PasskeyRefused("passkeys need https (or localhost)")
        return cls(rp_id=u.hostname, origin=f"{u.scheme}://{u.netloc}")


@dataclass
class Challenge:
    id: str
    purpose: Purpose
    subject: str  # e.g. plan ID, preview ID, "" for login
    challenge: bytes
    expires_at: datetime
    data: dict[str, Any]


@dataclass(frozen=True)
class Verified:
    credential_id: str
    name: str
    assertion: dict[str, str]  # the raw parts agents need for e2e checks


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def check_name(name: str) -> str:
    if not _NAME.match(name):
        raise PasskeyRefused("passkey names are 1–40 letters, digits, spaces, dots, dashes or underscores")
    return name


def active(engine: Engine) -> list[PasskeyRow]:
    with Session(engine, expire_on_commit=False) as s:
        return list(
            s.exec(
                select(PasskeyRow)
                .where(col(PasskeyRow.removed_at).is_(None))
                .order_by(col(PasskeyRow.created_at))
            )
        )


class Passkeys:
    """Challenges live in memory: `warden serve` is the only process that issues and checks them."""

    def __init__(self, engine: Engine, rp: RelyingParty) -> None:
        self.engine = engine
        self.rp = rp
        self._challenges: dict[str, Challenge] = {}

    # --- enrollment (first passkey via CLI link, later ones from Settings) ------------------------------

    def create_enrollment(self, name: str, *, actor: HumanActor, now: datetime) -> str:
        if not isinstance(actor, HumanActor):
            raise PasskeyRefused("only a human can enroll a passkey")
        check_name(name)
        token = secrets.token_urlsafe(24)
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            s.add(
                PasskeyEnrollmentRow(
                    token_hash=_hash(token),
                    name=name,
                    expires_at=_iso(now + ENROLL_TTL),
                    created_by=actor.label,
                )
            )
            audit.append(
                s, ts=now, actor=actor.label, action="passkey_enrollment_created", subject=name, detail={}
            )
        return token

    def _open_enrollment(self, s: Session, token: str, now: datetime) -> PasskeyEnrollmentRow:
        row = s.get(PasskeyEnrollmentRow, _hash(token))
        if row is None or row.used_at is not None or datetime.fromisoformat(row.expires_at) <= now:
            raise PasskeyRefused("this registration link is invalid, used or expired; create a new one")
        return row

    def registration_options(
        self, *, now: datetime, token: str | None = None, name: str | None = None
    ) -> tuple[str, str]:
        """(challenge id, options JSON). Either an enrollment token or (signed in, confirmed) a name."""
        if token is not None:
            with Session(self.engine, expire_on_commit=False) as s:
                name = self._open_enrollment(s, token, now).name
        if name is None:
            raise PasskeyRefused("a passkey needs a name")
        check_name(name)
        existing = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id)) for p in active(self.engine)
        ]
        challenge = secrets.token_bytes(32)
        opts = generate_registration_options(
            rp_id=self.rp.rp_id,
            rp_name="Warden",
            user_id=USER_ID,
            user_name="warden",
            user_display_name=f"Warden · {name}",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=existing,
            supported_pub_key_algs=ALGS,
        )
        cid = self._remember("add_passkey", token or "", challenge, now, {"name": name, "token": token})
        return cid, options_to_json(opts)

    def register(
        self, challenge_id: str, credential: dict[str, Any], *, now: datetime, actor: HumanActor | None = None
    ) -> PasskeyRow:
        """`actor` defaults to the person at the browser, named after the new passkey."""
        ch = self._take(challenge_id, "add_passkey", None, now)
        actor = actor or HumanActor("dashboard", actor_id(ch.data["name"]))
        try:
            v = verify_registration_response(
                credential=credential,
                expected_challenge=ch.challenge,
                expected_rp_id=self.rp.rp_id,
                expected_origin=self.rp.origin,
                require_user_verification=True,
                supported_pub_key_algs=ALGS,
            )
        except InvalidRegistrationResponse as exc:
            raise PasskeyRefused(f"the passkey response didn't verify: {exc}") from exc
        decoded = decode_credential_public_key(v.credential_public_key)
        alg = int(decoded.alg) if decoded.alg is not None else 0
        if alg not in (int(a) for a in ALGS):
            raise PasskeyRefused("only ES256 and Ed25519 passkeys can be used with Warden")
        spki = decoded_public_key_to_cryptography(decoded).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cred_id = bytes_to_base64url(v.credential_id)
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            if ch.data.get("token"):
                self._open_enrollment(s, ch.data["token"], now).used_at = _iso(now)
            if s.get(PasskeyRow, cred_id) is not None:
                raise PasskeyRefused("this passkey is already registered")
            row = PasskeyRow(
                credential_id=cred_id,
                name=ch.data["name"],
                cose_key=bytes_to_base64url(v.credential_public_key),
                spki=bytes_to_base64url(spki),
                alg=alg,
                sign_count=v.sign_count,
                created_at=_iso(now),
                created_by=actor.label,
            )
            s.add(row)
            audit.append(
                s,
                ts=now,
                actor=actor.label,
                action="passkey_registered",
                subject=row.name,
                detail={"credential_id": cred_id, "alg": alg},
            )
        return row

    def remove(self, credential_id: str, *, actor: HumanActor, now: datetime, keep_at_least: int = 1) -> None:
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            row = s.get(PasskeyRow, credential_id)
            if row is None or row.removed_at is not None:
                raise PasskeyRefused("no such passkey")
            remaining = s.exec(select(PasskeyRow).where(col(PasskeyRow.removed_at).is_(None))).all()
            if len(remaining) - 1 < keep_at_least:
                raise PasskeyRefused("that would leave no passkey to sign in or approve with")
            row.removed_at = _iso(now)
            s.add(row)
            for sess in s.exec(
                select(WebSessionRow).where(col(WebSessionRow.credential_id) == credential_id)
            ):
                sess.revoked_at = sess.revoked_at or _iso(now)
                s.add(sess)
            audit.append(
                s,
                ts=now,
                actor=actor.label,
                action="passkey_removed",
                subject=row.name,
                detail={"credential_id": credential_id},
            )

    # --- challenges and assertions -----------------------------------------------------------------------

    def _remember(
        self, purpose: Purpose, subject: str, challenge: bytes, now: datetime, data: dict[str, Any]
    ) -> str:
        for k in [k for k, c in self._challenges.items() if c.expires_at <= now]:
            del self._challenges[k]
        if len(self._challenges) > 1000:
            raise PasskeyRefused("too many open challenges; try again in a minute")
        cid = secrets.token_urlsafe(16)
        self._challenges[cid] = Challenge(cid, purpose, subject, challenge, now + CHALLENGE_TTL, data)
        return cid

    def _take(self, challenge_id: str, purpose: Purpose, subject: str | None, now: datetime) -> Challenge:
        ch = self._challenges.pop(challenge_id, None)
        if (
            ch is None
            or ch.expires_at <= now
            or ch.purpose != purpose
            or (subject is not None and ch.subject != subject)
        ):
            raise PasskeyRefused(
                "the passkey request expired or doesn't match; try again", code="challenge_invalid"
            )
        return ch

    def assertion_options(
        self,
        purpose: Purpose,
        subject: str,
        *,
        now: datetime,
        challenge: bytes | None = None,
        data: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        rows = active(self.engine)
        if not rows:
            raise PasskeyRefused(
                "no passkey is registered yet; run `warden passkey add <name>` on the warden guest"
            )
        challenge = challenge or secrets.token_bytes(32)
        opts = generate_authentication_options(
            rp_id=self.rp.rp_id,
            challenge=challenge,
            allow_credentials=[]
            if purpose == "login"
            else [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r.credential_id)) for r in rows],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return self._remember(purpose, subject, challenge, now, data or {}), options_to_json(opts)

    def verify(
        self, challenge_id: str, credential: dict[str, Any], purpose: Purpose, subject: str, *, now: datetime
    ) -> tuple[Verified, Challenge]:
        ch = self._take(challenge_id, purpose, subject, now)
        cred_id = credential.get("id") if isinstance(credential, dict) else None
        if not isinstance(cred_id, str):
            raise PasskeyRefused("malformed passkey response")
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            row = s.get(PasskeyRow, cred_id)
            if row is None or row.removed_at is not None:
                raise PasskeyRefused("This passkey isn't registered with Warden", code="unknown_passkey")
            try:
                v = verify_authentication_response(
                    credential=credential,
                    expected_challenge=ch.challenge,
                    expected_rp_id=self.rp.rp_id,
                    expected_origin=self.rp.origin,
                    credential_public_key=base64url_to_bytes(row.cose_key),
                    credential_current_sign_count=row.sign_count,
                    require_user_verification=True,
                )
            except InvalidAuthenticationResponse as exc:
                raise PasskeyRefused(f"the passkey response didn't verify: {exc}") from exc
            row.sign_count = v.new_sign_count
            row.last_used_at = _iso(now)
            s.add(row)
        resp = credential["response"]
        assertion = {
            "credential_id": cred_id,
            "authenticator_data": resp["authenticatorData"],
            "client_data_json": resp["clientDataJSON"],
            "signature": resp["signature"],
        }
        return Verified(cred_id, row.name, assertion), ch

    # --- sessions ----------------------------------------------------------------------------------------

    def login(
        self, challenge_id: str, credential: dict[str, Any], *, ip: str, user_agent: str, now: datetime
    ) -> tuple[str, WebSessionRow]:
        v, _ = self.verify(challenge_id, credential, "login", "", now=now)
        token = secrets.token_urlsafe(32)
        row = WebSessionRow(
            token_hash=_hash(token),
            credential_id=v.credential_id,
            name=v.name,
            created_at=_iso(now),
            expires_at=_iso(now + SESSION_TTL),
            last_seen_at=_iso(now),
            ip=ip[:64],
            user_agent=user_agent[:200],
        )
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            s.add(row)
            audit.append(
                s,
                ts=now,
                actor=f"dashboard:{actor_id(v.name)}",
                action="signed_in",
                subject=v.name,
                detail={"ip": row.ip},
            )
        return token, row

    def session(self, token: str | None, *, now: datetime) -> WebSessionRow | None:
        if not token or len(token) > 100:
            return None
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            row = s.get(WebSessionRow, _hash(token))
            if row is None or row.revoked_at is not None or datetime.fromisoformat(row.expires_at) <= now:
                return None
            pk = s.get(PasskeyRow, row.credential_id)
            if pk is None or pk.removed_at is not None:
                return None
            if (now - datetime.fromisoformat(row.last_seen_at)).total_seconds() > 60:
                row.last_seen_at = _iso(now)
                s.add(row)
            return row

    def revoke_session(self, token_hash: str, *, actor: HumanActor, now: datetime) -> None:
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            row = s.get(WebSessionRow, token_hash)
            if row is None:
                raise PasskeyRefused("no such session")
            row.revoked_at = row.revoked_at or _iso(now)
            s.add(row)
            audit.append(
                s,
                ts=now,
                actor=actor.label,
                action="session_revoked",
                subject=row.name,
                detail={"ip": row.ip},
            )

    def sessions(self, *, now: datetime) -> list[WebSessionRow]:
        with Session(self.engine, expire_on_commit=False) as s:
            rows = s.exec(select(WebSessionRow).where(col(WebSessionRow.revoked_at).is_(None))).all()
        return [r for r in rows if datetime.fromisoformat(r.expires_at) > now]


def actor_id(name: str) -> str:
    """A passkey name as a HumanActor id ("MacBook Pro" → "MacBook-Pro")."""
    return re.sub(r"[^A-Za-z0-9._@-]", "-", name)[:64] or "passkey"


def human(session: WebSessionRow) -> HumanActor:
    return HumanActor("dashboard", actor_id(session.name))


def approver_refs(engine: Engine) -> list[dict[str, Any]]:
    """What agents get in the bundle for e2e checks: [{credential_id, alg, public, name}]."""
    return [
        {"credential_id": p.credential_id, "alg": p.alg, "public": p.spki, "name": p.name}
        for p in active(engine)
    ]


def challenge_for(message: bytes) -> bytes:
    """The WebAuthn challenge for a signed message (approval, publish): its SHA-256."""
    return hashlib.sha256(message).digest()


def client_challenge(client_data_json_b64: str) -> str:
    return str(json.loads(base64url_to_bytes(client_data_json_b64))["challenge"])


def trust_for(engine: Engine, rp: RelyingParty, *, e2e: bool) -> dict[str, Any]:
    """The approval trust agents should have: the e2e flag, every active passkey, this relying party."""
    return {
        "e2e": e2e,
        "approvers": approver_refs(engine),
        "webauthn": {"rp_id": rp.rp_id, "origins": [rp.origin]},
    }
