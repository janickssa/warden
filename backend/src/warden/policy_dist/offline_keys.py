"""Offline policy keys: the public halves Warden knows (README 7A, DECISIONS D-04/D-05).

The private key never reaches a server; `warden-sign` holds it. Warden stores the public key to check uploaded
signatures and hands it to agents at enrollment, inside the CA-pinned channel the human confirmed. A primary
and an optional backup key; either can sign. Replacing a key is a Settings flow (M6), not something this
module does: registering refuses a role that's already taken.
"""

from __future__ import annotations

from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlmodel import Field, Session, SQLModel, col, select

from warden import audit
from warden.actors import HumanActor
from warden.errors import WardenError
from warden.keys import b64url, key_id_for, unb64url

ROLES = ("primary", "backup")


class OfflineKeyRefused(WardenError):
    code = "offline_key_refused"


class OfflineKeyRow(SQLModel, table=True):
    __tablename__ = "offline_keys"

    key_id: str = Field(primary_key=True)
    public: str
    role: str
    created_at: str
    created_by: str


def _parse_public(text: str) -> Ed25519PublicKey:
    try:
        raw = unb64url(text.strip())
    except ValueError as exc:
        raise OfflineKeyRefused("the public key isn't base64url") from exc
    if len(raw) != 32:
        raise OfflineKeyRefused("an ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def register(session: Session, public: str, *, role: str, actor: HumanActor, now: datetime) -> OfflineKeyRow:
    if role not in ROLES:
        raise OfflineKeyRefused(f"role must be one of {', '.join(ROLES)}")
    pub = _parse_public(public)
    key_id = key_id_for(pub)
    if session.get(OfflineKeyRow, key_id) is not None:
        raise OfflineKeyRefused(f"{key_id} is already registered")
    taken = session.exec(select(OfflineKeyRow).where(col(OfflineKeyRow.role) == role)).first()
    if taken is not None:
        raise OfflineKeyRefused(
            f"a {role} offline key is already registered ({taken.key_id}); replacing it is a Settings flow"
        )
    row = OfflineKeyRow(
        key_id=key_id,
        public=b64url(pub.public_bytes_raw()),
        role=role,
        created_at=now.isoformat(),
        created_by=actor.label,
    )
    session.add(row)
    audit.append(
        session,
        ts=now,
        actor=actor.label,
        action="offline_key_registered",
        subject=f"{role} · {key_id}",
        detail={"key_id": key_id, "role": role, "public": row.public},
    )
    return row


def active(session: Session) -> list[OfflineKeyRow]:
    rows = session.exec(select(OfflineKeyRow)).all()
    return sorted(rows, key=lambda r: ROLES.index(r.role))


def refs(session: Session) -> list[dict[str, str]]:
    """What an enrolling agent pins: [{key_id, public}]."""
    return [{"key_id": r.key_id, "public": r.public} for r in active(session)]


def verify(session: Session, key_id: str, sig: str, message: bytes) -> bool:
    row = session.get(OfflineKeyRow, key_id)
    if row is None or not sig.startswith("ed25519:"):
        return False
    try:
        _parse_public(row.public).verify(unb64url(sig[len("ed25519:") :]), message)
    except (InvalidSignature, ValueError):
        return False
    return True
