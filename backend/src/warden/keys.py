"""ed25519 key files on the warden guest (README section 12): mode 0600, owned by the Warden user.

Used for the approval key and the online policy key. The offline policy key never lives here (README 7A).
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from warden.errors import SigningError


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_public(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_for(public: Ed25519PublicKey) -> str:
    return "ed25519:" + hashlib.sha256(raw_public(public)).hexdigest()[:16]


def generate_key_file(path: Path) -> Ed25519PrivateKey:
    """Create a new key file. Never overwrites an existing file."""
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return private


def load_key_file(path: Path, *, what: str) -> Ed25519PrivateKey:
    try:
        st = path.stat()
    except OSError as exc:
        raise SigningError(f"can't read {what} {path}: {exc.strerror}") from exc
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SigningError(f"{what} {path} must not be readable by group or others (chmod 600)")
    if st.st_uid != os.geteuid():
        raise SigningError(f"{what} {path} must be owned by the user running Warden")
    try:
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except ValueError as exc:
        raise SigningError(f"{what} {path} is not a valid key") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise SigningError(f"{what} {path} is not an ed25519 key")
    return private


class OnlineKey:
    """Signs bundles proven to tighten (README 7A). In M2 it signs only each target's initial bundle."""

    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private
        self.public = private.public_key()
        self.key_id = key_id_for(self.public)

    @classmethod
    def generate(cls, path: Path) -> OnlineKey:
        return cls(generate_key_file(path))

    @classmethod
    def load(cls, path: Path) -> OnlineKey:
        return cls(load_key_file(path, what="online policy key"))

    def sign(self, message: bytes) -> str:
        return "ed25519:" + b64url(self._private.sign(message))

    @property
    def public_b64(self) -> str:
        return b64url(raw_public(self.public))
