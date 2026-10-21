"""Warden's internal CA (README 7A, 12): ed25519, used only for the agent mTLS channel.

The CA key, server key and certificates live in <home>/ca with mode 0600/0700. Agents pin the CA by its
fingerprint, which travels inside the one-time enrollment token.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from warden.keys import generate_key_file, load_key_file

CA_DAYS = 3 * 365
SERVER_DAYS = 365
CLIENT_DAYS = 365


def fingerprint(public: Ed25519PublicKey) -> str:
    """Human-comparable key fingerprint, e.g. SHA256:5f:2a:… (first 16 bytes of SHA-256)."""
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + ":".join(f"{b:02x}" for b in hashlib.sha256(raw).digest()[:16])


def cert_fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


class CA:
    def __init__(self, directory: Path, key: Ed25519PrivateKey, cert: x509.Certificate) -> None:
        self.dir = directory
        self._key = key
        self.cert = cert
        self.fingerprint = cert_fingerprint(cert)

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @classmethod
    def load_or_create(cls, directory: Path, now: datetime | None = None) -> CA:
        directory.mkdir(mode=0o700, exist_ok=True)
        key_path, cert_path = directory / "ca.key", directory / "ca.pem"
        if key_path.exists():
            key = load_key_file(key_path, what="CA key")
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return cls(directory, key, cert)
        now = now or datetime.now(UTC)
        key = generate_key_file(key_path)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("warden-ca"))
            .issuer_name(_name("warden-ca"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, None)
        )
        _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        return cls(directory, key, cert)

    def server_files(self, names: list[str], now: datetime | None = None) -> tuple[Path, Path]:
        """(cert, key) for the agent listener, re-issued if the names changed or it's close to expiry."""
        cert_path, key_path = self.dir / "server.pem", self.dir / "server.key"
        now = now or datetime.now(UTC)
        if cert_path.exists() and key_path.exists():
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            have = sorted(
                [str(n) for n in san.get_values_for_type(x509.DNSName)]
                + [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
            )
            if have == sorted(names) and cert.not_valid_after_utc - now > timedelta(days=30):
                return cert_path, key_path
            key_path.unlink()
        key = generate_key_file(key_path)
        alt: list[x509.GeneralName] = []
        for n in names:
            try:
                alt.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                alt.append(x509.DNSName(n))
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("warden-agent-listener"))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=SERVER_DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, None)
        )
        _write(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path

    def issue_client(
        self, *, agent_id: str, name: str, public: Ed25519PublicKey, now: datetime | None = None
    ) -> x509.Certificate:
        now = now or datetime.now(UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(_name(agent_id))
            .issuer_name(self.cert.subject)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=CLIENT_DAYS))
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"warden-agent:{name}")]),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, None)
        )


def new_token_secret() -> str:
    return secrets.token_urlsafe(24)
