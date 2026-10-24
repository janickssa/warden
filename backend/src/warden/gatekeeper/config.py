"""`gatekeeper.yaml` (README 9): which reviewers run, and how. The single source of truth (§16 rule 8).

API keys are never in the YAML: `api_key: secret:NAME` points at `<config dir>/secrets/NAME` (README 12,
`/etc/warden/secrets`, mode 0600, owned by the Warden user). A secret that's missing or too open makes that
reviewer unavailable (counted as escalate), never silently skipped.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from warden.config import load_yaml
from warden.errors import ConfigError

Provider = Literal["ollama", "openai", "anthropic", "openai_compatible"]
SECRET_PREFIX = "secret:"  # noqa: S105 - a prefix, not a secret
_NAME = r"^[a-z0-9][a-z0-9-]{0,31}$"
_SECRET_NAME = r"^[A-Z][A-Z0-9_]{0,63}$"  # noqa: S105 - a name pattern


class SecretError(ConfigError):
    code = "secret_unavailable"


class ReviewerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Annotated[str, Field(pattern=_NAME)]
    provider: Provider
    model: Annotated[str, Field(min_length=1, max_length=200)]
    url: str | None = None
    api_key: str | None = None  # "secret:NAME"
    # Command output and Claude's notes may contain anything; default: only the local model sees them.
    send_untrusted_output: bool | None = None
    temperature: float | None = 0.0  # null omits it, for models that refuse the parameter
    max_tokens: Annotated[int, Field(ge=256, le=32000)] | None = None  # provider default when unset
    options: dict[str, Any] = Field(default_factory=dict)  # provider-specific, e.g. {num_ctx: 8192}

    @field_validator("api_key")
    @classmethod
    def _secret_ref(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith(SECRET_PREFIX) or not re.match(_SECRET_NAME, v[len(SECRET_PREFIX) :]):
            raise ValueError("api_key must be secret:NAME (the key itself lives in the secrets directory)")
        return v

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v is not None and not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("url must start with http:// or https://")
        return v.rstrip("/") if v else v

    @property
    def sends_untrusted(self) -> bool:
        if self.send_untrusted_output is not None:
            return self.send_untrusted_output
        return self.provider == "ollama"

    @property
    def endpoint(self) -> str:
        if self.url:
            return self.url
        defaults = {
            "ollama": "http://localhost:11434",
            "openai": "https://api.openai.com/v1",
            "anthropic": "https://api.anthropic.com",
        }
        if self.provider not in defaults:
            raise ConfigError(f"reviewer {self.name}: openai_compatible needs a url")
        return defaults[self.provider]


class GatekeeperConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["strictest"] = "strictest"
    timeout_s: Annotated[int, Field(ge=5, le=600)] = 60
    injection_scan: bool = True
    reviewers: tuple[ReviewerConfig, ...] = ()

    @field_validator("reviewers")
    @classmethod
    def _unique(cls, v: tuple[ReviewerConfig, ...]) -> tuple[ReviewerConfig, ...]:
        names = [r.name for r in v]
        if len(set(names)) != len(names) or "injection-scan" in names:
            raise ValueError("reviewer names must be unique and not 'injection-scan'")
        return v


def parse_gatekeeper(text: str, *, source: str = "gatekeeper.yaml") -> GatekeeperConfig:
    data = load_yaml(text, source=source)
    if data is None:
        return GatekeeperConfig()
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level")
    try:
        return GatekeeperConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def load_gatekeeper(path: Path) -> GatekeeperConfig:
    if not path.exists():
        return GatekeeperConfig()
    return parse_gatekeeper(path.read_text(encoding="utf-8"), source=str(path))


class Secrets:
    """Reads `secret:NAME` from a directory of 0600 files owned by the current user."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def get(self, ref: str) -> str:
        if not ref.startswith(SECRET_PREFIX):
            raise SecretError("not a secret reference")
        name = ref[len(SECRET_PREFIX) :]
        path = self.dir / name
        try:
            st = path.stat()
        except OSError as exc:
            raise SecretError(f"secret {name} is missing ({path})") from exc
        if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SecretError(f"secret {name} must be owned by the Warden user with mode 0600")
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise SecretError(f"secret {name} is empty")
        return value

    def values(self) -> dict[str, str]:
        """Every readable secret, for scrubbing output before it leaves Warden."""
        out: dict[str, str] = {}
        if not self.dir.is_dir():
            return out
        for p in sorted(self.dir.iterdir()):
            try:
                out[p.name] = self.get(SECRET_PREFIX + p.name)
            except SecretError:
                continue
        return out
