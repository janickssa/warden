"""Load policy.yaml, targets.yaml and settings.yaml. Any problem refuses to load (fail closed)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from warden.errors import ConfigError
from warden.policy.schema import Policy, Targets


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys (PyYAML silently keeps the last one)."""


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ConfigError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def parse_policy(text: str, *, source: str = "policy.yaml") -> Policy:
    data = load_yaml(text, source=source)
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level")
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def parse_targets(text: str, *, source: str = "targets.yaml") -> Targets:
    data = load_yaml(text, source=source)
    if not isinstance(data, list):
        raise ConfigError(f"{source}: expected a list of targets")
    try:
        return Targets.model_validate({"targets": data})
    except ValidationError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


class ApprovalSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    expiry_min: Annotated[int, Field(ge=1, le=24 * 60)] = 30
    passkey_medium: bool = False
    chat: bool = True
    chat_max_steps: Annotated[int, Field(ge=1, le=100)] = 10


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    public_url: str = "https://warden.example.dk"


class AgentListenerSettings(BaseModel):
    """Where agents connect (directly, never through NPM: DECISIONS D-20)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    listen_host: str = "0.0.0.0"  # noqa: S104 - the agent port is firewalled to enrolled agents (README 2)
    listen_port: Annotated[int, Field(ge=1, le=65535)] = 8443
    server_names: tuple[str, ...] = ("warden.lan",)  # names/IPs agents use; they go into the server cert


class HttpSettings(BaseModel):
    """Where `/mcp`, `/api` and `/ws` listen. NPM forwards those paths here (README 14); never expose it
    directly."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    listen_host: str = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1, le=65535)] = 8700


class Settings(BaseModel):
    """Human-only settings. Claude can neither read nor change these (README 17.3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    server: ServerSettings = ServerSettings()
    approvals: ApprovalSettings = ApprovalSettings()
    agents: AgentListenerSettings = AgentListenerSettings()
    http: HttpSettings = HttpSettings()


def parse_settings(text: str, *, source: str = "settings.yaml") -> Settings:
    data = load_yaml(text, source=source)
    if data is None:
        return Settings()
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level")
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


def load_policy(path: Path) -> Policy:
    return parse_policy(path.read_text(encoding="utf-8"), source=str(path))


def load_targets(path: Path) -> Targets:
    return parse_targets(path.read_text(encoding="utf-8"), source=str(path))


def load_settings(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    return parse_settings(path.read_text(encoding="utf-8"), source=str(path))
