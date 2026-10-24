"""One small adapter per provider (README 9): `review(request) -> GatekeeperVerdict`.

Every failure (unreachable, timeout, HTTP error, refusal, truncated or malformed answer, missing secret) comes
back as an unavailable reviewer, which counts as `escalate`. Error text is reduced to a short reason, so
nothing from a provider's error body (or a key) ends up in the plan.

- Ollama: `/api/chat`, `format` = the verdict JSON schema, temperature 0, `num_ctx` 8192 unless set.
- OpenAI and OpenAI-compatible: chat completions with a JSON-schema `response_format` (or `json_object` /
  none for endpoints without schema support).
- Anthropic: the official SDK with structured outputs (`output_config.format`). No `temperature`: Claude's
  Messages API rejects sampling parameters from API version 2026-10-21. Server-side refusal fallbacks are on
  by default (`fallbacks: "default"`); a refusal that still comes back counts as escalate.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

import anthropic
import httpx2

from warden.gatekeeper.config import ReviewerConfig, SecretError, Secrets
from warden.gatekeeper.prompt import VERDICT_SCHEMA, ReviewRequest
from warden.gatekeeper.verdict import parse, unavailable
from warden.plans.models import GatekeeperVerdict

ANTHROPIC_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class Reviewer(Protocol):
    name: str
    model: str
    sends_untrusted: bool

    def review(self, req: ReviewRequest) -> GatekeeperVerdict: ...


class _Base:
    default_max_tokens = 2048

    def __init__(
        self,
        cfg: ReviewerConfig,
        secrets: Secrets,
        *,
        timeout_s: float,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self.model = cfg.model
        self.sends_untrusted = cfg.sends_untrusted
        self._secrets = secrets
        self._timeout = timeout_s
        self._transport = transport

    @property
    def max_tokens(self) -> int:
        return self.cfg.max_tokens or self.default_max_tokens

    def _key(self) -> str | None:
        return self._secrets.get(self.cfg.api_key) if self.cfg.api_key else None

    def _http(self) -> httpx2.Client:
        return httpx2.Client(timeout=httpx2.Timeout(self._timeout), transport=self._transport)

    def _call(self, req: ReviewRequest) -> str:
        raise NotImplementedError

    def review(self, req: ReviewRequest) -> GatekeeperVerdict:
        try:
            raw = self._call(req)
        except SecretError as exc:
            return unavailable(self.name, self.model, exc.message)
        except (httpx2.TimeoutException, anthropic.APITimeoutError):
            return unavailable(self.name, self.model, "timed out")
        except (httpx2.ConnectError, anthropic.APIConnectionError):
            return unavailable(self.name, self.model, "unreachable")
        except httpx2.HTTPStatusError as exc:
            return unavailable(self.name, self.model, f"HTTP {exc.response.status_code}")
        except anthropic.APIStatusError as exc:
            return unavailable(self.name, self.model, f"HTTP {exc.status_code}")
        except _Declined as exc:
            return unavailable(self.name, self.model, str(exc))
        except (httpx2.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            return unavailable(self.name, self.model, f"bad response ({type(exc).__name__})")
        return parse(raw, name=self.name, model=self.model, steps=req.step_numbers)


class _Declined(Exception):
    """The provider answered but didn't review (refusal, truncation, empty answer)."""


class OllamaReviewer(_Base):
    def _call(self, req: ReviewRequest) -> str:
        opts: dict[str, Any] = {
            "num_ctx": 8192,
            **{k: v for k, v in self.cfg.options.items() if k != "think"},
        }
        if self.cfg.temperature is not None:
            opts["temperature"] = self.cfg.temperature
        opts.setdefault("num_predict", self.max_tokens)
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "format": VERDICT_SCHEMA,
            "options": opts,
            "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}],
        }
        if "think" in self.cfg.options:
            body["think"] = bool(self.cfg.options["think"])
        with self._http() as http:
            r = http.post(f"{self.cfg.endpoint}/api/chat", json=body)
            r.raise_for_status()
            data = r.json()
        if data.get("done_reason") == "length":
            raise _Declined("answer was cut off")
        content = data["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise _Declined("empty answer")
        return content


class OpenAIReviewer(_Base):
    """OpenAI chat completions; `openai_compatible` reuses it with its own URL and format options."""

    def _call(self, req: ReviewRequest) -> str:
        fmt = self.cfg.options.get("response_format", "json_schema")
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}],
        }
        body["max_completion_tokens" if self.cfg.provider == "openai" else "max_tokens"] = self.max_tokens
        if self.cfg.temperature is not None:
            body["temperature"] = self.cfg.temperature
        if fmt == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "gatekeeper_verdict", "strict": True, "schema": VERDICT_SCHEMA},
            }
        elif fmt == "json_object":
            body["response_format"] = {"type": "json_object"}
        headers = {}
        key = self._key()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        with self._http() as http:
            r = http.post(f"{self.cfg.endpoint}/chat/completions", json=body, headers=headers)
            r.raise_for_status()
            data = r.json()
        choice = data["choices"][0]
        msg = choice["message"]
        if msg.get("refusal"):
            raise _Declined("model declined to review")
        if choice.get("finish_reason") == "length":
            raise _Declined("answer was cut off")
        content = msg.get("content")
        if not isinstance(content, str) or not content.strip():
            raise _Declined("empty answer")
        return content


class AnthropicReviewer(_Base):
    default_max_tokens = 16000  # current Claude models always think; leave room before the answer

    def _client(self) -> anthropic.Anthropic:
        key = self._key()
        if not key:
            raise SecretError(f"reviewer {self.name} needs api_key: secret:NAME")
        http = httpx2.Client(timeout=httpx2.Timeout(self._timeout), transport=self._transport)
        return anthropic.Anthropic(
            api_key=key,
            base_url=self.cfg.url or None,
            timeout=self._timeout,
            max_retries=1,
            http_client=http,
        )

    def _call(self, req: ReviewRequest) -> str:
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": VERDICT_SCHEMA}}
        if "effort" in self.cfg.options:
            output_config["effort"] = self.cfg.options["effort"]
        kwargs: dict[str, Any] = {}
        fallbacks = self.cfg.options.get("fallbacks", "default")
        if fallbacks:
            kwargs["betas"] = [ANTHROPIC_FALLBACK_BETA]
            kwargs["fallbacks"] = fallbacks
        kwargs.update(
            model=self.model,
            max_tokens=self.max_tokens,
            system=req.system,
            messages=[{"role": "user", "content": req.user}],
            output_config=output_config,
        )
        with self._client() as client:
            resp = client.beta.messages.create(**kwargs)
        if resp.stop_reason == "refusal":
            raise _Declined("model declined to review")
        if resp.stop_reason == "max_tokens":
            raise _Declined("answer was cut off")
        text = next((b.text for b in resp.content if b.type == "text"), "")
        if not text.strip():
            raise _Declined("empty answer")
        json.loads(text)  # structured outputs guarantee JSON; anything else is a bad response
        return text


def make_reviewer(
    cfg: ReviewerConfig, secrets: Secrets, *, timeout_s: float, transport: httpx2.BaseTransport | None = None
) -> Reviewer:
    cls: type[_Base] = {
        "ollama": OllamaReviewer,
        "openai": OpenAIReviewer,
        "openai_compatible": OpenAIReviewer,
        "anthropic": AnthropicReviewer,
    }[cfg.provider]
    return cls(cfg, secrets, timeout_s=timeout_s, transport=transport)
