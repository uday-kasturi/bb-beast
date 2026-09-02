"""
core/models.py — unified model transport for the agent bus.

ONE place model routing lives. Every agent calls `complete(role=..., messages=...)`
and never hardcodes a model id or a subprocess call. This replaces the four
duplicated `_call_claude_code` / `_call_opus` helpers scattered across
core/llm.py, core/attack_engine.py, core/zap_fable.py, core/agent.py.

Two backends:
  - openrouter : OpenAI-compatible HTTP API. Reaches Hermes + every cheap /
                 uncensored worker model. Needs OPENROUTER_API_KEY. Metered.
  - cli        : the local `claude --print` CLI (logged-in Claude Code session).
                 No metered cost, and refuses security/exploit content far less
                 than API Claude. Kept as an orchestrator-tier fallback.

Role -> model routing is config (ROLES below), overridable per-role via env:
    BB_MODEL_TRIAGE=nousresearch/hermes-3-llama-3.1-405b
    BB_MODEL_ORCHESTRATOR=cli:claude-fable-5      # use the CLI backend

A model id prefixed with "cli:" forces the CLI backend for that role.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# .env loading (zero-dependency — no python-dotenv required)
# ---------------------------------------------------------------------------
# Loads project-root/.env at import. Real shell env vars ALWAYS win over the
# file, so `export OPENROUTER_API_KEY=...` overrides .env for one-off runs.

def _load_dotenv() -> None:
    env_path = Path(__file__).parent.parent / ".env"
    if not env_path.exists():
        return
    try:
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:  # shell env wins
                os.environ[key] = value
    except OSError as exc:  # unreadable .env must not crash imports
        log.warning("Could not read .env: %s", exc)


_load_dotenv()

# ---------------------------------------------------------------------------
# Role -> model routing (the job->model table, made real)
# ---------------------------------------------------------------------------
# These are DEFAULTS — tune to whatever you have credits for on OpenRouter.
# Anything prefixed "cli:" runs on the local claude CLI instead of OpenRouter.
#
# Rationale per role:
#   orchestrator  — routing + final evidence sign-off. Needs best reasoning.
#                   Default keeps it on the CLI (refusal-safe, free). Switch to
#                   an OpenRouter anthropic id for "everything via OpenRouter".
#   triage/critic — high-volume verdict grind. Hermes: cheap + won't refuse.
#   exploit_smith — writes paste-ready exploit payloads. MUST be uncensored;
#                   hosted GPT/Claude API endpoints refuse this.
#   validator     — hypothesizes + judges probe evidence. Uncensored.
#   dedup         — pure rules today (no model). Listed for completeness.

_DEFAULT_ROLES: dict[str, str] = {
    "orchestrator":  "cli:claude-fable-5",
    "triage":        "nousresearch/hermes-3-llama-3.1-70b",
    "critic":        "nousresearch/hermes-3-llama-3.1-70b",
    "exploit_smith": "nousresearch/hermes-3-llama-3.1-405b",
    "validator":     "nousresearch/hermes-3-llama-3.1-405b",
    "classify":      "nousresearch/hermes-3-llama-3.1-70b",
    # Reasoning/orchestration engines migrated off hardcoded opus-4-8. fable-5
    # on the CLI is free, refusal-safe, and matches the triage-tier preference.
    "recon":         "cli:claude-fable-5",
    "attack_engine": "cli:claude-fable-5",
    "zap_fable":     "cli:claude-fable-5",
}


def _roles() -> dict[str, str]:
    """Resolve the role map with per-role env overrides (BB_MODEL_<ROLE>)."""
    resolved = dict(_DEFAULT_ROLES)
    for role in list(resolved):
        override = os.environ.get(f"BB_MODEL_{role.upper()}")
        if override:
            resolved[role] = override
    return resolved


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_DEFAULT_TIMEOUT = 120       # seconds per attempt (was 300 — a cold-start hang
                             # shouldn't stall an agent for 5 min; retry instead)
_DEFAULT_RETRIES = 2         # extra attempts on transient failures (timeout/5xx/429)
_RETRY_BACKOFF = 2.0         # seconds, multiplied by attempt number
_CLI_PREFIX = "cli:"


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class ModelError(RuntimeError):
    """Raised when a model call fails (transport, auth, or non-2xx)."""


@dataclass
class Completion:
    """Result of a single model call."""
    text: str
    model: str
    backend: str            # "openrouter" | "cli"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    finish_reason: str = ""

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def resolve(role_or_model: str) -> tuple[str, str]:
    """
    Map a role name (or a raw model id) to (backend, model_id).

    A known role -> its configured model. Anything else is treated as a raw
    model id. A "cli:" prefix on either forces the CLI backend.
    """
    roles = _roles()
    target = roles.get(role_or_model, role_or_model)
    if target.startswith(_CLI_PREFIX):
        return "cli", target[len(_CLI_PREFIX):]
    return "openrouter", target


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def complete(
    role_or_model: str,
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.2,
    max_tokens: int | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    retries: int = _DEFAULT_RETRIES,
    response_format: dict | None = None,
) -> Completion:
    """
    Run a chat completion for the given role (or raw model id).

    Args:
        role_or_model:   A role key (e.g. "triage") or raw model id.
        messages:        OpenAI-style [{"role": "system"|"user"|"assistant",
                         "content": "..."}].
        temperature:     Sampling temperature.
        max_tokens:      Optional cap on completion length.
        timeout:         Per-attempt timeout in seconds.
        retries:         Extra attempts on transient failures (OpenRouter only).
        response_format: Optional OpenRouter response_format (e.g.
                         {"type": "json_object"}). Ignored by the CLI backend.

    Returns:
        Completion with text + token accounting.

    Raises:
        ModelError: on any transport/auth/parse failure.
    """
    backend, model_id = resolve(role_or_model)
    if backend == "cli":
        return _complete_cli(model_id, messages, timeout=timeout)
    return _complete_openrouter(
        model_id, messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        retries=retries,
        response_format=response_format,
    )


def complete_json(
    role_or_model: str,
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.1,
    max_tokens: int | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> tuple[Any, Completion]:
    """
    Like complete(), but parses the response as JSON. Handles models that wrap
    JSON in markdown fences or add prose around it. Requests a JSON response
    format from OpenRouter backends when possible.

    Returns:
        (parsed_object, Completion)

    Raises:
        ModelError: if no valid JSON can be extracted.
    """
    backend, _ = resolve(role_or_model)
    response_format = {"type": "json_object"} if backend == "openrouter" else None
    comp = complete(
        role_or_model, messages,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        response_format=response_format,
    )
    parsed = _extract_json(comp.text)
    if parsed is None:
        raise ModelError(
            f"Model '{comp.model}' ({comp.backend}) returned no valid JSON. "
            f"First 500 chars:\n{comp.text[:500]}"
        )
    return parsed, comp


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def _complete_openrouter(
    model_id: str,
    messages: list[dict[str, str]],
    *,
    temperature: float,
    max_tokens: int | None,
    timeout: int,
    retries: int,
    response_format: dict | None,
) -> Completion:
    import time
    import requests  # local import — keeps CLI-only usage dependency-free

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ModelError(
            "OPENROUTER_API_KEY not set. Export it, or route this role to the "
            "CLI backend with BB_MODEL_<ROLE>=cli:<model>."
        )

    payload: dict[str, Any] = {
        "model": model_id,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    if response_format is not None:
        payload["response_format"] = response_format

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        # Optional attribution headers OpenRouter uses for its dashboard.
        "HTTP-Referer": os.environ.get("BB_OPENROUTER_REFERER", "https://localhost/bb-beast"),
        "X-Title": os.environ.get("BB_OPENROUTER_TITLE", "BugBounty Beast"),
    }

    # Retry only transient failures: timeouts, connection errors, 429, 5xx.
    # Auth (401/403) and bad-request (400/404 model) fail fast — retrying is futile.
    attempts = retries + 1
    last_err = "unknown"
    for attempt in range(attempts):
        if attempt:
            time.sleep(_RETRY_BACKOFF * attempt)
            log.warning("OpenRouter retry %d/%d for '%s' (%s)", attempt, retries, model_id, last_err)
        try:
            resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=timeout)
        except requests.RequestException as exc:
            last_err = f"transport: {exc}"
            continue  # transient — retry

        if resp.status_code == 200:
            try:
                data = resp.json()
                choice = data["choices"][0]
                text = choice["message"]["content"] or ""
                usage = data.get("usage", {})
            except (KeyError, IndexError, ValueError) as exc:
                raise ModelError(
                    f"Unexpected OpenRouter response shape for '{model_id}': {resp.text[:500]}"
                ) from exc
            return Completion(
                text=text.strip(),
                model=model_id,
                backend="openrouter",
                prompt_tokens=int(usage.get("prompt_tokens", 0)),
                completion_tokens=int(usage.get("completion_tokens", 0)),
                finish_reason=choice.get("finish_reason", ""),
            )

        if resp.status_code == 429 or resp.status_code >= 500:
            last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
            continue  # transient — retry

        # Non-retryable (auth, bad model, bad request)
        raise ModelError(
            f"OpenRouter returned {resp.status_code} for '{model_id}': {resp.text[:500]}"
        )

    raise ModelError(f"OpenRouter failed for '{model_id}' after {attempts} attempts: {last_err}")


def _complete_cli(
    model_id: str,
    messages: list[dict[str, str]],
    *,
    timeout: int,
) -> Completion:
    """Invoke the local `claude` CLI. Flattens chat messages into one prompt."""
    claude_bin = shutil.which("claude")
    if not claude_bin:
        raise ModelError(
            "claude CLI not found in PATH. Install Claude Code and log in, or "
            "route this role to OpenRouter via BB_MODEL_<ROLE>."
        )

    prompt = _flatten_messages(messages)
    # --tools none: every call in this system is pure-LLM reasoning that returns
    # JSON. We never want the Claude Code CLI spawning its own tools mid-call.
    cmd = [claude_bin, "--print", "--tools", "none"]
    if model_id:
        cmd += ["--model", model_id]

    try:
        # Pipe the prompt via stdin to avoid arg-length limits on large findings.
        result = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ModelError(f"claude CLI timed out after {timeout}s for '{model_id}'") from exc

    if result.returncode != 0:
        raise ModelError(
            f"claude CLI failed (exit {result.returncode}) for '{model_id}':\n"
            f"{result.stderr[:500]}"
        )

    # The CLI reports no token usage; leave counts at 0.
    return Completion(text=result.stdout.strip(), model=model_id, backend="cli")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_messages(messages: list[dict[str, str]]) -> str:
    """Collapse chat messages into a single prompt for the CLI backend."""
    parts: list[str] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role == "system":
            parts.append(content)
        elif role == "assistant":
            parts.append(f"[assistant]\n{content}")
        else:
            parts.append(content)
    return "\n\n---\n\n".join(p for p in parts if p)


def _extract_json(text: str) -> Any | None:
    """
    Best-effort JSON extraction: raw parse, then fenced ```json block, then the
    first balanced {...} / [...] span. Returns None if nothing parses.
    """
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                continue
    return None
