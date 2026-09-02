"""
Base class for all tool wrappers.

Each tool wrapper inherits from ToolWrapper and implements:
  - name: str — the tool's CLI name
  - version_flag: str — flag to get version, e.g. --version
  - run(target, depth, run_id, raw_output_dir, **kwargs) -> dict

The base class handles:
  - Subprocess execution with timeout
  - Timing
  - raw_output/[tool].json construction and validation
  - Out-of-scope guard (checked against program before invocation)
  - Jitter/throttling between requests
"""

from __future__ import annotations

import json
import logging
import random
import shutil
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Per-file write locks — prevents race conditions when parallel playbooks
# call the same tool and both try to merge findings into the same .json file.
_file_locks: dict[str, threading.Lock] = {}
_file_locks_registry_lock = threading.Lock()


def _get_file_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _file_locks_registry_lock:
        if key not in _file_locks:
            _file_locks[key] = threading.Lock()
        return _file_locks[key]

from core.validator import validate_and_write

log = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    pass


class ToolWrapper(ABC):

    #: CLI name of the tool. Must match the binary in PATH.
    name: str = ""

    #: Flag to pass to get the tool version string.
    version_flag: str = "--version"

    #: Default subprocess timeout in seconds.
    default_timeout: int = 3600

    def __init__(self) -> None:
        if not self.name:
            raise NotImplementedError("Tool subclass must set `name`")
        self._version_cache: str | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def available(self) -> bool:
        """Return True if the tool binary is found in PATH."""
        return shutil.which(self.name) is not None

    def require(self) -> None:
        """Raise ToolNotFoundError if not available."""
        if not self.available():
            raise ToolNotFoundError(
                f"Tool '{self.name}' not found in PATH. "
                f"Install it and make sure it is on your PATH."
            )

    def tool_version(self) -> str:
        if self._version_cache:
            return self._version_cache
        try:
            result = subprocess.run(
                [self.name, self.version_flag],
                capture_output=True, text=True, timeout=10,
            )
            ver = (result.stdout or result.stderr).strip().splitlines()[0]
            self._version_cache = ver
        except Exception:
            self._version_cache = "unknown"
        return self._version_cache

    @abstractmethod
    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        **kwargs: Any,
    ) -> dict:
        """
        Execute the tool against *target* and return the normalized raw_output dict.
        Implementations must call self._write_raw_output() before returning.
        """

    # ------------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------------

    def _exec(
        self,
        cmd: list[str],
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Execute *cmd* as a subprocess.
        Logs the command. Returns CompletedProcess regardless of exit code.
        """
        cmd_str = " ".join(str(c) for c in cmd)
        log.info("[%s] $ %s", self.name, cmd_str)
        t0 = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                cwd=cwd,
                env=env,
            )
        except subprocess.TimeoutExpired:
            log.warning("[%s] timed out after %ss", self.name, timeout or self.default_timeout)
            # Return a mock CompletedProcess so callers don't need to special-case
            return subprocess.CompletedProcess(
                args=cmd, returncode=-1,
                stdout="", stderr=f"TIMEOUT after {timeout}s"
            )
        elapsed = time.monotonic() - t0
        log.info("[%s] exit=%d elapsed=%.1fs", self.name, result.returncode, elapsed)
        return result

    def _write_raw_output(
        self,
        run_id: str,
        raw_output_dir: Path,
        target: str,
        invocation_command: str,
        started_at: str,
        finished_at: str,
        duration_seconds: float,
        status: str,
        findings: list[dict],
        errors: list[dict],
    ) -> Path:
        """
        Build, validate, and write raw_output/[tool].json.
        Returns the path written.
        """
        doc = {
            "schema_version": "1.0",
            "created_at": _now(),
            "run_id": run_id,
            "tool_name": self.name,
            "tool_version": self.tool_version(),
            "invocation_command": invocation_command,
            "target": target,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(duration_seconds, 2),
            "status": status,
            "findings": findings,
            "errors": errors,
        }
        out_path = raw_output_dir / f"{self.name}.json"

        # Acquire per-file lock before read-modify-write so parallel playbooks
        # calling the same tool don't corrupt the merged output file.
        file_lock = _get_file_lock(out_path)
        with file_lock:
            # If the file already exists (tool called multiple times in one run),
            # merge the new findings into the existing document instead of overwriting.
            if out_path.exists():
                try:
                    with open(out_path) as f:
                        existing = json.load(f)
                    existing_findings = existing.get("findings", [])
                    # Dedup by (type, url/host, evidence) — skip exact duplicates
                    seen_keys: set = set()
                    for ef in existing_findings:
                        key = (ef.get("type", ""), ef.get("url") or ef.get("host") or "", ef.get("evidence", "")[:120])
                        seen_keys.add(key)
                    for nf in findings:
                        key = (nf.get("type", ""), nf.get("url") or nf.get("host") or "", nf.get("evidence", "")[:120])
                        if key not in seen_keys:
                            existing_findings.append(nf)
                            seen_keys.add(key)
                    doc["findings"] = existing_findings
                    # Update metadata to reflect the latest invocation
                    doc["invocation_command"] = existing.get("invocation_command", invocation_command) + " [+more]"
                    doc["started_at"] = existing.get("started_at", started_at)
                except Exception as exc:
                    log.warning("[%s] could not merge existing output, overwriting: %s", self.name, exc)

            validate_and_write("raw_output", doc, out_path)
            log.info("[%s] wrote %s (%d findings)", self.name, out_path.name, len(doc["findings"]))
        return out_path

    @staticmethod
    def _auth_headers(session: dict | None) -> dict[str, str]:
        """All headers from session including Cookie. Empty dict if no session."""
        if not session:
            return {}
        return dict(session.get("headers", {}))

    @staticmethod
    def _auth_cookies(session: dict | None) -> str:
        """Cookie header value only. Empty string if no session."""
        if not session:
            return ""
        return session.get("headers", {}).get("Cookie", "")

    @staticmethod
    def sanitize_urls(urls: list[str], max_path_length: int = 200) -> list[str]:
        """
        Filter malformed URLs before passing to tools.

        Removes:
        - Non-HTTP(S) URLs
        - URLs with an embedded scheme (e.g. login.phphttps://...)
        - URLs with an excessively long path (infinite loop indicators)
        - Exact duplicates

        Args:
            urls:            Raw URL list (e.g. from waybackurls/gau).
            max_path_length: URLs whose path portion exceeds this are dropped.

        Returns:
            Deduplicated, sanitized URL list (order preserved).
        """
        seen: set[str] = set()
        result: list[str] = []
        for url in urls:
            if not url or not isinstance(url, str):
                continue
            url = url.strip()
            # Must start with http:// or https://
            if not (url.startswith("http://") or url.startswith("https://")):
                continue
            # No embedded scheme (e.g. "login.phphttps://...")
            if url.count("://") > 1:
                log.debug("sanitize_urls: dropping embedded-scheme URL: %s", url[:120])
                continue
            # Path length guard (catches /a/b/c/a/b/c/... loops from waybackurls)
            try:
                from urllib.parse import urlparse as _up
                path = _up(url).path
            except Exception:
                continue
            if len(path) > max_path_length:
                log.debug("sanitize_urls: dropping over-long path URL: %s", url[:120])
                continue
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    @staticmethod
    def _jitter(min_ms: int = 100, max_ms: int = 500) -> None:
        """Sleep for a random duration to avoid rate-limit triggers."""
        time.sleep(random.uniform(min_ms / 1000, max_ms / 1000))

    @staticmethod
    def _is_in_scope(target: str, program: dict) -> bool:
        """
        Return True if *target* is in the program's in-scope domains.
        Checks against both in_scope and out_of_scope lists.
        """
        import fnmatch

        out_domains = program.get("out_of_scope", {}).get("domains", [])
        for pattern in out_domains:
            if fnmatch.fnmatch(target, pattern) or target == pattern:
                log.debug("Target %s matches out-of-scope pattern %s — skipping", target, pattern)
                return False

        in_domains = program.get("in_scope", {}).get("domains", [])
        for pattern in in_domains:
            if fnmatch.fnmatch(target, pattern) or target == pattern:
                return True
            # Support wildcard like *.example.com matching sub.example.com
            if pattern.startswith("*."):
                apex = pattern[2:]
                if target == apex or target.endswith("." + apex):
                    return True

        log.debug("Target %s not found in in-scope domains — skipping", target)
        return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
