"""
Tool wrapper for gitleaks — git repo secrets scanning.

gitleaks detects hardcoded secrets using regex rules across git history.
Complements trufflehog — different ruleset, different false-positive profile.

Flags:
  detect            run detection
  --source <path>   path to repo (local) or URL
  --report-path <f> output file
  --report-format json
  --log-level warn  reduce noise
  --no-banner       suppress banner
  --exit-code 0     always exit 0 (we check output instead)
  --redact          redact secrets in output
  --max-decode-depth <n> depth for encoded secret detection
  --no-git          scan as filesystem (not git-aware)
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class GitleaksWrapper(ToolWrapper):
    name = "gitleaks"
    version_flag = "version"

    _DEPTH_CONFIG = {
        "quick":      {"max_decode_depth": 1},
        "standard":   {"max_decode_depth": 3},
        "exhaustive": {"max_decode_depth": 5},
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        source_path: str | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        if not source_path:
            errors.append({"message": "gitleaks: source_path required"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "gitleaks", "detect",
            "--source", source_path,
            "--report-path", str(out_path_tmp),
            "--report-format", "json",
            "--log-level", "warn",
            "--no-banner",
            "--exit-code", "0",
            "--redact",
            "--max-decode-depth", str(cfg["max_decode_depth"]),
        ]

        result = self._exec(cmd, timeout=1800)

        if result.returncode > 1:
            errors.append({
                "message": f"gitleaks exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
                "exit_code": result.returncode,
            })

        if out_path_tmp.exists():
            try:
                data = json.loads(out_path_tmp.read_text())
                for leak in (data if isinstance(data, list) else []):
                    rule_id = leak.get("RuleID", "unknown")
                    file_path = leak.get("File", "")
                    line = leak.get("StartLine", 0)
                    commit = leak.get("Commit", "")
                    author = leak.get("Author", "")
                    secret = leak.get("Secret", "REDACTED")

                    evidence = (
                        f"Secret [{rule_id}] in {file_path}:{line}"
                        f"{' commit:' + commit[:8] if commit else ''}"
                    )

                    findings.append({
                        "type": "secret_exposure",
                        "url": source_path,
                        "evidence": evidence,
                        "raw_output": {
                            "rule_id": rule_id,
                            "file": file_path,
                            "start_line": line,
                            "end_line": leak.get("EndLine", line),
                            "commit": commit[:12] if commit else "",
                            "author": author,
                            "date": leak.get("Date", ""),
                            "secret_redacted": secret,  # gitleaks redacts with --redact
                            "match": leak.get("Match", ""),
                            "tags": leak.get("Tags", []),
                        },
                        "metadata": {"severity": "high"},
                    })
            except (json.JSONDecodeError, Exception) as exc:
                errors.append({"message": f"gitleaks output parse error: {exc}"})
            out_path_tmp.unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at, finished_at=finished_at,
            duration_seconds=duration, status=status,
            findings=findings, errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}

    def _write_empty(self, run_id, raw_output_dir, target, started_at, errors):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="gitleaks (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
