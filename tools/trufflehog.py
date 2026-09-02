"""
Tool wrapper for trufflehog — secrets detection in git repos and filesystems.

trufflehog finds:
- API keys (AWS, GCP, GitHub, Stripe, Twilio, etc.)
- Private keys (RSA, EC, PGP)
- Database connection strings
- OAuth tokens
- Certificates

Supports scanning:
- Git repositories (public)
- Filesystem paths
- S3 buckets
- GitHub/GitLab orgs

Flags (v3):
  git <url>         scan a git repo
  github --org <o>  scan a GitHub org
  filesystem <path> scan a local path
  --json            JSON output
  --no-update       skip update check
  --only-verified   only report verified secrets (lower noise)
  --results <types> result types: verified, unknown, unverified
  --concurrency <n> concurrent workers
  --log-level <l>   logging level
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.base import ToolWrapper

log = logging.getLogger(__name__)


class TrufflehogWrapper(ToolWrapper):
    name = "trufflehog"
    version_flag = "--version"

    _DEPTH_CONFIG = {
        "quick":      {"only_verified": True,  "concurrency": 4},
        "standard":   {"only_verified": True,  "concurrency": 8},
        "exhaustive": {"only_verified": False, "concurrency": 8},  # include unverified
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        repo_url: str | None = None,
        github_org: str | None = None,
        filesystem_path: str | None = None,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        if repo_url:
            cmd = ["trufflehog", "git", repo_url, "--json", "--no-update"]
            scan_target = repo_url
        elif github_org:
            cmd = ["trufflehog", "github", "--org", github_org, "--json", "--no-update"]
            scan_target = f"github.com/{github_org}"
        elif filesystem_path:
            cmd = ["trufflehog", "filesystem", filesystem_path, "--json", "--no-update"]
            scan_target = filesystem_path
        else:
            errors.append({"message": "trufflehog: no scan target provided"})
            return self._write_empty(run_id, raw_output_dir, target, started_at, errors)

        cmd.extend(["--concurrency", str(cfg["concurrency"])])
        if cfg["only_verified"]:
            cmd.append("--only-verified")

        result = self._exec(cmd, timeout=3600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"trufflehog exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = entry.get("DetectorName", "unknown")
            verified = entry.get("Verified", False)
            raw = entry.get("Raw", "")
            source_meta = entry.get("SourceMetadata", {})
            file_path = source_meta.get("Data", {}).get("Git", {}).get("file", "")
            commit = source_meta.get("Data", {}).get("Git", {}).get("commit", "")

            # Redact the actual secret in evidence — don't store raw secrets in findings
            evidence = (
                f"{'[VERIFIED] ' if verified else '[UNVERIFIED] '}"
                f"Secret type: {detector}"
                f"{' | File: ' + file_path if file_path else ''}"
                f"{' | Commit: ' + commit[:8] if commit else ''}"
            )

            findings.append({
                "type": "secret_exposure",
                "url": scan_target,
                "evidence": evidence,
                "raw_output": {
                    "detector": detector,
                    "verified": verified,
                    "file": file_path,
                    "commit": commit[:12] if commit else "",
                    "source_type": entry.get("SourceName", ""),
                    # NOTE: raw secret value intentionally NOT stored here
                    "raw_redacted": f"{raw[:4]}{'*' * (len(raw) - 4)}" if raw and len(raw) > 4 else "****",
                },
                "metadata": {"severity": "high" if verified else "medium"},
            })

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
            invocation_command="trufflehog (not run)", started_at=started_at,
            finished_at=_now(), duration_seconds=0, status="failed",
            findings=[], errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
