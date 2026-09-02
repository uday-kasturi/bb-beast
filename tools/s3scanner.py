"""
Tool wrapper for s3scanner — exposed S3 bucket detection.

s3scanner checks if S3 buckets (and compatible storage like GCS, DigitalOcean)
are publicly accessible or misconfigured.

CRITICAL: Only runs if "cloud_enum" is in allowed_test_types.

Flags:
  scan              scan subcommand
  --bucket <name>   single bucket name
  --bucket-file <f> file of bucket names (one per line)
  --provider <p>    cloud provider: aws, gcp, do, dreamhost, linode
  --threads <n>     concurrent workers
  --enumerate       enumerate bucket contents if accessible
  --no-color        no color
  --json            JSON output
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


class S3ScannerWrapper(ToolWrapper):
    name = "s3scanner"
    version_flag = "version"

    _DEPTH_CONFIG = {
        "quick":      {"threads": 5,  "enumerate": False},
        "standard":   {"threads": 10, "enumerate": False},
        "exhaustive": {"threads": 10, "enumerate": True},
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        bucket_names: list[str] | None = None,
        bucket_file: Path | None = None,
        provider: str = "aws",
        **kwargs: Any,
    ) -> dict:
        if "cloud_enum" not in program.get("allowed_test_types", []):
            log.info("[s3scanner] cloud_enum not in allowed_test_types — skipping")
            return self._write_skipped(run_id, raw_output_dir, target)

        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        _tmp_input = None
        if bucket_file and bucket_file.exists():
            input_path = bucket_file
        elif bucket_names:
            _tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for b in bucket_names:
                _tmp_input.write(b + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)
        else:
            # Generate bucket name guesses from the target domain
            generated = _generate_bucket_names(target)
            _tmp_input = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for b in generated:
                _tmp_input.write(b + "\n")
            _tmp_input.flush()
            input_path = Path(_tmp_input.name)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path_tmp = Path(tmp.name)

        cmd = [
            "s3scanner", "scan",
            "--bucket-file", str(input_path),
            "--provider", provider,
            "--threads", str(cfg["threads"]),
            "--no-color",
            "--json",
        ]
        if cfg["enumerate"]:
            cmd.append("--enumerate")

        result = self._exec(cmd, timeout=600)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"s3scanner exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:300],
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

            bucket_name = entry.get("bucket", {}).get("name", "")
            exists = entry.get("bucket", {}).get("exists", False)
            allowed = entry.get("bucket", {}).get("allowed_access", [])

            if not exists:
                continue

            if "AuthenticatedRead" in allowed or "PublicRead" in allowed or "PublicReadWrite" in allowed:
                severity = "high" if "PublicReadWrite" in allowed else "medium"
                evidence = (
                    f"Exposed S3 bucket: {bucket_name} | "
                    f"Provider: {provider} | "
                    f"Access: {', '.join(allowed)}"
                )
                findings.append({
                    "type": "exposed_s3",
                    "url": f"https://{bucket_name}.s3.amazonaws.com",
                    "evidence": evidence,
                    "raw_output": {
                        "bucket_name": bucket_name,
                        "provider": provider,
                        "exists": exists,
                        "allowed_access": allowed,
                        "objects_count": entry.get("bucket", {}).get("num_objects", 0),
                    },
                    "metadata": {"severity": severity},
                })

        if _tmp_input:
            Path(_tmp_input.name).unlink(missing_ok=True)

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

    def _write_skipped(self, run_id, raw_output_dir, target):
        out_path = self._write_raw_output(
            run_id=run_id, raw_output_dir=raw_output_dir, target=target,
            invocation_command="s3scanner (skipped)", started_at=_now(),
            finished_at=_now(), duration_seconds=0, status="success",
            findings=[], errors=[],
        )
        return {"raw_output_path": out_path, "findings_count": 0}


def _generate_bucket_names(domain: str) -> list[str]:
    """Generate likely S3 bucket name permutations from a domain."""
    # Strip TLD, get base name
    parts = domain.rstrip(".").split(".")
    base = parts[0] if parts else domain

    suffixes = [
        "", "-prod", "-production", "-staging", "-dev", "-development",
        "-test", "-backup", "-backups", "-data", "-assets", "-static",
        "-media", "-uploads", "-files", "-logs", "-archive", "-cdn",
        "-public", "-private", "-internal", "-admin", "-api",
    ]
    names = []
    for suffix in suffixes:
        names.append(f"{base}{suffix}")
        if len(parts) > 1:
            names.append(f"{domain.replace('.', '-')}{suffix}")
    return list(dict.fromkeys(names))  # dedupe


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
