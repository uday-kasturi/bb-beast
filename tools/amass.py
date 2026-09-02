"""
Tool wrapper for amass — subdomain enumeration (active/passive/brute).

amass is the most thorough subdomain enumerator. It uses:
- Passive sources (similar to subfinder)
- Active DNS resolution
- Web archive scraping
- Certificate transparency
- ASN/IP range mapping
- Brute-force (exhaustive only)

Flags used:
  enum                  enumeration subcommand
  -d <domain>           target domain
  -o <file>             output file (one host per line)
  -json <file>          JSON output
  -passive              passive only (quick/standard)
  -active               active enumeration (exhaustive)
  -brute                brute force (exhaustive only)
  -w <wordlist>         wordlist for brute (exhaustive)
  -rf <resolvers>       custom resolver file
  -max-dns-queries <n>  rate limit DNS queries
  -timeout <mins>       overall timeout in minutes
  -silent               suppress most output
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

# Path to a shared DNS resolvers file — populated at setup time
_RESOLVERS_FILE = Path(__file__).parent.parent / "config" / "resolvers.txt"

# Small built-in wordlist for brute if no external one is configured
_BUILTIN_WORDLIST = Path(__file__).parent.parent / "config" / "subdomains-top1million-5000.txt"


class AmassWrapper(ToolWrapper):
    name = "amass"
    version_flag = "version"

    _DEPTH_CONFIG = {
        "quick": {
            "passive": True,
            "active": False,
            "brute": False,
            "max_dns_queries": 250,
            "timeout_mins": 10,
        },
        "standard": {
            "passive": True,
            "active": False,
            "brute": False,
            "max_dns_queries": 500,
            "timeout_mins": 30,
        },
        "exhaustive": {
            "passive": False,
            "active": True,
            "brute": True,
            "max_dns_queries": 1000,
            "timeout_mins": 120,
        },
    }

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        **kwargs: Any,
    ) -> dict:
        self.require()
        cfg = self._DEPTH_CONFIG[depth]
        started_at = _now()
        t0 = time.monotonic()

        findings: list[dict] = []
        errors: list[dict] = []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            json_out = Path(tmp.name)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp2:
            txt_out = Path(tmp2.name)

        # amass v5: -timeout was repurposed as a brute wordlist mask flag.
        # Use subprocess timeout instead of -timeout flag.
        # -passive is deprecated (now the default), so skip it.
        cmd = [
            "amass", "enum",
            "-d", target,
            "-o", str(txt_out),
            "-json", str(json_out),
            "-silent",
        ]
        if cfg["active"]:
            cmd.append("-active")
        if cfg["brute"]:
            cmd.append("-brute")
            if _BUILTIN_WORDLIST.exists():
                cmd.extend(["-w", str(_BUILTIN_WORDLIST)])
        if _RESOLVERS_FILE.exists():
            cmd.extend(["-rf", str(_RESOLVERS_FILE)])

        result = self._exec(cmd, timeout=cfg["timeout_mins"] * 60 + 120)

        if result.returncode not in (0, 1):
            errors.append({
                "message": f"amass exited with code {result.returncode}",
                "stderr_excerpt": result.stderr[:500],
                "exit_code": result.returncode,
            })

        # Parse JSON output (amass writes one JSON object per line)
        if json_out.exists():
            for line in json_out.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                name = entry.get("name", "")
                if not name:
                    continue
                if not self._is_in_scope(name, program):
                    continue
                findings.append({
                    "type": "subdomain",
                    "host": name,
                    "evidence": f"amass: {entry.get('tag', '')} via {entry.get('source', '')}",
                    "raw_output": entry,
                })
            json_out.unlink(missing_ok=True)
        txt_out.unlink(missing_ok=True)

        finished_at = _now()
        duration = time.monotonic() - t0
        status = "success" if not errors else ("partial" if findings else "failed")

        out_path = self._write_raw_output(
            run_id=run_id,
            raw_output_dir=raw_output_dir,
            target=target,
            invocation_command=" ".join(str(c) for c in cmd),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            status=status,
            findings=findings,
            errors=errors,
        )
        return {"raw_output_path": out_path, "findings_count": len(findings)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
