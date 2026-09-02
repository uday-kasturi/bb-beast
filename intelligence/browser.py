"""
Headless browser automation for XSS confirmation and screenshot capture.

Uses playwright-python to:
1. Load a URL in a headless Chromium browser
2. Inject an XSS payload via URL parameter or form submission
3. Wait for an interactsh OAST callback confirming execution
4. Capture a full-page screenshot as evidence
5. Save screenshot to runs/{uuid}/evidence/{finding_id}.png

Requires: pip install playwright && playwright install chromium
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def capture_xss_screenshot(
    url: str,
    finding_id: str,
    run_dir: Path,
    cookies: Optional[list[dict]] = None,
    extra_headers: Optional[dict] = None,
    wait_ms: int = 3000,
) -> Optional[Path]:
    """
    Open *url* in a headless browser, wait for any XSS payload to fire,
    and capture a full-page screenshot.

    Args:
        url:           The URL to load (should contain the XSS payload).
        finding_id:    UUID of the finding — used to name the screenshot file.
        run_dir:       Run output directory. Screenshot saved to evidence/ subdir.
        cookies:       Optional list of cookie dicts [{name, value, domain, ...}].
        extra_headers: Optional additional HTTP headers.
        wait_ms:       Milliseconds to wait after page load before screenshotting.

    Returns:
        Path to the saved screenshot, or None if capture failed.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.error(
            "playwright not installed. Run: pip install playwright && playwright install chromium"
        )
        return None

    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = evidence_dir / f"{finding_id}.png"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context_kwargs: dict = {}
            if extra_headers:
                context_kwargs["extra_http_headers"] = extra_headers

            context = browser.new_context(**context_kwargs)

            if cookies:
                context.add_cookies(cookies)

            page = context.new_page()

            # Capture console messages and alerts as evidence
            console_msgs: list[str] = []
            page.on("console", lambda msg: console_msgs.append(f"[{msg.type}] {msg.text}"))
            page.on("dialog", lambda dialog: (
                console_msgs.append(f"[ALERT] {dialog.message}"),
                dialog.dismiss()
            ))

            log.info("[browser] Navigating to: %s", url[:120])
            try:
                page.goto(url, timeout=15000, wait_until="networkidle")
            except Exception:
                # Page may time out if XSS payload causes a redirect — still screenshot
                pass

            if wait_ms > 0:
                page.wait_for_timeout(wait_ms)

            page.screenshot(path=str(screenshot_path), full_page=True)
            log.info("[browser] Screenshot saved: %s", screenshot_path)

            if console_msgs:
                log.info("[browser] Console/alert messages captured: %s", console_msgs[:5])
                # Save console log alongside screenshot
                log_path = evidence_dir / f"{finding_id}_console.txt"
                log_path.write_text("\n".join(console_msgs))

            browser.close()
            return screenshot_path

    except Exception as exc:
        log.error("[browser] Screenshot capture failed: %s", exc)
        return None


def confirm_xss_with_oast(
    url: str,
    oast_session,
    finding_id: str,
    run_dir: Path,
    cookies: Optional[list[dict]] = None,
    extra_headers: Optional[dict] = None,
    callback_timeout: int = 30,
) -> dict:
    """
    Load *url* in a headless browser (the URL should contain an interactsh
    OAST payload), wait for the callback, and capture a screenshot.

    Returns a result dict with:
      - confirmed: bool
      - screenshot_path: str | None
      - callbacks: list[dict]
      - execution_status: "callback_received" | "screenshot_confirmed" | "attempted_no_callback"
    """
    from tools.interactsh import format_callback_evidence

    # Start browser load in background, poll oast in parallel
    import threading

    screenshot_path: Optional[Path] = None
    browser_done = threading.Event()

    def _load_in_browser():
        nonlocal screenshot_path
        screenshot_path = capture_xss_screenshot(
            url=url,
            finding_id=finding_id,
            run_dir=run_dir,
            cookies=cookies,
            extra_headers=extra_headers,
        )
        browser_done.set()

    t = threading.Thread(target=_load_in_browser, daemon=True)
    t.start()

    # Poll for OAST callback
    callbacks = oast_session.poll_callbacks(timeout=callback_timeout)

    # Wait for browser to finish screenshot
    browser_done.wait(timeout=20)

    confirmed = len(callbacks) > 0
    execution_status = "attempted_no_callback"
    if confirmed and screenshot_path:
        execution_status = "screenshot_confirmed"
    elif confirmed:
        execution_status = "callback_received"

    return {
        "confirmed": confirmed,
        "screenshot_path": str(screenshot_path) if screenshot_path else None,
        "callbacks": callbacks,
        "execution_status": execution_status,
        "evidence": format_callback_evidence(callbacks, oast_session.oast_host),
    }
