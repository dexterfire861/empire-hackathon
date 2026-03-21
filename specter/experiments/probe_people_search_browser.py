from __future__ import annotations

"""
Standalone browser probe for Whitepages and FastPeopleSearch.

This script launches local Google Chrome in headless mode, connects via Chrome
DevTools Protocol, and asks Claude to decide the next browser action from a
page snapshot. It is read-only and does not attempt CAPTCHA bypass or login
workarounds.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anthropic
from websockets.sync.client import connect as ws_connect

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from specter.config import ANTHROPIC_API_KEY, CLAUDE_MODEL


DEFAULT_TIMEOUT = 20.0
DEFAULT_STEPS = 4
DEFAULT_HEADLESS = True

TARGETS = {
    "whitepages_search": {
        "url_template": "https://www.whitepages.com/name/{hyphenated}",
        "kind": "search",
    },
    "whitepages_opt_out": {
        "url_template": "https://www.whitepages.com/suppression-requests",
        "kind": "removal",
    },
    "fastpeoplesearch_search": {
        "url_template": "https://www.fastpeoplesearch.com/name/{hyphenated}",
        "kind": "search",
    },
    "fastpeoplesearch_opt_out": {
        "url_template": "https://www.fastpeoplesearch.com/removal",
        "kind": "removal",
    },
}

BLOCK_MARKERS = [
    "captcha",
    "verify you are human",
    "attention required",
    "access denied",
    "cloudflare",
    "bot detection",
    "security check",
    "unusual traffic",
    "are you human",
]

RESULT_MARKERS = [
    "current address",
    "phone number",
    "relatives",
    "associated persons",
    "possible previous address",
    "neighbors",
    "age",
    "lives in",
    "opt out",
    "suppression request",
    "remove my record",
]


def _name_variants(full_name: str) -> dict[str, str]:
    cleaned = " ".join(full_name.strip().split())
    parts = cleaned.split()
    return {
        "raw": cleaned,
        "hyphenated": "-".join(parts),
        "underscored": "_".join(parts),
        "query": urllib.parse.quote_plus(cleaned),
    }


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _chrome_candidates() -> list[str]:
    candidates = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    return [candidate for candidate in candidates if candidate]


def _find_chrome_binary() -> str:
    for candidate in _chrome_candidates():
        if Path(candidate).exists():
            return candidate
    raise FileNotFoundError(
        "Could not find a Chrome/Chromium binary. Set CHROME_PATH to a valid executable."
    )


def _wait_for_devtools(port: int, timeout: float) -> dict[str, Any]:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/json/version"
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # pragma: no cover - startup timing
            last_error = exc
            time.sleep(0.2)
    raise TimeoutError(f"Chrome DevTools never became ready: {last_error}")


def _list_targets(port: int) -> list[dict[str, Any]]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class BrowserHandle:
    proc: subprocess.Popen[Any]
    user_data_dir: str
    port: int

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        if self.user_data_dir:
            try:
                import shutil

                shutil.rmtree(self.user_data_dir, ignore_errors=True)
            except Exception:
                pass


class CDPSession:
    def __init__(self, ws_url: str) -> None:
        self.ws = ws_connect(ws_url, open_timeout=20)
        self.next_id = 1

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message = {"id": self.next_id, "method": method}
        if params:
            message["params"] = params
        current_id = self.next_id
        self.next_id += 1
        self.ws.send(json.dumps(message))

        while True:
            raw = self.ws.recv()
            data = json.loads(raw)
            if data.get("id") == current_id:
                if "error" in data:
                    raise RuntimeError(f"CDP {method} failed: {data['error']}")
                return data.get("result", {})

    def evaluate(self, expression: str, return_by_value: bool = True) -> dict[str, Any]:
        return self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": return_by_value,
                "awaitPromise": True,
            },
        )

    def navigate(self, url: str) -> dict[str, Any]:
        return self.call("Page.navigate", {"url": url})

    def wait_until_ready(self, timeout: float = DEFAULT_TIMEOUT) -> str:
        deadline = time.time() + timeout
        last_state = ""
        while time.time() < deadline:
            result = self.evaluate("document.readyState")
            last_state = (
                result.get("result", {})
                .get("value")
                if isinstance(result.get("result"), dict)
                else ""
            )
            if last_state in {"interactive", "complete"}:
                return str(last_state)
            time.sleep(0.25)
        return str(last_state)

    def set_value(self, selector: str, value: str) -> bool:
        expr = f"""
        (() => {{
          const el = document.querySelector({json.dumps(selector)});
          if (!el) return false;
          el.focus();
          const setter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype,
            'value'
          )?.set || Object.getOwnPropertyDescriptor(
            window.HTMLTextAreaElement.prototype,
            'value'
          )?.set;
          if (setter) {{
            setter.call(el, {json.dumps(value)});
          }} else {{
            el.value = {json.dumps(value)};
          }}
          el.dispatchEvent(new Event('input', {{ bubbles: true }}));
          el.dispatchEvent(new Event('change', {{ bubbles: true }}));
          return true;
        }})()
        """
        result = self.evaluate(expr)
        return bool(result.get("result", {}).get("value"))

    def click(self, selector: str) -> bool:
        expr = f"""
        (() => {{
          const el = document.querySelector({json.dumps(selector)});
          if (!el) return false;
          el.scrollIntoView({{ block: 'center' }});
          el.click();
          return true;
        }})()
        """
        result = self.evaluate(expr)
        return bool(result.get("result", {}).get("value"))

    def press_key(self, key: str) -> None:
        self.call(
            "Input.dispatchKeyEvent",
            {
                "type": "keyDown",
                "windowsVirtualKeyCode": 13 if key.lower() == "enter" else 0,
                "nativeVirtualKeyCode": 13 if key.lower() == "enter" else 0,
                "key": key,
                "code": "Enter" if key.lower() == "enter" else key,
                "text": "\r" if key.lower() == "enter" else "",
            },
        )
        self.call(
            "Input.dispatchKeyEvent",
            {
                "type": "keyUp",
                "windowsVirtualKeyCode": 13 if key.lower() == "enter" else 0,
                "nativeVirtualKeyCode": 13 if key.lower() == "enter" else 0,
                "key": key,
                "code": "Enter" if key.lower() == "enter" else key,
            },
        )

    def snapshot(self) -> dict[str, Any]:
        expr = """
        (() => {
          const limit = 25;
          const clean = (s) => String(s || '').replace(/\\s+/g, ' ').trim().slice(0, 180);
          const selectorFor = (el) => {
            if (!el) return '';
            if (el.id) return `#${CSS.escape(el.id)}`;
            const name = el.getAttribute('name');
            if (name) return `${el.tagName.toLowerCase()}[name=${JSON.stringify(name)}]`;
            const aria = el.getAttribute('aria-label');
            if (aria) return `${el.tagName.toLowerCase()}[aria-label=${JSON.stringify(aria)}]`;
            const type = el.getAttribute('type');
            if (type) return `${el.tagName.toLowerCase()}[type=${JSON.stringify(type)}]`;
            return el.tagName.toLowerCase();
          };
          const els = Array.from(document.querySelectorAll('a, button, input, textarea, select')).slice(0, limit).map((el) => ({
            tag: el.tagName.toLowerCase(),
            selector: selectorFor(el),
            text: clean(el.innerText || el.textContent || el.value || ''),
            placeholder: clean(el.getAttribute('placeholder') || ''),
            href: clean(el.href || ''),
            name: clean(el.getAttribute('name') || ''),
            aria: clean(el.getAttribute('aria-label') || ''),
            type: clean(el.getAttribute('type') || ''),
          }));
          const bodyText = clean(document.body ? document.body.innerText : '');
          const html = clean(document.documentElement ? document.documentElement.outerHTML : '');
          const blockedHints = Array.from(document.querySelectorAll('[id*="captcha" i], [class*="captcha" i], [id*="verify" i], [class*="verify" i], iframe[src*="captcha" i], iframe[src*="challenge" i]')).slice(0, 10).map((el) => clean(el.outerHTML || el.textContent || ''));
          return {
            title: document.title || '',
            url: location.href || '',
            ready_state: document.readyState || '',
            body_text: bodyText.slice(0, 12000),
            html_preview: html.slice(0, 12000),
            controls: els,
            blocked_hints: blockedHints,
          };
        })()
        """
        result = self.evaluate(expr)
        return result.get("result", {}).get("value", {})


def _launch_chrome(url: str, headless: bool, port: int) -> BrowserHandle:
    chrome = _find_chrome_binary()
    user_data_dir = tempfile.mkdtemp(prefix="specter-chrome-")
    args = [
        chrome,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-popup-blocking",
        "--disable-dev-shm-usage",
        "--disable-renderer-backgrounding",
        "--disable-features=Translate,BackForwardCache,AcceptCHFrame,MediaRouter",
        "--window-size=1440,2200",
        "--hide-scrollbars",
    ]
    if headless:
        args.append("--headless=new")
    args.append(url)
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return BrowserHandle(proc=proc, user_data_dir=user_data_dir, port=port)


def _extract_markers(text: str, markers: list[str]) -> list[str]:
    lower = text.lower()
    return [marker for marker in markers if marker in lower]


def _classify_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    body = str(snapshot.get("body_text", ""))
    html = str(snapshot.get("html_preview", ""))
    combined = f"{body}\n{html}"
    matched_block = _extract_markers(combined, BLOCK_MARKERS)
    matched_result = _extract_markers(combined, RESULT_MARKERS)
    return {
        "blocked": bool(matched_block),
        "matched_block_markers": matched_block,
        "matched_result_markers": matched_result,
        "useful_signal": bool(matched_result) and not matched_block,
    }


def _llm_decide_action(
    client: anthropic.Anthropic | None,
    target: str,
    snapshot: dict[str, Any],
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    if client is None:
        return {"action": "finish", "reason": "No Anthropic client configured."}

    prompt = {
        "target": target,
        "history": history[-4:],
        "snapshot": {
            "title": snapshot.get("title"),
            "url": snapshot.get("url"),
            "ready_state": snapshot.get("ready_state"),
            "body_text": snapshot.get("body_text", "")[:7000],
            "controls": snapshot.get("controls", [])[:20],
            "blocked_hints": snapshot.get("blocked_hints", []),
        },
        "task": (
            "Decide the single next browser action needed to determine whether "
            "this page yields useful searchable content or only bot protection. "
            "Do not attempt to bypass CAPTCHA or login walls. If the page already "
            "shows useful content, finish."
        ),
        "allowed_actions": [
            {
                "action": "click",
                "selector": "CSS selector from the snapshot controls list",
            },
            {
                "action": "type",
                "selector": "CSS selector from the snapshot controls list",
                "text": "string to enter",
            },
            {
                "action": "press",
                "key": "Enter",
            },
            {
                "action": "finish",
            },
        ],
        "output_schema": {
            "action": "click|type|press|finish",
            "selector": "string or null",
            "text": "string or null",
            "key": "string or null",
            "reason": "short explanation",
            "classification": "useful|blocked|no_results|form|unknown",
        },
    }

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=500,
        system=(
            "You are controlling a browser for a read-only feasibility probe. "
            "Choose one action at a time. Never suggest evasion, CAPTCHA solving, "
            "login bypass, or proxying around defenses."
        ),
        messages=[{"role": "user", "content": json.dumps(prompt, indent=2)}],
    )

    text = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "action": "finish",
            "reason": f"Non-JSON model output: {text[:200]}",
            "classification": "unknown",
        }


def _final_assessment(
    client: anthropic.Anthropic | None,
    target: str,
    snapshot: dict[str, Any],
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    heuristic = _classify_snapshot(snapshot)
    if client is None:
        return {
            "classification": "blocked" if heuristic["blocked"] else "unknown",
            "useful_signal": heuristic["useful_signal"],
            "heuristic": heuristic,
            "summary": "No Anthropic client configured.",
        }

    prompt = {
        "target": target,
        "heuristic": heuristic,
        "actions": actions,
        "final_snapshot": {
            "title": snapshot.get("title"),
            "url": snapshot.get("url"),
            "body_text": snapshot.get("body_text", "")[:9000],
            "controls": snapshot.get("controls", [])[:25],
            "blocked_hints": snapshot.get("blocked_hints", []),
        },
        "task": (
            "Summarize whether the browser session retrieved useful searchable "
            "content, what specific fields appear extractable, and whether the "
            "page is mostly blocked by bot protection or CAPTCHA."
        ),
        "output_schema": {
            "classification": "useful|blocked|no_results|unknown",
            "useful_signal": True,
            "extractable_fields": ["name", "phone", "address", "relatives", "age", "opt_out_url"],
            "summary": "short summary",
            "notes": ["short notes"],
        },
    }

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=500,
        system=(
            "You are summarizing a browser probe for people-search sites. "
            "Be concise and only report what the page actually exposed."
        ),
        messages=[{"role": "user", "content": json.dumps(prompt, indent=2)}],
    )
    text = "".join(
        block.text for block in response.content if getattr(block, "type", "") == "text"
    ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "classification": "unknown",
            "useful_signal": heuristic["useful_signal"],
            "heuristic": heuristic,
            "summary": text[:500],
        }


def _run_target(
    session: CDPSession,
    client: anthropic.Anthropic | None,
    target_name: str,
    target: dict[str, Any],
    name_vars: dict[str, str],
    max_steps: int,
) -> dict[str, Any]:
    url = target["url_template"].format(**name_vars)
    session.navigate(url)
    session.wait_until_ready()
    time.sleep(1.0)

    actions: list[dict[str, Any]] = []
    history: list[dict[str, Any]] = []

    for step in range(max_steps):
        snapshot = session.snapshot()
        history.append(
            {
                "step": step,
                "url": snapshot.get("url"),
                "title": snapshot.get("title"),
                "heuristic": _classify_snapshot(snapshot),
            }
        )

        decision = _llm_decide_action(client, target_name, snapshot, history)
        actions.append(decision)
        action = str(decision.get("action", "finish")).lower()

        if action == "finish":
            break

        selector = str(decision.get("selector") or "")
        if action == "click" and selector:
            session.click(selector)
            session.wait_until_ready()
        elif action == "type" and selector:
            session.set_value(selector, str(decision.get("text") or name_vars["raw"]))
            session.wait_until_ready()
        elif action == "press":
            session.press_key(str(decision.get("key") or "Enter"))
            session.wait_until_ready()
        else:
            break

        time.sleep(0.75)

    final_snapshot = session.snapshot()
    assessment = _final_assessment(client, target_name, final_snapshot, actions)
    heuristic = _classify_snapshot(final_snapshot)

    return {
        "target": target_name,
        "url": url,
        "actions": actions,
        "heuristic": heuristic,
        "assessment": assessment,
        "final_snapshot": {
            "title": final_snapshot.get("title"),
            "url": final_snapshot.get("url"),
            "ready_state": final_snapshot.get("ready_state"),
            "body_text": final_snapshot.get("body_text", "")[:2500],
            "controls": final_snapshot.get("controls", [])[:20],
            "blocked_hints": final_snapshot.get("blocked_hints", []),
        },
    }


def _build_client() -> anthropic.Anthropic | None:
    if not ANTHROPIC_API_KEY:
        return None
    return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Launch Chromium and probe Whitepages/FastPeopleSearch with a small "
            "browser loop controlled by Anthropic."
        )
    )
    parser.add_argument("full_name", help="Full name to probe, e.g. 'Aryaan Verma'")
    parser.add_argument(
        "--steps",
        type=int,
        default=DEFAULT_STEPS,
        help=f"Maximum LLM-driven browser steps per target (default: {DEFAULT_STEPS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"DevTools startup timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--chrome-path",
        default="",
        help="Optional Chrome/Chromium executable path. Defaults to auto-detection.",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Run Chrome with a visible window instead of headless mode.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON instead of pretty JSON.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    name_vars = _name_variants(args.full_name)
    port = _get_free_port()
    chrome_path = args.chrome_path or _find_chrome_binary()
    user_data_dir = tempfile.mkdtemp(prefix="specter-chrome-")

    launch_args = [
        chrome_path,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-popup-blocking",
        "--disable-dev-shm-usage",
        "--disable-renderer-backgrounding",
        "--disable-features=Translate,BackForwardCache,AcceptCHFrame,MediaRouter",
        "--window-size=1440,2200",
        "--hide-scrollbars",
        "about:blank",
    ]
    if not args.no_headless:
        launch_args.insert(1, "--headless=new")

    proc = subprocess.Popen(launch_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    handle = BrowserHandle(proc=proc, user_data_dir=user_data_dir, port=port)

    report: dict[str, Any] = {
        "full_name": args.full_name,
        "chrome_path": chrome_path,
        "headless": not args.no_headless,
        "targets": [],
    }

    session: CDPSession | None = None
    client = _build_client()
    try:
        _wait_for_devtools(port, args.timeout)
        targets = _list_targets(port)
        page_target = next((t for t in targets if t.get("type") == "page"), None)
        if not page_target:
            raise RuntimeError("No page target found after Chrome launch.")
        session = CDPSession(page_target["webSocketDebuggerUrl"])
        session.call("Page.enable")
        session.call("Runtime.enable")
        session.call("DOM.enable")

        for target_name, target in TARGETS.items():
            report["targets"].append(
                _run_target(session, client, target_name, target, name_vars, args.steps)
            )

        report["summary"] = {
            "useful_targets": [
                item["target"]
                for item in report["targets"]
                if item.get("assessment", {}).get("useful_signal")
                or item.get("assessment", {}).get("classification") == "useful"
            ],
            "blocked_targets": [
                item["target"]
                for item in report["targets"]
                if item.get("heuristic", {}).get("blocked")
                or item.get("assessment", {}).get("classification") == "blocked"
            ],
        }
    finally:
        if session is not None:
            session.close()
        handle.close()

    if args.compact:
        print(json.dumps(report, sort_keys=True))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
