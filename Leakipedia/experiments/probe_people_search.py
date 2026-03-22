from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any
from urllib.parse import quote_plus

import httpx


DEFAULT_TIMEOUT = 15.0
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
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
]

NO_RESULT_MARKERS = [
    "no results found",
    "no records found",
    "we didn't find",
    "0 results",
    "no matches",
    "person not found",
]

TARGETS = {
    "whitepages_search": {
        "kind": "search",
        "url_template": "https://www.whitepages.com/name/{hyphenated}",
        "result_markers": [
            "current address",
            "phone number",
            "relatives",
            "associated persons",
            "background report",
            "address history",
        ],
    },
    "whitepages_opt_out": {
        "kind": "removal",
        "url_template": "https://www.whitepages.com/suppression_requests",
        "result_markers": [
            "suppression request",
            "remove my info",
            "opt out",
            "privacy request",
        ],
    },
    "fastpeoplesearch_search": {
        "kind": "search",
        "url_template": "https://www.fastpeoplesearch.com/name/{hyphenated}",
        "result_markers": [
            "age",
            "lives in",
            "related to",
            "possible previous address",
            "phone",
            "current home address",
        ],
    },
    "fastpeoplesearch_opt_out": {
        "kind": "removal",
        "url_template": "https://www.fastpeoplesearch.com/removal",
        "result_markers": [
            "remove my record",
            "opt out",
            "privacy",
            "suppression",
        ],
    },
}


def _name_variants(full_name: str) -> dict[str, str]:
    cleaned = " ".join(full_name.strip().split())
    parts = cleaned.split()
    return {
        "raw": cleaned,
        "hyphenated": "-".join(parts),
        "query": quote_plus(cleaned),
    }


def _match_markers(text: str, markers: list[str]) -> list[str]:
    return [marker for marker in markers if marker in text]


def _classify_response(
    status_code: int,
    matched_blocks: list[str],
    matched_no_results: list[str],
    matched_results: list[str],
) -> str:
    if matched_blocks:
        return "block_page"
    if status_code == 404 or matched_no_results:
        return "no_results"
    if status_code == 200 and matched_results:
        return "possible_results"
    if status_code in (301, 302, 307, 308):
        return "redirect"
    if status_code in (401, 403):
        return "blocked"
    return "unknown"


async def _probe_target(
    client: httpx.AsyncClient,
    label: str,
    config: dict[str, Any],
    name_vars: dict[str, str],
) -> dict[str, Any]:
    url = config["url_template"].format(**name_vars)

    try:
        response = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {
            "target": label,
            "kind": config["kind"],
            "url": url,
            "error": str(exc),
            "classification": "request_error",
            "useful_signal": False,
        }

    text = response.text.lower()
    matched_blocks = _match_markers(text, BLOCK_MARKERS)
    matched_no_results = _match_markers(text, NO_RESULT_MARKERS)
    matched_results = _match_markers(text, config["result_markers"])
    classification = _classify_response(
        response.status_code,
        matched_blocks,
        matched_no_results,
        matched_results,
    )

    headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() in {"server", "content-type", "cf-ray", "location"}
    }

    return {
        "target": label,
        "kind": config["kind"],
        "url": url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "classification": classification,
        "useful_signal": bool(matched_results) and not matched_blocks,
        "matched_result_markers": matched_results,
        "matched_block_markers": matched_blocks,
        "matched_no_result_markers": matched_no_results,
        "headers": headers,
        "body_preview": response.text[:500],
    }


async def run_probe(full_name: str, timeout: float) -> dict[str, Any]:
    name_vars = _name_variants(full_name)
    async with httpx.AsyncClient(timeout=timeout, headers=DEFAULT_HEADERS) as client:
        results = await asyncio.gather(
            *[
                _probe_target(client, label, config, name_vars)
                for label, config in TARGETS.items()
            ]
        )

    return {
        "full_name": full_name,
        "targets": results,
        "summary": {
            "possible_results": [
                item["target"]
                for item in results
                if item.get("classification") == "possible_results"
            ],
            "blocked": [
                item["target"]
                for item in results
                if item.get("classification") in {"block_page", "blocked"}
            ],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only probe for Whitepages and FastPeopleSearch. "
            "This measures whether pages return useful HTML or mostly challenge/block pages."
        )
    )
    parser.add_argument("full_name", help="Full name to probe, e.g. 'Aryaan Verma'")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON instead of pretty JSON",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = asyncio.run(run_probe(args.full_name, args.timeout))
    if args.compact:
        print(json.dumps(report, sort_keys=True))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
