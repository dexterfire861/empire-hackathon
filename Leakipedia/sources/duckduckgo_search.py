from __future__ import annotations

import asyncio
from urllib.parse import quote_plus

import httpx

from Leakipedia.agent.schemas import Finding
from Leakipedia.config import API_TIMEOUT
from Leakipedia.sources.base import BaseSource, register_source


@register_source
class DuckDuckGoSearchSource(BaseSource):
    name = "duckduckgo"
    description = (
        "Search DuckDuckGo for web pages containing an email, name, phone number, or username. "
        "Free alternative to Google CSE with no API key needed. Finds data broker listings, "
        "documents, social profiles, and other web mentions. Use specific queries like "
        '"email@example.com", "Full Name" site:whitepages.com, "Full Name" filetype:pdf, etc.'
    )
    input_types = ["email", "name", "phone", "username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_duckduckgo",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": 'Search query. Use quotes for exact match, e.g. "john.doe@gmail.com" or "John Doe" site:whitepages.com',
                    },
                    "query_type": {
                        "type": "string",
                        "description": "What you're searching for: email, name, phone, username, document, data_broker",
                        "enum": ["email", "name", "phone", "username", "document", "data_broker"],
                    },
                },
                "required": ["query", "query_type"],
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        query = input_value.strip()
        query_type = input_type

        # DuckDuckGo HTML search (the lite/html version is more bot-friendly)
        results = await self._search_ddg(query)

        if not results:
            return []

        findings: list[Finding] = []
        for result in results:
            title = result.get("title", "")
            url = result.get("url", "")
            snippet = result.get("snippet", "")

            if not url:
                continue

            # Classify the finding
            finding_type, severity = self._classify_result(url, title, snippet, query_type)

            # Determine confidence
            query_clean = query.strip('"').lower()
            content_lower = (title + " " + snippet).lower()
            if query_clean in content_lower:
                confidence = "high"
            else:
                confidence = "medium"

            leads: list[str] = []
            # If it's a PDF or document, flag for exiftool
            if any(ext in url.lower() for ext in [".pdf", ".doc", ".xlsx", ".xls"]):
                leads.append(f"url:{url}")
            # If it's a profile page, try to extract username
            if any(site in url for site in ["linkedin.com/in/", "twitter.com/", "instagram.com/", "facebook.com/"]):
                parts = url.rstrip("/").split("/")
                if parts:
                    leads.append(f"username:{parts[-1]}")

            findings.append(
                Finding(
                    source="duckduckgo",
                    source_url=url,
                    finding_type=finding_type,
                    data={
                        "title": title,
                        "snippet": snippet,
                        "url": url,
                        "search_query": query,
                    },
                    confidence=confidence,
                    input_used=query_type,
                    original_input=query,
                    leads_to=leads,
                    severity=severity,
                )
            )

        return findings

    async def _search_ddg(self, query: str) -> list[dict]:
        """Search DuckDuckGo and parse results."""
        results: list[dict] = []

        # Method 1: DuckDuckGo HTML lite (most reliable for scraping)
        try:
            encoded = quote_plus(query)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"

            async with httpx.AsyncClient(
                timeout=API_TIMEOUT + 5,
                follow_redirects=True,
            ) as client:
                resp = await client.get(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    },
                )

            if resp.status_code == 200:
                results = self._parse_html_results(resp.text)
        except (httpx.HTTPError, httpx.TimeoutException):
            pass

        # Method 2: DuckDuckGo API (instant answers — less comprehensive but structured)
        if not results:
            try:
                api_url = f"https://api.duckduckgo.com/?q={quote_plus(query)}&format=json&no_html=1"
                async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
                    resp = await client.get(api_url)

                if resp.status_code == 200:
                    data = resp.json()
                    # Extract related topics
                    for topic in data.get("RelatedTopics", [])[:10]:
                        if isinstance(topic, dict) and topic.get("FirstURL"):
                            results.append({
                                "title": topic.get("Text", "")[:100],
                                "url": topic["FirstURL"],
                                "snippet": topic.get("Text", ""),
                            })
            except (httpx.HTTPError, httpx.TimeoutException):
                pass

        return results[:15]

    def _parse_html_results(self, html: str) -> list[dict]:
        """Parse DuckDuckGo HTML lite results without BeautifulSoup."""
        results: list[dict] = []
        # Find result blocks — each result link has class="result__a"
        import re

        # Extract result links and snippets
        # Pattern: <a rel="nofollow" class="result__a" href="...">title</a>
        link_pattern = re.compile(
            r'class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            re.DOTALL,
        )
        snippet_pattern = re.compile(
            r'class="result__snippet"[^>]*>(.*?)</(?:a|td|div|span)',
            re.DOTALL,
        )

        links = link_pattern.findall(html)
        snippets = snippet_pattern.findall(html)

        for i, (href, title) in enumerate(links[:15]):
            # DuckDuckGo redirects through their own URL, extract actual URL
            actual_url = href
            if "uddg=" in href:
                import urllib.parse
                parsed = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                if "uddg" in parsed:
                    actual_url = urllib.parse.unquote(parsed["uddg"][0])

            # Clean HTML tags from title and snippet
            clean_title = re.sub(r"<[^>]+>", "", title).strip()
            clean_snippet = ""
            if i < len(snippets):
                clean_snippet = re.sub(r"<[^>]+>", "", snippets[i]).strip()

            if actual_url and not actual_url.startswith("//duckduckgo.com"):
                results.append({
                    "title": clean_title,
                    "url": actual_url,
                    "snippet": clean_snippet,
                })

        return results

    @staticmethod
    def _classify_result(url: str, title: str, snippet: str, query_type: str) -> tuple[str, str]:
        """Classify a search result by type and severity."""
        url_lower = url.lower()
        text_lower = (title + " " + snippet).lower()

        # Data broker sites
        broker_domains = [
            "whitepages.com", "spokeo.com", "beenverified.com", "fastpeoplesearch.com",
            "truepeoplesearch.com", "radaris.com", "intelius.com", "thatsthem.com",
            "peoplefinder.com", "mylife.com", "zabasearch.com", "pipl.com",
            "instantcheckmate.com", "ussearch.com", "peekyou.com", "addresses.com",
        ]
        if any(d in url_lower for d in broker_domains):
            return ("data_broker_listing", "high")

        # Documents
        if any(ext in url_lower for ext in [".pdf", ".doc", ".docx", ".xlsx", ".xls", ".csv"]):
            return ("document", "medium")

        # Paste sites
        paste_domains = ["pastebin.com", "ghostbin.com", "rentry.co", "paste.ee", "dpaste.com"]
        if any(d in url_lower for d in paste_domains):
            return ("leaked_credential", "critical")

        # Social media
        social_domains = [
            "linkedin.com", "facebook.com", "twitter.com", "instagram.com",
            "tiktok.com", "reddit.com", "github.com", "youtube.com",
        ]
        if any(d in url_lower for d in social_domains):
            return ("account_exists", "low")

        # Court/legal records
        if any(kw in text_lower for kw in ["court record", "arrest", "criminal", "case number"]):
            return ("document", "high")

        return ("data_broker_listing", "low")
