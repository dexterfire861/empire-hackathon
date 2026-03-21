from __future__ import annotations

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT, GITHUB_TOKEN
from specter.sources.base import BaseSource, register_source


@register_source
class GitHubSearchSource(BaseSource):
    name = "github_search"
    description = "Search GitHub for user profiles, commits, and code containing an email or username. Reveals public repositories, commit history, and potential credential leaks in code."
    input_types = ["email", "username"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_github_search",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Email address to search for on GitHub",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to search for on GitHub",
                    },
                },
            },
        }

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        findings: list[Finding] = []
        headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"

        async with httpx.AsyncClient(timeout=API_TIMEOUT, headers=headers) as client:
            if input_type == "email":
                findings.extend(await self._search_by_email(client, input_value))
            elif input_type == "username":
                findings.extend(await self._search_by_username(client, input_value))

        return findings

    async def _search_by_email(
        self, client: httpx.AsyncClient, email: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        email = email.strip().lower()

        # Search users by email
        resp = await client.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for user in data.get("items", [])[:5]:
                login = user.get("login", "")
                findings.append(
                    Finding(
                        source="github_search",
                        source_url=user.get("html_url", ""),
                        finding_type="account_exists",
                        data={
                            "username": login,
                            "avatar_url": user.get("avatar_url", ""),
                            "profile_url": user.get("html_url", ""),
                            "type": user.get("type", ""),
                        },
                        confidence="high",
                        input_used="email",
                        original_input=email,
                        leads_to=[f"username:{login}"] if login else [],
                        severity="info",
                    )
                )

        # Search commits by author email
        resp = await client.get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email}"},
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])[:5]
            if items:
                repos = list(
                    {item.get("repository", {}).get("full_name", "") for item in items}
                )
                findings.append(
                    Finding(
                        source="github_search",
                        source_url=f"https://github.com/search?q=author-email%3A{email}&type=commits",
                        finding_type="account_exists",
                        data={
                            "commit_count": data.get("total_count", 0),
                            "repositories": repos,
                            "sample_commits": [
                                {
                                    "repo": item.get("repository", {}).get(
                                        "full_name", ""
                                    ),
                                    "message": item.get("commit", {}).get(
                                        "message", ""
                                    )[:200],
                                    "date": item.get("commit", {})
                                    .get("author", {})
                                    .get("date", ""),
                                }
                                for item in items
                            ],
                        },
                        confidence="high",
                        input_used="email",
                        original_input=email,
                        leads_to=[f"url:https://github.com/{r}" for r in repos[:3]],
                        severity="low",
                    )
                )

        # Search code for email (potential credential leaks)
        resp = await client.get(
            "https://api.github.com/search/code",
            params={"q": email},
        )
        if resp.status_code == 200:
            data = resp.json()
            total = data.get("total_count", 0)
            if total > 0:
                items = data.get("items", [])[:5]
                findings.append(
                    Finding(
                        source="github_search",
                        source_url=f"https://github.com/search?q={email}&type=code",
                        finding_type="data_broker_listing",
                        data={
                            "total_code_results": total,
                            "sample_files": [
                                {
                                    "repo": item.get("repository", {}).get(
                                        "full_name", ""
                                    ),
                                    "path": item.get("path", ""),
                                    "url": item.get("html_url", ""),
                                }
                                for item in items
                            ],
                        },
                        confidence="medium",
                        input_used="email",
                        original_input=email,
                        leads_to=[],
                        severity="medium" if total > 5 else "low",
                    )
                )

        return findings

    async def _search_by_username(
        self, client: httpx.AsyncClient, username: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        username = username.strip()

        # Get user profile
        resp = await client.get(f"https://api.github.com/users/{username}")
        if resp.status_code != 200:
            return findings

        user = resp.json()
        leads: list[str] = []
        if user.get("email"):
            leads.append(f"email:{user['email']}")
        if user.get("blog"):
            leads.append(f"url:{user['blog']}")

        findings.append(
            Finding(
                source="github_search",
                source_url=user.get("html_url", ""),
                finding_type="account_exists",
                data={
                    "name": user.get("name", ""),
                    "bio": user.get("bio", ""),
                    "company": user.get("company", ""),
                    "location": user.get("location", ""),
                    "email": user.get("email", ""),
                    "blog": user.get("blog", ""),
                    "public_repos": user.get("public_repos", 0),
                    "followers": user.get("followers", 0),
                    "created_at": user.get("created_at", ""),
                },
                confidence="high",
                input_used="username",
                original_input=username,
                leads_to=leads,
                severity="info",
            )
        )

        # Get repos
        resp = await client.get(
            f"https://api.github.com/users/{username}/repos",
            params={"sort": "updated", "per_page": 10},
        )
        if resp.status_code == 200:
            repos = resp.json()
            repo_data = [
                {
                    "name": r.get("name", ""),
                    "full_name": r.get("full_name", ""),
                    "description": r.get("description", ""),
                    "url": r.get("html_url", ""),
                    "language": r.get("language", ""),
                    "stars": r.get("stargazers_count", 0),
                    "fork": r.get("fork", False),
                }
                for r in repos
            ]
            if repo_data:
                findings.append(
                    Finding(
                        source="github_search",
                        source_url=f"https://github.com/{username}?tab=repositories",
                        finding_type="account_exists",
                        data={"repositories": repo_data},
                        confidence="high",
                        input_used="username",
                        original_input=username,
                        leads_to=[
                            f"url:{r['url']}" for r in repo_data[:3] if r.get("url")
                        ],
                        severity="info",
                    )
                )

        return findings
