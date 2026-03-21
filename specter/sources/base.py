from __future__ import annotations

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod

from specter.agent.schemas import Finding

logger = logging.getLogger("specter.sources")

SOURCE_REGISTRY: dict[str, type[BaseSource]] = {}


def register_source(cls: type[BaseSource]) -> type[BaseSource]:
    """Decorator that registers a source class in the global registry."""
    SOURCE_REGISTRY[cls.name] = cls
    return cls


class BaseSource(ABC):
    name: str = ""
    description: str = ""
    input_types: list[str] = []  # ["email", "username", "phone", "domain", "url"]

    @classmethod
    @abstractmethod
    def tool_definition(cls) -> dict:
        """Return Anthropic-format tool definition dict."""
        ...

    @abstractmethod
    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        """Run the scan and return standardized findings."""
        ...

    @classmethod
    def is_available(cls) -> bool:
        """Check if this source can run (e.g., CLI tool installed, API key set)."""
        return True

    # ── CLI helper ──────────────────────────────────────────────────────

    @staticmethod
    async def run_cli(
        args: list[str], timeout: int = 120
    ) -> tuple[str, str]:
        """
        Run a CLI command asynchronously.
        Returns (stdout, stderr). Raises on missing binary or timeout.
        """
        binary = shutil.which(args[0])
        if not binary:
            raise FileNotFoundError(f"{args[0]} is not installed")

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"{args[0]} timed out after {timeout}s")

        return stdout.decode(errors="replace"), stderr.decode(errors="replace")
