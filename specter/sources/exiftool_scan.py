from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import httpx

from specter.agent.schemas import Finding
from specter.config import API_TIMEOUT, SUBPROCESS_TIMEOUT
from specter.sources.base import BaseSource, register_source

MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


@register_source
class ExifToolScanSource(BaseSource):
    name = "exiftool"
    description = "Download a document or image from a URL and extract metadata using ExifTool. Reveals author name, GPS coordinates, creation date, software used, and camera model. GPS data is flagged as critical."
    input_types = ["url"]

    @classmethod
    def tool_definition(cls) -> dict:
        return {
            "name": "scan_exiftool",
            "description": cls.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of a document or image to analyze for metadata",
                    }
                },
                "required": ["url"],
            },
        }

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("exiftool") is not None

    async def scan(self, input_type: str, input_value: str) -> list[Finding]:
        url = input_value.strip()

        tmpdir = tempfile.mkdtemp(prefix="specter_exiftool_")

        try:
            # Download the file
            file_path = await self._download_file(url, tmpdir)
            if not file_path:
                return []

            # Run exiftool
            stdout, stderr = await self.run_cli(
                ["exiftool", "-json", str(file_path)],
                timeout=SUBPROCESS_TIMEOUT,
            )

            return self._parse_output(stdout, url)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    async def _download_file(self, url: str, tmpdir: str) -> Optional[Path]:
        """Download a file with size limit."""
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT, follow_redirects=True) as client:
                # Check content-length first
                head_resp = await client.head(url)
                content_length = int(head_resp.headers.get("content-length", 0))
                if content_length > MAX_DOWNLOAD_SIZE:
                    return None

                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                if len(resp.content) > MAX_DOWNLOAD_SIZE:
                    return None

                # Determine filename from URL or content-type
                filename = url.split("/")[-1].split("?")[0] or "downloaded_file"
                file_path = Path(tmpdir) / filename
                file_path.write_bytes(resp.content)
                return file_path

        except Exception:
            return None

    def _parse_output(self, stdout: str, url: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            metadata_list = json.loads(stdout)
        except json.JSONDecodeError:
            return findings

        if not metadata_list:
            return findings

        metadata = metadata_list[0]

        # Extract interesting fields
        author = metadata.get("Author", metadata.get("Creator", ""))
        create_date = metadata.get("CreateDate", metadata.get("DateTimeOriginal", ""))
        software = metadata.get("Software", metadata.get("Producer", ""))
        camera_model = metadata.get("Model", metadata.get("CameraModelName", ""))
        gps_lat = metadata.get("GPSLatitude", "")
        gps_lon = metadata.get("GPSLongitude", "")
        gps_position = metadata.get("GPSPosition", "")

        has_gps = bool(gps_lat or gps_lon or gps_position)
        has_author = bool(author)

        if not has_gps and not has_author and not create_date:
            # No interesting metadata
            severity = "info"
        elif has_gps:
            severity = "critical"
        elif has_author:
            severity = "medium"
        else:
            severity = "low"

        leads: list[str] = []
        if has_author and isinstance(author, str):
            leads.append(f"name:{author}")

        interesting_fields = {
            k: v
            for k, v in metadata.items()
            if k
            in (
                "Author",
                "Creator",
                "CreateDate",
                "DateTimeOriginal",
                "Software",
                "Producer",
                "Model",
                "CameraModelName",
                "GPSLatitude",
                "GPSLongitude",
                "GPSPosition",
                "GPSAltitude",
                "ImageDescription",
                "UserComment",
                "Copyright",
                "Artist",
                "OwnerName",
                "SerialNumber",
                "LensModel",
                "Title",
                "Subject",
                "Keywords",
            )
            and v
        }

        if interesting_fields:
            findings.append(
                Finding(
                    source="exiftool",
                    source_url=url,
                    finding_type="document",
                    data={
                        "metadata": interesting_fields,
                        "has_gps": has_gps,
                        "has_author": has_author,
                        "file_type": metadata.get("FileType", ""),
                        "mime_type": metadata.get("MIMEType", ""),
                    },
                    confidence="high",
                    input_used="url",
                    original_input=url,
                    leads_to=leads,
                    severity=severity,
                )
            )

        return findings
