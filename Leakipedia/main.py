from __future__ import annotations

import asyncio
import io
import json
import logging
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from Leakipedia.agent.orchestrator import Orchestrator
from Leakipedia.agent.scan_store import ScanState, ScanStatus, ScanStore
from Leakipedia.agent.schemas import ScanRequest
from Leakipedia.extension_analysis import build_extension_analysis

STATIC_DIR = Path(__file__).parent / "static"
RESULTS_APP_DIR = STATIC_DIR / "results-app"
RESULTS_APP_INDEX = RESULTS_APP_DIR / "index.html"
EXTENSION_DIR = Path(__file__).parent.parent / "browser_extension" / "leak-prevent"

logger = logging.getLogger("Leakipedia")
logging.basicConfig(level=logging.INFO)

store = ScanStore()
rescue_lead_store: dict[str, dict] = {}


class ExtensionAnalyzeRequest(BaseModel):
    url: str
    title: Optional[str] = None
    page_text_excerpt: Optional[str] = None
    form_fields: list[dict] = Field(default_factory=list)
    focused_field: Optional[dict] = None
    trackers_detected: list[str] = Field(default_factory=list)
    script_sources: list[str] = Field(default_factory=list)
    privacy_policy_exists: bool = False
    privacy_policy_url: Optional[str] = None
    dark_patterns_detected: list[str] = Field(default_factory=list)
    gpc_enabled: bool = False
    domain_age_days: Optional[int] = None
    user_state: Optional[str] = "CA"
    install_source: Optional[str] = None
    device_id: Optional[str] = None


class ExtensionRescueLeadRequest(BaseModel):
    saved_at: str
    page: str
    analysis: dict = Field(default_factory=dict)
    source: Optional[str] = "extension"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Leakipedia scanning agent started")
    yield
    logger.info("Leakipedia shutting down")


app = FastAPI(title="Leakipedia", description="Digital Exposure Scanning Agent", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/results")
async def results():
    if RESULTS_APP_INDEX.exists():
        return FileResponse(RESULTS_APP_INDEX)
    return FileResponse(STATIC_DIR / "results.html")


@app.get("/extension/install")
async def extension_install():
    return HTMLResponse(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Install Leak Prevent</title>
          <style>
            body {
              font-family: "Inter", ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
              margin: 0;
              color: #111827;
              background:
                radial-gradient(circle at top right, rgba(89, 169, 255, 0.16), transparent 28%),
                linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
            }
            main { max-width: 760px; margin: 0 auto; padding: 40px 24px; }
            .card {
              background: rgba(255,255,255,0.94);
              border: 1px solid #e5e7eb;
              border-radius: 18px;
              padding: 24px;
              margin-bottom: 18px;
              box-shadow: 0 18px 44px rgba(15, 23, 42, 0.08);
            }
            h1 { margin: 0 0 14px; }
            p, li { color: #475467; line-height: 1.6; }
            a { color: #3b82f6; font-weight: 600; }
            ol { margin: 0; padding-left: 28px; }
            li { margin-bottom: 10px; }
            code {
              background: #f3f4f6;
              border: 1px solid #e5e7eb;
              border-radius: 8px;
              padding: 2px 6px;
              color: #111827;
            }
          </style>
        </head>
        <body>
          <main>
            <div class="card">
              <h1>Install Leak Prevent</h1>
              <p>Chrome does not allow a website to silently enable an extension, so the activation flow is one guided step: download the bundle, open Chrome extensions, and load it once.</p>
            </div>
            <div class="card">
              <ol>
                <li>Download the extension package from <a href="/extension/package">/extension/package</a>.</li>
                <li>Unzip it to a folder on your machine.</li>
                <li>Open <code>chrome://extensions</code> and turn on Developer Mode.</li>
                <li>Click Load unpacked and select the unzipped <code>leak-prevent</code> folder.</li>
                <li>Return to Leakipedia and use the new top-right install button any time you need the extension again.</li>
              </ol>
            </div>
          </main>
        </body>
        </html>
        """
    )


@app.get("/extension/package")
async def extension_package():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, mode="w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in EXTENSION_DIR.rglob("*"):
            if path.is_file():
                bundle.write(path, arcname=path.relative_to(EXTENSION_DIR.parent))
    memory_file.seek(0)
    headers = {"Content-Disposition": 'attachment; filename="leak-prevent.zip"'}
    return StreamingResponse(memory_file, media_type="application/zip", headers=headers)


@app.post("/extension/analyze")
async def analyze_extension_page(request: ExtensionAnalyzeRequest):
    return await build_extension_analysis(request.model_dump())


@app.post("/extension/rescue-lead")
async def save_extension_rescue_lead(request: ExtensionRescueLeadRequest):
    lead_id = uuid4().hex
    payload = request.model_dump()
    payload["lead_id"] = lead_id
    rescue_lead_store[lead_id] = payload
    return {"ok": True, "lead_id": lead_id, "rescue_url": f"/rescue/{lead_id}"}


@app.get("/rescue/{lead_id}")
async def rescue_view(lead_id: str):
    lead = rescue_lead_store.get(lead_id)
    if not lead:
        raise HTTPException(status_code=404, detail="Rescue lead not found")

    analysis = lead.get("analysis", {})
    signals = analysis.get("signals", [])
    steps = analysis.get("steps", [])
    risk_score = analysis.get("riskScore", 0)
    risk_label = analysis.get("riskLabel", "Unknown")
    domain = analysis.get("domain", "Unknown domain")
    legal_note = analysis.get("legalNote", "")

    signal_items = "".join(f"<li>{item}</li>" for item in signals) or "<li>No signals recorded.</li>"
    step_items = "".join(f"<li>{item}</li>" for item in steps) or "<li>No next steps recorded.</li>"
    raw_json = json.dumps(lead, indent=2)

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Leak Rescue</title>
          <style>
            body {{ margin: 0; font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #08111d; color: #eef5ff; }}
            main {{ max-width: 860px; margin: 0 auto; padding: 32px 20px 48px; }}
            .card {{ background: rgba(15,29,49,0.92); border: 1px solid rgba(165,197,234,0.14); border-radius: 18px; padding: 22px; margin-bottom: 16px; }}
            .pill {{ display:inline-flex; padding:6px 10px; border-radius:999px; background:rgba(129,242,200,0.1); color:#81f2c8; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; }}
            .score {{ font-size: 40px; font-weight: 800; color: #81f2c8; }}
            h1 {{ margin: 12px 0 8px; }}
            p, li {{ line-height: 1.6; color: #d8e5f5; }}
            .muted {{ color: #98adc5; }}
            pre {{ background:#0d0d18; padding:12px; border-radius:12px; overflow:auto; color:#a8b8c9; }}
          </style>
        </head>
        <body>
          <main>
            <div class="card">
              <div class="pill">Leak Rescue</div>
              <h1>{domain}</h1>
              <p class="muted">Saved from the extension at {lead.get("saved_at", "unknown time")}.</p>
              <div class="score">{risk_score}</div>
              <p>{risk_label} risk for this site.</p>
              <p class="muted">{legal_note}</p>
            </div>
            <div class="card">
              <h2>Why Leak Prevent flagged it</h2>
              <ul>{signal_items}</ul>
            </div>
            <div class="card">
              <h2>Suggested next steps</h2>
              <ol>{step_items}</ol>
            </div>
            <div class="card">
              <h2>Raw saved lead</h2>
              <pre>{raw_json}</pre>
            </div>
          </main>
        </body>
        </html>
        """
    )


async def run_scan(scan_state: ScanState) -> None:
    """Background task that runs the full scan orchestration."""
    try:
        orchestrator = Orchestrator(scan_state, store)
        await orchestrator.run()
    except Exception:
        logger.exception("Scan %s failed", scan_state.scan_id)
        await store.update_status(scan_state.scan_id, ScanStatus.FAILED)
        await scan_state.event_bus.publish(
            {"type": "error", "message": "Scan failed unexpectedly"}
        )


# ── Endpoints ───────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan")
async def start_scan(request: ScanRequest):
    scan_state = await store.create(request)
    await scan_state.event_bus.publish(
        {"type": "scan_started", "scan_id": scan_state.scan_id}
    )
    asyncio.create_task(run_scan(scan_state))
    return {"scan_id": scan_state.scan_id, "status": "started"}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    state = store.get_or_load(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    if state.report:
        return state.report.model_dump(mode="json")

    return {
        "scan_id": state.scan_id,
        "status": state.status.value,
        "findings_count": len(state.findings),
        "inputs": state.request.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in state.findings],
        "audit_trail": state.audit_trail,
    }


@app.get("/scan/{scan_id}/audit-trail")
async def get_audit_trail(scan_id: str):
    state = store.get_or_load(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return state.audit_trail


@app.get("/scan/{scan_id}/actions")
async def get_actions(scan_id: str):
    state = store.get_or_load(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not state.report:
        return {"status": state.status.value, "actions": []}
    return {
        "actions": state.report.actions,
        "applicable_laws": state.report.applicable_laws,
        "privacy_resources": state.report.privacy_resources,
        "decision_summary": state.report.decision_summary,
        "safety_boundaries": state.report.safety_boundaries,
    }


@app.websocket("/scan/{scan_id}/stream")
async def stream_scan(websocket: WebSocket, scan_id: str):
    state = store.get(scan_id)
    if not state:
        await websocket.close(code=4004, reason="Scan not found")
        return

    await websocket.accept()
    queue = state.event_bus.subscribe()

    try:
        # Send current state first
        await websocket.send_json(
            {
                "type": "status",
                "status": state.status.value,
                "findings_count": len(state.findings),
                "inputs": state.request.model_dump(mode="json"),
            }
        )

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send keepalive ping
                await websocket.send_json({"type": "ping"})
                continue

            await websocket.send_json(event)

            if event.get("type") in ("scan_complete", "error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        state.event_bus.unsubscribe(queue)
