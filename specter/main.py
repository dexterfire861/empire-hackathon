from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from specter.agent.orchestrator import Orchestrator
from specter.agent.scan_store import ScanState, ScanStatus, ScanStore
from specter.agent.schemas import ScanRequest

STATIC_DIR = Path(__file__).parent / "static"

logger = logging.getLogger("specter")
logging.basicConfig(level=logging.INFO)

store = ScanStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Specter scanning agent started")
    yield
    logger.info("Specter shutting down")


app = FastAPI(title="Specter", description="Digital Exposure Scanning Agent", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


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
    state = store.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    if state.report:
        return state.report.model_dump(mode="json")

    return {
        "scan_id": state.scan_id,
        "status": state.status.value,
        "findings_count": len(state.findings),
        "findings": [f.model_dump(mode="json") for f in state.findings],
        "audit_trail": state.audit_trail,
    }


@app.get("/scan/{scan_id}/audit-trail")
async def get_audit_trail(scan_id: str):
    state = store.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    return state.audit_trail


@app.get("/scan/{scan_id}/actions")
async def get_actions(scan_id: str):
    state = store.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not state.report:
        return {"status": state.status.value, "actions": []}
    return {
        "actions": state.report.actions,
        "applicable_laws": state.report.applicable_laws,
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
