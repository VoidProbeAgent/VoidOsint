"""
VoidOsint FastAPI REST & WebSocket Application
===============================================
Main application entry point delivering REST APIs, real-time WebSocket event feeds,
and static dashboard hosting.

Conforms to Section 7 and Work Package 1 requirements.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.database import DatabaseManager
from backend.engines.bing_search import BingSearchRunner
from backend.engines.duckduckgo_search import DuckDuckGoSearchRunner
from backend.engines.github_search import GitHubSearchRunner
from backend.engines.google_search import GoogleSearchRunner
from backend.engines.maigret_runner import MaigretRunner
from backend.engines.spiderfoot_runner import SpiderFootRunner
from backend.models import (
    CaseSummary,
    DiscoveryItem,
    GraphData,
    InvestigationListResponse,
    ScanConfig,
    ScanSummary,
    SystemHealth,
    UpdateCaseNotesRequest,
    UserSettings,
    WSEvent,
)
from backend.orchestrator import ScanOrchestrator
from backend.security import (
    DNSRebindingMiddleware,
    SecurityHeadersMiddleware,
    TargetSanitizer,
    SecurityValidationError,
    DEFAULT_ALLOWED_HOSTS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("void_osint.app")

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "osint_nexus.db"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


# ---------------------------------------------------------------------------
# WebSocket Connection Hub
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Manages active WebSocket subscriptions per scan."""

    def __init__(self) -> None:
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.debug(f"Client connected to scan {scan_id} (active: {len(self.active_connections[scan_id])})")

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        if scan_id in self.active_connections:
            if websocket in self.active_connections[scan_id]:
                self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.debug(f"Client disconnected from scan {scan_id}")

    async def broadcast(self, scan_id: str, event: WSEvent) -> None:
        """Broadcasts event JSON to all clients subscribed to scan_id."""
        subscribers = self.active_connections.get(scan_id, [])
        if not subscribers:
            return

        payload = event.model_dump_json()
        dead_connections: List[WebSocket] = []

        for ws in subscribers:
            try:
                await ws.send_text(payload)
            except Exception:
                dead_connections.append(ws)

        for dead_ws in dead_connections:
            self.disconnect(scan_id, dead_ws)


# ---------------------------------------------------------------------------
# Application Initialization & Lifespan
# ---------------------------------------------------------------------------

db_manager = DatabaseManager(DB_PATH)
ws_manager = ConnectionManager()
orchestrator = ScanOrchestrator(
    db=db_manager,
    broadcast_callback=ws_manager.broadcast,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VoidOsint backend core started.")
    yield
    logger.info("VoidOsint backend shutting down.")


app = FastAPI(
    title="VoidOsint Platform Core",
    description="Unified Multi-Engine OSINT Intelligence Engine & Cockpit",
    version="1.0.0",
    lifespan=lifespan,
)

# Security Hardening: Loopback Isolation, DNS Rebinding Protection, and Defensive Headers
configured_host = os.getenv("VOID_HOST", "127.0.0.1")
configured_port = os.getenv("VOID_PORT", "5002")
allowed_hosts_set = set(DEFAULT_ALLOWED_HOSTS)
allowed_hosts_set.add(configured_host)
allowed_hosts_set.add(f"{configured_host}:{configured_port}")

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(DNSRebindingMiddleware, allowed_hosts=allowed_hosts_set)

# Strict CORS Policy restricted to local loopback interfaces
allowed_origins = [
    f"http://{configured_host}:{configured_port}",
    f"http://{configured_host}",
    "http://127.0.0.10:5002",
    "http://127.0.0.1:5002",
    "http://localhost:5002",
    "http://127.0.0.10",
    "http://127.0.0.1",
    "http://localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^http://(127\.0\.0\.\d+|localhost)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount Static Assets
if not STATIC_DIR.exists():
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Root Dashboard Route
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    """Serves the frontend cockpit index template or a fallback view."""
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        content = index_file.read_text(encoding="utf-8")
        return HTMLResponse(content=content)

    fallback_html = """
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <title>VoidOsint - Unified Intelligence Platform</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-zinc-950 text-zinc-100 min-h-screen flex flex-col items-center justify-center p-6">
        <div class="max-w-xl text-center space-y-4">
            <h1 class="text-4xl font-extrabold tracking-tight text-emerald-400">VoidOsint Engine Ready</h1>
            <p class="text-zinc-400">FastAPI Core and Engine Runners are active on loopback interface.</p>
            <div class="p-4 bg-zinc-900 border border-zinc-800 rounded-lg text-left text-sm font-mono space-y-2">
                <div>API Health: <a href="/api/v1/system/health" class="text-blue-400 hover:underline">/api/v1/system/health</a></div>
                <div>Swagger Docs: <a href="/docs" class="text-blue-400 hover:underline">/docs</a></div>
                <div>Active Scans: <a href="/api/v1/scans" class="text-blue-400 hover:underline">/api/v1/scans</a></div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=fallback_html)


@app.get("/favicon.ico", include_in_schema=False)
async def get_favicon():
    """Serves the brand favicon icon."""
    favicon_path = STATIC_DIR / "favicon.ico"
    if not favicon_path.exists():
        favicon_path = Path("static/favicon.ico")
    if favicon_path.exists():
        return FileResponse(str(favicon_path), media_type="image/x-icon")
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/system/health", response_model=SystemHealth)
async def get_system_health() -> SystemHealth:
    """Probes system environment, database connectivity, and engine availability."""
    engines_status = {
        "maigret": {
            "available": MaigretRunner.is_available(),
            "version": MaigretRunner.get_version(),
            "description": "Username enumeration across 3,000+ platforms",
        },
        "spiderfoot": {
            "available": SpiderFootRunner.is_available(),
            "version": SpiderFootRunner.get_version(),
            "description": "Multi-entity recon (domains, emails, IPs, phone numbers)",
        },
        "google_search": {
            "available": GoogleSearchRunner.is_available(),
            "version": GoogleSearchRunner.get_version(),
            "description": "Targeted search dorking and unlinked footprint scraper",
        },
        "duckduckgo": {
            "available": DuckDuckGoSearchRunner.is_available(),
            "version": DuckDuckGoSearchRunner.get_version(),
            "description": "High-speed web footprint discovery without aggressive CAPTCHA locks",
        },
        "bing": {
            "available": BingSearchRunner.is_available(),
            "version": BingSearchRunner.get_version(),
            "description": "Organic search dorking for corporate profiles, cached docs, and handles",
        },
        "github": {
            "available": GitHubSearchRunner.is_available(),
            "version": GitHubSearchRunner.get_version(),
            "description": "Developer footprint, public email leakage, GPG keys, and repository ownership",
        },
    }

    # Verify database connectivity
    db_ok = False
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.execute("SELECT 1;")
            db_ok = cursor.fetchone()[0] == 1
    except Exception as ex:
        logger.error(f"Database health check failed: {ex}")

    return SystemHealth(
        status="healthy" if db_ok else "degraded",
        host=os.getenv("VOID_HOST", "127.0.0.1"),
        port=int(os.getenv("VOID_PORT", "5002")),
        database_connected=db_ok,
        database_path=str(db_manager.db_path),
        engines=engines_status,
    )


@app.post("/api/v1/scans", response_model=ScanSummary)
async def create_scan(config: ScanConfig) -> ScanSummary:
    """Creates and triggers a new multi-engine OSINT investigation."""
    if not config.target or not config.target.strip():
        raise HTTPException(status_code=400, detail="Target cannot be empty.")

    # Security validation & sanitization per entity type
    try:
        t_type = config.target_type.value if hasattr(config.target_type, "value") else str(config.target_type)
        clean_target = TargetSanitizer.validate_target(config.target, t_type)
        config.target = clean_target
    except SecurityValidationError as e:
        raise HTTPException(status_code=422, detail=f"Target validation error: {e}")

    if not config.engines:
        raise HTTPException(status_code=400, detail="At least one engine must be selected.")

    summary = await orchestrator.start_scan(config)
    return summary


@app.get("/api/v1/scans", response_model=List[ScanSummary])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> List[ScanSummary]:
    """Lists past and active investigations with discovery totals and status."""
    return db_manager.list_scans(limit=limit, offset=offset)


@app.get("/api/v1/scans/{scan_id}", response_model=ScanSummary)
async def get_scan_details(scan_id: str) -> ScanSummary:
    """Retrieves full status and telemetry for an investigation."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return scan


@app.post("/api/v1/scans/{scan_id}/abort")
async def abort_scan(scan_id: str) -> Dict[str, Any]:
    """Gracefully terminates active scan subprocesses."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    success = await orchestrator.abort_scan(scan_id)
    return {"scan_id": scan_id, "status": "aborted", "success": success}


@app.get("/api/v1/investigations", response_model=InvestigationListResponse)
async def list_investigations(
    search: Optional[str] = Query(default=None),
    target_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    date_range: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=25, ge=1, le=100),
) -> InvestigationListResponse:
    """Returns paginated historical investigation cases with aggregated metrics."""
    total, cases = db_manager.get_investigations(
        search=search,
        target_type=target_type,
        status=status,
        date_range=date_range,
        page=page,
        limit=limit,
    )
    return InvestigationListResponse(
        total=total,
        page=page,
        limit=limit,
        cases=cases,
    )


@app.get("/api/v1/investigations/{scan_id}")
async def get_investigation_detail(scan_id: str) -> Dict[str, Any]:
    """Fetches full past investigation bundle (config, discoveries, graph, logs) for one-click reload."""
    detail = db_manager.get_investigation_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Investigation case {scan_id} not found.")
    return detail


@app.delete("/api/v1/investigations/{scan_id}")
async def delete_investigation(scan_id: str) -> Dict[str, Any]:
    """Cascades deletion of an investigation case, discoveries, logs, and graph edges."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Investigation {scan_id} not found.")

    deleted = db_manager.delete_investigation(scan_id)
    return {"scan_id": scan_id, "deleted": deleted}


@app.post("/api/v1/investigations/{scan_id}/resume")
async def resume_investigation(scan_id: str) -> Dict[str, Any]:
    """Reloads an investigation case into the active cockpit state."""
    detail = db_manager.get_investigation_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Investigation case {scan_id} not found.")
    return {
        "scan_id": scan_id,
        "status": "resumed",
        "message": f"Case {scan_id} successfully loaded into active workspace.",
        "data": detail,
    }


@app.patch("/api/v1/investigations/{scan_id}/notes")
async def update_investigation_notes(
    scan_id: str,
    request: UpdateCaseNotesRequest,
) -> Dict[str, Any]:
    """Updates analyst notes and hypotheses for a specific investigation."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Investigation {scan_id} not found.")
    success = db_manager.update_case_notes(scan_id, request.notes)
    return {"scan_id": scan_id, "notes": request.notes, "updated": success}


@app.get("/api/v1/settings", response_model=UserSettings)
async def get_settings() -> UserSettings:
    """Retrieves persistent user preferences."""
    s = db_manager.get_settings()
    return UserSettings(**s)


@app.put("/api/v1/settings", response_model=UserSettings)
async def update_settings(settings: UserSettings) -> UserSettings:
    """Updates user preferences in SQLite persistence."""
    saved = db_manager.update_settings(settings.model_dump())
    return UserSettings(**saved)


@app.post("/api/v1/system/db/purge")
async def purge_database(
    days_old: int = Query(default=7, ge=0),
    vacuum: bool = Query(default=True),
) -> Dict[str, Any]:
    """Performs database maintenance: removes inactive logs and vacuums WAL pages."""
    result = db_manager.purge_database(days_old=days_old, vacuum=vacuum)
    return result


@app.get("/api/v1/scans/{scan_id}/results", response_model=List[DiscoveryItem])
async def get_scan_results(
    scan_id: str,
    min_trust: Optional[float] = Query(default=None, ge=0.0, le=100.0),
    grade: Optional[str] = Query(default=None),
    engine: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> List[DiscoveryItem]:
    """Retrieves filterable tabular discovery findings with trust scores."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    return db_manager.get_discoveries(
        scan_id=scan_id,
        min_trust=min_trust,
        grade=grade,
        engine=engine,
        search=search,
        limit=limit,
        offset=offset,
    )


@app.get("/api/v1/scans/{scan_id}/graph", response_model=GraphData)
async def get_scan_graph(scan_id: str) -> GraphData:
    """Retrieves network nodes and edges for Vis.js / Cytoscape graph visualization."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    return db_manager.get_graph(scan_id)


@app.get("/api/v1/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Retrieves chronological console logs for a scan."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    return db_manager.get_logs(scan_id=scan_id, limit=limit)


@app.get("/api/v1/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
) -> Response:
    """Exports scan discoveries in JSON or CSV format for analytical reporting."""
    scan = db_manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    discoveries = db_manager.get_discoveries(scan_id=scan_id, limit=5000)

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID",
            "Target",
            "TargetType",
            "Engine",
            "Platform",
            "EntityType",
            "URL",
            "Title",
            "HTTPStatus",
            "ValidityScore",
            "AccuracyScore",
            "ConsensusScore",
            "Penalty",
            "CompositeScore",
            "Grade",
            "DiscoveredAt",
        ])

        for d in discoveries:
            tm = d.trust_metrics
            writer.writerow([
                d.id,
                d.target,
                d.target_type,
                d.engine,
                d.platform_name or "",
                d.entity_type,
                d.url or "",
                d.title or "",
                d.http_status or "",
                tm.validity_score if tm else "",
                tm.accuracy_score if tm else "",
                tm.consensus_score if tm else "",
                tm.penalty if tm else "",
                tm.composite_score if tm else "",
                tm.grade.value if tm and hasattr(tm.grade, "value") else (str(tm.grade) if tm else ""),
                d.discovered_at,
            ])

        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="void_osint_{scan_id}.csv"'},
        )

    # JSON export
    export_payload = {
        "scan": scan.model_dump(),
        "total_discoveries": len(discoveries),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "discoveries": [d.model_dump() for d in discoveries],
    }
    return JSONResponse(content=export_payload)


# ---------------------------------------------------------------------------
# WebSocket Real-Time Endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str) -> None:
    """Bi-directional WebSocket streaming live logs, progress updates, and discoveries."""
    await ws_manager.connect(scan_id, websocket)
    try:
        # Send current scan state upon initial connection
        scan = db_manager.get_scan(scan_id)
        if scan:
            await websocket.send_text(
                WSEvent(
                    event="scan_progress",
                    scan_id=scan_id,
                    data={"scan_id": scan_id, "progress": scan.progress, "status": scan.status.value},
                ).model_dump_json()
            )

        # Listen for client heartbeat/messages
        while True:
            client_msg = await websocket.receive_text()
            logger.debug(f"Received WS message from client for scan {scan_id}: {client_msg}")
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
    except Exception as ex:
        logger.debug(f"WebSocket connection error on scan {scan_id}: {ex}")
        ws_manager.disconnect(scan_id, websocket)
