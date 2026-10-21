"""
VoidOsint Scan Orchestrator
===========================
Coordinates concurrent engine runs, dispatches trust engine evaluations,
persists discoveries in SQLite WAL database, and publishes real-time WebSocket events.

Conforms to Section 3 and Work Package 1 requirements.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from backend.database import DatabaseManager
from backend.engines.bing_search import BingSearchRunner
from backend.engines.duckduckgo_search import DuckDuckGoSearchRunner
from backend.engines.github_search import GitHubSearchRunner
from backend.engines.google_search import GoogleSearchRunner
from backend.engines.maigret_runner import MaigretRunner
from backend.engines.spiderfoot_runner import SpiderFootRunner
from backend.models import (
    DiscoveryItem,
    ScanConfig,
    ScanStatus,
    ScanSummary,
    WSEvent,
    WSEventType,
)
from backend.trust_engine import evaluate_discovery

logger = logging.getLogger("void_osint.orchestrator")


class ScanOrchestrator:
    """Manages active multi-engine scan lifecycles and real-time event broadcasting."""

    def __init__(
        self,
        db: DatabaseManager,
        broadcast_callback: Optional[Callable[[str, WSEvent], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        self.db = db
        self.broadcast_callback = broadcast_callback
        self._active_tasks: Dict[str, asyncio.Task] = {}
        self._active_runners: Dict[str, List[Any]] = {}

    def set_broadcaster(
        self,
        callback: Callable[[str, WSEvent], Coroutine[Any, Any, None]],
    ) -> None:
        """Sets the WebSocket broadcast callback."""
        self.broadcast_callback = callback

    async def broadcast_event(self, scan_id: str, event_type: WSEventType, data: Dict[str, Any]) -> None:
        """Helper to fan-out events to connected WebSocket clients."""
        if not self.broadcast_callback:
            return
        event = WSEvent(
            event=event_type,
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
        )
        try:
            await self.broadcast_callback(scan_id, event)
        except Exception as ex:
            logger.debug(f"WebSocket broadcast error for scan {scan_id}: {ex}")

    async def start_scan(self, config: ScanConfig) -> ScanSummary:
        """Registers a new scan and dispatches concurrent worker tasks."""
        # Save scan to database
        scan_summary = self.db.create_scan(config)

        # Notify clients that scan has been created
        await self.broadcast_event(
            config.scan_id,
            WSEventType.SCAN_STARTED,
            {
                "scan_id": config.scan_id,
                "target": config.target,
                "target_type": config.target_type.value if hasattr(config.target_type, "value") else str(config.target_type),
                "engines": config.engines,
                "depth": config.depth.value if hasattr(config.depth, "value") else str(config.depth),
            },
        )

        # Launch background task
        task = asyncio.create_task(self._run_scan_pipeline(config))
        self._active_tasks[config.scan_id] = task

        def _cleanup(t: asyncio.Task) -> None:
            self._active_tasks.pop(config.scan_id, None)
            self._active_runners.pop(config.scan_id, None)

        task.add_done_callback(_cleanup)
        return scan_summary

    async def abort_scan(self, scan_id: str) -> bool:
        """Gracefully terminates running subprocesses and marks scan as aborted."""
        runners = self._active_runners.get(scan_id, [])
        for runner in runners:
            try:
                if hasattr(runner, "abort"):
                    await runner.abort()
            except Exception as ex:
                logger.warning(f"Error aborting runner for scan {scan_id}: {ex}")

        task = self._active_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()

        now_iso = datetime.now(timezone.utc).isoformat()
        self.db.update_scan_status(
            scan_id=scan_id,
            status=ScanStatus.ABORTED,
            completed_at=now_iso,
        )

        await self.broadcast_event(
            scan_id,
            WSEventType.SCAN_ABORTED,
            {"scan_id": scan_id, "message": "Scan aborted by user request"},
        )
        return True

    async def _run_scan_pipeline(self, config: ScanConfig) -> None:
        """Main asynchronous scan execution pipeline."""
        scan_id = config.scan_id
        now_iso = datetime.now(timezone.utc).isoformat()

        self.db.update_scan_status(
            scan_id=scan_id,
            status=ScanStatus.RUNNING,
            progress=5,
            started_at=now_iso,
        )

        runners: List[Any] = []
        self._active_runners[scan_id] = runners

        # Track engines and discoveries for consensus calculations
        active_engines: List[str] = list(config.engines)
        engine_discovery_urls: Dict[str, Set[str]] = {eng: set() for eng in active_engines}
        discovery_cache: Dict[str, DiscoveryItem] = {}

        # Callbacks
        async def handle_log(engine_name: str, message: str, level: str = "INFO") -> None:
            self.db.insert_log(scan_id=scan_id, engine=engine_name, message=message, level=level)
            await self.broadcast_event(
                scan_id,
                WSEventType.ENGINE_LOG,
                {"engine": engine_name, "message": message, "level": level},
            )

        async def handle_discovery(discovery: DiscoveryItem) -> None:
            engine = discovery.engine
            if discovery.url:
                engine_discovery_urls[engine].add(discovery.url)

            # Determine which engines confirm this URL or target
            confirming = [
                eng for eng, urls in engine_discovery_urls.items()
                if (discovery.url and discovery.url in urls) or eng == engine
            ]

            # Evaluate with Multi-Factor Trust Scoring Engine
            if config.enable_trust_scoring:
                t_type = config.target_type.value if hasattr(config.target_type, "value") else str(config.target_type)
                metrics = await evaluate_discovery(
                    target=config.target,
                    query_type=t_type,
                    url=discovery.url or "",
                    title=discovery.title or "",
                    body_text=discovery.snippet or "",
                    status_code=discovery.http_status or 200,
                    active_engines=active_engines,
                    confirming_engines=confirming,
                )
                discovery.trust_metrics = metrics

            # Persist to SQLite WAL database
            self.db.insert_discovery(discovery)
            discovery_cache[discovery.id] = discovery

            # Broadcast real-time discovery event
            await self.broadcast_event(
                scan_id,
                WSEventType.DISCOVERY_FOUND,
                discovery.model_dump(),
            )

        # Build runner tasks
        worker_coroutines = []

        if "maigret" in config.engines:
            maigret = MaigretRunner()
            runners.append(maigret)
            self.db.update_engine_status(scan_id, "maigret", "running")

            async def _run_maigret() -> None:
                try:
                    await maigret.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log("maigret", msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, "maigret", "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, "maigret", "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, "maigret", "failed")
                    await handle_log("maigret", f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_maigret())

        if "spiderfoot" in config.engines:
            sf = SpiderFootRunner()
            runners.append(sf)
            self.db.update_engine_status(scan_id, "spiderfoot", "running")

            async def _run_spiderfoot() -> None:
                try:
                    await sf.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log("spiderfoot", msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, "spiderfoot", "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, "spiderfoot", "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, "spiderfoot", "failed")
                    await handle_log("spiderfoot", f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_spiderfoot())

        if "google_search" in config.engines:
            gsearch = GoogleSearchRunner()
            runners.append(gsearch)
            self.db.update_engine_status(scan_id, "google_search", "running")

            async def _run_gsearch() -> None:
                try:
                    await gsearch.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log("google_search", msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, "google_search", "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, "google_search", "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, "google_search", "failed")
                    await handle_log("google_search", f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_gsearch())

        if "duckduckgo" in config.engines or "duckduckgo_search" in config.engines:
            ddg_key = "duckduckgo" if "duckduckgo" in config.engines else "duckduckgo_search"
            ddg = DuckDuckGoSearchRunner()
            runners.append(ddg)
            self.db.update_engine_status(scan_id, ddg_key, "running")

            async def _run_ddg() -> None:
                try:
                    await ddg.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log(ddg_key, msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, ddg_key, "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, ddg_key, "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, ddg_key, "failed")
                    await handle_log(ddg_key, f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_ddg())

        if "bing" in config.engines or "bing_search" in config.engines:
            bing_key = "bing" if "bing" in config.engines else "bing_search"
            bing = BingSearchRunner()
            runners.append(bing)
            self.db.update_engine_status(scan_id, bing_key, "running")

            async def _run_bing() -> None:
                try:
                    await bing.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log(bing_key, msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, bing_key, "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, bing_key, "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, bing_key, "failed")
                    await handle_log(bing_key, f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_bing())

        if "github" in config.engines or "github_search" in config.engines:
            gh_key = "github" if "github" in config.engines else "github_search"
            gh = GitHubSearchRunner()
            runners.append(gh)
            self.db.update_engine_status(scan_id, gh_key, "running")

            async def _run_gh() -> None:
                try:
                    await gh.run(
                        config=config,
                        on_log=lambda msg, lvl="INFO": handle_log(gh_key, msg, lvl),
                        on_discovery=handle_discovery,
                    )
                    self.db.update_engine_status(scan_id, gh_key, "completed")
                except asyncio.CancelledError:
                    self.db.update_engine_status(scan_id, gh_key, "aborted")
                    raise
                except Exception as ex:
                    self.db.update_engine_status(scan_id, gh_key, "failed")
                    await handle_log(gh_key, f"Runner failed: {ex}", "ERROR")

            worker_coroutines.append(_run_gh())

        # Progress monitor task
        async def _progress_ticker() -> None:
            pct = 10
            while pct < 90:
                await asyncio.sleep(2.0)
                pct += 5
                self.db.update_scan_status(scan_id=scan_id, progress=pct)
                await self.broadcast_event(
                    scan_id,
                    WSEventType.SCAN_PROGRESS,
                    {"scan_id": scan_id, "progress": pct},
                )

        ticker_task = asyncio.create_task(_progress_ticker())

        try:
            # Execute all engines concurrently
            if worker_coroutines:
                await asyncio.gather(*worker_coroutines, return_exceptions=True)

            ticker_task.cancel()

            # Finalize scan status
            comp_iso = datetime.now(timezone.utc).isoformat()
            self.db.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED,
                progress=100,
                completed_at=comp_iso,
            )

            total_disc = self.db.get_discovery_count(scan_id)
            conf_disc = self.db.get_discovery_count(scan_id, grade="CONFIRMED")

            await self.broadcast_event(
                scan_id,
                WSEventType.SCAN_COMPLETED,
                {
                    "scan_id": scan_id,
                    "status": "completed",
                    "progress": 100,
                    "total_discoveries": total_disc,
                    "confirmed_count": conf_disc,
                    "completed_at": comp_iso,
                },
            )

        except asyncio.CancelledError:
            ticker_task.cancel()
            logger.info(f"Scan pipeline cancelled for {scan_id}")
            raise
        except Exception as ex:
            ticker_task.cancel()
            logger.exception(f"Unhandled error in scan pipeline for {scan_id}")
            fail_iso = datetime.now(timezone.utc).isoformat()
            self.db.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                completed_at=fail_iso,
                error_message=str(ex),
            )
            await self.broadcast_event(
                scan_id,
                WSEventType.SCAN_FAILED,
                {"scan_id": scan_id, "error": str(ex)},
            )
