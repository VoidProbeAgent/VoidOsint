"""
VoidOsint SQLite WAL Database Manager
====================================
Thread-safe persistence layer utilizing SQLite 3 with Write-Ahead Logging (WAL) mode.
Handles scans, discoveries, real-time event logs, and graph entities.

Conforms to Section 3, Section 7, and Package 1 deliverables.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from backend.models import (
    CaseSummary,
    DiscoveryItem,
    GraphData,
    GraphEdge,
    GraphNode,
    ScanConfig,
    ScanStatus,
    ScanSummary,
    TrustMetrics,
    UserSettings,
)

DEFAULT_DB_PATH = Path("data/osint_nexus.db")


class DatabaseManager:
    """Manages SQLite connection lifecycle, schemas, and queries in WAL mode."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        if db_path is None:
            self.db_path = DEFAULT_DB_PATH
        else:
            self.db_path = Path(db_path)

        # Ensure parent directories exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides a thread-local SQLite connection configured with WAL and busy timeouts."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row
        try:
            # Enable WAL mode and foreign key constraints
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA busy_timeout=15000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initializes database tables, indices, and constraints."""
        with self.get_connection() as conn:
            # 1. Scans Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    scan_name TEXT,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    engines TEXT NOT NULL,
                    engine_statuses TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error_message TEXT,
                    notes TEXT
                );
            """)

            # Ensure notes column exists for legacy databases
            try:
                conn.execute("ALTER TABLE scans ADD COLUMN notes TEXT;")
            except sqlite3.OperationalError:
                pass

            # Settings Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # 2. Discoveries Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discoveries (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    platform_name TEXT,
                    url TEXT,
                    title TEXT,
                    snippet TEXT,
                    http_status INTEGER DEFAULT 200,
                    extracted_data TEXT,
                    trust_metrics TEXT,
                    validity_score REAL,
                    accuracy_score REAL,
                    consensus_score REAL,
                    composite_score REAL,
                    grade TEXT,
                    discovered_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
            """)

            # 3. Event Logs Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    engine TEXT,
                    level TEXT DEFAULT 'INFO',
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
            """)

            # 4. Graph Nodes Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    label TEXT NOT NULL,
                    group_type TEXT NOT NULL,
                    properties TEXT,
                    PRIMARY KEY (scan_id, id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
            """)

            # 5. Graph Edges Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    label TEXT,
                    PRIMARY KEY (scan_id, id),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
            """)

            # Indices for rapid querying and filtering
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_disc_scan ON discoveries(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_disc_score ON discoveries(scan_id, composite_score DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_disc_grade ON discoveries(scan_id, grade);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_scan ON event_logs(scan_id, id ASC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_scan ON graph_nodes(scan_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_scan ON graph_edges(scan_id);")

    # -----------------------------------------------------------------------
    # Scan Lifecycle Operations
    # -----------------------------------------------------------------------

    def create_scan(self, config: ScanConfig) -> ScanSummary:
        """Registers a new scan entry in the database."""
        now_iso = datetime.now(timezone.utc).isoformat()
        initial_engine_statuses = {engine: "pending" for engine in config.engines}

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, scan_name, target, target_type, status,
                    depth, progress, engines, engine_statuses, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    config.scan_id,
                    config.scan_name or f"Scan: {config.target}",
                    config.target,
                    config.target_type.value if hasattr(config.target_type, "value") else str(config.target_type),
                    ScanStatus.PENDING.value,
                    config.depth.value if hasattr(config.depth, "value") else str(config.depth),
                    0,
                    json.dumps(config.engines),
                    json.dumps(initial_engine_statuses),
                    now_iso,
                ),
            )

            # Insert Root Target Node in Graph
            conn.execute(
                """
                INSERT OR REPLACE INTO graph_nodes (id, scan_id, label, group_type, properties)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    f"target_{config.target}",
                    config.scan_id,
                    config.target,
                    "target",
                    json.dumps({
                        "target_type": config.target_type.value if hasattr(config.target_type, "value") else str(config.target_type),
                        "is_root": True,
                    }),
                ),
            )

        return self.get_scan(config.scan_id) or ScanSummary(
            scan_id=config.scan_id,
            scan_name=config.scan_name or f"Scan: {config.target}",
            target=config.target,
            target_type=str(config.target_type),
            status=ScanStatus.PENDING,
            depth=str(config.depth),
            engines=config.engines,
            engine_statuses=initial_engine_statuses,
        )

    def update_scan_status(
        self,
        scan_id: str,
        status: Optional[ScanStatus] = None,
        progress: Optional[int] = None,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Updates top-level scan execution status and telemetry."""
        fields: List[str] = []
        params: List[Any] = []

        if status is not None:
            fields.append("status = ?")
            params.append(status.value if hasattr(status, "value") else str(status))
        if progress is not None:
            fields.append("progress = ?")
            params.append(progress)
        if started_at is not None:
            fields.append("started_at = ?")
            params.append(started_at)
        if completed_at is not None:
            fields.append("completed_at = ?")
            params.append(completed_at)
        if error_message is not None:
            fields.append("error_message = ?")
            params.append(error_message)

        if not fields:
            return

        params.append(scan_id)
        query = f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = ?"

        with self.get_connection() as conn:
            conn.execute(query, tuple(params))

    def update_engine_status(self, scan_id: str, engine: str, status: str) -> None:
        """Updates the execution status of an individual engine in the scan."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT engine_statuses FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return
            statuses = json.loads(row["engine_statuses"]) if row["engine_statuses"] else {}
            statuses[engine] = status
            conn.execute(
                "UPDATE scans SET engine_statuses = ? WHERE scan_id = ?",
                (json.dumps(statuses), scan_id),
            )

    def get_scan(self, scan_id: str) -> Optional[ScanSummary]:
        """Fetches full metadata and aggregate discovery counts for a scan."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT s.*,
                    (SELECT COUNT(*) FROM discoveries d WHERE d.scan_id = s.scan_id) AS total_discoveries,
                    (SELECT COUNT(*) FROM discoveries d WHERE d.scan_id = s.scan_id AND d.grade = 'CONFIRMED') AS confirmed_count
                FROM scans s
                WHERE s.scan_id = ?
                """,
                (scan_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return ScanSummary(
                scan_id=row["scan_id"],
                scan_name=row["scan_name"],
                target=row["target"],
                target_type=row["target_type"],
                status=ScanStatus(row["status"]) if row["status"] in [s.value for s in ScanStatus] else ScanStatus.PENDING,
                depth=row["depth"],
                progress=row["progress"] or 0,
                engines=json.loads(row["engines"]) if row["engines"] else [],
                engine_statuses=json.loads(row["engine_statuses"]) if row["engine_statuses"] else {},
                total_discoveries=row["total_discoveries"] or 0,
                confirmed_count=row["confirmed_count"] or 0,
                created_at=row["created_at"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                error_message=row["error_message"],
            )

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[ScanSummary]:
        """Lists past and active scans ordered by creation date descending."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT s.*,
                    (SELECT COUNT(*) FROM discoveries d WHERE d.scan_id = s.scan_id) AS total_discoveries,
                    (SELECT COUNT(*) FROM discoveries d WHERE d.scan_id = s.scan_id AND d.grade = 'CONFIRMED') AS confirmed_count
                FROM scans s
                ORDER BY s.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            results: List[ScanSummary] = []
            for row in rows:
                results.append(
                    ScanSummary(
                        scan_id=row["scan_id"],
                        scan_name=row["scan_name"],
                        target=row["target"],
                        target_type=row["target_type"],
                        status=ScanStatus(row["status"]) if row["status"] in [s.value for s in ScanStatus] else ScanStatus.PENDING,
                        depth=row["depth"],
                        progress=row["progress"] or 0,
                        engines=json.loads(row["engines"]) if row["engines"] else [],
                        engine_statuses=json.loads(row["engine_statuses"]) if row["engine_statuses"] else {},
                        total_discoveries=row["total_discoveries"] or 0,
                        confirmed_count=row["confirmed_count"] or 0,
                        created_at=row["created_at"],
                        started_at=row["started_at"],
                        completed_at=row["completed_at"],
                        error_message=row["error_message"],
                    )
                )
            return results

    # -----------------------------------------------------------------------
    # Discovery Operations
    # -----------------------------------------------------------------------

    def insert_discovery(self, discovery: DiscoveryItem) -> DiscoveryItem:
        """Inserts an enriched discovery and synthesizes corresponding graph entities."""
        validity = discovery.trust_metrics.validity_score if discovery.trust_metrics else 1.0
        accuracy = discovery.trust_metrics.accuracy_score if discovery.trust_metrics else 1.0
        consensus = discovery.trust_metrics.consensus_score if discovery.trust_metrics else 1.0
        composite = discovery.trust_metrics.composite_score if discovery.trust_metrics else 100.0
        grade = (
            discovery.trust_metrics.grade.value
            if (discovery.trust_metrics and hasattr(discovery.trust_metrics.grade, "value"))
            else (str(discovery.trust_metrics.grade) if discovery.trust_metrics else "CONFIRMED")
        )

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO discoveries (
                    id, scan_id, target, target_type, engine, entity_type,
                    platform_name, url, title, snippet, http_status,
                    extracted_data, trust_metrics, validity_score,
                    accuracy_score, consensus_score, composite_score,
                    grade, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    discovery.id,
                    discovery.scan_id,
                    discovery.target,
                    discovery.target_type,
                    discovery.engine,
                    discovery.entity_type,
                    discovery.platform_name,
                    discovery.url,
                    discovery.title,
                    discovery.snippet,
                    discovery.http_status,
                    json.dumps(discovery.extracted_data or {}),
                    json.dumps(discovery.trust_metrics.to_dict() if hasattr(discovery.trust_metrics, "to_dict") else (discovery.trust_metrics.model_dump() if discovery.trust_metrics else {})),
                    validity,
                    accuracy,
                    consensus,
                    composite,
                    grade,
                    discovery.discovered_at,
                ),
            )

            # Insert Graph Node for this Discovery
            node_label = discovery.platform_name or discovery.title or discovery.url or discovery.id
            conn.execute(
                """
                INSERT OR REPLACE INTO graph_nodes (id, scan_id, label, group_type, properties)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    discovery.id,
                    discovery.scan_id,
                    node_label,
                    discovery.entity_type,
                    json.dumps({
                        "url": discovery.url,
                        "title": discovery.title,
                        "engine": discovery.engine,
                        "platform_name": discovery.platform_name,
                        "composite_score": composite,
                        "grade": grade,
                    }),
                ),
            )

            # Insert Graph Edge linking Target Root -> Discovery Node
            root_id = f"target_{discovery.target}"
            edge_id = f"edge_{root_id}_{discovery.id}"
            conn.execute(
                """
                INSERT OR REPLACE INTO graph_edges (id, scan_id, source_id, target_id, label)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    edge_id,
                    discovery.scan_id,
                    root_id,
                    discovery.id,
                    discovery.platform_name or discovery.engine,
                ),
            )

        return discovery

    def get_discoveries(
        self,
        scan_id: str,
        min_trust: Optional[float] = None,
        grade: Optional[str] = None,
        engine: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[DiscoveryItem]:
        """Retrieves discoveries matching multi-attribute filter criteria."""
        conditions = ["scan_id = ?"]
        params: List[Any] = [scan_id]

        if min_trust is not None:
            conditions.append("composite_score >= ?")
            params.append(min_trust)

        if grade:
            conditions.append("grade = ?")
            params.append(grade.upper())

        if engine:
            conditions.append("engine = ?")
            params.append(engine.lower())

        if search:
            like_pat = f"%{search}%"
            conditions.append("(platform_name LIKE ? OR url LIKE ? OR title LIKE ? OR snippet LIKE ?)")
            params.extend([like_pat, like_pat, like_pat, like_pat])

        where_clause = " AND ".join(conditions)
        query = f"""
            SELECT * FROM discoveries
            WHERE {where_clause}
            ORDER BY composite_score DESC, discovered_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            rows = cursor.fetchall()
            items: List[DiscoveryItem] = []
            for row in rows:
                raw_trust = json.loads(row["trust_metrics"]) if row["trust_metrics"] else None
                trust_obj = TrustMetrics(**raw_trust) if raw_trust else None
                items.append(
                    DiscoveryItem(
                        id=row["id"],
                        scan_id=row["scan_id"],
                        target=row["target"],
                        target_type=row["target_type"],
                        engine=row["engine"],
                        entity_type=row["entity_type"],
                        platform_name=row["platform_name"],
                        url=row["url"],
                        title=row["title"],
                        snippet=row["snippet"],
                        http_status=row["http_status"],
                        extracted_data=json.loads(row["extracted_data"]) if row["extracted_data"] else {},
                        trust_metrics=trust_obj,
                        discovered_at=row["discovered_at"],
                    )
                )
            return items

    def get_discovery_count(
        self,
        scan_id: str,
        min_trust: Optional[float] = None,
        grade: Optional[str] = None,
    ) -> int:
        """Returns the total number of discoveries matching filters."""
        conditions = ["scan_id = ?"]
        params: List[Any] = [scan_id]

        if min_trust is not None:
            conditions.append("composite_score >= ?")
            params.append(min_trust)
        if grade:
            conditions.append("grade = ?")
            params.append(grade.upper())

        query = f"SELECT COUNT(*) AS cnt FROM discoveries WHERE {' AND '.join(conditions)}"
        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            row = cursor.fetchone()
            return row["cnt"] if row else 0

    # -----------------------------------------------------------------------
    # Logging Operations
    # -----------------------------------------------------------------------

    def insert_log(
        self,
        scan_id: str,
        engine: Optional[str],
        message: str,
        level: str = "INFO",
    ) -> None:
        """Appends a subprocess or orchestrator log entry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO event_logs (scan_id, engine, level, message, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, engine, level, message, now_iso),
            )

    def get_logs(self, scan_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        """Retrieves recent logs for a scan."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, scan_id, engine, level, message, timestamp
                FROM event_logs
                WHERE scan_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (scan_id, limit),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # -----------------------------------------------------------------------
    # Graph Visualizer Support
    # -----------------------------------------------------------------------

    def get_graph(self, scan_id: str) -> GraphData:
        """Retrieves nodes and edges formatted for Vis.js or Cytoscape.js rendering."""
        with self.get_connection() as conn:
            cursor_nodes = conn.execute(
                "SELECT id, label, group_type, properties FROM graph_nodes WHERE scan_id = ?",
                (scan_id,),
            )
            nodes_rows = cursor_nodes.fetchall()

            cursor_edges = conn.execute(
                "SELECT id, source_id, target_id, label FROM graph_edges WHERE scan_id = ?",
                (scan_id,),
            )
            edges_rows = cursor_edges.fetchall()

            nodes_data: List[Dict[str, Any]] = []
            for r in nodes_rows:
                props = json.loads(r["properties"]) if r["properties"] else {}
                node_dict = {
                    "id": r["id"],
                    "label": r["label"],
                    "group": r["group_type"],
                    "title": props.get("url") or props.get("title") or r["label"],
                    "score": props.get("composite_score"),
                    "grade": props.get("grade"),
                }
                nodes_data.append(node_dict)

            edges_data: List[Dict[str, Any]] = []
            for r in edges_rows:
                edges_data.append({
                    "id": r["id"],
                    "from": r["source_id"],
                    "to": r["target_id"],
                    "label": r["label"],
                    "arrows": "to",
                })

            return GraphData(nodes=nodes_data, edges=edges_data)

    def delete_investigation(self, scan_id: str) -> bool:
        """Cascades deletion of an investigation case and all associated child entities."""
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?;", (scan_id,))
            return cursor.rowcount > 0

    def get_investigations(
        self,
        search: Optional[str] = None,
        target_type: Optional[str] = None,
        status: Optional[str] = None,
        date_range: Optional[str] = None,
        page: int = 1,
        limit: int = 25,
    ) -> Tuple[int, List[CaseSummary]]:
        """Retrieves paginated investigation cases with aggregated discovery and trust metrics."""
        conditions: List[str] = []
        params: List[Any] = []

        if search and search.strip():
            like_pat = f"%{search.strip()}%"
            conditions.append("(s.target LIKE ? OR s.scan_name LIKE ? OR s.notes LIKE ?)")
            params.extend([like_pat, like_pat, like_pat])

        if target_type and target_type.lower() != "all":
            conditions.append("LOWER(s.target_type) = ?")
            params.append(target_type.lower().strip())

        if status and status.lower() != "all":
            conditions.append("LOWER(s.status) = ?")
            params.append(status.lower().strip())

        if date_range:
            dr = date_range.lower().strip()
            if dr in ("today", "1d"):
                conditions.append("date(s.created_at) = date('now')")
            elif dr in ("last_7_days", "7d", "last 7 days"):
                conditions.append("s.created_at >= datetime('now', '-7 days')")
            elif dr in ("last_30_days", "30d", "last 30 days"):
                conditions.append("s.created_at >= datetime('now', '-30 days')")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_sql = f"SELECT COUNT(*) AS total FROM scans s {where_clause}"

        offset = max(0, (page - 1) * limit)

        data_sql = f"""
            SELECT 
                s.scan_id,
                s.scan_name,
                s.target,
                s.target_type,
                s.status,
                s.depth,
                s.progress,
                s.engines,
                s.created_at,
                s.started_at,
                s.completed_at,
                s.notes,
                COUNT(d.id) AS total_discoveries,
                COUNT(CASE WHEN d.grade = 'CONFIRMED' THEN 1 END) AS confirmed_count,
                COUNT(CASE WHEN d.grade = 'HIGH' THEN 1 END) AS high_count,
                COUNT(CASE WHEN d.grade = 'SUSPICIOUS' THEN 1 END) AS suspicious_count,
                COALESCE(AVG(d.composite_score), 0.0) AS avg_trust_score
            FROM scans s
            LEFT JOIN discoveries d ON s.scan_id = d.scan_id
            {where_clause}
            GROUP BY s.scan_id
            ORDER BY s.created_at DESC
            LIMIT ? OFFSET ?
        """

        with self.get_connection() as conn:
            # Get total matching count
            cur_count = conn.execute(count_sql, tuple(params))
            total_row = cur_count.fetchone()
            total_cases = total_row["total"] if total_row else 0

            # Get paginated data
            query_params = list(params)
            query_params.extend([limit, offset])
            cur_data = conn.execute(data_sql, tuple(query_params))
            rows = cur_data.fetchall()

            cases: List[CaseSummary] = []
            for row in rows:
                duration: Optional[float] = None
                if row["started_at"] and row["completed_at"]:
                    try:
                        t_s = datetime.fromisoformat(row["started_at"].replace("Z", "+00:00"))
                        t_c = datetime.fromisoformat(row["completed_at"].replace("Z", "+00:00"))
                        duration = max(0.0, round((t_c - t_s).total_seconds(), 2))
                    except Exception:
                        pass
                elif row["created_at"] and row["completed_at"]:
                    try:
                        t_s = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
                        t_c = datetime.fromisoformat(row["completed_at"].replace("Z", "+00:00"))
                        duration = max(0.0, round((t_c - t_s).total_seconds(), 2))
                    except Exception:
                        pass

                cases.append(
                    CaseSummary(
                        scan_id=row["scan_id"],
                        scan_name=row["scan_name"],
                        target=row["target"],
                        target_type=row["target_type"],
                        status=row["status"],
                        depth=row["depth"] or "standard",
                        progress=row["progress"] or 0,
                        engines=json.loads(row["engines"]) if row["engines"] else [],
                        created_at=row["created_at"],
                        started_at=row["started_at"],
                        completed_at=row["completed_at"],
                        duration_seconds=duration,
                        total_discoveries=row["total_discoveries"] or 0,
                        confirmed_count=row["confirmed_count"] or 0,
                        high_count=row["high_count"] or 0,
                        suspicious_count=row["suspicious_count"] or 0,
                        avg_trust_score=round(float(row["avg_trust_score"] or 0.0), 2),
                        notes=row["notes"],
                    )
                )

            return total_cases, cases

    def get_investigation_detail(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves full case payload for one-click reload or analytical review."""
        scan = self.get_scan(scan_id)
        if not scan:
            return None

        with self.get_connection() as conn:
            cursor = conn.execute("SELECT notes FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            notes = row["notes"] if row else None

        discoveries = self.get_discoveries(scan_id=scan_id, limit=5000)
        logs = self.get_logs(scan_id=scan_id, limit=2000)
        graph = self.get_graph(scan_id=scan_id)

        return {
            "scan_id": scan.scan_id,
            "scan": scan.model_dump(),
            "notes": notes,
            "discoveries": [d.model_dump() for d in discoveries],
            "logs": logs,
            "graph": graph.model_dump(),
            "total_discoveries": len(discoveries),
        }

    def update_case_notes(self, scan_id: str, notes: str) -> bool:
        """Updates analyst hypothesis and notes on a scan."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE scans SET notes = ? WHERE scan_id = ?",
                (notes, scan_id),
            )
            return cursor.rowcount > 0

    def get_settings(self) -> Dict[str, Any]:
        """Fetches stored user settings or returns defaults."""
        defaults = UserSettings().model_dump()
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT key, value FROM settings;")
            rows = cursor.fetchall()
            for r in rows:
                k = r["key"]
                try:
                    defaults[k] = json.loads(r["value"])
                except Exception:
                    defaults[k] = r["value"]
        return defaults

    def update_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Saves updated user settings."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            for k, v in new_settings.items():
                val_str = json.dumps(v) if isinstance(v, (dict, list, bool, int, float)) else str(v)
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;",
                    (k, val_str, now_iso),
                )
        return self.get_settings()

    def purge_database(self, days_old: Optional[int] = 7, vacuum: bool = True) -> Dict[str, Any]:
        """Performs database maintenance: deletes old event logs and vacuums WAL pages."""
        deleted_logs = 0
        with self.get_connection() as conn:
            if days_old is not None and days_old > 0:
                cur = conn.execute(
                    "DELETE FROM event_logs WHERE timestamp < datetime('now', ?);",
                    (f"-{days_old} days",),
                )
                deleted_logs = cur.rowcount

        # VACUUM must run outside an open multi-statement transaction
        if vacuum:
            raw_conn = sqlite3.connect(str(self.db_path))
            try:
                raw_conn.execute("VACUUM;")
                raw_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            finally:
                raw_conn.close()

        file_size_mb = 0.0
        try:
            file_size_mb = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)
        except Exception:
            pass

        return {
            "status": "purged",
            "deleted_logs": deleted_logs,
            "database_size_mb": file_size_mb,
            "vacuum_executed": vacuum,
        }
