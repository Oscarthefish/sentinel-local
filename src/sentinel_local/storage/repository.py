"""SQLite-backed persistence for analysis history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from sentinel_local.domain.models import SavedAnalysis


def init_analysis_table(database_path: Path) -> None:
    """Ensure the persisted analyses table exists."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                source_type TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                confidence TEXT NOT NULL,
                analyst_note TEXT,
                parsed_email_json TEXT NOT NULL,
                extraction_result_json TEXT NOT NULL,
                header_analysis_result_json TEXT,
                analysis_result_json TEXT NOT NULL,
                analyst_summary_result_json TEXT,
                url_analysis_result_json TEXT,
                attachment_analysis_result_json TEXT,
                attachment_scan_result_json TEXT,
                enrichment_result_json TEXT,
                narrative_report_json TEXT,
                markdown_report TEXT NOT NULL
            )
            """
        )
        _ensure_column(connection, "analyses", "url_analysis_result_json", "TEXT")
        _ensure_column(connection, "analyses", "attachment_analysis_result_json", "TEXT")
        _ensure_column(connection, "analyses", "attachment_scan_result_json", "TEXT")
        _ensure_column(connection, "analyses", "header_analysis_result_json", "TEXT")
        _ensure_column(connection, "analyses", "analyst_summary_result_json", "TEXT")
        _ensure_column(connection, "analyses", "enrichment_result_json", "TEXT")
        connection.commit()


def save_analysis(
    *,
    database_path: Path,
    subject: str | None,
    sender: str | None,
    source_type: str,
    verdict: str,
    score: int,
    confidence: str,
    analyst_note: str | None,
    parsed_email: dict,
    extraction_result: dict,
    header_analysis_result: dict | None,
    analysis_result: dict,
    analyst_summary_result: dict | None,
    url_analysis_result: dict | None,
    attachment_analysis_result: dict | None,
    attachment_scan_result: dict | None,
    enrichment_result: dict | None,
    narrative_report: dict | None,
    markdown_report: str,
) -> SavedAnalysis:
    """Persist a completed analysis and return the saved record."""
    record = SavedAnalysis(
        analysis_id=uuid4(),
        created_at=datetime.now(timezone.utc),
        subject=subject,
        sender=sender,
        source_type=source_type,
        verdict=verdict,
        score=score,
        confidence=confidence,
        analyst_note=analyst_note,
        parsed_email=parsed_email,
        extraction_result=extraction_result,
        header_analysis_result=header_analysis_result,
        analysis_result=analysis_result,
        analyst_summary_result=analyst_summary_result,
        url_analysis_result=url_analysis_result,
        attachment_analysis_result=attachment_analysis_result,
        attachment_scan_result=attachment_scan_result,
        enrichment_result=enrichment_result,
        narrative_report=narrative_report,
        markdown_report=markdown_report,
    )

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO analyses (
                analysis_id,
                created_at,
                subject,
                sender,
                source_type,
                verdict,
                score,
                confidence,
                analyst_note,
                parsed_email_json,
                extraction_result_json,
                header_analysis_result_json,
                analysis_result_json,
                analyst_summary_result_json,
                url_analysis_result_json,
                attachment_analysis_result_json,
                attachment_scan_result_json,
                enrichment_result_json,
                narrative_report_json,
                markdown_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(record.analysis_id),
                record.created_at.isoformat(),
                record.subject,
                record.sender,
                record.source_type,
                record.verdict,
                record.score,
                record.confidence,
                record.analyst_note,
                json.dumps(record.parsed_email),
                json.dumps(record.extraction_result),
                json.dumps(record.header_analysis_result) if record.header_analysis_result is not None else None,
                json.dumps(record.analysis_result),
                json.dumps(record.analyst_summary_result) if record.analyst_summary_result is not None else None,
                json.dumps(record.url_analysis_result) if record.url_analysis_result is not None else None,
                json.dumps(record.attachment_analysis_result) if record.attachment_analysis_result is not None else None,
                json.dumps(record.attachment_scan_result) if record.attachment_scan_result is not None else None,
                json.dumps(record.enrichment_result) if record.enrichment_result is not None else None,
                json.dumps(record.narrative_report) if record.narrative_report is not None else None,
                record.markdown_report,
            ),
        )
        connection.commit()

    return record


def list_saved_analyses(database_path: Path, *, limit: int = 25) -> list[SavedAnalysis]:
    """Return recent saved analyses."""
    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            SELECT
                analysis_id,
                created_at,
                subject,
                sender,
                source_type,
                verdict,
                score,
                confidence,
                analyst_note,
                parsed_email_json,
                extraction_result_json,
                header_analysis_result_json,
                analysis_result_json,
                analyst_summary_result_json,
                url_analysis_result_json,
                attachment_analysis_result_json,
                attachment_scan_result_json,
                enrichment_result_json,
                narrative_report_json,
                markdown_report
            FROM analyses
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()

    return [_row_to_saved_analysis(row) for row in rows]


def get_saved_analysis(database_path: Path, analysis_id: UUID) -> SavedAnalysis | None:
    """Return one saved analysis by id."""
    with sqlite3.connect(database_path) as connection:
        cursor = connection.execute(
            """
            SELECT
                analysis_id,
                created_at,
                subject,
                sender,
                source_type,
                verdict,
                score,
                confidence,
                analyst_note,
                parsed_email_json,
                extraction_result_json,
                header_analysis_result_json,
                analysis_result_json,
                analyst_summary_result_json,
                url_analysis_result_json,
                attachment_analysis_result_json,
                attachment_scan_result_json,
                enrichment_result_json,
                narrative_report_json,
                markdown_report
            FROM analyses
            WHERE analysis_id = ?
            """,
            (str(analysis_id),),
        )
        row = cursor.fetchone()

    if row is None:
        return None

    return _row_to_saved_analysis(row)


def _row_to_saved_analysis(row: tuple) -> SavedAnalysis:
    return SavedAnalysis(
        analysis_id=UUID(row[0]),
        created_at=datetime.fromisoformat(row[1]),
        subject=row[2],
        sender=row[3],
        source_type=row[4],
        verdict=row[5],
        score=row[6],
        confidence=row[7],
        analyst_note=row[8],
        parsed_email=json.loads(row[9]),
        extraction_result=json.loads(row[10]),
        header_analysis_result=json.loads(row[11]) if row[11] else None,
        analysis_result=json.loads(row[12]),
        analyst_summary_result=json.loads(row[13]) if row[13] else None,
        url_analysis_result=json.loads(row[14]) if row[14] else None,
        attachment_analysis_result=json.loads(row[15]) if row[15] else None,
        attachment_scan_result=json.loads(row[16]) if row[16] else None,
        enrichment_result=json.loads(row[17]) if row[17] else None,
        narrative_report=json.loads(row[18]) if row[18] else None,
        markdown_report=row[19],
    )


def _ensure_column(connection: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
    existing_columns = {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in existing_columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
