#!/usr/bin/env python3
import argparse
import sqlite3
import sys
from pathlib import Path


DEFAULT_DB = Path("data/aisosec_evidence.db")


def connect_database(db_path):
    if not db_path.exists():
        raise FileNotFoundError(f"Evidence repository database not found: {db_path}")

    return sqlite3.connect(db_path)


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def count_rows(conn, table_name):
    if not table_exists(conn, table_name):
        return 0
    return conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]


def print_header(title):
    print()
    print(title)
    print("=" * len(title))


def print_table(rows, empty_message):
    if not rows:
        print(empty_message)
        return

    for row in rows:
        print(row)


def latest_assessments(conn, limit):
    if not table_exists(conn, "assessments"):
        return []

    rows = conn.execute(
        """
        SELECT target, overall_risk, business_impact, remediation_priority, timestamp
        FROM assessments
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        f"- {target} | Risk: {risk} | Impact: {impact} | Priority: {priority} | {timestamp}"
        for target, risk, impact, priority, timestamp in rows
    ]


def findings_by_severity(conn):
    if not table_exists(conn, "findings"):
        return []

    rows = conn.execute(
        """
        SELECT severity, COUNT(*)
        FROM findings
        GROUP BY severity
        ORDER BY
            CASE LOWER(severity)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                WHEN 'info' THEN 5
                ELSE 6
            END
        """
    ).fetchall()

    return [f"- {severity}: {count}" for severity, count in rows]


def recent_findings(conn, limit):
    if not table_exists(conn, "findings"):
        return []

    rows = conn.execute(
        """
        SELECT severity, title, source
        FROM findings
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [f"- [{severity}] {title} ({source})" for severity, title, source in rows]


def top_controls(conn, limit):
    if not table_exists(conn, "control_mappings"):
        return []

    rows = conn.execute(
        """
        SELECT control_id, control_name, COUNT(*) as usage_count
        FROM control_mappings
        GROUP BY control_id, control_name
        ORDER BY usage_count DESC, control_id ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [
        f"- {control_id} — {control_name} ({usage_count})"
        for control_id, control_name, usage_count in rows
    ]


def evidence_types(conn):
    if not table_exists(conn, "evidence_items"):
        return []

    rows = conn.execute(
        """
        SELECT evidence_type, COUNT(*)
        FROM evidence_items
        GROUP BY evidence_type
        ORDER BY COUNT(*) DESC, evidence_type ASC
        """
    ).fetchall()

    return [f"- {evidence_type}: {count}" for evidence_type, count in rows]


def repository_events(conn, limit):
    if not table_exists(conn, "repository_events"):
        return []

    rows = conn.execute(
        """
        SELECT event_type, message, created_at
        FROM repository_events
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return [f"- {created_at} | {event_type}: {message}" for event_type, message, created_at in rows]


def run_summary(db_path, limit):
    conn = connect_database(db_path)

    print("AisoSec Evidence Repository Summary")
    print("===================================")
    print(f"Database: {db_path}")
    print()
    print(f"Assessments: {count_rows(conn, 'assessments')}")
    print(f"Findings: {count_rows(conn, 'findings')}")
    print(f"Evidence items: {count_rows(conn, 'evidence_items')}")
    print(f"Control mappings: {count_rows(conn, 'control_mappings')}")
    print(f"Repository events: {count_rows(conn, 'repository_events')}")

    print_header("Latest Assessments")
    print_table(latest_assessments(conn, limit), "No assessments found.")

    print_header("Findings by Severity")
    print_table(findings_by_severity(conn), "No findings found.")

    print_header("Recent Findings")
    print_table(recent_findings(conn, limit), "No recent findings found.")

    print_header("Evidence Types")
    print_table(evidence_types(conn), "No evidence items found.")

    print_header("Top AisoSec Controls")
    print_table(top_controls(conn, limit), "No control mappings found.")

    print_header("Recent Repository Events")
    print_table(repository_events(conn, limit), "No repository events found.")

    conn.close()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Show a readable summary of the local AisoSec evidence repository."
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help="Path to the SQLite evidence repository database.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of rows to show in summary sections.",
    )
    args = parser.parse_args()

    try:
        return run_summary(Path(args.db), max(1, args.limit))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
