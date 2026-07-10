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


def build_query(args):
    query = """
        SELECT
            f.severity,
            f.title,
            f.description,
            f.evidence,
            f.remediation,
            f.source,
            a.target,
            a.overall_risk,
            a.remediation_priority,
            f.created_at
        FROM findings f
        LEFT JOIN assessments a ON f.assessment_id = a.id
        WHERE 1=1
    """
    params = []

    if args.severity:
        query += " AND LOWER(f.severity) = LOWER(?)"
        params.append(args.severity)

    if args.target:
        query += " AND LOWER(a.target) LIKE LOWER(?)"
        params.append(f"%{args.target}%")

    if args.source:
        query += " AND LOWER(f.source) = LOWER(?)"
        params.append(args.source)

    query += " ORDER BY f.created_at DESC LIMIT ?"
    params.append(args.limit)

    return query, params


def print_finding(index, row):
    (
        severity,
        title,
        description,
        evidence,
        remediation,
        source,
        target,
        overall_risk,
        remediation_priority,
        created_at,
    ) = row

    print()
    print(f"Finding #{index}")
    print("-" * 40)
    print(f"Target: {target or '-'}")
    print(f"Severity: {severity or '-'}")
    print(f"Title: {title or '-'}")
    print(f"Source: {source or '-'}")
    print(f"Overall risk: {overall_risk or '-'}")
    print(f"Priority: {remediation_priority or '-'}")
    print(f"Created at: {created_at or '-'}")

    if description:
        print()
        print("Description:")
        print(description)

    if evidence:
        print()
        print("Evidence:")
        print(evidence)

    if remediation:
        print()
        print("Remediation:")
        print(remediation)


def run(args):
    conn = connect_database(Path(args.db))

    if not table_exists(conn, "findings"):
        print("No findings table found.")
        return 1

    query, params = build_query(args)
    rows = conn.execute(query, params).fetchall()

    print("AisoSec Evidence Repository Findings")
    print("====================================")
    print(f"Database: {args.db}")
    print(f"Results: {len(rows)}")

    if not rows:
        print()
        print("No findings matched the selected filters.")
        return 0

    for index, row in enumerate(rows, start=1):
        print_finding(index, row)

    conn.close()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Query findings from the local AisoSec evidence repository."
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help="Path to the SQLite evidence repository database.",
    )
    parser.add_argument(
        "--severity",
        help="Filter by severity, for example LOW, MEDIUM, HIGH or CRITICAL.",
    )
    parser.add_argument(
        "--target",
        help="Filter by target text, for example www.aisosu.fi.",
    )
    parser.add_argument(
        "--source",
        help="Filter by finding source, for example general, nuclei or source_code.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of findings to show.",
    )

    args = parser.parse_args()

    try:
        args.limit = max(1, args.limit)
        return run(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
