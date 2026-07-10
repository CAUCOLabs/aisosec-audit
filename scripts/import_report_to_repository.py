#!/usr/bin/env python3
"""Import an AisoSec JSON report into the local evidence repository."""

import argparse
import datetime
import hashlib
import json
import pathlib
import sqlite3


DATABASE_PATH = pathlib.Path("data") / "aisosec_evidence.db"


def stable_id(*parts):
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def now_utc():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def create_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assessments (
            id TEXT PRIMARY KEY,
            target TEXT,
            host TEXT,
            timestamp TEXT,
            assessment_type TEXT,
            overall_risk TEXT,
            business_impact TEXT,
            remediation_priority TEXT,
            source_json_path TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,
            source TEXT,
            created_at TEXT,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_items (
            id TEXT PRIMARY KEY,
            assessment_id TEXT,
            evidence_type TEXT,
            key TEXT,
            value TEXT,
            source TEXT,
            created_at TEXT,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS control_mappings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT,
            control_id TEXT,
            control_name TEXT,
            mapping_reason TEXT,
            created_at TEXT,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS repository_events (
            id TEXT PRIMARY KEY,
            event_type TEXT,
            message TEXT,
            created_at TEXT
        )
        """
    )


def parse_host(target):
    text = str(target or "")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    text = text.split("@", 1)[-1]
    text = text.split(":", 1)[0]
    return text


def risk_summary(scan_data, report):
    general = scan_data.get("general", {}) or {}
    headers = general.get("headers", {}) or {}
    nuclei_findings = scan_data.get("nuclei_findings", []) or []
    source_findings = (scan_data.get("source_code_analysis", {}) or {}).get("findings", []) or []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def normalize(value, fallback="info"):
        text = (value or fallback).strip().lower()
        return text if text in counts else fallback

    for item in report.get("findings", []) or []:
        severity = item.get("severity") if isinstance(item, dict) else "info"
        counts[normalize(severity)] += 1
    for item in nuclei_findings:
        if isinstance(item, dict):
            counts[normalize(item.get("severity"))] += 1
    for item in source_findings:
        if isinstance(item, dict):
            counts[normalize(item.get("severity"), "low")] += 1
    if missing_security_headers(headers):
        counts["low"] += 1

    if counts["critical"] or counts["high"]:
        return "High", "High", "Prompt remediation"
    if counts["medium"]:
        return "Medium", "Medium", "Planned remediation"
    if counts["low"]:
        return "Low", "Low", "Recommended hardening"
    if counts["info"]:
        return "Informational", "Informational", "Review and document"
    return "No material exposure identified", "No material exposure identified", "Continue monitoring"


def insert_assessment(conn, report, source_file, source_hash, created_at, scan_data):
    assessment_id = stable_id(
        report.get("target", ""),
        report.get("date", ""),
        source_hash,
    )
    target = report.get("target", "")
    overall_risk, business_impact, remediation_priority = risk_summary(scan_data, report)
    conn.execute(
        """
        INSERT OR REPLACE INTO assessments
        (id, target, host, timestamp, assessment_type, overall_risk, business_impact,
         remediation_priority, source_json_path, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            target,
            parse_host(target),
            report.get("date", ""),
            "Authenticated assessment" if report.get("authenticated") else "Unauthenticated assessment",
            overall_risk,
            business_impact,
            remediation_priority,
            str(source_file),
            created_at,
        ),
    )
    return assessment_id


def insert_finding(conn, assessment_id, source, index, severity, title, description, evidence, remediation, created_at):
    finding_id = stable_id(assessment_id, source, index, severity, title, description, evidence)
    conn.execute(
        """
        INSERT OR REPLACE INTO findings
        (id, assessment_id, severity, title, description, evidence, remediation, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding_id,
            assessment_id,
            severity,
            title,
            description,
            evidence,
            remediation,
            source,
            created_at,
        ),
    )


def insert_evidence(conn, assessment_id, evidence_type, index, key, value, source, created_at):
    evidence_id = stable_id(assessment_id, evidence_type, index, key, value, source)
    conn.execute(
        """
        INSERT OR REPLACE INTO evidence_items
        (id, assessment_id, evidence_type, key, value, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_id,
            assessment_id,
            evidence_type,
            key,
            value,
            source,
            created_at,
        ),
    )


def insert_control(conn, assessment_id, control_id, control_name, mapping_reason, created_at):
    mapping_id = stable_id(assessment_id, control_id, mapping_reason)
    conn.execute(
        """
        INSERT OR REPLACE INTO control_mappings
        (id, assessment_id, control_id, control_name, mapping_reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            mapping_id,
            assessment_id,
            control_id,
            control_name,
            mapping_reason,
            created_at,
        ),
    )


def insert_event(conn, event_type, message, created_at):
    event_id = stable_id(event_type, message)
    conn.execute(
        """
        INSERT OR REPLACE INTO repository_events
        (id, event_type, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (event_id, event_type, message, created_at),
    )


def required_headers():
    return [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]


def missing_security_headers(headers):
    return [
        header
        for header in required_headers()
        if not (headers.get(header) or headers.get(header.lower()))
    ]


def infer_controls(scan_data):
    general = scan_data.get("general", {}) or {}
    headers = general.get("headers", {}) or {}
    nmap_ports = (scan_data.get("nmap", {}) or {}).get("ports", []) or []
    nuclei_findings = scan_data.get("nuclei_findings", []) or []
    src_findings = (scan_data.get("source_code_analysis", {}) or {}).get("findings", []) or []
    emails = scan_data.get("emails", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    directory_hits = scan_data.get("directory_hits", []) or []

    controls = []
    if missing_security_headers(headers):
        controls.extend(
            [
                ("AISOSEC-WEB-001", "HTTP Security Header Hardening", "http_headers", "Missing recommended security headers were observed."),
                ("AISOSEC-CONFIG-001", "Secure Configuration Review", "http_headers", "Missing recommended security headers indicate configuration items for review."),
            ]
        )
    if emails or src_findings:
        controls.extend(
            [
                ("AISOSEC-INFO-001", "Public Information Exposure Review", "information_exposure", "Emails or source code findings were observed."),
                ("AISOSEC-DATA-001", "Data Minimization and Public Exposure Review", "information_exposure", "Publicly exposed data elements were observed."),
            ]
        )
    if nmap_ports:
        controls.extend(
            [
                ("AISOSEC-NET-001", "External Service Exposure Review", "open_ports", "Open ports were observed."),
                ("AISOSEC-ASSET-001", "Asset Inventory and Service Ownership Review", "open_ports", "Observed services should be tied to asset ownership."),
            ]
        )
    if any((item.get("severity") or "info").strip().lower() == "info" for item in nuclei_findings if isinstance(item, dict)):
        controls.extend(
            [
                ("AISOSEC-VM-001", "Vulnerability Management Triage", "nuclei_findings", "Nuclei informational findings were observed."),
                ("AISOSEC-TECH-001", "Technology Exposure Inventory", "nuclei_findings", "Technology exposure observations were collected."),
            ]
        )
    if api_endpoints:
        controls.extend(
            [
                ("AISOSEC-API-001", "API Authentication and Authorization Review", "api_endpoints", "API endpoints were discovered."),
                ("AISOSEC-API-002", "API Rate Limiting and Abuse Prevention Review", "api_endpoints", "API endpoints were discovered and may require abuse prevention review."),
            ]
        )
    if directory_hits:
        controls.extend(
            [
                ("AISOSEC-WEB-002", "Public Path Exposure Review", "directory_hits", "Directory hits were discovered."),
                ("AISOSEC-CONTENT-001", "Content Publishing Governance Review", "directory_hits", "Discovered paths may require content governance review."),
            ]
        )
    controls.append(
        (
            "AISOSEC-COMP-001",
            "Compliance Mapping Requires Auditor Validation",
            "compliance_mapping",
            "Control mappings are indicative and require auditor validation.",
        )
    )
    return controls


def import_findings(conn, assessment_id, report, scan_data, created_at):
    count = 0
    for index, item in enumerate(report.get("findings", []) or []):
        if isinstance(item, dict):
            insert_finding(
                conn,
                assessment_id,
                "report",
                index,
                item.get("severity", "info"),
                item.get("name", "Finding"),
                item.get("detail", ""),
                json_text(item),
                "",
                created_at,
            )
        else:
            insert_finding(conn, assessment_id, "report", index, "info", str(item), "", str(item), "", created_at)
        count += 1

    headers = (scan_data.get("general", {}) or {}).get("headers", {}) or {}
    missing_headers = missing_security_headers(headers)
    if missing_headers:
        insert_finding(
            conn,
            assessment_id,
            "general",
            "missing_security_headers",
            "LOW",
            "Security header hardening opportunity",
            "Recommended HTTP security headers were not observed in the collected response.",
            ", ".join(missing_headers),
            "Review and implement recommended HTTP security headers after compatibility testing.",
            created_at,
        )
        count += 1

    for index, item in enumerate(scan_data.get("nuclei_findings", []) or []):
        if isinstance(item, dict):
            insert_finding(
                conn,
                assessment_id,
                "nuclei",
                index,
                item.get("severity", "info"),
                item.get("name") or item.get("template_id") or "Nuclei finding",
                item.get("url", ""),
                json_text(item),
                "",
                created_at,
            )
            count += 1

    source_findings = (scan_data.get("source_code_analysis", {}) or {}).get("findings", []) or []
    for index, item in enumerate(source_findings):
        if isinstance(item, dict):
            insert_finding(
                conn,
                assessment_id,
                "source_code",
                index,
                item.get("severity", "low"),
                item.get("type", "Source code finding"),
                item.get("value") or item.get("url") or "",
                json_text(item),
                "",
                created_at,
            )
            count += 1

    return count


def import_evidence(conn, assessment_id, scan_data, created_at):
    count = 0
    general = scan_data.get("general", {}) or {}
    headers = general.get("headers", {}) or {}
    for index, key in enumerate(sorted(headers)):
        insert_evidence(conn, assessment_id, "http_header", index, key, str(headers.get(key)), "general", created_at)
        count += 1

    for index, item in enumerate(general.get("technologies", []) or []):
        key = item.get("name", "Technology") if isinstance(item, dict) else "Technology"
        insert_evidence(conn, assessment_id, "technology", index, key, json_text(item), "general", created_at)
        count += 1

    ports = (scan_data.get("nmap", {}) or {}).get("ports", []) or []
    for index, item in enumerate(ports):
        if isinstance(item, dict):
            key = str(item.get("port", "Port"))
            value = " ".join(str(item.get(key, "")) for key in ("protocol", "state", "service")).strip()
        else:
            key = "Port"
            value = str(item)
        insert_evidence(conn, assessment_id, "open_port", index, key, value, "nmap", created_at)
        count += 1

    for index, item in enumerate(scan_data.get("nuclei_findings", []) or []):
        if isinstance(item, dict):
            key = item.get("template_id") or item.get("name") or "Nuclei finding"
            value = item.get("url") or json_text(item)
        else:
            key = "Nuclei finding"
            value = str(item)
        insert_evidence(conn, assessment_id, "nuclei_finding", index, key, value, "nuclei", created_at)
        count += 1

    source_findings = (scan_data.get("source_code_analysis", {}) or {}).get("findings", []) or []
    for index, item in enumerate(source_findings):
        if isinstance(item, dict):
            key = item.get("type", "Source code finding")
            value = item.get("value") or item.get("url") or json_text(item)
        else:
            key = "Source code finding"
            value = str(item)
        insert_evidence(conn, assessment_id, "source_code_finding", index, key, value, "source_code_analysis", created_at)
        count += 1

    spider_urls = (scan_data.get("spider", {}) or {}).get("sample_urls", []) or []
    for index, item in enumerate(spider_urls):
        insert_evidence(conn, assessment_id, "spidered_url", index, "Spidered URL", str(item), "spider", created_at)
        count += 1

    for evidence_type, data_key, source in (("directory_hit", "directory_hits", "directory_discovery"), ("api_endpoint", "api_endpoints", "api_discovery")):
        for index, item in enumerate(scan_data.get(data_key, []) or []):
            insert_evidence(conn, assessment_id, evidence_type, index, evidence_type.replace("_", " ").title(), str(item), source, created_at)
            count += 1

    return count


def import_controls(conn, assessment_id, scan_data, created_at):
    controls = infer_controls(scan_data)
    for control_id, control_name, evidence_type, rationale in controls:
        insert_control(conn, assessment_id, control_id, control_name, f"{evidence_type}: {rationale}", created_at)
    return len(controls)


def import_report(report_path):
    source_file = pathlib.Path(report_path)
    raw = source_file.read_bytes()
    report = json.loads(raw.decode("utf-8"))
    source_hash = hashlib.sha256(raw).hexdigest()
    scan_data = report.get("scan_data", {}) or {}
    created_at = now_utc()

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        create_tables(conn)
        assessment_id = insert_assessment(conn, report, source_file, source_hash, created_at, scan_data)
        finding_count = import_findings(conn, assessment_id, report, scan_data, created_at)
        evidence_count = import_evidence(conn, assessment_id, scan_data, created_at)
        control_count = import_controls(conn, assessment_id, scan_data, created_at)
        insert_event(
            conn,
            "import",
            f"Imported report {source_file} as assessment {assessment_id} with {finding_count} findings, {evidence_count} evidence items, and {control_count} control mappings.",
            created_at,
        )
        conn.commit()
    finally:
        conn.close()

    return assessment_id, finding_count, evidence_count, control_count


def main():
    parser = argparse.ArgumentParser(description="Import an AisoSec JSON report into SQLite.")
    parser.add_argument("report_json", help="Path to an AisoSec JSON report")
    args = parser.parse_args()

    report_path = pathlib.Path(args.report_json)
    if not report_path.is_file():
        print(f"FAIL: report file not found: {report_path}")
        return 1

    try:
        assessment_id, finding_count, evidence_count, control_count = import_report(report_path)
    except Exception as exc:
        print(f"FAIL: could not import report: {exc}")
        return 1

    print("PASS: report imported")
    print(f"Assessment ID: {assessment_id}")
    print(f"Findings imported: {finding_count}")
    print(f"Evidence items imported: {evidence_count}")
    print(f"Control mappings imported: {control_count}")
    print(f"Database: {DATABASE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
