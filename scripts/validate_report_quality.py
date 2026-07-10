#!/usr/bin/env python3
"""Validate generated AisoSec report quality.

Usage:
    python3 scripts/validate_report_quality.py reports/www.aisosu.fi
"""

from pathlib import Path
import re
import sys


REQUIRED_SECTIONS = [
    "Report Metadata",
    "Assessment Result",
    "Executive Summary",
    "Assessment Scope",
    "Authorization & Limitations",
    "Methodology",
    "Risk Overview",
    "Business Impact",
    "Compliance Mapping",
    "Findings Summary",
    "Evidence",
    "Remediation Plan",
    "Technical Appendix",
]

FORBIDDEN_TEXT = [
    "WSTG Scanner",
    "WSTG Dashboard",
    "Información",
    "Cabeceras",
    "Reporte",
    "Hallazgos",
    "Sin datos",
    "Riesgo",
    "enumeracion",
    "al generar",
    "whenapplicable",
    "auditorvalidation",
]

REQUIRED_COMPLIANCE_TEXT = [
    "Control mappings are indicative",
    "auditor validation",
    "internal audit-support references",
    "not certification results",
]

EXPECTED_SUFFIXES = [".html", ".txt", ".md"]


def print_result(ok, label):
    prefix = "PASS" if ok else "FAIL"
    print(f"{prefix}: {label}")


def section_exists(content, section):
    return section in content or section.replace("&", "&amp;") in content


def risk_zero_present(content, severity):
    patterns = [
        rf"\b{severity}\s*:\s*0\b",
        rf"\b{severity}\s+findings\s*:\s*0\b",
    ]
    return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)


def validate_file(path):
    failures = []
    content = path.read_text(encoding="utf-8", errors="replace")
    lower_content = content.lower()

    for section in REQUIRED_SECTIONS:
        if not section_exists(content, section):
            failures.append(f"{path.name}: missing required section '{section}'")

    for forbidden in FORBIDDEN_TEXT:
        if forbidden in content:
            failures.append(f"{path.name}: forbidden text present '{forbidden}'")

    if "AisoSec Audit" not in content:
        failures.append(f"{path.name}: missing required branding 'AisoSec Audit'")

    for old_brand in ("WSTG Scanner", "WSTG Dashboard"):
        if old_brand in content:
            failures.append(f"{path.name}: old product branding present '{old_brand}'")

    for marker, severity in (
        ("[LOW]", "Low"),
        ("[MEDIUM]", "Medium"),
        ("[HIGH]", "High"),
        ("[CRITICAL]", "Critical"),
    ):
        if marker in content and risk_zero_present(content, severity):
            failures.append(
                f"{path.name}: Findings Summary contains {marker} but Risk Overview reports {severity}: 0"
            )

    if section_exists(content, "Compliance Mapping"):
        for required in REQUIRED_COMPLIANCE_TEXT:
            if required.lower() not in lower_content:
                failures.append(
                    f"{path.name}: Compliance Mapping missing required text '{required}'"
                )

    return failures


def collect_report_files(report_dir):
    files_by_suffix = {}
    for suffix in EXPECTED_SUFFIXES:
        files_by_suffix[suffix] = sorted(
            path for path in report_dir.iterdir() if path.is_file() and path.suffix == suffix
        )
    return files_by_suffix


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 scripts/validate_report_quality.py <report-directory>")
        return 1

    report_dir = Path(argv[1])
    failures = []

    if not report_dir.exists():
        print_result(False, f"report directory exists: {report_dir}")
        print("FINAL STATUS: FAIL")
        return 1
    print_result(True, f"report directory exists: {report_dir}")

    if not report_dir.is_dir():
        print_result(False, f"path is a directory: {report_dir}")
        print("FINAL STATUS: FAIL")
        return 1
    print_result(True, f"path is a directory: {report_dir}")

    files_by_suffix = collect_report_files(report_dir)
    for suffix in EXPECTED_SUFFIXES:
        files = files_by_suffix[suffix]
        if files:
            print_result(True, f"found {suffix} report file(s): {len(files)}")
        else:
            message = f"missing required {suffix} report file"
            print_result(False, message)
            failures.append(message)

    for suffix in EXPECTED_SUFFIXES:
        for path in files_by_suffix[suffix]:
            file_failures = validate_file(path)
            if file_failures:
                for failure in file_failures:
                    print_result(False, failure)
                failures.extend(file_failures)
            else:
                print_result(True, f"{path.name}: report quality checks passed")

    if failures:
        print(f"FINAL STATUS: FAIL ({len(failures)} issue(s))")
        return 1

    print("FINAL STATUS: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
