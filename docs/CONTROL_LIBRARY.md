# AisoSec Audit — Control Library

## Purpose

The AisoSec Control Library defines internal audit-support control references used by AisoSec Audit reports.

These controls help map technical evidence to security, compliance and risk-management themes.

They are not certification results. They do not claim that a system is compliant or non-compliant.

All control mappings are indicative and require auditor validation.

## Control ID format

AISOSEC-[DOMAIN]-[NUMBER]

Examples:
- AISOSEC-WEB-001
- AISOSEC-CONFIG-001
- AISOSEC-COMP-001

## Control domains

| Domain | Meaning |
|---|---|
| WEB | Web application and public web exposure |
| CONFIG | Secure configuration and hardening |
| INFO | Public information exposure |
| DATA | Data minimization and exposure review |
| NET | Network and external service exposure |
| ASSET | Asset ownership and inventory |
| VM | Vulnerability management |
| TECH | Technology exposure inventory |
| API | API governance and security |
| CONTENT | Public content and publishing governance |
| COMP | Compliance and auditor validation |

## Initial controls

| Control ID | Control name | Typical evidence |
|---|---|---|
| AISOSEC-WEB-001 | HTTP Security Header Hardening | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| AISOSEC-CONFIG-001 | Secure Configuration Review | Missing recommended headers, exposed metadata, configuration hardening opportunities |
| AISOSEC-INFO-001 | Public Information Exposure Review | Exposed emails, metadata, information disclosure findings |
| AISOSEC-DATA-001 | Data Minimization and Public Exposure Review | Public email addresses, personal data exposure, public identifiers |
| AISOSEC-NET-001 | External Service Exposure Review | Open ports, public services, service banners |
| AISOSEC-ASSET-001 | Asset Inventory and Service Ownership Review | Public hosts, open ports, discovered services |
| AISOSEC-VM-001 | Vulnerability Management Triage | Nuclei findings, severity-classified findings |
| AISOSEC-TECH-001 | Technology Exposure Inventory | Frameworks, CDN fingerprints, server technologies, TLS metadata |
| AISOSEC-API-001 | API Authentication and Authorization Review | API endpoints, authorization-sensitive paths |
| AISOSEC-API-002 | API Rate Limiting and Abuse Prevention Review | Public API routes, rate limit observations |
| AISOSEC-WEB-002 | Public Path Exposure Review | Directory hits, public paths, discovered files |
| AISOSEC-CONTENT-001 | Content Publishing Governance Review | Static assets, public JavaScript, exposed documentation |
| AISOSEC-COMP-001 | Compliance Mapping Requires Auditor Validation | Any generated compliance mapping or framework reference |

## Important limitation

AisoSec control mappings are internal audit-support references.

They help organize evidence and remediation priorities, but they do not replace formal compliance audits, legal review, certified ISO audits, regulator assessments or signed penetration testing reports.
