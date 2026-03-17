# AuditShield — NIST CSF 2.0 Cybersecurity Audit Platform

A full-featured cybersecurity audit platform for university IT systems, built with Flask and SQLite, following the NIST Cybersecurity Framework 2.0.

## Setup

```bash
cd audit_platform
pip install -r requirements.txt
python app.py
```

Visit: http://localhost:5000

## Demo Accounts

| Role     | Username | Password     |
|----------|----------|--------------|
| Admin    | admin    | admin123     |
| Auditor  | auditor  | auditor123   |
| Auditee  | auditee  | auditee123   |

## AI Feature (Ollama)

The AI Vulnerability Explainer requires Ollama:

```bash
# Install from https://ollama.com
ollama pull llama3.2
# Ollama runs on localhost:11434 by default
```

## Audit Workflow

1. **Organization** → Set up org profile (determines exposure level)
2. **Asset Inventory** → Register IT assets with CIA ratings
3. **Vulnerabilities** → Map OWASP/CWE vulnerabilities to assets
4. **Risk Assessment** → Review risk matrix and register
5. **Audit Checklist** → Assess 51 NIST CSF controls
6. **Evidence** → Upload evidence files per control
7. **Compliance** → View compliance scores by function
8. **Findings** → Auto-generate or add manual findings
9. **AI Explainer** → Get AI analysis of vulnerabilities
10. **Report** → Generate and export the full audit report

## Modules Implemented

-  Module 1: User & Role Management (Admin/Auditor/Auditee)
-  Module 2: Organization Profile with exposure determination
-  Module 3: Asset Inventory with CIA scores
-  Module 4: Threat & Vulnerability (OWASP pre-populated)
-  Module 5: Risk Assessment Engine (Risk = L × I)
-  Module 6: NIST CSF Control Audit Checklist (51 controls)
-  Module 7: Evidence Upload
-  Module 8: Compliance Scoring
-  Module 9: Audit Findings Generator
-  Module 10: AI Vulnerability Explainer (Ollama)
-  Module 11: Report Generator 
