# Web Vulnerability Scanner & Security Dashboard

A local educational web security scanner with a dashboard, scan history, findings severity summaries, and JSON/CSV exports.

## Safety and scope
- Use only against websites you own or have explicit written permission to test.
- The scanner intentionally performs **low-impact checks** only: HTTP security headers, cookie flags, TLS certificate validity (HTTPS), server banner disclosure, mixed content hints, and a small set of common public files (robots.txt, security.txt, sitemap.xml).
- It does not exploit vulnerabilities, brute-force credentials, crawl authenticated areas, or run destructive payloads.
- Scanning a public site without permission may violate its terms or applicable law.

## Requirements
- Python 3.10+
- Internet access for the target URL (and pip install, once)

## Run on Windows (PowerShell)
```powershell
cd Web_Vulnerability_Scanner
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run on macOS/Linux
```bash
cd Web_Vulnerability_Scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## How to use
1. Open the dashboard.
2. Enter an HTTPS or HTTP URL for a site you own / are authorized to assess.
3. Confirm the authorization checkbox.
4. Click **Start Scan**. Results are saved in `scanner.db`.
5. Open Scan History to view previous scans or export a report.

## What is checked
- Security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security (HTTPS only)
- HTTPS certificate verification and HTTP-to-HTTPS redirect behavior
- Cookie flags: Secure, HttpOnly, SameSite (when cookies are observed)
- Server header disclosure
- Mixed content indicators in returned HTML
- Presence of robots.txt, security.txt, sitemap.xml

## Limitations
This is a starter project, not a replacement for professional testing or tools such as OWASP ZAP. Results are heuristics and may contain false positives/negatives. Only the initial response is inspected; it does not execute JavaScript or authenticate. Use a staging environment for authorized tests.

## Project structure
```
Web_Vulnerability_Scanner/
├── app.py
├── scanner.py
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   └── history.html
└── static/
    ├── css/style.css
    └── js/dashboard.js
```
