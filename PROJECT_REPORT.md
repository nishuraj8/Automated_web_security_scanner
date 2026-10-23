# Project Report: Automated Web Security Scanner

## 1. Title
Automated Web Security Scanner Using Python and Flask

## 2. Abstract
Web applications rely on HTTP security headers and correctly configured transport security to reduce common browser-side risks. This project implements a lightweight scanner that checks selected response headers, HTTPS usage, basic CORS response configuration, and server-banner disclosure. A Flask dashboard displays the results and allows the user to export a CSV report. The tool is intended for learning and authorized configuration reviews; it does not replace a professional security assessment.

## 3. Objectives
- Learn how to make HTTP requests in Python.
- Understand common web security headers.
- Observe HTTPS and basic CORS response settings.
- Present scan findings through a simple web interface.
- Export findings into a portable report.

## 4. Technologies Used
- Python
- Flask
- Requests
- HTML and CSS
- CSV report generation

## 5. System Design
1. The user enters a URL in the dashboard.
2. The application validates the URL and rejects local/private destinations.
3. The scanner sends a limited HTTP GET request.
4. It inspects the final response URL and headers.
5. The checks are categorized as PASS, WARN, or INFO.
6. The dashboard displays results and offers a CSV download.

## 6. Security Checks
- HTTPS usage: whether the final URL uses HTTPS.
- HSTS: whether Strict-Transport-Security is present.
- Content Security Policy: whether Content-Security-Policy is present.
- MIME sniffing protection: whether X-Content-Type-Options is present.
- Clickjacking mitigation: whether X-Frame-Options is present.
- Referrer control: whether Referrer-Policy is present.
- Browser feature policy: whether Permissions-Policy is present.
- CORS observation: records Access-Control-Allow-Origin and notes potential review points.
- Server banner: notes whether the Server header is disclosed.

## 7. Implementation
The Flask application serves the form and result page. The scanner logic is separated into `scanner.py`, making the checks easier to test and maintain. The front end uses HTML and CSS for a responsive layout. The download route creates a CSV report from the most recent scan.

## 8. Testing Plan
Test only on a website you own or are explicitly authorized to scan.
- Valid public HTTPS URL: dashboard should display response status and header checks.
- URL without a scheme: application should try HTTPS by default.
- Empty URL: form should request a URL.
- Invalid or unresolvable hostname: a clear error should be shown.
- Local/private hostname: scan should be rejected.
- Download after a successful scan: CSV should contain target, timestamp, checks, statuses, and details.
- Download before any scan: application should explain that no report is available.

## 9. Limitations
- Checks only one basic GET response.
- Does not crawl links or test application workflows.
- Does not verify exploitability.
- CORS conclusions require context and browser testing.
- A missing security header is not always a vulnerability.
- Network and DNS edge cases are not fully mitigated; do not expose the local development server to the public internet.

## 10. Conclusion
The project provides a practical introduction to web security configuration reviews and Python-based web application development. It combines HTTP requests, basic security analysis, a dashboard, and report export in a small project suitable for a classroom demonstration.

## 11. Future Scope
- Save scan history to SQLite.
- Add JSON/PDF export.
- Create unit tests.
- Provide remediation suggestions per finding.
- Add a controlled lab mode for testing against intentionally vulnerable local applications.
