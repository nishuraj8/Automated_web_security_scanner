# Automated Web Security Scanner

A beginner-friendly Python + Flask college project that checks basic website security configuration.

## Features
- Checks whether the final URL uses HTTPS.
- Checks for common security headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
- Reports basic observations about `Access-Control-Allow-Origin`.
- Notes whether a `Server` banner is disclosed.
- Shows results in a responsive web dashboard.
- Exports scan results to CSV.
- Rejects hostnames resolving to private/non-public IP addresses as a basic safety measure.

## Important limitations
This is an educational configuration checker, not a full vulnerability scanner or penetration test. A missing header does not automatically mean a website is vulnerable. CORS behavior depends on request/response context and browser enforcement. DNS rebinding and other network edge cases are not fully addressed, so use this only on authorized targets and do not expose the development server to the internet.

## Requirements
- Python 3.10 or newer
- Internet connection for scanning public sites

## Run on Windows
1. Extract the ZIP file.
2. Open a terminal in the project folder.
3. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```
4. Activate it:
   ```bash
   .venv\Scripts\activate
   ```
5. Install packages:
   ```bash
   pip install -r requirements.txt
   ```
6. Start the dashboard:
   ```bash
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser.

## Run on Linux/macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Suggested demonstration
Use a website you own or have permission to assess. Enter its URL, review the results, and download the CSV report.

## Project abstract
The Automated Web Security Scanner is a lightweight web application that checks selected HTTP security configuration indicators. It retrieves response headers from a user-provided public website, evaluates common security headers, records HTTPS usage, and provides a basic CORS observation. The results are presented through a responsive Flask dashboard and can be exported as a CSV report. The project demonstrates Python programming, HTTP requests, web application development, and introductory web security concepts.

## Future improvements
- Add JSON and PDF report export.
- Store scan history in SQLite.
- Add tests with mocked HTTP responses.
- Include CSP and HSTS configuration guidance.
- Add authenticated user accounts if deployed for a class demonstration.
