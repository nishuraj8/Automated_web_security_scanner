from flask import Flask, render_template, request, send_file
from scanner import scan_url
from datetime import datetime
import io
import csv

app = Flask(__name__)
last_report = None

@app.route("/", methods=["GET", "POST"])
def index():
    global last_report
    error = None
    report = None

    if request.method == "POST":
        target = request.form.get("url", "").strip()
        if not target:
            error = "Please enter a URL."
        else:
            try:
                report = scan_url(target)
                last_report = report
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "The scan could not be completed. Check the URL and your network connection."

    return render_template("index.html", report=report, error=error)

@app.route("/download")
def download_report():
    if not last_report:
        return "No scan report is available yet. Run a scan first.", 400

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Automated Web Security Scanner Report"])
    writer.writerow(["Target", last_report["target"]])
    writer.writerow(["Scanned at", last_report["scanned_at"]])
    writer.writerow([])
    writer.writerow(["Check", "Status", "Details"])
    for check in last_report["checks"]:
        writer.writerow([check["name"], check["status"], check["details"]])

    data = io.BytesIO(output.getvalue().encode("utf-8"))
    data.seek(0)
    filename = "security_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name=filename)

if __name__ == "__main__":
    # Local-only dashboard; do not expose this development server to the public internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
