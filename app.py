import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort
from scanner import scan_target

app = Flask(__name__)
app.secret_key = "change-this-local-demo-secret"
DB_PATH = Path(__file__).with_name("scanner.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            findings_json TEXT NOT NULL,
            checks_json TEXT NOT NULL,
            counts_json TEXT NOT NULL,
            status_code INTEGER
        )""")
init_db()

def save_report(report):
    created = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    with db() as conn:
        cur = conn.execute("""INSERT INTO scans
            (created_at,url,score,findings_json,checks_json,counts_json,status_code)
            VALUES (?,?,?,?,?,?,?)""",
            (created, report["url"], report["score"], json.dumps(report["findings"]),
             json.dumps(report["checks"]), json.dumps(report["counts"]), report.get("status_code")))
        return cur.lastrowid, created

def get_scan(scan_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        abort(404)
    return {**dict(row), "findings": json.loads(row["findings_json"]),
            "checks": json.loads(row["checks_json"]), "counts": json.loads(row["counts_json"])}

@app.route("/")
def index():
    with db() as conn:
        rows = conn.execute("SELECT id,created_at,url,score,status_code FROM scans ORDER BY id DESC LIMIT 6").fetchall()
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        avg = conn.execute("SELECT AVG(score) FROM scans").fetchone()[0]
        all_rows = conn.execute("SELECT findings_json FROM scans").fetchall()
    severity_totals = {s: 0 for s in ("Critical","High","Medium","Low","Info")}
    for row in all_rows:
        try:
            for f in json.loads(row["findings_json"]):
                if f.get("severity") in severity_totals:
                    severity_totals[f["severity"]] += 1
        except (ValueError, TypeError):
            pass
    return render_template("index.html", recent=rows, total=total,
                           avg=round(avg or 0), severity_totals=severity_totals)

@app.route("/scan", methods=["POST"])
def scan():
    if request.form.get("authorized") != "yes":
        flash("Please confirm that you own the target or have permission to test it.", "error")
        return redirect(url_for("index"))
    target = request.form.get("url", "")
    try:
        report = scan_target(target)
        scan_id, created = save_report(report)
        return redirect(url_for("results", scan_id=scan_id))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/results/<int:scan_id>")
def results(scan_id):
    report = get_scan(scan_id)
    return render_template("results.html", report=report)

@app.route("/history")
def history():
    with db() as conn:
        scans = conn.execute("SELECT id,created_at,url,score,status_code FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("history.html", scans=scans)

@app.route("/export/<int:scan_id>.json")
def export_json(scan_id):
    report = get_scan(scan_id)
    payload = {k: report[k] for k in ("id","created_at","url","score","status_code","findings","checks","counts")}
    return Response(json.dumps(payload, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=security-scan-{scan_id}.json"})

@app.route("/export/<int:scan_id>.csv")
def export_csv(scan_id):
    report = get_scan(scan_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID","Date","URL","Score","Severity","Finding","Details","Recommendation"])
    for f in report["findings"]:
        writer.writerow([report["id"], report["created_at"], report["url"], report["score"],
                         f["severity"], f["title"], f["detail"], f["recommendation"]])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=security-scan-{scan_id}.csv"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
