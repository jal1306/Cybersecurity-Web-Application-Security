import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort, make_response
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from xml.sax.saxutils import escape
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

@app.route("/export/<int:scan_id>.pdf")
def export_pdf(scan_id):
    """Generate a downloadable PDF report for a saved scan."""
    report = get_scan(scan_id)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
        topMargin=18*mm, bottomMargin=18*mm,
        title=f"Website Security Scan #{report['id']}",
        author="Web Vulnerability Scanner & Security Dashboard"
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"],
                              fontSize=21, leading=26, textColor=colors.HexColor("#172554"),
                              alignment=TA_LEFT, spaceAfter=5*mm))
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"],
                              fontSize=13, leading=16, textColor=colors.HexColor("#1d4ed8"),
                              spaceBefore=5*mm, spaceAfter=2*mm))
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["BodyText"],
                              fontSize=8.5, leading=11, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=8, leading=10))
    story = []
    story.append(Paragraph("Website Security Scan Report", styles["ReportTitle"]))
    story.append(Paragraph("Web Vulnerability Scanner &amp; Security Dashboard", styles["Normal"]))
    story.append(Spacer(1, 5*mm))
    summary = [
        ["Scan ID", f"#{report['id']}", "Security score", f"{report['score']}/100"],
        ["Target URL", Paragraph(escape(str(report['url'])), styles["Cell"]), "HTTP status", str(report.get("status_code") or "TLS / connection error")],
        ["Scan date", Paragraph(escape(str(report['created_at'])), styles["Cell"]), "Findings", str(len(report["findings"]))],
    ]
    summary_table = Table(summary, colWidths=[25*mm, 62*mm, 28*mm, 42*mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#eff6ff")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#eff6ff")),
        ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (2,0), (2,-1), colors.HexColor("#1e3a8a")),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#dbeafe")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 7), ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story.append(summary_table)
    story.append(Paragraph("Severity Summary", styles["SectionHeading"]))
    severity = [["Severity", "Count"]]
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        severity.append([sev, str(report["counts"].get(sev, 0))])
    sev_table = Table(severity, colWidths=[50*mm, 25*mm], repeatRows=1)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(sev_table)
    story.append(Paragraph("Findings and Recommendations", styles["SectionHeading"]))
    if report["findings"]:
        for i, finding in enumerate(report["findings"], 1):
            content = [
                Paragraph(f"<b>{i}. [{escape(str(finding.get('severity','Info')))}] {escape(str(finding.get('title','Finding')))}</b>", styles["BodyText"]),
                Spacer(1, 1.5*mm),
                Paragraph(f"<b>Details:</b> {escape(str(finding.get('detail','')))}", styles["SmallBody"]),
                Spacer(1, 1.5*mm),
                Paragraph(f"<b>Recommendation:</b> {escape(str(finding.get('recommendation','')))}", styles["SmallBody"]),
                Spacer(1, 3*mm),
            ]
            story.append(KeepTogether(content))
    else:
        story.append(Paragraph("No findings were reported by the configured checks. This does not prove the website is secure.", styles["BodyText"]))
    story.append(Paragraph("Checks Performed", styles["SectionHeading"]))
    check_rows = [["Check", "Status", "Details"]]
    for check in report["checks"]:
        check_rows.append([
            Paragraph(escape(str(check.get("name", ""))), styles["Cell"]),
            Paragraph(escape(str(check.get("status", "unknown")).upper()), styles["Cell"]),
            Paragraph(escape(str(check.get("detail", ""))), styles["Cell"]),
        ])
    if len(check_rows) > 1:
        checks_table = Table(check_rows, colWidths=[43*mm, 22*mm, 100*mm], repeatRows=1)
        checks_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
            ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5),
            ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(checks_table)
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Scope and Disclaimer", styles["SectionHeading"]))
    story.append(Paragraph(
        "This report reflects only the low-impact checks implemented by this educational scanner at the time of the scan. "
        "Results may include false positives or false negatives and are not a comprehensive penetration test. "
        "Test only systems you own or are explicitly authorized to assess.", styles["SmallBody"]))

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#dbeafe"))
        canvas.line(18*mm, 13*mm, A4[0]-18*mm, 13*mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(18*mm, 8*mm, "Web Vulnerability Scanner — Educational Report")
        canvas.drawRightString(A4[0]-18*mm, 8*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    response = make_response(buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=security-scan-{scan_id}.pdf"
    return response


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
