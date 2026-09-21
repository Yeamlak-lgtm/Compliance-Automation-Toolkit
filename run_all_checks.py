"""
Compliance Automation Toolkit - Combined Report Runner
--------------------------------------------------------
Runs all control checks (IAM MFA, S3 Encryption, S3 Public Access) and
exports a single, clean HTML report - similar to a summary dashboard
you'd see in a tool like Vanta or Drata.

Requirements:
  pip install boto3
  AWS credentials configured locally (read-only IAM user recommended)

Usage:
  python run_all_checks.py
  (Generates report.html in the same folder and opens a summary in console)
"""

from datetime import datetime, timezone

from check_mfa import run_mfa_check
from Check_S3_encryption import run_s3_encryption_check
from check_S3_public_access import run_s3_public_access_check


def build_html_report(sections):
    """
    sections: list of dicts, each like:
      {
        "title": "IAM User MFA Enforcement",
        "controls": "NIST CSF PR.AC-07 | ISO 27001 A.9.4.2 | SOC2 CC6.1",
        "results": [ {label, status, detail}, ... ]
      }
    """
    run_time = datetime.now(timezone.utc).isoformat()
    total_checks = sum(len(s["results"]) for s in sections)
    total_pass = sum(1 for s in sections for r in s["results"] if r["status"] == "PASS")
    total_fail = total_checks - total_pass
    overall = "PASS" if total_fail == 0 else "ATTENTION NEEDED"
    overall_color = "#1a7f37" if total_fail == 0 else "#c62828"

    sections_html = ""
    for s in sections:
        rows = ""
        for r in s["results"]:
            color = "#1a7f37" if r["status"] == "PASS" else "#c62828"
            detail = f"<div class='detail'>{r['detail']}</div>" if r.get("detail") else ""
            rows += f"""
            <tr>
                <td>{r['label']}</td>
                <td><span class='badge' style='background:{color}'>{r['status']}</span>{detail}</td>
            </tr>"""
        sections_html += f"""
        <div class="section">
            <h2>{s['title']}</h2>
            <div class="controls">Mapped controls: {s['controls']}</div>
            <table>{rows}</table>
        </div>"""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Ariel Financial Services - Compliance Report</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background: #f6f8fa; margin: 0; padding: 40px; color: #24292f; }}
    .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    h1 {{ margin-top: 0; }}
    .meta {{ color: #57606a; font-size: 14px; margin-bottom: 24px; }}
    .overall {{ display: inline-block; padding: 8px 16px; border-radius: 6px; color: white; font-weight: bold; background: {overall_color}; margin-bottom: 24px; }}
    .section {{ margin-bottom: 28px; border-top: 1px solid #d0d7de; padding-top: 20px; }}
    .controls {{ color: #57606a; font-size: 13px; margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 8px 4px; border-bottom: 1px solid #eaeef2; font-size: 14px; }}
    .badge {{ color: white; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
    .detail {{ color: #57606a; font-size: 12px; margin-top: 4px; }}
    .summary {{ font-size: 14px; color: #57606a; margin-bottom: 8px; }}
</style>
</head>
<body>
<div class="container">
    <h1>Ariel Financial Services</h1>
    <div class="meta">Compliance Automation Report &bull; Generated {run_time}</div>
    <div class="overall">Overall status: {overall}</div>
    <div class="summary">{total_pass} of {total_checks} checks passed</div>
    {sections_html}
</div>
</body>
</html>"""


def main():
    mfa_results = run_mfa_check()
    encryption_results = run_s3_encryption_check()
    public_access_results = run_s3_public_access_check()

    sections = [
        {
            "title": "IAM User MFA Enforcement",
            "controls": "NIST CSF PR.AC-07 | ISO 27001 A.9.4.2 | SOC2 CC6.1",
            "results": [
                {"label": r["user"], "status": r["status"]}
                for r in mfa_results
            ],
        },
        {
            "title": "S3 Bucket Encryption",
            "controls": "NIST CSF PR.DS-01 | ISO 27001 A.8.24 | SOC2 CC6.1",
            "results": [
                {"label": r["bucket"], "status": r["status"]}
                for r in encryption_results
            ],
        },
        {
            "title": "S3 Bucket Public Access Block",
            "controls": "NIST CSF PR.AC-03 | ISO 27001 A.8.3 | SOC2 CC6.1",
            "results": [
                {
                    "label": r["bucket"],
                    "status": r["status"],
                    "detail": f"Missing: {', '.join(r['missing_settings'])}" if r["missing_settings"] else "",
                }
                for r in public_access_results
            ],
        },
    ]

    html = build_html_report(sections)
    with open("report.html", "w") as f:
        f.write(html)

    print("Report generated: report.html")
    print("Open it in your browser to view the full compliance dashboard.")


if __name__ == "__main__":
    main()