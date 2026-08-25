"""
HorusShield V-8 Scanner — Report Generator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Builds PDF / HTML / JSON reports from findings already produced by
OWASP ZAP, Nikto, and Nmap (via the AI Cortex). Purely a document
formatter — no scanning logic lives here.
"""
import json
import os
from datetime import datetime

from fpdf import FPDF, XPos, YPos

from config import active_config as config
from database.db_manager import db
from utils.helpers import pdf_safe_text
from utils.logger import get_logger

logger = get_logger("vscan_report_generator", "report")

SEV_COLORS = {
    "critical": (220, 30, 60),
    "high":     (255, 107, 53),
    "medium":   (255, 193, 7),
    "low":      (0, 200, 100),
    "info":     (0, 160, 220),
}


class V8PDF(FPDF):
    def __init__(self, target_url: str):
        super().__init__()
        self.target_url = target_url
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    def header(self):
        self.set_fill_color(5, 8, 20)
        self.rect(0, 0, 210, 20, "F")
        self.set_text_color(0, 245, 255)
        self.set_font("Arial", "B", 10)
        self.set_y(6)
        self.cell(0, 8, "HORUSSHIELD V-8 SCANNER - WEB SECURITY ASSESSMENT", align="C")
        self.set_text_color(100, 100, 120)
        self.set_font("Arial", "", 7)
        self.ln(2)
        self.cell(0, 4, pdf_safe_text(f"Target: {self.target_url}  |  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}"), align="C")
        self.ln(8)
        self.set_text_color(20, 20, 30)

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(5, 8, 20)
        self.rect(0, self.get_y(), 210, 20, "F")
        self.set_text_color(0, 128, 160)
        self.set_font("Arial", "I", 7)
        self.cell(0, 6, f"SECURED BY HORUSSHIELD V-8 SCANNER  |  Page {self.page_no()}  |  Authorized Assessment Only", align="C")
        self.set_text_color(20, 20, 30)

    def section_title(self, text, num):
        self.ln(4)
        self.set_fill_color(5, 8, 20)
        self.set_text_color(0, 245, 255)
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, f"  {num}. {text.upper()}", fill=True, ln=True)
        self.set_text_color(20, 20, 30)
        self.ln(2)

    def kv_row(self, label, value, color=None):
        self.set_font("Arial", "B", 9)
        self.set_fill_color(240, 242, 248)
        self.cell(50, 7, f"  {pdf_safe_text(label)}", fill=True, border="LTB")
        self.set_font("Arial", "", 9)
        self.set_fill_color(252, 252, 255)
        if color:
            self.set_text_color(*color)
        # multi_cell's default new_x is XPos.RIGHT (cursor stays at the right
        # edge of the cell just drawn) rather than back at the left margin —
        # without new_x=LMARGIN/new_y=NEXT here, the *next* kv_row's label
        # cell starts near the page's right edge with ~0 width left, which
        # fpdf2 raises as "Not enough horizontal space to render a single
        # character". Explicit is correct here; relying on the default isn't.
        self.multi_cell(0, 7, f"  {pdf_safe_text(value)}", fill=True, border="RTB",
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 30)

    def finding_block(self, f, idx):
        color = SEV_COLORS.get(f.get("severity", "info"), (0, 160, 220))
        self.set_font("Arial", "B", 10)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        header = pdf_safe_text(f"  #{idx}  [{f.get('severity','info').upper()}]  {f.get('finding_type','Finding')}")
        self.cell(0, 7, header, fill=True, ln=True)
        self.set_text_color(20, 20, 30)
        self.set_font("Arial", "", 8)
        self.ln(1)
        self.kv_row("Source Tool", f.get("source_tool", "").upper())
        if f.get("url"):
            self.kv_row("URL / Location", f.get("url", "")[:120])
        if f.get("parameter"):
            self.kv_row("Parameter", f.get("parameter", ""))
        self.kv_row("Confidence Score", f"{round(float(f.get('confidence', 0)) * 100)}%")
        if f.get("owasp_category"):
            self.kv_row("OWASP Category", f.get("owasp_category", ""))
        if f.get("cwe_id"):
            self.kv_row("CWE", f.get("cwe_id", ""))
        if f.get("ai_explanation"):
            self.set_font("Arial", "I", 8)
            self.multi_cell(0, 5, pdf_safe_text(f"  AI Analysis: {f.get('ai_explanation','')}"))
        if f.get("recommendation"):
            self.set_font("Arial", "B", 8)
            self.multi_cell(0, 5, pdf_safe_text(f"  Recommended Mitigation: {f.get('recommendation','')}"))
        self.ln(3)


class VScanReportGenerator:
    def __init__(self):
        self.output_dir = config.VSCAN_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    # ── PDF ──

    def generate_pdf(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        findings = db.get_vscan_findings(scan_id)

        pdf = V8PDF(target_url=scan["target_url"])
        pdf.add_page()

        pdf.section_title("Executive Summary", 1)
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f.get("severity") in by_sev:
                by_sev[f["severity"]] += 1
        pdf.kv_row("Target", scan["target_url"])
        pdf.kv_row("Tools Used", ", ".join(scan.get("tools_used", [])).upper())
        pdf.kv_row("Scan Status", scan.get("status", "").upper())
        pdf.kv_row("Total Findings", str(len(findings)))
        pdf.kv_row("Critical", str(by_sev["critical"]), SEV_COLORS["critical"])
        pdf.kv_row("High", str(by_sev["high"]), SEV_COLORS["high"])
        pdf.kv_row("Medium", str(by_sev["medium"]), SEV_COLORS["medium"])
        pdf.kv_row("Low", str(by_sev["low"]), SEV_COLORS["low"])

        pdf.section_title("Findings", 2)
        if not findings:
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(0, 6, "No findings were reported by the selected tools for this target.")
        for i, f in enumerate(findings, start=1):
            pdf.finding_block(f, i)

        pdf.section_title("Scan Metadata", 3)
        pdf.kv_row("Scan ID", scan_id)
        pdf.kv_row("Started", str(scan.get("started_at", "")))
        pdf.kv_row("Finished", str(scan.get("finished_at", "")))
        pdf.kv_row("Active Scan Enabled", "Yes" if scan.get("active_scan") else "No")

        filename = f"vscan_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        path = os.path.join(self.output_dir, filename)
        pdf.output(path)
        db.add_vscan_report(scan_id, "pdf", path)
        return path

    # ── HTML ──

    def generate_html(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        findings = db.get_vscan_findings(scan_id)

        rows = "\n".join(
            f"""<tr>
                <td>{i}</td>
                <td class="sev-{f.get('severity','info')}">{f.get('severity','info').upper()}</td>
                <td>{f.get('finding_type','')}</td>
                <td>{f.get('source_tool','').upper()}</td>
                <td>{(f.get('url','') or '')[:80]}</td>
                <td>{round(float(f.get('confidence',0))*100)}%</td>
                <td>{f.get('owasp_category','')}</td>
                <td>{f.get('cwe_id','')}</td>
            </tr>"""
            for i, f in enumerate(findings, start=1)
        )
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>V-8 Scanner Report — {scan['target_url']}</title>
<style>
body{{background:#050814;color:#e8ecf5;font-family:'Segoe UI',Arial,sans-serif;padding:24px}}
h1{{color:#00f5ff}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th,td{{padding:8px;border:1px solid #1f2940;text-align:left;font-size:13px}}
th{{background:#0d1326;color:#00f5ff}}
.sev-critical{{color:#dc1e3c;font-weight:bold}}
.sev-high{{color:#ff6b35;font-weight:bold}}
.sev-medium{{color:#ffc107}}
.sev-low{{color:#00c864}}
.sev-info{{color:#00a0dc}}
</style></head><body>
<h1>HorusShield V-8 Scanner Report</h1>
<p><b>Target:</b> {scan['target_url']}<br>
<b>Tools:</b> {', '.join(scan.get('tools_used', [])).upper()}<br>
<b>Status:</b> {scan.get('status','').upper()}<br>
<b>Findings:</b> {len(findings)}</p>
<table>
<tr><th>#</th><th>Severity</th><th>Type</th><th>Tool</th><th>URL</th><th>Confidence</th><th>OWASP</th><th>CWE</th></tr>
{rows}
</table>
<p style="margin-top:24px;color:#556;font-size:11px">SECURED BY HORUSSHIELD V-8 SCANNER — Authorized Assessment Only</p>
</body></html>"""

        filename = f"vscan_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(html)
        db.add_vscan_report(scan_id, "html", path)
        return path

    # ── JSON ──

    def generate_json(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError("Scan not found")
        findings = db.get_vscan_findings(scan_id, include_duplicates=True)
        payload = {"scan": scan, "findings": findings, "generated_at": datetime.now().isoformat()}

        filename = f"vscan_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, default=str)
        db.add_vscan_report(scan_id, "json", path)
        return path

    def generate(self, scan_id: str, fmt: str = "pdf") -> str:
        fmt = (fmt or "pdf").lower()
        if fmt == "pdf":
            return self.generate_pdf(scan_id)
        if fmt == "html":
            return self.generate_html(scan_id)
        if fmt == "json":
            return self.generate_json(scan_id)
        raise ValueError(f"Unsupported report format: {fmt}")
