"""
HorusShield V-8 Scanner — Report Generator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Builds PDF / HTML / JSON reports from findings produced by
web reconnaissance and assessment tools (via the AI Cortex).
Purely a document formatter — no scanning logic lives here.
"""
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

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
    """Custom FPDF generator for HorusShield V-8 Web Security Assessment Reports."""

    def __init__(self, target_url: str):
        super().__init__()
        self.target_url = target_url or "Unknown Target"
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    def cell(self, w=0, h=0, text="", *args, **kwargs):
        """Ensure all text passed to cell is Latin-1 safe."""
        safe_t = pdf_safe_text(text)
        return super().cell(w, h, safe_t, *args, **kwargs)

    def multi_cell(self, w=0, h=0, text="", *args, **kwargs):
        """Ensure all text passed to multi_cell is Latin-1 safe and defaults to clean line advance."""
        safe_t = pdf_safe_text(text)
        if "new_x" not in kwargs:
            kwargs["new_x"] = XPos.LMARGIN
        if "new_y" not in kwargs:
            kwargs["new_y"] = YPos.NEXT
        return super().multi_cell(w, h, safe_t, *args, **kwargs)

    def header(self):
        self.set_fill_color(5, 8, 20)
        self.rect(0, 0, self.w, 20, "F")
        self.set_text_color(0, 245, 255)
        self.set_font("Helvetica", "B", 10)
        self.set_y(5)
        self.cell(0, 6, "HORUSSHIELD V-8 SCANNER - WEB SECURITY ASSESSMENT", align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(100, 100, 120)
        self.set_font("Helvetica", "", 7)
        self.cell(0, 4, f"Target: {self.target_url}  |  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
                  align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(6)
        self.set_text_color(20, 20, 30)

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(5, 8, 20)
        self.rect(0, self.get_y(), self.w, 20, "F")
        self.set_text_color(0, 128, 160)
        self.set_font("Helvetica", "I", 7)
        self.cell(0, 6, f"SECURED BY HORUSSHIELD V-8 SCANNER  |  Page {self.page_no()}  |  Authorized Assessment Only",
                  align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 30)

    def section_title(self, text: str, num: int):
        self.ln(3)
        self.set_fill_color(5, 8, 20)
        self.set_text_color(0, 245, 255)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 9, f"  {num}. {text.upper()}", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 30)
        self.ln(2)

    def kv_row(self, label: str, value: Any, color: Optional[tuple] = None):
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(240, 242, 248)
        self.cell(50, 7, f"  {label}", fill=True, border="LTB")
        self.set_font("Helvetica", "", 9)
        self.set_fill_color(252, 252, 255)
        if color:
            self.set_text_color(*color)
        self.multi_cell(0, 7, f"  {value}", fill=True, border="RTB",
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 30)

    def finding_block(self, f: Dict[str, Any], idx: int):
        sev = (f.get("severity") or "info").lower()
        color = SEV_COLORS.get(sev, (0, 160, 220))
        self.set_font("Helvetica", "B", 10)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        finding_type = f.get("finding_type") or "Finding"
        header = f"  #{idx}  [{sev.upper()}]  {finding_type}"
        self.cell(0, 7, header, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(20, 20, 30)
        self.set_font("Helvetica", "", 8)
        self.ln(1)

        source_tool = f.get("source_tool") or "N/A"
        self.kv_row("Source Tool", source_tool.upper())

        if f.get("url"):
            self.kv_row("URL / Location", str(f.get("url"))[:120])
        if f.get("parameter"):
            self.kv_row("Parameter", str(f.get("parameter")))

        try:
            conf_val = float(f.get("confidence", 0) or 0)
            conf_str = f"{round(conf_val * 100)}%"
        except (ValueError, TypeError):
            conf_str = "N/A"
        self.kv_row("Confidence Score", conf_str)

        if f.get("owasp_category"):
            self.kv_row("OWASP Category", str(f.get("owasp_category")))
        if f.get("cwe_id"):
            self.kv_row("CWE", str(f.get("cwe_id")))

        if f.get("description"):
            self.set_font("Helvetica", "", 8)
            self.multi_cell(0, 5, f"  Description: {f.get('description')}",
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if f.get("evidence"):
            self.set_font("Helvetica", "", 8)
            self.multi_cell(0, 5, f"  Evidence: {f.get('evidence')}",
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if f.get("ai_explanation"):
            self.set_font("Helvetica", "I", 8)
            self.multi_cell(0, 5, f"  AI Analysis: {f.get('ai_explanation')}",
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if f.get("recommendation"):
            self.set_font("Helvetica", "B", 8)
            self.multi_cell(0, 5, f"  Recommended Mitigation: {f.get('recommendation')}",
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(3)


class VScanReportGenerator:
    def __init__(self):
        self.output_dir = config.VSCAN_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    # ── PDF ──

    def generate_pdf(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found")

        findings = db.get_vscan_findings(scan_id) or []
        target_url = scan.get("target_url") or "Unknown Target"

        pdf = V8PDF(target_url=target_url)
        pdf.add_page()

        pdf.section_title("Executive Summary", 1)
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            if sev in by_sev:
                by_sev[sev] += 1
            else:
                by_sev["info"] += 1

        tools = scan.get("tools_used") or ["nmap"]
        if isinstance(tools, str):
            try:
                tools = json.loads(tools)
            except Exception:
                tools = [tools]
        tools_str = ", ".join(tools).upper() if isinstance(tools, list) else str(tools).upper()

        pdf.kv_row("Target", target_url)
        pdf.kv_row("Tools Used", tools_str)
        pdf.kv_row("Scan Status", str(scan.get("status") or "UNKNOWN").upper())
        pdf.kv_row("Total Findings", str(len(findings)))
        pdf.kv_row("Critical", str(by_sev["critical"]), SEV_COLORS["critical"])
        pdf.kv_row("High", str(by_sev["high"]), SEV_COLORS["high"])
        pdf.kv_row("Medium", str(by_sev["medium"]), SEV_COLORS["medium"])
        pdf.kv_row("Low", str(by_sev["low"]), SEV_COLORS["low"])
        pdf.kv_row("Info", str(by_sev["info"]), SEV_COLORS["info"])

        pdf.section_title("Findings", 2)
        if not findings:
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 6, "No vulnerabilities or security misconfigurations reported for this target.",
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for i, f in enumerate(findings, start=1):
            pdf.finding_block(f, i)

        pdf.section_title("Scan Metadata", 3)
        pdf.kv_row("Scan ID", scan_id)
        pdf.kv_row("Started", str(scan.get("started_at") or "N/A"))
        pdf.kv_row("Finished", str(scan.get("finished_at") or "N/A"))
        pdf.kv_row("Active Scan Enabled", "Yes" if scan.get("active_scan") else "No")
        pdf.kv_row("Requested By", str(scan.get("requested_by") or "Anonymous"))

        safe_scan_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(scan_id))
        filename = f"vscan_{safe_scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        path = os.path.join(self.output_dir, filename)

        pdf.output(path)

        # Validate PDF signature
        with open(path, "rb") as fp:
            if not fp.read(4).startswith(b"%PDF"):
                raise ValueError(f"Generated file '{path}' is not a valid PDF")

        db.add_vscan_report(scan_id, "pdf", path)
        logger.info(f"V-8 Scanner PDF report generated successfully for scan {scan_id}: {path}")
        return path

    # ── HTML ──

    def generate_html(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found")
        findings = db.get_vscan_findings(scan_id) or []
        target_url = scan.get("target_url") or "Unknown Target"

        tools = scan.get("tools_used") or ["nmap"]
        if isinstance(tools, str):
            try:
                tools = json.loads(tools)
            except Exception:
                tools = [tools]
        tools_str = ", ".join(tools).upper() if isinstance(tools, list) else str(tools).upper()

        rows = "\n".join(
            f"""<tr>
                <td>{i}</td>
                <td class="sev-{(f.get('severity') or 'info').lower()}">{(f.get('severity') or 'info').upper()}</td>
                <td>{f.get('finding_type') or ''}</td>
                <td>{(f.get('source_tool') or '').upper()}</td>
                <td>{(f.get('url') or '')[:80]}</td>
                <td>{round(float(f.get('confidence', 0) or 0) * 100)}%</td>
                <td>{f.get('owasp_category') or ''}</td>
                <td>{f.get('cwe_id') or ''}</td>
            </tr>"""
            for i, f in enumerate(findings, start=1)
        )
        empty_row = '<tr><td colspan="8" style="text-align:center">No findings reported</td></tr>'
        content_rows = rows if findings else empty_row
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>V-8 Scanner Report — {target_url}</title>
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
<p><b>Target:</b> {target_url}<br>
<b>Tools:</b> {tools_str}<br>
<b>Status:</b> {str(scan.get('status') or '').upper()}<br>
<b>Findings:</b> {len(findings)}</p>
<table>
<tr><th>#</th><th>Severity</th><th>Type</th><th>Tool</th><th>URL</th><th>Confidence</th><th>OWASP</th><th>CWE</th></tr>
{content_rows}
</table>
<p style="margin-top:24px;color:#556;font-size:11px">SECURED BY HORUSSHIELD V-8 SCANNER — Authorized Assessment Only</p>
</body></html>"""

        safe_scan_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(scan_id))
        filename = f"vscan_{safe_scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(html)
        db.add_vscan_report(scan_id, "html", path)
        logger.info(f"V-8 Scanner HTML report generated successfully for scan {scan_id}: {path}")
        return path

    # ── JSON ──

    def generate_json(self, scan_id: str) -> str:
        scan = db.get_vscan(scan_id)
        if not scan:
            raise ValueError(f"Scan '{scan_id}' not found")
        findings = db.get_vscan_findings(scan_id, include_duplicates=True) or []
        payload = {"scan": scan, "findings": findings, "generated_at": datetime.now().isoformat()}

        safe_scan_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(scan_id))
        filename = f"vscan_{safe_scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, default=str)
        db.add_vscan_report(scan_id, "json", path)
        logger.info(f"V-8 Scanner JSON report generated successfully for scan {scan_id}: {path}")
        return path

    def generate(self, scan_id: str, fmt: str = "pdf") -> str:
        fmt = (fmt or "pdf").lower().strip()
        if fmt == "pdf":
            return self.generate_pdf(scan_id)
        if fmt == "html":
            return self.generate_html(scan_id)
        if fmt == "json":
            return self.generate_json(scan_id)
        raise ValueError(f"Unsupported report format: {fmt}")
