"""Generate the main HorusShield security posture report.

This module formats telemetry already collected by HorusShield. It does not
start scans or create synthetic security findings for presentation.
"""

import os
import re
from collections import Counter
from datetime import datetime, timedelta

from fpdf import FPDF

from config import active_config as config
from database.db_manager import db
from utils.helpers import pdf_safe_text
from utils.logger import get_logger

logger = get_logger("report_generator", "report")

SEV_COLORS = {
    "critical": (220, 30, 60),
    "high": (220, 90, 35),
    "medium": (190, 130, 0),
    "low": (0, 145, 90),
    "info": (0, 120, 180),
}
NAVY = (5, 8, 20)
INK = (25, 30, 42)
MUTED = (90, 100, 116)
PALE = (242, 245, 249)
PERIOD_HOURS = 24


def _text(value, fallback="Data unavailable"):
    if value is None or value == "":
        return fallback
    return str(value)


def _number(value, digits=0):
    if value is None:
        return "Data unavailable"
    try:
        return f"{float(value):,.{digits}f}"
    except (TypeError, ValueError):
        return _text(value)


def _severity(value):
    value = str(value or "info").lower()
    return value if value in SEV_COLORS else "info"


class HorusPDF(FPDF):
    """Compact report canvas with a restrained HorusShield visual system."""

    def __init__(self, report_id, facility_name="Facility"):
        super().__init__()
        self.report_id = report_id
        self.facility = facility_name
        self.generated = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(16, 25, 16)

    def cell(self, w=0, h=0, text="", *args, **kwargs):
        return super().cell(w, h, pdf_safe_text(text), *args, **kwargs)

    def multi_cell(self, w=0, h=0, text="", *args, **kwargs):
        return super().multi_cell(w, h, pdf_safe_text(text), *args, **kwargs)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*NAVY)
        self.rect(0, 0, 210, 16, "F")
        self.set_text_color(0, 210, 225)
        self.set_font("Helvetica", "B", 8)
        self.set_y(5)
        self.cell(110, 5, "HORUSSHIELD 2.0  |  CYBERSECURITY OPERATIONS", align="L")
        self.set_text_color(130, 145, 165)
        self.set_font("Helvetica", "", 7)
        self.cell(68, 5, self.generated, align="R")
        self.set_text_color(*INK)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(210, 216, 224)
        self.line(16, self.get_y(), 194, self.get_y())
        self.set_text_color(*MUTED)
        self.set_font("Helvetica", "", 7)
        self.set_x(16)
        self.cell(0, 7, f"HORUSSHIELD 2.0  |  {self.report_id}  |  Page {self.page_no()}  |  {self.generated}", align="C")
        self.set_text_color(*INK)

    def report_title(self, text, subtitle=None):
        self.ln(2)
        self.set_fill_color(*NAVY)
        self.set_text_color(0, 210, 225)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 9, f"  {text.upper()}", fill=True, ln=True)
        if subtitle:
            self.set_text_color(*MUTED)
            self.set_font("Helvetica", "", 8)
            self.cell(0, 6, subtitle, ln=True)
        self.set_text_color(*INK)
        self.ln(2)

    def section(self, text):
        self.set_fill_color(225, 231, 238)
        self.set_text_color(*NAVY)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 7, f"  {text.upper()}", fill=True, ln=True)
        self.set_text_color(*INK)
        self.ln(1)

    def note(self, text, color=MUTED):
        self.set_text_color(*color)
        self.set_font("Helvetica", "I", 8)
        self.set_x(16)
        self.multi_cell(0, 5, text)
        self.set_text_color(*INK)

    def kv(self, label, value, color=None):
        self.set_fill_color(*PALE)
        self.set_font("Helvetica", "B", 8)
        self.cell(55, 7, f"  {label}", fill=True, border="LTB")
        self.set_font("Helvetica", "", 8)
        if color:
            self.set_text_color(*color)
        self.cell(0, 7, f"  {_text(value)}", fill=True, border="RTB", ln=True)
        self.set_text_color(*INK)

    def table(self, headers, rows, widths):
        self.set_fill_color(*NAVY)
        self.set_text_color(0, 210, 225)
        self.set_font("Helvetica", "B", 7)
        for width, header in zip(widths, headers):
            self.cell(width, 7, header, fill=True, border=1)
        self.ln()
        self.set_text_color(*INK)
        self.set_font("Helvetica", "", 7)
        for row in rows:
            if self.get_y() > 260:
                self.add_page()
                self.set_fill_color(*NAVY)
                self.set_text_color(0, 210, 225)
                self.set_font("Helvetica", "B", 7)
                for width, header in zip(widths, headers):
                    self.cell(width, 7, header, fill=True, border=1)
                self.ln()
                self.set_text_color(*INK)
                self.set_font("Helvetica", "", 7)
            for width, value in zip(widths, row):
                self.set_fill_color(250, 251, 253)
                self.cell(width, 6, _text(value, "-"), fill=True, border=1)
            self.ln()

    def metric_grid(self, metrics):
        width = 44.5
        for index, (label, value, color) in enumerate(metrics):
            self.set_fill_color(*PALE)
            self.set_text_color(*MUTED)
            self.set_font("Helvetica", "B", 7)
            self.cell(width, 6, label.upper(), fill=True, border="LTR")
            self.ln()
            self.set_text_color(*(color or NAVY))
            self.set_font("Helvetica", "B", 14)
            self.cell(width, 10, _text(value), fill=True, border="LBR")
            if index % 4 == 3:
                self.ln(2)
        if len(metrics) % 4:
            self.ln(2)
        self.set_text_color(*INK)


class ReportGenerator:
    def __init__(self):
        self.output_dir = config.REPORT_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_daily_report(self, facility_name="Facility", language="en"):
        now = datetime.utcnow()
        period_start = now - timedelta(hours=PERIOD_HOURS)
        report_id = f"HS-{now.strftime('%Y%m%d-%H%M%S')}"
        safe_facility = re.sub(r"[^A-Za-z0-9 _-]", "", str(facility_name or "Facility")).strip() or "Facility"
        filename = f"HorusPosture_{re.sub(r'[^A-Za-z0-9_-]', '_', safe_facility)}_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        try:
            data = self._collect_data()
            pdf = HorusPDF(report_id, safe_facility)
            self._cover(pdf, data, report_id, safe_facility, now, period_start)
            self._executive(pdf, data, now, period_start)
            self._threats(pdf, data, period_start)
            self._network(pdf, data)
            self._devices(pdf, data)
            self._intelligence(pdf, data)
            self._defenses(pdf, data)
            self._findings(pdf, data)
            self._health_and_controls(pdf, data)
            self._quality(pdf, data, now, period_start)
            pdf.output(filepath)
            logger.info("General posture report generated: %s", filepath)
            return filepath
        except Exception as exc:
            logger.error("Report generation failed: %s", exc, exc_info=True)
            return None

    def _collect_data(self):
        try:
            score = db.get_latest_score()
        except Exception:
            score = None
        try:
            traffic_history = db.get_traffic_history(minutes=PERIOD_HOURS * 60)
        except Exception:
            traffic_history = []
        try:
            attacks = db.get_attacks(limit=1000)
        except Exception:
            attacks = []
        try:
            alerts = db.get_alerts(limit=1000)
        except Exception:
            alerts = []
        try:
            devices = db.get_all_devices()
        except Exception:
            devices = []
        try:
            honeypot_events = db.get_honeypot_events(limit=1000)
            honeypot_stats = db.get_honeypot_stats()
        except Exception:
            honeypot_events, honeypot_stats = [], {}
        try:
            mesh = db.get_mesh_topology()
        except Exception:
            mesh = {"nodes": [], "edges": []}
        try:
            predictions = db.get_recent_predictions(limit=100)
        except Exception:
            predictions = []
        try:
            audit = db.get_audit_log(limit=1000)
        except Exception:
            audit = []
        try:
            system = self._system_overview()
        except Exception:
            system = {}
        latest = traffic_history[-1] if traffic_history else None
        if latest is None:
            try:
                latest = db.get_latest_traffic() or {}
            except Exception:
                latest = {}
        return {"score": score, "traffic": traffic_history, "latest_traffic": latest, "attacks": attacks, "alerts": alerts, "devices": devices, "honeypot_events": honeypot_events, "honeypot_stats": honeypot_stats, "mesh": mesh, "predictions": predictions, "audit": audit, "system": system}

    @staticmethod
    def _system_overview():
        from services.system_monitor import system_monitor_service
        return system_monitor_service.get_system_overview()

    @staticmethod
    def _in_period(item, period_start):
        value = item.get("created_at") or item.get("timestamp") or item.get("started_at")
        if not value:
            return False
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed.replace(tzinfo=None) >= period_start
        except (TypeError, ValueError):
            return False

    def _cover(self, pdf, data, report_id, facility, now, period_start):
        pdf.add_page()
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.set_text_color(0, 210, 225)
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_y(48)
        pdf.cell(0, 14, "HORUSSHIELD 2.0", align="C", ln=True)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(245, 248, 252)
        pdf.cell(0, 10, "CYBERSECURITY SECURITY POSTURE REPORT", align="C", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(150, 170, 190)
        pdf.cell(0, 8, "Security Assessment & Threat Intelligence Report", align="C", ln=True)
        pdf.ln(25)
        score = data["score"].get("total_score") if data["score"] else None
        active = len([a for a in data["attacks"] if a.get("status") == "active" and self._in_period(a, period_start)])
        pdf.set_fill_color(12, 20, 38)
        pdf.rect(26, 126, 158, 57, "F")
        pdf.set_text_color(150, 170, 190)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_xy(38, 137)
        pdf.cell(64, 6, "OVERALL SECURITY SCORE")
        pdf.cell(64, 6, "ACTIVE THREATS")
        pdf.set_xy(38, 145)
        pdf.set_text_color(0, 210, 225)
        pdf.set_font("Helvetica", "B", 24)
        pdf.cell(64, 14, f"{_number(score)}/100" if score is not None else "Unavailable")
        pdf.set_text_color((220, 80, 80) if active else (70, 210, 140))
        pdf.cell(64, 14, str(active))
        pdf.set_text_color(150, 170, 190)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(38, 166)
        pdf.cell(128, 6, f"Report ID: {report_id}")
        pdf.set_xy(38, 174)
        pdf.cell(128, 6, f"Reporting period: {period_start.strftime('%Y-%m-%d %H:%M')} UTC to {now.strftime('%Y-%m-%d %H:%M')} UTC")
        pdf.set_y(222)
        pdf.set_text_color(150, 170, 190)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, f"Host: {data.get('system', {}).get('system', {}).get('hostname', 'Data unavailable')}", align="C", ln=True)
        pdf.cell(0, 6, f"Operating system: {data.get('system', {}).get('system', {}).get('os', 'Data unavailable')}", align="C", ln=True)
        pdf.cell(0, 6, f"Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}  |  Facility: {facility}", align="C", ln=True)
        pdf.set_text_color(*INK)

    def _executive(self, pdf, data, now, period_start):
        pdf.add_page()
        pdf.report_title("01  Executive Security Summary", "Observed telemetry and analysis for the reporting period")
        attacks = [a for a in data["attacks"] if self._in_period(a, period_start)]
        alerts = [a for a in data["alerts"] if self._in_period(a, period_start)]
        devices = data["devices"]
        score = data["score"].get("total_score") if data["score"] else None
        active = len([a for a in attacks if a.get("status") == "active"])
        network_status = "Observed" if data["traffic"] else "Data unavailable"
        pdf.metric_grid([("Score", f"{_number(score)}/100" if score is not None else None, (0, 150, 190)), ("Threats", len(attacks), None), ("Active", active, SEV_COLORS["critical"] if active else (0, 145, 90)), ("Events", len(alerts), None), ("Devices", len(devices), None), ("Network", network_status, None), ("Monitoring", "Active", (0, 145, 90)), ("Mesh nodes", len(data["mesh"].get("nodes", [])), None)])
        pdf.section("Security assessment summary")
        if attacks or alerts:
            pdf.multi_cell(0, 5, f"HorusShield recorded {len(attacks)} attack record(s) and {len(alerts)} alert event(s) during the reporting period. {active} attack record(s) are currently marked active. These are observed records, not a guarantee of system security.")
        else:
            pdf.multi_cell(0, 5, "No attack or alert records were found during the reporting period. This indicates no recorded events in the available telemetry; it does not prove zero risk.")
        pdf.ln(3)
        pdf.section("Score composition")
        score = data["score"]
        if not score:
            pdf.note("Score composition unavailable: no persisted security score snapshot was available.")
        else:
            components = score.get("components") or {}
            fields = [("Device security", score.get("device_security")), ("Network health", score.get("network_health")), ("Attack history", score.get("attack_history")), ("Vulnerability exposure", score.get("vulnerability_exposure")), ("AI confidence", score.get("ai_confidence"))]
            rows = [(label, _number(value), "Recorded") for label, value in fields if value is not None and float(value or 0) != 0]
            rows += [(str(key), _number(value), "Recorded") for key, value in components.items() if isinstance(value, (int, float))]
            self._rows_or_empty(pdf, ["Category", "Score", "Evidence"], rows, [75, 35, 68], "No category-level score factors were recorded.")

    def _threats(self, pdf, data, period_start):
        pdf.add_page()
        pdf.report_title("02  Threat Landscape", "Attack records, severity, categories, and event chronology")
        attacks = [a for a in data["attacks"] if self._in_period(a, period_start)]
        by_sev = Counter(_severity(a.get("severity")) for a in attacks)
        pdf.metric_grid([("Total", len(attacks), None), ("Active", sum(a.get("status") == "active" for a in attacks), SEV_COLORS["critical"]), ("Critical", by_sev["critical"], SEV_COLORS["critical"]), ("High", by_sev["high"], SEV_COLORS["high"]), ("Medium", by_sev["medium"], SEV_COLORS["medium"]), ("Low", by_sev["low"], SEV_COLORS["low"]), ("Resolved", sum(a.get("status") in ("mitigated", "resolved") for a in attacks), (0, 145, 90)), ("Categories", len(set(a.get("attack_type") for a in attacks)), None)])
        pdf.section("Observed threat records")
        rows = [(_text(attack.get("attack_type"), "Unknown"), _severity(attack.get("severity")).upper(), _text(attack.get("source_ip")), _text(attack.get("detected_by")), _text(attack.get("status")), _text(attack.get("created_at"))[:16]) for attack in attacks[:40]]
        self._rows_or_empty(pdf, ["Type", "Severity", "Source", "Method", "Status", "Detected"], rows, [35, 22, 38, 25, 25, 33], "NO THREATS RECORDED\nNo attack records were found during this reporting period.")
        pdf.section("Threat activity")
        if attacks:
            categories = Counter(_text(a.get("attack_type"), "Unknown") for a in attacks)
            self._rows_or_empty(pdf, ["Observed category", "Records", "Share of recorded threats"], [(key, count, f"{count / len(attacks) * 100:.1f}%") for key, count in categories.most_common()], [78, 35, 40], "No threat categories recorded.")
        else:
            pdf.note("No timeline or distribution is shown because there are no threat records to chart.")

    def _network(self, pdf, data):
        pdf.add_page()
        pdf.report_title("03  Network Security Analysis", "Telemetry snapshots collected by the network monitor")
        latest = data["latest_traffic"]
        if not latest:
            pdf.note("No network traffic snapshots were recorded. Network metrics, protocol distribution, and anomalies are unavailable.")
            return
        pdf.metric_grid([("Bytes in", _number(latest.get("bytes_in")), None), ("Bytes out", _number(latest.get("bytes_out")), None), ("Packets in", _number(latest.get("packets_in")), None), ("Packets out", _number(latest.get("packets_out")), None), ("Connections", _number(latest.get("active_connections")), None), ("Bandwidth Mbps", _number(latest.get("bandwidth_mbps"), 2), None), ("Unique sources", _number(latest.get("unique_src_ips")), None), ("Unique ports", _number(latest.get("unique_ports")), None)])
        pdf.section("Protocol distribution")
        protocol_fields = [("TCP", latest.get("tcp_count")), ("UDP", latest.get("udp_count")), ("ICMP", latest.get("icmp_count")), ("Other", latest.get("other_count"))]
        protocol_rows = [(name, _number(value), "Recorded") for name, value in protocol_fields if value is not None and float(value or 0) > 0]
        self._rows_or_empty(pdf, ["Protocol", "Count", "Source"], protocol_rows, [70, 45, 68], "No protocol data recorded.")
        pdf.section("Traffic timeline")
        rows = [(_text(item.get("timestamp"))[:16], _number(item.get("bandwidth_mbps"), 2), _number(item.get("active_connections")), _number(item.get("packets_in")), _number(item.get("packets_out"))) for item in data["traffic"][-30:]]
        self._rows_or_empty(pdf, ["Timestamp", "Bandwidth Mbps", "Connections", "Packets in", "Packets out"], rows, [35, 37, 37, 35, 34], "No traffic history recorded.")
        pdf.note("Traffic volume is operational telemetry. It is not classified as malicious without a corresponding recorded security event.")

    def _devices(self, pdf, data):
        pdf.add_page()
        pdf.report_title("04  Device Security", "Current inventory state from the device registry")
        devices = data["devices"]
        counts = Counter(_text(d.get("status"), "unknown").lower() for d in devices)
        pdf.metric_grid([("Total", len(devices), None), ("Trusted", counts["trusted"], (0, 145, 90)), ("Unknown", counts["unknown"], SEV_COLORS["medium"]), ("Blocked", counts["blocked"], SEV_COLORS["high"]), ("Suspicious", counts["suspicious"], SEV_COLORS["critical"]), ("At risk", sum(float(d.get("risk_score") or 0) > 0 for d in devices), SEV_COLORS["high"]), ("Online", "Data unavailable", None), ("Offline", "Data unavailable", None)])
        pdf.section("Device inventory")
        rows = [(_text(d.get("hostname"), "Unknown"), _text(d.get("ip_address")), _text(d.get("mac_address")), _text(d.get("device_type")), _text(d.get("status")), _text(d.get("last_seen"))[:16]) for d in devices[:60]]
        self._rows_or_empty(pdf, ["Device", "IP address", "MAC", "Type", "Status", "Last seen"], rows, [35, 31, 38, 25, 25, 24], "NO DEVICES RECORDED\nThe device registry contains no entries.")

    def _intelligence(self, pdf, data):
        pdf.add_page()
        pdf.report_title("05  Attack Intelligence & AI Analysis", "Observed attack attribution and persisted prediction records")
        attacks = data["attacks"]
        source_counts = Counter(_text(a.get("source_ip"), "Unknown") for a in attacks if a.get("source_ip"))
        pdf.section("Attack intelligence")
        rows = [(_text(ip), count, "Observed attack record(s)") for ip, count in source_counts.most_common(15)]
        self._rows_or_empty(pdf, ["Observed source", "Records", "Interpretation"], rows, [58, 30, 81], "No attack source data recorded.")
        pdf.note("An observed source address is reported as telemetry only; this report does not label a country or IP as malicious without supporting event data.")
        pdf.section("Attack prediction")
        predictions = data["predictions"]
        rows = [(_text(p.get("prediction_type")), _text(p.get("predicted_attack")), f"{float(p.get('probability', 0) or 0) * 100:.1f}%", _text(p.get("model_version")), _text(p.get("created_at"))[:16]) for p in predictions[:30]]
        self._rows_or_empty(pdf, ["Type", "Prediction", "Probability", "Model", "Created"], rows, [32, 48, 28, 32, 29], "No persisted attack predictions are available.")
        pdf.section("Detection methods")
        methods = Counter(_text(a.get("detected_by"), "Unknown") for a in attacks)
        self._rows_or_empty(pdf, ["Method", "Records", "Classification"], [(key, count, "Recorded source label") for key, count in methods.items()], [60, 35, 74], "No attack detection method data recorded.")

    def _defenses(self, pdf, data):
        pdf.add_page()
        pdf.report_title("06  Honeypot & Mesh Defense", "Telemetry from deception services and coordinated defense nodes")
        stats = data["honeypot_stats"]
        pdf.section("Honeypot activity")
        pdf.metric_grid([("Interactions", stats.get("total_events") if stats else None, None), ("Unique sources", stats.get("unique_attackers") if stats else None, None), ("Honeypot types", len(stats.get("by_type", [])) if stats else None, None), ("Status", "Telemetry available" if stats else "Data unavailable", None)])
        rows = [(_text(e.get("honeypot_type")), _text(e.get("source_ip")), _text(e.get("action")), _text(e.get("threat_level")).upper(), _text(e.get("created_at"))[:16]) for e in data["honeypot_events"][:35]]
        self._rows_or_empty(pdf, ["Service", "Source", "Action", "Level", "Timestamp"], rows, [30, 42, 42, 25, 40], "No honeypot interactions recorded during the reporting period.")
        pdf.section("Mesh defense")
        nodes = data["mesh"].get("nodes", [])
        self._rows_or_empty(pdf, ["Node", "Role", "Status", "Zone", "Risk"], [(_text(n.get("node_id")), _text(n.get("role")), _text(n.get("status")), _text(n.get("zone")), _number(n.get("risk_score"))) for n in nodes], [45, 30, 35, 35, 34], "No mesh nodes are recorded.")
        pdf.note(f"Mesh edges recorded: {len(data['mesh'].get('edges', []))}. Blocked-event totals are unavailable unless present in the mesh telemetry.")

    def _findings(self, pdf, data):
        pdf.add_page()
        pdf.report_title("07  Findings & Recommendations", "Findings are generated only from observed records")
        findings = []
        for attack in data["attacks"]:
            if _severity(attack.get("severity")) in ("critical", "high"):
                findings.append((attack, "Recorded attack activity", _text(attack.get("attack_type"), "Unknown attack")))
        for device in data["devices"]:
            if _text(device.get("status"), "unknown").lower() in ("unknown", "suspicious", "blocked"):
                findings.append((device, "Device registry requires review", f"Device {_text(device.get('hostname'), 'Unknown')} is marked {_text(device.get('status'), 'unknown')}"))
        if not findings:
            pdf.section("Top security findings")
            pdf.note("NO EVIDENCE-BASED FINDINGS\nNo critical/high attack records or non-trusted device states were observed in the available data.", (0, 145, 90))
            pdf.section("Recommendations")
            pdf.note("No remediation recommendation was generated because no corresponding finding evidence was available.")
            return
        rows = []
        for index, (item, title, evidence) in enumerate(findings[:25], 1):
            severity = _severity(item.get("severity")) if item.get("severity") else ("high" if item.get("status") == "suspicious" else "medium")
            affected = _text(item.get("source_ip") or item.get("hostname"), "Unknown component")
            rows.append((f"HS-{index:03d}", title, severity.upper(), evidence, affected, _text(item.get("status"), "open").upper()))
        pdf.section("Top security findings")
        self._rows_or_empty(pdf, ["ID", "Title", "Severity", "Evidence", "Affected", "Status"], rows, [20, 34, 23, 49, 30, 22], "No findings recorded.")
        pdf.section("Security recommendations")
        recs = []
        if any(item.get("source_ip") for item, _, _ in findings):
            recs.append(("HIGH", "Review and respond to recorded high-severity attack activity", "Validate the affected source, target, and mitigation state against the attack records."))
        if any(_text(item.get("status"), "").lower() in ("unknown", "suspicious") for item, _, _ in findings):
            recs.append(("MEDIUM", "Review non-trusted devices", "Confirm ownership and intended access for devices marked unknown or suspicious."))
        self._rows_or_empty(pdf, ["Priority", "What", "Suggested action"], recs, [25, 65, 88], "No recommendations generated.")

    def _health_and_controls(self, pdf, data):
        pdf.add_page()
        pdf.report_title("08  System Health, Controls & Response", "Operational health is separated from cybersecurity findings")
        system = data["system"]
        pdf.section("System health")
        if not system:
            pdf.note("System health telemetry unavailable.")
        else:
            pdf.metric_grid([("CPU", f"{_number(system.get('cpu', {}).get('usage_percent'), 1)}%", None), ("Memory", f"{_number(system.get('memory', {}).get('percent'), 1)}%", None), ("Disk", f"{_number(system.get('disk', {}).get('percent'), 1)}%", None), ("Connections", _number(system.get("network", {}).get("active_connections")), None), ("Download", f"{_number(system.get('network', {}).get('download_mb_s'), 2)} Mbps", None), ("Upload", f"{_number(system.get('network', {}).get('upload_mb_s'), 2)} Mbps", None), ("Uptime", system.get("system", {}).get("uptime"), None), ("Processes", "Data unavailable", None)])
            pdf.kv("Host", system.get("system", {}).get("hostname"))
            pdf.kv("Operating system", system.get("system", {}).get("os"))
        pdf.section("Security control coverage")
        controls = [("Monitoring", "Available" if data["traffic"] or data["system"] else "Unavailable", "Traffic/system telemetry"), ("Threat detection", "Available" if data["attacks"] else "No records", "Attack registry"), ("Alerting", "Available" if data["alerts"] else "No records", "Alert registry"), ("Device visibility", "Available" if data["devices"] else "No records", "Device registry"), ("Audit logging", "Available" if data["audit"] else "No records", "Audit log"), ("Automated response", "Data unavailable", "No response aggregate exposed")]
        self._rows_or_empty(pdf, ["Control", "Status", "Evidence"], controls, [55, 38, 85], "Control coverage unavailable.")
        pdf.section("Incident / response summary")
        incidents = [a for a in data["attacks"] if a.get("status") in ("active", "investigating", "mitigated", "resolved", "false_positive")]
        if incidents:
            self._rows_or_empty(pdf, ["ID", "Detected", "Severity", "Method", "Status", "Response"], [(_text(a.get("id")), _text(a.get("created_at"))[:16], _severity(a.get("severity")).upper(), _text(a.get("detected_by")), _text(a.get("status")).upper(), _text(a.get("mitigation"))) for a in incidents[:30]], [20, 32, 25, 30, 29, 42], "No incidents recorded.")
        else:
            pdf.note("No security incidents were recorded during the reporting period.")

    def _quality(self, pdf, data, now, period_start):
        pdf.add_page()
        pdf.report_title("09  Data Quality & Technical Details", "Coverage, freshness, and reporting limitations")
        sources = [("Security score", "Available" if data["score"] else "Unavailable"), ("Attack registry", "Available" if data["attacks"] else "No records"), ("Alert registry", "Available" if data["alerts"] else "No records"), ("Network telemetry", "Available" if data["traffic"] else "Unavailable"), ("Device registry", "Available" if data["devices"] else "No records"), ("Honeypot telemetry", "Available" if data["honeypot_events"] else "No records"), ("Mesh topology", "Available" if data["mesh"].get("nodes") else "No records"), ("AI predictions", "Available" if data["predictions"] else "No records"), ("System monitor", "Available" if data["system"] else "Unavailable"), ("Audit log", "Available" if data["audit"] else "No records")]
        self._rows_or_empty(pdf, ["Telemetry source", "Collection state"], sources, [100, 78], "No telemetry source information available.")
        pdf.section("Reporting context")
        pdf.kv("Report generated", now.strftime("%Y-%m-%d %H:%M UTC"))
        pdf.kv("Reporting period", f"{period_start.strftime('%Y-%m-%d %H:%M UTC')} to {now.strftime('%Y-%m-%d %H:%M UTC')}")
        pdf.kv("Collection status", "Summary of persisted telemetry; no new scan launched")
        pdf.kv("Unavailable telemetry", "Online/offline device split, process count, response aggregates where not exposed")
        pdf.kv("Source handling", "Observed data, analysis, and recommendations are presented separately")
        pdf.note("A missing record means the relevant source did not provide data to this report. It is not interpreted as a clean result.")

    @staticmethod
    def _rows_or_empty(pdf, headers, rows, widths, empty):
        if rows:
            pdf.table(headers, rows, widths)
        else:
            pdf.note(empty)
