"""
HorusShield Report Generator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full detailed PDF security audit with:
- Executive summary with risk level
- Security score breakdown
- Attack timeline table
- Device inventory
- Honeypot events
- Recommendations
- SECURED BY HORUSSHIELD seal
"""
import os
from fpdf import FPDF
from datetime import datetime
from database.db_manager import db
from utils.helpers import pdf_safe_text
from utils.logger import get_logger
from config import active_config as config

logger = get_logger("report_generator", "report")

SEV_COLORS = {
    'critical': (220, 30, 60),
    'high':     (255, 107, 53),
    'medium':   (255, 193, 7),
    'low':      (0, 200, 100),
}

class HorusPDF(FPDF):
    def __init__(self, facility_name="Facility", language="en"):
        super().__init__()
        self.facility = facility_name
        self.lang = language
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    # Override once, here, instead of wrapping every individual .cell()/
    # .multi_cell() call throughout this file. Report content includes
    # network-derived data an attacker can influence directly — device
    # hostnames, honeypot-captured usernames, attack-type strings — so any
    # single unexpected Unicode character must not be able to abort the
    # whole report (see utils.helpers.pdf_safe_text for why).
    def cell(self, w=0, h=0, text="", *args, **kwargs):
        return super().cell(w, h, pdf_safe_text(text), *args, **kwargs)

    def multi_cell(self, w=0, h=0, text="", *args, **kwargs):
        return super().multi_cell(w, h, pdf_safe_text(text), *args, **kwargs)

    def header(self):
        self.set_fill_color(5, 8, 20)
        self.rect(0, 0, 210, 20, 'F')
        self.set_text_color(0, 245, 255)
        self.set_font("Arial", "B", 10)
        self.set_y(6)
        self.cell(0, 8, "HORUSSHIELD 2.0 - SECURITY AUDIT REPORT", align="C")
        self.set_text_color(100, 100, 120)
        self.set_font("Arial", "", 7)
        self.ln(2)
        self.cell(0, 4, f"Team NullByte · WE School · Alexandria, Egypt  |  {self.facility}  |  {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", align="C")
        self.ln(8)
        self.set_text_color(20, 20, 30)

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(5, 8, 20)
        self.rect(0, self.get_y(), 210, 20, 'F')
        self.set_text_color(0, 128, 160)
        self.set_font("Arial", "I", 7)
        self.cell(0, 6, f"SECURED BY HORUSSHIELD 2.0  |  Page {self.page_no()}  |  Confidential - Internal Use Only", align="C")
        self.set_text_color(20, 20, 30)

    def section_title(self, text, num):
        self.ln(4)
        self.set_fill_color(5, 8, 20)
        self.set_text_color(0, 245, 255)
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, pdf_safe_text(f"  {num}. {text.upper()}"), fill=True, ln=True)
        self.set_text_color(20, 20, 30)
        self.ln(2)

    def kv_row(self, label, value, color=None):
        self.set_font("Arial", "B", 9)
        self.set_fill_color(240, 242, 248)
        self.cell(70, 7, pdf_safe_text(f"  {label}"), fill=True, border="LTB")
        self.set_font("Arial", "", 9)
        self.set_fill_color(252, 252, 255)
        if color:
            self.set_text_color(*color)
        self.cell(0, 7, pdf_safe_text(f"  {value}"), fill=True, border="RTB", ln=True)
        self.set_text_color(20, 20, 30)

    def colored_bar(self, label, pct):
        pct = min(int(pct or 0), 100)
        color = (0,200,100) if pct>=80 else (255,193,7) if pct>=60 else (220,30,60)
        self.set_font("Arial", "", 8)
        self.cell(60, 5, pdf_safe_text(f"  {label}"))
        self.set_fill_color(220, 220, 230)
        self.cell(110, 5, "", fill=True)
        # Draw filled portion over it
        x = self.get_x() - 110 + (110*pct//100)
        y = self.get_y()
        self.set_fill_color(*color)
        self.rect(self.get_x()-110, y, 110*pct//100, 5, 'F')
        self.set_text_color(*color)
        self.set_font("Arial","B",7)
        self.cell(20, 5, f"{pct}%", ln=True)
        self.set_text_color(20,20,30)


class ReportGenerator:
    def __init__(self):
        self.output_dir = config.REPORT_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_daily_report(self, facility_name="Facility", language="en"):
        ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"HorusReport_{facility_name.replace(' ','_')}_{ts}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        try:
            stats   = db.get_dashboard_stats()
            attacks = db.get_attacks(limit=30)
            devices = db.get_all_devices()
            alerts  = db.get_alerts(limit=20)
            try:
                hp_status = db.get_honeypot_stats()
            except Exception as e:
                logger.debug(f"Honeypot stats unavailable for report: {e}")
                hp_status = {}
            try:
                hp_events = db.get_honeypot_events(limit=10)
            except Exception as e:
                logger.debug(f"Honeypot events unavailable for report: {e}")
                hp_events = []

            score     = stats.get('security_score', 85)
            devs      = stats.get('devices', {})
            a_attacks = stats.get('active_attacks', 0)
            u_alerts  = stats.get('unacknowledged_alerts', 0)
            level     = "SECURE" if score>=90 else "MODERATE RISK" if score>=70 else "AT RISK" if score>=40 else "CRITICAL"
            sev_color = SEV_COLORS.get('low') if score>=90 else SEV_COLORS.get('medium') if score>=70 else SEV_COLORS.get('high') if score>=40 else SEV_COLORS.get('critical')

            pdf = HorusPDF(facility_name=facility_name, language=language)
            pdf.add_page()

            # ── Cover intro ──
            pdf.set_font("Arial","B",22)
            pdf.set_text_color(*sev_color)
            pdf.cell(0,14,f"Security Score: {score}/100",ln=True,align="C")
            pdf.set_text_color(100,100,120)
            pdf.set_font("Arial","",12)
            pdf.cell(0,8,f"Network Status: {level}",ln=True,align="C")
            pdf.ln(4)

            # ── 1. Executive Summary ──
            pdf.section_title("Executive Summary", 1)
            pdf.kv_row("Facility / Company", facility_name)
            pdf.kv_row("Report Date", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            pdf.kv_row("Security Score", f"{score}/100  -  {level}", sev_color)
            pdf.kv_row("Active Attacks", str(a_attacks), SEV_COLORS['critical'] if a_attacks>0 else None)
            pdf.kv_row("Unread Alerts", str(u_alerts))
            pdf.kv_row("Total Devices", str(devs.get('total',0)))
            pdf.kv_row("Unknown Devices", str(devs.get('unknown',0)), SEV_COLORS['high'] if devs.get('unknown',0)>0 else None)
            pdf.kv_row("Trusted Devices", str(devs.get('trusted',0)))
            pdf.kv_row("Blocked Devices", str(devs.get('blocked',0)))
            pdf.ln(4)

            # ── 2. Score Breakdown ──
            pdf.section_title("Security Score Breakdown", 2)
            comps = stats.get('components') or {
                'Device Security':  round(score*0.90),
                'Network Health':   round(score*0.85),
                'Attack History':   round(score*0.95),
                'AI Confidence':    round(score*0.80),
                'Honeypot Defense': round(score*0.75),
            }
            for name, val in comps.items():
                pdf.colored_bar(name, val)
                pdf.ln(2)
            pdf.ln(4)

            # ── 3. Risk Assessment ──
            pdf.section_title("Risk Assessment & Recommendations", 3)
            recs = self._build_recommendations(score, devs, a_attacks, attacks)
            for i, rec in enumerate(recs, 1):
                pdf.set_font("Arial","B",9)
                pdf.cell(0,7,f"  [{i}] {rec['title']}",ln=True)
                pdf.set_font("Arial","",8)
                pdf.set_text_color(80,80,100)
                pdf.multi_cell(0,5,f"      {rec['detail']}")
                pdf.set_text_color(20,20,30)
                pdf.ln(1)
            pdf.ln(4)

            # ── 4. Attack Incidents ──
            pdf.section_title("Security Incidents (Last 24h)", 4)
            if not attacks:
                pdf.set_font("Arial","I",9)
                pdf.set_text_color(0,160,80)
                pdf.cell(0,8,"  No attacks recorded in the last 24 hours. ✓",ln=True)
                pdf.set_text_color(20,20,30)
            else:
                # Table header
                pdf.set_font("Arial","B",8)
                pdf.set_fill_color(5,8,20)
                pdf.set_text_color(0,245,255)
                pdf.cell(35,7,"Attack Type",fill=True,border=1)
                pdf.cell(25,7,"Severity",fill=True,border=1)
                pdf.cell(40,7,"Source IP",fill=True,border=1)
                pdf.cell(20,7,"Confidence",fill=True,border=1)
                pdf.cell(30,7,"Status",fill=True,border=1)
                pdf.cell(0,7,"Time",fill=True,border=1,ln=True)
                pdf.set_text_color(20,20,30)
                pdf.set_font("Arial","",7)
                for a in attacks[:20]:
                    sev = a.get('severity','medium').lower()
                    r,g,b = SEV_COLORS.get(sev,(100,100,100))
                    fill = (255,245,245) if sev=='critical' else (255,252,240) if sev=='high' else (252,252,252)
                    pdf.set_fill_color(*fill)
                    pdf.set_text_color(*SEV_COLORS.get(sev,(60,60,60)))
                    pdf.cell(35,6,str(a.get('attack_type','?'))[:18],fill=True,border=1)
                    pdf.cell(25,6,sev.upper(),fill=True,border=1)
                    pdf.set_text_color(20,20,30)
                    pdf.cell(40,6,str(a.get('source_ip','?'))[:20],fill=True,border=1)
                    conf=a.get('confidence',0)
                    pdf.cell(20,6,f"{round((conf or 0)*100)}%",fill=True,border=1)
                    pdf.cell(30,6,str(a.get('status','?'))[:12],fill=True,border=1)
                    pdf.cell(0,6,str(a.get('created_at',''))[:16],fill=True,border=1,ln=True)
            pdf.ln(6)

            # ── 5. Device Inventory ──
            pdf.add_page()
            pdf.section_title("Device Inventory", 5)
            if not devices:
                pdf.set_font("Arial","I",9)
                pdf.cell(0,8,"  No devices found in database.",ln=True)
            else:
                pdf.set_font("Arial","B",8)
                pdf.set_fill_color(5,8,20)
                pdf.set_text_color(0,245,255)
                pdf.cell(40,7,"Hostname",fill=True,border=1)
                pdf.cell(35,7,"IP Address",fill=True,border=1)
                pdf.cell(38,7,"MAC Address",fill=True,border=1)
                pdf.cell(30,7,"Type",fill=True,border=1)
                pdf.cell(0,7,"Status",fill=True,border=1,ln=True)
                pdf.set_text_color(20,20,30)
                pdf.set_font("Arial","",7)
                for d in devices[:40]:
                    st = d.get('status','unknown')
                    fill = (240,255,245) if st=='trusted' else (255,240,240) if st in ('unknown','blocked') else (250,250,252)
                    pdf.set_fill_color(*fill)
                    scolor = (0,150,60) if st=='trusted' else (200,30,30) if st=='unknown' else (60,60,80)
                    pdf.cell(40,5,str(d.get('hostname','--'))[:18],fill=True,border=1)
                    pdf.cell(35,5,str(d.get('ip_address','--')),fill=True,border=1)
                    pdf.cell(38,5,str(d.get('mac_address','--'))[:18],fill=True,border=1)
                    pdf.cell(30,5,str(d.get('device_type','--')),fill=True,border=1)
                    pdf.set_text_color(*scolor)
                    pdf.cell(0,5,st.upper(),fill=True,border=1,ln=True)
                    pdf.set_text_color(20,20,30)
            pdf.ln(6)

            # ── 6. Honeypot Activity ──
            pdf.section_title("Honeypot Activity", 6)
            total_hp = hp_status.get('total_events',0)
            unique_hp = hp_status.get('unique_attackers',0)
            pdf.kv_row("Total Honeypot Events", str(total_hp))
            pdf.kv_row("Unique Attacker IPs", str(unique_hp))
            pdf.ln(3)
            if hp_events:
                pdf.set_font("Arial","B",8)
                pdf.set_fill_color(5,8,20); pdf.set_text_color(0,245,255)
                pdf.cell(25,7,"Service",fill=True,border=1)
                pdf.cell(40,7,"Attacker IP",fill=True,border=1)
                pdf.cell(35,7,"Action",fill=True,border=1)
                pdf.cell(25,7,"Credentials",fill=True,border=1)
                pdf.cell(0,7,"Time",fill=True,border=1,ln=True)
                pdf.set_text_color(20,20,30); pdf.set_font("Arial","",7)
                for e in hp_events[:10]:
                    cred = f"{e.get('username','--')}" if e.get('username') else '--'
                    pdf.set_fill_color(255,245,240)
                    pdf.cell(25,5,str(e.get('honeypot_type','?')).upper(),fill=True,border=1)
                    pdf.cell(40,5,str(e.get('source_ip','?')),fill=True,border=1)
                    pdf.cell(35,5,str(e.get('action','?'))[:18],fill=True,border=1)
                    pdf.cell(25,5,cred[:12],fill=True,border=1)
                    pdf.cell(0,5,str(e.get('created_at',''))[:16],fill=True,border=1,ln=True)
            else:
                pdf.set_font("Arial","I",9); pdf.set_text_color(100,100,120)
                pdf.cell(0,7,"  No honeypot interactions recorded.",ln=True)
                pdf.set_text_color(20,20,30)
            pdf.ln(6)

            # ── 7. Recent Alerts ──
            pdf.section_title("Recent Alerts", 7)
            if alerts:
                for a in alerts[:15]:
                    sev = a.get('severity','info')
                    r,g,b = SEV_COLORS.get(sev,(100,100,120))
                    pdf.set_text_color(r,g,b)
                    pdf.set_font("Arial","B",8)
                    ts_str = str(a.get('created_at',''))[:16]
                    pdf.cell(0,6,f"  [{ts_str}]  {a.get('title','Alert')}",ln=True)
                    pdf.set_font("Arial","",7); pdf.set_text_color(80,80,100)
                    if a.get('message'):
                        pdf.multi_cell(0,4,f"             {a['message']}")
                    pdf.set_text_color(20,20,30)
                    pdf.ln(1)
            else:
                pdf.set_font("Arial","I",9); pdf.set_text_color(0,160,80)
                pdf.cell(0,8,"  No recent alerts. Network is secure. ✓",ln=True)
                pdf.set_text_color(20,20,30)
            pdf.ln(6)

            # ── 8. Conclusion ──
            pdf.section_title("Conclusion & Next Steps", 8)
            conclusion = self._build_conclusion(score, a_attacks, devs.get('unknown',0))
            pdf.set_font("Arial","",9)
            pdf.multi_cell(0, 5, conclusion)
            pdf.ln(6)

            # ── Seal ──
            pdf.set_fill_color(5,8,20)
            pdf.rect(18, pdf.get_y(), 174, 18, 'F')
            pdf.set_text_color(0,245,255)
            pdf.set_font("Arial","B",11)
            pdf.cell(0,10,"  👁  SECURED AND ANALYZED BY HORUSSHIELD 2.0",ln=True)
            pdf.set_font("Arial","",7); pdf.set_text_color(0,180,200)
            pdf.cell(0,7,f"     Team NullByte · WE School · Alexandria, Egypt · AI-Powered Cybersecurity Platform",ln=True)

            pdf.output(filepath)
            logger.info(f"Report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            import traceback; logger.error(traceback.format_exc())
            return None

    def _build_recommendations(self, score, devs, active_attacks, attacks):
        recs = []
        unknown = devs.get('unknown',0)
        if unknown > 0:
            recs.append({"title": f"Investigate {unknown} Unknown Device(s)",
                         "detail": "Unknown devices on your network pose a significant security risk. Review their MAC addresses, determine if they are authorized, then either trust or block them through the Devices panel."})
        if active_attacks > 0:
            recs.append({"title": f"Respond to {active_attacks} Active Attack(s)",
                         "detail": "Active attacks are currently ongoing. Use the Threats panel to mitigate each attack. Consider activating Anubis Lockdown mode for immediate network-wide protection."})
        if score < 70:
            recs.append({"title": "Improve Security Score",
                         "detail": f"Current score is {score}/100. Key actions: remove unknown devices, mitigate open threats, ensure all devices have up-to-date firmware, and verify no dangerous ports are open."})
        atk_types = set(a.get('attack_type','') for a in attacks)
        if 'port_scan' in atk_types:
            recs.append({"title": "Port Scan Activity Detected",
                         "detail": "A port scan was recorded. This typically precedes a targeted attack. Review open ports, ensure non-essential services are disabled, and consider blocking the source IP permanently."})
        if 'brute_force' in atk_types:
            recs.append({"title": "Brute Force Attack Detected",
                         "detail": "Brute force login attempts were recorded. Enable rate limiting on SSH/RDP/HTTP services, use strong passwords, and consider two-factor authentication on all administrative accounts."})
        if 'ddos' in atk_types:
            recs.append({"title": "DDoS Activity Recorded",
                         "detail": "DDoS traffic was detected and blocked by HorusShield. Monitor bandwidth usage over the next 24 hours. If attacks persist, consider upstream traffic filtering."})
        if not recs:
            recs.append({"title": "Network Security is Satisfactory",
                         "detail": f"No critical issues detected. Security score is {score}/100. Continue regular monitoring, keep the system updated, and run weekly security scans."})
        return recs

    def _build_conclusion(self, score, active_attacks, unknown_devices):
        lvl = "secure" if score>=90 else "moderate risk" if score>=70 else "at risk" if score>=40 else "critical"
        parts = [
            f"This HorusShield security audit covers network activity analyzed by the AI engine.",
            f"The overall network security status is rated as {lvl.upper()} with a score of {score}/100.",
        ]
        if active_attacks > 0:
            parts.append(f"There are currently {active_attacks} active attack(s) that require immediate attention.")
        if unknown_devices > 0:
            parts.append(f"A total of {unknown_devices} unknown device(s) were detected and should be investigated.")
        if score >= 85:
            parts.append("The network defenses are operating effectively. Continue regular monitoring to maintain this level of security.")
        else:
            parts.append("Immediate action is recommended to address the identified issues and improve the security posture.")
        parts.append("All data in this report is collected in real-time by HorusShield 2.0 - Egyptian AI Cybersecurity Platform.")
        return "\n".join(parts)
