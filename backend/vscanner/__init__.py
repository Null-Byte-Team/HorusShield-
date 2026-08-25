"""
HorusShield V-8 Scanner
━━━━━━━━━━━━━━━━━━━━━━━
An orchestration layer over established, authorized security-assessment
tools (OWASP ZAP, Nikto, Nmap). This package intentionally contains NO
custom exploit or payload-generation logic — every actual test request
sent to a target is produced and controlled by the underlying tool
itself. HorusShield only starts these tools, waits for them to finish,
parses their own structured output, and hands the results to the AI
Cortex for summarization/classification/deduplication/prioritization.
"""
