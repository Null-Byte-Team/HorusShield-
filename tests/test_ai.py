"""Tests for the AI layer — security scorer and V-8 Scanner AI Cortex."""


def test_gemini_call_translates_history_and_response(monkeypatch):
    import json
    import urllib.request
    from ai import conversation_engine

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return json.dumps({
                "candidates": [{"content": {"parts": [{"text": "Gemini reply"}]}}]
            }).encode()

    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = conversation_engine._call_gemini(
        "system", "new question", [{"role": "assistant", "content": "previous answer"}]
    )

    payload = json.loads(captured["request"].data)
    assert result == "Gemini reply"
    assert payload["system_instruction"]["parts"][0]["text"] == "system"
    assert payload["contents"][0]["role"] == "model"
    assert payload["contents"][-1]["parts"][0]["text"] == "new question"


def test_gemini_is_selected_before_claude(monkeypatch):
    from ai.conversation_engine import AdvancedHorusAssistant

    assistant = AdvancedHorusAssistant()
    monkeypatch.setattr(assistant, "_get_security_data", lambda: {})
    monkeypatch.setattr(assistant, "_try_gemini", lambda *args: "Gemini wins")
    monkeypatch.setattr(assistant, "_try_claude", lambda *args: "Claude should not run")

    response, engine = assistant.ask_with_engine("hello", user_id="test")

    assert response == "Gemini wins"
    assert engine == "gemini"


def test_security_scorer_score_is_clamped():
    from ai.security_scorer import SecurityScorer

    scorer = SecurityScorer()
    result = scorer.calculate()
    assert result is not None, "SecurityScorer.calculate() raised/returned None — see logs"
    assert isinstance(result, dict)
    assert 0 <= result["total_score"] <= 100
    assert set(result["components"].keys()) == {
        "device_security",
        "network_health",
        "attack_history",
        "vulnerability_exposure",
        "ai_confidence",
    }


def test_vscanner_cortex_dedup_marks_repeats():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {
            "source_tool": "zap",
            "finding_type": "SQL Injection",
            "url": "http://example.com/login?user=1",
            "confidence": 0.6,
        },
        {
            "source_tool": "nikto",
            "finding_type": "SQL Injection",
            "url": "http://example.com/login?user=2",
            "confidence": 0.5,
        },
    ]
    result = VScannerCortex.deduplicate(findings)
    # same host+path ("/login") + finding type → treated as the same issue
    duplicates = [f for f in result if f["is_duplicate"]]
    assert len(duplicates) == 1
    kept = [f for f in result if not f["is_duplicate"]][0]
    # corroborated by a second tool → confidence should have increased
    assert kept["confidence"] > 0.6


def test_vscanner_cortex_classify_adds_owasp_and_cwe():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {
            "source_tool": "zap",
            "finding_type": "Cross Site Scripting",
            "url": "http://example.com/",
            "confidence": 0.7,
            "is_duplicate": False,
            "_corroboration_count": 1,
        }
    ]
    result = VScannerCortex.classify_and_explain(findings)
    assert result[0]["owasp_category"]
    assert result[0]["cwe_id"] == "CWE-79"
    assert "AI Cortex" in result[0]["ai_explanation"]


def test_vscanner_cortex_prioritize_orders_by_severity():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {"severity": "low", "confidence": 0.9},
        {"severity": "critical", "confidence": 0.5},
        {"severity": "medium", "confidence": 0.5},
    ]
    ordered = VScannerCortex.prioritize(findings)
    assert [f["severity"] for f in ordered] == ["critical", "medium", "low"]


def test_vscanner_cortex_summarize_excludes_duplicates():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {"severity": "high", "confidence": 0.8, "is_duplicate": False},
        {"severity": "high", "confidence": 0.8, "is_duplicate": True},
    ]
    summary = VScannerCortex.summarize(findings)
    assert summary["total_findings"] == 1
    assert summary["duplicates_removed"] == 1
    assert summary["by_severity"]["high"] == 1


def test_vscanner_cortex_never_touches_request_payload_fields():
    """Guardrail test: the AI Cortex module must not define anything that
    looks like payload/exploit generation — only normalization, dedup,
    classification, scoring, and explanation."""
    from ai import vscanner_cortex

    forbidden = {"payload", "exploit", "inject_sql", "craft_request"}
    defined = {name.lower() for name in dir(vscanner_cortex)}
    assert not (forbidden & defined)


def test_vscanner_cortex_correlates_findings_on_same_asset():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {
            "source_tool": "nmap",
            "finding_type": "Open Port",
            "url": "example.com:80",
            "confidence": 0.8,
            "severity": "low",
            "is_duplicate": False,
        },
        {
            "source_tool": "zap",
            "finding_type": "Missing Security Header",
            "url": "http://example.com/",
            "confidence": 0.6,
            "severity": "low",
            "is_duplicate": False,
        },
        {
            "source_tool": "nikto",
            "finding_type": "Directory Listing",
            "url": "http://other-host.com/",
            "confidence": 0.7,
            "severity": "medium",
            "is_duplicate": False,
        },
    ]
    result = VScannerCortex.correlate(findings)

    # nmap + zap findings share the "example.com" asset -> correlated
    assert result[0]["correlation_group"] == "example.com"
    assert result[1]["correlation_group"] == "example.com"
    assert "zap" in result[0]["correlated_with_tools"]
    assert "nmap" in result[1]["correlated_with_tools"]

    # nikto's finding is on a different host -> not correlated with anything
    assert result[2]["correlation_group"] is None
    assert result[2]["correlated_with_tools"] == []


def test_vscanner_cortex_correlate_ignores_duplicates():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {
            "source_tool": "nmap",
            "finding_type": "Open Port",
            "url": "example.com:80",
            "confidence": 0.8,
            "severity": "low",
            "is_duplicate": False,
        },
        {
            "source_tool": "zap",
            "finding_type": "Open Port",
            "url": "example.com:80",
            "confidence": 0.5,
            "severity": "low",
            "is_duplicate": True,
        },  # marked duplicate
    ]
    result = VScannerCortex.correlate(findings)
    # only one active finding on this asset -> no correlation group, even
    # though a duplicate row technically shares the same host
    assert result[0]["correlation_group"] is None


def test_vscanner_cortex_process_includes_correlation_step():
    from ai.vscanner_cortex import VScannerCortex

    findings = [
        {
            "source_tool": "nmap",
            "finding_type": "Open Port",
            "url": "example.com:22",
            "confidence": 0.8,
        },
        {
            "source_tool": "zap",
            "finding_type": "SQL Injection",
            "url": "http://example.com/login",
            "confidence": 0.7,
        },
    ]
    result = VScannerCortex.process(findings)
    assert all("correlation_group" in f for f in result)
