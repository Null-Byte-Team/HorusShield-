"""
HorusShield Advanced Conversation Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Primary brain: Google Gemini API (gemini-3.6-flash), then Claude
Fallback brain: Rule-based security + general-topic handler

Bugs fixed vs previous version:
    1. _intelligent_response() was dead code — never called from ask().
         Hosted AI providers are now the primary dispatch path.
  2. Animal handling was duplicated in two places; unified into one.
  3. Security topic fell through to joke responses when no keyword matched;
     now always returns a data-backed status as the safe default.
  4. `import random` repeated inside functions — hoisted to top-level.
    5. Hosted AI providers are tried before the rule-based fallback.
"""

import os
import random
import difflib
from datetime import datetime

from config import active_config as config
from utils.logger import get_logger
from database.db_manager import db

logger = get_logger("conversation_engine", "ai")


def _build_messages(history, user_message):
    messages = []
    for message in history[-6:]:
        role = message.get("role")
        content = message.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})

    if not messages or messages[-1].get("role") != "user":
        messages.append({"role": "user", "content": user_message})
    return messages


def _call_gemini(system_prompt, user_message, history):
    """Call Gemini, returning its text reply or None when unavailable."""
    try:
        import urllib.parse
        import urllib.request
        import json as _json

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return None

        contents = []
        for message in _build_messages(history, user_message):
            contents.append({
                "role": "model" if message["role"] == "assistant" else "user",
                "parts": [{"text": message["content"]}],
            })

        for model in ["gemini-3.6-flash", "gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]:
            endpoint = (
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?"
                + urllib.parse.urlencode({"key": api_key})
            )
            payload = _json.dumps({
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": contents,
                "generationConfig": {"maxOutputTokens": 1000},
            }).encode("utf-8")
            request = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    data = _json.loads(response.read())
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(part.get("text", "") for part in parts).strip()
                    if text:
                        return text
            except Exception as model_err:
                logger.debug(f"Gemini model {model} attempt failed: {model_err}")
                continue
    except Exception as error:
        if hasattr(error, "read"):
            try:
                detail = error.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                detail = str(error)
            logger.warning(f"Gemini API call failed (trying Claude/fallback): {detail}")
        else:
            logger.warning(f"Gemini API call failed (trying Claude/fallback): {error}")
    return None


def _call_claude(system_prompt, user_message, history):
    """
    Call Anthropic Claude API (claude-sonnet-4-20250514).
    Returns the text reply, or None on any error (triggers rule-based fallback).
    """
    try:
        import urllib.request
        import json as _json
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return None

        messages = _build_messages(history, user_message)

        payload = _json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "system": system_prompt,
            "messages": messages,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": api_key,
            },
            method="POST",
        )

        # nosec B310: bandit flags urlopen generically since it can accept
        # file:// or other unexpected schemes if the URL is dynamic/user-
        # influenced. This URL is a hardcoded literal
        # ("https://api.anthropic.com/v1/messages") a few lines above —
        # never constructed from any request/user input.
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            data = _json.loads(resp.read())
            for block in data.get("content", []):
                if block.get("type") == "text":
                    return block["text"].strip()

    except Exception as e:
        logger.warning(f"Claude API call failed (using fallback): {e}")

    return None


class IntelligentMatcher:
    @staticmethod
    def fuzzy_match(text, keywords, threshold=0.6):
        text_lower = text.lower().strip()
        matches = []
        for keyword in keywords:
            kw = keyword.lower()
            if kw in text_lower:
                matches.append((keyword, 1.0))
            else:
                ratio = difflib.SequenceMatcher(None, text_lower, kw).ratio()
                if ratio >= threshold:
                    matches.append((keyword, ratio))
        return sorted(matches, key=lambda x: x[1], reverse=True)


class ConversationMemory:
    def __init__(self, user_id, max_history=20):
        self.user_id = user_id
        self.max_history = max_history
        self.memory = []
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "topic_context": "general",
        }

    def add_message(self, role, content):
        self.memory.append({
            "timestamp": datetime.now().isoformat(),
            "role": role,
            "content": content,
        })
        if len(self.memory) > self.max_history:
            self.memory.pop(0)

    def get_context(self):
        return self.memory[-5:]

    def get_summary(self):
        user_msgs = [m["content"] for m in self.memory if m["role"] == "user"]
        return " | ".join(user_msgs[-3:]) if user_msgs else "New conversation"

    def detect_topic(self):
        security_kw = [
            "attack", "threat", "device", "network", "security", "hack",
            "port", "scan", "ddos", "lockdown", "anomaly", "alert", "breach",
            "vulnerability", "firewall", "intrusion", "exploit", "malware",
            "score", "protect", "defense", "traffic", "bandwidth", "speed",
            "download", "upload", "prediction", "honeypot", "mesh",
            "هجوم", "تهديد", "جهاز", "شبكة", "أمان", "اختراق",
        ]
        playful_kw = [
            "woof", "bark", "meow", "quack", "roar", "ooh", "aah",
            "dog", "cat", "duck", "monkey", "dino", "animal", "joke",
            "funny", "haha", "lol", "cute", "silly", "بوف", "ميو",
        ]
        recent_text = " ".join(m["content"].lower() for m in self.memory[-3:])
        for kw in playful_kw:
            if kw in recent_text:
                self.metadata["topic_context"] = "playful"
                return "playful"
        for kw in security_kw:
            if kw in recent_text:
                self.metadata["topic_context"] = "security"
                return "security"
        self.metadata["topic_context"] = "general"
        return "general"


class AdvancedHorusAssistant:
    """
    HorusShield AI assistant.

        Dispatch order for every query:
            1. Gemini API
            2. Claude API
            3. Rule-based security handler
            4. Rule-based general/playful handler
    """

    _SYSTEM_EN = (
        "You are Horus, the AI security assistant for HorusShield 2.0, "
        "a network cybersecurity platform built by Team NullByte at WE School, Alexandria, Egypt. "
        "Live network stats are injected at the end of each user message — use them to give precise answers. "
        "Keep responses concise (max 3 short paragraphs), use emojis sparingly. "
        "If the user plays around (animal sounds, jokes), play along briefly then redirect to security help. "
        "Never invent network data — only quote what is provided in the context. "
        "If you do not have a real answer, say what you can do next instead of refusing."
    )

    _SYSTEM_AR = (
        "أنت حورس، مساعد الذكاء الاصطناعي لـ HorusShield 2.0، "
        "منصة أمن الشبكات من فريق NullByte في مدرسة WE، الإسكندرية، مصر. "
        "إحصاءات الشبكة الحية تُحقن في نهاية كل رسالة مستخدم — استخدمها لإجابات دقيقة. "
        "كن موجزاً (3 فقرات قصيرة كحد أقصى)، استخدم الرموز التعبيرية بتحفظ. "
        "لا تخترع بيانات الشبكة — استخدم فقط ما هو مُقدَّم."
    )

    def __init__(self):
        self.conversations = {}
        self.config = {
            "model_type": "hybrid",
            "max_conversation_history": 20,
            "languages": ["en", "ar"],
        }

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_security_data(self):
        try:
            stats = db.get_dashboard_stats()
            traffic = db.get_latest_traffic() or {}
            devices = db.get_all_devices()
            alerts = db.get_alerts(limit=3)
            predictions = db.get_recent_predictions(limit=3)
            honeypot = db.get_honeypot_stats()
            mesh = db.get_mesh_topology()
            return {
                "security_score":        stats.get("security_score", 85),
                "devices":               stats.get("devices", {}),
                "active_attacks":        stats.get("active_attacks", 0),
                "unacknowledged_alerts": stats.get("unacknowledged_alerts", 0),
                "traffic":               traffic,
                "recent_devices":        devices[:5],
                "unknown_devices":       [d for d in devices if d.get("status") in ("unknown", "suspicious")][:5],
                "recent_alerts":         alerts,
                "predictions":           predictions,
                "honeypot":              honeypot,
                "mesh": {
                    "nodes": len(mesh.get("nodes", [])),
                    "edges": len(mesh.get("edges", [])),
                },
            }
        except Exception as e:
            logger.error(f"Security data fetch error: {e}")
            return {}

    def _get_or_create_conversation(self, user_id):
        if user_id not in self.conversations:
            self.conversations[user_id] = ConversationMemory(
                user_id, self.config["max_conversation_history"]
            )
        return self.conversations[user_id]

    # ── Claude API path ───────────────────────────────────────────────────────

    def _try_claude(self, query, memory, security_data, language):
        system = self._SYSTEM_AR if language == "ar" else self._SYSTEM_EN

        if security_data:
            score   = security_data.get("security_score", "N/A")
            attacks = security_data.get("active_attacks", 0)
            devs    = security_data.get("devices", {})
            total_d = devs.get("total", 0)
            unk_d   = devs.get("unknown", 0)
            alerts  = security_data.get("unacknowledged_alerts", 0)
            ctx = (
                f"\n\n[LIVE NETWORK CONTEXT — score:{score}/100 | "
                f"active_attacks:{attacks} | devices:{total_d} "
                f"(unknown:{unk_d}) | unread_alerts:{alerts}]"
            )
        else:
            ctx = ""

        enriched_query = query + ctx
        hist = [
            {"role": m["role"], "content": m["content"]}
            for m in memory.memory[:-1]
        ]
        return _call_claude(system, enriched_query, hist)

    def _try_gemini(self, query, memory, security_data, language):
        system = self._SYSTEM_AR if language == "ar" else self._SYSTEM_EN
        ctx = self._live_context(security_data)
        hist = [{"role": m["role"], "content": m["content"]} for m in memory.memory[:-1]]
        return _call_gemini(system, query + ctx, hist)

    @staticmethod
    def _live_context(security_data):
        if not security_data:
            return ""
        devices = security_data.get("devices", {})
        return (
            f"\n\n[LIVE NETWORK CONTEXT — score:{security_data.get('security_score', 'N/A')}/100 | "
            f"active_attacks:{security_data.get('active_attacks', 0)} | "
            f"devices:{devices.get('total', 0)} (unknown:{devices.get('unknown', 0)}) | "
            f"unread_alerts:{security_data.get('unacknowledged_alerts', 0)}]"
        )

    def _traffic_summary(self, data, language):
        traffic = data.get("traffic", {}) or {}
        down = traffic.get("download_mbps")
        up = traffic.get("upload_mbps")
        if down is None:
            down = ((traffic.get("bytes_in", 0) or 0) * 8) / (max(config.MONITOR_INTERVAL, 1) * 1_000_000)
        if up is None:
            up = ((traffic.get("bytes_out", 0) or 0) * 8) / (max(config.MONITOR_INTERVAL, 1) * 1_000_000)
        total = traffic.get("bandwidth_mbps")
        if total is None:
            total = down + up
        packets = traffic.get("packets_per_sec", 0)
        connections = traffic.get("active_connections", 0)

        if language == "ar":
            return (
                f"📶 حركة الشبكة الآن:\n"
                f"⬇️ التنزيل: {down:.2f} Mbps\n"
                f"⬆️ الرفع: {up:.2f} Mbps\n"
                f"📡 الإجمالي: {total:.2f} Mbps\n"
                f"🔗 الاتصالات النشطة: {connections}\n"
                f"📦 الحزم/ثانية: {packets:.0f}"
            )
        return (
            f"📶 Live Traffic:\n"
            f"⬇️ Download: {down:.2f} Mbps\n"
            f"⬆️ Upload: {up:.2f} Mbps\n"
            f"📡 Total Bandwidth: {total:.2f} Mbps\n"
            f"🔗 Active Connections: {connections}\n"
            f"📦 Packets/sec: {packets:.0f}"
        )

    def _device_summary(self, data, language):
        counts = data.get("devices", {})
        unknown = data.get("unknown_devices", [])
        recent = data.get("recent_devices", [])
        if language == "ar":
            head = (
                f"🖥️ نظرة على الأجهزة:\n"
                f"📱 الإجمالي: {counts.get('total', 0)}\n"
                f"✅ الموثوقة: {counts.get('trusted', 0)}\n"
                f"⚠️ المجهولة: {counts.get('unknown', 0)}\n"
                f"🚫 المحظورة: {counts.get('blocked', 0)}"
            )
            if unknown:
                suspects = ", ".join(f"{d.get('hostname') or d.get('ip_address')} ({d.get('ip_address')})" for d in unknown[:3])
                return head + f"\n\nالأجهزة التي تحتاج مراجعة: {suspects}"
            if recent:
                seen = ", ".join(f"{d.get('hostname') or d.get('ip_address')} ({d.get('ip_address')})" for d in recent[:3])
                return head + f"\n\nآخر الأجهزة التي أراها: {seen}"
            return head

        head = (
            f"🖥️ Device Overview:\n"
            f"📱 Total: {counts.get('total', 0)}\n"
            f"✅ Trusted: {counts.get('trusted', 0)}\n"
            f"⚠️ Unknown: {counts.get('unknown', 0)}\n"
            f"🚫 Blocked: {counts.get('blocked', 0)}"
        )
        if unknown:
            suspects = ", ".join(f"{d.get('hostname') or d.get('ip_address')} ({d.get('ip_address')})" for d in unknown[:3])
            return head + f"\n\nNeeds review: {suspects}"
        if recent:
            seen = ", ".join(f"{d.get('hostname') or d.get('ip_address')} ({d.get('ip_address')})" for d in recent[:3])
            return head + f"\n\nMost recent devices I can see: {seen}"
        return head

    def _threat_summary(self, data, language):
        attacks = data.get("active_attacks", 0)
        alerts = data.get("unacknowledged_alerts", 0)
        recent_alerts = data.get("recent_alerts", [])
        if language == "ar":
            message = (
                f"🛡️ حالة التهديدات:\n"
                f"⚔️ الهجمات النشطة: {attacks}\n"
                f"🔔 التنبيهات غير المقروءة: {alerts}"
            )
            if recent_alerts:
                titles = " | ".join(alert.get("title", "تنبيه") for alert in recent_alerts[:2])
                message += f"\n\nأحدث التنبيهات: {titles}"
            return message

        message = (
            f"🛡️ Threat Status:\n"
            f"⚔️ Active Attacks: {attacks}\n"
            f"🔔 Unread Alerts: {alerts}"
        )
        if recent_alerts:
            titles = " | ".join(alert.get("title", "Alert") for alert in recent_alerts[:2])
            message += f"\n\nLatest alerts: {titles}"
        return message

    def _prediction_summary(self, data, language):
        preds = data.get("predictions", [])
        if not preds:
            return (
                "🔮 لا توجد توقعات هجومية مرتفعة حالياً." if language == "ar"
                else "🔮 No high-confidence attack predictions right now."
            )
        top = preds[0]
        pct = round((top.get("probability") or 0) * 100)
        if language == "ar":
            return f"🔮 أعلى توقع حالي: {top.get('predicted_attack', 'تهديد غير معروف')} باحتمال {pct}% خلال {top.get('time_horizon', 30)} ثانية."
        return f"🔮 Top prediction right now: {top.get('predicted_attack', 'Unknown threat')} at {pct}% within {top.get('time_horizon', 30)} seconds."

    def _platform_summary(self, data, language):
        score = data.get("security_score", 85)
        attacks = data.get("active_attacks", 0)
        devices = data.get("devices", {})
        traffic = self._traffic_summary(data, language)
        if language == "ar":
            return (
                f"👁️ ملخص حورس الآن:\n"
                f"📊 درجة الأمان: {score}/100\n"
                f"🖥️ الأجهزة المرئية: {devices.get('total', 0)}\n"
                f"⚠️ الأجهزة المجهولة: {devices.get('unknown', 0)}\n"
                f"🛡️ الهجمات النشطة: {attacks}\n\n{traffic}"
            )
        return (
            f"👁️ Horus summary right now:\n"
            f"📊 Security Score: {score}/100\n"
            f"🖥️ Visible Devices: {devices.get('total', 0)}\n"
            f"⚠️ Unknown Devices: {devices.get('unknown', 0)}\n"
            f"🛡️ Active Attacks: {attacks}\n\n{traffic}"
        )

    def _capabilities_message(self, language):
        if language == "ar":
            return (
                "أستطيع مساعدتك في:\n"
                "1. تلخيص حالة الشبكة الحالية\n"
                "2. عرض الأجهزة الموصولة والمجهولة\n"
                "3. قراءة سرعات التنزيل والرفع\n"
                "4. شرح التنبيهات والهجمات والتوقعات\n"
                "5. شرح مفاهيم الأمن السيبراني"
            )
        return (
            "I can help with:\n"
            "1. Summarizing the live network state\n"
            "2. Listing connected and unknown devices\n"
            "3. Reporting download/upload speeds\n"
            "4. Explaining alerts, attacks, and predictions\n"
            "5. Explaining common cybersecurity concepts"
        )

    def _concept_explanation(self, query, language):
        q = query.lower()
        concepts = {
            "firewall": (
                "A firewall filters network traffic using rules so unwanted connections are blocked before they reach systems.",
                "جدار الحماية يرشّح حركة الشبكة وفق قواعد ليمنع الاتصالات غير المرغوبة قبل أن تصل إلى الأنظمة."
            ),
            "ddos": (
                "A DDoS attack floods a target with traffic from many sources so service becomes slow or unavailable.",
                "هجوم DDoS يغرق الهدف بحركة من مصادر كثيرة حتى تصبح الخدمة بطيئة أو غير متاحة."
            ),
            "phishing": (
                "Phishing is a fake message or page designed to trick users into giving passwords, codes, or money.",
                "التصيد هو رسالة أو صفحة مزيفة تهدف لخداع المستخدم وتسريب كلمات المرور أو الرموز أو المال."
            ),
            "malware": (
                "Malware is malicious software that steals data, disrupts systems, spies on users, or opens backdoors.",
                "البرمجيات الخبيثة هي برامج ضارة تسرق البيانات أو تعطل الأنظمة أو تتجسس أو تفتح أبواباً خلفية."
            ),
            "vpn": (
                "A VPN encrypts traffic between your device and a VPN server, mainly to protect traffic in transit and hide your public source.",
                "الـ VPN يشفّر الحركة بين جهازك وخادم VPN لحماية البيانات أثناء النقل وإخفاء المصدر العام."
            ),
            "honeypot": (
                "A honeypot is a decoy service that attracts attackers so you can observe behavior without exposing production systems.",
                "الـ honeypot هو خدمة خداعية تجذب المهاجمين لمراقبة سلوكهم دون تعريض الأنظمة الحقيقية للخطر."
            ),
            "mesh": (
                "Mesh defense models devices and links as a graph so critical nodes and isolation decisions are easier to spot.",
                "الدفاع الشبكي يصوّر الأجهزة والروابط كرسم بياني حتى يسهل اكتشاف العقد الحرجة وقرارات العزل."
            ),
            "bandwidth": (
                "Bandwidth is the data transfer rate over time, usually shown in Mbps for current network throughput.",
                "عرض النطاق هو معدل نقل البيانات مع الزمن وغالباً يُعرض بـ Mbps لقياس حركة الشبكة الحالية."
            ),
            "packet": (
                "A packet is a small unit of network data sent between devices. Traffic monitoring counts and inspects these packets.",
                "الحزمة هي وحدة صغيرة من بيانات الشبكة تنتقل بين الأجهزة، والمراقبة تعتمد على عدّ هذه الحزم وتحليلها."
            ),
        }
        for keyword, texts in concepts.items():
            if keyword in q:
                return texts[1] if language == "ar" else texts[0]
        return None

    # ── Rule-based security path ──────────────────────────────────────────────

    def _rule_security(self, query, data, language):
        q = query.lower()

        if any(kw in q for kw in ["help", "what can you do", "capabilities", "assist", "ماذا تستطيع", "مساعدة", "ساعدني"]):
            return self._capabilities_message(language)
        concept = self._concept_explanation(query, language)
        if concept:
            return concept
        if any(kw in q for kw in ["summary", "summarize", "overview", "status", "لخص", "ملخص", "نظرة عامة"]):
            return self._platform_summary(data, language)
        if any(kw in q for kw in ["device", "connected", "جهاز", "متصل", "أجهزة"]):
            return self._device_summary(data, language)
        if any(kw in q for kw in ["attack", "threat", "hack", "هجوم", "تهديد", "خطر"]):
            return self._threat_summary(data, language)
        if any(kw in q for kw in ["traffic", "bandwidth", "speed", "download", "upload", "packet", "latency", "حركة", "سرعة", "تنزيل", "رفع"]):
            return self._traffic_summary(data, language)
        if any(kw in q for kw in ["prediction", "predict", "forecast", "توقع", "تنبؤ"]):
            return self._prediction_summary(data, language)
        if any(kw in q for kw in ["honeypot", "mesh", "topology", "critical node", "مصيدة", "شبكة شبكية"]):
            honeypot = data.get("honeypot", {})
            mesh = data.get("mesh", {})
            if language == "ar":
                return (
                    f"🕸️ الدفاع الشبكي:\n"
                    f"🔗 عقد mesh: {mesh.get('nodes', 0)}\n"
                    f"📍 الروابط النشطة: {mesh.get('edges', 0)}\n"
                    f"🍯 أحداث honeypot: {honeypot.get('total_events', 0)}\n"
                    f"👤 مهاجمون فريدون: {honeypot.get('unique_attackers', 0)}"
                )
            return (
                f"🕸️ Mesh Defense:\n"
                f"🔗 Mesh Nodes: {mesh.get('nodes', 0)}\n"
                f"📍 Active Links: {mesh.get('edges', 0)}\n"
                f"🍯 Honeypot Events: {honeypot.get('total_events', 0)}\n"
                f"👤 Unique Attackers: {honeypot.get('unique_attackers', 0)}"
            )
        # Default for any security topic
        return self._platform_summary(data, language)

    # ── Rule-based general/playful path ──────────────────────────────────────

    def _rule_general(self, query, language, security_data=None):
        q = query.lower().strip()
        matcher = IntelligentMatcher()

        # ── animals ──────────────────────────────────────────────────────────
        animals = {
            "dog":    ["woof", "bark", "arf", "bow wow", "ruff", "pup", "doggo", "dog", "بوف", "نبح"],
            "cat":    ["meow", "mew", "purr", "kitten", "cat", "kitty", "ميو", "قطة", "قط"],
            "duck":   ["quack", "duck", "waddle", "بط", "واك"],
            "monkey": ["ooh ooh", "aah aah", "monkey", "ape", "primate", "قرد"],
            "dino":   ["roar", "dino", "dinosaur", "rex", "dragon", "تيراناصورس"],
        }
        replies = {
            "dog":    {"en": ["Woof! 🐕 Loyal security guard dog here — I bark at every threat!",
                              "Bark bark! 🐕 Smart guard dog online! I sniff out every intruder!"],
                       "ar": ["ووف! 🐕 كلب حراسة ذكي — أنبح عند كل تهديد!",
                              "هاو هاو! 🐕 كلب أمان هنا! أشمّ كل متسلل في شبكتك!"]},
            "cat":    {"en": ["Meow! 🐱 Security cat — silent but deadly accurate. I watch every packet!",
                              "Miaow! 🐱 Cats vs hackers — I always win! 🛡️"],
                       "ar": ["ميو! 🐱 قطة أمان — هادئة لكن دقيقة. أراقب كل حزمة بيانات!",
                              "ميياو! 🐱 القطط ضد الهاكرز — أنا دائماً أفوز! 🛡️"]},
            "duck":   {"en": ["Quack quack! 🦆 Security duck patrolling the data streams! 💧🔍"],
                       "ar": ["واك واك! 🦆 بطة أمان تراقب تدفقات البيانات! 💧🔍"]},
            "monkey": {"en": ["Ooh ooh! 🐵 Smart monkey watching from the top of the network tree! 🌳"],
                       "ar": ["أووه أووه! 🐵 قرد ذكي يراقب من أعلى شجرة الشبكة! 🌳"]},
            "dino":   {"en": ["ROARRR! 🦕 Mighty security dinosaur — no attacker survives! 💪"],
                       "ar": ["رووواار! 🦕 ديناصور أمان ضخم — لا ناجي منه! 💪"]},
        }
        for animal, kws in animals.items():
            if matcher.fuzzy_match(q, kws, threshold=0.5):
                pool = replies[animal].get(language, replies[animal]["en"])
                return random.choice(pool)

        # ── greetings ─────────────────────────────────────────────────────────
        greet_en = ["hello", "hi", "hey", "greetings", "howdy", "sup", "yo", "wassup"]
        greet_ar = ["مرحبا", "السلام", "اهلا", "كيف حالك", "السلام عليكم"]
        if any(w in q for w in (greet_ar if language == "ar" else greet_en)):
            if language == "ar":
                return ("السلام عليكم 👋\nأنا حورس، مساعدك في HorusShield.\n"
                        "✓ تحليل أمني  ✓ محادثة عامة  ✓ حتى أصوات الحيوانات! 🐕\nبماذا أساعدك؟")
            return ("Hello! 👋 I'm Horus, your HorusShield AI assistant.\n"
                    "✓ Security analysis  ✓ General chat  ✓ Even animal talk! 🐕\nWhat can I help with?")

        # ── how are you ───────────────────────────────────────────────────────
        if any(w in q for w in ["how are you", "what's up", "u good", "you good"]):
            return "All systems green! 🚀 Monitoring your network with full vigilance. How are YOU doing?"
        if any(w in q for w in ["كيف حالك", "كيفك", "ما أخبارك"]):
            return "أنا بحالة ممتازة! 🚀 جميع الأنظمة تعمل بكفاءة. كيف حالك أنت؟"

        # ── thanks ────────────────────────────────────────────────────────────
        if any(w in q for w in ["thanks", "thank you", "thx", "ty", "شكرا", "شكر"]):
            if language == "ar":
                return "أهلاً! 😊 أنا هنا دائماً للمساعدة."
            return "You're welcome! 😊 Always happy to help."

        if any(w in q for w in ["who are you", "what are you", "من أنت", "مين انت"]):
            if language == "ar":
                return "أنا حورس، مساعد HorusShield. أستطيع تلخيص حالة الشبكة، عرض الأجهزة، شرح التنبيهات، وشرح مفاهيم الأمن السيبراني بشكل مختصر وواضح."
            return "I'm Horus, the HorusShield assistant. I can summarize the network, list devices, explain alerts, report traffic speeds, and answer common cybersecurity questions."

        if any(w in q for w in ["help", "what can you do", "capabilities", "assist", "ماذا تستطيع", "مساعدة", "ساعدني"]):
            return self._capabilities_message(language)

        if any(w in q for w in ["fuck", "stupid", "idiot", "dumb", "غبي", "تافه"]):
            if language == "ar":
                return "سأبقى مفيداً. إذا أردت، أستطيع إعطاؤك ملخصاً فورياً للشبكة أو شرح أي تنبيه ظاهر."
            return "I’ll stay useful. If you want, I can give you a live network summary or explain any alert that’s showing."

        # ── jokes ─────────────────────────────────────────────────────────────
        if any(w in q for w in ["joke", "funny", "lol", "haha", "lmao", "نكتة", "مضحك", "ههه"]):
            jokes_en = [
                "Why do hackers never get tired? Because they're always plugged in! 😄",
                "What's a firewall's favourite film? The Great Blocker! 🍿",
                "I told a cybersecurity joke once… but it got blocked! 🚫😄",
            ]
            jokes_ar = [
                "لماذا القراصنة لا يتعبون؟ لأنهم دائماً متصلين! 😄",
                "ما أفضل فيلم لجدار الحماية؟ 'الحاجز العظيم'! 🍿",
                "قلت نكتة أمنية مرة... لكن جدار الحماية حجبها! 🚫😄",
            ]
            return random.choice(jokes_ar if language == "ar" else jokes_en)

        concept = self._concept_explanation(query, language)
        if concept:
            return concept

        if security_data and any(w in q for w in ["summary", "summarize", "overview", "status", "network", "traffic", "devices", "speed", "bandwidth", "لخص", "ملخص"]):
            return self._platform_summary(security_data, language)

        if any(w in q for w in ["secure my network", "improve security", "protect my network", "أمّن الشبكة", "حسّن الأمان"]):
            if language == "ar":
                return (
                    "ابدأ بهذه الخطوات:\n"
                    "1. وثّق كل جهاز مجهول أو احظره\n"
                    "2. راقب سرعات الرفع غير المعتادة\n"
                    "3. أغلق المنافذ غير الضرورية\n"
                    "4. فعّل المصائد والتنبيهات التلقائية\n"
                    "5. راجع الأجهزة ذات المنافذ الخطرة أولاً"
                )
            return (
                "Start with these steps:\n"
                "1. Review or block unknown devices\n"
                "2. Watch for unusual upload spikes\n"
                "3. Close unnecessary exposed ports\n"
                "4. Enable honeypots and automatic alerts\n"
                "5. Review devices with risky open ports first"
            )

        # ── default ───────────────────────────────────────────────────────────
        if security_data:
            if language == "ar":
                return (
                    "وصلتني رسالتك. أستطيع الرد بشكل أفضل إذا طلبت شيئاً محدداً مثل:\n"
                    "- لخص الشبكة الآن\n"
                    "- من المتصل بالشبكة؟\n"
                    "- ما سرعة التنزيل والرفع؟\n"
                    "- اشرح هذا التنبيه"
                )
            return (
                "I received your message. I can help best if you ask for something concrete like:\n"
                "- summarize the network\n"
                "- who is connected?\n"
                "- what are the download/upload speeds?\n"
                "- explain this alert"
            )
        return (
            "Tell me what you want to know and I’ll keep it practical."
            if language != "ar" else
            "قل لي ماذا تريد معرفته وسأجيب بشكل عملي."
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def ask(self, query, user_id="default", language="en"):
        """
        Main entry point.

        Dispatch order:
          1. Claude API  (with live security context injected)
          2. Rule-based security handler  (topic==security, Claude unavailable)
          3. Rule-based general/playful handler  (catch-all)
        """
        try:
            memory        = self._get_or_create_conversation(user_id)
            memory.add_message("user", query)
            topic         = memory.detect_topic()
            security_data = self._get_security_data()

            # 1. Gemini API, then Claude API
            gemini_reply = self._try_gemini(query, memory, security_data, language)
            if gemini_reply:
                memory.add_message("assistant", gemini_reply)
                logger.info(f"Gemini API reply — user={user_id} topic={topic}")
                return gemini_reply

            claude_reply = self._try_claude(query, memory, security_data, language)
            if claude_reply:
                memory.add_message("assistant", claude_reply)
                logger.info(f"Claude API reply — user={user_id} topic={topic}")
                return claude_reply

            # 2. Rule-based security
            if topic == "security" and security_data:
                reply = self._rule_security(query, security_data, language)
                memory.add_message("assistant", reply)
                logger.info(f"Rule-security reply — user={user_id}")
                return reply

            # 3. Rule-based general / playful
            reply = self._rule_general(query, language, security_data=security_data)
            memory.add_message("assistant", reply)
            logger.info(f"Rule-general reply — user={user_id} topic={topic}")
            return reply

        except Exception as e:
            logger.error(f"Horus error: {e}")
            if language == "ar":
                return "عذراً، حدث خطأ مؤقت 🔧 حاول مرة أخرى من فضلك"
            return "I encountered an error 🔧 Please try again"

    def get_conversation_history(self, user_id="default"):
        if user_id in self.conversations:
            return self.conversations[user_id].memory
        return []

    def clear_conversation(self, user_id="default"):
        if user_id in self.conversations:
            del self.conversations[user_id]
            logger.info(f"Conversation cleared for user {user_id}")
            return True
        return False

    def ask_with_engine(self, query, user_id="default", language="en"):
        """
        Like ask() but returns (response_str, engine_name) so callers can
        report which engine produced the answer.
        engine_name: 'gemini' | 'claude' | 'rule_security' | 'rule_general'
        """
        try:
            memory        = self._get_or_create_conversation(user_id)
            memory.add_message("user", query)
            topic         = memory.detect_topic()
            security_data = self._get_security_data()

            # 1. Gemini API, then Claude API
            gemini_reply = self._try_gemini(query, memory, security_data, language)
            if gemini_reply:
                memory.add_message("assistant", gemini_reply)
                logger.info(f"Gemini API reply — user={user_id} topic={topic}")
                return gemini_reply, "gemini"

            claude_reply = self._try_claude(query, memory, security_data, language)
            if claude_reply:
                memory.add_message("assistant", claude_reply)
                logger.info(f"Claude API reply — user={user_id} topic={topic}")
                return claude_reply, "claude"

            # 2. Rule-based security
            if topic == "security" and security_data:
                reply = self._rule_security(query, security_data, language)
                memory.add_message("assistant", reply)
                return reply, "rule_security"

            # 3. Rule-based general / playful
            reply = self._rule_general(query, language, security_data=security_data)
            memory.add_message("assistant", reply)
            return reply, "rule_general"

        except Exception as e:
            logger.error(f"Horus ask_with_engine error: {e}")
            msg = ("عذراً، حدث خطأ مؤقت 🔧 حاول مرة أخرى من فضلك"
                   if language == "ar" else
                   "I encountered an error 🔧 Please try again")
            return msg, "rule_general"
