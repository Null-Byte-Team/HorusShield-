"""
HorusShield Arabic Support — Factory Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Feature 13: Arabic language support and Factory Mode translations.
"""


# Complete Arabic translation dictionary
ARABIC_TRANSLATIONS = {
    # ── Navigation ──
    "dashboard": "لوحة التحكم",
    "network_monitor": "مراقبة الشبكة",
    "devices": "الأجهزة",
    "attacks": "الهجمات",
    "alerts": "التنبيهات",
    "security_score": "درجة الأمان",
    "network_map": "خريطة الشبكة",
    "threat_map": "خريطة التهديدات",
    "honeypot": "مصيدة العسل",
    "mesh_defense": "الدفاع الشبكي",
    "reports": "التقارير",
    "settings": "الإعدادات",
    "ask_horus": "اسأل حورس",

    # ── Dashboard ──
    "total_devices": "إجمالي الأجهزة",
    "active_attacks": "الهجمات النشطة",
    "security_level": "مستوى الأمان",
    "network_status": "حالة الشبكة",
    "traffic_overview": "نظرة عامة على حركة المرور",
    "recent_alerts": "التنبيهات الأخيرة",
    "threat_distribution": "توزيع التهديدات",
    "real_time_traffic": "حركة المرور المباشرة",

    # ── Device Status ──
    "trusted": "موثوق",
    "unknown": "غير معروف",
    "blocked": "محظور",
    "suspicious": "مشبوه",
    "online": "متصل",
    "offline": "غير متصل",
    "new_device": "جهاز جديد",
    "unknown_device": "جهاز غير معروف",

    # ── Device Types ──
    "router": "جهاز توجيه",
    "pc": "حاسوب",
    "phone": "هاتف",
    "server": "خادم",
    "printer": "طابعة",
    "iot": "إنترنت الأشياء",

    # ── Attack Types ──
    "ddos": "هجوم حجب الخدمة",
    "port_scan": "مسح المنافذ",
    "brute_force": "هجوم القوة الغاشمة",
    "anomaly": "سلوك غير طبيعي",
    "malware": "برمجيات خبيثة",
    "data_exfiltration": "تسريب البيانات",
    "intrusion": "اقتحام",
    "man_in_the_middle": "هجوم الرجل في المنتصف",

    # ── Severity Levels ──
    "critical": "حرج",
    "high": "عالي",
    "medium": "متوسط",
    "low": "منخفض",
    "info": "معلومات",

    # ── Attack Status ──
    "active": "نشط",
    "mitigated": "تم التخفيف",
    "false_positive": "إنذار كاذب",
    "investigating": "قيد التحقيق",

    # ── Actions ──
    "block": "حظر",
    "unblock": "إلغاء الحظر",
    "scan": "فحص",
    "trust": "وثق",
    "investigate": "تحقيق",
    "dismiss": "تجاهل",
    "export": "تصدير",
    "generate_report": "إنشاء تقرير",
    "download": "تحميل",
    "refresh": "تحديث",
    "start_scan": "بدء الفحص",
    "stop_scan": "إيقاف الفحص",
    "acknowledge": "إقرار",
    "acknowledge_all": "إقرار الكل",

    # ── Modes ──
    "dark_mode": "الوضع الداكن",
    "light_mode": "الوضع الفاتح",
    "emergency_mode": "وضع الطوارئ",
    "lockdown_mode": "وضع الإغلاق",
    "demo_mode": "وضع التجريبي",
    "factory_mode": "وضع المصنع",
    "anubis_mode": "وضع أنوبيس",

    # ── Lockdown ──
    "lockdown_activated": "تم تفعيل وضع الإغلاق الطارئ",
    "lockdown_deactivated": "تم إلغاء وضع الإغلاق",
    "all_traffic_blocked": "تم حظر جميع حركة المرور غير المصرح بها",
    "emergency_response": "الاستجابة للطوارئ",

    # ── Security Score ──
    "excellent": "ممتاز",
    "good": "جيد",
    "fair": "مقبول",
    "poor": "ضعيف",
    "critical_level": "مستوى حرج",
    "device_security": "أمان الأجهزة",
    "network_health": "صحة الشبكة",
    "attack_history": "سجل الهجمات",
    "vulnerability_exposure": "التعرض للثغرات",
    "ai_confidence": "ثقة الذكاء الاصطناعي",
    "improving": "تحسن",
    "stable": "مستقر",
    "declining": "تراجع",

    # ── Honeypot ──
    "honeypot_active": "المصيدة نشطة",
    "honeypot_inactive": "المصيدة غير نشطة",
    "trap_triggered": "تم تفعيل المصيدة",
    "attacker_detected": "تم كشف مهاجم",
    "ssh_honeypot": "مصيدة SSH",
    "http_honeypot": "مصيدة HTTP",
    "ftp_honeypot": "مصيدة FTP",
    "total_interactions": "إجمالي التفاعلات",
    "unique_attackers": "مهاجمون فريدون",

    # ── Mesh Defense ──
    "mesh_active": "الدفاع الشبكي نشط",
    "critical_nodes": "العقد الحرجة",
    "isolated_nodes": "العقد المعزولة",
    "network_redundancy": "تكرار الشبكة",
    "topology_analysis": "تحليل الطوبولوجيا",
    "isolate_node": "عزل العقدة",
    "restore_node": "استعادة العقدة",

    # ── Reports ──
    "security_report": "تقرير الأمان",
    "daily_report": "تقرير يومي",
    "weekly_report": "تقرير أسبوعي",
    "incident_report": "تقرير الحوادث",
    "report_generated": "تم إنشاء التقرير",

    # ── Horus Assistant ──
    "horus_greeting": "مرحباً، أنا حورس. كيف يمكنني مساعدتك في أمان شبكتك؟",
    "horus_thinking": "جارٍ التحليل...",
    "ask_question": "اطرح سؤالاً...",
    "type_message": "اكتب رسالتك...",

    # ── System Messages ──
    "system_online": "النظام متصل",
    "system_offline": "النظام غير متصل",
    "monitoring_active": "المراقبة نشطة",
    "monitoring_paused": "المراقبة متوقفة",
    "ai_analyzing": "الذكاء الاصطناعي يحلل",
    "scan_complete": "اكتمل الفحص",
    "no_threats": "لا توجد تهديدات",
    "threat_detected": "تم اكتشاف تهديد",

    # ── Time ──
    "just_now": "الآن",
    "minutes_ago": "دقائق مضت",
    "hours_ago": "ساعات مضت",
    "days_ago": "أيام مضت",

    # ── Common ──
    "yes": "نعم",
    "no": "لا",
    "ok": "حسناً",
    "cancel": "إلغاء",
    "save": "حفظ",
    "delete": "حذف",
    "edit": "تعديل",
    "close": "إغلاق",
    "search": "بحث",
    "filter": "تصفية",
    "sort": "ترتيب",
    "loading": "جارٍ التحميل...",
    "error": "خطأ",
    "success": "نجاح",
    "warning": "تحذير",
    "confirm": "تأكيد",
    "back": "رجوع",
    "next": "التالي",
    "previous": "السابق",

    # ── PDF Report Headers ──
    "pdf_title": "تقرير أمان HorusShield",
    "pdf_generated": "تم إنشاء التقرير بتاريخ",
    "pdf_summary": "ملخص الأمان",
    "pdf_devices_section": "قسم الأجهزة",
    "pdf_attacks_section": "قسم الهجمات",
    "pdf_recommendations": "التوصيات",
}


# English translations (default)
ENGLISH_TRANSLATIONS = {k: k.replace("_", " ").title() for k in ARABIC_TRANSLATIONS}
ENGLISH_TRANSLATIONS.update({
    "horus_greeting": "Hello, I'm Horus. How can I help you with your network security?",
    "horus_thinking": "Analyzing...",
    "ask_question": "Ask a question...",
    "type_message": "Type your message...",
    "pdf_title": "HorusShield Security Report",
    "pdf_generated": "Report generated on",
    "pdf_summary": "Security Summary",
    "pdf_devices_section": "Devices Section",
    "pdf_attacks_section": "Attacks Section",
    "pdf_recommendations": "Recommendations",
    "lockdown_activated": "Emergency lockdown mode activated",
    "lockdown_deactivated": "Lockdown mode deactivated",
    "all_traffic_blocked": "All unauthorized traffic has been blocked",
})


def translate(key, language="en"):
    """Translate a key to the specified language.

    Args:
        key: Translation key
        language: 'en' or 'ar'

    Returns:
        Translated string
    """
    if language == "ar":
        return ARABIC_TRANSLATIONS.get(key, key)
    return ENGLISH_TRANSLATIONS.get(key, key.replace("_", " ").title())


def get_all_translations(language="en"):
    """Get all translations for a language."""
    if language == "ar":
        return ARABIC_TRANSLATIONS.copy()
    return ENGLISH_TRANSLATIONS.copy()


def get_text_direction(language="en"):
    """Get text direction for a language."""
    return "rtl" if language == "ar" else "ltr"


def get_font_family(language="en"):
    """Get appropriate font family for a language."""
    if language == "ar":
        return "'Cairo', 'Noto Kufi Arabic', sans-serif"
    return "'Orbitron', 'JetBrains Mono', sans-serif"
