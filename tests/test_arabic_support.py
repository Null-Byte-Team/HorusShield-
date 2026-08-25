"""Tests for utils/arabic_support.py — pure translation/i18n helpers."""


def test_translate_returns_arabic_for_known_key():
    from utils.arabic_support import translate

    assert translate("dashboard", "ar") == "لوحة التحكم"


def test_translate_returns_english_for_known_key():
    from utils.arabic_support import translate

    result = translate("dashboard", "en")
    assert isinstance(result, str) and result


def test_translate_falls_back_gracefully_for_unknown_key():
    from utils.arabic_support import translate

    assert translate("totally_made_up_key_xyz", "ar") == "totally_made_up_key_xyz"
    assert translate("totally_made_up_key_xyz", "en") == "Totally Made Up Key Xyz"


def test_get_all_translations_returns_full_dict_for_each_language():
    from utils.arabic_support import get_all_translations

    ar = get_all_translations("ar")
    en = get_all_translations("en")
    assert isinstance(ar, dict) and len(ar) > 0
    assert isinstance(en, dict) and len(en) > 0
    # mutating the returned dict must not mutate the module's own translation table
    ar["dashboard"] = "MUTATED"
    assert get_all_translations("ar")["dashboard"] != "MUTATED"


def test_get_text_direction():
    from utils.arabic_support import get_text_direction

    assert get_text_direction("ar") == "rtl"
    assert get_text_direction("en") == "ltr"
    assert get_text_direction("fr") == "ltr"  # unknown language defaults to ltr


def test_get_font_family_differs_by_language():
    from utils.arabic_support import get_font_family

    assert "Cairo" in get_font_family("ar")
    assert "Cairo" not in get_font_family("en")
