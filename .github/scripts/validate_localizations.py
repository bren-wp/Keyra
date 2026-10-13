#!/usr/bin/env python3
"""Verify that Keyra's Android and iOS first-run copy stays in lockstep."""
import json
import re
from pathlib import Path

android = Path("android/app/src/main/java/com/keyra/app/MainActivity.kt").read_text(encoding="utf-8")
ios = Path("ios/Keyra/KeyraApp.swift").read_text(encoding="utf-8")


def section(text, begin, end):
    assert text.count(begin) == 1, f"Expected exactly one {begin}"
    return text.split(begin, 1)[1].split(end, 1)[0]


def quoted_list(value):
    return json.loads("[" + value + "]")


android_languages = set(re.findall(
    r'"([a-z]{2})"\s+to\s+"[^"]+"',
    section(android, "internal val keyraLanguageNames = linkedMapOf(", "\n)")
))
ios_languages = set(re.findall(
    r'\("([a-z]{2})",\s*"[^"]+"\)',
    section(ios, "private let keyraLanguages: [(code: String, name: String)] = [", "\n]")
))
assert android_languages == ios_languages, "Android and iOS selectable locales differ"
assert len(android_languages) == 27, "Keyra must expose exactly 27 configured languages"
assert {"en", "hr"} <= android_languages, "English and Croatian must remain available"

android_keys = quoted_list(
    section(android, "internal val keyraCoreKeys = listOf(", ")\n")
)
ios_keys = quoted_list(
    section(ios, "private let keyraCoreKeys: [String] = [", "]\n")
)
assert android_keys == ios_keys, "Primary translated strings differ between platforms"
assert len(android_keys) == len(set(android_keys)) and len(android_keys) >= 7

android_pairs = re.findall(
    r'^\s*"([a-z]{2})" to listOf\((.*)\),?\s*$',
    section(android, "internal val keyraCoreTranslations: Map<String, List<String>> = mapOf(", "\n)"),
    re.MULTILINE,
)
ios_pairs = re.findall(
    r'^\s*"([a-z]{2})": \[(.*)\],?\s*$',
    section(ios, "private let keyraCoreTranslations: [String: [String]] = [", "\n]"),
    re.MULTILINE,
)
android_copy = {code: quoted_list(values) for code, values in android_pairs}
ios_copy = {code: quoted_list(values) for code, values in ios_pairs}
expected = android_languages - {"en"}
assert set(android_copy) == expected, "Android translation coverage is incomplete"
assert set(ios_copy) == expected, "iOS translation coverage is incomplete"
assert android_copy == ios_copy, "Translated labels must match across platforms"
for code, values in android_copy.items():
    assert len(values) == len(android_keys), f"Wrong translation count for {code}"
    assert all(isinstance(s, str) and s.strip() for s in values), f"Blank translation for {code}"

print(
    f"Keyra localization parity verified: {len(android_languages)} languages, "
    f"{len(android_keys)} primary controls, Android and iOS identical."
)
