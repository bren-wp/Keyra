#!/usr/bin/env python3
"""Reject vault backup/transfer regressions in Android release candidates."""
from pathlib import Path
import xml.etree.ElementTree as ET

root = Path("android/app/src/main")
manifest = ET.parse(root / "AndroidManifest.xml").getroot()
android_ns = "{http://schemas.android.com/apk/res/android}"
application = manifest.find("application")
assert application is not None, "Android application manifest is missing"

expected = {
    "allowBackup": "false",
    "fullBackupContent": "false",
    "usesCleartextTraffic": "false",
    "dataExtractionRules": "@xml/data_extraction_rules",
}
for name, value in expected.items():
    actual = application.get(android_ns + name)
    assert actual == value, f"Android {name}: expected {value}, got {actual}"

permissions = {
    item.get(android_ns + "name")
    for item in manifest.findall("uses-permission")
}
assert "android.permission.INTERNET" not in permissions, "Offline vault gained INTERNET permission"
assert "android.permission.MANAGE_EXTERNAL_STORAGE" not in permissions, (
    "Do not grant broad storage access to a password manager"
)

policy = ET.parse(root / "res/xml/data_extraction_rules.xml").getroot()
assert policy.tag == "data-extraction-rules"
for channel in ("cloud-backup", "device-transfer"):
    target = policy.find(channel)
    assert target is not None, f"Missing Android {channel} exclusion policy"
    rules = {(e.get("domain"), e.get("path")) for e in target.findall("exclude")}
    for domain in ("root", "device_root", "external"):
        assert (domain, ".") in rules, f"{channel}: failed to exclude {domain}"
    assert not target.findall("include"), f"{channel}: must never explicitly include private vault files"

print("Keyra Android vault privacy: backup, D2D transfer and network gates verified")
