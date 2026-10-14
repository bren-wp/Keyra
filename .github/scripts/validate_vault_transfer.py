#!/usr/bin/env python3
"""Reject Android/iOS vault backup, transfer and lifecycle privacy regressions."""
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

# Cross-platform storage and lifecycle privacy gates.
android_code = Path("android/app/src/main/java/com/keyra/app/MainActivity.kt").read_text(encoding="utf-8")
ios_code = Path("ios/Keyra/KeyraApp.swift").read_text(encoding="utf-8")
assert "SystemClock.elapsedRealtime()" in android_code, "Android background timer uses wall time"
assert "System.currentTimeMillis() - started" not in android_code, (
    "Android must not allow a system clock rollback to bypass auto-lock"
)
assert "shouldLockAfterBackground(" in android_code, "Android fail-closed auto-lock policy missing"
assert "@State private var backgroundedAt: ContinuousClock.Instant?" in ios_code, (
    "iOS must use ContinuousClock for elapsed background time"
)
assert "backgroundedAt = Date()" not in ios_code, "iOS auto-lock reverted to wall time"

storage_start = ios_code.index("    private func storageURL() throws -> URL {")
storage_end = ios_code.index("    func hasPersistedCiphertext()", storage_start)
storage = ios_code[storage_start:storage_end]
assert "FileProtectionType.complete" in storage, "iOS directory protection is missing"
assert "FileManager.default.setAttributes(" in storage, "iOS existing vault directory may lack protection"
assert "values.isExcludedFromBackup = true" in storage, "iOS backup exclusion is missing"
assert "try directory.setResourceValues(values)" in storage, "iOS backup exclusion must report errors"
assert "try? directory.setResourceValues(values)" not in storage, (
    "iOS backup exclusion errors must not be silently swallowed"
)

# Locking a vault must revoke a Keyra-owned clipboard entry without clearing
# clipboard content copied later by the user or another app.
android_lock = android_code.split("    fun lock() {", 1)[1].split("    fun eraseAllLocalData()", 1)[0]
ios_lock = ios_code.split("    func lock() {", 1)[1].split("    @discardableResult", 1)[0]
assert "SensitiveClipboard.clearIfOwned(" in android_lock, "Android lock should revoke owned clipboard secrets"
assert "SecureClipboard.clearIfOwned()" in ios_lock, "iOS lock should revoke owned clipboard secrets"
assert "shouldClearOwnedClipboard(" in android_code, "Android clipboard ownership verifier is missing"
assert "pasteboard.changeCount == expected" in ios_code, "iOS clipboard ownership verifier is missing"

# Recovery export can only rewrap the existing vault key. A missing
# device-wrapped key must never be silently replaced with a new random one.
android_recovery = android_code.split("private class VaultStore(", 1)[1].split("internal fun readUtf8Limited(", 1)[0]
ios_vault = ios_code.split("final class EncryptedVault {", 1)[1].split("enum PortableBackup {", 1)[0]
assert "fun existingPortableKeyBytes(): ByteArray" in android_code, (
    "Android read-only portable key accessor is missing"
)
assert "fun recoveryKeyBytes(): ByteArray = crypto.existingPortableKeyBytes()" in android_recovery, (
    "Android Recovery Key export must never create a replacement vault key"
)
assert "static func existingRawKeyData() throws -> Data" in ios_code, (
    "iOS existing Keychain key accessor is missing"
)
assert "try KeychainVault.existingRawKeyData()" in ios_vault, (
    "iOS Recovery Key export must never generate a new Keychain key"
)

print("Keyra vault privacy gates passed: encrypted-storage, clipboard, monotonic locks and read-only Recovery Key exports")
