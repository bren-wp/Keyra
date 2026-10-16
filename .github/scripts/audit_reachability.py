#!/usr/bin/env python3
"""Conservative static route/dead-code/resource inventory for Keyra.

Lexical reachability is not a replacement for native compiler checks,
Compose/UI tests, instrumented tests, or physical-device security QA.
No vault contents, keys, passwords or user logs are collected.
"""
from pathlib import Path
import re

root = Path(".")
android = (root / "android/app/src/main/java/com/keyra/app/MainActivity.kt").read_text()
ios = (root / "ios/Keyra/KeyraApp.swift").read_text()
android_ui = (root / "android/app/src/androidTest/java/com/keyra/app/MasterPasswordEntryInstrumentedTest.kt").read_text()
ios_ui = (root / "ios/KeyraUITests/MasterPasswordEntryUITests.swift").read_text()
unit_tests = (root / "android/app/src/test/java/com/keyra/app/PasswordToolsTest.kt").read_text()
swift_policy = (root / "ios/Keyra/RecoveryCiphertextPolicy.swift").read_text()
swift_tests = (root / "ios/tests/RecoveryCiphertextPolicyTests.swift").read_text()
corpus = "\n".join((android, ios, android_ui, ios_ui, unit_tests, swift_policy, swift_tests))

android_enum = re.search(r"enum class Screen \{([^}]*)\}", android)
ios_enum = re.search(r"enum KeyraScreen: Equatable \{([^}]*)\}", ios)
assert android_enum is not None and ios_enum is not None, "Root navigation enum absent"
android_routes = [s.strip() for s in android_enum.group(1).split(",")]
ios_routes = [s.strip() for s in ios_enum.group(1).replace("case", "").split(",")]
android_root = android.split("private fun KeyraRoot(", 1)[1].split("private fun SplashScreen(", 1)[0]
ios_root = ios.split("switch store.screen", 1)[1].split("if [.vault, .collections", 1)[0]
for route in android_routes:
    assert re.search(r"\bScreen\." + re.escape(route) + r"\s*->", android_root), (
        f"Android route absent from rendered root: {route}"
    )
for route in ios_routes:
    assert re.search(r"\bcase \." + re.escape(route) + r"\s*:", ios_root), (
        f"iOS route absent from rendered root: {route}"
    )

# Private methods named exactly once are candidates for HUMAN review, never
# automatic deletion: frameworks invoke some methods without textual callsites.
private_methods = (
    ("Android", android, r"\bprivate\s+fun\s+([A-Za-z_]\w*)\s*\("),
    ("iOS", ios, r"\bprivate\s+func\s+([A-Za-z_]\w*)\s*\("),
)
method_count = 0
potential_orphans = []
for platform, code, pattern in private_methods:
    for match in re.finditer(pattern, code):
        method_count += 1
        name = match.group(1)
        uses = len(re.findall(r"\b" + re.escape(name) + r"\b", corpus))
        if uses == 1:
            potential_orphans.append(f"{platform}:{name}")
assert not potential_orphans, (
    "Review possible dead private methods; do not auto-delete: " +
    ", ".join(potential_orphans)
)

project = (root / "ios/Keyra.xcodeproj/project.pbxproj").read_text()
for resource in ("KeyraApp.swift", "RecoveryCiphertextPolicy.swift",
                 "MasterPasswordEntryUITests.swift", "Assets.xcassets", "PrivacyInfo.xcprivacy"):
    assert resource in project, f"Missing iOS project member: {resource}"
for path in (
    "ios/Keyra/Assets.xcassets/AppIcon.appiconset/AppIcon.png",
    "android/app/src/main/res/drawable/ic_keyra.xml",
    "android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml",
    "android/app/src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml",
):
    assert (root / path).is_file(), f"Missing required app branding: {path}"

for platform, code in (("Android", android_ui), ("iOS", ios_ui)):
    for tag in ("keyra-master-password", "keyra-unlock-failure", "keyra-recovery-new-master"):
        assert tag in code, f"{platform} security test missing field: {tag}"

android_write = android.split("    fun save(items: List<VaultItem>) {", 1)[1].split("    fun clear()", 1)[0]
ios_write = ios.split("    func save(_ items: [VaultItem]) throws {", 1)[1].split("    func load()", 1)[0]
assert android_write.index("canPersistVaultItemIds") < android_write.index("crypto.encrypt(")
assert ios_write.index("VaultWritePolicy.allowsWrite") < ios_write.index("combined.write(")
assert "var passwordBytes = Array(password.utf8)" in ios
assert "for index in passwordBytes.indices { passwordBytes[index] = 0 }" in ios

print(
    f"Keyra static inventory OK: {len(android_routes)} Android + "
    f"{len(ios_routes)} iOS rendered routes, {method_count} private methods "
    "scanned, required assets and authentication tests wired; vault-write "
    "guards precede ciphertext writes. Dynamic device behavior remains "
    "unverified by this script."
)
