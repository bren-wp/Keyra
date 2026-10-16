#!/usr/bin/env python3
"""Regression guard for safe password-entry and optional verifier upgrades.

Source-contract gate supplements (does not replace) real Compose/XCTest UI tests.
Do not log actual credentials or recovered vault data.
"""
from pathlib import Path

android = Path("android/app/src/main/java/com/keyra/app/MainActivity.kt").read_text()
ios = Path("ios/Keyra/KeyraApp.swift").read_text()
android_ui = Path("android/app/src/androidTest/java/com/keyra/app/MasterPasswordEntryInstrumentedTest.kt").read_text()
ios_ui = Path("ios/KeyraUITests/MasterPasswordEntryUITests.swift").read_text()

def segment(source: str, begin: str, end: str) -> str:
    assert begin in source and end in source, f"Missing section boundary: {begin}"
    section = source.split(begin, 1)[1]
    assert end in section, f"Missing section end: {end}"
    return section.split(end, 1)[0]

ios_auth = segment(ios, "    func verify(password: String) -> Bool {", "    private func clearLegacyDefaults()")
android_auth = segment(android, "    fun verify(password: String): Boolean {", "    private fun verifierKey(): SecretKey {")
assert "return create(password: password)" not in ios_auth, "iOS optional migration must never deny a valid password"
assert "_ = create(password: password)" in ios_auth, "iOS verifier upgrade must remain best effort"
assert "if (ok && !create(password)) return false" not in android_auth, "Android legacy verifier migration must not cause a false rejection"
assert "if (ok) create(password)" in android_auth, "Android legacy verifier should still upgrade when possible"

ios_recovery = segment(ios, "struct RecoverySetupView: View {", "struct UnlockView: View {")
android_recovery = segment(android, "private fun RecoverySetupScreen(", "internal fun boundedNewMasterPasswordInput(")
assert "private var newMasterBinding: Binding<String>" in ios_recovery
assert "private var confirmationBinding: Binding<String>" in ios_recovery
assert "String($0.prefix(256))" in ios_recovery
assert ".onChange(of: newPassword)" not in ios_recovery
assert ".onChange(of: confirmPassword)" not in ios_recovery
assert "testIdentifier: \"keyra-recovery-new-master\"" in ios_recovery
assert "newPassword == confirmPassword" in ios_recovery
assert "val masked = remember { PasswordVisualTransformation() }" in android_recovery
assert "visualTransformation = if (reveal) VisualTransformation.None else masked" in android_recovery
assert "testTag(\"keyra-recovery-new-master\")" in android_recovery
assert "newPassword == confirmPassword" in android_recovery

assert "keyra-first-run-recover" in android_ui and "keyra-recovery-new-master" in android_ui
assert "keyra-first-run-recover" in ios_ui and "keyra-recovery-new-master" in ios_ui

print("Keyra first-run recovery input and best-effort verifier migration contracts: OK")
