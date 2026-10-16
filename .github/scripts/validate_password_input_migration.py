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
assert "recoveryBack.waitForExistence" in ios_ui
assert "recoveryScroll.swipeUp()" in ios_ui and "recoveryScroll.swipeDown()" in ios_ui

# Stable and accessible rejection UI across both platforms, independent of
# short-lived global notices, without changing verifier or ciphertext behavior.
android_unlock = segment(android, "    fun unlock(password: String) {", "    fun biometricRequestToken(): Long")
ios_unlock = segment(ios, "    func unlock(password: String) {", "    func unlockBiometric() {")
android_form = segment(android, "private fun UnlockScreen(", "private fun KeyraPasswordField(")
ios_form = segment(ios, "struct UnlockView: View {", "struct SecretField: View {")
assert "unlockFailureMessage = null" in android_unlock
assert "unlockFailureMessage = " in android_unlock
assert "keyra-unlock-failure" in android_form and "model.unlockFailureMessage" in android_form
assert "keyra-unlock-failure" in android_ui and "unlockFailureMessage" in android_ui
assert "unlockFailureMessage = nil" in ios_unlock
assert "keyra-unlock-failure" in ios_form and "store.unlockFailureMessage" in ios_form
assert "keyra-unlock-failure" in ios_ui
assert "self.unlockFailureMessage = nil" in ios, "Biometric unlock must clear stale failure feedback"

print("Keyra first-run input, stable unlock rejection UI and verifier migration contracts: OK")
