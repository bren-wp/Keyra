# Master password first-run UI regression — issue #25

This checklist complements, but **does not replace**, a physical-device investigation of the reported keyboard crash. Do not close #25 solely because the app builds, launches, or emulator/simulator UI tests pass. The original report has no confirmed platform, model, OS version, reproduction trace, or redacted crash report.

## Automated regression coverage

- **Android:** `MasterPasswordEntryInstrumentedTest` runs against a clean Android emulator through `android.yml`. It taps **Create vault**, enters individual characters, diacritics and emoji, erases them, tests a 280-character input truncated to 256, toggles masking, changes focus between the main and confirmation fields, creates a vault with a synthetic 12-character password, locks, recreates the activity, rejects an incorrect password, and unlocks again.
- **iOS:** `MasterPasswordEntryUITests` runs as an XCTest UI test inside `ios.yml` against a fresh iPhone simulator. It enters several characters and diacritics, deletes them, toggles secure/visible input and focus, tests the 256-character cap, creates a vault with a synthetic 12-character password, locks, terminates and relaunches the app, rejects an incorrect password, then unlocks again.
- Both tests use **synthetic, hard-coded, non-personal passwords only**. They do not access an existing user's vault.

## Required physical QA

Run the full flow separately on an Android device and an iPhone (including one device with a non-English keyboard):

1. Fresh install with no existing vault. Open **Create vault**, then type the *first character*, one additional character at a time and a longer sequence.
2. Check masked and visible text, password/confirmation focus transitions, cursor editing, selection, backspace, keyboard show/hide, portrait/landscape, autocorrect suggestions, on-screen IME and paste.
3. Check ASCII, Croatian diacritics, combining marks, emoji and supplementary Unicode scalars; validate 11, **12**, **256**, and 257+ characters.
4. Complete vault creation; foreground/background, lock, force-close/reopen, reject a wrong password and unlock with the correct test password. Verify no existing data is silently replaced.
5. Repeat with TalkBack/VoiceOver enabled, larger accessibility text, and device lock/biometric options if available. Verify no unexpected crash/ANR/freezing.

Record OS version, build number, device model, keyboard/IME (and version), first failing step, screen orientation, whether the keyboard is physical/virtual, and whether the app closes, freezes or reports an error. **Do not record typed credentials.**

## Privacy-safe crash diagnostics

**Never attach raw device logs, real passwords, TOTP seeds, Recovery Key data, `.keyra` files, clipboard contents, account names, access tokens, device identifiers, emails, file paths or personal data to GitHub.**

For Android, capture the issue locally on a test device using a **synthetic password**:

```sh
adb logcat -c
# Reproduce the crash using only a synthetic test password.
adb logcat -d -v brief AndroidRuntime:E '*:S' > keyra-private-android-crash.log
```

The resulting file is **private/unredacted** and is **not ready to upload**. Manually extract only the exception type, sanitized app-specific stack frames, Android version, manufacturer/model (if appropriate), and precise reproduction steps. Remove all exception message values, user input, paths, account references and identifiers before sharing a minimal issue comment.

For iOS, retrieve the Keyra report from device Analytics Data or Xcode Devices and Simulators. Privately inspect the exception type and crashed thread, then manually redact all device identifiers, paths, addresses, input strings and potentially identifying metadata. Share only the sanitized exception category, relevant symbolicated Keyra frames, device/OS version and steps.

If the failure cannot be reproduced and no sanitized trace is available, leave #25 open and record the tested configurations and unverified criteria; do not claim a confirmed fix.
