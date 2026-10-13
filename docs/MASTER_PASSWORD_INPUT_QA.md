# Master password first-run UI regression — issue #25

This checklist complements, but **does not replace**, a physical-device investigation of the reported keyboard crash. Do not close #25 solely because the app builds, launches, or emulator/simulator UI tests pass. The original report has no confirmed platform, model, OS version, reproduction trace, or redacted crash report.

## Automated regression coverage

- **Android:** `MasterPasswordEntryInstrumentedTest` runs against a clean Android emulator through `android.yml`. It taps **Create vault**, enters individual characters, diacritics and emoji, erases them, tests a 280-character input truncated to 256, toggles masking, changes focus between the main and confirmation fields, creates a vault with a synthetic 12-character password, locks, recreates the activity, rejects an incorrect password, and unlocks again.
- **iOS:** `MasterPasswordEntryUITests` runs as an XCTest UI test inside `ios.yml` against a fresh iPhone simulator. It enters several characters and diacritics, deletes them, toggles secure/visible input and focus, tests the 256-character cap, creates a vault with a synthetic 12-character password, locks, terminates and relaunches the app, rejects an incorrect password, then unlocks again.
- Both tests use **synthetic, hard-coded, non-personal passwords only**. They do not access an existing user's vault.

## v0.6.25 additional hardening and remaining evidence

- iOS XCTest: the iOS 26.5 simulator exposed a misleading masked
  `SecureTextField.value` accessibility length of 1 while the test expected
  256. The original app flow proceeded through creation and unlock; the
  assertion was the test failure. The follow-up test checks length after
  revealing only synthetic text instead of treating a masked accessibility
  value as password length. This is a test fix, not evidence of an app crash.
- iOS: the create-vault password/confirmation cap now lives in the synchronous
  `Binding<String>` setter. Previously an `onChange` observer wrote the
  updated password back into the same SwiftUI state while the IME was editing.
  This removes that re-entrant state-write pattern; it is **not** a confirmed
  root-cause attribution for the originally reported crash.
- Android: first and second input digits in the main instrumented test are now sent using system `UiAutomation.injectInputEvent(KeyEvent)` keyboard events. The test waits for actual editable field content to change after each key. This covers more of the Android input dispatch path than Compose `performTextInput`, but it is still **an emulator**, not proof for a specific physical keyboard or IME.
- Android and iOS: instrumented first-run test flows now submit an 11-character
  synthetic password, confirm that it is rejected while the editing screen
  remains accessible, then clear it and successfully enter the minimum valid
  12-character synthetic password. Existing visibility, Unicode, 256-character,
  relock and wrong-password scenarios remain.
- Run the PR CI on its final commit on **both** platforms; earlier green runs
  from a different SHA are insufficient. Release CI now also runs Android
  instrumented UI tests and iOS first-run XCTest before artifact publication,
  rather than relying only on production builds and an iOS launch smoke test.
  Follow with actual hardware QA.
- The source report did not identify a platform, keyboard, OS, device or
  exception. Without a sanitized physical-device reproduction or evidence of
  a specific fixed defect, maintain issue #25 as open rather than marking
  the original crash resolved.

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
