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
- Android: v0.6.25 CI initially attempted `UiAutomation.injectInputEvent(KeyEvent)` for the first two digits, followed by a test predicate that compared a Compose `AnnotatedString` to a Kotlin `String`. The predicate could not become true, resulting in a `ComposeTimeoutException` in [Android run #38463002897](https://github.com/bren-wp/Keyra/actions/runs/38463002897). That failure **does not establish** whether the system key event reached the text field. The mandatory regression now uses deterministic Compose editing actions and checks `EditableText.text.text` (the actual String) after each digit. Hardware keyboard/IME delivery remains a separate physical-device QA requirement.
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

## v0.6.30 — readability and additional keyboard continuity coverage

- Android and iOS create-vault editors now show **12–256-character guidance** and
  a live password/confirmation matching hint. They display only lengths and
  matching status, not characters or entropy estimates.
- Android instrumented Compose regression verifies that the first inserted
  digit updates the visible guidance while the field stays mounted, that the
  confirmation hint appears and that previous Unicode/256-character/create/
  relock/wrong-password tests still run.
- iOS XCTest verifies first- and second-character field continuity, the
  corresponding accessible guidance and the confirmation status in addition
  to its secure/reveal/focus/Unicode/256-character/create/reopen tests.
- Android/iOS onboarding can scroll when larger accessibility text or a
  short screen would otherwise clip primary actions; on regular devices
  buttons remain reachable without needing to scroll. Navigation labels use
  larger type and up to two lines, rather than shrinking to tiny labels.
- **Original crash root cause remains unknown.** A correctly passing
  emulator/simulator suite cannot prove that the physical-device report is
  resolved. Neither the user report nor CI provides a matching physical
  device model, OS build, keyboard/IME, exception trace or crash signature.

### Exact physical-device evidence required before closing issue #25

On both an Android handset and an iPhone, using synthetic credentials only:

1. Clean install, choose Create vault, focus the master-password field and
   enter the *first character* using the real on-screen keyboard. Repeat for
   the second character, after emoji/diacritics, after revealing/hiding text,
   and after changing focus to the confirmation field.
2. Repeat with a third-party keyboard/IME when applicable, keyboard suggestion
   bar active, display/font scaling increased, narrow display, landscape and
   TalkBack/VoiceOver. Do not disable accessibility just to make the test pass.
3. Exercise 11/12/256-character boundaries, vault creation, app termination,
   relock, invalid unlock and correct unlock. Ensure unexpected process
   termination never destroys or replaces ciphertext.
4. If any crash occurs, capture a **sanitized** logcat exception/ANR tombstone
   or iOS crash report with only app stack, OS/device and keyboard version.
   Never upload typed credentials, clipboard content, item details, private
   backup files, authentication keys or full unredacted logs.
5. Attach device/OS/keyboard matrix and a redacted trace or a signed-off
   physical regression checklist to issue #25 before closing it.

Any passing CI run should record its **exact head SHA**. Cancelling older
runs after a new commit is not a passing result for the current head.

## v0.6.31 — Recovery Key keyboard and verifier migration follow-up

The first-run **Restore with Recovery Key** flow has a separate password editor from
**Create vault**. Prior iOS code rewrote `newPassword` and `confirmPassword` in
SwiftUI `.onChange` callbacks while the IME was editing. It now constrains both
inputs in synchronous `Binding` setters and uses the same `SecretField` component
as the standard new-vault editor, preserving focus on reveal/hide. Android's
recovery fields now reuse one remembered `PasswordVisualTransformation` during
recomposition. Both platforms display a non-secret length/matching hint and
require matching new passwords before enabling restore.

- Android Compose instrumented first-run test enters successive characters,
  Croatian Unicode and an oversized synthetic paste into the recovery password
  editor, then safely returns to onboarding before normal vault creation tests.
- iOS XCTest opens recovery before the first vault is created, enters the first
  and next characters (including Croatian diacritics), checks visible guidance
  and returns to onboarding. Its earlier 11/12/256-character new-vault tests
  remain; they do not constitute an independent 256-character iOS recovery test.
- Android/iOS opportunistic legacy master-password verifier migration no longer
  treats a correct password as wrong when the new verifier cannot be saved.
  The old verifier is preserved for retry; the vault's actual decryption
  still must succeed before any data is displayed.
- Cross-platform source-integrity CI enforces these input and verifier
  contracts, in addition to full Android/iOS build and simulator UI tests.

**Issue #25 remains open until the original hardware-reported crash can be
reproduced or excluded on documented real devices with privacy-safe diagnostic
evidence.** Emulator/simulator green results show their covered paths only.

## v0.6.32 — diagnosis of main Android CI failure (16 October 2026)

This is **an Android instrumented test failure, not a demonstrated Keyra
application crash**. At the merged v0.6.31 main SHA
`4577418fcf4e389391360029dc16e68040769f99`,
[Android Actions run 38958244102](https://github.com/bren-wp/Keyra/actions/runs/38958244102)
failed inside `MasterPasswordEntryInstrumentedTest.kt:198` with a
`ComposeTimeoutException` after 20 seconds. The Android build, lint, unit
tests and source/privacy gates passed. The test had already created and
relocked a synthetic vault, recreated its activity and submitted an
intentionally incorrect password.

The failing assertion waited for `Glavna lozinka nije ispravna.`, a visual
message which the root UI dismisses after approximately **2.6 seconds**.
Under variable emulator load, sampling that transient UI state is not a
reliable authentication-result assertion. The captured logcat did **not**
show a Keyra `FATAL EXCEPTION` or an attributable Android application
crash. The same original SHA passed its independent Android release-packaging
emulator run; that does not negate the main workflow test failure.

The v0.6.32 correction waits for the persistent, synthetic
`unlock_failed_attempts == 1` counter after submitting the incorrect
password, then checks that the screen remains `UNLOCK`, the vault is **not
unlocked**, and the asynchronous authentication request has completed. It
continues to test a subsequent successful unlock and missing-ciphertext
fail-closed behavior.

Release publication now also requires successful **main** Android and iOS
GitHub Actions workflows for the exact release commit, in addition to the
release workflow's own platform tests. A red main-platform check must no
longer be masked by a green independent packaging run.

This correction addresses a confirmed CI timing defect. It is **not** a
validated root-cause fix for the original hardware keyboard report #25,
which remains open pending physical-device evidence. No real passwords,
vaults or production keys were used in the failing synthetic test.

## v0.6.33 — stable iOS unlock rejection feedback

After the Android v0.6.32 timing regression, review found that the iOS XCTest
unlock flow still waited for the same short-lived 2.6-second root notification.
That observation was not a dependable assertion of authentication rejection.

On iOS, an incorrect password or active lockout now sets a **non-secret,
persistent inline error** on the unlock form, with a stable accessibility
identifier `keyra-unlock-failure`. The state is cleared on retry and on
manual lock. The root transient notification remains available for unrelated
operations. The UI regression waits for the persistent rejection, confirms the
vault's settings navigation is absent, and verifies that a subsequent correct
unlock removes the failure state. This does not modify the verifier, lockout
counters, ciphertext, KDF or backup formats.

The v0.6.33 Android and iOS build versions are synchronized at build 39.
Device-specific keyboard/IME crash #25 still requires a sanitized real-device
trace or documented physical-device reproduction before closure.

## v0.6.34 — durable Android unlock rejection and biometric success cleanup

Reviewed Android's `KeyraViewModel.unlock`, lockout, `lock`,
`unlockFromBiometric`, and the real Compose unlock form after v0.6.33.
Unlike iOS, Android still displayed a rejected password only through a
2.6-second global notification. The non-secret `unlockFailureMessage`
is now retained on the unlock form, with test tag `keyra-unlock-failure`,
readable scalable text, and no clipboard or credential content. It resets
before a new password attempt, on manual lock, and after successful biometric
unlock. An invalid password still increments the original persisted failed
attempt counter; the existing lockout thresholds and KDF are unchanged.

The Android emulator regression asserts both the persisted rejection count
and the durable UI error, the locked ViewModel state, and removal of the
message after successful synthetic unlock. Cross-platform source-contract
checks guard this UI accessibility wiring. On iOS, successful biometric
unlock now also clears any stale rejection text. No vault contents, backup
formats or encryption keys are altered. This work is not proof of a fix for
physical keyboard crash #25, which remains open.

Both platform build identifiers are now `0.6.34`, build `40`.

## v0.6.35 release follow-up — offscreen iOS recovery keyboard regression

The merged v0.6.35 main Android and iOS workflows both succeeded on
`942054ecbfdcfb452ef3e2b8e731d8bb90896e77`, but independent release
run 38978160202 stopped in the iOS XCTest suite before publishing.
Its actual XCTest transcript showed the onboarding Recovery Key button was
tapped, followed by a 15-second timeout finding
`keyra-recovery-new-master` and no matching SecureTextField in the
accessibility snapshot query. The recovery editor is below two document
pickers in a scrollable SwiftUI form. The old test neither asserted that
the recovery view itself appeared nor scrolled to an offscreen element.
There is no evidence in these logs of user-key loss or a native crash.

The corrected XCTest explicitly waits for the recovery view's back
control, then scrolls the real recovery form until the secure password
editor is hittable, exercises synthetic Unicode text, scrolls back
to its navigation control, and continues the existing first-run,
lock/relaunch, wrong-password and missing-Keychain regressions. If the
view or field is genuinely unavailable, the test still **fails** with
a precise message; no assertion or release gate is disabled.
The static cross-platform input contract now requires this traversal.

Existing master password code, cryptography, encrypted data, UI geometry,
fonts, assets, version name (0.6.35) and build (41) are unchanged. This
test-specific repair requires Android and iOS CI plus actual release
workflow verification before declaring v0.6.35 published.
