# Recovery cleanup failure-injection QA — Keyra 0.6.22

This document covers the initial Recovery Key + encrypted-backup restoration path, **not** routine unlocking or manual encrypted-backup import.

## Risk and fix

Previously, the iOS initial-recovery path ignored the result of deleting the old encrypted vault before clearing the Keychain encryption key. Its error path also removed keys even if vault deletion failed. This could make an existing encrypted file unreadable after an I/O failure.

The Android initial-recovery path previously removed the master-password verifier before attempting vault destruction; error cleanup was unconditional. Both platforms now require successful removal of the previous encrypted vault before discarding its credential material. Cleanup of a partial new installation only proceeds when that installation started, and key deletion is gated on successful encrypted-file/blob removal.

These changes do **not** add a guarantee of forensic secure erasure on flash storage, nor do they make restoration atomic in the event of device power loss.

## Automated coverage

- Android JUnit: `failedRecoveryPreflightPreservesVerifierAndDoesNotRunCleanup` injects a vault-deletion failure and asserts that verifier deletion is not invoked. It also tests verifier deletion failure and the successful operation order.
- Existing Android JUnit: `vaultErasureNeverRemovesKeyUntilEncryptedDataIsDeleted` verifies that encrypted-blob removal precedes wrapping-key deletion.
- Android PR CI: lint, unit tests, build and privacy gates. iOS PR CI: build, analyze, simulator launch and existing UI tests.
- No iOS filesystem/Keychain fault-injection test is present. A passing simulator launch test does **not** simulate a failed `FileManager.removeItem` or `SecItemDelete`.

## Physical-device QA still required

On a disposable device/test installation with **synthetic-only** credentials, validate separately on Android and iOS:

1. A normal KEYRAREC1 + KEYRA1/KEYRA2 backup restoration creates an unlockable vault with the expected synthetic items.
2. Inject denial/failure of the encrypted vault deletion operation; verify the original encryption key and old verifier are retained and that no false success is shown.
3. Inject failure deleting the old verifier or Keychain/Keystore entry; verify a failure is reported and that retry does not destroy an existing encrypted file with a missing key.
4. Inject failure saving the restored vault or creating its new password verifier; verify cleanup of the partially installed vault is ordered and retains its key if the encrypted data cannot be removed.
5. Repeat after app backgrounding, process termination, locked device, storage exhaustion and filesystem errors. Do not use a real vault to test destructive paths.
6. Confirm physical-device migration/restore compatibility with preserved KEYRA1, KEYRA2 and KEYRAREC1 fixture files. Never upload live vaults, passwords or keys to CI.

Issue #25 (first-run master-password typing crash) is separate and stays open pending reproductions or sanitized device crash evidence.

## Release and signing

Both platforms use version 0.6.22, build 28. Publish only after both PR checks pass on the exact final commit, both main-branch checks pass, and the release and all seven non-empty assets plus SHA256SUMS are independently confirmed. Release APK/AAB/IPA artifacts are not proof of store-production signing.
