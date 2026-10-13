# Vault integrity and missing encrypted data — Keyra 0.6.23–0.6.24

## Confirmed defect

Both platform implementations previously considered the complete absence of persisted ciphertext to be a valid empty vault during an existing user's unlock:

- Android: `VaultStore.load()` returned `emptyList()` for a missing `vault_blob` preference.
- iOS: `EncryptedVault.load()` returned `[]` when neither `vault.bin` nor its legacy stored blob existed.

A legitimate newly created **empty** vault already persists an encrypted empty collection during creation. An existing verifier without corresponding ciphertext is therefore an integrity failure, not evidence that the user's entries are empty.

The old behavior could silently display an empty vault after storage loss, causing confusion and risking overwrites if the user subsequently saved new items.

## Behavior in 0.6.23

- **Android:** unlock returns failure for absent or blank persisted ciphertext. The existing vault-load error is displayed and the session stays locked. Existing AES-GCM and legacy migration handling is unchanged.
- **iOS:** unlock throws an invalid-data error when both current and legacy storage are missing. The existing vault-load error is displayed and the session stays locked.
- **Both:** normal intentional empty vaults are still stored as encrypted records and can be created, locked, relaunched and unlocked. An authentication verifier is never deleted just because its vault file is absent.

Neither format changes nor automatic repair / silent replacement is performed. No automatic data restoration is claimed. Keep encrypted backup and Recovery Key documents in separate safe locations.

## Follow-up protection in 0.6.24

Manual Recovery Key installation on an **existing** vault now refuses to replace
the wrapping key when both current/legacy ciphertext storage are absent (or the
Android persisted blob is blank). This is distinct from the valid encrypted
empty array: an empty vault still has ciphertext and can be verified normally.

The explicit **initial recovery** path is the only exception: once it has
successfully completed its existing ordered cleanup preflight, it can install
the recovered key before writing the recovered encrypted backup. Neither
KEYRA1, KEYRA2 nor KEYRAREC1 serialization was changed.

The Android JUnit regression checks all four combinations of ciphertext
presence and initial-recovery intent. iOS CI compiles the actual Swift
recovery policy and runs four corresponding Swift assertions.

**Additional Android guard:** failure to persist an upgraded master-password
verifier no longer triggers destruction of a pre-existing valid verifier.
Fresh setup may still clean up a failed partial credential installation.
Android JUnit tests distinguish these two cases; actual disk write failure
injection remains device QA.

**Additional iOS guard:** Keychain read errors are distinguished from an
actual `errSecItemNotFound`. A transient or access-related read failure must
not trigger a new encryption key. Loading existing ciphertext requires an
existing Keychain key, and saving an already persisted vault cannot silently
create another key if its original key is unavailable. New empty vault
creation still provisions the initial key normally.

## Orphaned ciphertext safeguards in 0.6.24

When the master-password verifier is missing but encrypted vault data still
exists, ordinary first-run creation now refuses to overwrite the persisted
ciphertext. Android checks the stored vault preference before creating a new
empty vault. iOS checks its encrypted file and legacy stored data before
creating. Rejection occurs before any destructive cleanup or new save.

JUnit and compiled Swift regression assertions cover fresh/occupied storage.
Actual missing-verifier fault injection on disposable devices is still required.

## Automated verification

- Android instrumented `MasterPasswordEntryInstrumentedTest` first confirms that a synthetic encrypted vault is created and can be unlocked after an activity recreation.
- The same test deletes only that synthetic test vault's `vault_blob` preference, locks, and authenticates with the correct synthetic master password. It checks that the screen stays locked and reports the storage failure rather than showing an empty vault.
- Existing Android unit tests exercise encrypted backups, vault erasure ordering, and KEYRA compatibility.
- iOS simulator UI test verifies normal synthetic first-run empty-vault creation and subsequent unlock.
- The same iOS simulator test exercises **non-destructive simulated** missing ciphertext and transient Keychain read failure on a synthetic vault. Both must keep the application locked; clearing the simulator-only launch flags must restore successful unlocking with the original password. These do **not** delete the vault file or inject actual filesystem/Keychain failures.

## Device tests still required

Use disposable, synthetic-only installations and never delete data from a real user vault:

1. On Android, create and successfully reopen a **legitimately empty** vault, then test the separate missing-`vault_blob` case.
2. On iOS, create and reopen an empty vault. Separately remove the test installation's `vault.bin` and legacy storage while leaving its password verifier intact, then confirm correct-password unlock remains locked. Reproduce actual locked/unavailable Keychain access and verify the encryption key is not replaced.
3. Test file corruption, locked-device storage errors, insufficient capacity, backup restore, and relaunch on physical Android and iOS devices.
4. Confirm KEYRA1, KEYRA2, KEYRAREC1 restoration using safe fixture data. Do not upload real vaults or personal secrets to CI.

The first-run typing crash in issue #25 remains open until physical-device reproduction or sanitized crash evidence is available.

## Release policy

Version **0.6.24 / build 30** requires successful Android and iOS PR checks on the same final SHA, successful separate main-branch checks, and confirmation of the release tag, all seven nonempty assets and SHA-256 checksum manifests before claiming publication. Public CI packages must not be described as production-signed app-store uploads.
