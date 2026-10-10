# Vault integrity and missing encrypted data — Keyra 0.6.23

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

## Automated verification

- Android instrumented `MasterPasswordEntryInstrumentedTest` first confirms that a synthetic encrypted vault is created and can be unlocked after an activity recreation.
- The same test deletes only that synthetic test vault's `vault_blob` preference, locks, and authenticates with the correct synthetic master password. It checks that the screen stays locked and reports the storage failure rather than showing an empty vault.
- Existing Android unit tests exercise encrypted backups, vault erasure ordering, and KEYRA compatibility.
- iOS simulator UI test verifies normal synthetic first-run empty-vault creation and subsequent unlock. **No automated iOS missing-file fault injection is presently included.**

## Device tests still required

Use disposable, synthetic-only installations and never delete data from a real user vault:

1. On Android, create and successfully reopen a **legitimately empty** vault, then test the separate missing-`vault_blob` case.
2. On iOS, create and reopen an empty vault. Separately remove the test installation's `vault.bin` and legacy storage while leaving its password verifier intact, then confirm correct-password unlock remains locked.
3. Test file corruption, locked-device storage errors, insufficient capacity, backup restore, and relaunch on physical Android and iOS devices.
4. Confirm KEYRA1, KEYRA2, KEYRAREC1 restoration using safe fixture data. Do not upload real vaults or personal secrets to CI.

The first-run typing crash in issue #25 remains open until physical-device reproduction or sanitized crash evidence is available.

## Release policy

Version **0.6.23 / build 29** is only releasable after Android and iOS PR checks pass at the same final SHA, both main checks complete successfully, and the GitHub Release workflow confirms its tag plus all seven nonempty assets and SHA-256 checksum manifests. Public CI packages must not be described as production-signed app-store uploads.
