#!/usr/bin/env python3
"""Guard both initial backup import call sites against orphaned ciphertext."""
from pathlib import Path


def verify(label: str, path: str, start: str, end: str,
           guard: str, ciphertext: str, decrypt: str, write: str) -> None:
    source = Path(path).read_text(encoding="utf-8")
    assert source.count(start) == 1, f"{label}: expected one import method"
    remaining = source.split(start, 1)[1]
    assert end in remaining, f"{label}: import method ending missing"
    method = remaining.split(end, 1)[0]
    for token in (guard, ciphertext, decrypt, write):
        assert method.count(token) == 1, f"{label}: expected exactly one {token}"
    assert max(method.index(guard), method.index(ciphertext)) < method.index(decrypt) < method.index(write), (
        f"{label}: guard and persisted-ciphertext check must precede decryption and write"
    )


verify("Android", "android/app/src/main/java/com/keyra/app/MainActivity.kt",
       "    fun importNewVault(payload: String, password: String) {", "    fun recoverInitialVault(",
       "canCreateFreshVault(", "store.hasPersistedCiphertext()", "PortableBackup.decrypt(", "store.save(imported)")
verify("iOS", "ios/Keyra/KeyraApp.swift",
       "    func importNewVault(payload: String, password: String) {", "    func recoverInitialVault(",
       "RecoveryCiphertextPolicy.allowsFreshVaultCreation(",
       "self.vault.hasPersistedCiphertext()", "PortableBackup.decrypt(", "self.vault.save(decoded)")
print("Initial-import ciphertext preflight verified for Android and iOS.")
