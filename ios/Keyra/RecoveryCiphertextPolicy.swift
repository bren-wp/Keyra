// Recovery key replacement must not silently turn missing vault ciphertext
// into a new empty vault. A legitimate empty vault still has encrypted data.
// Only explicitly requested initial recovery may begin before ciphertext is saved.
enum RecoveryCiphertextPolicy {
    static func allowsInstall(hasCiphertext: Bool, initialRecovery: Bool) -> Bool {
        hasCiphertext || initialRecovery
    }

    static func allowsFreshVaultCreation(hasCiphertext: Bool) -> Bool {
        !hasCiphertext
    }
}

    
// Keep this pure policy in the compiled iOS target AND in standalone Swift
// regression tests. No save is permitted to replace ciphertext with a
// snapshot which cannot be safely reloaded.
enum VaultWritePolicy {
    static let maxItems = 10_000

    static func allowsWrite<ID: Hashable>(itemIDs: [ID]) -> Bool {
        itemIDs.count <= maxItems && Set(itemIDs).count == itemIDs.count
    }
}
