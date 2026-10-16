import Foundation

// A dependency-free executable regression test, compiled and run by iOS CI.
// The policy itself is compiled into the iOS app from the same source file.
@main
struct RecoveryCiphertextPolicyTests {
    static func main() {
        precondition(
            !RecoveryCiphertextPolicy.allowsInstall(
                hasCiphertext: false, initialRecovery: false
            ),
            "Missing ciphertext must not be treated as an empty existing vault."
        )
        precondition(
            RecoveryCiphertextPolicy.allowsInstall(
                hasCiphertext: true, initialRecovery: false
            ),
            "A valid encrypted vault, including an encrypted empty vault, remains supported."
        )
        precondition(
            RecoveryCiphertextPolicy.allowsInstall(
                hasCiphertext: false, initialRecovery: true
            ),
            "Initial recovery must be able to install its key before persisting the restored vault."
        )
        precondition(
            RecoveryCiphertextPolicy.allowsInstall(
                hasCiphertext: true, initialRecovery: true
            ),
            "Recovery with available ciphertext remains supported."
        )
        precondition(
            !RecoveryCiphertextPolicy.allowsFreshVaultCreation(hasCiphertext: true),
            "First-run creation and import must not overwrite orphaned encrypted vault data."
        )
        precondition(
            RecoveryCiphertextPolicy.allowsFreshVaultCreation(hasCiphertext: false),
            "Brand-new vault creation must remain possible with empty storage."
        )
        precondition(VaultWritePolicy.allowsWrite(itemIDs: [Int]()),
                     "Encrypted empty vaults must remain valid.")
        precondition(VaultWritePolicy.allowsWrite(itemIDs: [1, 2]),
                     "Distinct synthetic identifiers must be accepted.")
        precondition(!VaultWritePolicy.allowsWrite(itemIDs: [1, 1]),
                     "Duplicate identifiers must never be persisted.")
        precondition(VaultWritePolicy.allowsWrite(itemIDs: Array(0..<10_000)),
                     "The maximum supported item count must remain writable.")
        precondition(!VaultWritePolicy.allowsWrite(itemIDs: Array(0..<10_001)),
                     "Oversized snapshots must not replace ciphertext.")
        print("Recovery and vault-write policies: 11 assertions passed")
    }
}
