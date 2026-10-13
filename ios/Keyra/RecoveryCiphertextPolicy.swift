// Recovery key replacement must not silently turn missing vault ciphertext
// into a new empty vault. A legitimate empty vault still has encrypted data.
// Only explicitly requested initial recovery may begin before ciphertext is saved.
enum RecoveryCiphertextPolicy {
    static func allowsInstall(hasCiphertext: Bool, initialRecovery: Bool) -> Bool {
        hasCiphertext || initialRecovery
    }
}
