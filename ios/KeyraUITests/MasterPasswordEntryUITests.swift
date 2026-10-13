import XCTest

/// On-device/simulator interaction with the real SwiftUI fields.
/// Credentials are fixed synthetic test strings, never user data.
final class MasterPasswordEntryUITests: XCTestCase {
    func testFirstRunTypingVisibilityUnicodeCreateLockAndUnlock() throws {
        let app = XCUIApplication()
        app.launch()
        let create = app.buttons["keyra-first-run-create"]
        XCTAssertTrue(create.waitForExistence(timeout: 15), "Fresh simulator must show onboarding")
        create.tap()

        var master = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(master.waitForExistence(timeout: 15), "First-run secure field must render")
        master.tap()
        master.typeText("1")
        master.typeText("2")
        master.typeText("Čć")
        master.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 4))

        let show = app.buttons["keyra-toggle-Glavna lozinka"]
        XCTAssertTrue(show.exists)
        show.tap()
        let revealed = app.textFields["keyra-master-password"]
        XCTAssertTrue(revealed.waitForExistence(timeout: 10), "Visibility toggle must preserve the input")
        revealed.tap()
        revealed.typeText("Žž")
        revealed.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 2))
        show.tap()

        master = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(master.waitForExistence(timeout: 10))
        master.tap()
        master.typeText(String(repeating: "A", count: 260))
        // SecureTextField accessibility values may report a single masking
        // glyph instead of the real number of characters. Reveal only our
        // synthetic test input and verify the actual bounded field value.
        show.tap()
        let boundedVisible = app.textFields["keyra-master-password"]
        XCTAssertTrue(boundedVisible.waitForExistence(timeout: 10))
        XCTAssertEqual((boundedVisible.value as? String)?.count, 256,
                       "First-run field must cap long typed passwords at 256 characters")
        show.tap()
        // A long sequence of 256 synthetic backspaces may race with iOS IME
        // updates and leave the field nonempty. Test the 256-character boundary,
        // then create a fresh first-run view before exercising vault creation.
        // This keeps the keyboard stress test and the persistence test independent.
        app.terminate()
        app.launch()
        let createAgain = app.buttons["keyra-first-run-create"]
        XCTAssertTrue(createAgain.waitForExistence(timeout: 20),
                      "Stress-test typing must not create or alter a vault")
        createAgain.tap()

        master = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(master.waitForExistence(timeout: 15))
        let synthetic = "SafeDemo2026" // Exactly 12 characters
        let underlength = "Short123#26" // Exactly 11 characters
        let confirmation = app.secureTextFields["keyra-confirm-master-password"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 10))

        // Verify the exact 11-character value in both synthetic fields before
        // submitting. A transient toast disappears after 2.6 seconds and is
        // not a reliable XCTest synchronization point.
        master.tap()
        master.typeText(underlength)
        confirmation.tap()
        confirmation.typeText(underlength)
        let invalidToggle = app.buttons["keyra-toggle-Glavna lozinka"]
        invalidToggle.tap()
        let invalidMaster = app.textFields["keyra-master-password"]
        let invalidConfirmation = app.textFields["keyra-confirm-master-password"]
        XCTAssertTrue(invalidMaster.waitForExistence(timeout: 10))
        XCTAssertTrue(invalidConfirmation.waitForExistence(timeout: 10))
        XCTAssertEqual(invalidMaster.value as? String, underlength,
                       "The test must submit precisely 11 synthetic characters")
        XCTAssertEqual(invalidConfirmation.value as? String, underlength,
                       "The synthetic confirmation must match exactly")
        invalidToggle.tap()
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(master.waitForExistence(timeout: 10),
                      "Invalid first-run input must keep the editor accessible")
        XCTAssertTrue(app.buttons["keyra-submit-master-password"].exists,
                      "Rejected master password must not advance to the vault")
        XCTAssertFalse(app.buttons["keyra-nav-Postavke"].waitForExistence(timeout: 5),
                       "Eleven-character master password must not create a vault")

        // Restart only the local first-run editor: no vault was created, so
        // this avoids racing with keyboard backspace animations or IME state.
        app.terminate()
        app.launch()
        let freshCreate = app.buttons["keyra-first-run-create"]
        XCTAssertTrue(freshCreate.waitForExistence(timeout: 15),
                      "An invalid submission must leave the vault uninitialized")
        freshCreate.tap()
        master = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(master.waitForExistence(timeout: 15))
        master.tap()
        master.typeText(synthetic)
        let freshConfirmation = app.secureTextFields["keyra-confirm-master-password"]
        XCTAssertTrue(freshConfirmation.waitForExistence(timeout: 10))
        freshConfirmation.tap()
        freshConfirmation.typeText(synthetic)
        // Exact values are checked below after toggling the two synthetic
        // fields to visible mode; masked accessibility values are not reliable.

        // Equal lengths do not establish that the iOS keyboard entered equal
        // text. Reveal synthetic credentials only inside the test process to
        // compare exact values without printing them to CI logs.
        let toggle = app.buttons["keyra-toggle-Glavna lozinka"]
        toggle.tap()
        let visibleMaster = app.textFields["keyra-master-password"]
        let visibleConfirm = app.textFields["keyra-confirm-master-password"]
        XCTAssertTrue(visibleMaster.waitForExistence(timeout: 10))
        XCTAssertTrue(visibleConfirm.waitForExistence(timeout: 10))
        XCTAssertTrue((visibleMaster.value as? String) == synthetic,
                      "Master-password input differs from synthetic keyboard sequence")
        XCTAssertTrue((visibleConfirm.value as? String) == synthetic,
                      "Confirmation input differs from synthetic keyboard sequence")
        toggle.tap()

        app.buttons["keyra-submit-master-password"].tap()
        let failureMessages = [
            "Zaštitu glavne lozinke nije moguće spremiti u Keychain.",
            "Šifriranu datoteku trezora nije moguće spremiti na uređaj.",
            "Zaštitni ključ trezora nije moguće spremiti u Keychain.",
            "Zaštitni ključ trezora trenutno nije dostupan.",
            "Lozinke se ne podudaraju.",
            "Glavna lozinka mora imati između 12 i 256 znakova."
        ]
        let failure = app.staticTexts.matching(
            NSPredicate(
                format: "label IN %@ OR label BEGINSWITH %@ OR label BEGINSWITH %@",
                failureMessages,
                "Zaštitni ključ trezora nije moguće spremiti u Keychain.",
                "Šifriranu datoteku trezora nije moguće spremiti na uređaj."
            )
        ).firstMatch
        if failure.waitForExistence(timeout: 5) {
            // These messages describe a safe failure category, never a secret.
            XCTFail("Vault creation rejected a synthetic first-run input: " + failure.label)
            return
        }

        let settings = app.buttons["keyra-nav-Postavke"]
        XCTAssertTrue(settings.waitForExistence(timeout: 55), "Vault creation must complete")
        settings.tap()
        let lock = app.buttons["keyra-lock-vault"]
        XCTAssertTrue(lock.waitForExistence(timeout: 10))
        lock.tap()
        app.terminate()
        app.launch() // Persisted vault must survive a complete app relaunch.

        master = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(master.waitForExistence(timeout: 10))
        master.tap()
        master.typeText("WrongDemo#2026")
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(master.waitForExistence(timeout: 15), "Wrong password must not unlock")
        XCTAssertTrue(app.staticTexts["Glavna lozinka nije ispravna."].waitForExistence(timeout: 20),
                      "Wrong-password authentication must finish before another attempt")

        master.tap()
        master.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 14))
        master.typeText(synthetic)
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(settings.waitForExistence(timeout: 55), "Correct password must reopen vault")

        // A simulator-only launch argument makes both ciphertext locations
        // appear absent to load(), without deleting the synthetic vault or
        // touching the Keychain verifier. Correct credentials must not unlock.
        settings.tap()
        XCTAssertTrue(lock.waitForExistence(timeout: 10))
        lock.tap()
        app.terminate()
        app.launchArguments = ["-keyra-ci-simulate-missing-vault"]
        app.launch()

        let missingVaultMaster = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(missingVaultMaster.waitForExistence(timeout: 15))
        missingVaultMaster.tap()
        missingVaultMaster.typeText(synthetic)
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(
            app.staticTexts["Trezor nije moguće otvoriti. Podaci nisu promijenjeni."]
                .waitForExistence(timeout: 55),
            "Missing ciphertext must fail closed instead of displaying an empty vault"
        )
        XCTAssertTrue(missingVaultMaster.exists, "Vault must remain locked after missing ciphertext")
        XCTAssertFalse(settings.exists, "Missing ciphertext must never open the vault")

        // A transient Keychain read error must also fail closed. Never
        // create a replacement key or remove the existing ciphertext.
        app.terminate()
        app.launchArguments = ["-keyra-ci-simulate-keychain-unavailable"]
        app.launch()
        let keychainUnavailableMaster = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(keychainUnavailableMaster.waitForExistence(timeout: 15))
        keychainUnavailableMaster.tap()
        keychainUnavailableMaster.typeText(synthetic)
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(
            app.staticTexts["Trezor nije moguće otvoriti. Podaci nisu promijenjeni."]
                .waitForExistence(timeout: 55),
            "Unavailable Keychain data must not cause key replacement or unlock"
        )
        XCTAssertTrue(keychainUnavailableMaster.exists)
        XCTAssertFalse(settings.exists)

        // Removing both fault flags must reopen the untouched encrypted vault.
        app.terminate()
        app.launchArguments = []
        app.launch()
        let restoredMaster = app.secureTextFields["keyra-master-password"]
        XCTAssertTrue(restoredMaster.waitForExistence(timeout: 15))
        restoredMaster.tap()
        restoredMaster.typeText(synthetic)
        app.buttons["keyra-submit-master-password"].tap()
        XCTAssertTrue(
            settings.waitForExistence(timeout: 55),
            "Simulated missing ciphertext must not delete data or verifier"
        )
    }
}
