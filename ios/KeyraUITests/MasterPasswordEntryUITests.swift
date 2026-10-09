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
        XCTAssertEqual((master.value as? String)?.count, 256,
                       "First-run field must cap long pasted/typed passwords at 256 characters")
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
        master.tap()
        master.typeText(synthetic)
        XCTAssertEqual((master.value as? String)?.count, synthetic.count,
                       "Master-password IME must accept the complete synthetic input")

        let confirmation = app.secureTextFields["keyra-confirm-master-password"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 10))
        confirmation.tap()
        confirmation.typeText(synthetic)
        XCTAssertEqual((confirmation.value as? String)?.count, synthetic.count,
                       "Confirmation input must match the complete master-password length")

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
            "Lozinke se ne podudaraju.",
            "Glavna lozinka mora imati između 12 i 256 znakova."
        ]
        let failure = app.staticTexts.matching(
            NSPredicate(
                format: "label IN %@ OR label BEGINSWITH %@",
                failureMessages,
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
    }
}
