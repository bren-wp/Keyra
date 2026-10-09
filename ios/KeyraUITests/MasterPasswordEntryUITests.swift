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
        master.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 256))
        let synthetic = "SafeDemo2026" // Exactly 12 characters
        master.typeText(synthetic)
        let confirmation = app.secureTextFields["keyra-confirm-master-password"]
        XCTAssertTrue(confirmation.exists)
        confirmation.tap()
        confirmation.typeText(synthetic)
        app.buttons["keyra-submit-master-password"].tap()

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
