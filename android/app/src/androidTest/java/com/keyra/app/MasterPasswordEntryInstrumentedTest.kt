package com.keyra.app

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a fresh emulator with only synthetic credentials.
 * Exercises real Compose fields and IME semantics, not mock ViewModels.
 * Physical keyboard/IME crash reproduction is tracked separately in #25.
 */
@RunWith(AndroidJUnit4::class)
class MasterPasswordEntryInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun waitFor(tag: String, timeout: Long = 45_000) {
        compose.waitUntil(timeout) {
            compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test
    fun firstRunTextEntryUnicodeVisibilityBoundsCreateLockAndUnlock() {
        waitFor("keyra-first-run-create")
        compose.onNodeWithTag("keyra-first-run-create").performClick()
        waitFor("keyra-master-password")

        val master = compose.onNodeWithTag("keyra-master-password")
        val confirm = compose.onNodeWithTag("keyra-confirm-master-password")
        val submit = compose.onNodeWithTag("keyra-submit-master-password")
        master.performClick()
        master.performTextInput("1")
        master.performTextInput("2")
        master.performTextInput("ČćžŠ😀")
        master.performTextClearance()

        // A single overlong paste must be truncated without crashing the IME.
        master.performTextInput("A".repeat(280))
        compose.runOnIdle {
            val value = master.fetchSemanticsNode().config[SemanticsProperties.EditableText].text
            assertEquals(256, value.length)
        }
        master.performTextClearance()
        compose.onNodeWithContentDescription("Prikaži Glavna lozinka").performClick()
        master.performClick()

        val synthetic = "Čć😀Lozinka#2026"
        master.performTextInput(synthetic)
        confirm.performClick()
        confirm.performTextInput(synthetic)
        compose.onNodeWithContentDescription("Sakrij Glavna lozinka").performClick()
        submit.performClick()

        waitFor("keyra-nav-Postavke", 60_000)
        compose.onNodeWithTag("keyra-nav-Postavke").performClick()
        waitFor("keyra-lock-vault")
        compose.onNodeWithTag("keyra-lock-vault").performClick()
        waitFor("keyra-master-password")

        // Verify persisted vault can reject an incorrect password and reopen
        // with the synthetic password after explicit locking.
        val unlock = compose.onNodeWithTag("keyra-master-password")
        unlock.performTextInput("PogresnaLozinka2026")
        compose.onNodeWithTag("keyra-submit-master-password").performClick()
        waitFor("keyra-master-password")
        unlock.performTextClearance()
        unlock.performTextInput(synthetic)
        compose.onNodeWithTag("keyra-submit-master-password").performClick()
        waitFor("keyra-nav-Postavke", 60_000)
        compose.onNodeWithTag("keyra-nav-Postavke").assertExists()
    }
}
