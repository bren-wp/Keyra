package com.keyra.app

import android.content.Context
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.lifecycle.ViewModelProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
        try {
            compose.waitUntil(timeout) {
                compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
            }
        } catch (timeoutFailure: Throwable) {
            // Print only stage and non-secret state. Never dump Compose semantics,
            // screenshots, typed passwords, clipboard contents or vault items.
            val safeState = compose.runOnIdle {
                val model = ViewModelProvider(compose.activity)[KeyraViewModel::class.java]
                "screen=" + model.screen + "; setup=" + model.isSetup +
                    "; creating=" + model.isCreatingVault +
                    "; importing=" + model.isImportingVault +
                    "; unlocking=" + model.isUnlockingVault
            }
            throw AssertionError("First-run UI step timed out: " + tag + "; " + safeState, timeoutFailure)
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
        val bounded = master.fetchSemanticsNode().config[SemanticsProperties.EditableText].text
        assertEquals(256, bounded.length)
        master.performTextClearance()
        compose.onNodeWithContentDescription("Prikaži Glavna lozinka").performClick()
        master.performClick()

        val synthetic = "ČćDemo##2026" // Exactly 12 UTF-16 code units
        master.performTextInput(synthetic)
        confirm.performClick()
        confirm.performTextInput(synthetic)
        compose.onNodeWithContentDescription("Sakrij Glavna lozinka").performClick()
        submit.performClick()

        waitFor("keyra-nav-Postavke", 60_000)
        compose.onNodeWithTag("keyra-nav-Postavke").performClick()
        // LazyColumn only composes visible rows. Scroll the actual Settings list
        // to its footer rather than asserting that an off-screen row exists.
        waitFor("keyra-settings-list")
        compose.onNodeWithTag("keyra-settings-list")
            .performScrollToNode(hasTestTag("keyra-lock-vault"))
        waitFor("keyra-lock-vault")
        compose.onNodeWithTag("keyra-lock-vault").performClick()
        waitFor("keyra-master-password")
        // Activity recreation covers lifecycle restoration without resetting encrypted data.
        compose.activityRule.scenario.recreate()
        waitFor("keyra-master-password")

        // Verify persisted vault can reject an incorrect password and reopen
        // with the synthetic password after explicit locking.
        val unlock = compose.onNodeWithTag("keyra-master-password")
        unlock.performTextInput("PogresnaLozinka2026")
        compose.onNodeWithTag("keyra-submit-master-password").performClick()
        compose.waitUntil(20_000) {
            compose.onAllNodesWithText("Glavna lozinka nije ispravna.").fetchSemanticsNodes().isNotEmpty()
        }
        unlock.performTextClearance()
        unlock.performTextInput(synthetic)
        compose.onNodeWithTag("keyra-submit-master-password").performClick()
        waitFor("keyra-nav-Postavke", 60_000)
        compose.onNodeWithTag("keyra-nav-Postavke").assertExists()

        // Simulate the verifier surviving while the persisted encrypted blob
        // is missing. This test only uses the fresh emulator's synthetic vault.
        // Previously this scenario silently opened an empty vault.
        compose.runOnIdle {
            val prefs = compose.activity.getSharedPreferences("keyra", Context.MODE_PRIVATE)
            assertTrue("Synthetic encrypted vault must exist before fault injection", prefs.contains("vault_blob"))
            assertTrue("Fault injection must delete only the encrypted blob", prefs.edit().remove("vault_blob").commit())
        }

        compose.onNodeWithTag("keyra-nav-Postavke").performClick()
        waitFor("keyra-settings-list")
        compose.onNodeWithTag("keyra-settings-list")
            .performScrollToNode(hasTestTag("keyra-lock-vault"))
        compose.onNodeWithTag("keyra-lock-vault").performClick()
        waitFor("keyra-master-password")
        compose.onNodeWithTag("keyra-master-password").performTextInput(synthetic)
        compose.onNodeWithTag("keyra-submit-master-password").performClick()

        compose.waitUntil(25_000) {
            compose.onAllNodesWithText("Trezor nije moguće otvoriti. Podaci nisu promijenjeni.")
                .fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("keyra-master-password").assertExists()
        compose.runOnIdle {
            val model = ViewModelProvider(compose.activity)[KeyraViewModel::class.java]
            assertFalse("Missing encrypted data must not unlock a fabricated vault", model.unlocked)
            assertEquals(Screen.UNLOCK, model.screen)
        }
    }
}
