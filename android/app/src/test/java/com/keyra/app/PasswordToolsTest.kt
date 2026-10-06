package com.keyra.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordToolsTest {
    @Test
    fun generatedPasswordUsesRequestedLengthAndCharacterSets() {
        val password = generatePassword(
            length = 64,
            upper = true,
            lower = true,
            numbers = true,
            symbols = true
        )

        assertEquals(64, password.length)
        assertTrue(password.any(Char::isUpperCase))
        assertTrue(password.any(Char::isLowerCase))
        assertTrue(password.any(Char::isDigit))
        assertTrue(password.any { !it.isLetterOrDigit() })
    }

    @Test
    fun generatedPasswordFallsBackToLowercaseWhenNoSetIsSelected() {
        val password = generatePassword(
            length = 24,
            upper = false,
            lower = false,
            numbers = false,
            symbols = false
        )

        assertEquals(24, password.length)
        assertTrue(password.all(Char::isLowerCase))
    }

    @Test
    fun generatedPasswordRespectsSingleCharacterSetSelections() {
        val onlyUpper = generatePassword(32, upper = true, lower = false, numbers = false, symbols = false)
        val onlyLower = generatePassword(32, upper = false, lower = true, numbers = false, symbols = false)
        val onlyNumbers = generatePassword(32, upper = false, lower = false, numbers = true, symbols = false)
        val onlySymbols = generatePassword(32, upper = false, lower = false, numbers = false, symbols = true)

        assertTrue(onlyUpper.all(Char::isUpperCase))
        assertTrue(onlyLower.all(Char::isLowerCase))
        assertTrue(onlyNumbers.all(Char::isDigit))
        assertTrue(onlySymbols.all { !it.isLetterOrDigit() })
    }

    @Test
    fun generatedPasswordAlwaysIncludesEveryEnabledCharacterClass() {
        repeat(100) {
            val password = generatePassword(
                length = 20,
                upper = true,
                lower = true,
                numbers = true,
                symbols = true
            )

            assertTrue(password.any(Char::isUpperCase))
            assertTrue(password.any(Char::isLowerCase))
            assertTrue(password.any(Char::isDigit))
            assertTrue(password.any { !it.isLetterOrDigit() })
        }
    }

    @Test
    fun cardExpiryFormattingKeepsOnlyDigitsAndAddsSeparator() {
        assertEquals("12", formatCardExpiry("12"))
        assertEquals("12/27", formatCardExpiry("1227"))
        assertEquals("12/27", formatCardExpiry("12/27"))
        assertEquals("12/2027", formatCardExpiry("12 2027"))
        assertEquals("12/2027", formatCardExpiry("12202799"))
    }

    @Test
    fun securityIssuesDeduplicateWeakAndReusedPasswords() {
        val reused = "Abcd1234!Efgh56"
        val weak = "password123"
        val items = listOf(
            VaultItem(id = "a", title = "A", password = reused),
            VaultItem(id = "b", title = "B", password = reused),
            VaultItem(id = "c", title = "C", password = weak),
            VaultItem(id = "d", title = "D", password = "", type = "Bilješka")
        )

        assertEquals(setOf("a", "b", "c"), securityIssueIds(items))
        assertEquals(3, securityIssueCount(items))
    }

    @Test
    fun securityIssuesIgnoreStrongUniquePasswordsAndNonPasswordItems() {
        val items = listOf(
            VaultItem(id = "a", title = "A", password = "Abcd1234!Efgh56"),
            VaultItem(id = "b", title = "B", notes = "tajna", type = "Bilješka"),
            VaultItem(id = "c", title = "C", fields = mapOf("Broj kartice" to "4111111111111111"), type = "Kartica")
        )

        assertTrue(securityIssueIds(items).isEmpty())
        assertEquals(0, securityIssueCount(items))
    }

    @Test
    fun portableTimestampKeepsUnixMilliseconds() {
        val timestamp = 1_796_675_123_000.0
        assertEquals(timestamp.toLong(), normalizePortableUpdatedAt(timestamp, fallback = 1L))
    }

    @Test
    fun portableTimestampMigratesLegacyIOSReferenceSeconds() {
        val iosReferenceSeconds = 783_000_000.0
        val expectedUnixMilliseconds = ((iosReferenceSeconds + 978_307_200.0) * 1000.0).toLong()
        assertEquals(
            expectedUnixMilliseconds,
            normalizePortableUpdatedAt(iosReferenceSeconds, fallback = 1L)
        )
    }

    @Test
    fun portableTimestampUsesFallbackForInvalidValues() {
        assertEquals(1234L, normalizePortableUpdatedAt(Double.NaN, fallback = 1234L))
        assertEquals(1234L, normalizePortableUpdatedAt(0.0, fallback = 1234L))
    }

    @Test
    fun totpMatchesRfc6238Sha1Vector() {
        val config = TotpConfig(
            secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            algorithm = "SHA1",
            digits = 8,
            period = 30
        )

        assertEquals("94287082", generateTotp(config, timeMillis = 59_000L))
        assertEquals(1, totpRemainingSeconds(config, timeMillis = 59_000L))
    }

    @Test
    fun totpSupportsGoogleAuthenticatorStyleSixDigitCodes() {
        val config = TotpConfig(
            secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            algorithm = "SHA1",
            digits = 6,
            period = 30
        )

        assertEquals("287082", generateTotp(config, timeMillis = 59_000L))
        assertEquals("287 082", formatTotpCode("287082"))
    }

    @Test
    fun otpauthUriParsesIssuerAccountAndSettings() {
        val config = parseTotpInput(
            "otpauth://totp/Keyra%20Test:alice%40example.com" +
                "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" +
                "&issuer=Keyra%20Test&algorithm=SHA256&digits=8&period=45"
        )

        requireNotNull(config)
        assertEquals("Keyra Test", config.issuer)
        assertEquals("alice@example.com", config.account)
        assertEquals("SHA256", config.algorithm)
        assertEquals(8, config.digits)
        assertEquals(45, config.period)
    }

    @Test
    fun cardNumberValidationUsesLuhnChecksum() {
        assertTrue(isValidCardNumber("4111 1111 1111 1111"))
        assertTrue(isValidCardNumber("5555555555554444"))
        assertFalse(isValidCardNumber("4111111111111112"))
        assertFalse(isValidCardNumber("0000000000000000"))
        assertFalse(isValidCardNumber("1234"))
    }

    @Test
    fun cardExpiryRejectsPastDates() {
        assertTrue(isCardExpiryNotPast("12/30", currentYear = 2026, currentMonth = 10))
        assertTrue(isCardExpiryNotPast("10/26", currentYear = 2026, currentMonth = 10))
        assertFalse(isCardExpiryNotPast("09/26", currentYear = 2026, currentMonth = 10))
        assertFalse(isCardExpiryNotPast("13/26", currentYear = 2026, currentMonth = 10))
    }

    @Test
    fun strongPasswordRequiresLengthAndCharacterDiversity() {
        assertTrue(isStrongPassword("Abcd1234!Efgh56"))
        assertFalse(isStrongPassword("abcdefghijklmnop"))
        assertFalse(isStrongPassword("Ab1!short"))
    }

    @Test
    fun generatedStrongPresetMeetsStrengthRule() {
        val password = generatePassword(
            length = 16,
            upper = true,
            lower = true,
            numbers = true,
            symbols = true
        )
        assertTrue(isStrongPassword(password))
    }

    @Test
    fun recoveryPassphraseRejectsWeakSecretsAndAcceptsStrongPassphrases() {
        assertFalse(isStrongRecoveryPassphrase("kratko"))
        assertFalse(isStrongRecoveryPassphrase("abcdefghijklmnop"))
        assertTrue(isStrongRecoveryPassphrase("Correct Horse Battery Staple"))
        assertTrue(isStrongRecoveryPassphrase("Keyra-Recovery-2026!"))
    }

    @Test
    fun recoveryKeyEnvelopeRoundTripsPortableVaultKey() {
        val rawKey = ByteArray(32) { index -> (index + 1).toByte() }
        val passphrase = "Correct Horse Battery Staple"

        val payload = RecoveryKeyEnvelope.encrypt(rawKey, passphrase)
        val restored = RecoveryKeyEnvelope.decrypt(payload, passphrase)

        assertTrue(payload.startsWith("KEYRAREC1.600000."))
        assertArrayEquals(rawKey, restored)
    }

    @Test
    fun recoveryKeyEnvelopeRejectsWrongPassphrase() {
        val rawKey = ByteArray(32) { index -> (index + 11).toByte() }
        val payload = RecoveryKeyEnvelope.encrypt(rawKey, "Keyra-Recovery-2026!")

        assertTrue(
            runCatching {
                RecoveryKeyEnvelope.decrypt(payload, "Wrong-Recovery-2026!")
            }.isFailure
        )
    }

    @Test
    fun recoveryKeyEnvelopeRejectsTampering() {
        val rawKey = ByteArray(32) { index -> (index + 21).toByte() }
        val passphrase = "Four private recovery words"
        val payload = RecoveryKeyEnvelope.encrypt(rawKey, passphrase)
        val parts = payload.split(".").toMutableList()
        val encrypted = java.util.Base64.getDecoder().decode(parts[3])
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 0x01).toByte()
        parts[3] = java.util.Base64.getEncoder().encodeToString(encrypted)
        val tampered = parts.joinToString(".")

        assertTrue(runCatching { RecoveryKeyEnvelope.decrypt(tampered, passphrase) }.isFailure)
    }


}
