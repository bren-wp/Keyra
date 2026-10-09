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
    fun missingLoginAndWifiPasswordsAreSecurityIssues() {
        val items = listOf(
            VaultItem(id = "login", title = "Prijava bez lozinke", password = ""),
            VaultItem(id = "wifi", title = "Wi-Fi bez lozinke", type = "Wi-Fi", password = "  "),
            VaultItem(id = "strong", title = "Snažna prijava", password = "Abcd1234!Efgh56"),
            VaultItem(id = "note", title = "Bilješka", type = "Bilješka"),
            VaultItem(id = "card", title = "Kartica", type = "Kartica")
        )

        assertEquals(setOf("login", "wifi"), securityIssueIds(items))
        assertEquals(2, securityIssueCount(items))
        assertEquals(33, securityScore(items) ?: -1)
    }

    @Test
    fun securityScoreIgnoresNonPasswordRecordsAndCountsReusedPasswords() {
        val strong = "Abcd1234!Efgh56"
        val items = listOf(
            VaultItem(id = "a", title = "A", password = strong),
            VaultItem(id = "b", title = "B", password = strong),
            VaultItem(id = "c", title = "C", password = "Xyz12345!Klmn67890")
        )

        assertEquals(setOf("a", "b"), securityIssueIds(items))
        assertEquals(33, securityScore(items) ?: -1)
        assertEquals(null, securityScore(listOf(VaultItem(title = "Bilješka", type = "Bilješka"))))
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
    fun totpMatchesRfc6238Sha256AndSha512Vectors() {
        val sha256 = TotpConfig(
            secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
            algorithm = "SHA256",
            digits = 8,
            period = 30
        )
        val sha512 = TotpConfig(
            secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
            algorithm = "SHA512",
            digits = 8,
            period = 30
        )

        val vectors = listOf(
            Triple(59L, "46119246", "90693936"),
            Triple(1_111_111_109L, "68084774", "25091201"),
            Triple(1_111_111_111L, "67062674", "99943326"),
            Triple(1_234_567_890L, "91819424", "93441116"),
            Triple(2_000_000_000L, "90698825", "38618901"),
            Triple(20_000_000_000L, "77737706", "47863826")
        )

        vectors.forEach { (seconds, expectedSha256, expectedSha512) ->
            assertEquals(expectedSha256, generateTotp(sha256, timeMillis = seconds * 1000L))
            assertEquals(expectedSha512, generateTotp(sha512, timeMillis = seconds * 1000L))
        }
    }

    @Test
    fun base32DecoderMatchesRfc4648KnownValue() {
        assertArrayEquals(
            "foobar".toByteArray(Charsets.US_ASCII),
            decodeBase32("MZXW6YTBOI======")
        )
        assertTrue(decodeBase32("MZXW6YTB0I") == null)
    }

    @Test
    fun base32AcceptsPaddedAndUnpaddedRfc4648Secrets() {
        assertArrayEquals("f".toByteArray(Charsets.US_ASCII), decodeBase32("MY======"))
        assertArrayEquals("f".toByteArray(Charsets.US_ASCII), decodeBase32("MY"))
        assertEquals("MZXW6YTBOI", normalizeBase32Secret("mzxw6ytboi======"))
        assertEquals("MY", normalizeBase32Secret("my======"))
    }

    @Test
    fun base32RejectsTruncationBadPaddingAndNonzeroTrailingBits() {
        listOf("M", "MZ", "MZ======", "MY=====", "MY=======", "=MY======", "MY===A==", "MZXW6YTBO")
            .forEach { malformed ->
                assertTrue("Must reject malformed Base32: $malformed", decodeBase32(malformed) == null)
                assertTrue("Must not import malformed TOTP: $malformed", parseTotpInput(malformed) == null)
            }
        assertTrue(normalizeBase32Secret("MZ") == null)
    }

    @Test
    fun reusedStrongCredentialsCountAsVaultSecurityRisks() {
        val strong = "Abcd1234!Efgh56"
        val entries = listOf(
            VaultItem(id = "one", title = "One", password = strong),
            VaultItem(id = "two", title = "Two", password = strong)
        )

        assertTrue(entries.all { isStrongPassword(it.password) })
        assertEquals(2, securityIssueCount(entries))
        assertEquals(0, securityScore(entries) ?: -1)
    }

    @Test
    fun totpCountdownResetsExactlyOnPeriodBoundary() {
        val config = TotpConfig(
            secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            period = 30
        )

        assertEquals(30, totpRemainingSeconds(config, timeMillis = 0L))
        assertEquals(1, totpRemainingSeconds(config, timeMillis = 29_999L))
        assertEquals(30, totpRemainingSeconds(config, timeMillis = 30_000L))
        assertEquals(15, totpRemainingSeconds(config, timeMillis = 45_000L))
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
    fun firstRunRecoveryKeepsRecoveryAndBackupPasswordsIndependent() {
        val rawKey = ByteArray(32) { index -> (index + 7).toByte() }
        val recoveryPassphrase = "Correct Horse Battery Staple"
        val backupPassword = "Backup-Password-2026!"
        val vaultJson = """[{"id":"item-1","title":"Primjer"}]"""

        val recoveryPayload = RecoveryKeyEnvelope.encrypt(rawKey, recoveryPassphrase)
        val backupPayload = PortableBackup.encrypt(vaultJson, backupPassword)

        assertArrayEquals(rawKey, RecoveryKeyEnvelope.decrypt(recoveryPayload, recoveryPassphrase))
        assertEquals(vaultJson, PortableBackup.decrypt(backupPayload, backupPassword))
        assertTrue(runCatching { RecoveryKeyEnvelope.decrypt(recoveryPayload, backupPassword) }.isFailure)
        assertTrue(runCatching { PortableBackup.decrypt(backupPayload, recoveryPassphrase) }.isFailure)
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



    @Test
    fun recoveryKeyEnvelopeRejectsUnsupportedVersion() {
        val payload = RecoveryKeyEnvelope.encrypt(
            ByteArray(32) { index -> (index + 31).toByte() },
            "Keyra-Recovery-2026!"
        )
        val unsupported = payload.replaceFirst("KEYRAREC1.", "KEYRAREC9.")

        assertTrue(
            runCatching {
                RecoveryKeyEnvelope.decrypt(unsupported, "Keyra-Recovery-2026!")
            }.isFailure
        )
    }

    @Test
    fun recoveryKeyEnvelopeRejectsOversizedInputBeforeDecrypting() {
        val oversized = "KEYRAREC1.600000." + "A".repeat(20_000)

        assertTrue(
            runCatching {
                RecoveryKeyEnvelope.decrypt(oversized, "Keyra-Recovery-2026!")
            }.isFailure
        )
    }

}
