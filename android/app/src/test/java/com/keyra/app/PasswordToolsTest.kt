package com.keyra.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordToolsTest {
    @Test
    fun backupDecoderRejectsMalformedUtf8AndPreservesValidCharacters() {
        assertEquals("Keyra – šifrirani trezor", decodeUtf8Strict("Keyra – šifrirani trezor".toByteArray(Charsets.UTF_8)))
        assertTrue(runCatching { decodeUtf8Strict(byteArrayOf(0xC3.toByte(), 0x28)) }.isFailure)
        assertTrue(runCatching { decodeUtf8Strict(byteArrayOf(0xED.toByte(), 0xA0.toByte(), 0x80.toByte())) }.isFailure)
    }

    @Test
    fun masterPasswordBoundaryNeverCreatesBrokenUtf16Surrogates() {
        val oversized = "A".repeat(255) + "😀" + "suffix"
        assertEquals("A".repeat(255), boundedNewMasterPasswordInput(oversized))
        assertEquals("A".repeat(254) + "😀", boundedNewMasterPasswordInput("A".repeat(254) + "😀" + "suffix"))
    }
    @Test
    fun portableBackupRetainsDataAndRejectsTheWrongPassword() {
        val plain = """[{"id":"example","title":"Banka","password":"⚡Sigurna#2026"}]"""
        val secret = "VrloJaka-Lozinka#2026"
        val encrypted = PortableBackup.encrypt(plain, secret)
        assertTrue(encrypted.startsWith("KEYRA2."))
        assertFalse(encrypted.contains("⚡Sigurna#2026"))
        assertEquals(plain, PortableBackup.decrypt(encrypted, secret))
        assertTrue(runCatching { PortableBackup.decrypt(encrypted, "PogresnaLozinka#2026") }.isFailure)
    }

    @Test
    fun clipboardCleanupOnlyClearsTheKeyraCopiedText() {
        assertTrue(shouldClearOwnedClipboard("lozinka#2026", "lozinka#2026"))
        assertFalse(shouldClearOwnedClipboard("lozinka#2026", "drugaciji sadržaj"))
        assertFalse(shouldClearOwnedClipboard("lozinka#2026", null))
        assertFalse(shouldClearOwnedClipboard(null, "nečiji drugi tekst"))
        assertFalse(shouldClearOwnedClipboard(null, null))
    }

    @Test
    fun pendingAuthenticationCannotUnlockAfterBackgroundOrExplicitLock() {
        assertTrue(shouldAcceptAuthCompletion(10L, 10L, foreground = true))
        assertFalse(shouldAcceptAuthCompletion(10L, 10L, foreground = false))
        assertFalse(shouldAcceptAuthCompletion(10L, 11L, foreground = true))
        assertFalse(shouldAcceptAuthCompletion(10L, 12L, foreground = false))
        assertTrue(shouldAcceptAuthCompletion(12L, 12L, foreground = true))
    }

    @Test
    fun protectedActionsRequireAnUnchangedActiveUnlockedVaultAndItem() {
        assertTrue(shouldAcceptProtectedCompletion(
            7L, 7L, foreground = true, vaultUnlocked = true,
            sameScreen = true, sameItem = true
        ))
        assertFalse(shouldAcceptProtectedCompletion(
            7L, 7L, foreground = false, vaultUnlocked = true,
            sameScreen = true, sameItem = true
        ))
        assertFalse(shouldAcceptProtectedCompletion(
            7L, 8L, foreground = true, vaultUnlocked = true,
            sameScreen = true, sameItem = true
        ))
        assertFalse(shouldAcceptProtectedCompletion(
            7L, 7L, foreground = true, vaultUnlocked = false,
            sameScreen = true, sameItem = true
        ))
        assertFalse(shouldAcceptProtectedCompletion(
            7L, 7L, foreground = true, vaultUnlocked = true,
            sameScreen = false, sameItem = true
        ))
        assertFalse(shouldAcceptProtectedCompletion(
            7L, 7L, foreground = true, vaultUnlocked = true,
            sameScreen = true, sameItem = false
        ))
    }

    @Test
    fun newMasterPasswordInputIsBoundedWithoutChangingOrdinaryPasswords() {
        assertEquals("", boundedNewMasterPasswordInput(""))
        assertEquals("MojaLozinka#2026", boundedNewMasterPasswordInput("MojaLozinka#2026"))
        val oversized = "A".repeat(300)
        assertEquals(256, boundedNewMasterPasswordInput(oversized).length)
        assertEquals("A".repeat(256), boundedNewMasterPasswordInput(oversized))
        assertEquals("K".repeat(255) + "!", boundedNewMasterPasswordInput("K".repeat(255) + "!ostatak"))
    }

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
    fun savedCategoriesAreReusableAndPreserveImportedValues() {
        val standard = listOf("Osobno", "Posao", "Ostalo")
        val options = categoryChoices(
            standard = standard,
            existing = listOf("Posao", "Klijenti", "Projekt", "Klijenti", ""),
            selected = "Novo"
        )

        assertEquals(listOf("Osobno", "Posao", "Ostalo", "", "Klijenti", "Novo", "Projekt"), options)
        assertEquals("Klijenti", resolvedCategoryName("  Klijenti  ", original = null))
        assertEquals("Posebno", resolvedCategoryName("Posebno", original = "Posao"))
        assertEquals(null, resolvedCategoryName("  ", original = null))
        assertEquals("", resolvedCategoryName("", original = ""))
        assertEquals("", resolvedCategoryName("", original = null, existing = listOf("")))
    }

    @Test
    fun customCategoryNamesAreBoundedWithoutChangingUntouchedImportedNames() {
        val oversized = "K".repeat(60)
        assertEquals(40, resolvedCategoryName(oversized, original = null)?.length)
        assertEquals(oversized, resolvedCategoryName(oversized, original = oversized))
        assertEquals(oversized, resolvedCategoryName(oversized, original = null, existing = listOf(oversized)))
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
    fun cardNumbersRejectNonDigitsRatherThanSilentlyIgnoringThem() {
        val valid = "4111111111111111"
        assertEquals(valid, normalizedCardDigits("4111 1111-1111 1111"))
        assertTrue(isValidCardNumber("4111-1111-1111-1111"))
        assertFalse(isValidCardNumber("4111a11111111111"))
        assertFalse(isValidCardNumber("x" + valid))
        assertFalse(isValidCardNumber(valid + "!"))
        assertFalse(isValidCardNumber("٤١١١١١١١١١١١١١١١"))
        assertFalse(isValidCardNumber("4111\t1111 1111 1111"))
        assertEquals(null, normalizedCardDigits(valid + "/"))
        assertFalse(isValidCardNumber("4111111111111112"))
    }

    @Test
    fun cardNumberInputFormatsCommonGroupingButStorageStaysCanonical() {
        assertEquals("4111 1111 1111 1111", formatCardNumberInput("4111111111111111"))
        assertEquals("4111 1111 1111 1111", formatCardNumberInput("4111-1111-1111-1111"))
        assertEquals("4111 1111 1111 1111 123", formatCardNumberInput("4111111111111111123456789"))
        assertEquals("", formatCardNumberInput(""))
        assertEquals("4111111111111111", normalizedCardDigits(formatCardNumberInput("4111111111111111")))
    }

    @Test
    fun securityCodeRequiresThreeOrFourAsciiDigits() {
        assertTrue(isValidCardSecurityCode("123"))
        assertTrue(isValidCardSecurityCode("1234"))
        assertFalse(isValidCardSecurityCode("12"))
        assertFalse(isValidCardSecurityCode("12345"))
        assertFalse(isValidCardSecurityCode("12a"))
        assertFalse(isValidCardSecurityCode("１２３"))
        assertFalse(isValidCardSecurityCode("12 3"))
    }

    @Test
    fun cardExpiryRejectsPastDates() {
        assertTrue(isCardExpiryNotPast("12/30", currentYear = 2026, currentMonth = 10))
        assertTrue(isCardExpiryNotPast("10/26", currentYear = 2026, currentMonth = 10))
        assertFalse(isCardExpiryNotPast("09/26", currentYear = 2026, currentMonth = 10))
        assertFalse(isCardExpiryNotPast("13/26", currentYear = 2026, currentMonth = 10))
    }

    @Test
    fun expiredCardWarningsCoverPastAndInvalidDatesWithoutFlaggingMissingExpiry() {
        val entries = listOf(
            VaultItem(id = "expired", type = "Kartica", title = "Expired", fields = mapOf("Vrijedi do" to "09/26")),
            VaultItem(id = "invalid", type = "Kartica", title = "Invalid", fields = mapOf("Vrijedi do" to "13/29")),
            VaultItem(id = "current", type = "Kartica", title = "Current", fields = mapOf("Vrijedi do" to "10/26")),
            VaultItem(id = "future", type = "Kartica", title = "Future", fields = mapOf("Vrijedi do" to "12/30")),
            VaultItem(id = "no-expiry", type = "Kartica", title = "Unknown"),
            VaultItem(id = "note", type = "Bilješka", title = "Note", fields = mapOf("Vrijedi do" to "01/20"))
        )
        assertEquals(setOf("expired", "invalid"), expiredCardIssueIds(entries, 2026, 10))
        assertTrue(cardExpiryNeedsAttention("09/26", 2026, 10))
        assertTrue(cardExpiryNeedsAttention("not-a-date", 2026, 10))
        assertFalse(cardExpiryNeedsAttention("10/26", 2026, 10))
        assertFalse(cardExpiryNeedsAttention("12/30", 2026, 10))
        assertFalse(cardExpiryNeedsAttention("", 2026, 10))
        assertFalse(cardExpiryNeedsAttention("   ", 2026, 10))
    }

    @Test
    fun expiredCardsAreCountedAsSecurityIssuesButNotAsPasswordFailures() {
        val password = VaultItem(id = "login", title = "Safe login", password = "Abcd1234!Efgh56")
        val expired = VaultItem(id = "card", type = "Kartica", title = "Expired", fields = mapOf("Vrijedi do" to "01/20"))
        val entries = listOf(password, expired)
        assertEquals(setOf("card"), securityIssueIds(entries))
        assertEquals(1, securityIssueCount(entries))
        assertEquals(100, securityScore(entries))
        assertEquals(null, securityScore(listOf(expired)))
    }

    @Test
    fun predictableLongPasswordsAreNotMarkedStrong() {
        listOf(
            "Password123!VeryLong",
            "Qwerty123!LongSecret",
            "Welcome2026!Safe?",
            "Lozinka2026!Velika",
            "Abcdef!AAAAA123"
        ).forEach { password ->
            assertFalse("Predictable password must be flagged: $password", isStrongPassword(password))
        }
        assertTrue(isStrongPassword("Abcd1234!Efgh56"))
        assertTrue(isStrongPassword("Xyz12345!Klmn67890"))
    }

    @Test
    fun invalidImportedTotpFieldsBecomeSecurityWarningsWithoutAffectingPasswordScore() {
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        val validTotp = VaultItem(
            id = "valid", title = "Valid 2FA", type = "Autentifikator",
            fields = mapOf("TOTP tajna" to secret, "Znamenke" to "6", "Period" to "30")
        )
        val corruptedTotp = VaultItem(
            id = "broken", title = "Broken 2FA", type = "Autentifikator",
            fields = mapOf("TOTP tajna" to secret, "Znamenke" to "six", "Period" to "30")
        )
        val credential = VaultItem(id = "strong", title = "Strong login", password = "Abcd1234!Efgh56")
        assertTrue(totpConfigFromFields(validTotp.fields) != null)
        assertTrue(totpConfigFromFields(corruptedTotp.fields) == null)
        assertEquals(setOf("broken"), securityIssueIds(listOf(validTotp, corruptedTotp, credential)))
        assertEquals(1, securityIssueCount(listOf(validTotp, corruptedTotp, credential)))
        assertEquals(100, securityScore(listOf(validTotp, corruptedTotp, credential)) ?: -1)
        assertEquals(null, securityScore(listOf(corruptedTotp)))
    }

    @Test
    fun totpRejectsInvalidUriParametersAndFallbackSettings() {
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        listOf(
            "otpauth://totp/Keyra?secret=$secret&digits=six",
            "otpauth://totp/Keyra?secret=$secret&period=slow",
            "otpauth://totp/Keyra?secret=$secret&algorithm=SHA999"
        ).forEach { uri ->
            assertTrue("Invalid otpauth URI must fail: $uri", parseTotpInput(uri) == null)
        }
        assertTrue(parseTotpInput(secret, fallbackDigits = 9) == null)
        assertTrue(parseTotpInput(secret, fallbackPeriod = 0) == null)
        assertTrue(parseTotpInput(secret, fallbackAlgorithm = "SHA999") == null)
        assertTrue(totpConfigFromFields(mapOf("TOTP tajna" to secret, "Period" to "zero")) == null)
        assertTrue(parseTotpInput(secret) != null)
    }

    @Test
    fun otpauthRejectsDuplicateParametersAndUnsupportedAuthority() {
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        listOf(
            "otpauth://totp/Account?secret=$secret&secret=$secret",
            "otpauth://totp/Account?secret=$secret&SeCrEt=$secret",
            "otpauth://totp/Account?secret=$secret&digits=6&digits=8",
            "otpauth://totp/Account?secret=$secret&period=30&period=60",
            "otpauth://totp/Account?secret=$secret&issuer=One&issuer=Two",
            "otpauth://totp/Account?secret=$secret&bad=%GG",
            "otpauth://totp/Account?secret=$secret&missingEquals",
            "otpauth://user@totp/Account?secret=$secret",
            "otpauth://totp:80/Account?secret=$secret",
            "otpauth://totp/Account?secret=$secret#fragment"
        ).forEach { invalid ->
            assertTrue("Reject ambiguous otpauth URI: $invalid", parseTotpInput(invalid) == null)
        }
        assertTrue(parseTotpInput("otpauth://totp/Account?secret=$secret&digits=6&period=30") != null)
    }

    @Test
    fun totpLimitsVeryLargeSecretsAndMalformedTimeSettings() {
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        assertTrue(decodeBase32("A".repeat(1_025)) == null)
        assertTrue(normalizeBase32Secret("A".repeat(2_049)) == null)
        assertTrue(parseTotpInput("otpauth://totp/Test?secret=" + "A".repeat(4_100)) == null)
        val invalidPeriods = listOf(0, -1, 14, 121, Int.MAX_VALUE)
        invalidPeriods.forEach { period ->
            val config = TotpConfig(secret = secret, period = period)
            assertTrue("Invalid period must not generate TOTP: $period", generateTotp(config, 59_000L) == null)
            assertEquals(0, totpRemainingSeconds(config, 59_000L))
        }
        listOf(0, 5, 9).forEach { digits ->
            val config = TotpConfig(secret = secret, digits = digits)
            assertTrue(generateTotp(config, 59_000L) == null)
            assertEquals(0, totpRemainingSeconds(config, 59_000L))
        }
        assertTrue(generateTotp(TotpConfig(secret = secret, algorithm = "SHA999"), 59_000L) == null)
        assertTrue(generateTotp(TotpConfig(secret = secret), -1L) == null)
        assertEquals(0, totpRemainingSeconds(TotpConfig(secret = secret), -1L))
        assertEquals("287082", generateTotp(TotpConfig(secret = secret), 59_000L))
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
