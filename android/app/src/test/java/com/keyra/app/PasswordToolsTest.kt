package com.keyra.app

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
}
