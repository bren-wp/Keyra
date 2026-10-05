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
