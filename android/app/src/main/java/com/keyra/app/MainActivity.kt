package com.keyra.app

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ClipDescription
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.text.DateFormat
import java.util.Date
import java.util.Calendar
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private val Midnight = Color(0xFF0B0F14)
private val Slate = Color(0xFF121826)
private val Slate2 = Color(0xFF172033)
private val Cyan = Color(0xFF00E5D1)
private val Ice = Color(0xFF7DD3FC)
private val Indigo = Color(0xFF6366F1)
private val Muted = Color(0xFFAABBD5)
private val Good = Color(0xFF22E3B0)
private val Warn = Color(0xFFFFC247)
private val Danger = Color(0xFFFF5B6E)
private const val MAX_BACKUP_CHARS = 2_500_000
private const val MAX_VAULT_ITEMS = 10_000

enum class Screen { ONBOARDING, UNLOCK, VAULT, COLLECTIONS, GENERATOR, ADD, DETAIL, SETTINGS, SECURITY }

data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val username: String = "",
    val password: String = "",
    val website: String = "",
    val notes: String = "",
    val category: String = "Osobno",
    val favorite: Boolean = false,
    val type: String = "Prijava",
    val fields: Map<String, String> = emptyMap(),
    val updatedAt: Long = System.currentTimeMillis()
)

class MainActivity : FragmentActivity() {
    private val model: KeyraViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            KeyraTheme {
                KeyraRoot(model = model, requestBiometric = { reason, onSuccess ->
                    authenticateBiometric(reason, onSuccess)
                })
            }
        }
    }

    override fun onStart() {
        super.onStart()
        model.onAppForeground()
    }

    override fun onStop() {
        model.onAppBackground()
        super.onStop()
    }

    private fun authenticateBiometric(reason: String, onSuccess: () -> Unit) {
        val allowed = BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        if (allowed != BiometricManager.BIOMETRIC_SUCCESS) {
            model.message = "Biometrijsko otključavanje nije dostupno."
            return
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    model.message = errString.toString()
                }
            }
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Keyra")
                .setSubtitle(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()
        )
    }
}

class KeyraViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("keyra", Context.MODE_PRIVATE)
    private val auth = AuthStore(prefs)
    private val store = VaultStore(prefs)
    private val deviceAuthenticationAvailable =
        BiometricManager.from(app).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        ) == BiometricManager.BIOMETRIC_SUCCESS
    val items: SnapshotStateList<VaultItem> = mutableStateListOf()

    var isSetup by mutableStateOf(auth.isSetup())
    var unlocked by mutableStateOf(false)
    var screen by mutableStateOf(if (isSetup) Screen.UNLOCK else Screen.ONBOARDING)
    var selected by mutableStateOf<VaultItem?>(null)
    var message by mutableStateOf<String?>(null)
    var vaultCategoryFilter by mutableStateOf<String?>(null)
    var vaultTypeFilter by mutableStateOf<String?>(null)
    var biometricEnabled by mutableStateOf(
        prefs.getBoolean("biometric_enabled", true) && deviceAuthenticationAvailable
    )
    var sensitiveReauthEnabled by mutableStateOf(
        prefs.getBoolean("sensitive_reauth_enabled", true) &&
            prefs.getBoolean("biometric_enabled", true) &&
            deviceAuthenticationAvailable
    )
    var autoLockSeconds by mutableIntStateOf(prefs.getInt("auto_lock_seconds", 0))
    var importingNewVault by mutableStateOf(false)
    private var sessionPassword: String? = null
    private var backgroundAt: Long? = null

    fun startCreate() {
        importingNewVault = false
        screen = Screen.UNLOCK
    }

    fun startImport() {
        importingNewVault = true
        screen = Screen.UNLOCK
    }

    fun cancelSetup() {
        importingNewVault = false
        if (!isSetup) screen = Screen.ONBOARDING
    }

    fun open(screen: Screen) {
        if (screen == Screen.VAULT) {
            vaultCategoryFilter = null
            vaultTypeFilter = null
        }
        this.screen = screen
    }

    fun openCategory(category: String, type: String) {
        vaultCategoryFilter = category
        vaultTypeFilter = type
        screen = Screen.VAULT
    }

    fun clearVaultCategoryFilter() {
        vaultCategoryFilter = null
    }

    fun addNew() { selected = null; screen = Screen.ADD }
    fun editSelected() { if (selected != null) screen = Screen.ADD }
    fun select(item: VaultItem) { selected = item; screen = Screen.DETAIL }

    fun createVault(password: String): Boolean {
        if (password.length < 12) {
            message = "Glavna lozinka mora imati najmanje 12 znakova."
            return false
        }

        if (runCatching { store.save(emptyList()) }.isFailure) {
            message = "Trezor nije moguće izraditi. Provjerite zaključavanje uređaja i pokušajte ponovno."
            return false
        }
        if (!auth.create(password)) {
            store.clear()
            message = "Zaštitu glavne lozinke nije moguće trajno spremiti. Pokušajte ponovno."
            return false
        }

        finishInitialSetup(password, emptyList())
        return true
    }

    fun importNewVault(context: Context, password: String): Boolean {
        if (password.length < 12) {
            message = "Glavna lozinka sigurnosne kopije mora imati najmanje 12 znakova."
            return false
        }

        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        val payload = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(context)?.toString().orEmpty()
        } else {
            ""
        }
        if (payload.isBlank()) {
            message = "Međuspremnik ne sadrži Keyra sigurnosnu kopiju."
            return false
        }
        if (payload.length > MAX_BACKUP_CHARS) {
            message = "Sigurnosna kopija je prevelika za siguran uvoz."
            return false
        }

        val imported = runCatching {
            val json = PortableBackup.decrypt(payload, password)
            store.fromJson(json)
        }.getOrElse {
            message = "Sigurnosna kopija nije valjana ili lozinka nije odgovarajuća."
            return false
        }

        if (runCatching { store.save(imported) }.isFailure) {
            message = "Uvezeni trezor nije moguće trajno spremiti. Postojeći podaci nisu promijenjeni."
            return false
        }
        if (!auth.create(password)) {
            store.clear()
            message = "Zaštitu glavne lozinke nije moguće trajno spremiti. Uvoz je poništen."
            return false
        }

        clearClipboardIfMatches(context, payload)
        finishInitialSetup(password, imported)
        message = "Keyra trezor uspješno je uvezen."
        return true
    }

    private fun finishInitialSetup(password: String, initialItems: List<VaultItem>) {
        prefs.edit()
            .remove("unlock_failed_attempts")
            .remove("unlock_lockout_until")
            .apply()
        isSetup = true
        importingNewVault = false
        sessionPassword = password
        unlocked = true
        items.clear()
        items.addAll(initialItems)
        selected = null
        screen = Screen.VAULT
    }

    fun unlock(password: String): Boolean {
        val now = System.currentTimeMillis()
        val lockoutUntil = prefs.getLong("unlock_lockout_until", 0L)
        if (lockoutUntil > now) {
            val seconds = ((lockoutUntil - now + 999L) / 1000L).coerceAtLeast(1L)
            message = "Previše neuspjelih pokušaja. Pokušajte ponovno za " + seconds + " s."
            return false
        }

        if (!auth.verify(password)) {
            val attempts = prefs.getInt("unlock_failed_attempts", 0) + 1
            val penaltyMs = when {
                attempts >= 10 -> 300_000L
                attempts >= 7 -> 60_000L
                attempts >= 5 -> 30_000L
                else -> 0L
            }
            prefs.edit()
                .putInt("unlock_failed_attempts", attempts)
                .putLong("unlock_lockout_until", if (penaltyMs > 0L) now + penaltyMs else 0L)
                .apply()

            message = if (penaltyMs > 0L) {
                "Previše neuspjelih pokušaja. Trezor je privremeno zaključan."
            } else {
                "Glavna lozinka nije ispravna."
            }
            return false
        }

        prefs.edit()
            .remove("unlock_failed_attempts")
            .remove("unlock_lockout_until")
            .apply()
        sessionPassword = password
        if (!loadVault()) {
            sessionPassword = null
            unlocked = false
            return false
        }
        unlocked = true
        screen = Screen.VAULT
        return true
    }

    fun unlockFromBiometric() {
        if (!isSetup) return
        if (!loadVault()) {
            unlocked = false
            return
        }
        unlocked = true
        screen = Screen.VAULT
    }

    fun lock() {
        unlocked = false
        sessionPassword = null
        items.clear()
        selected = null
        vaultCategoryFilter = null
        vaultTypeFilter = null
        screen = Screen.UNLOCK
    }

    fun saveItem(item: VaultItem) {
        val saved = item.copy(updatedAt = System.currentTimeMillis())
        val next = items.toMutableList()
        val index = next.indexOfFirst { it.id == item.id }
        if (index >= 0) next[index] = saved else next.add(0, saved)

        runCatching { store.save(next) }
            .onSuccess {
                items.clear()
                items.addAll(next)
                selected = saved
                screen = Screen.VAULT
            }
            .onFailure {
                message = "Stavku nije moguće spremiti. Pokušajte ponovno."
            }
    }

    fun toggleSelectedFavorite() {
        val target = selected ?: return
        val updated = target.copy(
            favorite = !target.favorite,
            updatedAt = System.currentTimeMillis()
        )
        val next = items.map { if (it.id == target.id) updated else it }

        runCatching { store.save(next) }
            .onSuccess {
                items.clear()
                items.addAll(next)
                selected = updated
                message = if (updated.favorite)
                    "Stavka je dodana u favorite."
                else
                    "Stavka je uklonjena iz favorita."
            }
            .onFailure {
                message = "Promjenu favorita nije moguće spremiti."
            }
    }

    fun deleteSelected() {
        val target = selected ?: return
        val next = items.filterNot { it.id == target.id }
        runCatching { store.save(next) }
            .onSuccess {
                items.clear()
                items.addAll(next)
                selected = null
                screen = Screen.VAULT
            }
            .onFailure {
                message = "Stavku nije moguće izbrisati. Pokušajte ponovno."
            }
    }

    fun exportBackup(context: Context) {
        val password = sessionPassword
        if (password.isNullOrBlank()) {
            message = "Za sigurnosnu kopiju prvo otključajte trezor glavnom lozinkom."
            return
        }
        runCatching { PortableBackup.encrypt(store.toJson(items), password) }
            .onSuccess { payload ->
                copy(context, payload)
                message = "Šifrirana sigurnosna kopija kopirana je u međuspremnik i automatski će se ukloniti."
            }
            .onFailure {
                message = "Sigurnosnu kopiju nije moguće izraditi."
            }
    }

    fun importBackup(context: Context) {
        val password = sessionPassword
        if (password.isNullOrBlank()) {
            message = "Za uvoz prvo otključajte trezor glavnom lozinkom."
            return
        }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(context)?.toString().orEmpty()
        } else {
            ""
        }
        if (text.isBlank()) {
            message = "Međuspremnik ne sadrži sigurnosnu kopiju."
            return
        }
        if (text.length > MAX_BACKUP_CHARS) {
            message = "Sigurnosna kopija je prevelika za siguran uvoz."
            return
        }
        runCatching {
            val json = PortableBackup.decrypt(text, password)
            val imported = store.fromJson(json)
            store.save(imported)
            imported
        }.onSuccess { imported ->
            items.clear()
            items.addAll(imported)
            selected = null
            clearClipboardIfMatches(context, text)
            message = "Sigurnosna kopija uspješno je uvezena. Sadržaj kopije uklonjen je iz međuspremnika."
        }.onFailure {
            message = "Sigurnosna kopija nije valjana ili je nije moguće spremiti."
        }
    }

    fun toggleBiometric(value: Boolean) {
        if (value && !deviceAuthenticationAvailable) {
            biometricEnabled = false
            sensitiveReauthEnabled = false
            message = "Biometrija ili zaključavanje uređaja nisu dostupni. Najprije zaštitite uređaj."
            return
        }

        val nextSensitive = if (value) sensitiveReauthEnabled else false
        val persisted = prefs.edit()
            .putBoolean("biometric_enabled", value)
            .putBoolean("sensitive_reauth_enabled", nextSensitive)
            .commit()

        if (persisted) {
            biometricEnabled = value
            sensitiveReauthEnabled = nextSensitive
        } else {
            message = "Postavku biometrijskog otključavanja nije moguće spremiti."
        }
    }

    fun toggleSensitiveReauth(value: Boolean) {
        val next = value && biometricEnabled
        if (prefs.edit().putBoolean("sensitive_reauth_enabled", next).commit()) {
            sensitiveReauthEnabled = next
        } else {
            message = "Postavku dodatne potvrde nije moguće spremiti."
        }
    }

    fun cycleAutoLock() {
        val next = when (autoLockSeconds) {
            0 -> 30
            30 -> 60
            60 -> 300
            else -> 0
        }
        if (prefs.edit().putInt("auto_lock_seconds", next).commit()) {
            autoLockSeconds = next
            message = "Automatsko zaključavanje: " + autoLockLabel()
        } else {
            message = "Postavku automatskog zaključavanja nije moguće spremiti."
        }
    }

    fun autoLockLabel(): String = when (autoLockSeconds) {
        0 -> "Odmah"
        30 -> "30 sekundi"
        60 -> "1 minuta"
        300 -> "5 minuta"
        else -> autoLockSeconds.toString() + " s"
    }

    fun onAppBackground() {
        if (!unlocked) return
        if (autoLockSeconds == 0) {
            lock()
        } else {
            backgroundAt = System.currentTimeMillis()
        }
    }

    fun onAppForeground() {
        val started = backgroundAt ?: return
        backgroundAt = null
        if (unlocked && System.currentTimeMillis() - started >= autoLockSeconds * 1000L) {
            lock()
        }
    }

    private fun loadVault(): Boolean {
        val loaded = store.load()
        if (loaded == null) {
            message = "Trezor nije moguće otvoriti. Podaci nisu promijenjeni."
            return false
        }
        items.clear()
        items.addAll(loaded)
        return true
    }
}

private class AuthStore(private val prefs: android.content.SharedPreferences) {
    companion object {
        private const val CURRENT_ITERATIONS = 600_000
        private const val LEGACY_ITERATIONS = 180_000
    }

    fun isSetup() = prefs.contains("master_hash")

    fun create(password: String): Boolean {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val saved = prefs.edit()
            .putString("master_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .putInt("master_iterations", CURRENT_ITERATIONS)
            .putString("master_hash", derive(password, salt, CURRENT_ITERATIONS))
            .commit()
        if (!saved) clear()
        return saved
    }

    fun clear(): Boolean = prefs.edit()
        .remove("master_salt")
        .remove("master_iterations")
        .remove("master_hash")
        .commit()

    fun verify(password: String): Boolean {
        return runCatching {
            val encodedSalt = prefs.getString("master_salt", null) ?: return false
            val salt = Base64.decode(encodedSalt, Base64.NO_WRAP)
            val expected = prefs.getString("master_hash", null) ?: return false
            val iterations = prefs.getInt("master_iterations", LEGACY_ITERATIONS)
                .coerceIn(100_000, 2_000_000)
            val actual = derive(password, salt, iterations)
            val ok = MessageDigest.isEqual(expected.toByteArray(), actual.toByteArray())
            if (ok && iterations < CURRENT_ITERATIONS) {
                prefs.edit()
                    .putInt("master_iterations", CURRENT_ITERATIONS)
                    .putString("master_hash", derive(password, salt, CURRENT_ITERATIONS))
                    .apply()
            }
            ok
        }.getOrDefault(false)
    }

    private fun derive(password: String, salt: ByteArray, iterations: Int): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        } finally {
            spec.clearPassword()
        }
    }
}

private class CryptoStore {
    private val alias = "keyra-vault-key"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    fun encrypt(text: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val encrypted = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + "." +
            Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun decrypt(payload: String): String {
        val parts = payload.split(".")
        require(parts.size == 2)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(),
            GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP))
        )
        return cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)).toString(Charsets.UTF_8)
    }
}

internal fun normalizePortableUpdatedAt(
    raw: Double,
    fallback: Long = System.currentTimeMillis()
): Long {
    if (!raw.isFinite() || raw <= 0.0) return fallback

    // Legacy iOS JSONEncoder dates are seconds since 2001-01-01.
    // Current portable Keyra backups use Unix epoch milliseconds.
    return if (raw < 100_000_000_000.0) {
        ((raw + 978_307_200.0) * 1000.0).toLong()
    } else {
        raw.toLong()
    }
}

private class VaultStore(private val prefs: android.content.SharedPreferences) {
    private val crypto = CryptoStore()

    fun save(items: List<VaultItem>) {
        val encrypted = crypto.encrypt(toJson(items))
        check(prefs.edit().putString("vault_blob", encrypted).commit()) {
            "Trezor nije moguće trajno spremiti."
        }
    }

    fun clear(): Boolean = prefs.edit().remove("vault_blob").commit()

    fun load(): List<VaultItem>? {
        val blob = prefs.getString("vault_blob", null) ?: return emptyList()
        return runCatching { fromJson(crypto.decrypt(blob)) }.getOrNull()
    }

    fun toJson(items: List<VaultItem>): String {
        val array = JSONArray()
        items.forEach { item ->
            array.put(JSONObject().apply {
                put("id", item.id)
                put("title", item.title)
                put("username", item.username)
                put("password", item.password)
                put("website", item.website)
                put("notes", item.notes)
                put("category", item.category)
                put("favorite", item.favorite)
                put("type", item.type)
                put("fields", JSONObject().apply {
                    item.fields.forEach { (key, value) -> put(key, value) }
                })
                put("updatedAt", item.updatedAt)
            })
        }
        return array.toString()
    }

    fun fromJson(json: String): List<VaultItem> {
        val array = JSONArray(json)
        require(array.length() <= MAX_VAULT_ITEMS) { "Previše stavki u trezoru." }
        val seenIds = mutableSetOf<String>()
        return buildList {
            for (i in 0 until array.length()) {
                val o = array.getJSONObject(i)
                val rawId = o.optString("id").trim()
                val itemId = rawId.ifBlank { UUID.randomUUID().toString() }
                require(seenIds.add(itemId)) { "Sigurnosna kopija sadrži duplicirane identifikatore stavki." }
                val username = o.optString("username")
                val password = o.optString("password")
                val website = o.optString("website")
                val notes = o.optString("notes")
                val storedType = if (o.has("type")) o.optString("type", "Prijava") else ""
                val inferredType = when {
                    storedType.isNotBlank() -> storedType
                    password.isBlank() && website.isBlank() && username.isBlank() && notes.isNotBlank() -> "Bilješka"
                    else -> "Prijava"
                }
                val fieldsObject = o.optJSONObject("fields")
                val fields = buildMap {
                    if (fieldsObject != null) {
                        val keys = fieldsObject.keys()
                        while (keys.hasNext()) {
                            val key = keys.next()
                            put(key, fieldsObject.optString(key))
                        }
                    }
                }
                add(
                    VaultItem(
                        id = itemId,
                        title = o.optString("title"),
                        username = username,
                        password = password,
                        website = website,
                        notes = notes,
                        category = o.optString("category", "Osobno"),
                        favorite = o.optBoolean("favorite", false),
                        type = inferredType,
                        fields = fields,
                        updatedAt = normalizePortableUpdatedAt(
                            o.optDouble("updatedAt", Double.NaN)
                        )
                    )
                )
            }
        }
    }
}

internal object PortableBackup {
    private const val ITERATIONS = 600_000
    private const val LEGACY_ANDROID_ITERATIONS = 180_000
    private const val LEGACY_IOS_ITERATIONS = 120_000
    private const val IV_BYTES = 12
    private const val SALT_BYTES = 16
    private const val TAG_BYTES = 16

    fun encrypt(text: String, password: String): String {
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val key = derive(password, salt, ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        val combined = iv + encrypted

        // KEYRA2 is intentionally cross-platform:
        // version.iterations.salt.(12-byte nonce + ciphertext + 16-byte GCM tag)
        return listOf(
            "KEYRA2",
            ITERATIONS.toString(),
            Base64.encodeToString(salt, Base64.NO_WRAP),
            Base64.encodeToString(combined, Base64.NO_WRAP)
        ).joinToString(".")
    }

    fun decrypt(payload: String, password: String): String {
        val parts = payload.split(".")
        return when {
            parts.size == 4 && parts[0] == "KEYRA2" -> {
                val iterations = parts[1].toInt()
                require(iterations in 100_000..2_000_000)
                val salt = decodeSalt(parts[2])
                val combined = Base64.decode(parts[3], Base64.NO_WRAP)
                decryptCombined(combined, password, salt, listOf(iterations))
            }
            // Legacy Android KEYRA2 stored nonce and ciphertext/tag separately.
            parts.size == 5 && parts[0] == "KEYRA2" -> {
                val iterations = parts[1].toInt()
                require(iterations in 100_000..2_000_000)
                val salt = decodeSalt(parts[2])
                val iv = Base64.decode(parts[3], Base64.NO_WRAP)
                val encrypted = Base64.decode(parts[4], Base64.NO_WRAP)
                decryptParts(iv, encrypted, password, salt, listOf(iterations))
            }
            // Legacy iOS KEYRA1 used CryptoKit combined data and 120k PBKDF2 iterations.
            parts.size == 3 && parts[0] == "KEYRA1" -> {
                val salt = decodeSalt(parts[1])
                val combined = Base64.decode(parts[2], Base64.NO_WRAP)
                decryptCombined(
                    combined,
                    password,
                    salt,
                    listOf(LEGACY_IOS_ITERATIONS, LEGACY_ANDROID_ITERATIONS)
                )
            }
            // Legacy Android KEYRA1 stored nonce and ciphertext/tag separately.
            parts.size == 4 && parts[0] == "KEYRA1" -> {
                val salt = decodeSalt(parts[1])
                val iv = Base64.decode(parts[2], Base64.NO_WRAP)
                val encrypted = Base64.decode(parts[3], Base64.NO_WRAP)
                decryptParts(
                    iv,
                    encrypted,
                    password,
                    salt,
                    listOf(LEGACY_ANDROID_ITERATIONS, LEGACY_IOS_ITERATIONS)
                )
            }
            else -> error("Neispravan format sigurnosne kopije.")
        }
    }

    private fun decodeSalt(value: String): ByteArray {
        val salt = Base64.decode(value, Base64.NO_WRAP)
        require(salt.size == SALT_BYTES) { "Neispravna sol sigurnosne kopije." }
        return salt
    }

    private fun decryptCombined(
        combined: ByteArray,
        password: String,
        salt: ByteArray,
        iterations: List<Int>
    ): String {
        require(combined.size >= IV_BYTES + TAG_BYTES) { "Neispravan šifrirani sadržaj." }
        val iv = combined.copyOfRange(0, IV_BYTES)
        val encrypted = combined.copyOfRange(IV_BYTES, combined.size)
        return decryptParts(iv, encrypted, password, salt, iterations)
    }

    private fun decryptParts(
        iv: ByteArray,
        encrypted: ByteArray,
        password: String,
        salt: ByteArray,
        iterations: List<Int>
    ): String {
        require(iv.size == IV_BYTES) { "Neispravan nonce sigurnosne kopije." }
        require(encrypted.size >= TAG_BYTES) { "Neispravan šifrirani sadržaj." }

        var lastError: Throwable? = null
        for (iterationCount in iterations) {
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    derive(password, salt, iterationCount),
                    GCMParameterSpec(128, iv)
                )
                return cipher.doFinal(encrypted).toString(Charsets.UTF_8)
            } catch (error: Exception) {
                lastError = error
            }
        }
        throw lastError ?: IllegalArgumentException("Sigurnosnu kopiju nije moguće dešifrirati.")
    }

    private fun derive(password: String, salt: ByteArray, iterations: Int): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            javax.crypto.spec.SecretKeySpec(bytes, "AES")
        } finally {
            spec.clearPassword()
        }
    }
}

@Composable
private fun KeyraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Cyan,
            secondary = Indigo,
            background = Midnight,
            surface = Slate,
            onPrimary = Midnight,
            onBackground = Color.White,
            onSurface = Color.White
        ),
        content = content
    )
}

@Composable
private fun KeyraRoot(
    model: KeyraViewModel,
    requestBiometric: (String, () -> Unit) -> Unit
) {
    var splash by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) {
        delay(850)
        splash = false
    }
    Box(Modifier.fillMaxSize().background(Midnight)) {
        if (splash) SplashScreen()
        else when (model.screen) {
            Screen.ONBOARDING -> OnboardingScreen(model)
            Screen.UNLOCK -> UnlockScreen(model, requestBiometric)
            Screen.VAULT -> MainScaffold(model, Screen.VAULT) { VaultScreen(model) }
            Screen.COLLECTIONS -> MainScaffold(model, Screen.COLLECTIONS) { CollectionsScreen(model) }
            Screen.GENERATOR -> MainScaffold(model, Screen.GENERATOR) { GeneratorScreen(model) }
            Screen.ADD -> AddScreen(model)
            Screen.DETAIL -> DetailScreen(model, requestBiometric)
            Screen.SETTINGS -> MainScaffold(model, Screen.SETTINGS) { SettingsScreen(model, requestBiometric) }
            Screen.SECURITY -> MainScaffold(model, Screen.SETTINGS) { SecurityScreen(model) }
        }
        model.message?.let { msg ->
            LaunchedEffect(msg) { delay(2600); model.message = null }
            val hasBottomNavigation = model.screen in listOf(
                Screen.VAULT,
                Screen.COLLECTIONS,
                Screen.GENERATOR,
                Screen.SETTINGS,
                Screen.SECURITY
            )
            Surface(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(
                        start = 22.dp,
                        end = 22.dp,
                        bottom = if (hasBottomNavigation) 96.dp else 22.dp
                    ),
                shape = RoundedCornerShape(18.dp),
                color = Slate2,
                border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha = .28f))
            ) { Text(msg, modifier = Modifier.padding(16.dp), color = Color.White) }
        }
    }
}

@Composable
private fun SplashScreen() {
    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Midnight, Color(0xFF071B36), Midnight))),
        contentAlignment = Alignment.Center
    ) {
        val compact = maxHeight < 620.dp || maxWidth < 340.dp
        val markSize = if (compact) 94.dp else 118.dp
        val titleSize = if (compact) 46.sp else 54.sp

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            KeyraMark(markSize)
            Spacer(Modifier.height(if (compact) 14.dp else 18.dp))
            Text(
                "Keyra",
                color = Color.White,
                fontSize = titleSize,
                fontWeight = FontWeight.ExtraBold,
                maxLines = 1
            )
            Text(
                "SIGURNI UPRAVITELJ LOZINKI",
                color = Muted,
                fontSize = if (compact) 10.sp else 11.sp,
                letterSpacing = if (compact) 1.8.sp else 2.4.sp,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun KeyraMark(size: androidx.compose.ui.unit.Dp = 74.dp) {
    Box(
        Modifier.size(size)
            .clip(RoundedCornerShape(size * 0.25f))
            .background(Midnight)
            .border(1.dp, Cyan.copy(alpha=.7f), RoundedCornerShape(size * 0.25f)),
        contentAlignment = Alignment.Center
    ) {
        Image(
            painter = painterResource(id = R.drawable.ic_keyra),
            contentDescription = "Keyra",
            modifier = Modifier.fillMaxSize()
        )
    }
}

internal fun securityIssueIds(items: List<VaultItem>): Set<String> {
    val passwordItems = items.filter {
        (it.type == "Prijava" || it.type == "Wi-Fi") && it.password.isNotBlank()
    }
    val duplicatedIds = passwordItems
        .groupBy { it.password }
        .filterValues { it.size > 1 }
        .values
        .flatten()
        .map { it.id }
        .toSet()
    val weakIds = passwordItems
        .filter { !isStrongPassword(it.password) }
        .map { it.id }
        .toSet()
    return duplicatedIds + weakIds
}

internal fun securityIssueCount(items: List<VaultItem>): Int = securityIssueIds(items).size

@Composable
private fun BrandHeader(
    subtitle: String,
    notificationCount: Int = 0,
    onNotifications: () -> Unit = {}
) {
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val compact = maxWidth < 370.dp
        Row(
            Modifier
                .fillMaxWidth()
                .padding(
                    horizontal = if (compact) 14.dp else 20.dp,
                    vertical = if (compact) 8.dp else 12.dp
                ),
            verticalAlignment = Alignment.CenterVertically
        ) {
            KeyraMark(if (compact) 44.dp else 54.dp)
            Spacer(Modifier.width(if (compact) 10.dp else 14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    "Keyra",
                    fontSize = if (compact) 28.sp else 32.sp,
                    color = Color.White,
                    fontWeight = FontWeight.ExtraBold,
                    maxLines = 1
                )
                Text(
                    subtitle,
                    color = Muted,
                    fontSize = if (compact) 9.sp else 11.sp,
                    letterSpacing = if (compact) 1.4.sp else 2.2.sp,
                    maxLines = 1
                )
            }
            Box {
                IconButton(
                    onClick = onNotifications,
                    modifier = Modifier.size(if (compact) 38.dp else 44.dp)
                ) {
                    Icon(
                        Icons.Outlined.Notifications,
                        contentDescription = if (notificationCount > 0)
                            "Sigurnosna upozorenja: $notificationCount"
                        else
                            "Nema sigurnosnih upozorenja",
                        tint = Color.White
                    )
                }
                if (notificationCount > 0) {
                    Surface(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .offset(x = 2.dp, y = (-2).dp),
                        shape = CircleShape,
                        color = Danger
                    ) {
                        Text(
                            if (notificationCount > 9) "9+" else notificationCount.toString(),
                            color = Color.White,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                        )
                    }
                }
            }
            Spacer(Modifier.width(if (compact) 4.dp else 8.dp))
            Box(
                Modifier
                    .size(if (compact) 38.dp else 44.dp)
                    .clip(CircleShape)
                    .border(1.dp, Cyan, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text("K", color = Color.White, fontWeight = FontWeight.Bold, fontSize = if (compact) 13.sp else 14.sp)
            }
        }
    }
}


@Composable
private fun OnboardingHeroBadge(icon: ImageVector) {
    Box(
        modifier = Modifier
            .size(46.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Slate2.copy(alpha = .96f))
            .border(1.dp, Ice.copy(alpha = .38f), RoundedCornerShape(14.dp)),
        contentAlignment = Alignment.Center
    ) {
        Icon(icon, contentDescription = null, tint = Ice, modifier = Modifier.size(24.dp))
    }
}

@Composable
private fun OnboardingVaultHero(compact: Boolean) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(if (compact) 154.dp else 190.dp)
            .clip(RoundedCornerShape(if (compact) 24.dp else 30.dp))
            .background(
                Brush.radialGradient(
                    listOf(
                        Indigo.copy(alpha = .30f),
                        Color(0xFF0A3150).copy(alpha = .72f),
                        Midnight
                    )
                )
            )
            .border(
                1.dp,
                Brush.linearGradient(listOf(Cyan.copy(alpha = .72f), Indigo.copy(alpha = .58f))),
                RoundedCornerShape(if (compact) 24.dp else 30.dp)
            )
            .padding(if (compact) 12.dp else 16.dp)
    ) {
        Box(
            Modifier
                .align(Alignment.Center)
                .size(if (compact) 94.dp else 116.dp)
                .clip(RoundedCornerShape(if (compact) 26.dp else 32.dp))
                .background(Slate.copy(alpha = .92f))
                .border(1.dp, Cyan.copy(alpha = .62f), RoundedCornerShape(if (compact) 26.dp else 32.dp)),
            contentAlignment = Alignment.Center
        ) {
            KeyraMark(if (compact) 72.dp else 90.dp)
        }

        Box(Modifier.align(Alignment.TopStart)) {
            OnboardingHeroBadge(Icons.Outlined.Fingerprint)
        }
        Box(Modifier.align(Alignment.TopEnd)) {
            OnboardingHeroBadge(Icons.Outlined.Security)
        }
        Box(Modifier.align(Alignment.BottomStart)) {
            OnboardingHeroBadge(Icons.Outlined.CreditCard)
        }
        Box(Modifier.align(Alignment.BottomEnd)) {
            OnboardingHeroBadge(Icons.Outlined.Cloud)
        }
    }
}

@Composable
private fun OnboardingScreen(model: KeyraViewModel) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val compact = maxHeight < 720.dp || maxWidth < 360.dp
        val horizontal = if (maxWidth >= 600.dp) 72.dp else 20.dp

        Column(
            Modifier
                .fillMaxSize()
                .widthIn(max = 680.dp)
                .align(Alignment.TopCenter)
                .padding(horizontal = horizontal)
        ) {
            Column(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(Modifier.height(if (compact) 10.dp else 20.dp))
                KeyraMark(if (compact) 66.dp else 84.dp)
                Spacer(Modifier.height(if (compact) 6.dp else 8.dp))
                Text(
                    "Keyra",
                    color = Color.White,
                    fontSize = if (compact) 34.sp else 42.sp,
                    fontWeight = FontWeight.ExtraBold,
                    maxLines = 1
                )
                Text(
                    "SIGURNI UPRAVITELJ LOZINKI",
                    color = Muted,
                    fontSize = if (compact) 9.sp else 11.sp,
                    letterSpacing = if (compact) 1.4.sp else 2.sp,
                    maxLines = 1
                )

                Spacer(Modifier.height(if (compact) 10.dp else 14.dp))
                OnboardingVaultHero(compact)
                Spacer(Modifier.height(if (compact) 14.dp else 22.dp))
                Text(
                    "Sigurniji način upravljanja lozinkama",
                    modifier = Modifier.fillMaxWidth(),
                    color = Color.White,
                    fontSize = if (compact) 25.sp else 31.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    "Čuvajte svoje lozinke i osjetljive podatke na jednom sigurnom mjestu.",
                    modifier = Modifier.fillMaxWidth(),
                    color = Muted,
                    fontSize = if (compact) 14.sp else 16.sp
                )

                Spacer(Modifier.height(if (compact) 12.dp else 18.dp))
                FeatureCard(
                    Icons.Outlined.Lock,
                    "Potpuno šifrirano",
                    "Vaši podaci ostaju na vašem uređaju.",
                    compact
                )
                FeatureCard(
                    Icons.Outlined.Fingerprint,
                    "Privatnost u osnovi",
                    "Stvoreno za vaš mir.",
                    compact
                )
                FeatureCard(
                    Icons.Outlined.PhoneAndroid,
                    "Radi svugdje",
                    "Pregledno na Androidu i iOS-u.",
                    compact
                )
                Spacer(Modifier.height(12.dp))
            }

            Column(
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(top = 8.dp, bottom = 10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = model::startCreate,
                    modifier = Modifier.fillMaxWidth().height(if (compact) 52.dp else 58.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                    shape = RoundedCornerShape(28.dp)
                ) {
                    Text("Izradi trezor", fontSize = if (compact) 17.sp else 18.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(8.dp))
                    Icon(Icons.Outlined.ArrowForward, contentDescription = null)
                }
                OutlinedButton(
                    onClick = model::startImport,
                    modifier = Modifier.fillMaxWidth().height(if (compact) 48.dp else 54.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha = .72f)),
                    shape = RoundedCornerShape(27.dp)
                ) {
                    Icon(Icons.Outlined.Download, contentDescription = null, tint = Cyan)
                    Spacer(Modifier.width(8.dp))
                    Text("Uvezi Keyra trezor", color = Color.White, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

@Composable
private fun FeatureCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    compact: Boolean = false
) {
    Surface(
        Modifier
            .fillMaxWidth()
            .padding(vertical = if (compact) 3.dp else 5.dp),
        shape = RoundedCornerShape(if (compact) 17.dp else 20.dp),
        color = Slate.copy(alpha = .9f),
        border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha = .35f))
    ) {
        Row(
            Modifier.padding(if (compact) 10.dp else 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier
                    .size(if (compact) 40.dp else 48.dp)
                    .clip(RoundedCornerShape(if (compact) 12.dp else 15.dp))
                    .background(Color(0xFF0A2D3C)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = Cyan, modifier = Modifier.size(if (compact) 21.dp else 24.dp))
            }
            Spacer(Modifier.width(if (compact) 10.dp else 14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = if (compact) 15.sp else 17.sp
                )
                Text(
                    subtitle,
                    color = Muted,
                    fontSize = if (compact) 12.sp else 14.sp
                )
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    model: KeyraViewModel,
    requestBiometric: (String, () -> Unit) -> Unit
) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    val creating = !model.isSetup
    val importing = creating && model.importingNewVault
    val context = LocalContext.current

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val compact = maxHeight < 700.dp || maxWidth < 360.dp
        Box(
            Modifier.fillMaxSize(),
            contentAlignment = Alignment.TopCenter
        ) {
            Column(
                Modifier
                    .fillMaxHeight()
                    .widthIn(max = 620.dp)
                    .verticalScroll(rememberScrollState())
                    .imePadding()
                    .padding(horizontal = if (compact) 16.dp else 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(Modifier.height(if (compact) 10.dp else 22.dp))
                KeyraMark(if (compact) 66.dp else 84.dp)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Keyra",
                    color = Color.White,
                    fontSize = if (compact) 36.sp else 44.sp,
                    fontWeight = FontWeight.ExtraBold,
                    maxLines = 1
                )
                Text(
                    "SIGURNI UPRAVITELJ LOZINKI",
                    color = Muted,
                    fontSize = if (compact) 9.sp else 11.sp,
                    letterSpacing = if (compact) 1.4.sp else 2.sp,
                    maxLines = 1
                )
                Spacer(Modifier.height(if (compact) 18.dp else 30.dp))

                GlassCard {
                    Text(
                        when {
                            importing -> "Uvezite Keyra trezor"
                            creating -> "Izradite trezor"
                            else -> "Otključajte trezor"
                        },
                        color = Color.White,
                        fontSize = if (compact) 26.sp else 31.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        when {
                            importing -> "Kopirajte šifriranu Keyra sigurnosnu kopiju u međuspremnik i unesite njezinu glavnu lozinku."
                            creating -> "Postavite glavnu lozinku kojom ćete otključavati svoj trezor."
                            else -> "Unesite glavnu lozinku kako biste pristupili svom sigurnom trezoru."
                        },
                        color = Muted,
                        fontSize = if (compact) 14.sp else 16.sp
                    )
                    Spacer(Modifier.height(if (compact) 10.dp else 16.dp))
                    KeyraPasswordField(password, { password = it }, show, { show = !show }, "Glavna lozinka")
                    if (creating && !importing) {
                        Spacer(Modifier.height(10.dp))
                        KeyraPasswordField(confirm, { confirm = it }, show, { show = !show }, "Ponovite glavnu lozinku")
                    }
                    if (importing) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Uvoz prihvaća šifriranu Keyra sigurnosnu kopiju i neće zamijeniti podatke ako provjera ili spremanje ne uspiju.",
                            color = Muted,
                            fontSize = 12.sp
                        )
                    }
                    Spacer(Modifier.height(if (compact) 12.dp else 16.dp))
                    Button(
                        onClick = {
                            when {
                                importing -> model.importNewVault(context, password)
                                creating -> {
                                    if (password != confirm) model.message = "Lozinke se ne podudaraju."
                                    else model.createVault(password)
                                }
                                else -> model.unlock(password)
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(if (compact) 52.dp else 56.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                        shape = RoundedCornerShape(28.dp)
                    ) {
                        Icon(Icons.Outlined.Lock, null)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            when {
                                importing -> "Uvezi trezor"
                                creating -> "Izradi trezor"
                                else -> "Otključaj"
                            },
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    if (!creating && model.biometricEnabled) {
                        Spacer(Modifier.height(12.dp))
                        HorizontalDivider(color = Muted.copy(alpha=.25f))
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                requestBiometric("Potvrdite identitet za pristup trezoru.") {
                                    model.unlockFromBiometric()
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha=.6f))
                        ) {
                            Icon(Icons.Outlined.Fingerprint, null, tint = Cyan)
                            Spacer(Modifier.width(8.dp))
                            Text("Biometrijsko otključavanje", color = Color.White, maxLines = 1)
                        }
                    }
                }
                if (creating) {
                    TextButton(onClick = model::cancelSetup) {
                        Icon(Icons.Outlined.ArrowBack, contentDescription = null, tint = Ice)
                        Spacer(Modifier.width(6.dp))
                        Text("Natrag", color = Ice)
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

@Composable
private fun KeyraPasswordField(
    value: String,
    onValue: (String) -> Unit,
    show: Boolean,
    toggle: () -> Unit,
    label: String
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValue,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            IconButton(onClick = toggle) {
                Icon(if (show) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, null)
            }
        },
        colors = keyraFieldColors(),
        shape = RoundedCornerShape(18.dp)
    )
}

@Composable
private fun GlassCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        shape = RoundedCornerShape(28.dp),
        color = Slate.copy(alpha=.92f),
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.45f))
    ) {
        Column(Modifier.padding(22.dp), content = content)
    }
}

@Composable
private fun MainScaffold(model: KeyraViewModel, active: Screen, content: @Composable () -> Unit) {
    Scaffold(
        containerColor = Midnight,
        bottomBar = { BottomNav(model, active) }
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding),
            contentAlignment = Alignment.TopCenter
        ) {
            Box(
                Modifier
                    .fillMaxSize()
                    .widthIn(max = 920.dp)
            ) {
                content()
            }
        }
    }
}

@Composable
private fun BottomNav(model: KeyraViewModel, active: Screen) {
    BoxWithConstraints(
        Modifier
            .fillMaxWidth()
            .background(Midnight)
            .navigationBarsPadding()
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        val compact = maxWidth < 360.dp
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            color = Slate.copy(alpha = .98f),
            border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha = .28f)),
            shadowElevation = 8.dp
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                NavItem(Icons.Outlined.Home, "Trezor", active == Screen.VAULT, compact) { model.open(Screen.VAULT) }
                NavItem(Icons.Outlined.Refresh, "Generator", active == Screen.GENERATOR, compact) { model.open(Screen.GENERATOR) }
                NavItem(Icons.Outlined.Folder, "Kolekcije", active == Screen.COLLECTIONS, compact) { model.open(Screen.COLLECTIONS) }
                NavItem(Icons.Outlined.Settings, "Postavke", active == Screen.SETTINGS, compact) { model.open(Screen.SETTINGS) }
            }
        }
    }
}

@Composable
private fun RowScope.NavItem(
    icon: ImageVector,
    label: String,
    selected: Boolean,
    compact: Boolean,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .weight(1f)
            .height(if (compact) 52.dp else 58.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(if (selected) Cyan.copy(alpha = .11f) else Color.Transparent)
            .border(
                width = 1.dp,
                color = if (selected) Cyan.copy(alpha = .30f) else Color.Transparent,
                shape = RoundedCornerShape(18.dp)
            )
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                icon,
                contentDescription = label,
                tint = if (selected) Cyan else Muted,
                modifier = Modifier.size(if (compact) 20.dp else 23.dp)
            )
            Spacer(Modifier.height(2.dp))
            Text(
                label,
                color = if (selected) Cyan else Muted,
                fontSize = if (compact) 8.sp else 10.sp,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                maxLines = 1
            )
            Spacer(Modifier.height(3.dp))
            Box(
                Modifier
                    .width(if (selected) 24.dp else 0.dp)
                    .height(2.dp)
                    .clip(CircleShape)
                    .background(Cyan)
            )
        }
    }
}

internal fun isStrongPassword(password: String): Boolean {
    if (password.length < 14) return false
    val classes = listOf(
        password.any(Char::isUpperCase),
        password.any(Char::isLowerCase),
        password.any(Char::isDigit),
        password.any { !it.isLetterOrDigit() }
    ).count { it }
    return classes >= 3
}

@Composable
private fun VaultScreen(model: KeyraViewModel) {
    var search by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(model.vaultTypeFilter ?: "Sve") }
    var newestFirst by remember { mutableStateOf(true) }
    var filterMenuExpanded by remember { mutableStateOf(false) }

    val displayed = model.items
        .filter {
            val typeMatch = when (filter) {
                "Sve" -> true
                "Favoriti" -> it.favorite
                else -> it.type == filter
            }
            val haystack = buildString {
                append(it.title); append(' ')
                append(it.username); append(' ')
                append(it.website); append(' ')
                append(it.notes); append(' ')
                append(it.category); append(' ')
                append(it.fields.values.joinToString(" "))
            }
            val categoryMatch = model.vaultCategoryFilter == null || it.category == model.vaultCategoryFilter
            typeMatch && categoryMatch && (search.isBlank() || haystack.contains(search, true))
        }
        .let { list ->
            if (newestFirst) list.sortedByDescending { it.updatedAt }
            else list.sortedBy { it.title.lowercase() }
        }

    val passwordItems = model.items.filter { it.type == "Prijava" || it.type == "Wi-Fi" }
    val weak = passwordItems.count { it.password.isNotBlank() && !isStrongPassword(it.password) }
    val duplicated = passwordItems.groupBy { it.password }
        .filter { it.key.isNotBlank() && it.value.size > 1 }
        .values.flatten().map { it.id }.toSet()

    Column(Modifier.fillMaxSize()) {
        BrandHeader("MOJ TREZOR", securityIssueCount(model.items)) { model.open(Screen.SECURITY) }

        OutlinedTextField(
            search, { search = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp),
            placeholder = { Text("Pretražite svoj trezor...") },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            trailingIcon = {
                Box {
                    IconButton(onClick = { filterMenuExpanded = true }) {
                        Icon(Icons.Outlined.Tune, contentDescription = "Filtri i sortiranje", tint = Ice)
                    }
                    DropdownMenu(
                        expanded = filterMenuExpanded,
                        onDismissRequest = { filterMenuExpanded = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(if (newestFirst) "Poredaj A–Ž" else "Poredaj po nedavnim") },
                            onClick = {
                                newestFirst = !newestFirst
                                filterMenuExpanded = false
                            }
                        )
                        DropdownMenuItem(
                            text = { Text("Prikaži sve") },
                            onClick = {
                                filter = "Sve"
                                search = ""
                                model.clearVaultCategoryFilter()
                                filterMenuExpanded = false
                            }
                        )
                    }
                }
            },
            colors = keyraFieldColors(),
            shape = RoundedCornerShape(24.dp)
        )

        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 18.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("Sve", "Prijava", "Bilješka", "Kartica", "Identitet", "Wi-Fi", "Favoriti").forEach { value ->
                val label = when (value) {
                    "Prijava" -> "Prijave"
                    "Bilješka" -> "Bilješke"
                    "Kartica" -> "Kartice"
                    else -> value
                }
                FilterChip(
                    selected = filter == value,
                    onClick = { filter = value },
                    label = { Text(label) },
                    leadingIcon = {
                        Icon(
                            when (value) {
                                "Prijava" -> Icons.Outlined.Lock
                                "Bilješka" -> Icons.Outlined.Description
                                "Kartica" -> Icons.Outlined.CreditCard
                                "Identitet" -> Icons.Outlined.Badge
                                "Wi-Fi" -> Icons.Outlined.Wifi
                                "Favoriti" -> Icons.Outlined.Star
                                else -> Icons.Outlined.GridView
                            },
                            null,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                )
            }
        }

        model.vaultCategoryFilter?.let { category ->
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = Cyan.copy(alpha = .12f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha = .55f))
                ) {
                    Row(
                        Modifier.padding(start = 11.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Kategorija: $category", color = Cyan, fontSize = 12.sp)
                        IconButton(
                            onClick = model::clearVaultCategoryFilter,
                            modifier = Modifier.size(30.dp)
                        ) {
                            Icon(
                                Icons.Outlined.Close,
                                contentDescription = "Ukloni filtar",
                                tint = Cyan,
                                modifier = Modifier.size(17.dp)
                            )
                        }
                    }
                }
            }
        }

        BoxWithConstraints(Modifier.fillMaxWidth()) {
            if (maxWidth < 370.dp) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 14.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    SummaryCard(model.items.size.toString(), "Ukupno", Cyan, Modifier.width(112.dp))
                    SummaryCard(weak.toString(), "Slabe", Danger, Modifier.width(112.dp))
                    SummaryCard(duplicated.size.toString(), "Ponovljene", Indigo, Modifier.width(122.dp))
                }
            } else {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 18.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    SummaryCard(model.items.size.toString(), "Ukupno", Cyan, Modifier.weight(1f))
                    SummaryCard(weak.toString(), "Slabe", Danger, Modifier.weight(1f))
                    SummaryCard(duplicated.size.toString(), "Ponovljene", Indigo, Modifier.weight(1f))
                }
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Vaše stavke", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold, modifier = Modifier.weight(1f))
            TextButton(
                onClick = { newestFirst = !newestFirst },
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Icon(
                    if (newestFirst) Icons.Outlined.Schedule else Icons.Outlined.SortByAlpha,
                    contentDescription = null,
                    tint = Ice,
                    modifier = Modifier.size(17.dp)
                )
                Spacer(Modifier.width(4.dp))
                Text(if (newestFirst) "Najnovije" else "A–Ž", color = Muted, fontSize = 12.sp)
            }
            FilledIconButton(
                onClick = model::addNew,
                colors = IconButtonDefaults.filledIconButtonColors(containerColor = Cyan, contentColor = Midnight)
            ) { Icon(Icons.Outlined.Add, null) }
        }

        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp),
            contentPadding = PaddingValues(bottom = 18.dp)
        ) {
            items(displayed, key = { it.id }) { item ->
                VaultRow(item, duplicated.contains(item.id)) { model.select(item) }
            }
            if (displayed.isEmpty()) {
                item {
                    GlassCard {
                        Icon(
                            if (model.items.isEmpty()) Icons.Outlined.AddCircleOutline else Icons.Outlined.SearchOff,
                            null,
                            tint = Cyan,
                            modifier = Modifier.size(36.dp)
                        )
                        Text(
                            if (model.items.isEmpty()) "Vaš trezor je spreman" else "Nema rezultata",
                            color = Color.White,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            if (model.items.isEmpty())
                                "Dodajte prvu prijavu, sigurnu bilješku, karticu, identitet ili Wi‑Fi."
                            else
                                "Promijenite pretragu ili odaberite drugi filtar.",
                            color = Muted
                        )
                        if (model.items.isEmpty()) {
                            Button(
                                onClick = model::addNew,
                                colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                                shape = RoundedCornerShape(24.dp)
                            ) {
                                Icon(Icons.Outlined.Add, null)
                                Spacer(Modifier.width(6.dp))
                                Text("Dodaj prvu stavku", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(value: String, label: String, accent: Color, modifier: Modifier = Modifier) {
    Surface(modifier, shape = RoundedCornerShape(20.dp), color = Slate, border = androidx.compose.foundation.BorderStroke(1.dp, accent.copy(alpha=.6f))) {
        Column(Modifier.padding(14.dp)) {
            Text(value, color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.ExtraBold)
            Text(label, color = Muted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun VaultRow(item: VaultItem, duplicated: Boolean, onClick: () -> Unit) {
    val isPasswordItem = item.type == "Prijava" || item.type == "Wi-Fi"
    val stateColor = when {
        duplicated -> Danger
        isPasswordItem && item.password.isNotBlank() && !isStrongPassword(item.password) -> Warn
        else -> Good
    }
    val state = when {
        duplicated -> "Ponovno korištena"
        isPasswordItem && item.password.isNotBlank() && !isStrongPassword(item.password) -> "Potrebno ažuriranje"
        item.type == "Bilješka" -> "Zaštićena"
        item.type == "Kartica" -> "Zaštićena"
        item.type == "Identitet" -> "Zaštićen"
        else -> "Snažna"
    }
    val icon = when (item.type) {
        "Bilješka" -> Icons.Outlined.Description
        "Kartica" -> Icons.Outlined.CreditCard
        "Identitet" -> Icons.Outlined.Badge
        "Wi-Fi" -> Icons.Outlined.Wifi
        else -> Icons.Outlined.Lock
    }
    val accent = when (item.type) {
        "Bilješka" -> Indigo
        "Kartica" -> Color(0xFFFFC247)
        "Identitet" -> Color(0xFFB48CFF)
        "Wi-Fi" -> Color(0xFF22BDF7)
        else -> Cyan
    }
    val subtitle = when (item.type) {
        "Kartica" -> item.fields["Broj kartice"]?.let { "•••• " + it.takeLast(4) } ?: item.category
        "Identitet" -> item.fields["Puno ime"].orEmpty().ifBlank { item.category }
        "Wi-Fi" -> item.fields["Naziv mreže"].orEmpty().ifBlank { item.username.ifBlank { item.category } }
        "Bilješka" -> item.category
        else -> item.username.ifBlank { item.website.ifBlank { item.category } }
    }

    Surface(
        Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        BoxWithConstraints {
            val compact = maxWidth < 380.dp
            if (compact) {
                Column(Modifier.padding(11.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(14.dp))
                                .background(accent.copy(alpha=.16f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(icon, null, tint = accent)
                        }
                        Spacer(Modifier.width(9.dp))
                        Column(Modifier.weight(1f)) {
                            Text(item.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp, maxLines = 1)
                            Text(subtitle, color = Muted, fontSize = 11.sp, maxLines = 1)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    VaultStatusChip(
                        state = state,
                        stateColor = stateColor,
                        modifier = Modifier.align(Alignment.End),
                        compact = true
                    )
                }
            } else {
                Row(
                    Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(48.dp)
                            .clip(RoundedCornerShape(14.dp))
                            .background(accent.copy(alpha=.16f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(icon, null, tint = accent)
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(item.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp, maxLines = 1)
                        Text(subtitle, color = Muted, fontSize = 13.sp, maxLines = 1)
                    }
                    VaultStatusChip(state = state, stateColor = stateColor)
                }
            }
        }
    }
}

@Composable
private fun VaultStatusChip(
    state: String,
    stateColor: Color,
    modifier: Modifier = Modifier,
    compact: Boolean = false
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        color = stateColor.copy(alpha=.12f),
        border = androidx.compose.foundation.BorderStroke(1.dp, stateColor.copy(alpha=.8f))
    ) {
        Text(
            state,
            color = stateColor,
            fontSize = if (compact) 9.sp else 11.sp,
            modifier = Modifier.padding(
                horizontal = if (compact) 8.dp else 10.dp,
                vertical = if (compact) 5.dp else 7.dp
            ),
            maxLines = 1
        )
    }
}

@Composable
private fun CollectionsScreen(model: KeyraViewModel) {
    val categories = listOf(
        "Osobno" to Color(0xFF00AEE8),
        "Posao" to Indigo,
        "Financije" to Color(0xFF00D8A1),
        "Društvene mreže" to Color(0xFFFF3A7A),
        "Kupovina" to Color(0xFFFFC026),
        "Putovanja" to Color(0xFF00B8FF),
        "Zdravlje" to Color(0xFF9C6CFF),
        "Ostalo" to Muted
    )
    var search by remember { mutableStateOf("") }
    var type by remember { mutableStateOf("Prijava") }
    var filterMenuExpanded by remember { mutableStateOf(false) }

    val collectionItems = model.items
        .filter { item ->
            when (type) {
                "Favoriti" -> item.favorite
                else -> item.type == type
            }
        }
        .filter { item ->
            if (search.isBlank()) true
            else listOf(
                item.title,
                item.username,
                item.website,
                item.notes,
                item.category,
                item.fields.values.joinToString(" ")
            ).joinToString(" ").contains(search, true)
        }

    val recentNotes = model.items
        .filter { it.type == "Bilješka" && (search.isBlank() || it.title.contains(search, true) || it.notes.contains(search, true)) }
        .sortedByDescending { it.updatedAt }
        .take(3)

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val narrow = maxWidth < 370.dp
        val side = if (narrow) 14.dp else 18.dp

        Column(Modifier.fillMaxSize()) {
            BrandHeader("MOJ TREZOR", securityIssueCount(model.items)) { model.open(Screen.SECURITY) }
            Text(
                "Kolekcije",
                Modifier.padding(horizontal = side),
                color = Color.White,
                fontSize = if (narrow) 34.sp else 42.sp,
                fontWeight = FontWeight.ExtraBold
            )
            Text(
                "Organizirajte podatke. Pronađite ih odmah.",
                Modifier.padding(horizontal = side),
                color = Muted,
                fontSize = if (narrow) 14.sp else 16.sp
            )
            Spacer(Modifier.height(if (narrow) 8.dp else 12.dp))

            OutlinedTextField(
                search,
                { search = it },
                modifier = Modifier.fillMaxWidth().padding(horizontal = side),
                placeholder = { Text("Pretražite trezor...") },
                leadingIcon = { Icon(Icons.Outlined.Search, null) },
                trailingIcon = {
                    Box {
                        IconButton(onClick = { filterMenuExpanded = true }) {
                            Icon(Icons.Outlined.Tune, contentDescription = "Filtriraj kolekcije", tint = Ice)
                        }
                        DropdownMenu(
                            expanded = filterMenuExpanded,
                            onDismissRequest = { filterMenuExpanded = false }
                        ) {
                            listOf("Prijava", "Bilješka", "Kartica", "Identitet", "Wi-Fi", "Favoriti").forEach { value ->
                                DropdownMenuItem(
                                    text = {
                                        Text(
                                            when (value) {
                                                "Prijava" -> "Lozinke"
                                                "Bilješka" -> "Bilješke"
                                                "Kartica" -> "Kartice"
                                                else -> value
                                            }
                                        )
                                    },
                                    onClick = {
                                        type = value
                                        filterMenuExpanded = false
                                    }
                                )
                            }
                            DropdownMenuItem(
                                text = { Text("Očisti pretragu") },
                                onClick = {
                                    search = ""
                                    filterMenuExpanded = false
                                }
                            )
                        }
                    }
                },
                colors = keyraFieldColors(),
                shape = RoundedCornerShape(24.dp),
                singleLine = true
            )

            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = side, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Favoriti").forEach { value ->
                    FilterChip(
                        selected = type == value,
                        onClick = { type = value },
                        label = {
                            Text(
                                when (value) {
                                    "Prijava" -> "Lozinke"
                                    "Bilješka" -> "Bilješke"
                                    "Kartica" -> "Kartice"
                                    else -> value
                                }
                            )
                        }
                    )
                }
            }

            LazyColumn(
                Modifier.fillMaxSize().padding(horizontal = side),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 18.dp)
            ) {
                items(categories.chunked(if (narrow) 1 else 2)) { group ->
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        group.forEach { (name, accent) ->
                            val count = collectionItems.count { it.category == name }
                            Surface(
                                Modifier
                                    .weight(1f)
                                    .height(if (narrow) 74.dp else 88.dp)
                                    .clickable { model.openCategory(name, type) },
                                shape = RoundedCornerShape(20.dp),
                                color = accent.copy(alpha=.13f),
                                border = androidx.compose.foundation.BorderStroke(1.dp, accent.copy(alpha=.8f))
                            ) {
                                Row(
                                    Modifier.padding(if (narrow) 12.dp else 15.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        Modifier
                                            .size(if (narrow) 40.dp else 44.dp)
                                            .clip(RoundedCornerShape(13.dp))
                                            .background(accent.copy(alpha=.18f)),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            when (name) {
                                                "Posao" -> Icons.Outlined.Work
                                                "Financije" -> Icons.Outlined.CreditCard
                                                "Društvene mreže" -> Icons.Outlined.Groups
                                                "Kupovina" -> Icons.Outlined.ShoppingCart
                                                "Putovanja" -> Icons.Outlined.Flight
                                                "Zdravlje" -> Icons.Outlined.Favorite
                                                "Ostalo" -> Icons.Outlined.GridView
                                                else -> Icons.Outlined.Person
                                            },
                                            null,
                                            tint = accent
                                        )
                                    }
                                    Spacer(Modifier.width(10.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(name, color = Color.White, fontWeight = FontWeight.Bold, fontSize = if (narrow) 15.sp else 16.sp, maxLines = 1)
                                        Text("$count stavki", color = Muted, fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                        if (!narrow && group.size == 1) Spacer(Modifier.weight(1f))
                    }
                }

                item {
                    Spacer(Modifier.height(6.dp))
                    Text("Nedavne bilješke", color = Color.White, fontSize = if (narrow) 22.sp else 25.sp, fontWeight = FontWeight.ExtraBold)
                    Text("Vaše najnovije bilješke i sigurne informacije.", color = Muted, fontSize = if (narrow) 13.sp else 14.sp)
                }

                items(recentNotes) { noteItem ->
                    Surface(
                        Modifier.fillMaxWidth().clickable { model.select(noteItem) },
                        shape = RoundedCornerShape(18.dp),
                        color = Slate
                    ) {
                        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Outlined.Description, null, tint = Indigo)
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(noteItem.title, color = Color.White, fontWeight = FontWeight.Bold, maxLines = 1)
                                Text(noteItem.notes, color = Muted, maxLines = 1)
                            }
                            Icon(Icons.Outlined.MoreVert, null, tint = Muted)
                        }
                    }
                }

                if (recentNotes.isEmpty()) {
                    item { Text("Još nema sigurnih bilješki.", color = Muted, modifier = Modifier.padding(vertical = 18.dp)) }
                }
            }
        }
    }
}

@Composable
private fun GeneratorScreen(model: KeyraViewModel) {
    val context = LocalContext.current
    var length by remember { mutableFloatStateOf(16f) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var numbers by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var password by remember { mutableStateOf(generatePassword(16, true, true, true, true)) }
    var preset by remember { mutableStateOf("Snažna") }

    fun refresh() {
        password = generatePassword(length.toInt(), upper, lower, numbers, symbols)
    }

    fun updateCharacterSet(current: Boolean, enabled: Boolean, apply: (Boolean) -> Unit) {
        val activeCount = listOf(upper, lower, numbers, symbols).count { it }
        if (current && !enabled && activeCount <= 1) {
            model.message = "Generator mora koristiti barem jednu vrstu znakova."
            return
        }
        apply(enabled)
        preset = "Prilagodi"
        refresh()
    }

    fun applyPreset(name: String) {
        preset = name
        when (name) {
            "Jednostavna" -> {
                length = 12f; upper = true; lower = true; numbers = true; symbols = false
            }
            "Maksimalna" -> {
                length = 32f; upper = true; lower = true; numbers = true; symbols = true
            }
            else -> {
                length = 16f; upper = true; lower = true; numbers = true; symbols = true
            }
        }
        refresh()
    }

    val poolSize = (if (upper) 26 else 0) +
        (if (lower) 26 else 0) +
        (if (numbers) 10 else 0) +
        (if (symbols) 15 else 0)
    val entropyBits = if (poolSize > 1) {
        (length * (kotlin.math.ln(poolSize.toDouble()) / kotlin.math.ln(2.0))).toInt()
    } else 0
    val strengthProgress = (entropyBits / 128f).coerceIn(0.08f, 1f)
    val strengthLabel = when {
        entropyBits >= 100 -> "Vrlo snažna"
        entropyBits >= 75 -> "Snažna"
        entropyBits >= 50 -> "Srednja"
        else -> "Slaba"
    }
    val strengthColor = when {
        entropyBits >= 75 -> Good
        entropyBits >= 50 -> Warn
        else -> Danger
    }

    Column(Modifier.fillMaxSize()) {
        BrandHeader("Generator lozinki", securityIssueCount(model.items)) { model.open(Screen.SECURITY) }
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(bottom = 20.dp)
        ) {
            item {
                GlassCard {
                    Text("Generirajte sigurnu lozinku", color = Color.White, fontSize = 25.sp, fontWeight = FontWeight.ExtraBold)
                    Text("Izradite snažne, jedinstvene lozinke u nekoliko sekundi.", color = Muted)
                    Spacer(Modifier.height(18.dp))
                    Text(
                        password,
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 3
                    )
                    Spacer(Modifier.height(12.dp))
                    LinearProgressIndicator(
                        progress = { strengthProgress },
                        modifier = Modifier.fillMaxWidth(),
                        color = strengthColor,
                        trackColor = Color(0xFF164C53)
                    )
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(strengthLabel, color = strengthColor, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        Text("~" + entropyBits + " bita entropije", color = Muted, fontSize = 12.sp)
                    }
                }
            }
            item {
                GlassCard {
                    Text("Zadana jačina", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Row(
                        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf("Jednostavna", "Snažna", "Maksimalna", "Prilagodi").forEach { name ->
                            FilterChip(
                                selected = preset == name,
                                onClick = {
                                    if (name == "Prilagodi") preset = name else applyPreset(name)
                                },
                                label = { Text(name) }
                            )
                        }
                    }
                }
            }
            item {
                GlassCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Duljina lozinke", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        Text(length.toInt().toString(), color = Cyan, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    Slider(
                        value = length,
                        onValueChange = {
                            length = it
                            preset = "Prilagodi"
                            refresh()
                        },
                        valueRange = 8f..64f,
                        steps = 55
                    )
                }
            }
            item {
                GlassCard {
                    Text("Vrste znakova", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    GeneratorToggle("Velika slova (A–Z)", upper) {
                        updateCharacterSet(upper, it) { value -> upper = value }
                    }
                    GeneratorToggle("Mala slova (a–z)", lower) {
                        updateCharacterSet(lower, it) { value -> lower = value }
                    }
                    GeneratorToggle("Brojevi (0–9)", numbers) {
                        updateCharacterSet(numbers, it) { value -> numbers = value }
                    }
                    GeneratorToggle("Simboli (!@#...)", symbols) {
                        updateCharacterSet(symbols, it) { value -> symbols = value }
                    }
                }
            }
            item {
                BoxWithConstraints(Modifier.fillMaxWidth()) {
                    if (maxWidth < 390.dp) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { refresh() },
                                modifier = Modifier.fillMaxWidth().height(54.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                                shape = RoundedCornerShape(27.dp)
                            ) {
                                Icon(Icons.Outlined.Refresh, null)
                                Spacer(Modifier.width(7.dp))
                                Text("Generiraj novu", fontWeight = FontWeight.Bold)
                            }
                            OutlinedButton(
                                onClick = {
                                    copy(context, password)
                                    model.message = "Lozinka je kopirana i automatski će se ukloniti iz međuspremnika."
                                },
                                modifier = Modifier.fillMaxWidth().height(54.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha=.7f)),
                                shape = RoundedCornerShape(27.dp)
                            ) {
                                Icon(Icons.Outlined.ContentCopy, null, tint = Ice)
                                Spacer(Modifier.width(7.dp))
                                Text("Kopiraj lozinku", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedButton(
                                onClick = {
                                    copy(context, password)
                                    model.message = "Lozinka je kopirana i automatski će se ukloniti iz međuspremnika."
                                },
                                modifier = Modifier.weight(1f).height(56.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha=.7f)),
                                shape = RoundedCornerShape(28.dp)
                            ) {
                                Icon(Icons.Outlined.ContentCopy, null, tint = Ice)
                                Spacer(Modifier.width(7.dp))
                                Text("Kopiraj lozinku", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                            Button(
                                onClick = { refresh() },
                                modifier = Modifier.weight(1f).height(56.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                                shape = RoundedCornerShape(28.dp)
                            ) {
                                Icon(Icons.Outlined.Refresh, null)
                                Spacer(Modifier.width(7.dp))
                                Text("Generiraj novu", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

internal data class TotpConfig(
    val secret: String,
    val issuer: String = "",
    val account: String = "",
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30
)

private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

internal fun normalizeBase32Secret(raw: String): String? {
    val clean = raw
        .trim()
        .replace(" ", "")
        .replace("-", "")
        .trimEnd('=')
        .uppercase()

    if (clean.isBlank() || clean.any { it !in BASE32_ALPHABET }) return null
    return if (decodeBase32(clean)?.isNotEmpty() == true) clean else null
}

internal fun decodeBase32(raw: String): ByteArray? {
    val clean = raw.trim().trimEnd('=').uppercase()
    if (clean.isBlank()) return null

    val output = ArrayList<Byte>()
    var buffer = 0
    var bits = 0

    for (char in clean) {
        val value = BASE32_ALPHABET.indexOf(char)
        if (value < 0) return null

        buffer = (buffer shl 5) or value
        bits += 5

        while (bits >= 8) {
            bits -= 8
            output.add(((buffer shr bits) and 0xFF).toByte())
            buffer = if (bits == 0) 0 else buffer and ((1 shl bits) - 1)
        }
    }

    return output.toByteArray()
}

private fun normalizeTotpAlgorithm(raw: String): String? = when (
    raw.trim().uppercase().replace("-", "")
) {
    "SHA1" -> "SHA1"
    "SHA256" -> "SHA256"
    "SHA512" -> "SHA512"
    else -> null
}

private fun decodeUrlPart(value: String): String =
    runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }
        .getOrDefault(value)

internal fun parseTotpInput(
    raw: String,
    fallbackIssuer: String = "",
    fallbackAccount: String = "",
    fallbackAlgorithm: String = "SHA1",
    fallbackDigits: Int = 6,
    fallbackPeriod: Int = 30
): TotpConfig? {
    val input = raw.trim()
    if (input.isBlank()) return null

    if (!input.startsWith("otpauth://", ignoreCase = true)) {
        val secret = normalizeBase32Secret(input) ?: return null
        val algorithm = normalizeTotpAlgorithm(fallbackAlgorithm) ?: "SHA1"
        val digits = fallbackDigits.takeIf { it in 6..8 } ?: 6
        val period = fallbackPeriod.takeIf { it in 15..120 } ?: 30
        return TotpConfig(
            secret = secret,
            issuer = fallbackIssuer.trim(),
            account = fallbackAccount.trim(),
            algorithm = algorithm,
            digits = digits,
            period = period
        )
    }

    val uri = runCatching { URI(input) }.getOrNull() ?: return null
    if (!uri.scheme.equals("otpauth", ignoreCase = true)) return null
    if (!uri.host.equals("totp", ignoreCase = true)) return null

    val params = uri.rawQuery
        ?.split("&")
        ?.mapNotNull { entry ->
            val pair = entry.split("=", limit = 2)
            if (pair.isEmpty()) null
            else decodeUrlPart(pair[0]).lowercase() to decodeUrlPart(pair.getOrElse(1) { "" })
        }
        ?.toMap()
        .orEmpty()

    val secret = normalizeBase32Secret(params["secret"].orEmpty()) ?: return null
    val label = decodeUrlPart(uri.rawPath.orEmpty().trimStart('/'))
    val labelParts = label.split(":", limit = 2)
    val labelIssuer = if (labelParts.size == 2) labelParts[0].trim() else ""
    val labelAccount = if (labelParts.size == 2) labelParts[1].trim() else label.trim()

    val issuer = params["issuer"].orEmpty().trim().ifBlank {
        fallbackIssuer.trim().ifBlank { labelIssuer }
    }
    val account = fallbackAccount.trim().ifBlank { labelAccount }
    val algorithm = normalizeTotpAlgorithm(params["algorithm"] ?: fallbackAlgorithm) ?: return null
    val digits = (params["digits"]?.toIntOrNull() ?: fallbackDigits).takeIf { it in 6..8 } ?: return null
    val period = (params["period"]?.toIntOrNull() ?: fallbackPeriod).takeIf { it in 15..120 } ?: return null

    return TotpConfig(
        secret = secret,
        issuer = issuer,
        account = account,
        algorithm = algorithm,
        digits = digits,
        period = period
    )
}

internal fun generateTotp(
    config: TotpConfig,
    timeMillis: Long = System.currentTimeMillis()
): String? {
    val secretBytes = decodeBase32(config.secret) ?: return null
    if (secretBytes.isEmpty()) return null

    val counter = (timeMillis / 1000L) / config.period
    val counterBytes = ByteArray(8)
    for (index in 0 until 8) {
        counterBytes[7 - index] = ((counter ushr (index * 8)) and 0xFF).toByte()
    }

    val macName = when (config.algorithm) {
        "SHA256" -> "HmacSHA256"
        "SHA512" -> "HmacSHA512"
        else -> "HmacSHA1"
    }
    val hash = runCatching {
        val mac = Mac.getInstance(macName)
        mac.init(SecretKeySpec(secretBytes, macName))
        mac.doFinal(counterBytes)
    }.getOrNull() ?: return null

    val offset = hash.last().toInt() and 0x0F
    if (offset + 3 >= hash.size) return null

    val binary =
        ((hash[offset].toInt() and 0x7F) shl 24) or
        ((hash[offset + 1].toInt() and 0xFF) shl 16) or
        ((hash[offset + 2].toInt() and 0xFF) shl 8) or
        (hash[offset + 3].toInt() and 0xFF)

    var modulo = 1
    repeat(config.digits) { modulo *= 10 }
    return (binary % modulo).toString().padStart(config.digits, '0')
}

internal fun totpRemainingSeconds(
    config: TotpConfig,
    timeMillis: Long = System.currentTimeMillis()
): Int {
    val elapsed = ((timeMillis / 1000L) % config.period).toInt()
    return config.period - elapsed
}

internal fun totpConfigFromFields(fields: Map<String, String>): TotpConfig? {
    val secret = fields["TOTP tajna"] ?: return null
    return parseTotpInput(
        raw = secret,
        fallbackIssuer = fields["Izdavatelj"].orEmpty(),
        fallbackAccount = fields["Račun"].orEmpty(),
        fallbackAlgorithm = fields["Algoritam"].orEmpty().ifBlank { "SHA1" },
        fallbackDigits = fields["Znamenke"]?.toIntOrNull() ?: 6,
        fallbackPeriod = fields["Period"]?.toIntOrNull() ?: 30
    )
}

internal fun formatTotpCode(code: String): String = when {
    code.length == 6 -> code.chunked(3).joinToString(" ")
    code.length == 8 -> code.chunked(4).joinToString(" ")
    else -> code
}

internal fun isValidCardNumber(raw: String): Boolean {
    val digits = raw.filter(Char::isDigit)
    if (digits.length !in 12..19) return false
    if (digits.toSet().size < 2) return false

    var sum = 0
    var doubleDigit = false
    for (index in digits.indices.reversed()) {
        var value = digits[index].digitToInt()
        if (doubleDigit) {
            value *= 2
            if (value > 9) value -= 9
        }
        sum += value
        doubleDigit = !doubleDigit
    }
    return sum % 10 == 0
}

internal fun isCardExpiryNotPast(
    raw: String,
    currentYear: Int,
    currentMonth: Int
): Boolean {
    val match = Regex("^(0[1-9]|1[0-2])/(\\d{2}|\\d{4})$").matchEntire(raw.trim())
        ?: return false
    val month = match.groupValues[1].toInt()
    val yearPart = match.groupValues[2].toInt()
    val year = if (match.groupValues[2].length == 2) {
        2000 + yearPart
    } else {
        yearPart
    }
    return year > currentYear || (year == currentYear && month >= currentMonth)
}

internal fun formatCardExpiry(raw: String): String {
    val digits = raw.filter(Char::isDigit).take(6)
    return when {
        digits.length <= 2 -> digits
        else -> digits.take(2) + "/" + digits.drop(2)
    }
}

internal fun generatePassword(length: Int, upper: Boolean, lower: Boolean, numbers: Boolean, symbols: Boolean): String {
    val sets = buildList {
        if (upper) add("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if (lower) add("abcdefghijklmnopqrstuvwxyz")
        if (numbers) add("0123456789")
        if (symbols) add("!@#$%&*+-_=.?")
    }.ifEmpty { listOf("abcdefghijklmnopqrstuvwxyz") }

    val random = SecureRandom()
    val required = sets.map { it[random.nextInt(it.length)] }.toMutableList()
    val pool = sets.joinToString("")
    while (required.size < length) {
        required.add(pool[random.nextInt(pool.length)])
    }
    for (i in required.lastIndex downTo 1) {
        val j = random.nextInt(i + 1)
        val tmp = required[i]
        required[i] = required[j]
        required[j] = tmp
    }
    return required.take(length).joinToString("")
}

@Composable
private fun GeneratorToggle(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Color.White, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun AddScreen(model: KeyraViewModel) {
    val original = model.selected
    var title by remember(original?.id) { mutableStateOf(original?.title.orEmpty()) }
    var website by remember(original?.id) { mutableStateOf(original?.website.orEmpty()) }
    var username by remember(original?.id) { mutableStateOf(original?.username.orEmpty()) }
    var password by remember(original?.id) { mutableStateOf(original?.password.orEmpty()) }
    var notes by remember(original?.id) { mutableStateOf(original?.notes.orEmpty()) }
    var category by remember(original?.id) { mutableStateOf(original?.category ?: "Osobno") }
    var favorite by remember(original?.id) { mutableStateOf(original?.favorite ?: false) }
    var type by remember(original?.id) { mutableStateOf(original?.type ?: "Prijava") }
    var show by remember { mutableStateOf(false) }
    var field1 by remember(original?.id) {
        mutableStateOf(
            when (original?.type) {
                "Kartica" -> original.fields["Vlasnik kartice"].orEmpty()
                "Identitet" -> original.fields["Puno ime"].orEmpty()
                "Wi-Fi" -> original.fields["Naziv mreže"].orEmpty()
                "Autentifikator" -> original.fields["Izdavatelj"].orEmpty()
                else -> ""
            }
        )
    }
    var field2 by remember(original?.id) {
        mutableStateOf(
            when (original?.type) {
                "Kartica" -> original.fields["Broj kartice"].orEmpty()
                "Identitet" -> original.fields["Broj dokumenta"].orEmpty()
                "Wi-Fi" -> original.fields["Vrsta zaštite"].orEmpty()
                "Autentifikator" -> original.fields["Račun"].orEmpty()
                else -> ""
            }
        )
    }
    var field3 by remember(original?.id) {
        mutableStateOf(
            when (original?.type) {
                "Kartica" -> original.fields["Vrijedi do"].orEmpty()
                "Identitet" -> original.fields["Datum isteka"].orEmpty()
                "Autentifikator" -> original.fields["TOTP tajna"].orEmpty()
                else -> ""
            }
        )
    }
    var field4 by remember(original?.id) {
        mutableStateOf(if (original?.type == "Kartica") original.fields["Sigurnosni kod"].orEmpty() else "")
    }
    var totpAlgorithm by remember(original?.id) {
        mutableStateOf(original?.fields?.get("Algoritam").orEmpty().ifBlank { "SHA1" })
    }
    var totpDigits by remember(original?.id) {
        mutableIntStateOf(original?.fields?.get("Znamenke")?.toIntOrNull() ?: 6)
    }
    var totpPeriod by remember(original?.id) {
        mutableIntStateOf(original?.fields?.get("Period")?.toIntOrNull() ?: 30)
    }
    val totpPreview = remember(type, field1, field2, field3, totpAlgorithm, totpDigits, totpPeriod) {
        if (type == "Autentifikator") {
            parseTotpInput(
                raw = field3,
                fallbackIssuer = field1,
                fallbackAccount = field2,
                fallbackAlgorithm = totpAlgorithm,
                fallbackDigits = totpDigits,
                fallbackPeriod = totpPeriod
            )
        } else {
            null
        }
    }

    val itemLabel = when (type) {
        "Bilješka" -> "bilješku"
        "Kartica" -> "karticu"
        "Identitet" -> "identitet"
        "Wi-Fi" -> "Wi-Fi"
        "Autentifikator" -> "autentifikator"
        else -> "prijavu"
    }
    val screenTitle = if (original == null) "Dodaj $itemLabel" else "Uredi $itemLabel"
    val screenSubtitle = when (type) {
        "Bilješka" -> "Sigurno spremite privatne bilješke i osjetljive informacije"
        "Kartica" -> "Zaštitite podatke kartice i držite ih na jednom mjestu"
        "Identitet" -> "Sigurno spremite podatke identiteta i dokumenata"
        "Wi-Fi" -> "Spremite naziv mreže, zaštitu i pristupne podatke"
        "Autentifikator" -> "Generirajte vremenski 2FA kod koji se automatski mijenja"
        else -> "Sigurno spremite svoje vjerodajnice"
    }
    val saveLabel = when (type) {
        "Bilješka" -> "Spremi bilješku"
        "Kartica" -> "Spremi karticu"
        "Identitet" -> "Spremi identitet"
        "Wi-Fi" -> "Spremi Wi-Fi"
        "Autentifikator" -> "Spremi autentifikator"
        else -> "Spremi prijavu"
    }

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val compact = maxWidth < 360.dp

        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.fillMaxHeight().widthIn(max = 760.dp)) {
        Row(Modifier.fillMaxWidth().padding(if (compact) 8.dp else 12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { model.open(if (original == null) Screen.VAULT else Screen.DETAIL) }) {
                Icon(Icons.Outlined.ArrowBack, null, tint = Color.White)
            }
            KeyraMark(38.dp)
            Spacer(Modifier.width(10.dp))
            Text("Keyra", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        }

        LazyColumn(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp)
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 26.dp)
        ) {
            item {
                Text(
                    screenTitle,
                    color = Color.White,
                    fontSize = if (compact) 32.sp else 38.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(screenSubtitle, color = Muted)
            }

            item {
                Text("Vrsta stavke", color = Ice, fontSize = 12.sp, letterSpacing = 2.sp)
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    listOf("Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Autentifikator").forEach { value ->
                        FilterChip(
                            selected = type == value,
                            onClick = {
                                if (original == null) {
                                    type = value
                                    field1 = ""; field2 = ""; field3 = ""; field4 = ""
                                    totpAlgorithm = "SHA1"; totpDigits = 6; totpPeriod = 30
                                }
                            },
                            enabled = original == null || type == value,
                            label = { Text(value) },
                            leadingIcon = {
                                Icon(
                                    when (value) {
                                        "Bilješka" -> Icons.Outlined.Description
                                        "Kartica" -> Icons.Outlined.CreditCard
                                        "Identitet" -> Icons.Outlined.Badge
                                        "Wi-Fi" -> Icons.Outlined.Wifi
                                        "Autentifikator" -> Icons.Outlined.Security
                                        else -> Icons.Outlined.Lock
                                    },
                                    null,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        )
                    }
                }
            }

            item { KeyraTextField(title, { title = it }, "Naslov", Icons.Outlined.Title) }

            if (type == "Prijava") {
                item { KeyraTextField(website, { website = it }, "Web-stranica", Icons.Outlined.Link) }
                item { KeyraTextField(username, { username = it }, "Korisničko ime / e-pošta", Icons.Outlined.Person) }
                item {
                    KeyraPasswordField(password, { password = it }, show, { show = !show }, "Lozinka")
                    TextButton(onClick = { password = generatePassword(18, true, true, true, true) }) {
                        Icon(Icons.Outlined.Refresh, null); Spacer(Modifier.width(5.dp)); Text("Generiraj")
                    }
                }
            }

            if (type == "Wi-Fi") {
                item { KeyraTextField(field1, { field1 = it }, "Naziv mreže", Icons.Outlined.Wifi) }
                item { KeyraTextField(username, { username = it }, "Korisničko ime (nije obavezno)", Icons.Outlined.Person) }
                item {
                    KeyraPasswordField(password, { password = it }, show, { show = !show }, "Lozinka mreže")
                    TextButton(onClick = { password = generatePassword(20, true, true, true, true) }) {
                        Icon(Icons.Outlined.Refresh, null); Spacer(Modifier.width(5.dp)); Text("Generiraj")
                    }
                }
                item { KeyraTextField(field2, { field2 = it }, "Vrsta zaštite, npr. WPA3", Icons.Outlined.Security) }
            }

            if (type == "Kartica") {
                item { KeyraTextField(field1, { field1 = it }, "Vlasnik kartice", Icons.Outlined.Person) }
                item { KeyraTextField(field2, { field2 = it.filter(Char::isDigit).take(19) }, "Broj kartice", Icons.Outlined.CreditCard) }
                item { KeyraTextField(field3, { field3 = formatCardExpiry(it) }, "Vrijedi do (MM/GG)", Icons.Outlined.DateRange) }
                item { KeyraTextField(field4, { field4 = it.filter(Char::isDigit).take(4) }, "Sigurnosni kod", Icons.Outlined.Lock) }
            }

            if (type == "Identitet") {
                item { KeyraTextField(field1, { field1 = it }, "Puno ime", Icons.Outlined.Person) }
                item { KeyraTextField(field2, { field2 = it }, "Broj dokumenta", Icons.Outlined.Badge) }
                item { KeyraTextField(field3, { field3 = it }, "Datum isteka", Icons.Outlined.DateRange) }
            }

            if (type == "Autentifikator") {
                item { KeyraTextField(field1, { field1 = it }, "Izdavatelj / servis", Icons.Outlined.Security) }
                item { KeyraTextField(field2, { field2 = it }, "Račun / e-pošta", Icons.Outlined.Person) }
                item {
                    KeyraPasswordField(
                        field3,
                        { field3 = it },
                        show,
                        { show = !show },
                        "TOTP tajna ili otpauth:// URI"
                    )
                    val parsed = totpPreview
                    if (parsed != null) {
                        Text(
                            "TOTP • ${parsed.algorithm} • ${parsed.digits} znamenki • ${parsed.period} s",
                            color = Good,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    } else if (field3.isNotBlank()) {
                        Text(
                            "Tajna mora biti Base32 ili valjani otpauth://totp URI.",
                            color = Warn,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                    if (field3.trim().startsWith("otpauth://", ignoreCase = true) && parsed != null) {
                        TextButton(
                            onClick = {
                                field1 = parsed.issuer
                                field2 = parsed.account
                                field3 = parsed.secret
                                totpAlgorithm = parsed.algorithm
                                totpDigits = parsed.digits
                                totpPeriod = parsed.period
                                model.message = "Podaci autentifikatora učitani su iz otpauth URI-ja."
                            }
                        ) {
                            Icon(Icons.Outlined.Download, contentDescription = null)
                            Spacer(Modifier.width(5.dp))
                            Text("Učitaj podatke iz URI-ja")
                        }
                    }
                    Text(
                        "Kompatibilno s RFC 6238 TOTP aplikacijama. Kod se obnavlja prema vremenu uređaja.",
                        color = Muted,
                        fontSize = 12.sp
                    )
                }
            }

            item {
                KeyraTextField(notes, { notes = it.take(500) }, "Bilješke (nije obavezno)", Icons.Outlined.Description, singleLine = false)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    Text(notes.length.toString() + "/500", color = Muted, fontSize = 11.sp)
                }
            }

            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.StarBorder, null, tint = Ice)
                    Spacer(Modifier.width(8.dp))
                    Text("Dodaj u favorite", color = Color.White, modifier = Modifier.weight(1f))
                    Switch(favorite, { favorite = it })
                }
            }

            item {
                Text("Mapa / kategorija", color = Ice, fontSize = 12.sp, letterSpacing = 2.sp)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("Osobno","Posao","Financije","Društvene mreže","Kupovina","Putovanja","Zdravlje","Ostalo").forEach {
                        FilterChip(selected = category == it, onClick = { category = it }, label = { Text(it) })
                    }
                }
            }

            item {
                Button(
                    onClick = {
                        val cleanTitle = title.trim()
                        val now = Calendar.getInstance()
                        val currentYear = now.get(Calendar.YEAR)
                        val currentMonth = now.get(Calendar.MONTH) + 1
                        val validationMessage = when {
                            cleanTitle.isBlank() -> "Unesite naslov stavke."
                            type == "Prijava" && website.isNotBlank() && normalizedWebsiteUri(website) == null ->
                                "Web-adresa nije valjana. Unesite ispravnu HTTP ili HTTPS adresu."
                            type == "Wi-Fi" && field1.isBlank() ->
                                "Unesite naziv Wi-Fi mreže."
                            type == "Kartica" && field2.isNotBlank() && field2.length !in 12..19 ->
                                "Broj kartice mora sadržavati između 12 i 19 znamenki."
                            type == "Kartica" && field2.isNotBlank() && !isValidCardNumber(field2) ->
                                "Broj kartice nije prošao provjeru kontrolne znamenke."
                            type == "Kartica" && field4.isNotBlank() && field4.length !in 3..4 ->
                                "Sigurnosni kod mora sadržavati 3 ili 4 znamenke."
                            type == "Kartica" && field3.isNotBlank() && !Regex("^(0[1-9]|1[0-2])/(\\d{2}|\\d{4})$").matches(field3.trim()) ->
                                "Datum isteka kartice unesite u obliku MM/GG ili MM/GGGG."
                            type == "Kartica" && field3.isNotBlank() && !isCardExpiryNotPast(field3, currentYear, currentMonth) ->
                                "Datum isteka kartice je u prošlosti."
                            type == "Identitet" && field1.isBlank() && field2.isBlank() ->
                                "Unesite puno ime ili broj dokumenta."
                            type == "Autentifikator" && totpPreview == null ->
                                "Unesite valjanu Base32 TOTP tajnu ili otpauth:// URI."
                            else -> null
                        }
                        if (validationMessage != null) {
                            model.message = validationMessage
                        } else {
                            val extra = when (type) {
                                "Kartica" -> mapOf(
                                    "Vlasnik kartice" to field1,
                                    "Broj kartice" to field2,
                                    "Vrijedi do" to field3,
                                    "Sigurnosni kod" to field4
                                ).filterValues { it.isNotBlank() }
                                "Identitet" -> mapOf(
                                    "Puno ime" to field1,
                                    "Broj dokumenta" to field2,
                                    "Datum isteka" to field3
                                ).filterValues { it.isNotBlank() }
                                "Wi-Fi" -> mapOf(
                                    "Naziv mreže" to field1,
                                    "Vrsta zaštite" to field2
                                ).filterValues { it.isNotBlank() }
                                "Autentifikator" -> {
                                    val config = requireNotNull(totpPreview)
                                    mapOf(
                                        "Izdavatelj" to config.issuer,
                                        "Račun" to config.account,
                                        "TOTP tajna" to config.secret,
                                        "Algoritam" to config.algorithm,
                                        "Znamenke" to config.digits.toString(),
                                        "Period" to config.period.toString()
                                    ).filterValues { it.isNotBlank() }
                                }
                                else -> emptyMap()
                            }

                            model.saveItem(
                                VaultItem(
                                    id = original?.id ?: UUID.randomUUID().toString(),
                                    title = cleanTitle,
                                    website = if (type == "Prijava") website.trim() else "",
                                    username = if (type == "Prijava" || type == "Wi-Fi") username.trim() else "",
                                    password = if (type == "Prijava" || type == "Wi-Fi") password else "",
                                    notes = notes.trim(),
                                    category = category,
                                    favorite = favorite,
                                    type = type,
                                    fields = extra
                                )
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(58.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                    shape = RoundedCornerShape(29.dp)
                ) {
                    Icon(Icons.Outlined.Lock, null)
                    Spacer(Modifier.width(8.dp))
                    Text(saveLabel, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                }
            }
        }
        }
        }
    }
}

@Composable
private fun KeyraTextField(value: String, onValue: (String) -> Unit, label: String, icon: ImageVector, singleLine: Boolean = true) {
    OutlinedTextField(
        value = value,
        onValueChange = onValue,
        modifier = Modifier.fillMaxWidth(),
        label = { Text(label) },
        leadingIcon = { Icon(icon, null) },
        singleLine = singleLine,
        minLines = if (singleLine) 1 else 3,
        colors = keyraFieldColors(),
        shape = RoundedCornerShape(18.dp)
    )
}

@Composable
private fun DetailScreen(
    model: KeyraViewModel,
    requestBiometric: (String, () -> Unit) -> Unit
) {
    val current = model.selected ?: return
    var reveal by remember(current.id) { mutableStateOf(false) }
    var revealCardNumber by remember(current.id) { mutableStateOf(false) }
    var revealSecurityCode by remember(current.id) { mutableStateOf(false) }
    var revealDocumentNumber by remember(current.id) { mutableStateOf(false) }
    var confirmDelete by remember(current.id) { mutableStateOf(false) }
    var selectedTab by remember(current.id) { mutableStateOf("Detalji") }
    val context = LocalContext.current
    val isPasswordItem = current.type == "Prijava" || current.type == "Wi-Fi"
    val duplicatedPassword = isPasswordItem &&
        current.password.isNotBlank() &&
        model.items.any { it.id != current.id && it.password == current.password }
    val securityLabel = when {
        isPasswordItem && current.password.isBlank() -> "Bez lozinke"
        duplicatedPassword -> "Ponovno korištena"
        isPasswordItem && isStrongPassword(current.password) -> "Snažna"
        isPasswordItem -> "Potrebno ažuriranje"
        else -> "Zaštićena"
    }
    val securityColor = when (securityLabel) {
        "Snažna", "Zaštićena" -> Good
        "Ponovno korištena" -> Danger
        "Potrebno ažuriranje" -> Warn
        else -> Muted
    }
    val updatedLabel = remember(current.updatedAt) {
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(current.updatedAt))
    }

    fun guarded(reason: String, action: () -> Unit) {
        if (model.sensitiveReauthEnabled && model.biometricEnabled) {
            requestBiometric(reason, action)
        } else {
            action()
        }
    }

    val titleIcon = when (current.type) {
        "Bilješka" -> Icons.Outlined.Description
        "Kartica" -> Icons.Outlined.CreditCard
        "Identitet" -> Icons.Outlined.Badge
        "Wi-Fi" -> Icons.Outlined.Wifi
        else -> Icons.Outlined.Lock
    }

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val compact = maxWidth < 360.dp

        if (confirmDelete) {
            AlertDialog(
                onDismissRequest = { confirmDelete = false },
                icon = { Icon(Icons.Outlined.Delete, contentDescription = null, tint = Danger) },
                title = { Text("Izbrisati stavku?") },
                text = { Text("Ova radnja ne može se poništiti.") },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmDelete = false
                            guarded("Potvrdite identitet za brisanje stavke.") {
                                model.deleteSelected()
                            }
                        }
                    ) { Text("Izbriši", color = Danger) }
                },
                dismissButton = {
                    TextButton(onClick = { confirmDelete = false }) { Text("Odustani") }
                },
                containerColor = Slate
            )
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.fillMaxHeight().widthIn(max = 760.dp)) {
        Row(Modifier.fillMaxWidth().padding(if (compact) 8.dp else 12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { model.open(Screen.VAULT) }) {
                Icon(Icons.Outlined.ArrowBack, null, tint = Color.White)
            }
            Box(
                Modifier.size(54.dp).clip(RoundedCornerShape(16.dp)).background(Cyan.copy(alpha=.12f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(titleIcon, null, tint = Cyan)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(current.title, color = Color.White, fontSize = if (compact) 23.sp else 30.sp, fontWeight = FontWeight.ExtraBold, maxLines = 2)
                Text(current.type + " • " + current.category, color = Muted)
            }
            IconButton(onClick = model::toggleSelectedFavorite) {
                Icon(
                    if (current.favorite) Icons.Outlined.Star else Icons.Outlined.StarBorder,
                    contentDescription = if (current.favorite) "Ukloni iz favorita" else "Dodaj u favorite",
                    tint = if (current.favorite) Warn else Ice
                )
            }
        }

        DetailTabBar(
            selected = selectedTab,
            onSelected = { selectedTab = it },
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 4.dp)
        )

        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 28.dp)
        ) {
            if (selectedTab == "Detalji" && current.type == "Prijava") {
                if (current.website.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Link, "Web-stranica", current.website) {
                        if (!openWebsite(context, current.website)) {
                            model.message = "Web-stranicu nije moguće otvoriti. Provjerite adresu."
                        }
                    }
                }
                if (current.username.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Person, "Korisničko ime / e-pošta", current.username) {
                        guarded("Potvrdite identitet za kopiranje korisničkog imena.") {
                            copy(context, current.username)
                            model.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                        }
                    }
                }
            }

            if (selectedTab == "Detalji" && current.type == "Wi-Fi") {
                current.fields["Naziv mreže"]?.takeIf { it.isNotBlank() }?.let { network ->
                    item { DetailRow(Icons.Outlined.Wifi, "Naziv mreže", network) }
                }
                if (current.username.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Person, "Korisničko ime", current.username) {
                        guarded("Potvrdite identitet za kopiranje korisničkog imena.") {
                            copy(context, current.username)
                            model.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                        }
                    }
                }
                current.fields["Vrsta zaštite"]?.takeIf { it.isNotBlank() }?.let { security ->
                    item { DetailRow(Icons.Outlined.Security, "Vrsta zaštite", security) }
                }
            }

            if (selectedTab == "Detalji" && (current.type == "Prijava" || current.type == "Wi-Fi") && current.password.isNotBlank()) item {
                PasswordDetailRow(
                    password = current.password,
                    reveal = reveal,
                    onReveal = {
                        if (reveal) reveal = false
                        else guarded("Potvrdite identitet za prikaz lozinke.") { reveal = true }
                    },
                    onCopy = {
                        guarded("Potvrdite identitet za kopiranje lozinke.") {
                            copy(context, current.password)
                            model.message = "Lozinka je kopirana i automatski će se ukloniti iz međuspremnika."
                        }
                    }
                )
            }

            if (selectedTab == "Detalji" && current.type == "Kartica") {
                current.fields["Vlasnik kartice"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.Person, "Vlasnik kartice", value) }
                }
                current.fields["Broj kartice"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item {
                        SensitiveDetailRow(
                            icon = Icons.Outlined.CreditCard,
                            label = "Broj kartice",
                            value = value,
                            reveal = revealCardNumber,
                            hidden = "•••• •••• •••• " + value.takeLast(4),
                            onReveal = {
                                if (revealCardNumber) revealCardNumber = false
                                else guarded("Potvrdite identitet za prikaz broja kartice.") { revealCardNumber = true }
                            },
                            onCopy = {
                                guarded("Potvrdite identitet za kopiranje broja kartice.") {
                                    copy(context, value)
                                    model.message = "Broj kartice kopiran je i automatski će se ukloniti."
                                }
                            }
                        )
                    }
                }
                current.fields["Vrijedi do"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.DateRange, "Vrijedi do", value) }
                }
                current.fields["Sigurnosni kod"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item {
                        SensitiveDetailRow(
                            icon = Icons.Outlined.Lock,
                            label = "Sigurnosni kod",
                            value = value,
                            reveal = revealSecurityCode,
                            hidden = "•••",
                            onReveal = {
                                if (revealSecurityCode) revealSecurityCode = false
                                else guarded("Potvrdite identitet za prikaz sigurnosnog koda.") { revealSecurityCode = true }
                            },
                            onCopy = {
                                guarded("Potvrdite identitet za kopiranje sigurnosnog koda.") {
                                    copy(context, value)
                                    model.message = "Sigurnosni kod kopiran je i automatski će se ukloniti."
                                }
                            }
                        )
                    }
                }
            }

            if (selectedTab == "Detalji" && current.type == "Identitet") {
                current.fields["Puno ime"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.Person, "Puno ime", value) }
                }
                current.fields["Broj dokumenta"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item {
                        SensitiveDetailRow(
                            icon = Icons.Outlined.Badge,
                            label = "Broj dokumenta",
                            value = value,
                            reveal = revealDocumentNumber,
                            hidden = "••••" + value.takeLast(4),
                            onReveal = {
                                if (revealDocumentNumber) revealDocumentNumber = false
                                else guarded("Potvrdite identitet za prikaz broja dokumenta.") { revealDocumentNumber = true }
                            },
                            onCopy = {
                                guarded("Potvrdite identitet za kopiranje broja dokumenta.") {
                                    copy(context, value)
                                    model.message = "Broj dokumenta kopiran je i automatski će se ukloniti."
                                }
                            }
                        )
                    }
                }
                current.fields["Datum isteka"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.DateRange, "Datum isteka", value) }
                }
            }

            if (selectedTab == "Detalji" && current.notes.isNotBlank()) item {
                DetailRow(Icons.Outlined.Description, "Bilješke", current.notes)
            }

            if (selectedTab == "Sigurnost") {
                item {
                    GlassCard {
                        Icon(Icons.Outlined.Security, contentDescription = null, tint = securityColor)
                        Text("Ocjena sigurnosti", color = Muted, fontSize = 13.sp)
                        Text(
                            securityLabel,
                            color = securityColor,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            when {
                                duplicatedPassword ->
                                    "Ova se lozinka koristi i na drugoj stavci. Preporučujemo jedinstvenu lozinku."
                                isPasswordItem && current.password.isBlank() ->
                                    "Ova stavka nema spremljenu lozinku."
                                isPasswordItem && !isStrongPassword(current.password) ->
                                    "Lozinka ne zadovoljava preporučenu kombinaciju duljine i vrsta znakova."
                                isPasswordItem ->
                                    "Lozinka je dovoljno duga i koristi dobru kombinaciju vrsta znakova."
                                else ->
                                    "Ova vrsta stavke nema lozinku za procjenu, ali je sadržaj zaštićen trezorom."
                            },
                            color = Muted
                        )
                    }
                }
                item {
                    DetailMetaCard(
                        icon = Icons.Outlined.Security,
                        label = "Zaštita stavke",
                        value = if (model.sensitiveReauthEnabled && model.biometricEnabled)
                            "Dodatna potvrda uključena"
                        else
                            "Zaštita trezora",
                        accent = Cyan,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                if (
                    isPasswordItem &&
                    (current.password.isBlank() || duplicatedPassword || !isStrongPassword(current.password))
                ) {
                    item {
                        Button(
                            onClick = model::editSelected,
                            modifier = Modifier.fillMaxWidth().height(54.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                            shape = RoundedCornerShape(27.dp)
                        ) {
                            Icon(Icons.Outlined.Edit, contentDescription = null)
                            Spacer(Modifier.width(7.dp))
                            Text("Uredi i promijeni lozinku", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            if (selectedTab == "Aktivnost") {
                item {
                    DetailMetaCard(
                        icon = Icons.Outlined.Schedule,
                        label = "Zadnja izmjena",
                        value = updatedLabel,
                        accent = Indigo,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                item {
                    GlassCard {
                        Icon(Icons.Outlined.Info, contentDescription = null, tint = Cyan)
                        Text("Aktivnost stavke", color = Color.White, fontWeight = FontWeight.Bold)
                        Text(
                            "Keyra čuva samo vrijeme posljednje izmjene ove stavke. Radi privatnosti ne zapisuje povijest otvaranja, prikaza ni kopiranja osjetljivih vrijednosti.",
                            color = Muted
                        )
                    }
                }
            }

            if (selectedTab == "Detalji") item {
                BoxWithConstraints(Modifier.fillMaxWidth()) {
                    if (maxWidth < 390.dp) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = model::editSelected,
                                modifier = Modifier.fillMaxWidth().height(52.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.65f)),
                                shape = RoundedCornerShape(26.dp)
                            ) {
                                Icon(Icons.Outlined.Edit, null)
                                Spacer(Modifier.width(6.dp))
                                Text("Uredi stavku")
                            }
                            OutlinedButton(
                                onClick = { confirmDelete = true },
                                modifier = Modifier.fillMaxWidth().height(52.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Danger.copy(alpha=.65f)),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger),
                                shape = RoundedCornerShape(26.dp)
                            ) {
                                Icon(Icons.Outlined.Delete, null)
                                Spacer(Modifier.width(6.dp))
                                Text("Izbriši")
                            }
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedButton(
                                onClick = model::editSelected,
                                modifier = Modifier.weight(1f),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.65f))
                            ) {
                                Icon(Icons.Outlined.Edit, null)
                                Spacer(Modifier.width(6.dp))
                                Text("Uredi stavku")
                            }
                            OutlinedButton(
                                onClick = { confirmDelete = true },
                                modifier = Modifier.weight(1f),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Danger.copy(alpha=.65f)),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger)
                            ) {
                                Icon(Icons.Outlined.Delete, null)
                                Spacer(Modifier.width(6.dp))
                                Text("Izbriši")
                            }
                        }
                    }
                }
            }
        }
        }
        }
    }
}

@Composable
private fun DetailTabBar(
    selected: String,
    onSelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(Slate),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        listOf("Detalji", "Sigurnost", "Aktivnost").forEach { label ->
            Surface(
                modifier = Modifier
                    .weight(1f)
                    .clickable { onSelected(label) },
                shape = RoundedCornerShape(16.dp),
                color = if (selected == label) Cyan.copy(alpha = .16f) else Color.Transparent,
                border = if (selected == label)
                    androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha = .8f))
                else
                    null
            ) {
                Text(
                    label,
                    color = if (selected == label) Cyan else Muted,
                    fontWeight = if (selected == label) FontWeight.Bold else FontWeight.Medium,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(vertical = 12.dp)
                )
            }
        }
    }
}

@Composable
private fun DetailMetaCard(
    icon: ImageVector,
    label: String,
    value: String,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier,
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, accent.copy(alpha = .45f))
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(44.dp).clip(RoundedCornerShape(13.dp)).background(accent.copy(alpha = .14f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = accent)
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(label, color = Muted, fontSize = 12.sp)
                Text(value, color = if (label == "Ocjena sigurnosti") accent else Color.White, fontWeight = FontWeight.Bold)
            }
        }
    }
}

@Composable
private fun SensitiveDetailRow(
    icon: ImageVector,
    label: String,
    value: String,
    reveal: Boolean,
    hidden: String,
    onReveal: () -> Unit,
    onCopy: () -> Unit
) {
    Surface(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF063A3A)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, null, tint = Cyan)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(label, color = Muted, fontSize = 13.sp)
                Text(if (reveal) value else hidden, color = Color.White, fontSize = 16.sp)
            }
            IconButton(onClick = onReveal) {
                Icon(if (reveal) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, null, tint = Ice)
            }
            IconButton(onClick = onCopy) {
                Icon(Icons.Outlined.ContentCopy, null, tint = Cyan)
            }
        }
    }
}

@Composable
private fun PasswordDetailRow(
    password: String,
    reveal: Boolean,
    onReveal: () -> Unit,
    onCopy: () -> Unit
) {
    Surface(
        Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF063A3A)),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Outlined.Lock, null, tint = Cyan)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text("Lozinka", color = Muted, fontSize = 13.sp)
                Text(if (reveal) password else "••••••••••••••", color = Color.White, fontSize = 16.sp)
            }
            IconButton(onClick = onReveal) {
                Icon(if (reveal) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility, null, tint = Ice)
            }
            IconButton(onClick = onCopy) {
                Icon(Icons.Outlined.ContentCopy, null, tint = Cyan)
            }
        }
    }
}

@Composable
private fun DetailRow(icon: ImageVector, label: String, value: String, action: (() -> Unit)? = null) {
    Surface(
        Modifier.fillMaxWidth().then(if (action != null) Modifier.clickable { action() } else Modifier),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF0B3551)), contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = Cyan)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(label, color = Muted, fontSize = 13.sp)
                Text(value, color = Color.White, fontSize = 16.sp)
            }
            if (action != null) Icon(Icons.Outlined.ChevronRight, null, tint = Ice)
        }
    }
}

@Composable
private fun SettingsScreen(
    model: KeyraViewModel,
    requestBiometric: (String, () -> Unit) -> Unit
) {
    val context = LocalContext.current
    var search by remember { mutableStateOf("") }
    var confirmImport by remember { mutableStateOf(false) }

    fun runProtectedImport() {
        if (model.sensitiveReauthEnabled && model.biometricEnabled) {
            requestBiometric("Potvrdite identitet za uvoz sigurnosne kopije.") {
                model.importBackup(context)
            }
        } else {
            model.importBackup(context)
        }
    }

    fun matches(vararg values: String): Boolean =
        search.isBlank() || values.any { it.contains(search, ignoreCase = true) }

    val accountVisible = matches(
        "Biometrijsko otključavanje",
        "Potvrda prije prikaza tajni",
        "Automatsko zaključavanje",
        "Provjera sigurnosti"
    )
    val dataVisible = matches("Kopiraj sigurnosnu kopiju", "Uvezi sigurnosnu kopiju", "sigurnosna kopija")
    val preferenceVisible = matches("Tamni način", "tamni izgled")
    val privacyVisible = matches("O aplikaciji Keyra", "Zaključaj trezor", "sigurnost privatnost")

    Column(Modifier.fillMaxSize()) {
        if (confirmImport) {
            AlertDialog(
                onDismissRequest = { confirmImport = false },
                icon = {
                    Icon(
                        Icons.Outlined.Warning,
                        contentDescription = null,
                        tint = Warn
                    )
                },
                title = { Text("Uvesti sigurnosnu kopiju?") },
                text = {
                    Text(
                        "Trenutni sadržaj trezora bit će zamijenjen sadržajem iz sigurnosne kopije. " +
                            "Prije nastavka provjerite da je kopija ispravna."
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmImport = false
                            runProtectedImport()
                        }
                    ) {
                        Text("Uvezi i zamijeni", color = Warn)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { confirmImport = false }) {
                        Text("Odustani")
                    }
                },
                containerColor = Slate
            )
        }

        BrandHeader("POSTAVKE I SIGURNOST", securityIssueCount(model.items)) { model.open(Screen.SECURITY) }
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 4.dp),
            placeholder = { Text("Pretražite postavke...") },
            leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
            trailingIcon = if (search.isNotBlank()) {
                {
                    IconButton(onClick = { search = "" }) {
                        Icon(Icons.Outlined.Close, contentDescription = "Očisti pretragu")
                    }
                }
            } else null,
            singleLine = true,
            colors = keyraFieldColors(),
            shape = RoundedCornerShape(24.dp)
        )
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 20.dp)
        ) {
            if (accountVisible) item { SectionTitle("RAČUN I SIGURNOST") }
            if (matches("Biometrijsko otključavanje", "biometrija")) item {
                SettingRow(Icons.Outlined.Fingerprint, "Biometrijsko otključavanje", "Brz i siguran pristup trezoru.") {
                    Switch(model.biometricEnabled, model::toggleBiometric)
                }
            }
            if (matches("Potvrda prije prikaza tajni", "osjetljive vrijednosti", "potvrda identiteta")) item {
                SettingRow(
                    Icons.Outlined.Visibility,
                    "Potvrda prije prikaza tajni",
                    "Tražite biometriju ili zaključavanje uređaja prije prikaza i kopiranja osjetljivih podataka."
                ) {
                    Switch(
                        checked = model.sensitiveReauthEnabled,
                        onCheckedChange = model::toggleSensitiveReauth,
                        enabled = model.biometricEnabled
                    )
                }
            }
            if (matches("Automatsko zaključavanje", "zaključavanje")) item {
                SettingRow(
                    Icons.Outlined.Timer,
                    "Automatsko zaključavanje",
                    "Odredite kada se trezor zaključava nakon napuštanja aplikacije."
                ) {
                    TextButton(onClick = model::cycleAutoLock) {
                        Text(model.autoLockLabel(), color = Cyan)
                    }
                }
            }
            if (matches("Provjera sigurnosti", "slabe lozinke", "ponovljene lozinke")) item {
                SettingRow(
                    Icons.Outlined.Security,
                    "Provjera sigurnosti",
                    "Pronađite slabe i ponovljene lozinke.",
                    onClick = { model.open(Screen.SECURITY) }
                )
            }

            if (dataVisible) item { SectionTitle("UPRAVLJANJE PODACIMA") }
            if (matches("Kopiraj sigurnosnu kopiju", "izvoz", "sigurnosna kopija")) item {
                SettingRow(Icons.Outlined.Upload, "Kopiraj sigurnosnu kopiju", "Stvorite šifriranu kopiju trezora.") {
                    IconButton(onClick = {
                        if (model.sensitiveReauthEnabled && model.biometricEnabled) {
                            requestBiometric("Potvrdite identitet za izradu sigurnosne kopije.") {
                                model.exportBackup(context)
                            }
                        } else {
                            model.exportBackup(context)
                        }
                    }) { Icon(Icons.Outlined.ContentCopy, null, tint = Cyan) }
                }
            }
            if (matches("Uvezi sigurnosnu kopiju", "uvoz", "sigurnosna kopija")) item {
                SettingRow(
                    Icons.Outlined.Download,
                    "Uvezi sigurnosnu kopiju",
                    "Zamijenite trenutačni trezor šifriranom kopijom iz međuspremnika."
                ) {
                    IconButton(onClick = { confirmImport = true }) {
                        Icon(
                            Icons.Outlined.Download,
                            contentDescription = "Uvezi sigurnosnu kopiju",
                            tint = Cyan
                        )
                    }
                }
            }

            if (preferenceVisible) item { SectionTitle("PREFERENCIJE") }
            if (matches("Tamni način", "tamni izgled")) item {
                SettingRow(Icons.Outlined.DarkMode, "Tamni način", "Čistije i ugodnije iskustvo za oči.") {
                    Text("Uvijek uključen", color = Cyan, fontSize = 12.sp)
                }
            }

            if (privacyVisible) item { SectionTitle("SIGURNOST I PRIVATNOST") }
            if (matches("O aplikaciji Keyra", "verzija")) item {
                SettingRow(Icons.Outlined.Info, "O aplikaciji Keyra", "Verzija 0.5.0 • Vaši ključevi. Vaši podaci. Uvijek vaši.")
            }
            if (matches("Zaključaj trezor", "zaključavanje")) item {
                OutlinedButton(onClick = model::lock, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.Logout, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Zaključaj trezor")
                }
            }

            if (search.isNotBlank() && !accountVisible && !dataVisible && !preferenceVisible && !privacyVisible) {
                item {
                    GlassCard {
                        Icon(Icons.Outlined.SearchOff, contentDescription = null, tint = Cyan)
                        Text("Nema rezultata", color = Color.White, fontWeight = FontWeight.Bold)
                        Text("Pokušajte s drugim pojmom za pretragu postavki.", color = Muted)
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, color = Ice, fontSize = 13.sp, letterSpacing = 2.sp, modifier = Modifier.padding(top = 8.dp))
}

@Composable
private fun SettingRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        BoxWithConstraints {
            val compact = maxWidth < 380.dp
            if (compact && trailing != null) {
                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(44.dp)
                                .clip(RoundedCornerShape(13.dp))
                                .background(Color(0xFF0B3551)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(icon, null, tint = Cyan)
                        }
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp, maxLines = 2)
                            Text(subtitle, color = Muted, fontSize = 12.sp)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Box(Modifier.align(Alignment.End)) {
                        trailing.invoke()
                    }
                }
            } else {
                Row(
                    Modifier.fillMaxWidth().padding(if (compact) 12.dp else 14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(if (compact) 44.dp else 48.dp)
                            .clip(RoundedCornerShape(14.dp))
                            .background(Color(0xFF0B3551)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(icon, null, tint = Cyan)
                    }
                    Spacer(Modifier.width(if (compact) 10.dp else 12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            title,
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = if (compact) 15.sp else 17.sp,
                            maxLines = 2
                        )
                        Text(subtitle, color = Muted, fontSize = if (compact) 12.sp else 13.sp)
                    }
                    trailing?.invoke()
                    if (onClick != null && trailing == null) {
                        Icon(Icons.Outlined.ChevronRight, null, tint = Ice)
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityScreen(model: KeyraViewModel) {
    val passwordItems = model.items.filter {
        (it.type == "Prijava" || it.type == "Wi-Fi") && it.password.isNotBlank()
    }
    val duplicatedIds = passwordItems
        .groupBy { it.password }
        .filterValues { it.size > 1 }
        .values
        .flatten()
        .map { it.id }
        .toSet()
    val weak = passwordItems.filter { !isStrongPassword(it.password) }
    val strong = passwordItems.filter { isStrongPassword(it.password) && it.id !in duplicatedIds }
    val issueIds = securityIssueIds(model.items)
    val score = if (passwordItems.isEmpty()) null else {
        ((strong.size.toFloat() / passwordItems.size) * 100).toInt()
    }

    Column(Modifier.fillMaxSize()) {
        BrandHeader("SIGURNOST", securityIssueCount(model.items)) { model.open(Screen.SECURITY) }
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 22.dp)
        ) {
            item {
                GlassCard {
                    Text("Ocjena sigurnosti", color = Muted, fontSize = 14.sp)
                    Row(verticalAlignment = Alignment.Bottom) {
                        Text(
                            score?.toString() ?: "—",
                            color = if (score == null) Muted else if (score >= 80) Good else Warn,
                            fontSize = 54.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text("/100", color = Muted, fontSize = 18.sp, modifier = Modifier.padding(bottom = 10.dp))
                    }
                    LinearProgressIndicator(
                        progress = { (score ?: 0) / 100f },
                        modifier = Modifier.fillMaxWidth(),
                        color = if (score == null) Muted else if (score >= 80) Good else Warn,
                        trackColor = Color(0xFF203449)
                    )
                    Text(
                        when {
                            score == null -> "Dodajte barem jednu lozinku kako bi Keyra mogla izračunati ocjenu sigurnosti."
                            score >= 80 -> "Vaš trezor izgleda dobro zaštićen."
                            else -> "Pregledajte stavke koje zahtijevaju pažnju."
                        },
                        color = Muted
                    )
                }
            }
            item {
                BoxWithConstraints(Modifier.fillMaxWidth()) {
                    if (maxWidth < 350.dp) {
                        Row(
                            Modifier.horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            SummaryCard(strong.size.toString(), "Snažne", Good, Modifier.width(110.dp))
                            SummaryCard(weak.size.toString(), "Slabe", Warn, Modifier.width(110.dp))
                            SummaryCard(duplicatedIds.size.toString(), "Ponovljene", Danger, Modifier.width(122.dp))
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            SummaryCard(strong.size.toString(), "Snažne", Good, Modifier.weight(1f))
                            SummaryCard(weak.size.toString(), "Slabe", Warn, Modifier.weight(1f))
                            SummaryCard(duplicatedIds.size.toString(), "Ponovljene", Danger, Modifier.weight(1f))
                        }
                    }
                }
            }
            item { SectionTitle("STAVKE KOJE ZAHTIJEVAJU PAŽNJU") }
            items((weak + model.items.filter { it.id in duplicatedIds }).distinctBy { it.id }) { issue ->
                val duplicate = issue.id in duplicatedIds
                val weakPassword = !isStrongPassword(issue.password)
                Surface(
                    Modifier.fillMaxWidth().clickable { model.select(issue) },
                    shape = RoundedCornerShape(20.dp),
                    color = Slate,
                    border = androidx.compose.foundation.BorderStroke(1.dp, (if (duplicate) Danger else Warn).copy(alpha=.55f))
                ) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (duplicate) Icons.Outlined.ContentCopy else Icons.Outlined.Warning,
                            null,
                            tint = if (duplicate) Danger else Warn
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(issue.title, color = Color.White, fontWeight = FontWeight.Bold)
                            Text(
                                when {
                                    duplicate && weakPassword -> "Lozinka je slaba i koristi se na više mjesta."
                                    duplicate -> "Lozinka se koristi na više mjesta."
                                    else -> "Lozinka nije dovoljno snažna i preporučuje se zamjena."
                                },
                                color = Muted,
                                fontSize = 13.sp
                            )
                        }
                        Icon(Icons.Outlined.ChevronRight, null, tint = Ice)
                    }
                }
            }
            if (issueIds.isEmpty()) {
                item {
                    Surface(
                        shape = RoundedCornerShape(20.dp),
                        color = Good.copy(alpha=.10f),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Good.copy(alpha=.55f))
                    ) {
                        Row(Modifier.fillMaxWidth().padding(18.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Outlined.VerifiedUser, null, tint = Good)
                            Spacer(Modifier.width(12.dp))
                            Text("Nisu pronađene slabe ili ponovljene lozinke.", color = Color.White)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun keyraFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = Cyan,
    unfocusedBorderColor = Ice.copy(alpha=.4f),
    focusedTextColor = Color.White,
    unfocusedTextColor = Color.White,
    focusedLabelColor = Cyan,
    unfocusedLabelColor = Muted,
    focusedLeadingIconColor = Cyan,
    unfocusedLeadingIconColor = Ice,
    cursorColor = Cyan
)


private fun normalizedWebsiteUri(raw: String): Uri? {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) return null

    val normalized = if (
        trimmed.startsWith("https://", ignoreCase = true) ||
        trimmed.startsWith("http://", ignoreCase = true)
    ) {
        trimmed
    } else {
        "https://$trimmed"
    }

    val uri = runCatching { Uri.parse(normalized) }.getOrNull() ?: return null
    if (uri.scheme?.lowercase() !in listOf("https", "http") || uri.host.isNullOrBlank()) return null
    return uri
}

private fun openWebsite(context: Context, raw: String): Boolean {
    val uri = normalizedWebsiteUri(raw) ?: return false

    return runCatching {
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
        true
    }.getOrDefault(false)
}

private fun clearClipboardIfMatches(context: Context, expected: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = clipboard.primaryClip
    val current = if (clip != null && clip.itemCount > 0) {
        clip.getItemAt(0).coerceToText(context)?.toString()
    } else {
        null
    }
    if (current == expected) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) clipboard.clearPrimaryClip()
        else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
    }
}

private fun copy(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("Keyra", text)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
    Handler(Looper.getMainLooper()).postDelayed({
        val currentClip = clipboard.primaryClip
        val current = if (currentClip != null && currentClip.itemCount > 0) {
            currentClip.getItemAt(0).text?.toString()
        } else {
            null
        }
        if (current == text) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) clipboard.clearPrimaryClip()
            else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }, 30_000)
}
