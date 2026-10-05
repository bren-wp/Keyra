package com.keyra.app

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ClipDescription
import android.content.Context
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
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec

private val Midnight = Color(0xFF06111F)
private val Slate = Color(0xFF0B2034)
private val Slate2 = Color(0xFF121826)
private val Cyan = Color(0xFF00E5D1)
private val Ice = Color(0xFF7DD3FC)
private val Indigo = Color(0xFF6366F1)
private val Muted = Color(0xFFAABBD5)
private val Good = Color(0xFF22E3B0)
private val Warn = Color(0xFFFFC247)
private val Danger = Color(0xFFFF5B6E)

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
                KeyraRoot(model = model, requestBiometric = { authenticateBiometric() })
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

    private fun authenticateBiometric() {
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
                    model.unlockFromBiometric()
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    model.message = errString.toString()
                }
            }
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Otključajte Keyru")
                .setSubtitle("Potvrdite identitet za pristup trezoru.")
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
    val items: SnapshotStateList<VaultItem> = mutableStateListOf()

    var isSetup by mutableStateOf(auth.isSetup())
    var unlocked by mutableStateOf(false)
    var screen by mutableStateOf(if (isSetup) Screen.UNLOCK else Screen.ONBOARDING)
    var selected by mutableStateOf<VaultItem?>(null)
    var message by mutableStateOf<String?>(null)
    var biometricEnabled by mutableStateOf(prefs.getBoolean("biometric_enabled", true))
    var autoLockSeconds by mutableIntStateOf(prefs.getInt("auto_lock_seconds", 0))
    private var sessionPassword: String? = null
    private var backgroundAt: Long? = null

    fun startCreate() { screen = Screen.UNLOCK }
    fun open(screen: Screen) { this.screen = screen }
    fun addNew() { selected = null; screen = Screen.ADD }
    fun editSelected() { if (selected != null) screen = Screen.ADD }
    fun select(item: VaultItem) { selected = item; screen = Screen.DETAIL }

    fun createVault(password: String): Boolean {
        if (password.length < 12) {
            message = "Glavna lozinka mora imati najmanje 12 znakova."
            return false
        }
        auth.create(password)
        prefs.edit()
            .remove("unlock_failed_attempts")
            .remove("unlock_lockout_until")
            .apply()
        isSetup = true
        sessionPassword = password
        unlocked = true
        items.clear()
        items.addAll(seedItems())
        store.save(items)
        screen = Screen.VAULT
        return true
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
        loadVault()
        unlocked = true
        screen = Screen.VAULT
        return true
    }

    fun unlockFromBiometric() {
        if (!isSetup) return
        loadVault()
        unlocked = true
        screen = Screen.VAULT
    }

    fun lock() {
        unlocked = false
        sessionPassword = null
        items.clear()
        selected = null
        screen = Screen.UNLOCK
    }

    fun saveItem(item: VaultItem) {
        val index = items.indexOfFirst { it.id == item.id }
        val saved = item.copy(updatedAt = System.currentTimeMillis())
        if (index >= 0) items[index] = saved else items.add(0, saved)
        store.save(items)
        selected = saved
        screen = Screen.VAULT
    }

    fun deleteSelected() {
        selected?.let { target ->
            items.removeAll { it.id == target.id }
            store.save(items)
        }
        selected = null
        screen = Screen.VAULT
    }

    fun exportBackup(context: Context) {
        val password = sessionPassword
        if (password.isNullOrBlank()) {
            message = "Za sigurnosnu kopiju prvo otključajte trezor glavnom lozinkom."
            return
        }
        val payload = PortableBackup.encrypt(store.toJson(items), password)
        copy(context, payload)
        message = "Šifrirana sigurnosna kopija kopirana je u međuspremnik i automatski će se ukloniti."
    }

    fun importBackup(context: Context) {
        val password = sessionPassword
        if (password.isNullOrBlank()) {
            message = "Za uvoz prvo otključajte trezor glavnom lozinkom."
            return
        }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
        runCatching {
            val json = PortableBackup.decrypt(text, password)
            val imported = store.fromJson(json)
            items.clear()
            items.addAll(imported)
            store.save(items)
        }.onSuccess {
            message = "Sigurnosna kopija uspješno je uvezena."
        }.onFailure {
            message = "Sigurnosna kopija nije valjana ili lozinka nije odgovarajuća."
        }
    }

    fun toggleBiometric(value: Boolean) {
        biometricEnabled = value
        prefs.edit().putBoolean("biometric_enabled", value).apply()
    }

    fun cycleAutoLock() {
        autoLockSeconds = when (autoLockSeconds) {
            0 -> 30
            30 -> 60
            60 -> 300
            else -> 0
        }
        prefs.edit().putInt("auto_lock_seconds", autoLockSeconds).apply()
        message = "Automatsko zaključavanje: " + autoLockLabel()
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

    private fun loadVault() {
        items.clear()
        items.addAll(store.load())
    }

    private fun seedItems() = listOf(
        VaultItem(title="Google", username="primjer@keyra.app", password="K3yra!Google#2026", website="https://accounts.google.com", notes="Primjer prijave", category="Osobno", favorite=true, type="Prijava"),
        VaultItem(title="Apple ID", username="primjer@keyra.app", password="Appl3!Keyra#2026", website="https://account.apple.com", category="Osobno", type="Prijava"),
        VaultItem(title="GitHub", username="primjer", password="Git#Keyra!90210", website="https://github.com", category="Posao", type="Prijava"),
        VaultItem(title="Kućni Wi‑Fi", username="Dnevni boravak", password="Wifi!Keyra#8821", category="Osobno", type="Wi-Fi", fields=mapOf("Naziv mreže" to "Keyra Home", "Vrsta zaštite" to "WPA3")),
        VaultItem(title="Netflix", username="primjer@keyra.app", password="K3yra!Google#2026", website="https://netflix.com", category="Zabava", type="Prijava"),
        VaultItem(title="Sigurne bilješke", notes="Ovdje možete spremati važne privatne bilješke.", category="Osobno", type="Bilješka"),
        VaultItem(title="Putna kartica", category="Putovanja", type="Kartica", fields=mapOf("Vlasnik kartice" to "Primjer Korisnik", "Broj kartice" to "4111111111111111", "Vrijedi do" to "12/30", "Sigurnosni kod" to "123")),
        VaultItem(title="Osobni dokument", category="Osobno", type="Identitet", fields=mapOf("Puno ime" to "Primjer Korisnik", "Broj dokumenta" to "ID-KEYRA-2026", "Datum isteka" to "31. 12. 2030."))
    )
}

private class AuthStore(private val prefs: android.content.SharedPreferences) {
    companion object {
        private const val CURRENT_ITERATIONS = 600_000
        private const val LEGACY_ITERATIONS = 180_000
    }

    fun isSetup() = prefs.contains("master_hash")

    fun create(password: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs.edit()
            .putString("master_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .putInt("master_iterations", CURRENT_ITERATIONS)
            .putString("master_hash", derive(password, salt, CURRENT_ITERATIONS))
            .apply()
    }

    fun verify(password: String): Boolean {
        val salt = prefs.getString("master_salt", null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val expected = prefs.getString("master_hash", null) ?: return false
        val iterations = prefs.getInt("master_iterations", LEGACY_ITERATIONS)
        val actual = derive(password, salt, iterations)
        val ok = MessageDigest.isEqual(expected.toByteArray(), actual.toByteArray())
        if (ok && iterations < CURRENT_ITERATIONS) {
            prefs.edit()
                .putInt("master_iterations", CURRENT_ITERATIONS)
                .putString("master_hash", derive(password, salt, CURRENT_ITERATIONS))
                .apply()
        }
        return ok
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

private class VaultStore(private val prefs: android.content.SharedPreferences) {
    private val crypto = CryptoStore()

    fun save(items: List<VaultItem>) {
        prefs.edit().putString("vault_blob", crypto.encrypt(toJson(items))).apply()
    }

    fun load(): List<VaultItem> {
        val blob = prefs.getString("vault_blob", null) ?: return emptyList()
        return runCatching { fromJson(crypto.decrypt(blob)) }.getOrDefault(emptyList())
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
        return buildList {
            for (i in 0 until array.length()) {
                val o = array.getJSONObject(i)
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
                        id = o.optString("id", UUID.randomUUID().toString()),
                        title = o.optString("title"),
                        username = username,
                        password = password,
                        website = website,
                        notes = notes,
                        category = o.optString("category", "Osobno"),
                        favorite = o.optBoolean("favorite", false),
                        type = inferredType,
                        fields = fields,
                        updatedAt = o.optLong("updatedAt", System.currentTimeMillis())
                    )
                )
            }
        }
    }
}

private object PortableBackup {
    private const val ITERATIONS = 600_000

    fun encrypt(text: String, password: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = derive(password, salt, ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val data = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return listOf(
            "KEYRA2",
            ITERATIONS.toString(),
            Base64.encodeToString(salt, Base64.NO_WRAP),
            Base64.encodeToString(iv, Base64.NO_WRAP),
            Base64.encodeToString(data, Base64.NO_WRAP)
        ).joinToString(".")
    }

    fun decrypt(payload: String, password: String): String {
        val p = payload.split(".")
        val iterations: Int
        val saltIndex: Int
        when {
            p.size == 5 && p[0] == "KEYRA2" -> {
                iterations = p[1].toInt()
                require(iterations in 100_000..2_000_000)
                saltIndex = 2
            }
            p.size == 4 && p[0] == "KEYRA1" -> {
                iterations = 180_000
                saltIndex = 1
            }
            else -> error("Neispravan format sigurnosne kopije.")
        }
        val salt = Base64.decode(p[saltIndex], Base64.NO_WRAP)
        val iv = Base64.decode(p[saltIndex + 1], Base64.NO_WRAP)
        val data = Base64.decode(p[saltIndex + 2], Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, derive(password, salt, iterations), GCMParameterSpec(128, iv))
        return cipher.doFinal(data).toString(Charsets.UTF_8)
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
private fun KeyraRoot(model: KeyraViewModel, requestBiometric: () -> Unit) {
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
            Screen.GENERATOR -> MainScaffold(model, Screen.GENERATOR) { GeneratorScreen() }
            Screen.ADD -> AddScreen(model)
            Screen.DETAIL -> DetailScreen(model)
            Screen.SETTINGS -> MainScaffold(model, Screen.SETTINGS) { SettingsScreen(model) }
            Screen.SECURITY -> MainScaffold(model, Screen.SETTINGS) { SecurityScreen(model) }
        }
        model.message?.let { msg ->
            LaunchedEffect(msg) { delay(2600); model.message = null }
            Surface(
                modifier = Modifier.align(Alignment.BottomCenter).padding(22.dp),
                shape = RoundedCornerShape(18.dp),
                color = Slate2
            ) { Text(msg, modifier = Modifier.padding(16.dp), color = Color.White) }
        }
    }
}

@Composable
private fun SplashScreen() {
    Box(
        Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Midnight, Color(0xFF071B36), Midnight))),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            KeyraMark(132.dp)
            Spacer(Modifier.height(24.dp))
            Text("Keyra", color = Color.White, fontSize = 58.sp, fontWeight = FontWeight.ExtraBold)
            Text("SIGURNI UPRAVITELJ LOZINKI", color = Muted, fontSize = 13.sp, letterSpacing = 3.sp)
            Spacer(Modifier.height(32.dp))
            Text("VAŠI KLJUČEVI. VAŠI PODACI. UVIJEK VAŠI.", color = Ice, fontSize = 11.sp, letterSpacing = 1.8.sp)
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

@Composable
private fun BrandHeader(subtitle: String) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        KeyraMark(56.dp)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text("Keyra", fontSize = 34.sp, color = Color.White, fontWeight = FontWeight.ExtraBold)
            Text(subtitle, color = Muted, fontSize = 12.sp, letterSpacing = 3.sp)
        }
        Icon(Icons.Outlined.Notifications, null, tint = Color.White)
        Spacer(Modifier.width(14.dp))
        Box(
            Modifier.size(48.dp).clip(CircleShape).border(1.dp, Cyan, CircleShape),
            contentAlignment = Alignment.Center
        ) { Text("K", color = Color.White, fontWeight = FontWeight.Bold) }
    }
}

@Composable
private fun OnboardingScreen(model: KeyraViewModel) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(24.dp))
        KeyraMark(96.dp)
        Text("Keyra", color = Color.White, fontSize = 48.sp, fontWeight = FontWeight.ExtraBold)
        Text("SIGURNI UPRAVITELJ LOZINKI", color = Muted, fontSize = 12.sp, letterSpacing = 2.sp)
        Spacer(Modifier.height(34.dp))
        Text("Sigurniji način", color = Color.White, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold)
        Text("upravljanja lozinkama", color = Cyan, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold)
        Spacer(Modifier.height(12.dp))
        Text(
            "Čuvajte svoje lozinke, pristupne ključeve i osjetljive podatke na jednom sigurnom mjestu.",
            color = Muted, fontSize = 17.sp
        )
        Spacer(Modifier.height(26.dp))
        FeatureCard(Icons.Outlined.Lock, "Potpuno šifrirano", "Vaši podaci ostaju na vašem uređaju.")
        FeatureCard(Icons.Outlined.Fingerprint, "Privatnost u osnovi", "Stvoreno za vaš mir.")
        FeatureCard(Icons.Outlined.PhoneAndroid, "Radi svugdje", "Besprijekorno na Androidu i iOS-u.")
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = model::startCreate,
            modifier = Modifier.fillMaxWidth().height(58.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
            shape = RoundedCornerShape(28.dp)
        ) {
            Text("Izradi trezor", fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(8.dp)); Icon(Icons.Outlined.ArrowForward, null)
        }
    }
}

@Composable
private fun FeatureCard(icon: ImageVector, title: String, subtitle: String) {
    Surface(
        Modifier.fillMaxWidth().padding(vertical = 5.dp),
        shape = RoundedCornerShape(20.dp),
        color = Slate.copy(alpha=.9f),
        border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha=.35f))
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(15.dp)).background(Color(0xFF0A2D3C)),
                contentAlignment = Alignment.Center
            ) { Icon(icon, null, tint = Cyan) }
            Spacer(Modifier.width(14.dp))
            Column {
                Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(subtitle, color = Muted, fontSize = 14.sp)
            }
        }
    }
}

@Composable
private fun UnlockScreen(model: KeyraViewModel, requestBiometric: () -> Unit) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }
    val creating = !model.isSetup
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(26.dp))
        KeyraMark(90.dp)
        Text("Keyra", color = Color.White, fontSize = 48.sp, fontWeight = FontWeight.ExtraBold)
        Text("SIGURNI UPRAVITELJ LOZINKI", color = Muted, fontSize = 12.sp, letterSpacing = 2.sp)
        Spacer(Modifier.height(38.dp))
        GlassCard {
            Text(if (creating) "Izradite trezor" else "Otključajte trezor", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.ExtraBold)
            Text(
                if (creating) "Postavite glavnu lozinku kojom ćete otključavati svoj trezor."
                else "Unesite glavnu lozinku kako biste pristupili svom sigurnom trezoru.",
                color = Muted, fontSize = 16.sp
            )
            Spacer(Modifier.height(18.dp))
            KeyraPasswordField(password, { password = it }, show, { show = !show }, "Glavna lozinka")
            if (creating) {
                Spacer(Modifier.height(12.dp))
                KeyraPasswordField(confirm, { confirm = it }, show, { show = !show }, "Ponovite glavnu lozinku")
            }
            Spacer(Modifier.height(18.dp))
            Button(
                onClick = {
                    if (creating) {
                        if (password != confirm) model.message = "Lozinke se ne podudaraju."
                        else model.createVault(password)
                    } else model.unlock(password)
                },
                modifier = Modifier.fillMaxWidth().height(56.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                shape = RoundedCornerShape(28.dp)
            ) {
                Icon(Icons.Outlined.Lock, null)
                Spacer(Modifier.width(8.dp))
                Text(if (creating) "Izradi trezor" else "Otključaj", fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
            if (!creating && model.biometricEnabled) {
                Spacer(Modifier.height(18.dp))
                HorizontalDivider(color = Muted.copy(alpha=.25f))
                Spacer(Modifier.height(12.dp))
                OutlinedButton(
                    onClick = requestBiometric,
                    modifier = Modifier.fillMaxWidth(),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Cyan.copy(alpha=.6f))
                ) {
                    Icon(Icons.Outlined.Fingerprint, null, tint = Cyan)
                    Spacer(Modifier.width(8.dp))
                    Text("Biometrijsko otključavanje", color = Color.White)
                }
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
        Box(Modifier.fillMaxSize().padding(padding)) { content() }
    }
}

@Composable
private fun BottomNav(model: KeyraViewModel, active: Screen) {
    NavigationBar(containerColor = Slate, tonalElevation = 10.dp) {
        NavItem(Icons.Outlined.Home, "Trezor", active == Screen.VAULT) { model.open(Screen.VAULT) }
        NavItem(Icons.Outlined.Refresh, "Generator", active == Screen.GENERATOR) { model.open(Screen.GENERATOR) }
        NavItem(Icons.Outlined.Folder, "Kolekcije", active == Screen.COLLECTIONS) { model.open(Screen.COLLECTIONS) }
        NavItem(Icons.Outlined.Settings, "Postavke", active == Screen.SETTINGS) { model.open(Screen.SETTINGS) }
    }
}

@Composable
private fun RowScope.NavItem(icon: ImageVector, label: String, selected: Boolean, onClick: () -> Unit) {
    NavigationBarItem(
        selected = selected,
        onClick = onClick,
        icon = { Icon(icon, null) },
        label = { Text(label) },
        colors = NavigationBarItemDefaults.colors(
            selectedIconColor = Cyan,
            selectedTextColor = Cyan,
            indicatorColor = Color(0xFF0A3242),
            unselectedIconColor = Muted,
            unselectedTextColor = Muted
        )
    )
}

@Composable
private fun VaultScreen(model: KeyraViewModel) {
    var search by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("Sve") }

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
            typeMatch && (search.isBlank() || haystack.contains(search, true))
        }
        .sortedByDescending { it.updatedAt }

    val passwordItems = model.items.filter { it.type == "Prijava" || it.type == "Wi-Fi" }
    val weak = passwordItems.count { it.password.isNotBlank() && it.password.length < 12 }
    val duplicated = passwordItems.groupBy { it.password }
        .filter { it.key.isNotBlank() && it.value.size > 1 }
        .values.flatten().map { it.id }.toSet()

    Column(Modifier.fillMaxSize()) {
        BrandHeader("MOJ TREZOR")

        OutlinedTextField(
            search, { search = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp),
            placeholder = { Text("Pretražite svoj trezor...") },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            trailingIcon = { Icon(Icons.Outlined.Tune, null, tint = Ice) },
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

        Row(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            SummaryCard(model.items.size.toString(), "Ukupno", Cyan, Modifier.weight(1f))
            SummaryCard(weak.toString(), "Slabe", Danger, Modifier.weight(1f))
            SummaryCard(duplicated.size.toString(), "Ponovljene", Indigo, Modifier.weight(1f))
        }

        Row(
            Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Vaše stavke", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold, modifier = Modifier.weight(1f))
            Text("Poredaj po nedavnim", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(end = 10.dp))
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
                    Box(Modifier.fillMaxWidth().padding(40.dp), contentAlignment = Alignment.Center) {
                        Text("Nema stavki za prikaz.", color = Muted)
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
        isPasswordItem && item.password.isNotBlank() && item.password.length < 12 -> Warn
        else -> Good
    }
    val state = when {
        duplicated -> "Ponovno korištena"
        isPasswordItem && item.password.isNotBlank() && item.password.length < 12 -> "Potrebno ažuriranje"
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
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(accent.copy(alpha=.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, null, tint = accent)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(subtitle, color = Muted, fontSize = 13.sp, maxLines = 1)
            }
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = stateColor.copy(alpha=.12f),
                border = androidx.compose.foundation.BorderStroke(1.dp, stateColor.copy(alpha=.8f))
            ) {
                Text(state, color = stateColor, fontSize = 11.sp, modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp))
            }
        }
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

    val recentNotes = model.items
        .filter { it.type == "Bilješka" && (search.isBlank() || it.title.contains(search, true) || it.notes.contains(search, true)) }
        .sortedByDescending { it.updatedAt }
        .take(3)

    Column(Modifier.fillMaxSize()) {
        BrandHeader("MOJ TREZOR")
        Text("Kolekcije", Modifier.padding(horizontal = 18.dp), color = Color.White, fontSize = 42.sp, fontWeight = FontWeight.ExtraBold)
        Text("Organizirajte podatke. Pronađite ih odmah.", Modifier.padding(horizontal = 18.dp), color = Muted, fontSize = 16.sp)
        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            search, { search = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp),
            placeholder = { Text("Pretražite lozinke, bilješke, kartice...") },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            trailingIcon = { Icon(Icons.Outlined.Tune, null, tint = Ice) },
            colors = keyraFieldColors(),
            shape = RoundedCornerShape(24.dp)
        )

        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 18.dp, vertical = 10.dp),
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
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 18.dp)
        ) {
            items(categories.chunked(2)) { pair ->
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    pair.forEach { (name, accent) ->
                        val count = model.items.count { it.category == name }
                        Surface(
                            Modifier.weight(1f).height(90.dp),
                            shape = RoundedCornerShape(20.dp),
                            color = accent.copy(alpha=.13f),
                            border = androidx.compose.foundation.BorderStroke(1.dp, accent.copy(alpha=.8f))
                        ) {
                            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    Modifier.size(44.dp).clip(RoundedCornerShape(13.dp)).background(accent.copy(alpha=.18f)),
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
                                Column {
                                    Text(name, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                    Text(count.toString() + " stavki", color = Muted, fontSize = 13.sp)
                                }
                            }
                        }
                    }
                }
            }
            item {
                Spacer(Modifier.height(8.dp))
                Text("Nedavne bilješke", color = Color.White, fontSize = 25.sp, fontWeight = FontWeight.ExtraBold)
                Text("Vaše najnovije bilješke i sigurne informacije.", color = Muted)
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
                            Text(noteItem.title, color = Color.White, fontWeight = FontWeight.Bold)
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

@Composable
private fun GeneratorScreen() {
    var length by remember { mutableFloatStateOf(16f) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var numbers by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var password by remember { mutableStateOf(generatePassword(16, true, true, true, true)) }
    fun refresh() { password = generatePassword(length.toInt(), upper, lower, numbers, symbols) }

    Column(Modifier.fillMaxSize()) {
        BrandHeader("Generator lozinki")
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
                    Text(password, color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(12.dp))
                    LinearProgressIndicator(progress = { 0.9f }, modifier = Modifier.fillMaxWidth(), color = Cyan, trackColor = Color(0xFF164C53))
                    Text("Vrlo snažna", color = Good, fontWeight = FontWeight.Bold)
                }
            }
            item {
                GlassCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Duljina lozinke", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        Text(length.toInt().toString(), color = Cyan, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    }
                    Slider(value = length, onValueChange = { length = it; refresh() }, valueRange = 8f..64f, steps = 55)
                }
            }
            item {
                GlassCard {
                    Text("Vrste znakova", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    GeneratorToggle("Velika slova (A–Z)", upper) { upper = it; refresh() }
                    GeneratorToggle("Mala slova (a–z)", lower) { lower = it; refresh() }
                    GeneratorToggle("Brojevi (0–9)", numbers) { numbers = it; refresh() }
                    GeneratorToggle("Simboli (!@#...)", symbols) { symbols = it; refresh() }
                }
            }
            item {
                Button(
                    onClick = { refresh() },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                    shape = RoundedCornerShape(28.dp)
                ) {
                    Icon(Icons.Outlined.Refresh, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Generiraj novu", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

private fun generatePassword(length: Int, upper: Boolean, lower: Boolean, numbers: Boolean, symbols: Boolean): String {
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
                else -> ""
            }
        )
    }
    var field3 by remember(original?.id) {
        mutableStateOf(
            when (original?.type) {
                "Kartica" -> original.fields["Vrijedi do"].orEmpty()
                "Identitet" -> original.fields["Datum isteka"].orEmpty()
                else -> ""
            }
        )
    }
    var field4 by remember(original?.id) {
        mutableStateOf(if (original?.type == "Kartica") original.fields["Sigurnosni kod"].orEmpty() else "")
    }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { model.open(if (original == null) Screen.VAULT else Screen.DETAIL) }) {
                Icon(Icons.Outlined.ArrowBack, null, tint = Color.White)
            }
            KeyraMark(38.dp)
            Spacer(Modifier.width(10.dp))
            Text("Keyra", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        }

        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 26.dp)
        ) {
            item {
                Text(if (original == null) "Dodaj stavku" else "Uredi stavku", color = Color.White, fontSize = 38.sp, fontWeight = FontWeight.ExtraBold)
                Text("Sigurno spremite osjetljive podatke", color = Muted)
            }

            item {
                Text("Vrsta stavke", color = Ice, fontSize = 12.sp, letterSpacing = 2.sp)
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    listOf("Prijava","Bilješka","Kartica","Identitet","Wi-Fi").forEach { value ->
                        FilterChip(
                            selected = type == value,
                            onClick = {
                                if (original == null) {
                                    type = value
                                    field1 = ""; field2 = ""; field3 = ""; field4 = ""
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
                item { KeyraTextField(field3, { field3 = it.take(7) }, "Vrijedi do", Icons.Outlined.DateRange) }
                item { KeyraTextField(field4, { field4 = it.filter(Char::isDigit).take(4) }, "Sigurnosni kod", Icons.Outlined.Lock) }
            }

            if (type == "Identitet") {
                item { KeyraTextField(field1, { field1 = it }, "Puno ime", Icons.Outlined.Person) }
                item { KeyraTextField(field2, { field2 = it }, "Broj dokumenta", Icons.Outlined.Badge) }
                item { KeyraTextField(field3, { field3 = it }, "Datum isteka", Icons.Outlined.DateRange) }
            }

            item { KeyraTextField(notes, { notes = it.take(1000) }, "Bilješke (nije obavezno)", Icons.Outlined.Description, singleLine = false) }

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
                        if (title.isBlank()) {
                            model.message = "Unesite naslov stavke."
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
                                else -> emptyMap()
                            }

                            model.saveItem(
                                VaultItem(
                                    id = original?.id ?: UUID.randomUUID().toString(),
                                    title = title.trim(),
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
                    Text(if (type == "Prijava") "Spremi prijavu" else "Spremi stavku", fontWeight = FontWeight.Bold, fontSize = 17.sp)
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
private fun DetailScreen(model: KeyraViewModel) {
    val current = model.selected ?: return
    var reveal by remember(current.id) { mutableStateOf(false) }
    var revealCard by remember(current.id) { mutableStateOf(false) }
    val context = LocalContext.current

    val titleIcon = when (current.type) {
        "Bilješka" -> Icons.Outlined.Description
        "Kartica" -> Icons.Outlined.CreditCard
        "Identitet" -> Icons.Outlined.Badge
        "Wi-Fi" -> Icons.Outlined.Wifi
        else -> Icons.Outlined.Lock
    }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
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
                Text(current.title, color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.ExtraBold)
                Text(current.type + " • " + current.category, color = Muted)
            }
            if (current.favorite) Icon(Icons.Outlined.Star, null, tint = Warn)
        }

        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 28.dp)
        ) {
            if (current.type == "Prijava") {
                if (current.website.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Link, "Web-stranica", current.website)
                }
                if (current.username.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Person, "Korisničko ime / e-pošta", current.username) {
                        copy(context, current.username)
                        model.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                    }
                }
            }

            if (current.type == "Wi-Fi") {
                current.fields["Naziv mreže"]?.takeIf { it.isNotBlank() }?.let { network ->
                    item { DetailRow(Icons.Outlined.Wifi, "Naziv mreže", network) }
                }
                if (current.username.isNotBlank()) item {
                    DetailRow(Icons.Outlined.Person, "Korisničko ime", current.username) {
                        copy(context, current.username)
                        model.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                    }
                }
                current.fields["Vrsta zaštite"]?.takeIf { it.isNotBlank() }?.let { security ->
                    item { DetailRow(Icons.Outlined.Security, "Vrsta zaštite", security) }
                }
            }

            if ((current.type == "Prijava" || current.type == "Wi-Fi") && current.password.isNotBlank()) item {
                PasswordDetailRow(
                    password = current.password,
                    reveal = reveal,
                    onReveal = { reveal = !reveal },
                    onCopy = {
                        copy(context, current.password)
                        model.message = "Lozinka je kopirana i automatski će se ukloniti iz međuspremnika."
                    }
                )
            }

            if (current.type == "Kartica") {
                current.fields["Vlasnik kartice"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.Person, "Vlasnik kartice", value) }
                }
                current.fields["Broj kartice"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item {
                        SensitiveDetailRow(
                            icon = Icons.Outlined.CreditCard,
                            label = "Broj kartice",
                            value = value,
                            reveal = revealCard,
                            hidden = "•••• •••• •••• " + value.takeLast(4),
                            onReveal = { revealCard = !revealCard },
                            onCopy = {
                                copy(context, value)
                                model.message = "Broj kartice kopiran je i automatski će se ukloniti."
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
                            reveal = revealCard,
                            hidden = "•••",
                            onReveal = { revealCard = !revealCard },
                            onCopy = {
                                copy(context, value)
                                model.message = "Sigurnosni kod kopiran je i automatski će se ukloniti."
                            }
                        )
                    }
                }
            }

            if (current.type == "Identitet") {
                current.fields["Puno ime"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.Person, "Puno ime", value) }
                }
                current.fields["Broj dokumenta"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item {
                        SensitiveDetailRow(
                            icon = Icons.Outlined.Badge,
                            label = "Broj dokumenta",
                            value = value,
                            reveal = revealCard,
                            hidden = "••••" + value.takeLast(4),
                            onReveal = { revealCard = !revealCard },
                            onCopy = {
                                copy(context, value)
                                model.message = "Broj dokumenta kopiran je i automatski će se ukloniti."
                            }
                        )
                    }
                }
                current.fields["Datum isteka"]?.takeIf { it.isNotBlank() }?.let { value ->
                    item { DetailRow(Icons.Outlined.DateRange, "Datum isteka", value) }
                }
            }

            if (current.notes.isNotBlank()) item {
                DetailRow(Icons.Outlined.Description, "Bilješke", current.notes)
            }

            item {
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
                        onClick = model::deleteSelected,
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
private fun SettingsScreen(model: KeyraViewModel) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        BrandHeader("POSTAVKE I SIGURNOST")
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 20.dp)
        ) {
            item { SectionTitle("RAČUN I SIGURNOST") }
            item {
                SettingRow(Icons.Outlined.Fingerprint, "Biometrijsko otključavanje", "Brz i siguran pristup trezoru.") {
                    Switch(model.biometricEnabled, model::toggleBiometric)
                }
            }
            item {
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
            item {
                SettingRow(
                    Icons.Outlined.Security,
                    "Provjera sigurnosti",
                    "Pronađite slabe i ponovljene lozinke.",
                    onClick = { model.open(Screen.SECURITY) }
                )
            }
            item { SectionTitle("UPRAVLJANJE PODACIMA") }
            item {
                SettingRow(Icons.Outlined.Upload, "Kopiraj sigurnosnu kopiju", "Stvorite šifriranu kopiju trezora.") {
                    IconButton(onClick = { model.exportBackup(context) }) { Icon(Icons.Outlined.ContentCopy, null, tint = Cyan) }
                }
            }
            item {
                SettingRow(Icons.Outlined.Download, "Uvezi sigurnosnu kopiju", "Vratite šifriranu kopiju iz međuspremnika.") {
                    IconButton(onClick = { model.importBackup(context) }) { Icon(Icons.Outlined.Download, null, tint = Cyan) }
                }
            }
            item { SectionTitle("PREFERENCIJE") }
            item { SettingRow(Icons.Outlined.DarkMode, "Tamni način", "Čistije i ugodnije iskustvo za oči.") }
            item { SectionTitle("SIGURNOST I PRIVATNOST") }
            item { SettingRow(Icons.Outlined.Info, "O aplikaciji Keyra", "Verzija 0.2.0 • Vaši ključevi. Vaši podaci. Uvijek vaši.") }
            item {
                OutlinedButton(onClick = model::lock, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.Logout, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Zaključaj trezor")
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
        modifier = Modifier.then(if (onClick != null) Modifier.clickable { onClick() } else Modifier),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF0B3551)), contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = Cyan)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(subtitle, color = Muted, fontSize = 13.sp)
            }
            trailing?.invoke()
            if (onClick != null && trailing == null) {
                Icon(Icons.Outlined.ChevronRight, null, tint = Ice)
            }
        }
    }
}

@Composable
private fun SecurityScreen(model: KeyraViewModel) {
    val passwordItems = model.items.filter { (it.type == "Prijava" || it.type == "Wi-Fi") && it.password.isNotBlank() }
    val duplicatedGroups = passwordItems
        .groupBy { it.password }
        .filterValues { it.size > 1 }
    val duplicatedIds = duplicatedGroups.values.flatten().map { it.id }.toSet()
    val weak = passwordItems.filter { it.password.length < 12 }
    val strong = passwordItems.filter { it.password.length >= 12 && it.id !in duplicatedIds }
    val score = if (passwordItems.isEmpty()) 100 else {
        ((strong.size.toFloat() / passwordItems.size.coerceAtLeast(1)) * 100).toInt()
    }

    Column(Modifier.fillMaxSize()) {
        BrandHeader("SIGURNOST")
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 22.dp)
        ) {
            item {
                GlassCard {
                    Text("Ocjena sigurnosti", color = Muted, fontSize = 14.sp)
                    Row(verticalAlignment = Alignment.Bottom) {
                        Text("$score", color = if (score >= 80) Good else Warn, fontSize = 54.sp, fontWeight = FontWeight.ExtraBold)
                        Text("/100", color = Muted, fontSize = 18.sp, modifier = Modifier.padding(bottom = 10.dp))
                    }
                    LinearProgressIndicator(
                        progress = { score / 100f },
                        modifier = Modifier.fillMaxWidth(),
                        color = if (score >= 80) Good else Warn,
                        trackColor = Color(0xFF203449)
                    )
                    Text(
                        if (score >= 80) "Vaš trezor izgleda dobro zaštićen."
                        else "Pregledajte stavke koje zahtijevaju pažnju.",
                        color = Muted
                    )
                }
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    SummaryCard(strong.size.toString(), "Snažne", Good, Modifier.weight(1f))
                    SummaryCard(weak.size.toString(), "Slabe", Warn, Modifier.weight(1f))
                    SummaryCard(duplicatedIds.size.toString(), "Ponovljene", Danger, Modifier.weight(1f))
                }
            }
            item { SectionTitle("STAVKE KOJE ZAHTIJEVAJU PAŽNJU") }
            items((weak + model.items.filter { it.id in duplicatedIds }).distinctBy { it.id }) { issue ->
                val duplicate = issue.id in duplicatedIds
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
                                if (duplicate) "Lozinka se koristi na više mjesta."
                                else "Lozinka je prekratka i preporučuje se zamjena.",
                                color = Muted,
                                fontSize = 13.sp
                            )
                        }
                        Icon(Icons.Outlined.ChevronRight, null, tint = Ice)
                    }
                }
            }
            if (weak.isEmpty() && duplicatedIds.isEmpty()) {
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
        val current = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
        if (current == text) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) clipboard.clearPrimaryClip()
            else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }, 30_000)
}
