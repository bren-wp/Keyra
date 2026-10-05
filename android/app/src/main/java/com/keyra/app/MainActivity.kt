package com.keyra.app

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
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

enum class Screen { ONBOARDING, UNLOCK, VAULT, COLLECTIONS, GENERATOR, ADD, DETAIL, SETTINGS }

data class VaultItem(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val username: String = "",
    val password: String = "",
    val website: String = "",
    val notes: String = "",
    val category: String = "Osobno",
    val favorite: Boolean = false,
    val updatedAt: Long = System.currentTimeMillis()
)

class MainActivity : FragmentActivity() {
    private val model: KeyraViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            KeyraTheme {
                KeyraRoot(model = model, requestBiometric = { authenticateBiometric() })
            }
        }
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
    private var sessionPassword: String? = null

    fun startCreate() { screen = Screen.UNLOCK }
    fun open(screen: Screen) { this.screen = screen }
    fun addNew() { selected = null; screen = Screen.ADD }
    fun editSelected() { if (selected != null) screen = Screen.ADD }
    fun select(item: VaultItem) { selected = item; screen = Screen.DETAIL }

    fun createVault(password: String): Boolean {
        if (password.length < 8) {
            message = "Glavna lozinka mora imati najmanje 8 znakova."
            return false
        }
        auth.create(password)
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
        if (!auth.verify(password)) {
            message = "Glavna lozinka nije ispravna."
            return false
        }
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
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Keyra sigurnosna kopija", payload))
        message = "Šifrirana sigurnosna kopija kopirana je u međuspremnik."
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

    private fun loadVault() {
        items.clear()
        items.addAll(store.load())
    }

    private fun seedItems() = listOf(
        VaultItem(title="Google", username="primjer@keyra.app", password="K3yra!Google#2026", website="https://accounts.google.com", notes="Primjer prijave", category="Osobno", favorite=true),
        VaultItem(title="Apple ID", username="primjer@keyra.app", password="Appl3!Keyra#2026", website="https://account.apple.com", category="Osobno"),
        VaultItem(title="GitHub", username="primjer", password="Git#Keyra!90210", website="https://github.com", category="Posao"),
        VaultItem(title="Home Wi‑Fi", username="Dnevni boravak", password="Wifi!Keyra#8821", category="Osobno"),
        VaultItem(title="Netflix", username="primjer@keyra.app", password="K3yra!Google#2026", website="https://netflix.com", category="Zabava"),
        VaultItem(title="Sigurne bilješke", notes="Ovdje možete spremati važne privatne bilješke.", category="Osobno")
    )
}

private class AuthStore(private val prefs: android.content.SharedPreferences) {
    fun isSetup() = prefs.contains("master_hash")

    fun create(password: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs.edit()
            .putString("master_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString("master_hash", derive(password, salt))
            .apply()
    }

    fun verify(password: String): Boolean {
        val salt = prefs.getString("master_salt", null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        val expected = prefs.getString("master_hash", null) ?: return false
        return MessageDigest.isEqual(expected.toByteArray(), derive(password, salt).toByteArray())
    }

    private fun derive(password: String, salt: ByteArray): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, 180_000, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}

private class CryptoStore {
    private val alias = "keyra-vault-key"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
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
                add(
                    VaultItem(
                        id = o.optString("id", UUID.randomUUID().toString()),
                        title = o.optString("title"),
                        username = o.optString("username"),
                        password = o.optString("password"),
                        website = o.optString("website"),
                        notes = o.optString("notes"),
                        category = o.optString("category", "Osobno"),
                        favorite = o.optBoolean("favorite", false),
                        updatedAt = o.optLong("updatedAt", System.currentTimeMillis())
                    )
                )
            }
        }
    }
}

private object PortableBackup {
    fun encrypt(text: String, password: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = derive(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val data = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return listOf(
            "KEYRA1",
            Base64.encodeToString(salt, Base64.NO_WRAP),
            Base64.encodeToString(iv, Base64.NO_WRAP),
            Base64.encodeToString(data, Base64.NO_WRAP)
        ).joinToString(".")
    }

    fun decrypt(payload: String, password: String): String {
        val p = payload.split(".")
        require(p.size == 4 && p[0] == "KEYRA1")
        val salt = Base64.decode(p[1], Base64.NO_WRAP)
        val iv = Base64.decode(p[2], Base64.NO_WRAP)
        val data = Base64.decode(p[3], Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, derive(password, salt), GCMParameterSpec(128, iv))
        return cipher.doFinal(data).toString(Charsets.UTF_8)
    }

    private fun derive(password: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, 180_000, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return javax.crypto.spec.SecretKeySpec(bytes, "AES")
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
        Modifier.size(size).clip(RoundedCornerShape(size * 0.25f))
            .background(Brush.linearGradient(listOf(Cyan, Color(0xFF22BDF7), Indigo)))
            .border(1.dp, Ice.copy(alpha=.5f), RoundedCornerShape(size * 0.25f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(Icons.Outlined.Lock, null, tint = Midnight, modifier = Modifier.size(size * .42f))
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
        Modifier.fillMaxSize().padding(22.dp),
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
        Spacer(Modifier.weight(1f))
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
    val displayed = model.items.filter {
        (filter == "Sve" || it.category == filter || (filter == "Favoriti" && it.favorite)) &&
            (search.isBlank() || it.title.contains(search, true) || it.username.contains(search, true))
    }
    val weak = model.items.count { it.password.isNotBlank() && it.password.length < 12 }
    val duplicated = model.items.groupBy { it.password }
        .filter { it.key.isNotBlank() && it.value.size > 1 }
        .values.flatten().map { it.id }.toSet()

    Column(Modifier.fillMaxSize()) {
        BrandHeader("MOJ TREZOR")
        OutlinedTextField(
            search, { search = it },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp),
            placeholder = { Text("Pretražite svoj trezor...") },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            colors = keyraFieldColors(),
            shape = RoundedCornerShape(24.dp)
        )
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 18.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("Sve","Osobno","Posao","Zabava","Favoriti").forEach {
                FilterChip(selected = filter == it, onClick = { filter = it }, label = { Text(it) })
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
    val stateColor = when {
        duplicated -> Danger
        item.password.isNotBlank() && item.password.length < 12 -> Warn
        else -> Good
    }
    val state = when {
        duplicated -> "Ponovno korištena"
        item.password.isNotBlank() && item.password.length < 12 -> "Ažurirajte"
        else -> "Snažna"
    }
    Surface(
        Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        color = Slate,
        border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(Color(0xFF0B3551)),
                contentAlignment = Alignment.Center
            ) {
                Text(item.title.take(1).uppercase(), color = Cyan, fontSize = 22.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.title, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(item.username.ifBlank { item.category }, color = Muted, fontSize = 13.sp)
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
    Column(Modifier.fillMaxSize()) {
        BrandHeader("MOJ TREZOR")
        Text("Kolekcije", Modifier.padding(horizontal = 18.dp), color = Color.White, fontSize = 42.sp, fontWeight = FontWeight.ExtraBold)
        Text("Organizirajte podatke. Pronađite ih odmah.", Modifier.padding(horizontal = 18.dp), color = Muted, fontSize = 16.sp)
        Spacer(Modifier.height(14.dp))
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
                            Column(Modifier.padding(16.dp)) {
                                Text(name, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                                Text("$count stavki", color = Muted)
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
            items(model.items.filter { it.notes.isNotBlank() }.take(3)) { noteItem ->
                Surface(shape = RoundedCornerShape(18.dp), color = Slate) {
                    Column(Modifier.fillMaxWidth().padding(14.dp)) {
                        Text(noteItem.title, color = Color.White, fontWeight = FontWeight.Bold)
                        Text(noteItem.notes, color = Muted, maxLines = 1)
                    }
                }
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
    val pool = buildString {
        if (upper) append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if (lower) append("abcdefghijklmnopqrstuvwxyz")
        if (numbers) append("0123456789")
        if (symbols) append("!@#$%&*+-_=.?")
    }.ifBlank { "abcdefghijklmnopqrstuvwxyz" }
    val random = SecureRandom()
    return buildString { repeat(length) { append(pool[random.nextInt(pool.length)]) } }
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
    var show by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { model.open(if (original == null) Screen.VAULT else Screen.DETAIL) }) {
                Icon(Icons.Outlined.ArrowBack, null, tint = Color.White)
            }
            Text("Keyra", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        }
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 20.dp)
        ) {
            item {
                Text(if (original == null) "Dodaj prijavu" else "Uredi stavku", color = Color.White, fontSize = 38.sp, fontWeight = FontWeight.ExtraBold)
                Text("Sigurno spremite svoje vjerodajnice", color = Muted)
            }
            item { KeyraTextField(title, { title = it }, "Naslov", Icons.Outlined.Title) }
            item { KeyraTextField(website, { website = it }, "Web-stranica", Icons.Outlined.Link) }
            item { KeyraTextField(username, { username = it }, "Korisničko ime / e-pošta", Icons.Outlined.Person) }
            item {
                KeyraPasswordField(password, { password = it }, show, { show = !show }, "Lozinka")
                TextButton(onClick = { password = generatePassword(18, true, true, true, true) }) {
                    Icon(Icons.Outlined.Refresh, null); Spacer(Modifier.width(5.dp)); Text("Generiraj")
                }
            }
            item { KeyraTextField(notes, { notes = it }, "Bilješke (nije obavezno)", Icons.Outlined.Description, singleLine = false) }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Favorit", color = Color.White, modifier = Modifier.weight(1f))
                    Switch(favorite, { favorite = it })
                }
            }
            item {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("Osobno","Posao","Financije","Zabava","Putovanja","Ostalo").forEach {
                        FilterChip(selected = category == it, onClick = { category = it }, label = { Text(it) })
                    }
                }
            }
            item {
                Button(
                    onClick = {
                        if (title.isBlank()) model.message = "Unesite naslov stavke."
                        else model.saveItem(
                            VaultItem(
                                id = original?.id ?: UUID.randomUUID().toString(),
                                title=title, website=website, username=username, password=password,
                                notes=notes, category=category, favorite=favorite
                            )
                        )
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Midnight),
                    shape = RoundedCornerShape(28.dp)
                ) {
                    Icon(Icons.Outlined.Save, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Spremi", fontWeight = FontWeight.Bold)
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
    var reveal by remember { mutableStateOf(false) }
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { model.open(Screen.VAULT) }) { Icon(Icons.Outlined.ArrowBack, null, tint = Color.White) }
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(current.title, color = Color.White, fontSize = 34.sp, fontWeight = FontWeight.ExtraBold)
                Text("Prijava • ${current.category}", color = Muted)
            }
            if (current.favorite) Icon(Icons.Outlined.Star, null, tint = Warn)
        }
        LazyColumn(
            Modifier.fillMaxSize().padding(horizontal = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 20.dp)
        ) {
            if (current.website.isNotBlank()) item { DetailRow(Icons.Outlined.Link, "Web-stranica", current.website) }
            if (current.username.isNotBlank()) item {
                DetailRow(Icons.Outlined.Person, "Korisničko ime / e-pošta", current.username) {
                    copy(context, current.username); model.message = "Korisničko ime kopirano je."
                }
            }
            if (current.password.isNotBlank()) item {
                DetailRow(Icons.Outlined.Lock, "Lozinka", if (reveal) current.password else "••••••••••••••") {
                    reveal = !reveal
                }
            }
            if (current.notes.isNotBlank()) item { DetailRow(Icons.Outlined.Description, "Bilješke", current.notes) }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedButton(onClick = model::editSelected, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Outlined.Edit, null); Spacer(Modifier.width(5.dp)); Text("Uredi stavku")
                    }
                    OutlinedButton(onClick = model::deleteSelected, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Outlined.Delete, null, tint = Danger); Spacer(Modifier.width(5.dp)); Text("Izbriši", color = Danger)
                    }
                }
            }
        }
    }
}

private fun copy(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Keyra", text))
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
            item { SettingRow(Icons.Outlined.Security, "Provjera sigurnosti", "Pronađite slabe i ponovljene lozinke.") }
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
            item { SettingRow(Icons.Outlined.Info, "O aplikaciji Keyra", "Verzija 0.1.0 • Vaši ključevi. Vaši podaci. Uvijek vaši.") }
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
private fun SettingRow(icon: ImageVector, title: String, subtitle: String, trailing: (@Composable () -> Unit)? = null) {
    Surface(shape = RoundedCornerShape(20.dp), color = Slate, border = androidx.compose.foundation.BorderStroke(1.dp, Ice.copy(alpha=.2f))) {
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
