# Keyra — Full Dead Code Audit

**Datum:** 6. listopada 2026.  
**Polazna verzija:** 0.6.0  
**Repozitorij:** `bren-wp/Keyra`

## Opseg

Audit je obuhvatio:

- Android Kotlin / Jetpack Compose kod
- iOS Swift / SwiftUI kod
- Android Gradle dependencyje
- Android resource datoteke i manifest
- iOS projektne reference i build/analyze izlaz
- GitHub Actions workflowe
- brand i screenshot assete
- sigurnosne i release dokumente
- legacy KEYRA1 / KEYRA2 / Recovery Key putanje

## Metodologija

Provjereni su:

1. deklarirani Kotlin/Swift simboli i njihova stvarna pojavljivanja unutar produkcijskog izvornog koda
2. Compose `remember` stateovi te SwiftUI `@State` / `@Published` vrijednosti
3. Screen enum vrijednosti i navigacijske putanje
4. compiler/lint/analyze upozorenja
5. Android dependencyji prema stvarno korištenim API-jima/importima
6. Android resources prema manifestu, launcheru i Compose kodu
7. svi `assets/brand` i `assets/screens` resursi prema README referencama
8. repozitorij za `TODO`, `FIXME`, `HACK`, stare verzijske reference i branch-era tekst
9. backward-compatibility grane kako se migracijski kod ne bi pogrešno uklonio kao "dead code"

## Uklonjeno / pojednostavljeno

### Android dependency sloj

Uklonjeni su dependencyji koji nisu imali stvarnu produkcijsku uporabu:

- `androidx.lifecycle:lifecycle-viewmodel-compose`
- `androidx.compose.ui:ui-tooling-preview`
- debug `androidx.compose.ui:ui-tooling`

`lifecycle-viewmodel-ktx` zamijenjen je baznim `lifecycle-viewmodel` artefaktom jer Keyra koristi `AndroidViewModel`, ali ne koristi ViewModel KTX ekstenzije poput `viewModelScope`.

`core-ktx` i `fragment-ktx` zamijenjeni su baznim `core` i `fragment` artefaktima jer Keyra koristi `ContextCompat` i `FragmentActivity`, ali ne koristi KTX ekstenzije iz tih paketa.

## Potvrđeno kao aktivno — nije uklonjeno

### Android i iOS glavni kod

Nisu pronađene produkcijske funkcije, Compose screenovi, SwiftUI Viewovi ili store klase koje su deklarirane bez stvarne izvršne putanje.

Posebno su potvrđeni kao aktivni:

- onboarding / unlock / recovery / vault / collections / generator / add / detail / settings / security screenovi
- AuthStore / CryptoStore / VaultStore / EncryptedVault
- TOTP parser, generator i formatting helperi
- card validation helperi
- sigurnosne metrike i security-center putanje
- backup/recovery file picker tokovi
- clipboard backup/import tokovi uklonjeni su iz Settingsa u 0.6.4 jer dupliciraju sigurniji sistemski file-picker tok; clipboard ostaje samo za kratkotrajno kopiranje osjetljivih vrijednosti

### Legacy kompatibilnost

Sljedeći kod je namjerno zadržan jer nije mrtav:

- legacy Android vault migracija na prijenosni vault ključ
- KEYRA1 import
- stariji KEYRA2 Android format
- stariji KEYRA2/iOS timestamp kompatibilnost
- postojeći Recovery Key envelope compatibility checks

Brisanje tih grana prekinulo bi obnovu starijih stvarnih trezora i backupova.

### Swift `FileDocument`

`fileWrapper(configuration:)` može izgledati kao simbol s jednim tekstualnim pojavljivanjem, ali je obavezna implementacija SwiftUI `FileDocument` protokola i zato nije dead code.

## UI state audit

Nisu pronađeni neiskorišteni:

- Compose `remember` / mutable stateovi
- SwiftUI `@State`
- SwiftUI `@Published`

Screen enum vrijednosti na obje platforme imaju stvarne reference i nisu reducirane.

## Resource / asset audit

Android:

- `app_name` koristi manifest
- `Theme.Keyra` koristi manifest
- `keyra_icon_background` koriste adaptive launcher ikone
- `ic_keyra` koriste launcher i Compose brand mark
- launcher i round-launcher resursi koriste se iz manifesta

Repo brand/screenshot asseti:

- svi `assets/brand/*.svg` referencirani su iz README-a
- svi `assets/screens/*.svg` referencirani su iz README-a

Nije pronađen asset koji je sigurno moguće obrisati kao neupotrebljavan.

## Compiler / lint nalazi

Android lint na 0.6.0 nije prijavio unused/dead-code upozorenja.

Xcode build/analyze nije prijavio mrtvi aplikacijski kod. Zabilježena upozorenja odnosila su se na:

- izbor prvog od više odgovarajućih simulator destinationa
- preskočenu AppIntents metadata ekstrakciju jer aplikacija ne koristi AppIntents.framework

To nisu dead-code problemi.

## Dokumentacijski cleanup

U `SECURITY.md` uklonjen je zastarjeli branch-era opis Recovery Key implementacije. Dokument sada razlikuje implementirano u 0.6.0 od još otvorenog stvarnog device/interoperability QA-a.

## Zaključak

Nakon audita Keyra nema dokazano mrtvih produkcijskih screenova, storeova, helper funkcija, stateova ili asseta koje bi bilo sigurno ukloniti bez funkcionalnog gubitka.

Stvarni dead weight pronađen je u Android dependency sloju i uklonjen je. Legacy migracijski i backup kod namjerno je zadržan jer ima aktivnu kompatibilnosnu ili korisničku ulogu.

Svako buduće uklanjanje legacy KEYRA1/KEYRA2 putanja treba raditi tek nakon eksplicitne odluke o minimalno podržanoj migracijskoj verziji, a ne kao običan dead-code cleanup.

## Dopunski pregled — 9. listopada 2026. (0.6.5)

Usporedbom trenutačnih Android i iOS izvora pronađen je preostali clipboard uvoz sigurnosne kopije u **početnom import toku**, izvan Settings ekrana. Zamijenjen je sistemskim odabirom datoteke na obje platforme. Androidov `clearClipboardIfMatches` nakon uklanjanja tog toka više nije imao pozivatelja pa je uklonjen; zasebni `copy` i iOS sensitive clipboard ostaju jer služe kopiranju pojedinačnih tajni.

Provjera izvornog teksta nakon izmjena: nema korisničkih poruka `Kopirajte šifriranu`, `Kopiraj sigurnosnu kopiju`, `Pretražite postavke` ni `Tamni način`; `importNewVault` prima sadržaj odabrane datoteke i na Androidu i na iOS-u. KEYRA1, KEYRA2 i KEYRAREC1 kompatibilnost ostaje. Android manifest ostaje bez `INTERNET` dozvole, uz `allowBackup=false` i `usesCleartextTraffic=false`; iOS privacy manifest ostaje nepromijenjen.

Ovo je **ciljani pregled identificiranih tokova i simbola**, a ne dokaz odsutnosti svakog neiskorištenog simbola; statički lint/analyze i build trebaju proći u CI-ju na završnom SHA-u. Ručno testiranje prvog uvoza na oba uređaja i provjera starijih datoteka ostaju zasebni QA zadaci.

## Re-audit — 13 October 2026 (v0.6.25 candidate)

This pass reviewed the current repository file tree, Android production imports
and Compose UI test dependencies, iOS production imports and SwiftUI protocol
conformances, and the marketing README's asset references. It also preserved
the validated KEYRA1/KEYRA2/KEYRAREC1 migration code.

### Confirmed removable assets

Nine `assets/screens/*.svg` files were static illustrative mock-ups, **not
screenshots captured from the running Android/iOS applications**. The new
marketing README no longer refers to them; all nine have therefore been
removed from this candidate. The three `assets/brand/*.svg` files remain in
use by README branding.

An iOS CI simulator step now captures a fresh, synthetic-data-free onboarding
screenshot, providing a source for genuine future marketing screenshots.
No hand-drawn mock-up is relabeled as a real application screenshot.

### Code and build inspection

- Checked Android production imports for plain unreferenced symbols: none
  identified in the current single Kotlin production source.
- Examined iOS `FileDocument.fileWrapper(configuration:)`: retained as a
  required protocol method, even though it has no direct call site.
- Examined asynchronous recovery/export functions and their SwiftUI call sites:
  retained as active user operations.
- Kept Android Keystore, iOS Keychain and legacy encrypted backup migration
  branches despite their comparatively low invocation frequency.
- Fixed the Android UI test compile regression: using `.text.text` on a
  `String` fails; the actual `SemanticsProperties.EditableText` string is
  accessed through `.text`.
- The Android lint/JUnit/build and iOS build/analyze/Swift/UI suites remain
  mandatory final-SHA checks. Source-occurrence analysis is not a substitute
  for compiler, linker, platform lifecycle or hardware verification.

### Outstanding validation

A complete semantic proof that all runtime/UI/reflection-reachable code is
live or dead is not available from text searches. No uncertain production
method, protocol requirement or backward-compatibility path was deleted based
on name-frequency heuristics. Physical keyboard crash reproduction (#25),
cross-platform device restore, production signing, and store-console submission
are separate release gates.

## 14 October 2026 — v0.6.28 scoped production review

This review compared the current 0.6.27 production Kotlin and Swift sources,
the referenced resource tree and the existing UI/release workflows. It did not
treat low reference frequency as proof of dead code. Existing recovery protocols,
Keychain/Keystore integration, Swift `FileDocument` methods and first-run
fault-injection coverage are intentionally preserved.

**Findings and verified code changes**

- The Android and iOS PDF-report implementations each scanned the entire
  category list repeatedly, once per displayed category. Both now aggregate
  item counts in a **single pass**, preserving the fixed report labels and
  excluding user-created category/type strings from serialized PDF contents.
- Android's original PDF ZIP exporter wrote to the user-selected destination
  inside the same background operation that rendered the report. It now checks
  its authentication epoch, foreground status and Settings screen **after**
  rendering but **before** opening the destination URI. This prevents a
  paused/locked session from initiating a new export.
- Android had `allowBackup=false` and `fullBackupContent=false` but lacked
  an explicit Android 12+ `dataExtractionRules` exclusion for device-to-device
  transfer. This has been added, with a separate CI validator for cloud and
  device-transfer policy. iOS already stores ciphertext with
  `completeFileProtection` and excludes its application-support vault
  directory from backup.
- A genuine first-run **iOS simulator PNG** is now captured before any vault
  or synthetic credentials exist, validated, included in release checksums,
  uploaded as a release asset and referenced by the product README. No
  fabricated screenshot/mock-up files were reintroduced.
- Current production Kotlin and Swift source scans found no diagnostic
  `println`/`NSLog` logging or cleartext password dumps. No production
  function was removed on an unsupported single-reference heuristic.

**Remaining evidence requirements**

The only proof of release-ready compilation is green **Android CI, iOS CI and
the release workflow on the final release SHA**. Cross-device hardware/IME
reproduction (issue #25), Keyra legacy recovery on real Android/iOS devices,
production Play/App Store signing, store-console review and complete per-screen
translations remain outstanding. This static and workflow-scoped audit is not
a formal proof that all runtime-reachable code is free of defects.

## 14 October 2026 — v0.6.29 orphaned-ciphertext import review

- Found a data-preservation gap in both first-run backup import paths. Fresh vault creation correctly refused to overwrite surviving encrypted ciphertext, but the import flow did not enforce the same pre-write policy if its password verifier was missing.
- Android `importNewVault` now rejects surviving ciphertext before any decryption or storage. iOS `importNewVault` applies `RecoveryCiphertextPolicy.allowsFreshVaultCreation` before any storage mutation, guiding the user to explicit Recovery Key restoration.
- New cross-platform CI source-level regression check asserts the guard executes before import decryption and save. Policy tests remain enabled. KEYRA1, KEYRA2, KEYRAREC1 and existing encrypted records are unchanged.
- No speculative deletion of low-reference compatibility functions, cryptographic migration logic or Swift FileDocument methods. Still requires hardware recovery, large-vault and interrupted-write verification, as well as store signing and full 27-language localization.

## 14 October 2026 — v0.6.29 cross-platform code, privacy and UI audit

### Complete current source inventory (static, not a formal reachability proof)

Inspected both main UI/application implementations, Android JUnit and instrumented
tests, iOS policy tests and XCTest UI flows, Gradle dependencies, Xcode project
references, release/CI gates, Android manifests and extraction rules, iOS privacy
manifest, README-brand assets, and public privacy/security documentation.

- Android `MainActivity.kt`: over 6,300 source lines; about 174 declared
  Kotlin functions (including UI composables, lifecycle callbacks and internal
  cryptographic helpers). Import-name screening found no plainly unused
  explicit import. Two low-reference private composables were **false
  positives**: `KeyraTheme` and `GlassCard` use trailing-lambda syntax
  without parentheses and are invoked in live UI code.
- iOS `KeyraApp.swift`: over 6,400 source lines, about 113 declared Swift
  functions, plus `RecoveryCiphertextPolicy.swift`, production FileDocument
  conformances and XCTest files. The textual low-reference scan produced no
  independently verifiable dead private helper. Framework-required methods,
  Objective-C/runtime callbacks, SwiftUI renderers, backup-format fallbacks
  and app launch hooks are not removable based on occurrence count.
- Checked source and resource retention: Android app icon/mipmap resources,
  iOS AppIcon, brand SVGs, iOS PrivacyInfo, extraction rules and existing
  backup migration parsers remain intentionally in place. No unused
  dependency or asset was safely proven removable during this pass.
- No speculative function deletion or mass movement of encryption/persistence
  code: that would risk backward compatibility without device QA and a more
  complete call graph.

### Actual improvements committed to this PR

- Android now uses `SystemClock.elapsedRealtime` for background auto-lock
  instead of adjustable wall-clock time; rejects invalid persisted auto-lock
  values, fails closed on suspicious timer readings, and clears the stale
  timer when explicitly locked. JUnit exercises 30/60/300-second boundaries.
- iOS now uses `ContinuousClock` to measure background duration, rejects
  invalid persisted intervals and enforces complete file protection for the
  pre-existing vault directory as well as newly created directories.
  Failure to apply the directory backup exclusion is no longer swallowed.
- Android imported backup plaintext is decoded as strict UTF-8 after
  successful AEAD verification; malformed authenticated payloads cannot
  silently alter user-supplied text via replacement characters.
- English/Croatian destructive-data warnings, About Keyra links, Brendigo
  attribution and relevant Settings rows are consistent on both platforms.
  The 27-language selector still does **not** imply complete translation
  of every screen; only the existing seven shared core keys have full
  27-language coverage.
- Repeated lookup of shared localized labels now uses immutable
  precomputed key-index mappings on Android and iOS. No external
  library/dependency was added.
- Expanded cross-platform CI privacy gate checks backup transfer,
  the iOS file-protection/exclusion error path and monotonic auto-lock.
  Existing Android build/lint, JVM, emulator and iOS build/analyze/XCTest
  remain the actual runtime verification gates.

### Residual production risks / QA blockers

- Issue #25 still needs a physical-device stack trace or reproduction, not
  just passing simulator password-entry automation.
- Manual screen-by-screen UI QA (small phones, tablets, split screen, large
  fonts, IME interactions, accessibility, RTL) and full 27-locale translation
  are **not** completed by this code audit.
- Legacy KEYRA1/KEYRA2/KEYRAREC1 cross-platform recovery, low-disk failures,
  key loss, full-device restore and background write interruption still
  require real Android/iOS device exercises. External penetration testing
  and instrumented memory inspection are outside CI scope.
- Password-manager security relies on cryptographic correctness and
  migrations; a textual dead-code report must never be represented as
  evidence that all runtime-reachable paths are safe. No PR merge without
  green Android and iOS checks on the same final SHA.

## 14 October 2026 — v0.6.29 follow-up key lifecycle / release integrity

- **Confirmed read-only recovery export risk:** Android `CryptoStore.portableKeyBytes()` and iOS `KeychainVault.rawKeyData()` are allowed to create a key during **new vault initialization**, but were also reused in export-only Recovery Key retrieval. If the original wrapped/keychain key disappears while the session is still accessible, an export could create a fresh unrelated key. The export call sites now use dedicated `existingPortableKeyBytes` / `existingRawKeyData` methods that reject absent or unreadable key material instead of silently replacing it. Android's missing-key requirement is unit-tested; cross-platform source-integrity CI asserts correct wiring.
- **Clipboard lifetime:** foreground manual vault locks revoke the last Keyra-owned clipboard entry immediately when possible, leaving newer third-party clipboard contents untouched. Existing 30-second expiration is retained where platform/background access does not permit instant cleanup.
- **Release supply-chain integrity:** workflow_dispatch version input now enters Bash through environment variables and is checked against strict `MAJOR.MINOR.PATCH` syntax. Release publication is main-only, refuses an existing release or Git tag, checks eight non-empty expected artifacts and verifies both SHA-256 manifests before publication. Previously published archives cannot be overwritten by `--clobber`.
- **Remaining security test gaps:** real-device Keychain/Keystore errors, OS clipboard behavior on backgrounding, legacy migrations, restore failures caused by low storage, manual touchscreen/accessibility QA, and independent penetration testing. These changes are preventive fixes with automated regressions, not proof of zero vulnerabilities.
