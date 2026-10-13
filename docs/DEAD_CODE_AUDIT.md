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
