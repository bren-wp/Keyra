# Apple App Privacy — Keyra

Ovo je tehnička podloga za App Store Connect. Konačni odgovori moraju odgovarati točnom buildu koji se šalje.

## Privacy manifest

iOS target sadrži `PrivacyInfo.xcprivacy`:

- `NSPrivacyTracking = false`
- nema tracking domena
- trenutačno nema deklariranih collected data types
- `UserDefaults` required-reason API deklariran je kao `NSPrivacyAccessedAPICategoryUserDefaults`
- razlog: `CA92.1`, čitanje/pisanje postavki dostupnih samo samoj aplikaciji

Ako se doda SDK koji ima vlastiti privacy manifest ili prikuplja podatke, App Privacy odgovori moraju se ponovno provjeriti.

## Podaci i tracking

Trenutačni iOS build:

- nema Keyra account sustav
- nema Keyra backend
- nema oglase
- nema analytics/tracking SDK
- ne koristi ATT
- ne šalje sadržaj trezora razvojnom programeru
- TOTP se računa lokalno
- .keyra backup šifrira se prije nego što ga korisnik preda Files/cloud provideru

Za App Store Connect to tehnički odgovara modelu "No, we do not collect data from this app", sve dok se prije predaje nije promijenio kod ili dodao third-party SDK koji prikuplja podatke.

## Privacy Policy

App ima in-app poveznicu na javni `PRIVACY.md`. Za produkcijsku objavu preporučuje se stabilna branded HTTPS stranica i ista URL vrijednost u App Store Connectu.

## Account deletion

Apple zahtijeva mogućnost pokretanja brisanja računa unutar aplikacije kada aplikacija podržava account creation. Keyra trenutačno nema account creation, pa ovaj zahtjev nije primjenjiv. Ako se uvede Keyra račun, deletion flow mora biti gotov prije slanja te verzije na review.

## Encryption / export compliance

iOS implementacija koristi standardnu kriptografiju kroz Appleove CryptoKit, CommonCrypto i Keychain API-je. Projekt postavlja `ITSAppUsesNonExemptEncryption = NO` kako bi deklarirao da aplikacija koristi samo oblike enkripcije za koje se ne traži non-exempt dokumentacija.

Developer ipak mora u App Store Connectu odgovoriti na export-compliance pitanja prema točnoj verziji aplikacije i planiranim državama distribucije. Apple može tražiti dodatnu dokumentaciju ovisno o okolnostima distribucije.

## Permissions

- Face ID: koristi jasan `NSFaceIDUsageDescription`
- nema kamere, mikrofona, lokacije, kontakata ni photo-library dozvole u trenutačnom buildu
- Files import/export koristi user-selected document flow

Ako se doda QR skeniranje za TOTP, prije objave treba dodati jasnu camera purpose string deklaraciju i ponovno pregledati App Privacy/purpose-string zahtjeve.

## Review notes

Reviewer treba moći testirati aplikaciju bez računa:

1. pokrenuti Keyru
2. izraditi lokalni trezor s glavnom lozinkom od najmanje 12 znakova
3. dodati prijavu ili TOTP stavku
4. otvoriti Settings za privacy/backup funkcije

Biometrija ovisi o tome je li Face ID/Touch ID/device credential konfiguriran na uređaju ili simulatoru.
