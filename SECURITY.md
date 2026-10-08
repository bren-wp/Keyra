# Sigurnost

Ako pronađete sigurnosni problem u Keyri, nemojte ga javno objavljivati dok se problem ne riješi.

Prijavite problem vlasniku repozitorija kroz privatni sigurnosni kanal na GitHubu. U prijavi navedite što ste primijetili, kako se problem može ponoviti i koje bi posljedice mogao imati.

Stvarne lozinke, pristupne ključeve i privatne sigurnosne kopije nemojte prilagati prijavi.


## Sigurnosni model

- sadržaj trezora šifrira se autentificiranom AES-256-GCM enkripcijom
- trezor koristi prijenosni 256-bitni vault ključ; na Androidu se taj ključ lokalno omata AES-GCM ključem iz Android Keystorea, a na iOS-u se čuva u Apple Keychainu s `ThisDeviceOnly` zaštitom
- glavna lozinka obrađuje se PBKDF2-HMAC-SHA-256 derivacijom s 600.000 iteracija
- novi trezor zahtijeva glavnu lozinku od najmanje 12 znakova
- uzastopni pogrešni pokušaji otključavanja uvode privremeno zaključavanje
- osjetljivi prikaz i kopiranje mogu zahtijevati dodatnu potvrdu identiteta
- TOTP tajne čuvaju se unutar šifriranog trezora; kodovi se računaju lokalno prema RFC 6238 bez slanja tajne na udaljeni poslužitelj
- TOTP podržava HMAC-SHA-1, HMAC-SHA-256 i HMAC-SHA-512 s kontroliranim brojem znamenki i periodom
- izvoz u cloud počinje tek nakon lokalnog šifriranja KEYRA2 kopije; Keyra ne preuzima vjerodajnice cloud servisa
- Android koristi sistemski Storage Access Framework bez široke storage dozvole, a iOS koristi sistemski Files dokumentni tok
- biometrijska / uređajna potvrda može se uključiti samo kada je podržana i konfigurirana na uređaju
- spremanje trezora mora uspjeti prije nego što aplikacija prikaže novo stanje kao spremljeno
- Android onemogućuje snimanje osjetljivog prozora, a iOS skriva sadržaj tijekom aktivnog snimanja zaslona
- sigurnosne kopije imaju ograničenje veličine i broja stavki prije prihvaćanja uvoza
- KEYRA2 sigurnosne kopije koriste zajednički Android/iOS AES-256-GCM format i prijenosni model podataka
- `KEYRAREC1` Recovery Key datoteka zasebno štiti samo prijenosni vault ključ: AES-256-GCM + PBKDF2-HMAC-SHA-256 s 600.000 iteracija, 16-bajtnom soli i autentificiranim integritetom; ne sadrži zapise trezora niti sirovi ključ
- recovery datoteka i recovery lozinka nisu zamjena za šifriranu KEYRA2 sigurnosnu kopiju podataka; za potpuni oporavak nakon gubitka uređaja korisnik treba sačuvati i podatkovni backup
- Android trezori nastali prije prijenosnog vault ključa migriraju se tek nakon uspješnog dešifriranja postojećim Keystore ključem, a novi omotani ključ i ponovno šifrirani blob spremaju se zajedno prije nastavka
- podržano je čitanje postojećih KEYRA1 i starijih KEYRA2 formata s obje platforme
- zamjena postojećeg trezora uvozom traži izričitu korisničku potvrdu
- oštećena sigurnosna kopija ne zamjenjuje postojeći trezor
- trezor se zaključava prema odabranoj politici automatskog zaključavanja
- korisnik može pokrenuti potpuno lokalno brisanje trezora, auth podataka, postavki i uređajnog kriptografskog ključa

Sigurnosne tvrdnje odnose se na implementirani model zaštite i ne znače da je bilo koji softver apsolutno neprobojan.


## Recovery Key — granice trenutne implementacije

Keyra 0.6.0 uključuje kriptografsku jezgru prijenosnog vault ključa, zajednički `KEYRAREC1` envelope za Android i iOS, korisnički export/import ekran te first-run tok **Imam Recovery Key**. Recovery datoteka ne izvozi Android Keystore ili Apple Keychain hardverski/uređajni ključ i nikada ne sadrži vault ključ u plaintextu.

PBKDF2-HMAC-SHA-256 s 600.000 iteracija trenutačno je odabran kao kompatibilni KDF jer obje platforme imaju zajedničku implementaciju bez dodavanja novog kriptografskog dependencyja. Argon2id ostaje preferirana buduća opcija tek kada bude uvedena održavana, međusobno kompatibilna Android/iOS implementacija i potvrđena migracija formata.

Preostali release gateovi za potpuno označavanje Recovery Key funkcionalnosti kao provjerene odnose se na stvarni Android ↔ iOS device interoperability, Keychain/Keystore re-wrapping na fizičkim uređajima i store-signing/device QA.


## 0.6.2 privacy/security hardening

- Android master-password verifier više se ne sprema čitljivo kao salt/hash u običnom SharedPreferences storageu. Novi `KEYRAAUTH1` verifier šifriran je zasebnim Android Keystore AES-GCM ključem s `setUnlockedDeviceRequired(true)` gdje platforma podržava tu zaštitu.
- iOS master-password verifier premješten je iz UserDefaults u zaseban Data Protection Keychain zapis s `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- Postojeći 0.6.x verifieri migriraju se tek nakon uspješne provjere glavne lozinke; ne postoji silent migration bez autentikacije.
- Usporedba iOS password verifiera koristi constant-time byte comparison.
- Android blokira screen capture preko `FLAG_SECURE` i od Androida 12 skriva app prozor od overlay prozora preko `setHideOverlayWindows(true)`.
- iOS skriva Keyra sadržaj u app switcheru, pri neaktivnoj sceni i tijekom aktivnog screen capturea.
- Backup export/import, Recovery Key export/import i trajno brisanje lokalnog trezora traže device-owner autentikaciju kada je uređaj može pružiti, neovisno o opcionalnom toggleu za svakodnevne sensitive akcije.

## 0.6.3 privacy/security parity hardening

- Android 13+ eksplicitno isključuje screenshot koji bi sustav koristio kao prikaz aplikacije u Recents/Overview preko `setRecentsScreenshotEnabled(false)`, uz postojeći `FLAG_SECURE`.
- Android root view odbacuje touch događaje kada je prozor obscured, kao dodatnu zaštitu od tapjacking/overlay scenarija.
- Android password/recovery polja označena su kao password input prema IME-u, uz postojeće maskiranje vrijednosti.
- iOS privacy shield aktivira se već na `UIApplication.willResignActiveNotification`, prije nego aplikacija potpuno prijeđe u neaktivno/background stanje, a ponovno se uklanja tek nakon `didBecomeActive`.
- Android i iOS Security Center prikazuju isti blok aktivnih zaštita: lokalni šifrirani trezor, zaštitu zaslona, privremeni međuspremnik i potvrdu kritičnih radnji.
- Android osjetljivi clipboard i dalje je označen kao sensitive na podržanim verzijama i čisti se nakon 30 sekundi; iOS clipboard ostaje `localOnly` s istim rokom od 30 sekundi.
