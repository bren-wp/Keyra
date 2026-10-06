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

Aktualni razvojni branch uvodi kriptografsku jezgru prijenosnog vault ključa i zajednički `KEYRAREC1` envelope za Android i iOS. Recovery datoteka ne izvozi Android Keystore ili Apple Keychain hardverski/uređajni ključ i nikada ne sadrži vault ključ u plaintextu.

PBKDF2-HMAC-SHA-256 s 600.000 iteracija trenutačno je odabran kao kompatibilni KDF jer obje postojeće platforme već imaju provjerenu zajedničku implementaciju bez dodavanja novog kriptografskog dependencyja. Argon2id ostaje preferirana buduća opcija tek kada bude uvedena održavana, međusobno kompatibilna Android/iOS implementacija i potvrđena migracija formata.

Korisnički export/import ekran, first-run "Imam Recovery Key" tok i end-to-end Android ↔ iOS recovery QA moraju proći prije nego što se Recovery Key smatra release-ready funkcionalnošću.
