<div align="center">

<img src="assets/brand/keyra-logo.svg" alt="Keyra" width="460">

# Keyra

### Sigurni upravitelj lozinki za Android i iOS

**Vaši ključevi. Vaši podaci. Uvijek vaši.**

<img src="assets/brand/keyra-icon.svg" alt="Keyra ikona" width="118">

**Bez računa · Bez oglasa · Šifrirani trezor na uređaju**

</div>

---

## Sigurniji način upravljanja lozinkama

Keyra objedinjuje prijave, sigurne bilješke, kartice, identitete i Wi‑Fi podatke u jednom preglednom trezoru. Sučelje prati tamni Keyra identitet s tirkiznim, plavim i indigo naglascima, tankim obrubima i jasnom hijerarhijom.

<div align="center">
<img src="assets/screens/splash.svg" alt="Keyra početni prikaz" width="230">
<img src="assets/screens/onboarding.svg" alt="Keyra dobrodošlica" width="230">
<img src="assets/screens/unlock.svg" alt="Keyra otključavanje" width="230">
</div>

## Ključne mogućnosti

🔐 **Šifrirani trezor** — sadržaj se štiti AES‑256‑GCM enkripcijom.  
🔑 **Glavna lozinka** — provjera koristi PBKDF2‑HMAC‑SHA‑256 s 600.000 iteracija.  
👆 **Biometrijsko otključavanje** — koristi podržanu potvrdu identiteta uređaja.  
🛡️ **Dodatna potvrda za osjetljive radnje** — prikaz i kopiranje tajnih vrijednosti mogu tražiti novu potvrdu identiteta.  
⏱️ **Automatsko zaključavanje** — odmah ili nakon odabranog vremenskog razdoblja.  
🚫 **Zaštita od uzastopnih pokušaja** — ponavljani pogrešni pokušaji privremeno zaustavljaju novo otključavanje.  
📋 **Zaštićeni međuspremnik** — osjetljive kopirane vrijednosti automatski istječu.  
🔎 **Provjera sigurnosti** — prepoznaje slabe i ponovno korištene lozinke.  
✨ **Generator lozinki** — duljina do 64 znaka, vrste znakova i brzi presetovi jačine.  
🔢 **TOTP / 2FA autentifikator** — vremenski kodovi kompatibilni s RFC 6238; podržani su Base32 tajne i `otpauth://totp` URI-jevi.  
📦 **Šifrirana sigurnosna kopija** — izvoz i povrat Keyra trezora uz provjeru formata i ograničenja veličine; KEYRA2 kopije prenosive su između Androida i iOS-a.  
☁️ **Privatni cloud backup** — .keyra datoteka može se spremiti ili otvoriti kroz sistemski Files/Document picker, uključujući kompatibilne privatne cloud providere bez predaje njihovih vjerodajnica Keyri.  
📱 **Prilagodljivo sučelje** — telefoni, veći zasloni, tableti, uspravni i vodoravni prikaz.  
🧯 **Sigurno spremanje** — prikaz podataka mijenja se tek nakon uspješnog trajnog spremanja.

## Moj trezor

Pretraga, tipovi stavki, favoriti, kategorije, sortiranje i sigurnosni sažetak dostupni su odmah nakon otključavanja. Novi trezor počinje prazan i Keyra ne umeće probne vjerodajnice.

<div align="center">
<img src="assets/screens/vault.svg" alt="Moj trezor" width="320">
</div>

## Dodavanje i detalji

Podržane su prijave, bilješke, kartice, identiteti, Wi‑Fi podaci i TOTP autentifikatori. Svaki tip prikazuje samo odgovarajuća polja. Osjetljive vrijednosti ostaju skrivene dok ih korisnik ne odluči prikazati ili kopirati.

Prije spremanja provjeravaju se obavezna i posebna polja, web-adrese se otvaraju samo kroz HTTP/HTTPS, a brisanje uvijek traži potvrdu. Broj kartice dodatno prolazi Luhn provjeru, a datum isteka ne može biti u prošlosti.

<div align="center">
<img src="assets/screens/add-login.svg" alt="Dodavanje prijave" width="280">
<img src="assets/screens/detail.svg" alt="Detalji stavke" width="280">
</div>

## 2FA autentifikator

Keyra može čuvati TOTP tajnu i generirati vremenski jednokratni kod koji se automatski obnavlja. Podržan je ručni unos Base32 tajne ili lijepljenje standardnog `otpauth://totp` URI-ja. Iz URI-ja se mogu preuzeti izdavatelj, račun, algoritam, broj znamenki i vremenski period.

Kod se računa lokalno na uređaju prema RFC 6238, bez slanja TOTP tajne na udaljeni poslužitelj. Podržani su SHA‑1, SHA‑256 i SHA‑512, kodovi od 6 do 8 znamenki te periodi od 15 do 120 sekundi. TOTP tajna ostaje dio šifriranog trezora, a njezin prikaz i kopiranje mogu koristiti dodatnu potvrdu identiteta.

Za ispravne kodove uređaj mora imati točno postavljeno vrijeme. Ako autentifikacija ne prolazi, prvo treba provjeriti automatsku sinkronizaciju vremena operacijskog sustava.

## Generator lozinki

Presetovi **Jednostavna**, **Snažna** i **Maksimalna** omogućuju brz izbor, dok **Prilagodi** daje potpunu kontrolu nad duljinom i vrstama znakova. Generator koristi sigurni izvor slučajnosti platforme i prikazuje procjenu jačine.

<div align="center">
<img src="assets/screens/generator.svg" alt="Generator lozinki" width="320">
</div>

## Kolekcije

Kategorije **Osobno**, **Posao**, **Financije**, **Društvene mreže**, **Kupovina**, **Putovanja**, **Zdravlje** i **Ostalo** otvaraju odgovarajući filtrirani sadržaj trezora. Brojevi stavki dolaze iz stvarnog sadržaja korisničkog trezora.

<div align="center">
<img src="assets/screens/collections.svg" alt="Kolekcije" width="320">
</div>

## Privatni cloud backup

Keyra ne traži korisničko ime ni lozinku za Proton Drive, iCloud Drive, Nextcloud ili drugi cloud servis. Umjesto toga stvara već šifriranu `.keyra` datoteku i predaje je sistemskom odabiru datoteka. Time korisnik sam bira gdje će je spremiti ili iz kojeg će je providera vratiti.

Na iOS-u se koristi standardni Files dokumentni tok. Na Androidu se koristi Storage Access Framework, bez široke dozvole za pristup pohrani. Dostupnost pojedinog providera ovisi o tome je li njegov servis registriran u sistemskom Files/Document sučelju na uređaju.

Izravna automatska Proton Drive sinkronizacija nije ugrađena dok Protonov SDK za komercijalne/produkcijske third-party aplikacije ne bude službeno spreman. To izbjegava neslužbeno rukovanje Proton vjerodajnicama i nestabilne privatne API-je.

## Postavke i sigurnost

Keyra prikazuje samo dostupne mogućnosti: biometrijsko otključavanje, dodatnu potvrdu identiteta, automatsko zaključavanje, provjeru sigurnosti, šifriranu sigurnosnu kopiju i ručno zaključavanje trezora. Zaštita uređaja ne može se uključiti ako platforma nema dostupnu biometriju ili zaključavanje uređaja. Tamni Keyra prikaz dio je stalnog vizualnog identiteta.

Na Androidu je osjetljivi prozor zaštićen od snimanja kada platforma to omogućuje. Na iOS-u Keyra skriva sadržaj kada aplikacija nije aktivna te tijekom aktivnog snimanja zaslona.

<div align="center">
<img src="assets/screens/settings.svg" alt="Postavke i sigurnost" width="320">
</div>

## Sigurnost podataka

- sadržaj trezora šifrira se prije trajnog spremanja
- ključ trezora štiti Android Keystore ili Apple Keychain
- sigurnosna kopija dodatno se šifrira glavnom lozinkom
- KEYRA2 format sigurnosne kopije koristi isti prijenosni format na Androidu i iOS-u
- podržan je uvoz postojećih KEYRA1 i ranijih KEYRA2 kopija s obje platforme
- uvoz koji zamjenjuje trenutačni trezor traži izričitu potvrdu
- oštećena ili prevelika sigurnosna kopija ne zamjenjuje postojeći trezor
- neuspjelo spremanje ne mijenja prikazano stanje kao da je radnja uspjela
- TOTP tajne ostaju u šifriranom trezoru, a vremenski kodovi generiraju se lokalno
- Keyra nema široku storage dozvolu; cloud backup prolazi kroz korisnički odabrani sistemski file provider
- Keyra ne sprema vjerodajnice privatnog cloud servisa
- osjetljive vrijednosti ne zapisuju se u aplikacijske logove
- novi trezor ne sadrži unaprijed umetnute račune ni lozinke

Više pojedinosti nalazi se u [SECURITY.md](SECURITY.md) i [PRIVACY.md](PRIVACY.md).

## Vizualni identitet

| Element | Vrijednost |
|---|---|
| Ponoćna | `#0B0F14` |
| Duboki škriljevac | `#121826` |
| Tirkizna | `#00E5D1` |
| Indigo | `#6366F1` |
| Ledeno plava | `#7DD3FC` |

<div align="center">
<img src="assets/brand/keyra-styleboard.svg" alt="Keyra vizualni identitet" width="100%">
</div>

---

<div align="center">

### Keyra

**Sigurnost za bezbrižniji život.**

Vaši ključevi. Vaši podaci. Uvijek vaši.

</div>
