# Keyra — Store release checklist

Ovaj dokument prati tehničku spremnost Keyre za Google Play i Apple App Store. Konzole trgovina i njihova pravila mogu se mijenjati, pa prije svakog izdanja treba ponovno provjeriti aktualne obrasce i zahtjeve.

**Posljednja provjera javnih store pravila: 9. listopada 2026.**

## Zajednički release gate

- [ ] Android i iOS CI su zeleni na točnom release commitu.
- [ ] Android release AAB i iOS Release build prolaze bez upozorenja koja utječu na privatnost ili sigurnost.
- [ ] Smoke test na stvarnom Android i iOS uređaju.
- [ ] Novi trezor, otključavanje, biometrija, auto-lock, dodavanje/uređivanje/brisanje i favoriti rade.
- [ ] TOTP kodovi potvrđeni su RFC 6238 testovima i barem jednim stvarnim servisom.
- [ ] Potpuno lokalno brisanje potvrđeno je na stvarnom uređaju i nakon njega se stari trezor više ne može otvoriti.
- [ ] KEYRA2 backup Android → iOS i iOS → Android uspješno je vraćen.
- [ ] KEYRAREC1 Recovery Key Android → iOS i iOS → Android uspješno je verificiran.
- [x] Recovery Key export/import i first-run recovery tok implementirani su na Androidu i iOS-u.
- [ ] Recovery Key export/import i first-run recovery tok provjereni su na stvarnim uređajima.
- [x] First-run recovery koristi sistemski Files/Document picker za Recovery Key i KEYRA2 backup.
- [ ] .keyra izvoz/uvoz kroz sistemski Files/Document picker potvrđen je na stvarnim uređajima.
- [ ] Screenshot/screen-record zaštita ponovno provjerena.
- [ ] Nema demo vjerodajnica, API ključeva, tokena, lozinki ili privatnih testnih podataka u repozitoriju i buildu.
- [ ] PRIVACY.md, SECURITY.md i store deklaracije odgovaraju stvarnom kodu.

## Google Play

### Tehnički

- [x] `targetSdk = 36` za Android 16.
- [x] `compileSdk = 36`.
- [x] AAB se gradi u CI-ju.
- [x] `android:allowBackup="false"` i `android:fullBackupContent="false"`.
- [x] `android:usesCleartextTraffic="false"`.
- [x] Nema široke storage dozvole; datoteke se biraju kroz Storage Access Framework.
- [x] Nema `INTERNET` dozvole u trenutačnoj aplikaciji.
- [x] Nema advertising/analytics SDK-ova.
- [ ] Release potpisivanje konfigurirati izvan repozitorija i uključiti Play App Signing.
- [ ] Pokrenuti Play pre-launch report na release kandidatu.
- [ ] Provjeriti App Bundle Explorer nakon uploada.

### Play Console

- [ ] Privacy Policy URL: javno dostupna verzija `PRIVACY.md`; Google zahtijeva da privacy policy bude dostupan u Play Consoleu i unutar aplikacije te da odgovara stvarnoj obradi podataka. Za produkciju je poželjna stabilna branded HTTPS stranica.
- [ ] Data safety obrazac uskladiti s `docs/PLAY_DATA_SAFETY.md`.
- [ ] Ads: označiti da aplikacija ne sadrži oglase.
- [ ] App access: opisati da aplikacija ne traži Keyra račun; reviewer može izraditi lokalni trezor.
- [ ] Content rating dovršiti i objaviti valjanu ocjenu.
- [ ] Target audience odabrati prema stvarnoj ciljanoj publici.
- [ ] Data deletion pitanja: nema Keyra računa; ako se kasnije uvede account creation, implementirati in-app i web deletion prije objave te verzije.
- [ ] Store listing, ikona, feature graphic, screenshots i opis moraju odgovarati stvarnoj funkcionalnosti.
- [ ] Provjeriti da opis ne tvrdi automatski Proton Drive sync dok takva produkcijska integracija ne postoji.

Google od 31. kolovoza 2026. za nove aplikacije i ažuriranja mobilnih aplikacija zahtijeva ciljanu razinu Android 16 / API 36 ili noviju.

## Apple App Store

### Tehnički

- [ ] Završni CI koristi Xcode 26 ili noviji i iOS 26 SDK ili noviji, kako zahtijevaju aktualna App Store Connect pravila za upload od 28. travnja 2026.
- [x] Release build i simulator launch smoke test postoje u CI-ju.
- [x] `PrivacyInfo.xcprivacy` je dio iOS targeta.
- [x] Privacy manifest prijavljuje `UserDefaults` required-reason API s razlogom `CA92.1`.
- [x] Tracking je deklariran kao isključen i nema deklarirane collected data types u trenutačnom buildu.
- [x] Face ID ima jasan purpose string.
- [x] Sistemskom Files pickeru predaje se već šifrirana .keyra datoteka.
- [x] `ITSAppUsesNonExemptEncryption = NO` postavljen je zato što iOS build koristi Appleove sistemske CryptoKit/CommonCrypto implementacije standardne kriptografije. Prije slanja developer mora potvrditi odgovor kroz App Store Connect export-compliance upitnik za planirane države distribucije.
- [ ] Archive/Validate App proći u Xcodeu s produkcijskim signingom.
- [ ] TestFlight test na stvarnom iPhoneu/iPadu.

### App Store Connect

- [ ] Privacy Policy URL postaviti na javnu, stabilnu HTTPS stranicu.
- [ ] App Privacy: prema trenutačnom buildu Keyra ne prikuplja podatke za developera i ne prati korisnika; prije predaje potvrditi da nisu dodani novi SDK-ovi ili mrežne funkcije te da App Store Connect deklaracija ostaje potpuno usklađena s privacy policyjem.
- [ ] User Privacy Choices URL nije obavezan bez Keyra računa/backenda, ali ga se može dodati uz javnu privacy stranicu.
- [ ] Account deletion nije primjenjiv dok Keyra nema account creation.
- [ ] Export Compliance pitanja odgovoriti točno prema stvarnom buildu i državama distribucije.
- [ ] Age rating, category, description, keywords, screenshots i review notes dovršiti.
- [ ] Review notes objasniti da se trezor izrađuje lokalno i da nije potreban testni račun.
- [ ] Ako reviewer treba testirati biometriju, navesti da je dostupnost ovisna o konfiguraciji simulatora/uređaja.

## Privacy regression gate

Svaka od ovih promjena automatski zahtijeva novu provjeru store deklaracija prije mergea:

- dodavanje `INTERNET` dozvole ili Keyra backenda
- analytics/crash-reporting/ads SDK
- direktni Proton Drive ili drugi cloud SDK
- korisnički računi ili prijava
- push obavijesti
- kamera za QR skeniranje
- kontakti, lokacija, fotografije ili mikrofon
- bilo kakvo slanje podataka iz trezora izvan korisnički pokrenutog izvoza

Ako se uvede prava automatska cloud sinkronizacija, mora biti opt-in, end-to-end šifrirana prije prijenosa, imati jasnu politiku konflikata i brisanja te ažurirane Google Play Data safety i Apple App Privacy deklaracije.


## 0.6.2 security gate
- [x] Android master verifier vezan uz Keystore i legacy verifier migrira tek nakon uspješne prijave.
- [x] iOS master verifier premješten u ThisDeviceOnly Keychain uz constant-time usporedbu.
- [x] Android FLAG_SECURE + overlay protection aktivni.
- [x] iOS privacy shield aktivan za inactive scene i screen capture.
- [x] Backup/Recovery/Erase critical operations koriste owner-auth kada je dostupan.
- [x] Android 0.6.2 CI zelen na završnom commitu.
- [x] iOS 0.6.2 CI zelen na završnom commitu.
- [x] GitHub release v0.6.2 objavljen tek nakon oba release builda.

## 0.6.3 security/privacy parity gate
- [x] Android Recents screenshot blokada implementirana na API 33+ uz postojeći FLAG_SECURE.
- [x] Android obscured-touch zaštita implementirana.
- [x] Android osjetljiva password/recovery polja koriste password keyboard tip.
- [x] iOS privacy shield reagira na willResignActive prije background snapshot faze.
- [x] Security Center ima isti raspored aktivnih zaštita na Androidu i iOS-u.
- [x] Android 0.6.3 CI zelen na završnom commitu.
- [x] iOS 0.6.3 CI zelen na završnom commitu.
- [x] GitHub release v0.6.3 objavljen tek nakon oba release builda.

## 0.6.4 UI/UX simplification gate
- [x] Android/iOS Settings imaju isti informacijski raspored i iste primarne akcije.
- [x] Duplicirani clipboard backup/import uklonjen je iz korisničkog UI-ja; ostaje sistemski file-picker tok.
- [x] Neaktivna "Tamni način — uvijek uključen" stavka uklonjena je.
- [x] Settings pretraga uklonjena je jer više nije potrebna za reducirani broj opcija.
- [x] Vault i Collections više nemaju duplicirani filter izbornik uz već postojeće chipove.
- [x] Collections se zadano otvara na "Sve" i prikazuje puni presjek trezora.
- [x] Duplicirani blok "Nedavne bilješke" uklonjen je iz Collections ekrana.
- [x] Generator preset/duljina/vrste znakova objedinjeni su u jednu postavnu karticu.
- [x] Android 0.6.4 CI zelen na završnom commitu `3fa37b0846f99bef7ee490f41a3d98629cd979a2`.
- [x] iOS 0.6.4 CI zelen na istom commitu.
- [x] GitHub release v0.6.4 objavljen 9. listopada 2026. sa sedam artefakata.

## 0.6.5 accessibility i backup UX gate
- [x] Početni KEYRA2 import na Androidu i iOS-u koristi sistemski file picker; clipboard import uklonjen.
- [x] Trezor i Kolekcije nude jedinstvenu akciju za brisanje filtara kada nema rezultata.
- [x] Prazna lozinka više se ne prikazuje kao snažna; prazna sigurnosna statistika nije lažno označena kao uspješna provjera.
- [x] iOS popis stavki koristi pristupačne gumbe; akcije za dodavanje i sortiranje imaju VoiceOver oznake.
- [x] Zadržani KEYRA1 / KEYRA2 / KEYRAREC1 parseri i postojeće privacy zaštite.
- [x] Android 0.6.5 CI i privacy gate zeleni na PR commitu `73910449c75b58fa4d39949f3ef79ebe7b3d24d7`.
- [x] iOS 0.6.5 CI i privacy gate zeleni na istom PR commitu.
- [x] GitHub release v0.6.5 objavljen nakon uspješnog main CI-ja i release workflowa na `e270387b0c941949dace7d3b01ce1b19f93cdb7e`.
- [ ] Ručni test obnove stare KEYRA1/KEYRA2 kopije i mobilne pristupačnosti na stvarnim uređajima.

## 0.6.6 security scoring i Collections regression gate
- [x] Android i iOS: nedostajuće lozinke prijava i Wi-Fi stavki uključene su u sigurnosna upozorenja i rezultat.
- [x] Ponovljene lozinke i dalje se računaju samo za popunjene vrijednosti; rizični rezultati se ne prikazuju zeleno.
- [x] Lokalna sigurnosna procjena prikazuje ispravne poruke za stavke bez lozinke.
- [x] Trezor i Security Center prikazuju broj rizičnih umjesto samo slabih lozinki.
- [x] Kolekcije ne prikazuju kartice s 0 stavki i imaju akciju za prazan trezor; uvezene kategorije ostaju dostupne.
- [x] Android unit testovi dodani za prazne/ponovljene lozinke i sigurnosni rezultat.
- [ ] Android 0.6.6 lint, unit testovi, build i privacy gate zeleni na završnom PR SHA-u.
- [ ] iOS 0.6.6 build, analyze, simulator smoke i privacy gate zeleni na istom PR SHA-u.
- [ ] GitHub release v0.6.6 sa svim paketima i SHA256SUMS potvrđen nakon mergea i main CI-ja.
- [ ] Ručna provjera na fizičkom Android i iOS uređaju (uvijek ostaje otvorena dok se ne provede).
