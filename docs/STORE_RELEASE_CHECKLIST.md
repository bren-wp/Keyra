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
- [x] Android 0.6.6 lint, unit testovi, build i privacy gate zeleni na PR SHA-u `0de4986922e5fc08d97e7028f3fa5d8c22bd0288`.
- [x] iOS 0.6.6 build, analyze, simulator smoke i privacy gate zeleni na istom PR SHA-u.
- [x] GitHub release v0.6.6 sa sedam artefakata i SHA256SUMS potvrđen nakon zelenog main CI-ja na `fe553c535a3ea51d100120abdb7ae321c77e3193`.
- [ ] Ručna provjera na fizičkom Android i iOS uređaju (uvijek ostaje otvorena dok se ne provede).

## 0.6.7 TOTP RFC4648 i sigurnosni brojači
- [x] Android/iOS Trezor prikazuje jedinstveni broj svih rizičnih stavki uključujući ponovno korištene snažne lozinke.
- [x] Android/iOS Base32 parser odbacuje nevaljanu duljinu, neispravan znak =, pogrešan padding i nezero ostatne bitove po RFC 4648.
- [x] Ispravni RFC4648 padded/unpadded TOTP zapisi ostaju prihvaćeni; Android ima regresijske testove.
- [x] iOS generator odmah osvježava lozinku kada korisnik promijeni duljinu klizačem.
- [x] Uvezene kategorije dostupne su u uređivaču; prazan naziv se korisniku prikazuje kao „Bez kategorije”, bez izmjene vrijednosti u trezoru.
- [x] Android 0.6.7 lint, unit, build i privacy gate zeleni na završnom PR SHA-u `53a4223c21a0c08756900800821adbbca5c07f24`.
- [x] iOS 0.6.7 build/analyze, simulator smoke i privacy gate zeleni na istom PR SHA-u.
- [x] Oba main CI-ja zelena i GitHub release v0.6.7 s 7 artefakata objavljen na `0520546e8d1fdda0c953fb6d9663fe9c68f501c7`.
- [ ] Ručni testovi na fizičkim Android/iOS uređajima uključujući stare KEYRA1/KEYRA2 kopije.

## 0.6.8 vlastite kategorije i precizan sigurnosni prikaz
- [x] Android/iOS: unos do 40 znakova omogućuje korisničke kategorije bez poslužitelja ili novog formata trezora.
- [x] Uređivač nudi standardne kategorije te sve postojeće u trezoru, uključujući uvezene.
- [x] Novi unos se trimma i prazan se odbija. Nepromijenjene ili odabrane postojeće uvezene vrijednosti, uključujući duge i prazne nazive, ostaju netaknute.
- [x] Android JUnit testovi pokrivaju ponovne odabire, nazive i očuvanje uvezenih kategorija.
- [x] Detalji prijave uspoređuju ponovno korištenje lozinke samo s prijavama i Wi-Fi stavkama.
- [x] Android 0.6.8 lint, unit, build, privacy uspješni na završnom PR commitu `d2cd30be63a7d714ace0395d85d05e49c27a1895`.
- [x] iOS 0.6.8 build/analyze, simulator launch smoke, privacy uspješni na istom SHA-u.
- [x] Android i iOS main CI te GitHub release workflow uspješni nakon mergea na `a4c89dcc5c78ade3386688c8457de77f51cb9a7f`; 7 artefakata potvrđeno.
- [ ] Ručni QA fizičkih Android/iOS uređaja i KEYRA1/KEYRA2 povrata.

## 0.6.9 2FA i lokalna procjena predvidljivih lozinki
- [x] Android/iOS: neispravni autentifikatori nisu lažno označeni kao „2FA aktivan”, nego su vidljivi u trezoru i sigurnosnim upozorenjima.
- [x] Neispravni TOTP algoritam, broj znamenki ili period iz uvoza i otpauth URI-ja ne zamjenjuju se prešutno zadanim vrijednostima.
- [x] Ocjena 0–100 jasno je ograničena na lozinke; ukupan broj upozorenja uključuje neispravan TOTP.
- [x] Android/iOS: lokalni heuristički test dodatno upozorava na očite predvidljive fragmente i ponovljene znakove. Ne provjerava poznate kompromitirane lozinke online.
- [x] Android regresijski testovi dodani za invalid TOTP, score i predvidljive lozinke.
- [x] Android lint, unit, build, privacy 0.6.9 uspješni na finalnom PR SHA-u `ccf2888dfc6c4f0b205852c4ace7d3875325be0a`.
- [x] iOS build/analyze, simulator launch smoke, privacy 0.6.9 uspješni na istom SHA-u.
- [x] Oba main CI-ja i release workflow uspješni na `61d5cef8b414c35f9f1fcbeb1cc7e694803c601e`; v0.6.9 objavljen sa svih 7 artefakata.
- [ ] Ručni fizički Android/iOS QA i stare KEYRA1/KEYRA2 sigurnosne kopije.

## 0.6.10 kartice, validacija i zaštita unosa
- [x] Android/iOS: automatsko grupiranje broja kartice po četiri znamenke pri uređivanju.
- [x] Stroga Luhnova provjera prihvaća samo ASCII znamenke, razmake i crtice; Unicode znamenke i drugi znakovi odbijaju se umjesto tihog zanemarivanja.
- [x] U šifriranom trezoru broj kartice sprema se kao niz znamenki; zadnje četiri znamenke u popisu ispravno rade i kod grupiranih uvoza.
- [x] Android/iOS: CVV unos skriven je prema zadanim postavkama, postoji prekidač prikaza i brojčana tipkovnica.
- [x] Postojeći neispravni uvezeni brojevi ostaju neizmijenjeni dok se korisnik ne odluči urediti ih.
- [x] Android testovi pokrivaju grupiranje, Unicode/slovna odbijanja, Luhn, sigurnosni kod i uvezene zapise.
- [x] Android CI lint, unit, build, privacy 0.6.10 uspješni na završnom PR SHA-u `ba0f4a33fbc84c516a442a23bcd472df68d41f1f`.
- [x] iOS CI build/analyze, simulator launch smoke, privacy 0.6.10 uspješni na istom SHA-u.
- [x] Oba main CI-ja i release workflow uspješni na `c725eade59215f4b2e3d78a31e35d13e0f817d75`; v0.6.10 objavljen sa svih 7 artefakata.
- [ ] Ručna provjera fizičkih Android/iOS uređaja i obnove starijih KEYRA1/KEYRA2 kopija.

## 0.6.11 stroga obrada autentifikatora i otporniji TOTP
- [x] Android/iOS: duplicirani otpauth URI parametri odbijaju se umjesto tihog prepisivanja, uz usporedbu naziva bez razlike velikih i malih slova.
- [x] Otpauth URI adrese odbijaju nevaljanu strukturu, korisničke podatke u authority dijelu, port i fragment.
- [x] Base32 i otpauth ulazi imaju gornje granice duljine radi zaštite memorije i vremena parsiranja.
- [x] Generiranje TOTP koda validira algoritam, interval, broj znamenki i vrijeme; neispravna konfiguracija ne ruši aplikaciju.
- [x] Android JUnit regresijski testovi dodani za duplicirane URI parametre, velika polja, pogrešne periode i postojeći RFC 6238 vektor.
- [x] Android lint/unit/build/privacy na završnom PR SHA-u `7f38cfd1bf4b05688379f1718373ac29b80ed390` uspješni.
- [x] iOS build/analyze/simulator launch smoke/privacy na istom PR SHA-u uspješni.
- [x] Android/iOS main CI i release workflow uspješni na `e9732842267622a07a3cdb55bcc55dd640168e2d`; v0.6.11 objavljen sa svih 7 artefakata.
- [ ] Ručni testovi na stvarnim Android/iOS uređajima i povrat KEYRA1/KEYRA2 kopija.

## 0.6.12 upozorenja za istekle kartice
- [x] Android/iOS: valjan datum kartice u aktualnom ili budućem mjesecu ne stvara upozorenje, a prošli ili neispravan datum stvara.
- [x] Kartice bez upisanog datuma ne označavaju se kao istekle.
- [x] Trezor i detalji kartice prikazuju „Provjeri istek”, a Sigurnosni centar navodi konkretne kartice koje treba ažurirati.
- [x] Brojač rizičnih stavki uključuje istekle kartice; ocjena 0–100 ostaje ograničena na lozinke.
- [x] Android regresijski testovi pokrivaju prethodni/aktualni/budući mjesec, loše i prazne datume, broj upozorenja i ocjenu lozinki.
- [x] Android lint/unit/build/privacy 0.6.12 uspješni na završnom PR SHA-u `7ba93d4a8f28bc3ecdb17a6f99eaec6ad717b4c5`.
- [x] iOS build/analyze/simulator smoke/privacy 0.6.12 uspješni na istom SHA-u.
- [x] Oba main CI-ja i release workflow uspješni na `5917115dc7d88c2830e8868bff1c60d2b90673a4`; izdanje v0.6.12 ima svih 7 paketa.
- [ ] Fizički Android/iOS QA i obnove KEYRA1/KEYRA2 sigurnosnih kopija.

## 0.6.13 jednostavniji početak, stabilnost i pravne stranice
- [x] Android/iOS: početna stranica ne skrola; uklonjene tri promotivne kartice, a visina dizajna prilagođava se manjim zaslonima.
- [x] Uklonjena promotivna oznaka LOCAL i nepotrebni tehnički izrazi iz vidljivih tekstova i postavki.
- [x] Android/iOS: zvonce vodi u Sigurnosni centar, profil u Postavke.
- [x] Pravila privatnosti, Uvjeti korištenja i O aplikaciji vode na zadane /keya/ adrese.
- [x] Android/iOS: izrada, otključavanje i uvoz trezora izdvojeni iz glavne UI niti uz blokiranje dvostrukih zahtjeva, status i poruke za neuspjeh.
- [ ] Potvrditi vanjsku dostupnost sve tri pravne stranice na poslužitelju (ovaj repozitorij ih ne objavljuje).
- [ ] Android lint/unit/build/privacy uspješni na završnom PR SHA-u.
- [ ] iOS build/analyze/simulator launch smoke/privacy uspješni na istom SHA-u.
- [x] Android/iOS main CI i release workflow uspješni na `cf9285af4428463add4f3e65679be167b2da0729`; v0.6.13 sa svih 7 artefakata.
- [ ] Klik-po-klik QA na fizičkim Android/iOS uređajima: soft keyboard, izrada, otključavanje, pogrešna lozinka, uvoz/recovery, kratki i visoki zasloni, zvonce/profil i vanjske poveznice.

## 0.6.14 potpuno brisanje i unos glavne lozinke
- [x] Android: potpuno brisanje poziva i AuthStore.clear() za Keystore ključ provjere glavne lozinke te zasebno provjerava rezultat.
- [x] iOS: AuthStore.clear() vraća rezultat brisanja verifikatora iz Keychaina; postupak brisanja ne prijavljuje lažni uspjeh ako taj korak ne uspije.
- [x] Android/iOS: novi unos glavne lozinke i potvrde ograničen je na 256 znakova te ima kratku uputu o 12 znakova; postojeća lozinka pri otključavanju i importu ne mijenja se.
- [x] Android JUnit testovi za ograničenje unosa i nepromijenjene kraće vrijednosti.
- [ ] Android lint/unit/build/privacy uspješni na završnom PR SHA-u.
- [ ] iOS build/analyze/simulator launch smoke/privacy uspješni na istom PR SHA-u.
- [ ] Android/iOS main CI i release workflow uspješni; v0.6.14 objavljen sa 7 artefakata.
- [ ] Fizički Android/iOS QA, provjera tipkovnice/IME, izrada trezora i potpunog brisanja s provjerom KeyStore/Keychain unosa.
- [ ] Potvrda dostupnosti vanjskih pravnih stranica app.brendigo.com/keya.

## 0.6.15 sigurnost asinkronog otključavanja
- [x] Android/iOS: svaki zahtjev za otključavanje povezan je s generacijom autentifikacijske sesije; rezultat se odbacuje ako je aplikacija otišla u pozadinu ili je trezor naknadno zaključan.
- [x] Android/iOS: dovršetak izrade ili uvoza trezora u pozadini sprema šifrirani trezor, ali ga ne otvara bez nove korisničke autentifikacije.
- [x] Android/iOS: biometrijski rezultat ne može otvoriti trezor nakon zastarjele sesije.
- [x] Android regresijski testovi pokrivaju završetak u valjanoj sesiji, pozadinu i zastarjeli zahtjev.
- [ ] PR Android lint/unit/build/privacy potvrđen na završnom SHA-u.
- [ ] PR iOS build/analyze/simulator launch/privacy potvrđen na istom SHA-u.
- [ ] Oba main CI-ja i release workflow uspješni, release v0.6.15 sa sedam artefakata provjeren.
- [ ] Ručni testovi na fizičkim Android i iOS uređajima: typing, prikaz tipkovnice, izrada trezora, zaključavanje u pozadini tijekom PBKDF2, biometrija, stare KEYRA1/KEYRA2 kopije.
- [ ] Potvrđena dostupnost vanjskih pravnih stranica na app.brendigo.com/keya.

## 0.6.16 recovery responsiveness, bounded imports and English README

- [x] Android: first-run recovery validation/decryption/key installation moved off the UI thread, with recovery-in-progress state, single-request guard, progress feedback, and lock-on-background completion.
- [x] iOS: first-run recovery validation/decryption/key installation moved off the UI thread, with matching progress feedback, cancellation guard, and stale-session protection.
- [x] iOS: five external document import paths read a bounded number of bytes before decoding UTF-8, rather than mapping a potentially oversized file.
- [x] Android: malformed UTF-8 backup bytes are rejected; password input truncation does not split a UTF-16 surrogate pair.
- [x] Android JUnit regression tests cover invalid UTF-8 and input boundaries.
- [x] Main GitHub README rewritten in English, retaining verified Keyra visual assets and accurate unsigned-artifact guidance.
- [ ] Android PR CI lint/unit/build/privacy success on final commit.
- [ ] iOS PR CI build/analyze/simulator launch/privacy success on the same final commit.
- [ ] Both main CI checks and release workflow success, seven v0.6.16 assets verified.
- [ ] Physical Android/iOS interactive QA: initial password typing and keyboard, full recovery, imported older KEYRA1/KEYRA2 backups, auto-lock in background, TOTP and biometric access.
- [ ] Legal URLs validated on a real device; store signing and distribution readiness independently verified.

## 0.6.17 protected actions and settings polish

- [x] Android: snapshot biometric request epoch, screen and selected item; ignore stale callback after background, lock, navigation or item change.
- [x] iOS: guard sensitive and critical owner-auth callbacks with an active matching session, screen and selected item; also protect no-prompt fallbacks.
- [x] Android JUnit regression tests cover invalidated sensitive authorizations.
- [x] Both platforms: About section reads the installed application version, not a hard-coded obsolete version.
- [x] Unlock UI: progress feedback and accessible show/hide password control names.
- [ ] Android PR lint/unit/build/privacy CI passes for final branch commit.
- [ ] iOS PR build/analyze/simulator launch/privacy CI passes for the same commit.
- [ ] Both main CI runs and release workflow pass and all seven v0.6.17 assets are verified.
- [ ] Physical-device testing: #25 master-password typing crash, biometrics, backup import/export, erase, recovery and accessibility.
- [ ] Store signing, distribution readiness and full end-to-end testing on physical Android and iOS devices.

## 0.6.18 async Settings backups and clipboard privacy

- [x] Android: Settings backup export performs PBKDF2 encryption and document writes on IO dispatcher; progress state and duplicate-operation guard added.
- [x] Android: Settings backup import reads and decrypts on IO dispatcher; main-thread commit only when the original authenticated session and Settings screen are still active.
- [x] iOS: Settings backup encrypt/decrypt performed off main thread; UI commit guarded by authentication epoch, foreground and screen state.
- [x] Both apps: progress feedback and import/export buttons disabled during ongoing backup operations.
- [x] Android: clear Keyra-owned clipboard content on activity pause and after 30 seconds when OS permits; do not clear a different clipboard value.
- [x] Android JUnit coverage for clipboard ownership comparison.
- [ ] Android and iOS PR CI succeed on exact final branch commit.
- [ ] Both main CI workflows and release succeed on merge commit; verify seven v0.6.18 assets.
- [ ] Physical Android/iOS QA of large encrypted backup round trips, lifecycle changes mid-import, automatic locking, clipboard and OS file providers.
- [ ] Reproduce and fix #25 keyboard crash on physical devices; check passwords with accents, emoji, paste, visibility toggle, IME focus and orientation.
- [ ] Verify distribution signing, store packaging and end-to-end accessibility on supported physical devices.

## 0.6.19 external paste usability and async Recovery Key

- [x] Android: preserve Keyra-owned clipboard text when changing applications so users can paste copied credentials externally; retain sensitive clipboard labeling and timed best-effort clearing (subject to Android background clipboard limitations).
- [x] Both platforms: Settings Recovery Key PBKDF2 encryption/decryption moved off the UI thread.
- [x] Both platforms: background recovery results are ignored after vault lock, erase, backgrounding or navigation; recovery operations have a dedicated processing indicator.
- [x] Both platforms: encrypted backup operations cannot start during ongoing Recovery Key work.
- [ ] Physical Android QA: copy a password, switch to another app, paste within 30 seconds; confirm expiration where OS supports it, and ensure unrelated clipboard contents stay intact.
- [ ] Physical Android/iOS QA: open system document picker, import/export Recovery Key and KEYRA2 backup with immediate auto-lock enabled; test background/lock before KDF completes.
- [ ] Android PR lint/unit/build/privacy and iOS PR build/analyze/simulator/privacy both succeed on final commit.
- [ ] Android/iOS main CI, release workflow, and seven v0.6.19 assets independently verified.
- [ ] Issue #25 master-password entry crash reproduced, diagnosed and fixed on physical devices (not yet confirmed).
- [ ] Production signing / App Store and Play Store readiness independently verified.
