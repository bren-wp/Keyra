# Keyra — Store release checklist

Ovaj dokument prati tehničku spremnost Keyre za Google Play i Apple App Store. Konzole trgovina i njihova pravila mogu se mijenjati, pa prije svakog izdanja treba ponovno provjeriti aktualne obrasce i zahtjeve.

**Posljednja provjera javnih store pravila: 6. listopada 2026.**

## Zajednički release gate

- [ ] Android i iOS CI su zeleni na točnom release commitu.
- [ ] Android release AAB i iOS Release build prolaze bez upozorenja koja utječu na privatnost ili sigurnost.
- [ ] Smoke test na stvarnom Android i iOS uređaju.
- [ ] Novi trezor, otključavanje, biometrija, auto-lock, dodavanje/uređivanje/brisanje i favoriti rade.
- [ ] TOTP kodovi potvrđeni su RFC 6238 testovima i barem jednim stvarnim servisom.
- [ ] Potpuno lokalno brisanje potvrđeno je na stvarnom uređaju i nakon njega se stari trezor više ne može otvoriti.
- [ ] KEYRA2 backup Android → iOS i iOS → Android uspješno je vraćen.
- [ ] .keyra izvoz/uvoz kroz sistemski Files/Document picker radi.
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
