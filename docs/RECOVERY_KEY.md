# Keyra Recovery Key

## Status

Ovaj dokument opisuje aktualni Recovery Key sustav. Export/import UI postoji na obje platforme, a first-run tok sada vodi kroz Recovery Key, zasebni KEYRA2 backup i novu glavnu lozinku. Funkcionalnost se i dalje ne smatra release-ready dok cross-platform device QA i završni CI na istom commitu ne budu zeleni.

## Što Recovery Key jest

Recovery Key omogućuje prijenos i ponovno uspostavljanje **vault ključa** bez izvoza Android Keystore ili Apple Keychain uređajnog ključa.

- vault ključ: nasumični 256-bitni ključ kojim se štiti lokalni trezor
- Android: vault ključ je omotan AES-256-GCM ključem iz Android Keystorea
- iOS: vault ključ je spremljen u Apple Keychainu s `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Recovery Key datoteka: zaseban šifrirani omot vault ključa za oporavak
- KEYRA2 backup: zasebna šifrirana kopija **podataka trezora**

Recovery Key **nije backup podataka**.

## Format KEYRAREC1

Tekstualni envelope:

```text
KEYRAREC1.<iterations>.<salt-base64>.<aes-gcm-combined-base64>
```

Trenutačni parametri:

- format version: `KEYRAREC1`
- KDF: PBKDF2-HMAC-SHA-256
- iterations: 600.000
- salt: 16 nasumičnih bajtova
- encryption: AES-256-GCM
- nonce: 12 bajtova, uključen u combined payload
- authentication tag: 16 bajtova
- plaintext unutar envelopea: točno 32 bajta vault ključa
- maksimalna prihvaćena veličina recovery payload-a: 16 KiB

Android i iOS koriste isti format.

## Zašto trenutačno PBKDF2, a ne Argon2id

Argon2id je poželjan memory-hard KDF za recovery passphrase. Trenutačni Keyra kod nema zajedničku, već provjerenu Argon2id implementaciju na obje platforme. Dodavanje različitih ili nedovoljno održavanih crypto biblioteka samo radi ovog koraka povećalo bi supply-chain i interoperability rizik.

Zato je za prvu kompatibilnu verziju odabran postojeći, provjereni PBKDF2-HMAC-SHA-256 put s 600.000 iteracija. Format je verzioniran tako da se kasnije može dodati novi KDF bez reinterpretacije starih datoteka.

## Recovery passphrase

Export zahtijeva najmanje 16 znakova i dodatnu složenost:

- najmanje tri od četiri klase: velika slova, mala slova, brojke, simboli; ili
- najmanje četiri riječi od barem tri znaka.

Passphrase se ne zapisuje u recovery datoteku niti logove.

## Android migracija postojećih trezora

Stari Android trezori šifrirani su izravno Keystore AES ključem. Pri prvom uspješnom otvaranju nakon nadogradnje:

1. postojeći blob se dešifrira starim Keystore ključem
2. generira se novi nasumični 256-bitni prijenosni vault ključ
3. vault se ponovno šifrira prijenosnim ključem
4. prijenosni ključ se AES-GCM omata postojećim Keystore ključem
5. omotani ključ i novi vault blob zapisuju se zajedno
6. tek nakon uspješnog zapisa koristi se novi format

Ako migracija ne uspije, učitavanje se prekida; ne prikazuje se lažno uspješno stanje.

## Import zaštite

Recovery import odbija:

- nepoznatu verziju
- premali ili preveliki kriptografski payload
- KDF iteracije izvan sigurnog podržanog raspona
- neispravan Base64
- pogrešnu passphrase
- izmijenjeni AES-GCM ciphertext/tag
- ključ pogrešne duljine
- recovery ključ koji ne može dešifrirati postojeći lokalni vault

Postojeći lokalni Keychain/Keystore materijal ne zamjenjuje se kandidatom prije uspješne verifikacije postojećeg vaulta.

## Oporavak nakon ponovne instalacije

Ciljani završni tok je:

```text
Ponovno instalirana Keyra
→ Imam Recovery Key
→ odaberi Keyra-Recovery.keyra
→ unesi recovery passphrase
→ verificiraj KEYRAREC1
→ odaberi pripadajući šifrirani KEYRA2 backup
→ unesi lozinku sigurnosne kopije i validiraj backup
→ postavi novu glavnu lozinku za novi uređaj
→ tek nakon pune provjere zaštiti vault ključ novim uređajnim Keychain/Keystore materijalom
→ ponovno šifriraj vraćene zapise prijenosnim vault ključem
→ otvori obnovljeni trezor
```

Recovery Key sam po sebi ne može vratiti zapise koji su fizički izbrisani zajedno s aplikacijom. Za taj scenarij potreban je i KEYRA2 backup ili budući kompletni recovery paket koji sadrži zasebno šifrirane komponente.

## Release gate

Prije označavanja funkcionalnosti spremnom potrebno je najmanje:

- [x] Android export/import UI
- [x] iOS export/import UI
- [x] first-run recovery flow na obje platforme
- Android → iOS KEYRAREC1 interoperability test
- iOS → Android KEYRAREC1 interoperability test
- pogrešna passphrase test
- tampered file test
- oversized/malformed input test
- [x] first-run restore provjerava KEYRAREC1 i KEYRA2 prije trajne izmjene uređajnog stanja
- restore postojećeg aktivnog vaulta bez izmjene prije pune verifikacije
- stvarni device test Keychain/Keystore re-wrappinga
- zelen Android CI i iOS CI na istom završnom commitu
