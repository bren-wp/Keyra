# Privacy cloud backup

## Cilj

Keyra treba omogućiti siguran prijenos šifrirane sigurnosne kopije u privacy-oriented cloud servise bez preuzimanja njihovih korisničkih vjerodajnica i bez uvođenja nepotrebnog Keyra backenda.

## Implementirano

### iOS / iPadOS

Keyra koristi standardni SwiftUI document exporter/importer. Korisnik bira lokaciju u Files sučelju. Ako je cloud servis registriran kao File Provider, može se odabrati iz tog sistemskog toka.

Proton Drive ima iOS File Provider/Share integraciju u svojoj službenoj aplikaciji, pa korisnik može koristiti Proton Drive kroz standardni Files tok kada je provider dostupan i prijavljen na uređaju.

### Android

Keyra koristi Storage Access Framework `CreateDocument` / `OpenDocument`. Nisu potrebne broad storage dozvole. Dostupnost pojedinog cloud providera ovisi o njegovoj Android integraciji s dokumentnim pickerom.

Ako provider nije izložen kroz DocumentsUI, korisnik i dalje može spremiti lokalnu šifriranu `.keyra` datoteku i potom je prenijeti službenom aplikacijom providera.

## Kriptografski redoslijed

1. Trezor je već lokalno šifriran.
2. Za portable backup Keyra serializira podatke u provjereni prijenosni model.
3. Backup se dodatno šifrira KEYRA2 formatom koristeći AES-256-GCM i ključ izveden iz glavne lozinke.
4. Tek gotov ciphertext predaje se sistemskom Files/Document provideru.
5. Cloud servis nikada ne dobiva plaintext Keyra trezora iz ovog toka.

## Zašto nema direktnog Proton login/sync koda

Proton Drive SDK je u 2026. javno dostupan, ali Proton navodi da još nije spreman za commercial/production third-party aplikacije i da su Kotlin/Swift integracije još u razvoju. Ugradnja privatnih Proton API-ja ili skupljanje Proton korisničkog imena/lozinke unutar Keyre u ovoj fazi bila bi lošija sigurnosna i produkcijska odluka.

Zato Keyra trenutačno koristi provider-neutralan sistemski file flow. Direktna automatska Proton sinkronizacija može se razmotriti kada Proton službeno proglasi SDK spremnim za third-party production use i kada postoji podržan authentication/session flow.

## Buduća prava sinkronizacija

Prije uvođenja automatske sinkronizacije potrebno je definirati:

- opt-in bez automatskog uključivanja
- end-to-end šifriranje prije mreže
- conflict detection bez tihog prepisivanja novije kopije
- device list i mogućnost opoziva
- jasnu last-sync oznaku i greške
- recovery ako provider nije dostupan
- account/session token zaštitu u OS secure storageu
- brisanje remote kopije i disconnect
- update PRIVACY.md, Google Play Data safety i Apple App Privacy deklaracija
- threat model i cross-platform interop testove
