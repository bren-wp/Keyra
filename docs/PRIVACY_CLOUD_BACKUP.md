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

Protonovi službeni materijali u 2026. opisuju Drive SDK kao zajedničku osnovu koja pokreće njihove Drive aplikacije te navode da će s vremenom olakšati integracije vanjskim alatima. Trenutačna javna dokumentacija ne daje Keyri stabilan, službeno dokumentiran third-party produkcijski login/storage tok koji bi bilo razumno ugraditi izravno. Ugradnja privatnih Proton API-ja ili skupljanje Proton korisničkog imena/lozinke unutar Keyre zato se namjerno izbjegava.

Zato Keyra trenutačno koristi provider-neutralan sistemski file flow. Direktna automatska Proton sinkronizacija može se razmotriti kada Proton javno dokumentira podržan third-party authentication/session i file-storage API/SDK s uvjetima prikladnima za produkcijsku mobilnu aplikaciju.

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
