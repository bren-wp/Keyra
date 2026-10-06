# Pravila privatnosti — Keyra

**Razvojni programer / publisher:** Brendigo  
**Kontakt za privatnost:** info@brendigo.com  
**Posljednje ažuriranje:** 6. listopada 2026.

Keyra je osmišljena tako da se osjetljivi podaci čuvaju šifrirani na uređaju.

Za korištenje trezora nije potreban Keyra račun. Keyra ne prikazuje oglase, ne sadrži oglasne ni analitičke SDK-ove i ne zahtijeva slanje sadržaja trezora razvojnom programeru ili Keyra poslužitelju.

Sadržaj trezora šifrira se prije spremanja. Ključ uređaja čuva se kroz sigurnosni spremnik operacijskog sustava, a glavna lozinka ne sprema se u čitljivom obliku.

Korisnik može uključiti dodatnu potvrdu identiteta prije prikaza ili kopiranja osjetljivih podataka. Međuspremnik za osjetljive vrijednosti ograničen je i automatski se čisti kada platforma to podržava.

Korisnik sam upravlja sigurnosnim kopijama, uvozom i izvozom svojih podataka. Sigurnosne kopije koje izrađuje Keyra dodatno su šifrirane glavnom lozinkom. Korisnik može spremiti `.keyra` datoteku kroz sistemski Files/Document picker u lokalnu pohranu ili kompatibilni cloud provider. Keyra pri tome ne prima niti pohranjuje korisničko ime, lozinku ili pristupni token cloud servisa. Odabrani cloud provider zasebno obrađuje datoteku prema vlastitim pravilima privatnosti.

Ako korisnik spremi TOTP / 2FA autentifikator, TOTP tajna ostaje dio šifriranog trezora. Vremenski kod izračunava se lokalno na uređaju i za njegovo generiranje nije potrebno slati TOTP tajnu udaljenom poslužitelju.

Keyra ne umeće probne vjerodajnice u novi trezor.


## Podaci koje Keyra ne prikuplja

U trenutnoj implementaciji Keyra nema vlastiti mrežni backend niti dozvolu za mrežni pristup na Androidu, ne koristi oglašavanje, analitiku, identifikatore za praćenje, lokaciju, kontakte, mikrofon ni fotografije. Sadržaj trezora, glavna lozinka i TOTP tajne ne šalju se razvojnom programeru.

Ako se u budućnosti uvede opcionalna mrežna sinkronizacija koju pruža Keyra, ova pravila privatnosti i deklaracije u Google Playu/App Storeu moraju se ažurirati prije objave te funkcije.


## Zadržavanje podataka

Lokalni sadržaj trezora ostaje na uređaju dok ga korisnik ne izbriše pojedinačno, ne pokrene potpuno lokalno brisanje ili ne ukloni aplikaciju uz ponašanje pohrane koje određuje operacijski sustav. Keyra ne održava serversku kopiju trezora. Vanjske šifrirane `.keyra` kopije zadržava lokacija ili cloud provider koji je korisnik sam odabrao, prema pravilima tog providera i korisnikovim postavkama.

## Razvojni programer i kontakt

Za pitanja o privatnosti, sigurnosti ili načinu obrade podataka korisnik se može javiti na **info@brendigo.com**. Ova pravila odnose se na aplikaciju **Keyra** koju objavljuje **Brendigo**.

## Brisanje lokalnih podataka

U postavkama postoji radnja **Izbriši sve lokalne podatke**. Ona uklanja lokalni trezor, podatke za provjeru glavne lozinke, lokalne sigurnosne postavke i uređajni ključ šifriranja te vraća aplikaciju na početni onboarding. Vanjske `.keyra` kopije koje je korisnik prethodno spremio u Files ili cloud provider nisu pod kontrolom Keyre i ne brišu se tom radnjom.


## Dodatno očvršćivanje u verziji 0.6.2

Keyra i dalje ne koristi oglašavanje, analitiku, tracking SDK-ove, crash-reporting servise ni vlastiti backend. Master-password verifier dodatno je vezan uz uređaj: Android ga štiti Android Keystore ključem, a iOS ga sprema u `ThisDeviceOnly` Data Protection Keychain. To smanjuje vrijednost kopiranog app-data direktorija za offline napad na glavnu lozinku.

Kritični izvoz/uvoz sigurnosnih kopija i Recovery Key datoteka te trajno brisanje podataka koriste device-owner potvrdu kada je dostupna. Clipboard ostaje local-only/privremeni kanal i automatski se čisti.
