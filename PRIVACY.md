# Privatnost

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
