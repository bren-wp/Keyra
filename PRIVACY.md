# Privatnost

Keyra je osmišljena tako da se osjetljivi podaci čuvaju šifrirani na uređaju.

Za korištenje trezora nije potreban račun. Keyra ne prikazuje oglase i ne zahtijeva slanje sadržaja trezora na udaljene poslužitelje.

Sadržaj trezora šifrira se prije spremanja. Ključ uređaja čuva se kroz sigurnosni spremnik operacijskog sustava, a glavna lozinka ne sprema se u čitljivom obliku.

Korisnik može uključiti dodatnu potvrdu identiteta prije prikaza ili kopiranja osjetljivih podataka. Međuspremnik za osjetljive vrijednosti ograničen je i automatski se čisti kada platforma to podržava.

Korisnik sam upravlja sigurnosnim kopijama, uvozom i izvozom svojih podataka. Sigurnosne kopije koje izrađuje Keyra dodatno su šifrirane glavnom lozinkom.

Ako korisnik spremi TOTP / 2FA autentifikator, TOTP tajna ostaje dio šifriranog trezora. Vremenski kod izračunava se lokalno na uređaju i za njegovo generiranje nije potrebno slati TOTP tajnu udaljenom poslužitelju.

Keyra ne umeće probne vjerodajnice u novi trezor.
