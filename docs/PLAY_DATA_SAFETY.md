# Google Play Data safety — Keyra

Ovo je tehnička podloga za ispunjavanje Play Console Data safety obrasca. Konačne odgovore u Play Consoleu treba provjeriti prema točnom buildu koji se šalje.

## Trenutačni model podataka

Keyra je lokalni password manager i TOTP autentifikator bez Keyra korisničkog računa i bez Keyra mrežnog backenda.

Trenutačni Android manifest:

- nema `INTERNET` dozvolu
- koristi samo `USE_BIOMETRIC` za lokalnu potvrdu identiteta
- nema broad storage/read-media dozvole
- backup datoteku bira korisnik kroz Storage Access Framework
- nema advertising ID, analytics ili ads SDK

## Data collection / sharing

Za trenutačni build tehnička implementacija ne šalje sadržaj trezora, glavnu lozinku, TOTP tajne, identifikatore, lokaciju ili usage analytics razvojnom programeru.

Kada korisnik izričito odabere spremanje .keyra datoteke u cloud kroz sistemski picker, Keyra lokalno izradi šifriranu KEYRA2 datoteku i predaje je odabranom OS/provider sučelju. Keyra ne prima vjerodajnice cloud providera i nema svoj poslužitelj u tom toku.

Google Play traži da Data safety odgovori budu potpuni, točni i usklađeni s privacy policyjem. Ako se tumačenje user-directed transfera kroz third-party document provider ili formular promijeni, odgovor u konzoli treba prilagoditi tada važećim definicijama. Ne treba automatski kopirati ovaj dokument bez provjere obrasca.

## Security practices

- AES-256-GCM za sadržaj trezora i portable backup
- PBKDF2-HMAC-SHA-256 za derivaciju iz glavne lozinke
- Android Keystore za lokalni uređajni ključ
- `FLAG_SECURE` protiv screenshots/screen recording gdje ga Android poštuje
- automatsko zaključavanje
- rate limiting pogrešnih pokušaja otključavanja
- dodatna biometrijska/device-credential potvrda za osjetljive radnje
- osjetljivi clipboard označen je kao sensitive na podržanim Android verzijama i automatski se čisti
- Android backup sustava je isključen
- cleartext mrežni promet je isključen
- .keyra cloud backup šifrira se prije predaje provideru

## Account deletion

Keyra trenutačno nema account creation. Googleov zahtjev za in-app i web account deletion aktivira se ako se u budućnosti uvede Keyra račun. Takva verzija ne smije biti objavljena dok nisu implementirani i dokumentirani brisanje računa i pripadajućih server-side podataka.

## Obavezna provjera prije svake objave

Ako se doda internet pristup, crash reporting, analytics, telemetry, push, cloud SDK, login/account sustav ili bilo koji novi third-party SDK, ovaj dokument i Play Console Data safety moraju se ponovno pregledati prije releasea.


### 0.6.2 sigurnosne napomene
- nema INTERNET permissiona
- Android backup je onemogućen
- screenshot/screen recording aplikacijskog sadržaja blokiran je s `FLAG_SECURE`
- overlay prozori skrivaju se na podržanim Android verzijama
- master-password verifier vezan je uz Android Keystore
- nema novih kategorija prikupljenih ili dijeljenih podataka
