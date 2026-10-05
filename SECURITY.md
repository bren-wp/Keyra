# Sigurnost

Ako pronađete sigurnosni problem u Keyri, nemojte ga javno objavljivati dok se problem ne riješi.

Prijavite problem vlasniku repozitorija kroz privatni sigurnosni kanal na GitHubu. U prijavi navedite što ste primijetili, kako se problem može ponoviti i koje bi posljedice mogao imati.

Stvarne lozinke, pristupne ključeve i privatne sigurnosne kopije nemojte prilagati prijavi.


## Sigurnosni model

- sadržaj trezora šifrira se autentificiranom AES-256-GCM enkripcijom
- kriptografski ključ uređaja čuva se u Android Keystoreu ili Apple Keychainu
- glavna lozinka obrađuje se PBKDF2-HMAC-SHA-256 derivacijom s 600.000 iteracija
- novi trezor zahtijeva glavnu lozinku od najmanje 12 znakova
- uzastopni pogrešni pokušaji otključavanja uvode privremeno zaključavanje
- osjetljivi prikaz i kopiranje mogu zahtijevati dodatnu potvrdu identiteta
- aplikacija onemogućuje snimanje osjetljivog Android prozora i zaključava trezor prema odabranoj politici

Sigurnosne tvrdnje odnose se na implementirani model zaštite i ne znače da je bilo koji softver apsolutno neprobojan.
