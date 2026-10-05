# Keyra — Google Play i App Store priprema za objavu

Ovaj dokument opisuje trenutno stanje aplikacije i obavezne provjere prije svake produkcijske objave. Ne zamjenjuje službena pravila Google Playa, Apple App Storea niti pravni savjet.

## Trenutni privatnosni model

- Keyra nema korisnički račun, vlastiti cloud račun ni udaljeni trezor.
- Sadržaj trezora pohranjuje se šifrirano na uređaju.
- Android manifest nema `INTERNET` dozvolu.
- Nema oglasa ni analitičkog SDK-a u trenutnoj bazi koda.
- TOTP kodovi generiraju se lokalno; TOTP tajna ne šalje se Keyra poslužitelju.
- Cloud prijenos koristi sistemski odabir datoteka. U odabranu lokaciju predaje se već šifrirana `.keyra` datoteka.
- Proton Drive, iCloud Drive i drugi file provideri rade kao zasebne korisnički odabrane usluge. Keyra ne traži njihove vjerodajnice.
- Korisnik može iz aplikacije trajno izbrisati trezor, lokalne postavke i uređajni ključ.

## Google Play — tehnička provjera

- `compileSdk = 36`
- `targetSdk = 36`
- `minSdk = 26`
- jedina deklarirana osjetljiva dozvola je `USE_BIOMETRIC`
- `android:allowBackup="false"`
- `android:fullBackupContent="false"`
- `android:usesCleartextTraffic="false"`
- produkcijski AAB mora proći lint i testove prije objave
- provjeriti da release potpisivanje koristi produkcijski Play App Signing ključ / upload key

### Play Console obavezne stavke

Prije slanja verzije ručno potvrditi:

1. **Privacy policy** — URL mora biti javno dostupan i sadržaj mora odgovarati stvarnom ponašanju aplikacije.
2. **Data safety** — prijava mora odgovarati konačnom APK/AAB-u i svim SDK-ovima. Trenutna baza nema Keyra backend, oglase ni analitiku, ali svaku novu integraciju treba ponovno procijeniti.
3. **App access** — nije potreban online račun; reviewer može izraditi lokalni trezor.
4. **Ads** — deklarirati samo stvarno stanje; trenutna aplikacija nema oglase.
5. **Content rating** — dovršiti upitnik u Play Consoleu.
6. **Target API** — prije objave provjeriti aktualni Play zahtjev; ova baza cilja API 36.
7. **Data deletion** — aplikacija nema serverski račun. Lokalni podaci mogu se izbrisati kroz Postavke → Izbriši sve lokalne podatke.
8. **Permissions** — ne dodavati široke storage, location, contacts, camera ili druge dozvole ako se ista funkcija može ostvariti sistemskim pickerom.

## Apple App Store — tehnička provjera

- projekt uključuje `PrivacyInfo.xcprivacy`
- tracking je isključen
- nema deklariranih tracking domena
- Privacy Manifest deklarira UserDefaults required-reason API
- Face ID opis uporabe je definiran
- aplikacija nema obaveznu registraciju računa
- lokalno brisanje svih Keyra podataka dostupno je iz Postavki
- cloud datoteke biraju se kroz sistemski file importer/exporter

### App Store Connect obavezne stavke

Prije slanja verzije ručno potvrditi:

1. **Privacy Policy URL** — javno dostupan i identičan stvarnom ponašanju verzije koja se šalje.
2. **App Privacy** — ponovno pregledati Apple “nutrition label” za svaku novu biblioteku ili mrežnu integraciju. Trenutna baza nema Keyra telemetriju ni Keyra backend.
3. **Account deletion** — pravilo o brisanju online računa nije primjenjivo dok Keyra ne nudi izradu Keyra računa. Ako se račun ikada uvede, brisanje cijelog računa mora biti dostupno iz aplikacije.
4. **Export compliance** — Keyra koristi standardnu kriptografiju kroz Appleove kriptografske API-je. Prije distribucije potvrditi Apple export-compliance odgovore za zemlje distribucije. `ITSAppUsesNonExemptEncryption=NO` smije ostati samo dok konačna konfiguracija zadovoljava Appleovu iznimku.
5. **App Review notes** — navesti da je trezor lokalni, da reviewer može stvoriti testni trezor bez vanjskog računa i da su cloud backup lokacije korisnički odabrane.
6. **Screenshots / metadata** — ne tvrditi automatsku Proton sinkronizaciju ako verzija koristi provider-neutralni file picker. Ispravan opis je šifrirani izvoz/uvoz kroz podržane sistemske cloud lokacije.
7. **Privacy Manifest** — ponovno auditirati pri svakoj novoj Apple/third-party biblioteci koja koristi required-reason API-je.

## Privatni cloud / Proton Drive

Trenutni namjerni model je provider-neutralan:

1. Keyra lokalno izradi KEYRA2 sigurnosnu kopiju.
2. Kopija je šifrirana glavnom lozinkom prije predaje drugoj aplikaciji/provideru.
3. Sistem prikazuje dostupne lokacije za spremanje.
4. Korisnik može odabrati Proton Drive kada ga sustav nudi, ili drugu lokaciju/provider.
5. Provider obavlja vlastitu mrežnu sinkronizaciju.
6. Keyra ne vidi niti sprema lozinku Proton/Apple/drugog cloud računa.

Ovo je sigurnije od ugrađivanja neslužbenog ili privatnog Proton API-ja. Izravnu pozadinsku sinkronizaciju treba dodati tek ako postoji službeno podržan javni SDK/API s jasnim uvjetima distribucije i privatnosti.

## Release gate

Verzija se ne smatra spremnom za trgovine dok nisu zeleni:

- Android lint
- Android unit testovi
- Android release AAB build
- iOS simulator build
- iOS analyze
- iOS Release device build
- iOS simulator launch smoke test
- provjera Privacy Policy / Data safety / App Privacy deklaracija
- provjera da nema tajni, testnih računa, API ključeva ili razvojnih URL-ova u releaseu
- ručna provjera uvoza/izvoza šifrirane kopije preko sistemskog file providera
- ručna provjera TOTP koda s poznatim RFC 6238 testnim vektorom
