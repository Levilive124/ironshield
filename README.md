# Iron Shield Website (HTML-Frontend und API)

Alle sichtbaren Seiten sind statische HTML-Dateien; CSS und Browserlogik liegen in `assets/`. PHP bleibt als serverseitige API für Discord-OAuth, Sitzungen, sichere Datenänderungen und Bot-Synchronisierung. Dadurch werden weder Discord-Tokens noch Bridge-Schlüssel an den Browser ausgeliefert. Für getrennte Web- und Bot-Server beim selben Hoster siehe den Abschnitt „Getrennte Web- und Bot-Server beim selben Hoster“.

## Lokal starten

1. Installiere PHP 8.1 oder neuer und Python 3.8 oder neuer mit aktivierter HTTPS-Unterstützung.
2. Kopiere `.env.example` nach `.env`.
3. Trage das **Client Secret** deiner Discord-Anwendung in `.env` ein. Diese Werte gehören nur auf den Server und dürfen nicht in den Browsercode oder ein öffentliches Repository.
4. Öffne im Discord Developer Portal deiner Anwendung **OAuth2 → Redirects** und registriere exakt `http://localhost:8000/api/index.php?route=callback`.
5. Starte im Projektordner `sh start.sh` und öffne <http://localhost:8000>. Das Script startet nur die Website. Der Discord-Bot läuft unabhängig auf seinem Bot-Server.

Der Discord-Login nutzt die OAuth2-Scopes `identify` und `guilds`. Das Server-Dashboard liegt unter `/dashboard.html`; Support, Team-Login und Tickets haben ebenfalls statische HTML-Seiten. Die API prüft Sitzung und Berechtigungen für jede geschützte Aktion. Serveradmins erhalten je nach Status einen Button zum Einladen oder zur Ticketverwaltung. Falls der Dashboard-Bot eine andere Discord-Anwendung ist als der Login, setze `DISCORD_BOT_CLIENT_ID` auf die Client-ID dieser Bot-Anwendung.

### Server-Dashboard und Bot-Verbindung

Der bestehende Iron-Shield-Bot bleibt unverändert. Für den anderen discord.py-Bot liegt die Integration in `bot/statuscheck/`. Du kannst `ironshield_dashboard.py` direkt in den `cogs`-Ordner des anderen Bots legen **oder** den kompletten Ordner `statuscheck` neben dessen `cogs`-Ordner und Startdatei kopieren. Lade zuerst dessen Ticket-Cog und danach die Dashboard-Extension:

```python
await bot.load_extension("cogs.ticketsystem")
await bot.load_extension("cogs.ironshield_dashboard")  # Datei liegt in cogs/
# Alternativ, wenn du den Ordner statuscheck neben cogs/ kopiert hast:
# await bot.load_extension("statuscheck.ironshield_dashboard")
```

Falls dein Bot Cogs automatisch lädt, ergänze den passenden Extension-Pfad (`cogs.ironshield_dashboard` oder `statuscheck.ironshield_dashboard`) in dessen Loader und achte darauf, dass der Ticket-Cog zuerst geladen wird. Setze auf dem Bot-Host `PUBLIC_SITE_URL` auf die öffentliche HTTPS-Domain des Website-Servers, exakt ohne abschließenden Pfad. Der Dashboard-Cog synchronisiert Einstellungen per HTTPS und postet oder bearbeitet dabei keine Nachrichten und erstellt keine Kanäle. Beim Start löscht er nur den alten Kanal, dessen Thema den eindeutigen Marker `ironshield-dashboard-relay:v1` enthält; bei fehlender Berechtigung löscht er eigene Nachrichten darin einmalig und protokolliert, dass der Kanal nicht entfernt werden konnte. Für die Kanalentfernung ist `Kanäle verwalten` nötig. Für den Sync müssen `guilds`-Intent sowie derselbe eigene Zufallsschlüssel `DASHBOARD_BRIDGE_SECRET` (mindestens 32 Zeichen) auf Bot- und Website-Host gesetzt sein. Für bestehende Installationen wird vorübergehend auch `BOT_WEBHOOK_SECRET` als Bridge-Schlüssel akzeptiert. Diese Schlüssel sind getrennt vom Discord-Token. `DASHBOARD_BOT_TOKEN` auf dem Website-Host wird ausschließlich für Discord-API-Abfragen verwendet; der Bot-Token wird nie als Bridge-Schlüssel gesendet. Tokens und Schlüssel nur in Hosting-Umgebungsvariablen eintragen, niemals in Quellcode oder Chat.

Damit der Cog wirklich alle Server und deren Kanäle sehen kann, muss beim Erzeugen deines **anderen** `commands.Bot` der nicht privilegierte Discord-Intent `guilds` aktiviert sein. Wenn dein Startcode `discord.Intents.none()` verwendet, setze vor dem Erzeugen des Bots:

```python
intents = discord.Intents.none()
intents.guilds = True
bot = commands.Bot(command_prefix="!", intents=intents)
```

Wenn dein Bot schon `discord.Intents.default()` verwendet, ist `guilds` standardmäßig aktiv. Im Bot-Log bestätigt `Relay-Bereinigung geprüft: N Server, M markierte Kanäle gefunden, K Kanäle gelöscht`, wie viele Server geprüft und markierte Relay-Kanäle gefunden wurden. Ein fehlgeschlagener Löschversuch wird mit wachsendem Abstand wiederholt; fehlende Berechtigungen werden im Log ausgewiesen.

Unter „Server verwalten“ kannst du die Ticket-Konfiguration bearbeiten. Beim Speichern schreibt der Dashboard-Cog die Werte in die Datendatei des Ticket-Cogs; er erstellt oder postet keine Panel-Nachrichten und stößt keine Discord-Nachrichtenaktionen an. Laufende Tickets, Ticket-Metadaten, Zähler und Statistiken bleiben geschützt.

## Team-Login und Tickets

Beim Erstellen eines Tickets speichert PHP dieses dauerhaft ausschließlich im Webportal. Es wird nichts an Discord gesendet oder dort erstellt. Die alte Ticket-Bridge antwortet mit `410 discord_publishing_disabled` und veröffentlicht keine Threads oder Nachrichten.

Das Team-Portal liegt statisch unter `/team-login.html`; die Verwaltungsansicht liegt unter `/team.html`. Beim ersten Aufruf werden `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD` aus der Hosting-Konfiguration verwendet, um das erste Admin-Konto anzulegen. Das Admin-Konto kann Teamkonten erstellen und Rechte zum Verwalten weiterer Konten sowie zum Veröffentlichen von Startseiten-Ankündigungen vergeben. Berechtigte Teammitglieder können Ankündigungen mit Ablaufzeitpunkt einstellen und entfernen. Alle angemeldeten Teammitglieder können Tickets ansehen, übernehmen und beantworten. Passwörter werden nur als Passwort-Hash gespeichert.

Nutzer melden sich über `/support.html` mit Discord an und öffnen dort ein Ticket. Ohne Datenbank werden Tickets und Teamkonten mit Dateisperren in `store.json` gespeichert. Der private Speicher liegt im persistenten `TEAM_DATA_DIR`; auf Panel-Servern kann das zum Beispiel `/home/container/.ironshield-private` sein, andernfalls standardmäßig `.ironshield-private` neben `index.php`. PHP-Sitzungen liegen in einem `sessions`-Unterordner desselben Speicherorts. Ein auf `/tmp` gesetzter Speicherpfad wird abgelehnt. Vorhandene Daten aus dem bisherigen Projektordner oder einer alten temporären Ablage werden beim ersten Start samt Ticket-Anhängen übernommen. Der private Ordner wird gegen Webzugriffe gesperrt. Teamkonten, Passwort-Hashes, Tickets und Ankündigungen überstehen Neustarts nur, wenn der Hoster den Speicherordner dauerhaft erhält. Im Docker-Setup ist `/var/lib/ironshield-team` als Volume vorgesehen. Bei der Ersteinrichtung zuerst `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD` setzen; das Admin-Konto wird nur erstellt, solange noch kein Teamkonto existiert. Ticketinhaber können ihre Tickets schließen und bis zu 3 Anhänge à 5 MB pro Nachricht hochladen. Anhänge werden nur nach derselben Ticket-Zugriffsprüfung ausgeliefert. `start.sh` setzt ein maximales POST-Limit von 20 MB.

## Veröffentlichung

Setze im Hosting-Panel `DISCORD_REDIRECT_URI` auf die öffentliche HTTPS-Callback-URL deiner Website, zum Beispiel `https://deine-domain.example/api/index.php?route=callback`, und registriere exakt dieselbe URL unter **Discord Developer Portal → OAuth2 → Redirects**. Die Beispieladresse `http://localhost:8000/api/index.php?route=callback` funktioniert ausschließlich lokal. Verwende im Hosting außerdem dieselbe Client-ID und das dazugehörige Client-Secret wie in der Discord-Anwendung. Stelle die Website hinter HTTPS bereit. Der OAuth-Sicherheitswert wird in einem kurzlebigen HttpOnly-Cookie gespeichert, damit der Login-Rücksprung auch mit mehreren PHP-Prozessen funktioniert; `.env` muss außerhalb des öffentlichen Dateiverzeichnisses liegen.

### Website als separater Server beim selben Hoster wie der Bot

Website und Bot laufen auf zwei getrennten Servern, auch wenn beide beim gleichen Hoster liegen. `localhost` und `127.0.0.1` zeigen immer nur auf den jeweiligen Server. Die Website benötigt deshalb eine eigene Domain mit HTTPS und muss den Bot über seine erreichbare WebAPI-Adresse ansprechen.

**Website-Dateien:** Im Webroot müssen `index.html`, `dashboard.html`, `support.html`, `team-login.html`, `team.html`, `ticket.html`, `error.html`, `impressum.html`, `datenschutz.html`, `nutzungsbedingungen.html`, `index.php`, `.htaccess` sowie die Ordner `api/`, `assets/`, `includes/` und die Datei `bot/discord.php` liegen. `api/index.php` ist der PHP-Endpunkt; normale Seiten werden als HTML geladen. Nicht hochladen: `.env`, `.ironshield-private/`, `.runtime/` oder die Python-Bot-Dateien.

**Laufzeit:** Der Webserver braucht PHP 8.1 oder neuer, HTTPS-Ausgangsverbindungen und Apache `mod_rewrite`/`mod_headers` (oder gleichwertige Webserver-Regeln). Wenn du den Docker-Build nutzt, baut das `Dockerfile` nur die eigenständige Website; es startet keinen Discord-Bot. Apache verwendet `SERVER_PORT`, danach `PORT`, und fällt sonst auf 8080 zurück. Das Image erwartet ein dauerhaftes, beschreibbares Volume unter `/var/lib/ironshield-team`. Bei einem Server-Panel ohne Docker kannst du `sh start.sh` verwenden; es bindet den PHP-Webserver an `SERVER_PORT`, `PORT` oder Port 8000.

**Dauerhafte Daten:** Ohne PostgreSQL speichert die Website Teamkonten, Tickets, Anhänge und PHP-Sitzungen unter `TEAM_DATA_DIR`. Setze diesen Wert auf einen privaten, beschreibbaren und bei Neuinstallationen/Neustarts erhaltenen Ordner. Bei einem Panel, das `/home/container` dauerhaft erhält, eignet sich zum Beispiel `/home/container/.ironshield-private`. Ohne persistenten Speicher gehen Anmeldung und gespeicherte Daten verloren. Mit PostgreSQL setze `DATABASE_URL`; das Dockerfile enthält dafür `pdo_pgsql`. Vorhandene Daten aus `.ironshield-private/` müssen gesichert und in den neuen Datenspeicher übernommen werden, bevor die alte Installation abgeschaltet wird.

**Discord-Anmeldung:** Setze `PUBLIC_SITE_URL` auf die neue Website-Adresse und `DISCORD_REDIRECT_URI` exakt auf `https://DEINE-DOMAIN/api/index.php?route=callback`. Trage dieselbe Callback-URL im Discord Developer Portal unter **OAuth2 → Redirects** ein. `DISCORD_CLIENT_ID` und `DISCORD_CLIENT_SECRET` gehören als serverseitige Variablen in die Website-Konfiguration. Nach jeder Änderung an diesen Werten muss der Webserver neu gestartet beziehungsweise neu deployed werden.

**Bot-Verbindung:** Auf der Website müssen `DASHBOARD_BRIDGE_SECRET` und `DASHBOARD_BOT_TOKEN` serverseitig gesetzt sein; der Bridge-Schlüssel muss auf Bot und Website übereinstimmen. Für die Modulverwaltung setze `DASHBOARD_WEBAPI_URL` auf den TLS-Hostnamen der Bot-WebAPI (zum Beispiel `https://BOT-DOMAIN:33041`), außerdem `DASHBOARD_WEBAPI_PATH`, `DASHBOARD_WEBAPI_HMAC` und `DASHBOARD_WEBAPI_SERVER_CA_PEM`. Nutze keinen IP-Link, wenn das Zertifikat für einen Hostnamen ausgestellt ist: Der Browser/Client muss den passenden Hostnamen für TLS/SNI verwenden. Im mTLS-Modus kommen `DASHBOARD_WEBAPI_CLIENT_CERT_PEM` und `DASHBOARD_WEBAPI_CLIENT_KEY_PEM` dazu. Falls beide Server gemeinsam auf HMAC-only umgestellt wurden, kann die Clientzertifikatspflicht auf beiden Seiten deaktiviert werden; die TLS-Serverprüfung bleibt aktiv. Die vollständige Variablenliste und Sicherheitsdetails stehen unter „Externe Bot-WebAPI (mTLS)“.

Nach dem Hochladen zuerst `https://DEINE-DOMAIN/api/health.php` öffnen. Erwartet wird JSON mit `"ok":true`. Danach muss `/api/index.php?route=dashboard_login` zu Discord weiterleiten. Modulverwaltung funktioniert erst, wenn die WebAPI auf dem Bot-Server erreichbar ist und dieselben abgestimmten WebAPI-Schlüssel und Zertifikate nutzt. Nur beim selben Hoster zu sein schaltet keine private Netzwerkverbindung frei; frage den Anbieter nach interner Server-zu-Server-Adresse, falls du keine öffentliche HTTPS-Adresse verwenden kannst.

### Externe Bot-WebAPI (mTLS)

Das Dashboard verwendet `bot/cogs/webapi.py` für Bot-Status sowie das Ein- und Ausschalten von Bot-Modulen. Standardmäßig verlangt die API gegenseitiges TLS, einen geheimen URL-Pfad, HMAC-Signaturen und eine vom Bot autorisierte Discord-Nutzer-ID. Wenn der Website-Host kein Clientzertifikat von der privaten Bot-CA erhalten kann, kann der mitgelieferte alternative HMAC-only-Modus aktiviert werden. Er deaktiviert ausschließlich das Clientzertifikat; TLS-Serverprüfung, geheimer Pfad, HMAC mit Zeitstempel und Einmal-Nonce, Actor-Freigabe, Berechtigungsprüfung und RPC-Schema bleiben aktiv.

Die Datei gehört in den `cogs/`-Ordner des vollständigen Discord-Bot-Projekts und muss von dessen Extension-Loader geladen werden (z. B. `await bot.load_extension("cogs.webapi")`). Sie importiert unter anderem `modules`, `storage`, `rolesafety` und `owners`; diese Bot-Module müssen dort vorhanden sein.

Auf dem Bot-Host müssen `WEBAPI_ENABLED=1`, `WEBAPI_PORT=33041`, `WEBAPI_CERT`, ein 64-stelliger Hex-Wert für `WEBAPI_PATH`, mindestens 32 zufällige Zeichen für `WEBAPI_HMAC` sowie `WEBAPI_ACTORS` gesetzt sein. `WEBAPI_ACTORS` muss die Discord-Nutzer-ID des Dashboard-Administrators enthalten; sie muss zugleich in `OWNER_IDS` des Bots stehen. Im Standard-mTLS-Modus sind außerdem `WEBAPI_CA` und `WEBAPI_CLIENT_CN` nötig; dieser CN muss zum Clientzertifikat passen. Für den HMAC-only-Modus setze `WEBAPI_REQUIRE_CLIENT_CERT=0`; dann werden `WEBAPI_CA` und der CN-Pin für Clientzertifikate nicht verwendet.

Auf dem Website-Host werden `DASHBOARD_WEBAPI_URL` (zum Beispiel `https://BOT-DOMAIN:33041`), derselbe `WEBAPI_PATH` und `WEBAPI_HMAC` sowie `DASHBOARD_WEBAPI_SERVER_CA_PEM` benötigt. Im Standard-mTLS-Modus setze zusätzlich `DASHBOARD_WEBAPI_REQUIRE_CLIENT_CERT=1` und `DASHBOARD_WEBAPI_CLIENT_CERT_PEM`/`DASHBOARD_WEBAPI_CLIENT_KEY_PEM`; das Clientzertifikat muss von `WEBAPI_CA` signiert sein und den bei `WEBAPI_CLIENT_CN` eingestellten CN tragen. Wenn der Hoster kein solches Clientzertifikat ausstellen kann, setze `WEBAPI_REQUIRE_CLIENT_CERT=0` auf dem Bot und `DASHBOARD_WEBAPI_REQUIRE_CLIENT_CERT=0` auf der Website. Die Server-CA-Prüfung bleibt in beiden Modi eingeschaltet. PEM-Werte als geheime Umgebungsvariablen speichern; der PHP-Code legt sie mit Dateirechten `0600` im temporären Laufzeitverzeichnis ab. Werte niemals in Git oder Chat veröffentlichen.

### Getrennte Web- und Bot-Server beim selben Hoster

Die Website und der Discord-Bot sind zwei getrennte Dienste auf zwei Servern. Dasselbe Hosting-Unternehmen ändert daran nichts: `localhost`, `127.0.0.1` und `BOT_INTERNAL_URL` verbinden die Server nicht miteinander. `start.sh` und das beiliegende `Dockerfile` starten ausschließlich die Website; der Bot wird nur auf seinem eigenen Server gestartet.

Die Website braucht auf ihrem Hosting einen eigenen HTTPS-Hostnamen. Der Bot braucht auf seinem Hosting einen erreichbaren HTTPS-Hostnamen und einen freigegebenen WebAPI-Port. Trage auf dem Website-Server `DASHBOARD_WEBAPI_URL=https://BOT-HOSTNAME:PORT` ein. Verwende den Bot-Server-Hostnamen, für den sein TLS-Zertifikat ausgestellt wurde, und nicht dessen private IP oder `localhost`. Falls der Hoster ein privates Servernetz bereitstellt, kann dessen DNS-Name verwendet werden, sofern TLS-Zertifikat und Netzwerkfreigabe dazu passen.

Auf dem Website-Server laufen PHP 8.1 oder neuer und die PHP-API; auf dem Bot-Server laufen Python und der Discord-Bot samt `cogs/webapi.py`. Die Bot-WebAPI muss am zugewiesenen Port erreichbar sein. Falls dein Hoster dafür eine Portfreigabe oder Firewall-Regel verlangt, erlaube den Zugriff vom Webserver auf diesen Port. Halte die API mit mTLS oder dem dokumentierten HMAC-only-Modus abgesichert.

Wenn dein Hosting einen eigenen Docker-Build unterstützt, verwendet das beiliegende `Dockerfile` PHP Apache und `pdo_pgsql`; es enthält weder Python noch den Discord-Bot. `.env` wird absichtlich nicht ins Image kopiert. Trage OAuth-, Website- und Datenbankwerte als Umgebungsvariablen im Website-Hosting ein. Bot-Token, `WEBAPI_*` und die Bot-Erweiterung gehören ausschließlich in die Umgebungsvariablen beziehungsweise Dateien des Bot-Servers. `DATABASE_URL` oder ein dauerhaftes privates Volume ist nötig, damit Sitzungen, Teamdaten und Tickets einen Neustart überstehen.

## Umzug auf Vercel

Die Dateispeicherung aus dem bisherigen Hosting gilt nicht für Vercel. Dort müssen Sitzungen, Teamkonten, Tickets, Dashboard-Einstellungen und Anhänge über `DATABASE_URL` in PostgreSQL liegen. Die private Quelldatensicherung unter `.ironshield-private/` wird nicht mit deployed (sie steht absichtlich in `.vercelignore`). Nach Einrichtung der Datenbank trägst du dieselbe PostgreSQL-Verbindungs-URL wie in Vercel Production in die ignorierte lokale `.env` ein und startest in PowerShell `.\scripts\import-private-data.ps1`. Der Helfer verwendet die im Projekt enthaltene PHP-CLI und PostgreSQL-Erweiterung; Zugangsdaten werden nicht ausgegeben. Die vollständige Reihenfolge steht in [`VERCEL_DEPLOY.md`](VERCEL_DEPLOY.md). Ohne Vercel-Zugang und Produktions-Datenbank bleibt Bereitstellung beziehungsweise Import offen.
