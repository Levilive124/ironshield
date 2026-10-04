# Iron Shield Website (HTML-Frontend und API)

Alle sichtbaren Seiten sind statische HTML-Dateien; CSS und Browserlogik liegen in `assets/`. PHP bleibt als serverseitige API für Discord-OAuth, Sitzungen, sichere Datenänderungen und Bot-Synchronisierung. Dadurch werden weder Discord-Tokens noch Bridge-Schlüssel an den Browser ausgeliefert. Für Vercel, PostgreSQL und die einmalige Datenübernahme siehe `VERCEL_DEPLOY.md`.

## Lokal starten

1. Installiere PHP 8.1 oder neuer und Python 3.8 oder neuer mit aktivierter HTTPS-Unterstützung.
2. Kopiere `.env.example` nach `.env`.
3. Trage das **Client Secret** deiner Discord-Anwendung in `.env` ein. Diese Werte gehören nur auf den Server und dürfen nicht in den Browsercode oder ein öffentliches Repository.
4. Öffne im Discord Developer Portal deiner Anwendung **OAuth2 → Redirects** und registriere exakt `http://localhost:8000/api/index.php?route=callback`.
5. Starte im Projektordner `sh start.sh` und öffne <http://localhost:8000>. Beim ersten Start richtet das Script die Python-Abhängigkeit in `.runtime/` ein und startet danach PHP und Bot gemeinsam.

Der Discord-Login nutzt die OAuth2-Scopes `identify` und `guilds`. Das Server-Dashboard liegt unter `/dashboard.html`; Support, Team-Login und Tickets haben ebenfalls statische HTML-Seiten. Die API prüft Sitzung und Berechtigungen für jede geschützte Aktion. Serveradmins erhalten je nach Status einen Button zum Einladen oder zur Ticketverwaltung. Falls der Dashboard-Bot eine andere Discord-Anwendung ist als der Login, setze `DISCORD_BOT_CLIENT_ID` auf die Client-ID dieser Bot-Anwendung.

### Server-Dashboard und Bot-Verbindung

Der bestehende Iron-Shield-Bot bleibt unverändert. Für den anderen discord.py-Bot liegt die Integration in `bot/statuscheck/`. Du kannst `ironshield_dashboard.py` direkt in den `cogs`-Ordner des anderen Bots legen **oder** den kompletten Ordner `statuscheck` neben dessen `cogs`-Ordner und Startdatei kopieren. Lade zuerst dessen Ticket-Cog und danach die Dashboard-Extension:

```python
await bot.load_extension("cogs.ticketsystem")
await bot.load_extension("cogs.ironshield_dashboard")  # Datei liegt in cogs/
# Alternativ, wenn du den Ordner statuscheck neben cogs/ kopiert hast:
# await bot.load_extension("statuscheck.ironshield_dashboard")
```

Falls dein Bot Cogs automatisch lädt, ergänze den passenden Extension-Pfad (`cogs.ironshield_dashboard` oder `statuscheck.ironshield_dashboard`) in dessen Loader und achte darauf, dass der Ticket-Cog zuerst geladen wird. Setze auf dem Bot-Host `PUBLIC_SITE_URL=https://ironshield.novium.link` exakt ohne Port. Der Dashboard-Cog synchronisiert Einstellungen per HTTPS und postet oder bearbeitet dabei keine Nachrichten und erstellt keine Kanäle. Beim Start löscht er nur den alten Kanal, dessen Thema den eindeutigen Marker `ironshield-dashboard-relay:v1` enthält; bei fehlender Berechtigung löscht er eigene Nachrichten darin einmalig und protokolliert, dass der Kanal nicht entfernt werden konnte. Für die Kanalentfernung ist `Kanäle verwalten` nötig. Für den Sync müssen `guilds`-Intent sowie derselbe eigene Zufallsschlüssel `DASHBOARD_BRIDGE_SECRET` (mindestens 32 Zeichen) auf Bot- und Website-Host gesetzt sein. Für bestehende Installationen wird vorübergehend auch `BOT_WEBHOOK_SECRET` als Bridge-Schlüssel akzeptiert. Diese Schlüssel sind getrennt vom Discord-Token. `DASHBOARD_BOT_TOKEN` auf dem Website-Host wird ausschließlich für Discord-API-Abfragen verwendet; der Bot-Token wird nie als Bridge-Schlüssel gesendet. Tokens und Schlüssel nur in Hosting-Umgebungsvariablen eintragen, niemals in Quellcode oder Chat.

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

Nutzer melden sich über `/support.html` mit Discord an und öffnen dort ein Ticket. Tickets und Teamkonten werden mit Dateisperren in `store.json` gespeichert. Auf Novium liegt der private Datenspeicher standardmäßig im persistenten Serververzeichnis `/home/container/.ironshield-private`; andernfalls im Ordner `.ironshield-private` neben `index.php`. Ein versehentlich auf `/tmp` gesetzter Speicherpfad wird abgelehnt. Vorhandene Daten aus dem bisherigen Projektordner oder dem alten temporären Speicher werden beim ersten Start samt Ticket-Anhängen übernommen. Wenn Novium einen abweichenden TEAM_DATA_DIR nutzt, wird zusätzlich eine geschützte Kopie unter `/home/container/.ironshield-private` gehalten und beim Start bei Bedarf zurückgespielt. Beim ersten Start übernimmt die Website vorhandene Tickets und Teamkonten aus dem früheren temporären Speicher. Der private Ordner wird gegen Webzugriffe gesperrt. Teamkonten, Passworthashes, Tickets und Startseiten-Ankündigungen werden bei jedem erfolgreichen Speichervorgang gemeinsam in die Datei geschrieben und überstehen normale PHP-, Webserver- und Serverneustarts; beim Start werden vorhandene Konten nicht neu angelegt oder gelöscht. Im Docker-Setup liegt die Datei im eingebundenen Volume `/var/lib/ironshield-team`. Der Hosting-Anbieter muss dieses Volume beziehungsweise den privaten Projektordner bei Neustarts beibehalten. Wenn Novium Dateien bei einer Neuinstallation oder einem erneuten Deployment löscht, muss `.ironshield-private` separat erhalten bleiben oder `TEAM_DATA_DIR` auf ein dauerhaft eingebundenes privates Volume zeigen. Das beiliegende Dockerfile verwendet `/var/lib/ironshield-team` als Volume. Bei der Ersteinrichtung zuerst `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD` setzen; das Admin-Konto wird nur erstellt, solange noch kein Teamkonto existiert. Ticketinhaber können ihre Tickets schließen und Bilder (JPG, PNG, GIF, WebP) oder Videos (MP4, WebM, MOV) mit bis zu 3 Anhängen à 5 MB an ein Ticket oder eine Antwort hängen. Anhänge liegen im privaten Teamdatenspeicher und werden nur nach derselben Ticket-Zugriffsprüfung ausgeliefert. `start.sh` setzt dafür ein maximales POST-Limit von 20 MB.

## Veröffentlichung

Setze im Hosting-Panel `DISCORD_REDIRECT_URI` auf die öffentliche HTTPS-Callback-URL deiner Website, zum Beispiel `https://deine-domain.example/api/index.php?route=callback`, und registriere exakt dieselbe URL unter **Discord Developer Portal → OAuth2 → Redirects**. Die Beispieladresse `http://localhost:8000/api/index.php?route=callback` funktioniert ausschließlich lokal. Verwende im Hosting außerdem dieselbe Client-ID und das dazugehörige Client-Secret wie in der Discord-Anwendung. Stelle die Website hinter HTTPS bereit. Der OAuth-Sicherheitswert wird in einem kurzlebigen HttpOnly-Cookie gespeichert, damit der Login-Rücksprung auch mit mehreren PHP-Prozessen funktioniert; `.env` muss außerhalb des öffentlichen Dateiverzeichnisses liegen.

### Externe Bot-WebAPI (mTLS)

Das PHP-Dashboard kann den externen Bot direkt über dessen `cogs/webapi.py`-RPC abfragen. Das ist unabhängig von `DASHBOARD_BRIDGE_SECRET` und vom Discord-Bot-Token. Für Status und Modulverwaltung muss die Bot-WebAPI `status.public`, `modules.list` und `modules.set` bereitstellen; der Bot prüft Guild-Adminrechte selbst.

Setze die folgenden Werte ausschließlich in der Hosting-Konfiguration der **Website**. URL ist die öffentlich erreichbare HTTPS-Basisadresse des Bot-Listeners mit Port, aber ohne Pfad:

```text
DASHBOARD_WEBAPI_URL=https://play.nod3.de:33041
DASHBOARD_WEBAPI_PATH=<derselbe WEBAPI_PATH wie auf dem Bot>
DASHBOARD_WEBAPI_HMAC=<derselbe WEBAPI_HMAC wie auf dem Bot>
DASHBOARD_WEBAPI_SERVER_CA_FILE=/home/container/secrets/server-issuing-ca.crt
DASHBOARD_WEBAPI_CLIENT_CERT_FILE=/home/container/secrets/dashboard-client.pem
DASHBOARD_WEBAPI_CLIENT_KEY_FILE=/home/container/secrets/dashboard-client.key
```

`DASHBOARD_WEBAPI_SERVER_CA_FILE` muss die CA enthalten, die das Bot-Serverzertifikat ausgestellt hat. Das Client-Zertifikat muss von der CA aus `WEBAPI_CA` auf dem Bot akzeptiert werden; sein CN muss `WEBAPI_CLIENT_CN` entsprechen. Wenn Zertifikat und privater Schlüssel gemeinsam in einer PEM-Datei liegen, kann `DASHBOARD_WEBAPI_CLIENT_KEY_FILE` leer bleiben. Private Schlüssel und HMAC-Werte nie veröffentlichen. Die Website benötigt PHP-OpenSSL und HTTPS-Ausgangszugriff zum Bot-Port. Ein erfolgreicher Statusaufruf erscheint im Dashboard; unter „Server verwalten“ können Serveradmins Bot-Module aktivieren und deaktivieren.

### Linux-Container mit `start.sh`

Der Container braucht PHP CLI 8.1 oder neuer. Läuft der Bot auf demselben Server, wird zusätzlich Python 3.8 oder neuer benötigt. Baue dafür am besten das beiliegende Dockerfile; es installiert PHP, Python und den Bot. Als Startbefehl verwende `sh start.sh`; es startet PHP auf dem zugewiesenen Port und den Bot lokal, wenn `BOT_INTERNAL_URL` auf localhost zeigt. Bei einer externen HTTPS-Bot-URL startet es nur PHP; Python muss dann nur auf dem Bot-Server laufen.

Wenn dein Hosting einen eigenen Docker-Build unterstützt, verwendet das beiliegende `Dockerfile` PHP CLI 8.5, Python und die Bot-Abhängigkeiten. `.env` wird absichtlich nicht ins Image kopiert; trage `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_REDIRECT_URI` und `BOT_WEBHOOK_SECRET` im Webhosting ein. `DISCORD_BOT_TOKEN`, `DISCORD_TICKET_CHANNEL_ID` und denselben `BOT_WEBHOOK_SECRET` setzt du auf dem Bot-Server. Die externe Bot-Adresse muss HTTPS verwenden; weitere Einrichtung steht in `bot/README.md`.

### Novium-Webspace

Für `node2.novium.world:22039` muss das Start-Image PHP CLI enthalten. Wenn der Bot auf einem externen Server läuft, braucht nur der Bot-Server Python; setze auf der Website `BOT_INTERNAL_URL` auf die HTTPS-Adresse des Bots und hinterlege auf beiden Servern denselben `BOT_WEBHOOK_SECRET`. Das Panel-Image aus dem Screenshot hatte kein PHP; nutze ein PHP-Image. Wenn Website und Bot doch zusammen laufen sollen, verwende den beiliegenden Dockerfile-Build mit beiden Laufzeitumgebungen.

Für Discord OAuth2 muss `DISCORD_REDIRECT_URI` auf die vollständige Callback-Adresse dieser Website zeigen und im Developer Portal exakt gleich unter **OAuth2 → Redirects** eingetragen sein, inklusive Schema, Port und Pfad `/api/index.php?route=callback`. Verwende nach Möglichkeit die HTTPS-Adresse, falls Novium sie für diesen Port bereitstellt. Die Adresse ohne `http://` oder `https://` allein ist keine vollständige Callback-URL.

Für die veröffentlichte Website `https://ironshield.novium.link/` lautet der konkrete Wert `https://ironshield.novium.link/api/index.php?route=callback`. Trage ihn sowohl im Hosting-Panel als `DISCORD_REDIRECT_URI` als auch in Discord unter **OAuth2 → Redirects** ein. Die Live-Seite hat zuvor noch die lokale `localhost`-Adresse an Discord gesendet.

## Umzug auf Vercel

Die Dateispeicherung aus dem bisherigen Hosting gilt nicht für Vercel. Dort müssen Sitzungen, Teamkonten, Tickets, Dashboard-Einstellungen und Anhänge über `DATABASE_URL` in PostgreSQL liegen. Die private Quelldatensicherung unter `.ironshield-private/` wird nicht mit deployed (sie steht absichtlich in `.vercelignore`). Nach Einrichtung der Datenbank trägst du dieselbe PostgreSQL-Verbindungs-URL wie in Vercel Production in die ignorierte lokale `.env` ein und startest in PowerShell `.\scripts\import-private-data.ps1`. Der Helfer verwendet die im Projekt enthaltene PHP-CLI und PostgreSQL-Erweiterung; Zugangsdaten werden nicht ausgegeben. Die vollständige Reihenfolge steht in [`VERCEL_DEPLOY.md`](VERCEL_DEPLOY.md). Ohne Vercel-Zugang und Produktions-Datenbank bleibt Bereitstellung beziehungsweise Import offen.
