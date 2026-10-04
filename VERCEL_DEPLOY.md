# Vercel-Migration

Alle sichtbaren Seiten liegen als statische HTML-Dateien vor: Startseite, Dashboard, Support, Team-Anmeldung, Teamverwaltung, Tickets und die drei Rechtstexte. Styles und Browserlogik liegen in statischen CSS-/JavaScript-Dateien. Login, Discord-Abfragen, Sitzungen, Ticketänderungen und Bot-Synchronisierung bleiben geschützte PHP-API-Funktionen unter `api/`; PHP erzeugt keine Seitenansichten mehr. Die Browser und der Bot rufen die Funktion direkt unter `/api/index.php?route=…` auf. Alte Links mit `/?route=…` werden nicht als API-Endpunkt vorausgesetzt.

## Vor einem Live-Umzug zwingend erledigen

Vor dem Cutover auch `datenschutz.html` aktualisieren: Die vorhandenen Abschnitte nennen noch Novium und beschreiben teils eine SQL-freie Speicherung sowie eine Ticket-Veröffentlichung in Discord. Beides entspricht dem Vercel-Ziel beziehungsweise dem aktuellen Ticket-Code nicht. Trage erst nach Auswahl des tatsächlichen Vercel-/Datenbank-Setups die bestätigten Anbieter-, Speicherort-, Protokoll- und Aufbewahrungsinformationen ein; beschreibe den aktuellen Ticketablauf korrekt. Bis diese Angaben geprüft sind, die Datenschutzseite nicht als für den neuen Host aktualisiert betrachten.

Für Vercel werden Teamkonten, Tickets, Ankündigungen, Sitzungen, Dashboard-Relay-Zustand und Ticket-Anhänge in PostgreSQL gespeichert. Der Adapter legt seine Tabellen beim ersten Verbindungsaufbau an. Ohne `DATABASE_URL` lehnt die Anwendung dynamische Vercel-Routen mit HTTP 503 ab, statt Daten in flüchtige Dateien zu schreiben. Vor dem Live-Schalten muss der bestehende `.ironshield-private`-Inhalt einmalig in die Datenbank migriert werden. Die konfigurierte `vercel-php@0.9.0`-Runtime verwendet PHP 8.5 und enthält `PDO_PGSQL` (`pdo_pgsql`). Für den Import unter Windows enthält das Projekt zusätzlich eine portable PHP-CLI und den PowerShell-Helfer; eine systemweite PHP-Installation ist nicht nötig.

Die private Datensicherung aus dem bisherigen Hosting muss lokal in `.ironshield-private/` liegen. Eine `DATABASE_URL` kann für den Einmalimport in die ignorierte lokale `.env` geschrieben werden; der Import liest nur diesen Schlüssel und gibt den Wert nicht aus. Die portable PHP-CLI und `PDO_PGSQL` liegen im Projekt unter `.runtime/php/`. In PowerShell im Projektordner den Importhelfer einmalig starten:

```sh
.\scripts\import-private-data.ps1
```

Trage dafür die Verbindungs-URL derselben PostgreSQL-Datenbank ein, die Vercel **Production** verwendet. Die URL nicht hier im Chat posten und `.env` nicht hochladen. Der Helfer aktiviert nur für diesen Aufruf die vorhandene PostgreSQL-PHP-Erweiterung.

Das Script importiert Konten, Tickets, Ankündigungen, Dashboard-Zustand und passende Ticket-Anhänge in einer Transaktion. Der Import-Fingerabdruck berücksichtigt Store, Dashboard-Zustand und Anhänge; unveränderte Wiederholungen werden übersprungen. Bei einem neueren Ticketstand werden neue Nachrichten ergänzt, bestehende Nachrichten bleiben erhalten. Das Script gibt weder private Inhalte noch Zugangsdaten aus und verändert die Quelldateien nicht.

Die Abschlussmeldung enthält nur Mengenangaben zu Teamkonten, Tickets, Ankündigungen und neu gespeicherten Anhängen. Vergleiche sie vor dem Live-Cutover mit dem bisherigen Datenstand.

Bereits aktive PHP-Sitzungen des bisherigen Hosts werden nicht mitgenommen; die Sitzungen lagen außerhalb dieser privaten Datensicherung. Nach dem Umzug müssen sich Nutzer erneut über Discord anmelden und Teammitglieder erneut mit ihrem bisherigen Teamkonto anmelden. Teamkonten einschließlich Passwort-Hashes und die gespeicherten Tickets werden durch den Import übernommen.

## Hosting-Werte nach Einrichtung des Speichers

### Meldung „DATABASE_URL ist auf Vercel erforderlich“

Diese Meldung bedeutet, dass das aktuelle Deployment keine Datenbank-Verbindungsvariable sieht. Die Sperre bitte nicht aus dem Code entfernen: Ohne dauerhafte Datenbank könnten Sitzungen und Änderungen bei Serverless-Neustarts verloren gehen.

1. Öffne in Vercel das **Projekt → Storage** beziehungsweise den **Marketplace** und füge einen PostgreSQL-Anbieter hinzu, zum Beispiel Neon. Vercel führt PostgreSQL über Marketplace-Integrationen; beim Verbinden werden die Zugangsdaten als Projekt-Umgebungsvariablen bereitgestellt.
2. Wähle mindestens **Production**. Wenn Preview-Deployments genutzt werden, verbinde auch **Preview** mit einer Datenbank. Prüfe unter **Project → Settings → Environment Variables**, dass der Variablenname exakt `DATABASE_URL` lautet.
3. Falls die Integration den Namen nicht automatisch anlegt, füge `DATABASE_URL` dort manuell hinzu und trage die vollständige PostgreSQL-Verbindungs-URL des Anbieters ein. Den Wert nur in Vercel speichern, niemals hier im Chat, in HTML/JavaScript oder im Git-Repository.
4. Speichere die Variable und starte unter **Deployments** für Production ein neues Deployment beziehungsweise ein Redeploy. Vercel wendet geänderte Umgebungsvariablen nicht rückwirkend auf bereits erstellte Deployments an.
5. Lade das Dashboard nach erfolgreichem Deployment neu. Der Datenbankadapter legt die Tabellen beim ersten API-Aufruf an. Importiere anschließend beziehungsweise vor dem Live-Cutover die vorhandenen privaten Daten mit dem oben beschriebenen PowerShell-Helfer in genau diese Datenbank, damit Teamkonten und Tickets erhalten bleiben.

Vercel dokumentiert das Verbinden von Storage über Marketplace-Integrationen und verlangt für geänderte Variablen ein neues Deployment: [Storage on Vercel](https://vercel.com/docs/marketplace-storage), [Environment Variables](https://vercel.com/docs/environment-variables/managing-environment-variables).

In Vercel unter **Project → Settings → Environment Variables** serverseitig hinterlegen (niemals in `assets/` oder im Browser):

- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` — `https://<deine-vercel-domain>/api/index.php?route=callback`
- `PUBLIC_SITE_URL` — `https://<deine-vercel-domain>`
- `DASHBOARD_BRIDGE_SECRET` — derselbe zufällige Schlüssel wie beim Bot, mindestens 32 Zeichen
- `DASHBOARD_BOT_TOKEN` — nur, falls der Website-Code die Discord-API direkt abfragen muss
- `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD`
- `DATABASE_URL` — TLS-geschützte PostgreSQL-Verbindungs-URL (z. B. von Neon)

Der PHP-Session-Handler hält seinen Sperr-Lock in einer eigenen kurzen Transaktion. Daher funktionieren sowohl direkte PostgreSQL-URLs als auch Transaktions-Pooler-URLs; verwende für den Datenbank-Import und für Vercel dieselbe Datenbank und dasselbe Schema.

Bei Neon ergänzt der Adapter die Endpoint-ID aus dem Datenbank-Hostname automatisch als libpq-Verbindungsoption. Das ist ein Fallback für PHP/PostgreSQL-Clients, deren libpq-Build Neon nicht über TLS-SNI routen kann. Der Endpoint-Identifier ist kein Passwort und wird nicht an Browser oder Logs ausgegeben.

Der Bot-Token und der Bridge-Schlüssel bleiben ausschließlich in serverseitigen Umgebungsvariablen. Sie werden nicht in HTML, JavaScript oder statischen Dateien eingebettet. Für Ticketanhänge begrenzt Vercel die Anfragegröße; auf Vercel lässt das Portal daher derzeit insgesamt bis zu 4 MiB pro Upload-Anfrage zu.

Die Redirect-URL muss exakt dieselbe sein wie unter **Discord Developer Portal → OAuth2 → Redirects**. Der Bot-Host braucht nach dem Domainwechsel `PUBLIC_SITE_URL` mit der neuen HTTPS-Domain und denselben `DASHBOARD_BRIDGE_SECRET`. Browser-Aufrufe, OAuth-Callbacks und Bot-Synchronisierung verwenden `/api/index.php?route=…`, damit sie direkt die PHP-Funktion aufrufen und nicht von statischen Dateien oder Rewrites abgefangen werden.

Die Website-Einladelinks fordern keine Berechtigung zum Erstellen von Kanälen oder Senden von Nachrichten an. Das Dashboard listet vorhandene Kanäle nur zum Auswählen. Im Bot-Verzeichnis gibt es in dieser Version keinen Kanal-Erstellungs- oder Nachrichten-Sendeaufruf; die vorhandene Startbereinigung löscht ausschließlich alte Relay-Kanäle mit dem eindeutigen IronShield-Marker.

### PHP-API-Bereitstellung prüfen

Rufe nach einem Deployment `https://<deine-vercel-domain>/api/health.php` direkt im Browser auf. Bei korrekt ausgeführter PHP-Funktion muss JSON `{"ok":true,"service":"ironshield-api"}` erscheinen. HTML, eine Vercel-Fehlerseite oder ein Redirect bedeutet, dass der API-Endpunkt nicht als PHP-Funktion bereitgestellt wird. Erst wenn dieser Health-Endpunkt JSON liefert, prüfe `https://<deine-vercel-domain>/api/index.php?route=dashboard_data`; ohne Anmeldung ist `{"error":"login_required"}` die erwartete JSON-Antwort. Ein Datenbankfehler kommt erst danach und wird als JSON mit HTTP 503 ausgegeben.

## Deployment

Die Vercel-PHP-Ausführung verwendet `vercel-php@0.9.0` mit Node.js 22. Die ältere Runtime `0.5.2` basiert auf Node.js 14 und wird von Vercel nicht mehr akzeptiert. Direkte Aufrufe der alten `/index.php`-Seitenroute werden auf eine 404-API-Antwort umgeleitet; die Datei bleibt nur als serverseitige gemeinsame API-Logik vorhanden.

### GitHub-Repository vorbereiten

Wenn Vercel meldet, dass der angegebene Branch oder Commit fehlt, ist das GitHub-Repository meist noch leer oder der ausgewählte Branch existiert darin nicht. Erstelle in GitHub zuerst ein **leeres** Repository (ohne README, Lizenz oder `.gitignore`). Öffne dann PowerShell im Projektordner und veröffentliche den ersten Commit:

```powershell
git init -b main
git config user.name "<DEIN NAME>"
git config user.email "<DEINE GITHUB-E-MAIL>"
git add .
git commit -m "Prepare Iron Shield for Vercel"
git remote add origin https://github.com/<BENUTZERNAME>/<REPOSITORY>.git
git push -u origin main
```

Ersetze die Platzhalter durch deine Angaben. `git config` setzt den Commit-Namen und die E-Mail nur für dieses Repository; du kannst in GitHub unter den E-Mail-Einstellungen eine private `noreply`-Adresse verwenden. `.gitignore` schließt `.env` und `.ironshield-private/` aus; prüfe vor dem Commit und Push trotzdem mit `git status`, dass dort keine Zugangsdaten oder privaten Sicherungsdateien zur Veröffentlichung vorgemerkt sind. Wähle beim Vercel-Import anschließend genau dieses Repository und den Branch `main`; als Root Directory den Projektordner verwenden, Framework Preset **Other**, keinen eigenen Build-Befehl und kein separates Output-Verzeichnis setzen.

### Erforderliche externe Einrichtung

Die Bereitstellung benötigt außerdem ein Vercel-Projekt, eine Vercel-Anmeldung und eine PostgreSQL-Datenbank. Importiere die vorhandene private Datensicherung wie oben beschrieben, setze alle Hosting-Variablen in Vercel und deploye danach neu. Ohne GitHub-Repository, Vercel-Zugang und konfigurierte `DATABASE_URL` ist die lokale Umstellung vorbereitet, aber noch nicht live veröffentlicht.
