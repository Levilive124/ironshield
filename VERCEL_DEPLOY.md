# Vercel-Migration

Alle sichtbaren Seiten liegen als statische HTML-Dateien vor: Startseite, Dashboard, Support, Team-Anmeldung, Teamverwaltung, Tickets und die drei Rechtstexte. Styles und Browserlogik liegen in statischen CSS-/JavaScript-Dateien. Login, Discord-Abfragen, Sitzungen, Ticketänderungen und Bot-Synchronisierung bleiben geschützte PHP-API-Funktionen unter `api/`; PHP erzeugt keine Seitenansichten mehr. Die Browser und der Bot rufen die Funktion direkt unter `/api/index.php?route=…` auf. Alte Links mit `/?route=…` werden nicht als API-Endpunkt vorausgesetzt.

## Vor einem Live-Umzug zwingend erledigen

Vor dem Cutover auch `datenschutz.html` aktualisieren: Die vorhandenen Abschnitte nennen noch Novium und beschreiben teils eine SQL-freie Speicherung sowie eine Ticket-Veröffentlichung in Discord. Beides entspricht dem Vercel-Ziel beziehungsweise dem aktuellen Ticket-Code nicht. Trage erst nach Auswahl des tatsächlichen Vercel-/Datenbank-Setups die bestätigten Anbieter-, Speicherort-, Protokoll- und Aufbewahrungsinformationen ein; beschreibe den aktuellen Ticketablauf korrekt. Bis diese Angaben geprüft sind, die Datenschutzseite nicht als für den neuen Host aktualisiert betrachten.

Für Vercel werden Teamkonten, Tickets, Ankündigungen, Sitzungen, Dashboard-Relay-Zustand und Ticket-Anhänge in PostgreSQL gespeichert. Der Adapter legt seine Tabellen beim ersten Verbindungsaufbau an. Ohne `DATABASE_URL` lehnt die Anwendung dynamische Vercel-Routen mit HTTP 503 ab, statt Daten in flüchtige Dateien zu schreiben. Vor dem Live-Schalten muss der bestehende `.ironshield-private`-Inhalt einmalig in die Datenbank migriert werden. Die konfigurierte `vercel-php@0.9.0`-Runtime verwendet PHP 8.5 und enthält `PDO_PGSQL` (`pdo_pgsql`); für den Import auf deinem PC muss deine lokale PHP-Installation dieselbe Erweiterung aktivieren.

Die private Datensicherung aus dem bisherigen Hosting muss lokal in `.ironshield-private/` liegen. Eine `DATABASE_URL` kann für den Einmalimport in die ignorierte lokale `.env` geschrieben werden; der Import liest nur diesen Schlüssel und gibt den Wert nicht aus. Danach mit installiertem PHP einmalig im Projektordner ausführen:

```sh
php scripts/import-private-data.php
```

Das Script importiert Konten, Tickets, Ankündigungen, Dashboard-Zustand und passende Ticket-Anhänge in einer Transaktion. Der Import-Fingerabdruck berücksichtigt Store, Dashboard-Zustand und Anhänge; unveränderte Wiederholungen werden übersprungen. Bei einem neueren Ticketstand werden neue Nachrichten ergänzt, bestehende Nachrichten bleiben erhalten. Das Script gibt weder private Inhalte noch Zugangsdaten aus und verändert die Quelldateien nicht.

Bereits aktive PHP-Sitzungen des bisherigen Hosts werden nicht mitgenommen; die Sitzungen lagen außerhalb dieser privaten Datensicherung. Nach dem Umzug müssen sich Nutzer erneut über Discord anmelden und Teammitglieder erneut mit ihrem bisherigen Teamkonto anmelden. Teamkonten einschließlich Passwort-Hashes und die gespeicherten Tickets werden durch den Import übernommen.

## Hosting-Werte nach Einrichtung des Speichers

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

Der Bot-Token und der Bridge-Schlüssel bleiben ausschließlich in serverseitigen Umgebungsvariablen. Sie werden nicht in HTML, JavaScript oder statischen Dateien eingebettet. Für Ticketanhänge begrenzt Vercel die Anfragegröße; auf Vercel lässt das Portal daher derzeit insgesamt bis zu 4 MiB pro Upload-Anfrage zu.

Die Redirect-URL muss exakt dieselbe sein wie unter **Discord Developer Portal → OAuth2 → Redirects**. Der Bot-Host braucht nach dem Domainwechsel `PUBLIC_SITE_URL` mit der neuen HTTPS-Domain und denselben `DASHBOARD_BRIDGE_SECRET`. Browser-Aufrufe, OAuth-Callbacks und Bot-Synchronisierung verwenden `/api/index.php?route=…`, damit sie direkt die PHP-Funktion aufrufen und nicht von statischen Dateien oder Rewrites abgefangen werden.

Die Website-Einladelinks fordern keine Berechtigung zum Erstellen von Kanälen oder Senden von Nachrichten an. Das Dashboard listet vorhandene Kanäle nur zum Auswählen. Im Bot-Verzeichnis gibt es in dieser Version keinen Kanal-Erstellungs- oder Nachrichten-Sendeaufruf; die vorhandene Startbereinigung löscht ausschließlich alte Relay-Kanäle mit dem eindeutigen IronShield-Marker.

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
