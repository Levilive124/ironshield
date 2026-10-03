# Vercel-Migration

Alle sichtbaren Seiten liegen als statische HTML-Dateien vor: Startseite, Dashboard, Support, Team-Anmeldung, Teamverwaltung, Tickets und die drei Rechtstexte. Styles und Browserlogik liegen in statischen CSS-/JavaScript-Dateien. Login, Discord-Abfragen, Sitzungen, Ticketänderungen und Bot-Synchronisierung bleiben geschützte PHP-API-Funktionen unter `api/`; PHP erzeugt keine Seitenansichten mehr. Alte Links mit `?route=...` werden zur API weitergeleitet, Links auf die früheren Rechtstext-Routen leiten zu den statischen Dateien um.

## Vor einem Live-Umzug zwingend erledigen

Für Vercel werden Teamkonten, Tickets, Ankündigungen, Sitzungen, Dashboard-Relay-Zustand und Ticket-Anhänge in PostgreSQL gespeichert. Der Adapter legt seine Tabellen beim ersten Verbindungsaufbau an. Ohne `DATABASE_URL` lehnt die Anwendung dynamische Vercel-Routen mit HTTP 503 ab, statt Daten in flüchtige Dateien zu schreiben. Vor dem Live-Schalten muss der bestehende `.ironshield-private`-Inhalt einmalig in die Datenbank migriert werden. Die PDO-PostgreSQL-Erweiterung der PHP-Runtime wird benötigt.

Die private Datensicherung aus dem bisherigen Hosting muss lokal in `.ironshield-private/` liegen. Eine `DATABASE_URL` kann für den Einmalimport in die ignorierte lokale `.env` geschrieben werden; der Import liest nur diesen Schlüssel und gibt den Wert nicht aus. Danach mit installiertem PHP einmalig im Projektordner ausführen:

```sh
php scripts/import-private-data.php
```

Das Script importiert Konten, Tickets, Ankündigungen, Dashboard-Zustand und passende Ticket-Anhänge in einer Transaktion. Wiederholte Aufrufe mit unverändertem Datenstand werden erkannt. Es gibt weder private Inhalte noch Zugangsdaten aus und verändert die Quelldateien nicht.

## Hosting-Werte nach Einrichtung des Speichers

In Vercel unter **Project → Settings → Environment Variables** serverseitig hinterlegen (niemals in `assets/` oder im Browser):

- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` — `https://<deine-vercel-domain>/?route=callback`
- `PUBLIC_SITE_URL` — `https://<deine-vercel-domain>`
- `DASHBOARD_BRIDGE_SECRET` — derselbe zufällige Schlüssel wie beim Bot, mindestens 32 Zeichen
- `DASHBOARD_BOT_TOKEN` — nur, falls der Website-Code die Discord-API direkt abfragen muss
- `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD`
- `DATABASE_URL` — TLS-geschützte PostgreSQL-Verbindungs-URL (z. B. von Neon)

Der Bot-Token und der Bridge-Schlüssel bleiben ausschließlich in serverseitigen Umgebungsvariablen. Sie werden nicht in HTML, JavaScript oder statischen Dateien eingebettet. Für Ticketanhänge begrenzt Vercel die Anfragegröße; auf Vercel lässt das Portal daher derzeit insgesamt bis zu 4 MiB pro Upload-Anfrage zu.

Die Redirect-URL muss exakt dieselbe sein wie unter **Discord Developer Portal → OAuth2 → Redirects**. Der Bot-Host braucht nach dem Domainwechsel `PUBLIC_SITE_URL` mit der neuen HTTPS-Domain und denselben `DASHBOARD_BRIDGE_SECRET`.

Die Website-Einladelinks fordern keine Berechtigung zum Erstellen von Kanälen oder Senden von Nachrichten an. Das Dashboard listet vorhandene Kanäle nur zum Auswählen. Im Bot-Verzeichnis gibt es in dieser Version keinen Kanal-Erstellungs- oder Nachrichten-Sendeaufruf; die vorhandene Startbereinigung löscht ausschließlich alte Relay-Kanäle mit dem eindeutigen IronShield-Marker.

## Deployment

Die Vercel-PHP-Ausführung verwendet `vercel-php@0.9.0` mit Node.js 22. Die ältere Runtime `0.5.2` basiert auf Node.js 14 und wird von Vercel nicht mehr akzeptiert. Die Bereitstellung benötigt ein verbundenes Git-Repository oder eine Vercel-CLI-Anmeldung. Beides ist in diesem Arbeitsordner derzeit nicht eingerichtet; außerdem muss vor Livebetrieb PostgreSQL bereitgestellt, befüllt und in Vercel konfiguriert werden. Deshalb ist diese lokale Umstellung noch nicht live veröffentlicht.
