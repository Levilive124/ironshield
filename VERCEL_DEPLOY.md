# Vercel-Migration

Die öffentliche Startseite liegt als statisches `index.html` vor; Styles und Startseiten-Script liegen als `.css` und `.js` vor. Vercel leitet vorhandene dynamische Funktionen mit `?route=...` an `api/index.php` weiter und den Rechtstext-Aufruf an `api/recht.php`, damit keine PHP-Datei als Download ausgeliefert wird. Diese dynamischen Ansichten sind noch nicht vollständig auf HTML/JavaScript-Oberflächen umgestellt.

## Vor einem Live-Umzug zwingend erledigen

Für Vercel werden Teamkonten, Tickets, Ankündigungen, Sitzungen, Dashboard-Relay-Zustand und Ticket-Anhänge in PostgreSQL gespeichert. Der Adapter legt seine Tabellen beim ersten Verbindungsaufbau an. Ohne `DATABASE_URL` lehnt die Anwendung dynamische Vercel-Routen mit HTTP 503 ab, statt Daten in flüchtige Dateien zu schreiben. Vor dem Live-Schalten muss der bestehende `.ironshield-private`-Inhalt einmalig in die Datenbank migriert werden. Die PDO-PostgreSQL-Erweiterung der PHP-Runtime wird benötigt.

Die private Datensicherung aus dem bisherigen Hosting muss lokal in einen geschützten Ordner heruntergeladen werden. Danach mit installiertem PHP und `DATABASE_URL` als Umgebungsvariable einmalig ausführen:

```sh
php scripts/import-private-data.php /pfad/zum/.ironshield-private
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

Die Redirect-URL muss exakt dieselbe sein wie unter **Discord Developer Portal → OAuth2 → Redirects**. Der Bot-Host braucht nach dem Domainwechsel `PUBLIC_SITE_URL` mit der neuen HTTPS-Domain und denselben `DASHBOARD_BRIDGE_SECRET`.

## Deployment

Die Vercel-PHP-Ausführung verwendet `vercel-php@0.9.0` mit Node.js 22. Die ältere Runtime `0.5.2` basiert auf Node.js 14 und wird von Vercel nicht mehr akzeptiert. Die Bereitstellung benötigt ein verbundenes Git-Repository oder eine Vercel-CLI-Anmeldung. Beides ist in diesem Arbeitsordner derzeit nicht eingerichtet. Erst nach dem persistenten Speicherumbau und dem Setzen der Geheimnisse sollte das Projekt als Produktion veröffentlicht werden.
