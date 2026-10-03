# Vercel-Migration

Die Anwendung wird serverseitig von `index.php` gerendert und verwendet PHP für Discord-OAuth, Team-Login, Tickets und Datei-Anhänge. `api/index.php` und `vercel.json` leiten Web-Anfragen an die PHP-Funktion weiter; statische Dateien aus `assets/` bleiben Teil des Deployments.

## Vor einem Live-Umzug zwingend erledigen

Die Website speichert Teamkonten, Tickets, Ankündigungen und Anhänge derzeit unter `.ironshield-private`. Vercel-Funktionen dürfen nicht als dauerhafter Dateispeicher verwendet werden. Vor dem Live-Schalten muss dieser Speicher durch eine dauerhafte Datenbank und privaten Objektspeicher ersetzt und der vorhandene Inhalt migriert werden. Bis dahin darf die Vercel-Version keine produktiven Schreibvorgänge annehmen.

Außerdem verwendet PHP-Dateisitzungen. Für einen zuverlässigen Login über mehrere kurzlebige Funktionsaufrufe muss die Sitzung in einen gemeinsamen persistenten Sitzungsspeicher umgestellt werden.

## Hosting-Werte nach Einrichtung des Speichers

In Vercel unter **Project → Settings → Environment Variables** serverseitig hinterlegen (niemals in `assets/` oder im Browser):

- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` — `https://<deine-vercel-domain>/?route=callback`
- `PUBLIC_SITE_URL` — `https://<deine-vercel-domain>`
- `DASHBOARD_BRIDGE_SECRET` — derselbe zufällige Schlüssel wie beim Bot, mindestens 32 Zeichen
- `DASHBOARD_BOT_TOKEN` — nur, falls der Website-Code die Discord-API direkt abfragen muss
- `TEAM_ADMIN_USERNAME` und `TEAM_ADMIN_PASSWORD`
- `DATABASE_URL` und die Zugangsdaten des privaten Datei-Speichers, sobald der Speicheradapter eingebaut ist

Die Redirect-URL muss exakt dieselbe sein wie unter **Discord Developer Portal → OAuth2 → Redirects**. Der Bot-Host braucht nach dem Domainwechsel `PUBLIC_SITE_URL` mit der neuen HTTPS-Domain und denselben `DASHBOARD_BRIDGE_SECRET`.

## Deployment

Die Vercel-PHP-Ausführung verwendet `vercel-php@0.9.0` mit Node.js 22. Die ältere Runtime `0.5.2` basiert auf Node.js 14 und wird von Vercel nicht mehr akzeptiert. Die Bereitstellung benötigt ein verbundenes Git-Repository oder eine Vercel-CLI-Anmeldung. Beides ist in diesem Arbeitsordner derzeit nicht eingerichtet. Erst nach dem persistenten Speicherumbau und dem Setzen der Geheimnisse sollte das Projekt als Produktion veröffentlicht werden.
