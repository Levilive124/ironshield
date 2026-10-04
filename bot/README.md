# Iron Shield Ticket-Bot (Python)

Dieser Ordner enthält den eigenständig hostbaren Python-Dienst. Er kann Discord verbinden, veröffentlicht mit der aktuellen Konfiguration aber keine Nachrichten und erstellt keine Serverkanäle oder Ticket-Threads. Website und Bot können beim selben Anbieter auf getrennten Servern laufen.

## Einrichtung auf dem externen Server

1. Setze den Discord-Bot-Token privat als `DISCORD_BOT_TOKEN`.
2. Setze einen eigenen zufälligen `DASHBOARD_BRIDGE_SECRET` (mindestens 32 Zeichen), identisch auf Website- und Bot-Host. Während der Umstellung wird ein bereits geteilter eigener `BOT_WEBHOOK_SECRET` ersatzweise akzeptiert. Verwende niemals den Discord-Token als diesen Schlüssel.
3. Setze `PUBLIC_SITE_URL` auf die HTTPS-Domain des Website-Hosts (ohne Pfad und Query).
4. Starte den Dienst mit `docker compose up -d --build` und prüfe die Logs mit `docker compose logs -f ticket-bot`.

Dieses Docker-Setup wird für die Website-zu-Bot-Ticketveröffentlichung nicht mehr benötigt; die Bridge erstellt keine Discord-Threads oder Nachrichten.

`PUBLIC_SITE_URL` ist die Website-Adresse, die der Dashboard-Cog abfragt. Der Cog ruft darunter direkt `/api/index.php?route=dashboard_bridge` auf. Er sendet die konfigurierte Domain als TLS-SNI-Hostname. Website und Bot benötigen keine gemeinsame Maschine; `localhost` funktioniert zwischen getrennten Servern nicht. Nutze für HTTPS den Domainnamen, für den das Zertifikat ausgestellt ist.

Für die Modulverwaltung setze `WEBAPI_ENABLED=1`, `WEBAPI_PORT`, `WEBAPI_CERT`, `WEBAPI_PATH`, `WEBAPI_HMAC` und `WEBAPI_ACTORS`. Wenn der Webhost kein Clientzertifikat samt privatem Schlüssel bekommen kann, setze `WEBAPI_REQUIRE_CLIENT_CERT=0` auf dem Bot und `DASHBOARD_WEBAPI_REQUIRE_CLIENT_CERT=0` auf der Website. Beide Schalter müssen übereinstimmen. Dann sind `WEBAPI_CA` und `WEBAPI_CLIENT_CN` für Clientzertifikate nicht nötig; die Website prüft weiterhin das HTTPS-Serverzertifikat mit `DASHBOARD_WEBAPI_SERVER_CA_PEM`. HMAC-Signatur, geheimer Pfad, Actor-Freigabe und Berechtigungsprüfung bleiben aktiv. Die Bot-WebAPI braucht einen von außen oder über ein freigeschaltetes internes Hosternetz erreichbaren Listener-Port.

Falls das Log `DISCORD_BOT_TOKEN fehlt` zeigt, hat der Bot-Server die Variable noch nicht erhalten. Setze sie in dessen Hosting-Panel unter den Startup-/Environment-Variablen oder lege eine private `.env` neben `main.py` an. `.env.example` enthält absichtlich Platzhalter. Beim Compose-Betrieb werden die Werte aus `bot/.env` geladen; lade `.env` nicht in ein öffentliches Git-Repository hoch. Auf der Website wird der Discord-Token als `DASHBOARD_BOT_TOKEN` ausschließlich für Discord-API-Abfragen benötigt. Der Bot sendet stattdessen nur `DASHBOARD_BRIDGE_SECRET` an die Website.

## Discord-Rechte

Für den Dashboard-Cog ist `guilds` als Gateway-Intent erforderlich, damit er Serverinventare lesen kann. Er sendet keine Nachrichten und erstellt keine Kanäle. Der einzige Discord-Löschzugriff betrifft den alten Relay-Kanal mit Marker `ironshield-dashboard-relay:v1`.

## Ablauf

PHP speichert Tickets dauerhaft nur auf der Website. Es erfolgt keine Veröffentlichung in Discord.
