"""cogs/webapi.py — abgeschirmte RPC-Schnittstelle für das Web-Dashboard.

Sie wird nur serverseitig von der Website aufgerufen, nie direkt vom Browser.
Die Website prüft das Bot-Serverzertifikat gegen ihre hinterlegte CA. mTLS mit
Clientzertifikat ist standardmäßig zusätzlich aktiv; falls der Website-Host kein
Clientzertifikat erhalten kann, lässt sich ausschließlich diese zusätzliche
Schicht bewusst abschalten. Die weiteren Prüfungen bleiben zwingend:

  1. TLS 1.3; Clientzertifikat und CN-Pin sind standardmäßig Pflicht (mTLS).
  2. Geheimer Pfad (256 Bit) — jeder andere Pfad: 404, leer.
  3. HMAC-SHA256 über Zeitstempel, Nonce, Actor und Body-Hash. Fenster 30 s,
     Nonce-Speicher gegen Replay.
  4. Actor muss in OWNER_IDS *und* in WEBAPI_ACTORS stehen.
  5. Nur Kommandos aus der RPC-Registry, jedes mit Schema-Prüfung. Kein getattr
     auf Eingaben, kein eval, kein Dateipfad aus Parametern.
  6. Rate-Limit pro Actor, 64-KB-Body-Limit, harte Handshake-/Read-Timeouts.
  7. Kill-Switch: existiert die Datei data/webapi.off, antwortet alles mit 503 und
     der Listener wird geschlossen — ohne Bot-Neustart, per Panel-Dateimanager.

Antworten im Fehlerfall sind IMMER generisch ("denied"), Details nur ins Log —
ein Angreifer erfährt nicht, welche Schicht ihn gestoppt hat.

Der Listener kann den Bot nicht mitreißen: fehlt die Konfiguration, bleibt das Cog
still; jeder Fehler wird geloggt, nie geworfen.

ENV (in /home/container/.env):
    WEBAPI_ENABLED=1
    WEBAPI_PORT=33041                       # default: SERVER_PORT
    WEBAPI_CERT=/home/container/secrets/webapi-server.pem   # Cert + Key (PEM)
    WEBAPI_CA=/home/container/secrets/webapi-ca.crt         # CA, die Clients ausstellt
    WEBAPI_REQUIRE_CLIENT_CERT=1             # 0 nur falls Client-CA-Zugang fehlt
    WEBAPI_CLIENT_CN=vercel-dash
    WEBAPI_PATH=<64 Hex>                    # geheimer Pfadanteil
    WEBAPI_HMAC=<64 Hex>                    # Signaturschlüssel
    WEBAPI_ACTORS=<discord-user-id>          # Komma-Liste, Teilmenge von OWNER_IDS
    WEBAPI_ALLOW_ADMIN=0                    # 1 = logs.tail/cogs.reload freigeben
"""

import asyncio
import glob
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import ssl
import time
import uuid
from collections import deque

import discord
from aiohttp import web
from discord.ext import commands

import modules
import storage
import rolesafety
from owners import OWNER_IDS

log = logging.getLogger("ironshield.webapi")

VERSION = 1

# --- Konfiguration ----------------------------------------------------------
ENABLED = os.getenv("WEBAPI_ENABLED", "0") == "1"
PORT = int(os.getenv("WEBAPI_PORT") or os.getenv("SERVER_PORT") or 0)
CERT = os.getenv("WEBAPI_CERT", "")
CA = os.getenv("WEBAPI_CA", "")
CLIENT_CN = os.getenv("WEBAPI_CLIENT_CN", "vercel-dash")
REQUIRE_CLIENT_CERT = os.getenv("WEBAPI_REQUIRE_CLIENT_CERT", "1").strip() != "0"
SECRET_PATH = os.getenv("WEBAPI_PATH", "")
HMAC_KEY = os.getenv("WEBAPI_HMAC", "").encode()
ALLOW_ADMIN = os.getenv("WEBAPI_ALLOW_ADMIN", "0") == "1"

ACTORS = set()
for _raw in os.getenv("WEBAPI_ACTORS", "").replace(" ", "").split(","):
    if _raw.isdigit():
        ACTORS.add(int(_raw))
# Doppelte Sicherung: nur wer AUCH echter Owner ist, darf rein. Selbst wenn die
# ENV manipuliert würde, kommt niemand Fremdes durch.
ACTORS &= OWNER_IDS

KILL_FILE = os.path.join("data", "webapi.off")
AUDIT_NS = "webapi_audit"
AUDIT_KEEP = 2000

MAX_BODY = 64 * 1024
CLOCK_SKEW = 30          # Sekunden, in beide Richtungen
NONCE_TTL = 120           # Nonce so lange merken (> 2x CLOCK_SKEW)
RATE_LIMIT = 300          # Requests …
RATE_WINDOW = 60          # … pro Actor pro Minute
AUTHZ_TTL = 60            # Sekunden, wie lange eine Guild-Autorisierung gecacht wird

_DENIED = {"error": "denied"}


# --- RPC-Registry -----------------------------------------------------------
# name -> (spec, handler, admin, writes, scope)
# spec: {feld: (typ, pflicht)} mit typ aus {"id", "str", "text", "int", "bool"}
# scope: "super" (nur ACTORS/Bot-Owner), "guild" (ACTORS ODER Guild-Admin/-Owner,
#        siehe _guild_authorized), "self" (jeder authentifizierte Actor, Kommando
#        filtert selbst nach Actor). Standardmäßig automatisch aus dem Vorhanden-
#        sein von "guild_id" im Spec abgeleitet -- alle ~45 Guild-Kommandos haben
#        das Feld, alle "super"-Kommandos (status/guilds.list/audit.list/logs.tail/
#        cogs.reload) nicht. Explizites scope= überschreibt die Ableitung (nötig
#        für guilds.mine: kein guild_id-Feld, aber trotzdem kein Bot-Owner-Only).
RPC: dict[str, tuple] = {}


def rpc(name, spec=None, admin=False, writes=False, scope=None):
    def deco(fn):
        s = spec or {}
        resolved_scope = scope or ("guild" if "guild_id" in s else "super")
        RPC[name] = (s, fn, admin, writes, resolved_scope)
        return fn
    return deco


def _check(args, spec):
    """Minimale, strikte Schema-Prüfung. Gibt normalisierte Werte zurück.

    Unbekannte Felder sind ein Fehler (kein stilles Ignorieren) — so fällt eine
    veraltete oder manipulierte Gegenseite sofort auf.

    spec-Werte sind normalerweise (typ, pflicht) — ein optionales drittes
    Element (typ, pflicht, nullable=True) erlaubt ein Feld, das der Client
    per explizitem JSON `null` LÖSCHEN kann (z.B. verify.set_roles: eine
    einmal gesetzte Rolle musste bisher für immer gesetzt bleiben, weil
    "Feld fehlt" und "Feld ist null" identisch behandelt wurden). Ohne dieses
    Flag bleibt das bisherige Verhalten: null == fehlt == nicht angetastet.
    """
    if not isinstance(args, dict):
        raise ValueError("args kein Objekt")
    unknown = set(args) - set(spec)
    if unknown:
        raise ValueError(f"unbekannte Felder: {sorted(unknown)}")
    out = {}
    for field, meta in spec.items():
        typ, required = meta[0], meta[1]
        nullable = meta[2] if len(meta) > 2 else False
        if field not in args:
            if required:
                raise ValueError(f"{field} fehlt")
            continue
        if args[field] is None:
            if nullable:
                out[field] = None            # explizites Löschen, siehe Docstring
                continue
            if required:
                raise ValueError(f"{field} fehlt")
            continue
        v = args[field]
        if typ == "id":
            # Discord-Snowflakes kommen als STRING über JSON (JS verliert bei
            # >2^53 Präzision). Hier zurück zu int, streng validiert.
            if not isinstance(v, str) or not v.isdigit() or len(v) > 20:
                raise ValueError(f"{field} keine gültige ID")
            out[field] = int(v)
        elif typ == "str":
            if not isinstance(v, str) or len(v) > 200:
                raise ValueError(f"{field} kein kurzer String")
            out[field] = v
        elif typ == "text":
            # längere Freitexte (Willkommens-/Verify-Nachrichten) — immer noch
            # klar begrenzt, kein unbeschränktes Freitextfeld.
            if not isinstance(v, str) or len(v) > 2000:
                raise ValueError(f"{field} zu lang (max. 2000 Zeichen)")
            out[field] = v
        elif typ == "int":
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f"{field} kein Integer")
            out[field] = v
        elif typ == "bool":
            if not isinstance(v, bool):
                raise ValueError(f"{field} kein Bool")
            out[field] = v
        elif typ == "any":
            # Polymorpher Wert für generische Config-Setter (security.config.set) —
            # der HANDLER validiert selbst gegen das konkrete Feld-Schema (Choice/
            # Range/Bool/Channel). Hier nur ein grober Typ-Filter gegen Objekte/Arrays.
            if not isinstance(v, (str, int, bool)):
                raise ValueError(f"{field}: unerlaubter Typ")
            out[field] = v
        elif typ == "json":
            # Verschachtelte Struktur (Block-Liste des Embed-Baukastens). Hier
            # nur die STRUKTURELLE Abwehr: Größe und Tiefe. Was die Blöcke
            # bedeuten dürfen, prüft ausschließlich der Handler gegen
            # cogs.embeds.validate_blocks -- eine Stelle, ein Regelwerk.
            if not isinstance(v, (list, dict)):
                raise ValueError(f"{field} kein JSON-Objekt/-Array")
            try:
                raw = json.dumps(v)
            except (TypeError, ValueError):
                raise ValueError(f"{field} nicht serialisierbar")
            if len(raw) > 20000:
                raise ValueError(f"{field} zu groß (max. 20000 Zeichen)")

            def _depth(x, d=0):
                if d > 6:
                    raise ValueError(f"{field} zu tief verschachtelt")
                if isinstance(x, dict):
                    for item in x.values():
                        _depth(item, d + 1)
                elif isinstance(x, list):
                    for item in x:
                        _depth(item, d + 1)

            _depth(v)
            out[field] = v
        elif typ == "id_list":
            # Liste von Discord-Snowflakes (Rollen-IDs etc.) als JSON-Array von
            # Strings -- für Kommandos, die eine ganze Auswahl auf einmal ERSETZEN
            # (z.B. teamlist.set), statt einzeln an-/abzuwählen wie sonst üblich
            # (siehe security.config.roles.add/remove). Hart begrenzt (500),
            # damit ein manipulierter Client keine Riesen-Listen durchdrücken kann.
            if not isinstance(v, list) or len(v) > 500:
                raise ValueError(f"{field} keine gültige Liste (max. 500)")
            out_ids = []
            for item in v:
                if not isinstance(item, str) or not item.isdigit() or len(item) > 20:
                    raise ValueError(f"{field}: ungültige ID in Liste")
                out_ids.append(int(item))
            out[field] = out_ids
        else:                                     # pragma: no cover
            raise ValueError(f"unbekannter Typ {typ}")
    return out


# --- Cog --------------------------------------------------------------------
class WebAPI(commands.Cog):
    """HTTPS-RPC für das Dashboard. Läuft nur bei vollständiger Konfiguration."""

    def __init__(self, bot):
        self.bot = bot
        self._runner = None
        self._site = None
        self._nonces: dict[str, float] = {}
        self._hits: dict[int, deque] = {}
        self._killed = False
        self._watch = None
        # Guild-Autorisierung: (guild_id, actor) -> (ok, checked_at). Kurzes TTL
        # (siehe AUTHZ_TTL) + In-Flight-Lock pro Key, damit die ~17 parallelen
        # RPC-Calls, die ein einzelner Dashboard-Seitenaufruf abfeuert, nicht
        # 17x denselben fetch_member-Call gegen Discord auslösen.
        self._authz_cache: dict[tuple[int, int], tuple[bool, float]] = {}
        self._authz_locks: dict[tuple[int, int], asyncio.Lock] = {}

    # -- Lebenszyklus --------------------------------------------------------
    async def cog_load(self):
        problems = self._config_problems()
        if problems:
            log.warning("WebAPI bleibt AUS: %s", "; ".join(problems))
            return
        try:
            await self._start()
        except Exception as e:
            log.error("WebAPI-Start fehlgeschlagen: %r", e)

    async def cog_unload(self):
        self._watch and self._watch.cancel()
        await self._stop()

    def _config_problems(self):
        p = []
        if not ENABLED:
            p.append("WEBAPI_ENABLED != 1")
        if not PORT:
            p.append("kein Port (WEBAPI_PORT/SERVER_PORT)")
        if not CERT or not os.path.isfile(CERT):
            p.append("WEBAPI_CERT fehlt")
        if REQUIRE_CLIENT_CERT and (not CA or not os.path.isfile(CA)):
            p.append("WEBAPI_CA fehlt")
        if len(SECRET_PATH) < 32:
            p.append("WEBAPI_PATH zu kurz")
        if len(HMAC_KEY) < 32:
            p.append("WEBAPI_HMAC zu kurz")
        if not ACTORS:
            p.append("WEBAPI_ACTORS leer (oder keine Owner-IDs)")
        if os.path.exists(KILL_FILE):
            p.append(f"Kill-Switch aktiv ({KILL_FILE})")
        return p

    def _ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # nichts Älteres, keine Downgrades
        ctx.load_cert_chain(CERT)
        if REQUIRE_CLIENT_CERT:
            ctx.load_verify_locations(CA)
            ctx.verify_mode = ssl.CERT_REQUIRED        # Client-Zertifikat bleibt Standard
        else:
            # Server-TLS bleibt aktiv; HMAC, Zeitfenster, Nonce, Actor und
            # RPC-Schema sind auch in diesem Modus zwingend.
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _start(self):
        app = web.Application(client_max_size=MAX_BODY)
        # Genau EINE echte Route. Alles andere fällt in den Catch-all -> 404.
        app.router.add_post("/{secret}/rpc", self._handle)
        app.router.add_route("*", "/{tail:.*}", self._notfound)

        self._runner = web.AppRunner(app, access_log=None, handle_signals=False)
        await self._runner.setup()
        self._site = web.TCPSite(
            self._runner, "0.0.0.0", PORT,
            ssl_context=self._ssl_context(),
            backlog=64,
            shutdown_timeout=5,
        )
        await self._site.start()
        log.info("WebAPI lauscht auf 0.0.0.0:%s (TLS, Client-Zertifikat=%s, CN-Pin=%s, Admin=%s)",
                 PORT, "Pflicht" if REQUIRE_CLIENT_CERT else "aus; HMAC erforderlich",
                 CLIENT_CN if REQUIRE_CLIENT_CERT else "nicht verwendet", ALLOW_ADMIN)
        self._watch = asyncio.create_task(self._kill_watch())

    async def _stop(self):
        try:
            if self._runner:
                await self._runner.cleanup()
        except Exception as e:
            log.warning("WebAPI-Stop: %r", e)
        finally:
            self._runner = self._site = None

    async def _kill_watch(self):
        """Kill-Switch: data/webapi.off anlegen -> Listener geht sofort zu."""
        try:
            while True:
                await asyncio.sleep(5)
                if os.path.exists(KILL_FILE):
                    self._killed = True
                    log.warning("WebAPI Kill-Switch erkannt -> Listener wird geschlossen")
                    await self._stop()
                    return
        except asyncio.CancelledError:
            pass

    # -- Request-Pipeline ----------------------------------------------------
    async def _notfound(self, request):
        return web.Response(status=404)

    async def _handle(self, request):
        rid = os.urandom(6).hex()
        try:
            actor, cmd, result, args, writes = await self._authorize_and_run(request, rid)
        except _Denied as d:
            log.warning("webapi[%s] abgewiesen: %s (ip=%s)", rid, d.reason, self._ip(request))
            # Abweisungen SIND das interessante Signal — mitschreiben, aber ohne den
            # genauen Grund (der Client soll nicht erfahren, welche Schicht griff;
            # im Audit steht der Status, im Log der Grund).
            self._audit(rid, 0, f"denied:{d.status}", "denied", self._ip(request),
                        cert=(request.get("_cert") or {}).get("fp"))
            return web.json_response(_DENIED, status=d.status,
                                     headers={"Cache-Control": "no-store"})
        except Exception as e:
            log.error("webapi[%s] Fehler: %r", rid, e)
            return web.json_response(_DENIED, status=500,
                                     headers={"Cache-Control": "no-store"})
        gid = args.get("guild_id")
        self._audit(rid, actor, cmd, "ok", self._ip(request),
                    guild_id=str(gid) if gid is not None else None,
                    writes=writes, detail=args if writes else None,
                    cert=(request.get("_cert") or {}).get("fp"))
        return web.json_response({"ok": True, "rid": rid, "data": result},
                                 headers={"Cache-Control": "no-store"})

    async def _authorize_and_run(self, request, rid):
        if self._killed or os.path.exists(KILL_FILE):
            raise _Denied("Kill-Switch aktiv", 503)

        # (3) geheimer Pfad — konstantzeitiger Vergleich, damit kein Timing-Leak
        if not hmac.compare_digest(request.match_info.get("secret", ""), SECRET_PATH):
            raise _Denied("falscher Pfad", 404)

        # (2) Client-Zertifikat/CN-Pin bleiben Standard. Der optionale HMAC-only
        # Modus überspringt ausschließlich diese Client-Identität. HMAC,
        # Zeitfenster, Einmal-Nonce, Actor-Freigabe und RPC-Prüfung bleiben Pflicht.
        if REQUIRE_CLIENT_CERT:
            cn, serial, fp = self._peer_ident(request)
            request["_cert"] = {"cn": cn, "serial": serial, "fp": fp}
            if cn is None or not hmac.compare_digest(cn, CLIENT_CN):
                log.warning("webapi: fremdes Client-Zertifikat abgewiesen "
                            "(cn=%r serial=%r fp=%s ip=%s)", cn, serial, fp, self._ip(request))
                raise _Denied(f"Client-CN {cn!r} nicht erlaubt", 403)
            # Ein zweiter Fingerprint bei gleichem CN heisst: es ruft eine ZWEITE
            # Gegenstelle an (kopierter Schluessel oder zweites Zertifikat).
            known = self._cache("_cert_seen")
            if fp and fp not in known:
                known[fp] = True
                if len(known) > 1:
                    log.warning("webapi: NEUES Client-Zertifikat gesehen (cn=%r serial=%r fp=%s) -- "
                                "insgesamt %d verschiedene. Bitte pruefen, ob das erwartet ist.",
                                cn, serial, fp, len(known))
                else:
                    log.info("webapi: Client-Zertifikat cn=%r serial=%r fp=%s", cn, serial, fp)
        else:
            request["_cert"] = {}

        # aiohttp bricht selbst ab, sobald client_max_size überschritten ist
        # (HTTPRequestEntityTooLarge) — als Abweisung behandeln, nicht als Serverfehler.
        try:
            body = await request.read()
        except web.HTTPException:
            raise _Denied("Body zu groß", 413)
        if len(body) > MAX_BODY:
            raise _Denied("Body zu groß", 413)

        # (4) Zeitfenster + Nonce
        ts_raw = request.headers.get("X-IS-Ts", "")
        nonce = request.headers.get("X-IS-Nonce", "")
        actor_raw = request.headers.get("X-IS-Actor", "")
        sig = request.headers.get("X-IS-Sig", "")
        if not (ts_raw.isdigit() and len(nonce) == 32 and actor_raw.isdigit() and len(sig) == 64):
            raise _Denied("Header unvollständig", 400)

        now = time.time()
        if abs(now - int(ts_raw)) > CLOCK_SKEW:
            raise _Denied("Zeitstempel außerhalb des Fensters", 403)
        self._prune_nonces(now)
        if nonce in self._nonces:
            raise _Denied("Nonce schon benutzt (Replay)", 403)

        # (4) Signatur — erst NACH den billigen Prüfungen, aber VOR jeder
        # Auswertung von actor. Wichtig: das muss vor der Actor-Prüfung laufen,
        # nicht danach — erst die Signatur macht actor überhaupt vertrauenswürdig
        # (sonst könnte ein Angreifer, der die Body-Prüfungen umgeht, einen
        # beliebigen actor-Header behaupten, ohne dass er kryptografisch
        # verifiziert wäre).
        canonical = b"\n".join([
            b"v1", ts_raw.encode(), nonce.encode(), actor_raw.encode(),
            hashlib.sha256(body).hexdigest().encode(),
        ])
        expect = hmac.new(HMAC_KEY, canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            raise _Denied("Signatur falsch", 403)
        self._nonces[nonce] = now
        actor = int(actor_raw)          # ab hier kryptografisch bestätigt

        # (7) Rate-Limit
        if not self._rate_ok(actor, now):
            raise _Denied("Rate-Limit", 429)

        # (6) Kommando aus der Registry, Schema-geprüft
        try:
            payload = json.loads(body or b"{}")
        except Exception:
            raise _Denied("kein JSON", 400)
        if not isinstance(payload, dict):
            raise _Denied("Payload kein Objekt", 400)
        cmd = payload.get("cmd")
        if not isinstance(cmd, str) or cmd not in RPC:
            raise _Denied(f"unbekanntes Kommando {cmd!r}", 404)
        spec, fn, admin, writes, scope = RPC[cmd]
        if admin and not ALLOW_ADMIN:
            raise _Denied(f"{cmd} ist gesperrt (WEBAPI_ALLOW_ADMIN=0)", 403)

        # (5) Actor/Scope. Bot-Owner (ACTORS) dürfen wie bisher immer alles.
        # "super"-Kommandos (status/guilds.list/audit.list/logs.tail/cogs.reload)
        # bleiben exklusiv den Bot-Ownern vorbehalten. "guild"-Kommandos sind für
        # jeden authentifizierten Discord-Nutzer erlaubt, der laut Bot (live aus
        # dem Gateway-Cache, nicht aus einem eingefrorenen OAuth-Scope) Owner
        # oder Administrator der jeweiligen Guild ist — dafür MUSS aber erst das
        # Schema geprüft sein (liefert die normalisierte guild_id als int).
        # "self"-Kommandos (z.B. guilds.mine) sind für jeden Actor erlaubt, der
        # Handler selbst filtert nach dem, was zu diesem Actor gehört.
        is_owner = actor in ACTORS
        if scope == "super" and not is_owner:
            raise _Denied(f"Actor {actor} nicht erlaubt (super)", 403)

        try:
            args = _check(payload.get("args") or {}, spec)
        except ValueError as e:
            raise _Denied(f"Argumente: {e}", 400)

        # "team"-Kommandos: Team-Mitglieder dieser Guild dürfen lesen, Verwaltung
        # (Owner/Admin/ausdrücklich freigeschaltet) darf auch schreiben. Die
        # Zugehörigkeit kommt aus dem BESTEHENDEN Team-System des Bots
        # (cogs/team_dashboard.py: members + sync_roles + verwaltung_access) —
        # kein zweites Rechte-Modell, keine zweite Mitgliederliste.
        if scope == "team" and not is_owner:
            g = self._resolve_team_guild(args)
            trole = await self._team_role(g, actor)
            if trole is None:
                raise _Denied(f"Actor {actor} nicht im IronShield-Team (Server {g.id})", 403)
            if writes and trole != "manage":
                raise _Denied(f"Actor {actor} darf im Team-Bereich nicht schreiben", 403)

        # "apps"-Kommandos: der Bewerbungs-Arbeitsplatz. Zugriff hat, wer laut
        # Discord auch die Annehmen/Ablehnen-Buttons druecken darf -- also
        # Owner/Administrator ODER "Rollen verwalten" (genau die Pruefung, die
        # AppAcceptButton/AppDenyButton machen). Bewusst NICHT der guild-Scope:
        # Personalverantwortliche sind selten Server-Administratoren.
        if scope == "apps" and not is_owner:
            gid = args.get("guild_id")
            if gid is None:                        # Registry-Bug, kein Nutzerfehler
                raise _Denied(f"{cmd}: apps-scope ohne guild_id", 500)
            g = self.bot.get_guild(gid)
            if g is None:
                raise _Denied("Guild unbekannt", 404)
            if not self._apps_authorized(g, actor):
                raise _Denied(f"Actor {actor} darf in Guild {gid} keine Bewerbungen bearbeiten", 403)

        # "support"-Kommandos: der Ticket-Arbeitsplatz. Zugriff hat, wer laut
        # Ticketsystem auch in Discord an den Tickets arbeitet -- Admin/Owner ODER
        # eine konfigurierte Support-Rolle (siehe _support_authorized). Die
        # Ticket-KONFIGURATION bleibt bewusst im guild-Scope (Admin-Sache).
        if scope == "support" and not is_owner:
            gid = args.get("guild_id")
            if gid is None:                        # Registry-Bug, kein Nutzerfehler
                raise _Denied(f"{cmd}: support-scope ohne guild_id", 500)
            g = self.bot.get_guild(gid)
            if g is None:
                raise _Denied("Guild unbekannt", 404)
            if not await self._support_authorized(g, actor):
                raise _Denied(f"Actor {actor} kein Support in Guild {gid}", 403)

        if scope == "guild" and not is_owner:
            gid = args.get("guild_id")
            if gid is None:                        # Registry-Bug, kein Nutzerfehler
                raise _Denied(f"{cmd}: guild-scope ohne guild_id", 500)
            g = self.bot.get_guild(gid)
            if g is None:
                raise _Denied("Guild unbekannt", 404)
            if not await self._guild_authorized(g, actor):
                raise _Denied(f"Actor {actor} kein Admin in Guild {gid}", 403)

        try:
            result = await fn(self, args, actor)
        except _Denied:
            # Erwartete Abweisung (kein Serverfehler): _handle protokolliert sie
            # ohnehin als WARNING mit Grund. Ein zusätzlicher log.exception würde
            # für jeden normalen 403/404/409 einen vollen Traceback ins Log
            # schreiben und die echten Fehler darin untergehen lassen.
            raise
        except Exception:
            # Ohne cmd/guild_id im Log war ein Fehler wie "'int' object has no
            # attribute 'get'" bisher nicht auf ein Kommando zurückzuführen
            # (_handle sieht bei einer Exception hier nur "irgendein Fehler",
            # weil das actor/cmd/result-Tupel nie zugewiesen wurde) — jetzt mit
            # vollem Traceback + Kommando/Guild geloggt, bevor es hochgereicht wird.
            log.exception("webapi[%s] Fehler in %s (guild=%s)", rid, cmd, args.get("guild_id"))
            raise
        return actor, cmd, result, args, writes

    @staticmethod
    def _guild_authorized_cached(guild: discord.Guild, actor: int) -> bool:
        """Wie _guild_authorized, aber OHNE fetch_member-Fallback — rein
        synchron aus dem lokalen Cache, keine Discord-API-Calls. Für
        guilds.mine gedacht, das über ALLE Guilds des Bots (aktuell 749+)
        iteriert: ein fetch_member-Fallback pro Guild würde dort sequenziell
        hunderte echte HTTP-Requests auslösen und den 10s-Client-Timeout
        reißen (genau das ist am 02.08. mit einem Nicht-Owner-Testaccount
        passiert). Nebenwirkung: eine Guild, in der der Actor als Admin/Owner
        noch nicht im Member-Cache steht (chunk_guilds_at_startup=False),
        taucht in guilds.mine erst auf, sobald der Cache ihn kennt (z.B. nach
        der nächsten Gateway-Aktivität) — bis dahin funktioniert der direkte
        Aufruf von /guild/<id> trotzdem sofort korrekt, weil dort
        _guild_authorized (MIT fetch_member-Fallback, nur für eine einzelne
        Guild) läuft."""
        if guild.owner_id == actor:
            return True
        member = guild.get_member(actor)
        return bool(member and member.guild_permissions.administrator)

    async def _guild_authorized(self, guild: discord.Guild, actor: int) -> bool:
        """Ist actor Owner oder Administrator dieser Guild? Live aus dem Bot-
        eigenen Discord-Gateway-Cache geprüft (aktueller als ein bei Login
        eingefrorenes OAuth-guilds-Scope-Bitfeld) — mit TTL-Cache + In-Flight-
        Deduplizierung, weil ein einzelner Dashboard-Seitenaufruf ~17 RPC-Calls
        für dieselbe (guild, actor)-Kombination parallel abfeuert. Deny-by-
        default bei jedem Fehler/Timeout — nie fail-open."""
        key = (guild.id, actor)
        now = time.monotonic()
        cached = self._authz_cache.get(key)
        if cached is not None and now - cached[1] < AUTHZ_TTL:
            return cached[0]

        lock = self._authz_locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._authz_cache.get(key)         # nach Warten erneut prüfen
            if cached is not None and now - cached[1] < AUTHZ_TTL:
                return cached[0]
            if guild.owner_id == actor:
                ok = True
            else:
                member = guild.get_member(actor)
                if member is None:
                    # chunk_guilds_at_startup=False -> Member-Cache ist nicht
                    # vollständig; bei Cache-Miss real nachladen statt zu verweigern.
                    try:
                        member = await guild.fetch_member(actor)
                    except (discord.NotFound, discord.HTTPException):
                        member = None
                ok = bool(member and member.guild_permissions.administrator)
            self._authz_cache[key] = (ok, now)
            return ok

    # -- Actor-Hierarchie (Audit 23.09.2026) ---------------------------------
    # Seit Multi-Tenant ist der Actor NICHT mehr automatisch Bot-Owner, sondern
    # oft ein normaler Server-Admin. Ohne diese Prüfungen konnte ein niedriger
    # Admin über das Web höhere Admins bannen oder sich Rollen über der eigenen
    # Position geben (Verify-/Team-/Bewerbungsrollen).
    async def _actor_member(self, g: discord.Guild, actor: int):
        """Member des Actors — oder None, wenn keine Hierarchie gilt
        (Bot-Owner/ACTORS, Server-Owner)."""
        if actor in ACTORS or actor == g.owner_id:
            return None
        m = g.get_member(actor)
        if m is None:
            try:
                m = await g.fetch_member(actor)
            except (discord.NotFound, discord.HTTPException):
                raise _Denied("Actor ist kein Mitglied dieses Servers", 403)
        return m

    async def _require_outranks(self, g: discord.Guild, actor: int, target: discord.Member):
        am = await self._actor_member(g, actor)
        if am is None:
            return
        if target.id == am.id:
            raise _Denied("Aktion gegen dich selbst nicht erlaubt", 403)
        if target.top_role >= am.top_role:
            raise _Denied("Hierarchie: Ziel steht über/gleich deiner höchsten Rolle", 403)

    async def _role_guard(self, g: discord.Guild, role: discord.Role, actor: int,
                          allow_dangerous: bool = False):
        am = await self._actor_member(g, actor)
        ok, code = rolesafety.check(role, g.me, actor=am, allow_dangerous=allow_dangerous)
        if not ok:
            raise _Denied(f"Rolle nicht erlaubt: {rolesafety.reason(code, g.id)}", 400)

    # -- Helfer --------------------------------------------------------------
    @staticmethod
    def _ip(request):
        # KEIN X-Forwarded-For: es gibt keinen Reverse-Proxy vor uns, der Header
        # wäre also frei fälschbar. Nur die echte Peer-Adresse.
        peer = request.transport.get_extra_info("peername") if request.transport else None
        return peer[0] if peer else "?"

    @staticmethod
    def _peer_cn(request):
        ssl_obj = request.transport.get_extra_info("ssl_object") if request.transport else None
        cert = ssl_obj.getpeercert() if ssl_obj else None
        if not cert:
            return None
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return None

    @staticmethod
    def _peer_ident(request):
        """Kennung des Client-Zertifikats: (CN, Seriennummer, SHA256-Fingerprint).

        Die QUELL-IP taugt zur Unterscheidung nicht: vor dem Container steht ein
        NAT-Gateway, hinter dem jeder externe Aufrufer dieselbe Adresse hat. Was
        Aufrufer wirklich unterscheidet, ist das Zertifikat -- deshalb wird es
        mitprotokolliert. Taucht im Protokoll je ein zweiter Fingerprint auf,
        ruft eine ZWEITE Gegenstelle an, auch wenn ihr CN stimmt.
        """
        ssl_obj = request.transport.get_extra_info("ssl_object") if request.transport else None
        if ssl_obj is None:
            return None, None, None
        cert = ssl_obj.getpeercert() or {}
        cn = None
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    cn = value
        serial = cert.get("serialNumber")
        fp = None
        try:
            raw = ssl_obj.getpeercert(binary_form=True)
            if raw:
                fp = hashlib.sha256(raw).hexdigest()[:16]
        except (ValueError, AttributeError):
            pass
        return cn, serial, fp

    def _prune_nonces(self, now):
        if len(self._nonces) > 10000:            # Notbremse gegen Speicherwachstum
            self._nonces.clear()
            return
        for n, t in list(self._nonces.items()):
            if now - t > NONCE_TTL:
                del self._nonces[n]

    def _rate_ok(self, actor, now):
        q = self._hits.setdefault(actor, deque())
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


    # Inhalte, die im Audit-Protokoll NICHT im Klartext stehen sollen
    # (Datensparsamkeit, Audit 04.09.2026 Befund 12 — am 23.09. als verloren
    # gefunden und neu eingespielt): Ticket-Antworten, interne Notizen,
    # Verwarn-/Ban-Gründe. Wer wann welches Kommando ausgeführt hat, bleibt
    # vollständig protokolliert — nur der Freitext wird durch die Länge ersetzt.
    AUDIT_REDACT_KEYS = frozenset({"text", "reason", "message", "note", "answer", "content"})

    @classmethod
    def _audit_detail(cls, detail):
        out = {}
        for k, v in detail.items():
            if k == "guild_id":
                continue
            if k in cls.AUDIT_REDACT_KEYS and isinstance(v, str):
                out[k] = f"<{len(v)} Zeichen entfernt>"
            else:
                out[k] = v
        return out
    def _audit(self, rid, actor, cmd, outcome, ip, guild_id=None, writes=False, detail=None,
               cert=None):
        """Append-only Audit-Log in der SQLite-Schicht (kv, automatisch getrimmt).

        guild_id/writes/detail sind neu (siehe activity.list): erst damit lässt
        sich aus dem globalen, bisher nur Bot-Ownern zugänglichen Audit-Log ein
        pro-Guild sichtbares "wer hat wann was geändert" ableiten, ohne eine
        zweite Tabelle zu brauchen -- activity.list filtert einfach nach
        guild_id + writes=True."""
        try:
            storage.kv_set(AUDIT_NS, f"{int(time.time())}-{rid}", {
                "ts": int(time.time()), "actor": str(actor),
                "cmd": cmd, "outcome": outcome, "ip": ip,
                "guild_id": guild_id, "writes": bool(writes),
                "detail": self._audit_detail(detail) if detail else None,
                # Fingerprint des Client-Zertifikats: die Quell-IP ist wegen des
                # NAT-Gateways fuer alle Aufrufer gleich, das Zertifikat nicht.
                # Damit laesst sich im Nachhinein zeigen, dass wirklich nur EINE
                # Gegenstelle angerufen hat.
                "cert": cert,
            })
            # Trimmen ist ein DELETE über den ganzen Namespace — nicht bei jedem
            # Request, sondern gelegentlich. Reicht, um die Tabelle zu begrenzen.
            self._audit_n = getattr(self, "_audit_n", 0) + 1
            if self._audit_n % 50 == 0:
                storage.kv_trim(AUDIT_NS, AUDIT_KEEP)
        except Exception as e:
            log.warning("Audit-Schreiben fehlgeschlagen: %r", e)

    def _guild_dict(self, g):
        return {
            "id": str(g.id),
            "name": g.name,
            "members": g.member_count or 0,
            "owner_id": str(g.owner_id) if g.owner_id else None,
            "icon": g.icon.url if g.icon else None,
            "joined_at": g.me.joined_at.isoformat() if g.me and g.me.joined_at else None,
        }

    # -- RPC-Kommandos -------------------------------------------------------
    @rpc("status")
    async def _rpc_status(self, args, actor):
        return {
            "bot": str(self.bot.user.id) if self.bot.user else None,
            "name": str(self.bot.user) if self.bot.user else None,
            "avatar": (self.bot.user.display_avatar.url if self.bot.user else None),
            "latency_ms": round(self.bot.latency * 1000, 1),
            "guilds": len(self.bot.guilds),
            "members": sum(g.member_count or 0 for g in self.bot.guilds),
            "cogs": len(self.bot.cogs),
            "extensions": len(self.bot.extensions),
            "uptime_s": int(time.time() - getattr(self.bot, "start_time", time.time())),
            "python": platform.python_version(),
            "discordpy": discord.__version__,
            "api_version": VERSION,
            "admin_enabled": ALLOW_ADMIN,
        }

    # --- Öffentliche Kommandos (scope="self") --------------------------------
    # Diese zwei liefern absichtlich NUR Informationen, die auch jeder
    # Discord-Nutzer sehen kann: Erreichbarkeit des Bots und die Liste seiner
    # Slash-Befehle. Sie sind für die öffentlichen Seiten des Web-Dashboards
    # (Status-Seite, Befehlsliste) gedacht, die keinen eingeloggten Nutzer
    # haben. Der Aufrufer ist trotzdem authentifiziert — der Transport verlangt
    # mTLS-Clientzertifikat, geheimen Pfad, Zeitfenster, Nonce und HMAC; ohne
    # das kommt niemand bis hierher. scope="self" heißt hier deshalb "unser
    # eigener Webserver, egal welcher Actor" und NICHT "jeder im Internet".
    # Bewusst NICHT enthalten: Server- und Mitgliederzahlen, Guild-Namen,
    # Konfigurationen, irgendetwas Nutzerbezogenes.
    @rpc("status.public", scope="self")
    async def _rpc_status_public(self, args, actor):
        return {
            "online": bool(self.bot.is_ready() and not self.bot.is_closed()),
            "latency_ms": round(self.bot.latency * 1000, 1),
            "uptime_s": int(time.time() - getattr(self.bot, "start_time", time.time())),
            "modules": len(self.bot.extensions),
            # Nur aufrufbare Befehle zählen: walk_commands() liefert auch die
            # Gruppen selbst ("/ticket"), die niemand ausführen kann.
            "commands": sum(
                1 for c in self.bot.tree.walk_commands()
                if isinstance(c, discord.app_commands.Command)
            ),
            "discordpy": discord.__version__,
            "python": platform.python_version(),
        }

    @rpc("commands.public", scope="self")
    async def _rpc_commands_public(self, args, actor):
        """Slash-Befehle so, wie Discord sie den Nutzern anzeigt.

        `walk_commands` läuft auch durch Gruppen; ausgegeben wird der volle
        Aufrufname ("ticket panel"), damit die Webseite nichts
        zusammensetzen muss. `default_permissions` sagt, ob ein Befehl
        standardmäßig Rechte braucht — daraus macht die Webseite den Hinweis
        "nur für Team/Admins".
        """
        out = []
        for c in self.bot.tree.walk_commands():
            if not isinstance(c, discord.app_commands.Command):
                continue          # Gruppen selbst sind nicht aufrufbar
            # Bei Unterbefehlen ("/ticket panel") hängen die Rechte und das
            # guild_only-Flag an der GRUPPE, nicht am Unterbefehl — sonst meldet
            # die Webseite "für alle nutzbar", obwohl Discord den Befehl nur
            # Team-Rollen zeigt.
            perms = getattr(c, "default_permissions", None)
            guild_only = bool(getattr(c, "guild_only", False))
            if c.parent is not None:
                if perms is None:
                    perms = getattr(c.parent, "default_permissions", None)
                guild_only = guild_only or bool(getattr(c.parent, "guild_only", False))
            opts = []
            for p in getattr(c, "parameters", []) or []:
                opts.append({
                    "name": p.name,
                    "desc": (p.description or "")[:120],
                    "required": bool(p.required),
                })
            out.append({
                "name": c.qualified_name,
                "desc": (c.description or "")[:200],
                "group": c.parent.name if c.parent is not None else None,
                "guild_only": guild_only,
                "needs_perms": sorted(n for n, v in perms if v) if perms else [],
                "options": opts,
            })
        out.sort(key=lambda x: x["name"])
        return {"commands": out, "count": len(out)}

    _GUILD_SORTS = {
        "members_desc": lambda g: -(g.member_count or 0),
        "members_asc": lambda g: (g.member_count or 0),
        "name_asc": lambda g: g.name.lower(),
        "name_desc": None,  # unten per reverse gelöst (Text-Keys invertiert man nicht per Minus)
    }

    def _filter_sort_guilds(self, gs, args):
        """Gemeinsame q/min_members/max_members-Filterung + Sortierung für
        guilds.list und guilds.mine — ein Ort statt zwei divergierender Kopien."""
        q = (args.get("q") or "").lower()
        if q:
            gs = [g for g in gs if q in g.name.lower() or q == str(g.id)]
        min_m = args.get("min_members")
        if min_m is not None:
            gs = [g for g in gs if (g.member_count or 0) >= min_m]
        max_m = args.get("max_members")
        if max_m is not None:
            gs = [g for g in gs if (g.member_count or 0) <= max_m]
        sort = args.get("sort") or "members_desc"
        if sort == "name_desc":
            gs = sorted(gs, key=lambda g: g.name.lower(), reverse=True)
        else:
            key = self._GUILD_SORTS.get(sort, self._GUILD_SORTS["members_desc"])
            gs = sorted(gs, key=key)
        return gs

    # --- Live-Feed + Scan-Tester der Startseite (04.09.2026), scope="self" -----
    # Beide liefern nichts Server- oder Nutzerbezogenes: der Feed nur Art+Zeit
    # anonymer Ereignisse (events_feed.py), der Scan nur die Bewertung eines vom
    # Besucher eingegebenen Textes.
    @rpc("events.public", {"limit": ("int", False)}, scope="self")
    async def _rpc_events_public(self, args, actor):
        import events_feed
        return events_feed.snapshot(int(args.get("limit") or 30))

    SCAN_AI_BUDGET = 40      # KI-verfeinerte Bewertungen pro Fenster (Kostenbremse)
    SCAN_AI_WINDOW = 600     # Sekunden

    @rpc("scan.public", {"text": ("text", True)}, scope="self")
    async def _rpc_scan_public(self, args, actor):
        """Echter ScamRadar (Engine v2, cogs.scamradar.assess) für den Tester auf der Startseite.

        writes=False ist hier Absicht und wichtig: nur schreibende Kommandos legen
        ihre Argumente als `detail` ins Audit-Protokoll — der eingegebene Text
        soll nirgends gespeichert werden. Die KI-Verfeinerung ist global auf
        SCAN_AI_BUDGET pro Fenster begrenzt; darüber hinaus antwortet die reine
        Engine (Web-Route bremst zusätzlich pro IP).
        """
        import cogs.scamradar as sr
        text = str(args["text"]).strip()[:400]
        if not text:
            raise _Denied("Leerer Text", 400)
        bucket = self._cache("_scan_ai_hits").setdefault("all", deque())
        now = time.time()
        while bucket and now - bucket[0] > self.SCAN_AI_WINDOW:
            bucket.popleft()
        use_ai = len(bucket) < self.SCAN_AI_BUDGET
        if use_ai:
            bucket.append(now)
        try:
            r = await sr.assess(text, use_ai=use_ai)
        except Exception as e:
            log.warning("webapi scan.public: %s", e)
            raise _Denied("Scan fehlgeschlagen", 503)
        verdict = r.get("verdict") or "clean"
        level = "dangerous" if verdict in ("confirmed", "high") else "suspicious" if verdict == "suspicious" else "safe"
        reasons = [str(x) for x in (r.get("reasons") or [])]
        if r.get("ai_note"):
            reasons.append("KI-Einschätzung: " + str(r["ai_note"]))
        ev = [{"kind": e.get("kind"), "text": e.get("text"), "source": e.get("source")}
              for e in (r.get("evidence") or []) if e.get("kind") != "info"][:8]
        domains = r.get("domains") or []
        # Zeichen-Roentgen: Homoglyphen sind unsichtbar, deshalb muss die Website
        # die Domain Zeichen fuer Zeichen zeigen koennen statt nur zu behaupten,
        # da sei was faul. Nur Anzeigedaten, hoechstens 2 Domains, 64 Zeichen.
        spoof = [{
            "shown": str(f.get("shown", ""))[:64],
            "punycode": str(f.get("punycode", ""))[:96],
            "looks_like": str(f.get("looks_like", ""))[:64],
            "brand": f.get("brand") or None,
            "swapped": int(f.get("swapped") or 0),
            "chars": [{"c": c.get("c", ""), "cp": c.get("cp", ""), "name": c.get("name", ""),
                       "script": c.get("script", ""), "fake": bool(c.get("fake")),
                       "as": c.get("as", "")} for c in (f.get("chars") or [])[:64]],
        } for f in (r.get("spoof") or [])[:2]]
        cats = {k: {"score": v.get("score", 0), "verdict": v.get("verdict", "clean"), "label": v.get("label", k)}
                for k, v in (r.get("categories") or {}).items()}
        return {
            "score": int(r.get("score", 0)), "level": level, "verdict": verdict,
            "category": r.get("category", "scam"), "category_label": r.get("category_label", ""),
            "categories": cats,
            "confidence": r.get("confidence", "low"), "reasons": reasons[:6],
            "evidence": ev, "sources": r.get("sources") or [],
            "domain": domains[0] if domains else None, "domains": domains[:5],
            "spoof": spoof,
            "hint": r.get("hint") or "", "engine": 3,
        }

    @rpc("scan.status", scope="self")
    async def _rpc_scan_status(self, args, actor):
        """Zustand der Bedrohungs-Datenbanken (Einträge, letzter Abruf, Fehler) — für
        die Status-Seite und zur Kontrolle nach Deploys."""
        import scanengine
        st = scanengine.INTEL.status()
        st["engine"] = scanengine.VERSION
        return st

    _GUILD_LIST_SPEC = {
        "q": ("str", False), "limit": ("int", False), "offset": ("int", False),
        "sort": ("str", False), "min_members": ("int", False), "max_members": ("int", False),
    }

    @rpc("guilds.list", _GUILD_LIST_SPEC)
    async def _rpc_guilds(self, args, actor):
        limit = min(max(args.get("limit", 50), 1), 200)
        offset = max(args.get("offset", 0), 0)
        gs = self._filter_sort_guilds(list(self.bot.guilds), args)
        return {
            "total": len(gs),
            "items": [self._guild_dict(g) for g in gs[offset:offset + limit]],
        }

    @rpc("guilds.mine", _GUILD_LIST_SPEC, scope="self")
    async def _rpc_guilds_mine(self, args, actor):
        """Wie guilds.list, aber für normale (Nicht-Bot-Owner-)Actors gefiltert
        auf die Guilds, in denen sie laut Bot Owner oder Administrator sind.
        Bot-Owner sehen unverändert alle Guilds (bisheriges Verhalten von
        guilds.list). Ersetzt guilds.list als Frontend-Kommando: der Server
        entscheidet, was der jeweilige Actor zu sehen bekommt, statt zwei
        getrennte Frontend-Code-Pfade zu brauchen."""
        if actor in ACTORS:
            res = await self._rpc_guilds(args, actor)
            for it in res["items"]:
                it["access"] = "admin"
            return res
        # Cache-only-Check (kein fetch_member) -- siehe _guild_authorized_cached-
        # Docstring: ein Fallback über 749+ Guilds hinweg würde den Request-
        # Timeout reißen.
        # "access" unterscheidet die zwei Wege: "admin" -> ganzes Server-
        # Dashboard, "support" -> nur der Ticket-Arbeitsplatz. Ohne diese
        # Markierung würde das Frontend Support-Personal auf eine Seite
        # schicken, die für sie zu 403 führt.
        access = {}
        for g in self.bot.guilds:
            if self._guild_authorized_cached(g, actor):
                access[g.id] = "admin"
            elif self._support_authorized_cached(g, actor):
                access[g.id] = "support"
        mine = self._filter_sort_guilds([g for g in self.bot.guilds if g.id in access], args)
        limit = min(max(args.get("limit", 50), 1), 200)
        offset = max(args.get("offset", 0), 0)
        return {
            "total": len(mine),
            "items": [{**self._guild_dict(g), "access": access[g.id]}
                      for g in mine[offset:offset + limit]],
        }

    @rpc("guild.get", {"guild_id": ("id", True)})
    async def _rpc_guild(self, args, actor):
        g = self.bot.get_guild(args["guild_id"])
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        d = self._guild_dict(g)
        d["channels"] = [{"id": str(c.id), "name": c.name, "type": c.type.name}
                         for c in g.text_channels[:200]]
        d["roles"] = [{"id": str(r.id), "name": r.name, "managed": r.managed}
                      for r in g.roles[:200] if not r.is_default()]
        return d

    @rpc("modules.list", {"guild_id": ("id", True)})
    async def _rpc_modules(self, args, actor):
        gid = args["guild_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        state = modules.enabled_map(gid)
        cats = []
        for cat, mods in modules.by_category().items():
            cats.append({
                "key": cat,
                "label": modules.CATEGORIES[cat]["de"],
                "modules": [{
                    "key": m["key"], "emoji": m["emoji"],
                    "label": m["label"]["de"], "desc": m["desc"]["de"],
                    "enabled": state.get(m["key"], m["default"]),
                    "default": m["default"],
                } for m in mods],
            })
        return {"guild_id": str(gid), "categories": cats}

    @rpc("modules.set", {"guild_id": ("id", True), "key": ("str", True), "enabled": ("bool", True)},
         writes=True)
    async def _rpc_modules_set(self, args, actor):
        gid, key, enabled = args["guild_id"], args["key"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        m = modules.get(key)
        if m is None:
            raise _Denied(f"Modul {key!r} unbekannt", 404)
        if m["core"]:
            raise _Denied(f"Modul {key!r} ist core und nicht abschaltbar", 403)
        if not modules.set_module_enabled(gid, key, enabled):
            raise _Denied("Speichern fehlgeschlagen", 500)
        log.info("webapi: Modul %s auf Guild %s -> %s", key, gid, enabled)
        return {"guild_id": str(gid), "key": key, "enabled": enabled}

    @rpc("automod.status", {"guild_id": ("id", True)})
    async def _rpc_automod_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.automod as am  # lazy: greift den aktuellen Modulstand, Hot-Reload-fest
        gid_s = str(gid)
        systems = [{"key": k, "label": label, "enabled": am.data[k].get(gid_s, False)}
                  for k, label in am.SYSTEMS]
        exempt = []
        for cid in am.data["channel_exempt"].get(gid_s, []):
            ch = g.get_channel_or_thread(cid)
            exempt.append({"id": str(cid), "name": ch.name if ch else None})
        return {
            "guild_id": gid_s,
            "systems": systems,
            "badwords": len(am.data["badwords"].get(gid_s, [])),
            "whitelist": len(am.data["whitelist"].get(gid_s, [])),
            "channel_exempt": exempt,
        }

    @rpc("automod.toggle",
         {"guild_id": ("id", True), "key": ("str", True), "enabled": ("bool", True)},
         writes=True)
    async def _rpc_automod_toggle(self, args, actor):
        gid, key, enabled = args["guild_id"], args["key"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.automod as am
        if key not in {k for k, _ in am.SYSTEMS}:
            raise _Denied(f"Unbekanntes System {key!r}", 404)
        am.data[key][str(gid)] = enabled
        am.save_data(am.data)
        log.info("webapi: AutoMod-System %s auf Guild %s -> %s", key, gid, enabled)
        return {"guild_id": str(gid), "key": key, "enabled": enabled}

    @rpc("automod.channel_exempt.add",
         {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_exempt_add(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel_or_thread(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        import cogs.automod as am
        gid_s = str(gid)
        ids = am.data["channel_exempt"].setdefault(gid_s, [])
        if cid not in ids:
            ids.append(cid)
            am.save_data(am.data)
        log.info("webapi: Kanal-Ausnahme +%s auf Guild %s", cid, gid)
        return {"guild_id": gid_s, "channel_id": str(cid), "name": ch.name}

    @rpc("automod.channel_exempt.remove",
         {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_exempt_remove(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.automod as am
        gid_s = str(gid)
        ids = am.data["channel_exempt"].get(gid_s, [])
        if cid in ids:
            ids.remove(cid)
            am.save_data(am.data)
        log.info("webapi: Kanal-Ausnahme -%s auf Guild %s", cid, gid)
        return {"guild_id": gid_s, "channel_id": str(cid), "removed": True}

    @rpc("audit.list", {"limit": ("int", False)})
    async def _rpc_audit(self, args, actor):
        limit = min(max(args.get("limit", 100), 1), 500)
        try:
            rows = storage.kv_get_all(AUDIT_NS) or {}
        except Exception:
            rows = {}
        items = sorted(rows.values(), key=lambda r: r.get("ts", 0), reverse=True)
        return {"items": items[:limit]}

    @rpc("activity.list", {"guild_id": ("id", True), "limit": ("int", False)})
    async def _rpc_activity(self, args, actor):
        """Pro-Guild-Verlauf für Server-Admins (nicht nur Bot-Owner, wie
        audit.list): nur erfolgreiche SCHREIB-Kommandos dieser Guild, neueste
        zuerst. Actor wird -- wenn im Member-Cache vorhanden -- als Anzeigename
        aufgelöst, sonst bleibt die rohe ID stehen."""
        gid = args["guild_id"]
        gid_s = str(gid)
        limit = min(max(args.get("limit", 50), 1), 200)
        g = self.bot.get_guild(gid)
        try:
            rows = storage.kv_get_all(AUDIT_NS) or {}
        except Exception:
            rows = {}
        items = [r for r in rows.values()
                 if r.get("guild_id") == gid_s and r.get("writes") and r.get("outcome") == "ok"]
        items.sort(key=lambda r: r.get("ts", 0), reverse=True)
        out = []
        for r in items[:limit]:
            actor_id = r.get("actor")
            member = g.get_member(int(actor_id)) if g and actor_id and actor_id.isdigit() else None
            out.append({
                "ts": r.get("ts"), "cmd": r.get("cmd"),
                "actor_id": actor_id,
                "actor_name": member.display_name if member else None,
                "detail": r.get("detail") or {},
            })
        return {"guild_id": gid_s, "items": out}

    @rpc("logs.tail", {"lines": ("int", False)}, admin=True)
    async def _rpc_logs(self, args, actor):
        lines = min(max(args.get("lines", 200), 1), 2000)
        # Pfad steht FEST im Code — nie aus Parametern, sonst Path-Traversal.
        candidates = sorted(glob.glob(os.path.join("state", "logs", "*.log")))
        if not candidates:
            return {"file": None, "lines": []}
        path = candidates[-1]
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            tail = deque(f, maxlen=lines)
        return {"file": path, "lines": [l.rstrip("\n") for l in tail]}

    @rpc("cogs.reload", {"ext": ("str", True)}, admin=True, writes=True)
    async def _rpc_reload(self, args, actor):
        ext = args["ext"]
        # Nur bereits geladene Extensions — kein Laden beliebiger Modulnamen.
        if ext not in self.bot.extensions:
            raise _Denied(f"Extension {ext!r} nicht geladen", 404)
        await self.bot.reload_extension(ext)
        log.info("webapi: %s neu geladen", ext)
        return {"ext": ext, "reloaded": True}

    # -- Moderation -----------------------------------------------------------
    # Web-Aktionen kommen von BOT-OWNERN (Discord-OAuth + zwei unabhängige
    # Allowlists), nicht von normalen Server-Moderatoren. Deshalb wird hier NICHT
    # geprüft, ob der Actor selbst eine Guild-Rolle über dem Ziel hat (wie im
    # Discord-Menü) — nur, ob der BOT die Aktion technisch darf (_hierarchy_ok).

    async def _safe_fetch_user(self, actor_id):
        """Owner-Name fürs Audit/den Grundtext — bei Fehler fällt es auf die ID zurück."""
        try:
            u = self.bot.get_user(actor_id) or await self.bot.fetch_user(actor_id)
            return str(u)
        except Exception:
            return str(actor_id)

    @rpc("member.lookup", {"guild_id": ("id", True), "user_id": ("id", True)})
    async def _rpc_member_lookup(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        member = g.get_member(uid)
        if member is None:
            try:
                member = await g.fetch_member(uid)
            except discord.HTTPException:
                member = None
        if member is not None:
            return {
                "id": str(uid), "name": str(member), "display_name": member.display_name,
                "avatar": member.display_avatar.url if member.display_avatar else None,
                "in_guild": True,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
                "top_role": member.top_role.name,
                "is_owner": member.id == g.owner_id,
                "timed_out": member.is_timed_out(),
            }
        try:
            user = await self.bot.fetch_user(uid)
        except discord.NotFound:
            raise _Denied("User existiert nicht", 404)
        except discord.HTTPException as e:
            raise _Denied(f"HTTP-Fehler: {e}", 502)
        return {"id": str(uid), "name": str(user), "display_name": user.name,
                "avatar": user.display_avatar.url if user.display_avatar else None,
                "in_guild": False, "joined_at": None, "top_role": None,
                "is_owner": False, "timed_out": False}

    @rpc("warns.list", {"guild_id": ("id", True), "user_id": ("id", True)})
    async def _rpc_warns_list(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.warnsystem as ws
        return {"user_id": str(uid), "warns": ws.get_warns(self.bot.get_guild(gid), uid)}

    @rpc("warns.add", {"guild_id": ("id", True), "user_id": ("id", True), "reason": ("str", True)},
         writes=True)
    async def _rpc_warns_add(self, args, actor):
        gid, uid, reason = args["guild_id"], args["user_id"], args["reason"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        member = g.get_member(uid)
        if member is None:
            raise _Denied("Nutzer ist kein Mitglied dieses Servers", 404)
        await self._require_outranks(g, actor, member)
        import cogs.warnsystem as ws
        moderator = _ActorProxy(await self._safe_fetch_user(actor))
        amount = await ws.do_warn(g, moderator, member, reason)
        log.info("webapi: Warn für %s auf Guild %s (%s. Verwarnung, durch %s)", uid, gid, amount, actor)
        return {"user_id": str(uid), "amount": amount}

    @rpc("warns.clear", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_warns_clear(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.warnsystem as ws
        cleared = ws.do_unwarn(g, uid)
        log.info("webapi: Warns von %s auf Guild %s gelöscht durch %s", uid, gid, actor)
        return {"user_id": str(uid), "cleared": cleared}

    @rpc("moderation.kick", {"guild_id": ("id", True), "user_id": ("id", True), "reason": ("str", False)},
         writes=True)
    async def _rpc_kick(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        reason = (args.get("reason") or "Dashboard-Aktion").strip()
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        me = g.me
        if me is None or not me.guild_permissions.kick_members:
            raise _Denied("Bot hat keine Kick-Berechtigung", 403)
        member = g.get_member(uid)
        if member is None:
            raise _Denied("Nutzer ist kein Mitglied dieses Servers", 404)
        ok, why = _hierarchy_ok(member, me)
        if not ok:
            raise _Denied(f"Hierarchie: {why}", 403)
        await self._require_outranks(g, actor, member)
        mod_name = await self._safe_fetch_user(actor)
        try:
            await member.kick(reason=f"{reason} — Dashboard/{mod_name}"[:512])
        except discord.Forbidden:
            raise _Denied("Discord verweigert (Forbidden)", 403)
        except discord.HTTPException as e:
            raise _Denied(f"HTTP-Fehler: {e}", 502)
        log.info("webapi: Kick %s auf Guild %s durch %s", uid, gid, actor)
        return {"user_id": str(uid), "kicked": True}

    @rpc("moderation.ban",
         {"guild_id": ("id", True), "user_id": ("id", True), "reason": ("str", False),
          "delete_days": ("int", False)}, writes=True)
    async def _rpc_ban(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        reason = (args.get("reason") or "Dashboard-Aktion").strip()
        delete_days = args.get("delete_days", 0) or 0
        if not (0 <= delete_days <= 7):
            raise _Denied("delete_days muss 0-7 sein", 400)
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        me = g.me
        if me is None or not me.guild_permissions.ban_members:
            raise _Denied("Bot hat keine Ban-Berechtigung", 403)
        # Owner-Schutz IMMER prüfen, auch wenn das Mitglied nicht (mehr) im
        # lokalen Cache steht (Ban erlaubt Ziel-IDs ohne Member-Objekt) — sonst
        # greift der Schutz nur zufällig, je nachdem ob der Owner gerade gecacht ist.
        if uid == g.owner_id:
            raise _Denied("Ziel ist der Server-Owner", 403)
        member = g.get_member(uid)
        if member is not None:
            ok, why = _hierarchy_ok(member, me)
            if not ok:
                raise _Denied(f"Hierarchie: {why}", 403)
            await self._require_outranks(g, actor, member)
        mod_name = await self._safe_fetch_user(actor)
        try:
            await g.ban(discord.Object(id=uid), reason=f"{reason} — Dashboard/{mod_name}"[:512],
                       delete_message_seconds=delete_days * 86400)
        except discord.Forbidden:
            raise _Denied("Discord verweigert (Forbidden)", 403)
        except discord.HTTPException as e:
            raise _Denied(f"HTTP-Fehler: {e}", 502)
        log.info("webapi: Ban %s auf Guild %s durch %s", uid, gid, actor)
        return {"user_id": str(uid), "banned": True}

    @rpc("moderation.timeout",
         {"guild_id": ("id", True), "user_id": ("id", True), "duration": ("str", True),
          "reason": ("str", False)}, writes=True)
    async def _rpc_timeout(self, args, actor):
        gid, uid, duration = args["guild_id"], args["user_id"], args["duration"]
        reason = (args.get("reason") or "Dashboard-Aktion").strip()
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        me = g.me
        if me is None or not me.guild_permissions.moderate_members:
            raise _Denied("Bot hat keine Timeout-Berechtigung", 403)
        member = g.get_member(uid)
        if member is None:
            raise _Denied("Nutzer ist kein Mitglied dieses Servers", 404)
        ok, why = _hierarchy_ok(member, me)
        if not ok:
            raise _Denied(f"Hierarchie: {why}", 403)
        await self._require_outranks(g, actor, member)
        import cogs.moderation as modn
        delta = modn.parse_duration(duration)
        if not delta:
            raise _Denied("Ungültige Dauer (z.B. 10m, 2h, 1d, max 28 Tage)", 400)
        mod_name = await self._safe_fetch_user(actor)
        try:
            await member.timeout(delta, reason=f"{reason} — Dashboard/{mod_name}"[:512])
        except discord.Forbidden:
            raise _Denied("Discord verweigert (Forbidden)", 403)
        except discord.HTTPException as e:
            raise _Denied(f"HTTP-Fehler: {e}", 502)
        log.info("webapi: Timeout %s (%s) auf Guild %s durch %s", uid, duration, gid, actor)
        return {"user_id": str(uid), "timed_out_until": (discord.utils.utcnow() + delta).isoformat()}

    @rpc("moderation.untimeout", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_untimeout(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        me = g.me
        if me is None or not me.guild_permissions.moderate_members:
            raise _Denied("Bot hat keine Timeout-Berechtigung", 403)
        member = g.get_member(uid)
        if member is None:
            raise _Denied("Nutzer ist kein Mitglied dieses Servers", 404)
        mod_name = await self._safe_fetch_user(actor)
        try:
            await member.timeout(None, reason=f"Dashboard/{mod_name}"[:512])
        except discord.Forbidden:
            raise _Denied("Discord verweigert (Forbidden)", 403)
        except discord.HTTPException as e:
            raise _Denied(f"HTTP-Fehler: {e}", 502)
        log.info("webapi: Untimeout %s auf Guild %s durch %s", uid, gid, actor)
        return {"user_id": str(uid), "timed_out": False}

    # -- Tickets & Bewerbungen (Übersicht + Bewerbungs-Panel öffnen/schließen) ----

    @rpc("tickets.overview", {"guild_id": ("id", True)})
    async def _rpc_tickets_overview(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)
        panels = []
        for pid, p in d.get("panels", {}).items():
            ch = g.get_channel(p.get("channel")) if p.get("channel") else None
            panels.append({
                "id": pid, "name": p.get("name", "Support"),
                "channel": ch.name if ch else None,
                "open_count": len(p.get("open_tickets", {})),
                "reasons": p.get("reasons", []),
            })
        return {
            "guild_id": str(gid),
            "counter": d.get("counter", 0),
            "total_open": sum(len(p.get("open_tickets", {})) for p in d.get("panels", {}).values()),
            "support_roles": len(d.get("support_roles", [])),
            "panels": panels,
        }

    @rpc("applications.overview", {"guild_id": ("id", True)})
    async def _rpc_applications_overview(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.applications as apps
        conf = apps._guild_conf(str(gid))
        panels = []
        for pid, p in conf.get("panels", {}).items():
            role = g.get_role(p.get("role")) if p.get("role") else None
            log_ch = g.get_channel(p.get("log")) if p.get("log") else None
            panels.append({
                "id": pid, "name": p.get("name", pid),
                "open": bool(p.get("open", True)),
                "questions": len(p.get("questions") or []),
                "role": role.name if role else None,
                "log_channel": log_ch.name if log_ch else None,
            })
        return {"guild_id": str(gid), "panels": panels}

    @rpc("applications.toggle",
         {"guild_id": ("id", True), "pid": ("str", True), "open": ("bool", True)}, writes=True)
    async def _rpc_applications_toggle(self, args, actor):
        gid, pid, open_ = args["guild_id"], args["pid"], args["open"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.applications as apps
        gid_s = str(gid)
        if not apps._panel_exists(gid_s, pid):
            raise _Denied(f"Panel {pid!r} unbekannt", 404)
        panel = apps._panel_conf_w(gid_s, pid)
        panel["open"] = open_
        apps.save_data(apps.application_data)
        log.info("webapi: Bewerbungs-Panel %s auf Guild %s -> open=%s (durch %s)", pid, gid, open_, actor)
        return {"guild_id": gid_s, "pid": pid, "open": open_}

    # -- Langzeit-Statistik ----------------------------------------------------
    # Datenquelle ist cogs/stats.py (Tageszeilen). Hier wird nur gelesen und
    # aufbereitet -- kein zweites Zaehlwerk.

    @rpc("stats.guild", {"guild_id": ("id", True), "days": ("int", False)})
    async def _rpc_stats_guild(self, args, actor):
        """Verlauf EINES Servers: Mitglieder, Nachrichten, Zu-/Abgaenge.

        Die Reihe beginnt an dem Tag, an dem cogs/stats.py in Betrieb ging --
        vorher wurde nichts mitgeschrieben. Damit im Web kein leeres Diagramm
        ohne Erklaerung steht, wird `since` mitgeliefert.
        """
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        try:
            import cogs.stats as st
        except Exception:
            raise _Denied("Statistik-Modul nicht geladen", 503)
        days = min(max(args.get("days", 30), 7), 180)
        series = st.guild_series(gid, days)
        known = [d for d in series if d["known"]]
        totals = {
            "messages": sum(d["messages"] for d in series),
            "joins": sum(d["joins"] for d in series),
            "leaves": sum(d["leaves"] for d in series),
            "voice_join": sum(d["voice_join"] for d in series),
        }
        first, last = (known[0]["members"] if known else 0), (known[-1]["members"] if known else 0)
        return {
            "guild_id": str(gid),
            "days": days,
            "since": known[0]["day"] if known else None,
            "series": series,
            "totals": totals,
            "members_now": g.member_count or 0,
            "members_change": (last - first) if known else 0,
        }

    @rpc("stats.web", {"days": ("int", False)}, scope="super")
    async def _rpc_stats_web(self, args, actor):
        """Nutzung des Web-Dashboards ueber die Zeit.

        Bot-Owner-Sache (scope="super"): hier stehen Personen-IDs aller
        Dashboard-Nutzer ueber alle Server hinweg.
        """
        try:
            import cogs.stats as st
        except Exception:
            raise _Denied("Statistik-Modul nicht geladen", 503)
        days = min(max(args.get("days", 30), 7), 180)
        series = st.web_series(days)
        tot = st.web_totals(days)

        def person(uid):
            u = self.bot.get_user(int(uid)) if str(uid).isdigit() else None
            return {"id": str(uid), "name": (str(u) if u else None),
                    "avatar": (u.display_avatar.url if u else None)}

        top_people = sorted(tot["actors"].items(), key=lambda kv: -kv[1])[:25]
        top_cmds = sorted(tot["cmds"].items(), key=lambda kv: -kv[1])[:20]
        top_guilds = sorted(tot["guilds"].items(), key=lambda kv: -kv[1])[:20]
        known = [d for d in series if d["known"]]
        return {
            "days": days,
            "since": known[0]["day"] if known else None,
            "series": series,
            "totals": {
                "requests": tot["requests"], "writes": tot["writes"],
                "denied": tot["denied"], "people": len(tot["actors"]),
                "guilds": len(tot["guilds"]),
            },
            "top_people": [{**person(uid), "count": n} for uid, n in top_people],
            "top_commands": [{"cmd": c, "count": n} for c, n in top_cmds],
            "top_guilds": [{"id": str(gid),
                            "name": (self.bot.get_guild(int(gid)).name
                                     if str(gid).isdigit() and self.bot.get_guild(int(gid)) else None),
                            "count": n} for gid, n in top_guilds],
        }

    # -- Bewerbungs-Arbeitsplatz -----------------------------------------------
    # Wie bei den Tickets gilt: EIN Bewerbungssystem, zwei Oberflaechen. Die
    # Kommandos hier haben keine eigene Entscheidungslogik, sie rufen
    # cogs.applications.decide_application() -- dieselbe Funktion, die auch der
    # Annehmen/Ablehnen-Button in Discord benutzt.

    def _apps_authorized(self, guild, actor) -> bool:
        """Darf actor auf diesem Server Bewerbungen bearbeiten?

        Dieselbe Regel wie die Buttons im Bewerbungs-Log: Owner/Administrator
        oder "Rollen verwalten" (die Annahme vergibt eine Rolle). Cache-only --
        wer nicht im Member-Cache steht, kommt hier ohnehin nicht her.
        """
        if guild.owner_id == actor:
            return True
        m = guild.get_member(actor)
        if m is None:
            return False
        p = m.guild_permissions
        return bool(p.administrator or p.manage_roles)

    @staticmethod
    def _app_custom_ids(message):
        """Alle Button-custom_ids einer Nachricht (V2: Container -> Row -> Button).

        Die Bewerbungs-Log-Nachricht traegt ihre Kennung ausschliesslich dort
        (`app_acc:<uid>:<pid>`), nicht im Text -- ueber diese Liste erkennt der
        Arbeitsplatz, was eine Bewerbung ist und ob sie noch offen ist.
        """
        out = []

        def walk(items):
            for it in items or []:
                cid = getattr(it, "custom_id", None)
                if isinstance(cid, str):
                    out.append(cid)
                kids = getattr(it, "children", None) or getattr(it, "components", None)
                if kids:
                    walk(kids)

        walk(getattr(message, "components", None))
        return out

    @staticmethod
    def _app_parse_body(body, decided=False):
        """Zerlegt den Log-Text in Kopfzeilen und Frage/Antwort-Paare.

        Format siehe cogs/applications.py (_build_application_log_text): eine
        Frage steht als `> **Frage**`, darunter die Antwort, aufeinander
        folgende Paare sind durch eine `---`-Zeile getrennt. Deshalb wird hier
        an den Trennstrichen zerlegt und je Block EIN Paar gelesen -- ein
        durchlaufender Ausdruck ueber den ganzen Text verschluckt sonst
        einzelne Paare, sobald in einer Antwort selbst `---` oder `> **` steht.

        `decided` kommt aus den Buttons, NICHT aus dem Text: auch eine offene
        Bewerbung beginnt mit einer Ueberschrift ("Neue Bewerbung: ..."), der
        Ergebnis-Kopf existiert aber nur bei entschiedenen.
        """
        blocks = re.split(r"\n---[ \t]*\n", body)
        # Bei entschiedenen Bewerbungen ist der ERSTE Block der Ergebnis-Kopf
        # (Status, Entscheider, Begruendung) -- und der ist selbst in `> **`
        # gesetzt. Er wird als Kopf abgetrennt, sonst stuende die Begruendung
        # als zusaetzliche "Frage" im Verlauf.
        head = ""
        if decided and blocks:
            head, blocks = blocks[0], blocks[1:]
        pairs = []
        for i, b in enumerate(blocks):
            m = re.search(r"> \*\*(.+?)\*\*[ \t]*\n(.*)", b, re.S)
            if m is None:
                if i == 0 and not head:
                    head = b            # reiner Vorspann ohne Frage
                continue
            if i == 0 and not head:
                head = b[:m.start()]
            answer = m.group(2)
            # Alt-Logs tragen am Ende noch den sichtbaren HTML-Kommentar-Marker.
            answer = re.sub(r"<!--\s*applicant:\d+\s*-->", "", answer)
            pairs.append({"question": m.group(1).strip(), "answer": answer.strip()})
        return head.strip(), pairs

    def _app_entry(self, g, apps, msg, full=False):
        """Eine Log-Nachricht als Listen-Element. None = keine Bewerbung."""
        cids = self._app_custom_ids(msg)
        acc = [c for c in cids if c.startswith("app_acc:")]
        tick = [c for c in cids if c.startswith("app_ticket:")]
        if not acc and not tick:
            return None
        ref = (acc or tick)[0].split(":")
        uid = int(ref[1]) if len(ref) > 1 and ref[1].isdigit() else None
        pid = ref[2] if len(ref) > 2 and ref[2] else apps.DEFAULT_PID
        if uid is None:
            uid = apps._extract_applicant_id(msg)
        body = apps._extract_log_body(msg) or (msg.content or "")
        # Offen = die Annehmen/Ablehnen-Buttons stehen noch dran. Nach der
        # Entscheidung bleibt nur der Ticket-Button uebrig (siehe
        # _decision_action_row), deshalb ist das ein verlaesslicher Marker.
        pending = bool(acc)
        head, pairs = self._app_parse_body(body, decided=not pending)
        status, decided_by, reason = "pending", None, None
        if not pending:
            import i18n
            acc_title = i18n.t("app.status_accepted", guild_id=g.id)
            status = "accepted" if acc_title and acc_title.strip("# ") in head else "denied"
            m = re.search(r"<@!?(\d+)>", head)
            decided_by = m.group(1) if m else None
            # Der Kopf ist uebersetzt, deshalb wird nicht nach festen Woertern
            # gesucht, sondern nach der Struktur: Zeile 1 ist der Status, dann
            # die Zeile mit der Erwaehnung (Entscheider), und ALLES danach ist
            # die Begruendung. Sie steht mehrzeilig da -- das Label ("> **Grund:**")
            # hat oft eine eigene Zeile, der Text folgt darunter.
            lines = [ln.strip() for ln in head.splitlines() if ln.strip()]
            tail, after_actor = [], False
            for ln in lines[1:]:
                if after_actor:
                    tail.append(re.sub(r"^> ?", "", ln))
                elif re.search(r"<@!?\d+>", ln):
                    after_actor = True
            if tail:
                # Fuehrendes Label der ersten Zeile abschneiden; bleibt danach
                # nichts uebrig, faengt die Begruendung erst darunter an.
                tail[0] = re.sub(r"^\*\*.*?\*\*:?\s*", "", tail[0])
                reason = "\n".join(x for x in tail if x).strip()[:600] or None

        member = g.get_member(uid) if uid else None
        panel = apps._panel_conf(str(g.id), pid) or {}
        out = {
            "message_id": str(msg.id),
            "channel_id": str(msg.channel.id),
            "panel": {"id": pid, "name": panel.get("name") or pid},
            "applicant": {
                "id": str(uid) if uid else None,
                "name": member.display_name if member else None,
                "avatar": member.display_avatar.url if member else None,
                "left": member is None,
            },
            "created": msg.created_at.isoformat(),
            "status": status,
            "answers": len(pairs),
            "decided_by": decided_by,
            "decision_reason": reason,
            "url": msg.jump_url,
        }
        if full:
            out["questions"] = pairs
            out["intro"] = head
            # Rollen, die eine Annahme vergeben wuerde -- damit im Web sichtbar
            # ist, was der Knopf tatsaechlich tut.
            out["accept_roles"] = [
                {"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                for rid in (panel.get("roles") or [])
            ]
        return out

    async def _app_log_channels(self, g, apps):
        """Log-Kanaele aller Bewerbungs-Panels dieses Servers (ohne Dubletten)."""
        conf = apps._guild_conf(str(g.id))
        seen, out = set(), []
        for pid, p in (conf.get("panels") or {}).items():
            cid = p.get("log")
            if not cid or cid in seen:
                continue
            ch = g.get_channel(cid)
            if ch is not None:
                seen.add(cid)
                out.append(ch)
        return out

    @rpc("applications.inbox", {"guild_id": ("id", True), "limit": ("int", False)}, scope="apps")
    async def _rpc_applications_inbox(self, args, actor):
        """Alle Bewerbungen aus den Log-Kanaelen der Panels -- offene zuerst.

        Es gibt keinen eigenen Bewerbungs-Speicher: eine Bewerbung IST die
        Nachricht im Log-Kanal (mit den Entscheidungs-Buttons). Deshalb wird
        hier der Kanalverlauf gelesen statt eine Tabelle abgefragt.
        """
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.applications as apps
        limit = min(max(args.get("limit", 60), 5), 150)

        items, unreadable = [], []
        for ch in await self._app_log_channels(g, apps):
            try:
                async for msg in ch.history(limit=limit, oldest_first=False):
                    if msg.author.id != (self.bot.user.id if self.bot.user else 0):
                        continue
                    e = self._app_entry(g, apps, msg)
                    if e:
                        items.append(e)
            except (discord.Forbidden, discord.HTTPException):
                unreadable.append({"id": str(ch.id), "name": ch.name})
        # Arbeitsreihenfolge: offene zuerst, darin die aelteste oben (wer am
        # laengsten wartet, kommt zuerst dran). Entschiedene danach, neueste
        # oben -- die liest man zum Nachschlagen, nicht zum Abarbeiten.
        pend = sorted([x for x in items if x["status"] == "pending"],
                      key=lambda x: x["created"])
        rest = sorted([x for x in items if x["status"] != "pending"],
                      key=lambda x: x["created"], reverse=True)
        items = pend + rest

        conf = apps._guild_conf(str(gid))
        panels = []
        for pid, p in (conf.get("panels") or {}).items():
            log_ch = g.get_channel(p.get("log")) if p.get("log") else None
            panels.append({
                "id": pid, "name": p.get("name") or pid,
                "open": bool(p.get("open", True)),
                "questions": len(p.get("questions") or []),
                "log_channel": ({"id": str(log_ch.id), "name": log_ch.name} if log_ch else None),
                "roles": [{"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                          for rid in (p.get("roles") or [])],
            })
        return {
            "guild_id": str(gid),
            "items": items,
            "panels": panels,
            "unreadable": unreadable,   # Log-Kanaele ohne Leserecht -> im Web benennen
            "counts": {
                "pending": len(pend),
                "accepted": sum(1 for x in rest if x["status"] == "accepted"),
                "denied": sum(1 for x in rest if x["status"] == "denied"),
            },
        }

    async def _app_message(self, gid, cid, mid):
        """Bewerbungs-Log-Nachricht holen -- und pruefen, dass sie eine IST.

        Waechter gegen untergeschobene IDs: der Kanal muss ein Log-Kanal eines
        Panels DIESER Guild sein, und die Nachricht muss vom Bot stammen und
        Bewerbungs-Buttons tragen. Ohne das koennte man ueber diese Kommandos
        beliebige Nachrichten auslesen oder ueberschreiben.
        """
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.applications as apps
        channels = {c.id: c for c in await self._app_log_channels(g, apps)}
        ch = channels.get(cid)
        if ch is None:
            raise _Denied("Kein Bewerbungs-Log-Kanal dieser Guild", 404)
        try:
            msg = await ch.fetch_message(mid)
        except discord.NotFound:
            raise _Denied("Bewerbung nicht gefunden (Nachricht geloescht?)", 404)
        except (discord.Forbidden, discord.HTTPException) as e:
            raise _Denied(f"Bewerbung nicht lesbar: {e}", 502)
        if self.bot.user is None or msg.author.id != self.bot.user.id:
            raise _Denied("Keine Bewerbung", 404)
        entry = self._app_entry(g, apps, msg, full=True)
        if entry is None:
            raise _Denied("Keine Bewerbung", 404)
        return g, apps, msg, entry

    @rpc("applications.get",
         {"guild_id": ("id", True), "channel_id": ("id", True), "message_id": ("id", True)},
         scope="apps")
    async def _rpc_applications_get(self, args, actor):
        _g, _apps, _msg, entry = await self._app_message(
            args["guild_id"], args["channel_id"], args["message_id"])
        return entry

    @rpc("applications.decide",
         {"guild_id": ("id", True), "channel_id": ("id", True), "message_id": ("id", True),
          "accept": ("bool", True), "reason": ("text", True)},
         writes=True, scope="apps")
    async def _rpc_applications_decide(self, args, actor):
        """Annehmen oder Ablehnen -- exakt der Ablauf des Buttons in Discord."""
        g, apps, msg, entry = await self._app_message(
            args["guild_id"], args["channel_id"], args["message_id"])
        if entry["status"] != "pending":
            raise _Denied("Diese Bewerbung ist bereits entschieden", 409)
        if not entry["applicant"]["id"]:
            raise _Denied("Bewerber-ID nicht lesbar", 422)
        reason = str(args["reason"]).strip()[:1000]
        if not reason:
            raise _Denied("Begruendung fehlt", 400)
        member = await self._actor_member(g, actor)
        pid = entry["panel"]["id"]
        panel = apps._panel_conf(str(g.id), pid) or {}
        why = apps.check_decider(g, member if member is not None else actor,
                                 int(entry["applicant"]["id"]), bool(args["accept"]),
                                 panel.get("roles") or [])
        if why:
            raise _Denied(why, 403)
        view, role_failed = await apps.decide_application(
            g, member or actor, int(entry["applicant"]["id"]), bool(args["accept"]), reason,
            log_message=msg, panel_id=pid, role_ids=(panel.get("roles") or []),
        )
        try:
            await msg.edit(view=view)
        except (discord.HTTPException, discord.Forbidden, discord.NotFound) as e:
            # Entscheidung ist durch (Rolle + DM), nur die Anzeige haengt.
            log.warning("webapi: Bewerbungs-Log %s nicht aktualisierbar: %r", msg.id, e)
            return {"ok": True, "log_updated": False, "role_failed": role_failed}
        log.info("webapi: Bewerbung %s auf Guild %s %s (durch %s)", msg.id, g.id,
                 "angenommen" if args["accept"] else "abgelehnt", actor)
        return {"ok": True, "log_updated": True, "role_failed": role_failed,
                "status": "accepted" if args["accept"] else "denied"}

    @rpc("applications.remind",
         {"guild_id": ("id", True), "channel_id": ("id", True), "message_id": ("id", True),
          "reason": ("text", True)},
         writes=True, scope="apps")
    async def _rpc_applications_remind(self, args, actor):
        """Zwischen-Info an den Bewerber ("dauert noch") -- wie der
        Erinnerungs-Button. Aendert weder Rollen noch die Log-Nachricht."""
        g, _apps, _msg, entry = await self._app_message(
            args["guild_id"], args["channel_id"], args["message_id"])
        uid = entry["applicant"]["id"]
        if not uid:
            raise _Denied("Bewerber-ID nicht lesbar", 422)
        reason = str(args["reason"]).strip()[:1000]
        if not reason:
            raise _Denied("Text fehlt", 400)
        member = g.get_member(int(uid))
        if member is None:
            try:
                member = await g.fetch_member(int(uid))
            except discord.HTTPException:
                member = None
        if member is None:
            raise _Denied("Bewerber ist nicht mehr auf dem Server", 404)
        import i18n
        dm_view = discord.ui.LayoutView(timeout=None)
        dm_view.add_item(discord.ui.Container(
            discord.ui.TextDisplay(
                i18n.t("app.dm_reminder_title", guild_id=g.id) + "\n\n"
                + i18n.t("app.dm_reminder_body", guild_id=g.id,
                         guild=g.name, reason=reason)
            ),
            accent_colour=discord.Colour.orange(),
        ))
        try:
            await member.send(view=dm_view)
        except (discord.Forbidden, discord.HTTPException) as e:
            raise _Denied(f"Erinnerung konnte nicht gesendet werden: {e}", 502)
        return {"ok": True, "user_id": str(uid)}

    # -- Welcome ---------------------------------------------------------------

    @rpc("welcome.status", {"guild_id": ("id", True)})
    async def _rpc_welcome_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.welcome as wc
        import i18n
        settings = wc.welcome_data.get(str(gid)) or {}
        channel = g.get_channel(settings.get("channel")) if settings.get("channel") else None
        autoroles = []
        for rid in settings.get("autoroles", []):
            r = g.get_role(rid)
            autoroles.append({"id": str(rid), "name": r.name if r else None})
        feats = wc._features(settings)
        features = [{"key": k, "label": i18n.t(label_key, guild_id=gid), "enabled": feats[k]}
                    for k, label_key, _d in wc.FEATURE_DEFS]
        return {
            "guild_id": str(gid),
            "configured": bool(settings),
            "enabled": settings.get("enabled", True),
            "channel": ({"id": str(settings["channel"]), "name": channel.name if channel else None}
                       if settings.get("channel") else None),
            "title": settings.get("title") or "",
            "message": settings.get("message") or "",
            "autoroles": autoroles,
            "features": features,
        }

    @rpc("welcome.set_channel", {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_welcome_set_channel(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        import cogs.welcome as wc
        gid_s = str(gid)
        settings = wc.welcome_data.setdefault(gid_s, {})
        settings["channel"] = cid
        wc.save_data(wc.welcome_data)
        log.info("webapi: Welcome-Kanal auf Guild %s -> %s durch %s", gid, cid, actor)
        return {"guild_id": gid_s, "channel_id": str(cid), "name": ch.name}

    @rpc("welcome.set_text",
         {"guild_id": ("id", True), "title": ("text", False), "message": ("text", False)}, writes=True)
    async def _rpc_welcome_set_text(self, args, actor):
        gid = args["guild_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.welcome as wc
        gid_s = str(gid)
        settings = wc.welcome_data.setdefault(gid_s, {})
        if "title" in args:
            settings["title"] = args["title"]
        if "message" in args:
            settings["message"] = args["message"]
        wc.save_data(wc.welcome_data)
        log.info("webapi: Welcome-Text auf Guild %s geändert durch %s", gid, actor)
        return {"guild_id": gid_s, "title": settings.get("title"), "message": settings.get("message")}

    @rpc("welcome.toggle", {"guild_id": ("id", True), "enabled": ("bool", True)}, writes=True)
    async def _rpc_welcome_toggle(self, args, actor):
        gid, enabled = args["guild_id"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.welcome as wc
        gid_s = str(gid)
        settings = wc.welcome_data.get(gid_s)
        if not settings:
            raise _Denied("Welcome noch nicht konfiguriert (erst Kanal setzen)", 404)
        settings["enabled"] = enabled
        wc.save_data(wc.welcome_data)
        log.info("webapi: Welcome auf Guild %s -> enabled=%s durch %s", gid, enabled, actor)
        return {"guild_id": gid_s, "enabled": enabled}

    @rpc("welcome.feature.set",
         {"guild_id": ("id", True), "key": ("str", True), "enabled": ("bool", True)}, writes=True)
    async def _rpc_welcome_feature(self, args, actor):
        gid, key, enabled = args["guild_id"], args["key"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.welcome as wc
        valid = {k for k, _l, _d in wc.FEATURE_DEFS}
        if key not in valid:
            raise _Denied(f"Unbekanntes Feature {key!r}", 404)
        gid_s = str(gid)
        settings = wc.welcome_data.setdefault(gid_s, {})
        settings.setdefault("features", {})[key] = enabled
        wc.save_data(wc.welcome_data)
        log.info("webapi: Welcome-Feature %s auf Guild %s -> %s durch %s", key, gid, enabled, actor)
        return {"guild_id": gid_s, "key": key, "enabled": enabled}

    # -- Verify ------------------------------------------------------------------
    # KEIN Weg, eine Rolle über die API wieder auf "nicht gesetzt" zu leeren
    # (das Schema unterscheidet "Feld fehlt" nicht von "Feld ist null" — siehe
    # _check()). Bewusste Lücke für diese Welle: Rolle SETZEN geht, Rolle
    # ENTFERNEN erst mal nur über die bestehende Discord-UI.

    @rpc("verify.status", {"guild_id": ("id", True)})
    async def _rpc_verify_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.verify as vf
        conf = vf.guild_conf(gid)
        channel = g.get_channel(conf.get("channel")) if conf.get("channel") else None
        add_role = g.get_role(conf.get("add_role")) if conf.get("add_role") else None
        remove_role = g.get_role(conf.get("remove_role")) if conf.get("remove_role") else None
        return {
            "guild_id": str(gid),
            "configured": bool(conf.get("channel")),
            "channel": ({"id": str(conf["channel"]), "name": channel.name if channel else None}
                       if conf.get("channel") else None),
            "add_role": ({"id": str(conf["add_role"]), "name": add_role.name if add_role else None}
                        if conf.get("add_role") else None),
            "remove_role": ({"id": str(conf["remove_role"]), "name": remove_role.name if remove_role else None}
                           if conf.get("remove_role") else None),
            "title": conf.get("titel") or "",
            "message": conf.get("nachricht") or "",
            "button_text": conf.get("button_text") or "",
        }

    @rpc("verify.set_channel", {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_verify_set_channel(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        import cogs.verify as vf
        conf = vf.guild_conf(gid)
        conf["channel"] = cid
        vf.save_data(vf.verify_data)
        log.info("webapi: Verify-Kanal auf Guild %s -> %s durch %s", gid, cid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid), "name": ch.name}

    @rpc("verify.set_roles",
         {"guild_id": ("id", True), "add_role": ("id", False, True), "remove_role": ("id", False, True)},
         writes=True)
    async def _rpc_verify_set_roles(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.verify as vf
        conf = vf.guild_conf(gid)
        # nullable=True (siehe _check): "add_role"/"remove_role" können jetzt
        # explizit null sein (Client will die Rolle LÖSCHEN) statt nur entweder
        # "gesetzt" oder "im Payload komplett weggelassen" zu sein.
        if "add_role" in args:
            rid = args["add_role"]
            if rid is not None and g.get_role(rid) is None:
                raise _Denied("Rolle unbekannt (add_role)", 404)
            if rid is not None:
                # Die Erfolgsrolle bekommt JEDER, der den Knopf drückt.
                await self._role_guard(g, g.get_role(rid), actor)
            conf["add_role"] = rid
        if "remove_role" in args:
            rid = args["remove_role"]
            if rid is not None and g.get_role(rid) is None:
                raise _Denied("Rolle unbekannt (remove_role)", 404)
            conf["remove_role"] = rid
        vf.save_data(vf.verify_data)
        log.info("webapi: Verify-Rollen auf Guild %s geändert durch %s", gid, actor)
        return {"guild_id": str(gid), "add_role": str(conf.get("add_role") or ""),
                "remove_role": str(conf.get("remove_role") or "")}

    @rpc("verify.set_text",
         {"guild_id": ("id", True), "title": ("text", False), "message": ("text", False),
          "button_text": ("str", False)}, writes=True)
    async def _rpc_verify_set_text(self, args, actor):
        gid = args["guild_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.verify as vf
        conf = vf.guild_conf(gid)
        if "title" in args:
            conf["titel"] = args["title"]
        if "message" in args:
            conf["nachricht"] = args["message"]
        if "button_text" in args:
            conf["button_text"] = args["button_text"]
        vf.save_data(vf.verify_data)
        log.info("webapi: Verify-Text auf Guild %s geändert durch %s", gid, actor)
        return {"guild_id": str(gid), "title": conf.get("titel"), "message": conf.get("nachricht"),
                "button_text": conf.get("button_text")}

    # -- Security-Suite (ScamRadar/AdminGuard/AccountShield/Honeypot) -------------
    # Alle vier folgen demselben Muster (_get/_conf lädt+mergt Defaults,
    # _save/_save_conf schreibt zurück) — EIN generischer RPC-Handler statt vier
    # fast identischer. exempt_roles/whitelist_roles sind bewusst NUR lesbar
    # (Listen-Editing bräuchte eigene add/remove-RPCs wie bei channel_exempt,
    # nicht in dieser Welle).
    _SECURITY_SYSTEMS = {
        "scamradar": {
            "getter": "_get", "setter": "_save",
            "fields": {
                "action": ("choice", ("flag", "delete")),
                "min_score": ("range", (0, 100)),
                "alert_channel": ("channel", None),
                "ai_assist": ("bool", None),
                "timeout": ("bool", None),
                "exempt_roles": ("roles", None),
            },
        },
        "adminguard": {
            "getter": "_get", "setter": "_save",
            "fields": {
                "alert_channel": ("channel", None),
                "sensitivity": ("choice", ("low", "medium", "high")),
                "mode": ("choice", ("alert", "quarantine")),
                "exempt_roles": ("roles", None),
                "exempt_users": ("roles", None),  # nur Anzeige, gleiche ID-Liste-Logik
            },
        },
        "accountshield": {
            "getter": "_get", "setter": "_save",
            "fields": {
                "action": ("choice", ("alert", "timeout")),
                "timeout_minutes": ("range", (1, 1440)),
                "purge": ("bool", None),
                "sensitivity": ("choice", ("low", "medium", "high")),
                "established_days": ("range", (0, 365)),
                "alert_channel": ("channel", None),
                "exempt_roles": ("roles", None),
            },
        },
        "honeypot": {
            "getter": "_conf", "setter": "_save_conf",
            "fields": {
                "channel": ("channel", None),
                "action": ("choice", ("timeout", "kick", "ban")),
                "timeout_minutes": ("range", (1, 1440)),
                "whitelist_roles": ("roles", None),
            },
        },
    }

    @rpc("security.config.get", {"guild_id": ("id", True), "system": ("str", True)})
    async def _rpc_security_get(self, args, actor):
        gid, system = args["guild_id"], args["system"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        spec = self._SECURITY_SYSTEMS.get(system)
        if spec is None:
            raise _Denied(f"Unbekanntes System {system!r}", 404)
        import importlib
        mod = importlib.import_module(f"cogs.{system}")
        conf = getattr(mod, spec["getter"])(gid)
        out, field_spec = {}, {}
        for key, (typ, extra) in spec["fields"].items():
            v = conf.get(key)
            if typ == "channel":
                ch = g.get_channel(v) if v else None
                out[key] = {"id": str(v), "name": ch.name if ch else None} if v else None
            elif typ == "roles":
                out[key] = [
                    {"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                    for rid in (v or [])
                ]
            else:
                out[key] = v
            # Typ-Info fürs Frontend, damit es das passende Widget rendert, ohne
            # Systeme fest zu verdrahten — neue Systeme brauchen nur einen
            # Registry-Eintrag hier, keine Frontend-Änderung.
            field_spec[key] = {"type": typ, "choices": list(extra) if typ == "choice" else None,
                               "range": list(extra) if typ == "range" else None}
        return {"guild_id": str(gid), "system": system, "fields": out, "spec": field_spec}

    @rpc("security.config.set",
         {"guild_id": ("id", True), "system": ("str", True), "key": ("str", True), "value": ("any", True)},
         writes=True)
    async def _rpc_security_set(self, args, actor):
        gid, system, key, value = args["guild_id"], args["system"], args["key"], args["value"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        spec = self._SECURITY_SYSTEMS.get(system)
        if spec is None:
            raise _Denied(f"Unbekanntes System {system!r}", 404)
        field_spec = spec["fields"].get(key)
        if field_spec is None:
            raise _Denied(f"Unbekanntes Feld {key!r} für {system!r}", 404)
        typ, extra = field_spec
        if typ == "choice":
            if value not in extra:
                raise _Denied(f"{key} muss einer von {extra} sein", 400)
        elif typ == "range":
            lo, hi = extra
            if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
                raise _Denied(f"{key} muss eine Zahl zwischen {lo} und {hi} sein", 400)
        elif typ == "bool":
            if not isinstance(value, bool):
                raise _Denied(f"{key} muss ein Bool sein", 400)
        elif typ == "channel":
            try:
                cid = int(value)
            except (TypeError, ValueError):
                raise _Denied(f"{key}: ungültige Kanal-ID", 400)
            if g.get_channel(cid) is None:
                raise _Denied(f"{key}: Kanal unbekannt", 404)
            value = cid
        else:
            raise _Denied(f"Feld {key!r} ist über die API nur lesbar (Typ {typ})", 400)

        import importlib
        mod = importlib.import_module(f"cogs.{system}")
        getter, setter = getattr(mod, spec["getter"]), getattr(mod, spec["setter"])
        # Shallow-Kopie: honeypot._conf() liefert (anders als scamradar/adminguard/
        # accountshield._get(), die immer ein frisches Dict mergen) das GECACHTE
        # storage.read_doc-Objekt direkt zurück — das darf laut storage.py-Vertrag
        # nicht mutiert werden. dict(...) schützt hier unabhängig vom jeweiligen
        # Getter, auch falls ein künftiges System denselben Cache-Rückgabestil hat.
        conf = dict(getter(gid))
        conf[key] = value
        setter(gid, conf)
        log.info("webapi: Security-Config %s.%s auf Guild %s -> %s durch %s",
                 system, key, gid, value, actor)
        return {"guild_id": str(gid), "system": system, "key": key, "value": value}

    async def _security_roles_mutate(self, args, actor, add: bool):
        """Gemeinsame Implementierung für security.config.roles.add/remove.
        Eigene add/remove-Kommandos statt eines Listen-Werts in
        security.config.set: passt zum bestehenden Muster (siehe
        antiping.protected.add/remove, automod.channel_exempt.add/remove) und
        braucht keine Erweiterung von _check() auf Array-Werte."""
        gid, system, key, role_id = args["guild_id"], args["system"], args["key"], args["role_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        spec = self._SECURITY_SYSTEMS.get(system)
        if spec is None:
            raise _Denied(f"Unbekanntes System {system!r}", 404)
        field_spec = spec["fields"].get(key)
        if field_spec is None or field_spec[0] != "roles":
            raise _Denied(f"Feld {key!r} ist kein Rollen-Feld für {system!r}", 400)
        if add and g.get_role(role_id) is None:
            raise _Denied("Rolle unbekannt", 404)

        import importlib
        mod = importlib.import_module(f"cogs.{system}")
        getter, setter = getattr(mod, spec["getter"]), getattr(mod, spec["setter"])
        conf = dict(getter(gid))                    # Kopie — siehe Kommentar oben in _rpc_security_set
        ids = list(conf.get(key) or [])
        if add:
            if role_id not in ids:
                ids.append(role_id)
        else:
            ids = [r for r in ids if r != role_id]
        conf[key] = ids
        setter(gid, conf)
        log.info("webapi: Security-Config %s.%s Rolle %s %s auf Guild %s durch %s",
                 system, key, role_id, "hinzugefügt" if add else "entfernt", gid, actor)
        return {
            "guild_id": str(gid), "system": system, "key": key,
            "roles": [
                {"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                for rid in ids
            ],
        }

    @rpc("security.config.roles.add",
         {"guild_id": ("id", True), "system": ("str", True), "key": ("str", True), "role_id": ("id", True)},
         writes=True)
    async def _rpc_security_roles_add(self, args, actor):
        return await self._security_roles_mutate(args, actor, add=True)

    @rpc("security.config.roles.remove",
         {"guild_id": ("id", True), "system": ("str", True), "key": ("str", True), "role_id": ("id", True)},
         writes=True)
    async def _rpc_security_roles_remove(self, args, actor):
        return await self._security_roles_mutate(args, actor, add=False)

    # -- Anti-Raid (eigenes, feld-majores Schema — passt nicht ins generische Muster) --

    @rpc("antiraid.status", {"guild_id": ("id", True)})
    async def _rpc_antiraid_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.antiraid as ar
        gid_s = str(gid)
        ch_id = ar.data["alertchannel"].get(gid_s)
        ch = g.get_channel(ch_id) if ch_id else None
        return {
            "guild_id": gid_s,
            "toggles": {
                "joinlimit": ar.data["joinlimit"].get(gid_s, False),
                "newaccount": ar.data["newaccount"].get(gid_s, False),
                "predictor": ar.data["predictor"].get(gid_s, False),
                "noavatar": ar.data["noavatar"].get(gid_s, False),
            },
            "response": ar.data["response"].get(gid_s, "slowmode"),
            "sensitivity": ar.data["sensitivity"].get(gid_s, "medium"),
            "alert_channel": {"id": str(ch_id), "name": ch.name if ch else None} if ch_id else None,
        }

    @rpc("antiraid.toggle",
         {"guild_id": ("id", True), "key": ("str", True), "enabled": ("bool", True)}, writes=True)
    async def _rpc_antiraid_toggle(self, args, actor):
        gid, key, enabled = args["guild_id"], args["key"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        if key not in ("joinlimit", "newaccount", "predictor", "noavatar"):
            raise _Denied(f"Unbekannter Schalter {key!r}", 404)
        import cogs.antiraid as ar
        ar.data[key][str(gid)] = enabled
        ar.save_data(ar.data)
        log.info("webapi: Antiraid %s auf Guild %s -> %s durch %s", key, gid, enabled, actor)
        return {"guild_id": str(gid), "key": key, "enabled": enabled}

    @rpc("antiraid.set",
         {"guild_id": ("id", True), "response": ("str", False), "sensitivity": ("str", False),
          "alert_channel": ("id", False)}, writes=True)
    async def _rpc_antiraid_set(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.antiraid as ar
        gid_s = str(gid)
        if "response" in args:
            if args["response"] not in ("slowmode", "lockdown", "alert"):
                raise _Denied("response muss slowmode/lockdown/alert sein", 400)
            ar.data["response"][gid_s] = args["response"]
        if "sensitivity" in args:
            if args["sensitivity"] not in ("low", "medium", "high"):
                raise _Denied("sensitivity muss low/medium/high sein", 400)
            ar.data["sensitivity"][gid_s] = args["sensitivity"]
        if "alert_channel" in args:
            cid = args["alert_channel"]
            if g.get_channel(cid) is None:
                raise _Denied("Kanal unbekannt", 404)
            ar.data["alertchannel"][gid_s] = cid
        ar.save_data(ar.data)
        log.info("webapi: Antiraid-Settings auf Guild %s geändert durch %s", gid, actor)
        return {"guild_id": gid_s}

    # -- Server-Log ----------------------------------------------------------

    @rpc("serverlog.status", {"guild_id": ("id", True)})
    async def _rpc_serverlog_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.serverlog as sl
        conf = sl._conf(gid)
        main_ch = g.get_channel(conf.get("log_channel")) if conf.get("log_channel") else None
        disabled = set(conf.get("disabled") or [])
        cats_conf = conf.get("categories") or {}
        cats = []
        for key in sl.CAT_ORDER:
            emoji, _colour = sl.CATS[key]
            override_id = cats_conf.get(key)
            override_ch = g.get_channel(override_id) if override_id else None
            cats.append({
                "key": key, "emoji": emoji, "enabled": key not in disabled,
                "channel": ({"id": str(override_id), "name": override_ch.name if override_ch else None}
                           if override_id else None),
            })
        return {
            "guild_id": str(gid),
            "log_channel": ({"id": str(conf["log_channel"]), "name": main_ch.name if main_ch else None}
                           if conf.get("log_channel") else None),
            "categories": cats,
        }

    @rpc("serverlog.set_channel", {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_serverlog_set_channel(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        import cogs.serverlog as sl
        # dict()-Kopie: sl._conf() liefert das gecachte storage.read_doc()-Objekt
        # direkt zurück (nicht gemergt wie bei scamradar/adminguard/accountshield) —
        # gleicher Bug wie zuvor bei honeypot, hier separat gefixt, da serverlog
        # nicht Teil des generischen security.config-Mechanismus ist.
        conf = dict(sl._conf(gid))
        conf["log_channel"] = cid
        sl._save_conf(gid, conf)
        log.info("webapi: Serverlog-Kanal auf Guild %s -> %s durch %s", gid, cid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid), "name": ch.name}

    @rpc("serverlog.category.toggle",
         {"guild_id": ("id", True), "category": ("str", True), "enabled": ("bool", True)}, writes=True)
    async def _rpc_serverlog_cat_toggle(self, args, actor):
        gid, category, enabled = args["guild_id"], args["category"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.serverlog as sl
        if category not in sl.CAT_ORDER:
            raise _Denied(f"Unbekannte Kategorie {category!r}", 404)
        conf = dict(sl._conf(gid))  # Kopie — siehe Kommentar in _rpc_serverlog_set_channel
        disabled = set(conf.get("disabled") or [])
        if enabled:
            disabled.discard(category)
        else:
            disabled.add(category)
        conf["disabled"] = sorted(disabled)
        sl._save_conf(gid, conf)
        log.info("webapi: Serverlog-Kategorie %s auf Guild %s -> %s durch %s",
                 category, gid, enabled, actor)
        return {"guild_id": str(gid), "category": category, "enabled": enabled}

    @rpc("serverlog.category.set_channel",
         {"guild_id": ("id", True), "category": ("str", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_serverlog_cat_channel(self, args, actor):
        gid, category, cid = args["guild_id"], args["category"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.serverlog as sl
        if category not in sl.CAT_ORDER:
            raise _Denied(f"Unbekannte Kategorie {category!r}", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        conf = dict(sl._conf(gid))  # Kopie — siehe Kommentar in _rpc_serverlog_set_channel
        conf.setdefault("categories", {})[category] = cid
        sl._save_conf(gid, conf)
        log.info("webapi: Serverlog-Kategorie-Kanal %s auf Guild %s -> %s durch %s",
                 category, gid, cid, actor)
        return {"guild_id": str(gid), "category": category, "channel_id": str(cid), "name": ch.name}

    # -- Giveaways (nur Übersicht — Erstellen/Beenden bleibt im Discord-Menü) ----

    @rpc("giveaways.overview", {"guild_id": ("id", True)})
    async def _rpc_giveaways_overview(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.giveaways as gw
        items = gw._all().get("items", {})
        mine = [x for x in items.values() if x.get("guild") == gid]

        def _shape(x):
            ch = g.get_channel(x.get("channel"))
            return {
                "id": x.get("id"), "prize": x.get("prize"), "winners": x.get("winners"),
                "channel": ch.name if ch else None, "ends_at": x.get("end"),
                "entries": len(x.get("entries") or []), "ended": bool(x.get("ended")),
            }

        running = sorted([x for x in mine if not x.get("ended")], key=lambda x: x.get("end", 0))
        ended = sorted([x for x in mine if x.get("ended")], key=lambda x: x.get("end", 0), reverse=True)
        return {
            "guild_id": str(gid),
            "running": [_shape(x) for x in running],
            "ended": [_shape(x) for x in ended[:10]],
        }

    # -- Levels ----------------------------------------------------------------

    @rpc("levels.leaderboard", {"guild_id": ("id", True)})
    async def _rpc_levels_leaderboard(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.levels as lv
        d = storage.kv_get_all(lv._xpns(gid))
        top = sorted(d.items(), key=lambda kv: kv[1][0], reverse=True)[:10]
        out = []
        for uid, rec in top:
            m = g.get_member(int(uid))
            out.append({
                "user_id": str(uid), "name": m.display_name if m else None,
                "xp": rec[0], "level": lv.level_from_xp(rec[0]),
            })
        return {"guild_id": str(gid), "top": out}

    @rpc("levels.config.get", {"guild_id": ("id", True)})
    async def _rpc_levels_config_get(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.levels as lv
        cfg = storage.read_doc(lv.CFG, {}).get(str(gid), {})
        cid = cfg.get("announce_channel")
        ch = g.get_channel(cid) if cid else None
        return {
            "guild_id": str(gid),
            "announce_channel": {"id": str(cid), "name": ch.name if ch else None} if cid else None,
            "multiplier": float(cfg.get("multiplier", 1.0)),
        }

    @rpc("levels.config.set",
         {"guild_id": ("id", True), "announce_channel": ("id", False), "multiplier": ("str", False)},
         writes=True)
    async def _rpc_levels_config_set(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.levels as lv
        gid_s = str(gid)
        d = storage.load_doc(lv.CFG, {})
        cfg = d.setdefault(gid_s, {})
        if "announce_channel" in args:
            cid = args["announce_channel"]
            if g.get_channel(cid) is None:
                raise _Denied("Kanal unbekannt", 404)
            cfg["announce_channel"] = cid
        if "multiplier" in args:
            try:
                mult = float(args["multiplier"])
            except ValueError:
                raise _Denied("multiplier muss eine Zahl sein", 400)
            if not (0.1 <= mult <= 10):
                raise _Denied("multiplier muss zwischen 0.1 und 10 liegen", 400)
            cfg["multiplier"] = mult
        storage.save_doc(lv.CFG, d)
        log.info("webapi: Level-Config auf Guild %s geändert durch %s", gid, actor)
        return {"guild_id": gid_s, "announce_channel": cfg.get("announce_channel"),
                "multiplier": cfg.get("multiplier", 1.0)}

    # -- Anti-Ping (geschützte User/Rollen + Whitelist) --------------------------

    @rpc("antiping.status", {"guild_id": ("id", True)})
    async def _rpc_antiping_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.antiping as ap
        gid_s = str(gid)

        def _user_refs(ids):
            out = []
            for uid in ids:
                m = g.get_member(uid)
                out.append({"id": str(uid), "name": m.display_name if m else None})
            return out

        def _role_refs(ids):
            out = []
            for rid in ids:
                r = g.get_role(rid)
                out.append({"id": str(rid), "name": r.name if r else None})
            return out

        return {
            "guild_id": gid_s,
            "protected_users": _user_refs(ap.data["protected_users"].get(gid_s, [])),
            "protected_roles": _role_refs(ap.data["protected_roles"].get(gid_s, [])),
            "whitelist": _user_refs(ap.data["whitelist"].get(gid_s, [])),
        }

    @rpc("antiping.protected.add",
         {"guild_id": ("id", True), "kind": ("str", True), "target_id": ("id", True)}, writes=True)
    async def _rpc_antiping_protected_add(self, args, actor):
        gid, kind, tid = args["guild_id"], args["kind"], args["target_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        if kind not in ("user", "role"):
            raise _Denied("kind muss 'user' oder 'role' sein", 400)
        import cogs.antiping as ap
        gid_s = str(gid)
        if kind == "role":
            if g.get_role(tid) is None:
                raise _Denied("Rolle unbekannt", 404)
            bucket = ap.data["protected_roles"].setdefault(gid_s, [])
        else:
            bucket = ap.data["protected_users"].setdefault(gid_s, [])
        if tid not in bucket:
            bucket.append(tid)
            ap.save_data(ap.data)
        log.info("webapi: Anti-Ping-Schutz +%s (%s) auf Guild %s durch %s", tid, kind, gid, actor)
        return {"guild_id": gid_s, "kind": kind, "target_id": str(tid)}

    @rpc("antiping.protected.remove",
         {"guild_id": ("id", True), "kind": ("str", True), "target_id": ("id", True)}, writes=True)
    async def _rpc_antiping_protected_remove(self, args, actor):
        gid, kind, tid = args["guild_id"], args["kind"], args["target_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        if kind not in ("user", "role"):
            raise _Denied("kind muss 'user' oder 'role' sein", 400)
        import cogs.antiping as ap
        gid_s = str(gid)
        bucket = ap.data["protected_roles" if kind == "role" else "protected_users"].get(gid_s, [])
        if tid in bucket:
            bucket.remove(tid)
            ap.save_data(ap.data)
        log.info("webapi: Anti-Ping-Schutz -%s (%s) auf Guild %s durch %s", tid, kind, gid, actor)
        return {"guild_id": gid_s, "kind": kind, "target_id": str(tid)}

    @rpc("antiping.whitelist.add", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_antiping_whitelist_add(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.antiping as ap
        gid_s = str(gid)
        bucket = ap.data["whitelist"].setdefault(gid_s, [])
        if uid not in bucket:
            bucket.append(uid)
            ap.save_data(ap.data)
        log.info("webapi: Anti-Ping-Whitelist +%s auf Guild %s durch %s", uid, gid, actor)
        return {"guild_id": gid_s, "user_id": str(uid)}

    @rpc("antiping.whitelist.remove", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_antiping_whitelist_remove(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.antiping as ap
        gid_s = str(gid)
        bucket = ap.data["whitelist"].get(gid_s, [])
        if uid in bucket:
            bucket.remove(uid)
            ap.save_data(ap.data)
        log.info("webapi: Anti-Ping-Whitelist -%s auf Guild %s durch %s", uid, gid, actor)
        return {"guild_id": gid_s, "user_id": str(uid)}

    # -- Selfroles ------------------------------------------------------------

    # Selfroles (v3-Format: Panels unter einer zufälligen pid, Nachricht in
    # p["message"]/p["posted_channel"]). Die Handler liefen bis 24.09. noch im
    # Alt-Format (Key = Message-ID) -> „'int' object has no attribute 'get'“,
    # 400 bei Löschen/Rolle, 500 beim Refresh (Audit 23.09.2026). Das Web
    # reicht die pid unverändert als `message_id` durch (opaker String).
    _SR_PID_RE = re.compile(r"^[0-9a-f]{8}$|^\d{15,21}$")

    def _sr_panel(self, gid, pid):
        import cogs.selfroles as sr
        if not isinstance(pid, str) or not self._SR_PID_RE.match(pid):
            raise _Denied("Panel-ID ungültig", 400)
        panel = sr.gdata(gid).get(pid)
        if not isinstance(panel, dict):
            raise _Denied("Panel unbekannt", 404)
        if sr._clean_roles(panel):
            sr.save_data(sr.selfrole_data)
        return sr, panel

    @rpc("selfroles.panel.list", {"guild_id": ("id", True)})
    async def _rpc_selfroles_list(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.selfroles as sr
        panels = sr.gdata(gid)
        out = []
        for pid, p in panels.items():
            if not isinstance(p, dict):
                continue
            sr._clean_roles(p)
            cid = p.get("posted_channel") or p.get("channel")
            ch = g.get_channel(cid) if cid else None
            roles = []
            for key, r in (p.get("roles") or {}).items():
                role = g.get_role(int(r.get("role_id") or 0))
                roles.append({
                    "key": key, "role_id": str(r.get("role_id")),
                    "role_name": role.name if role else None,
                    "label": r.get("label"), "emoji": r.get("emoji"),
                })
            out.append({
                "message_id": pid,
                "channel": {"id": str(cid), "name": ch.name if ch else None} if cid else None,
                "titel": p.get("titel", ""), "nachricht": p.get("nachricht", ""),
                "roles": roles, "max_roles": sr.MAX_ROLES,
            })
        return {"guild_id": str(gid), "panels": out}

    @rpc("selfroles.panel.create",
         {"guild_id": ("id", True), "channel_id": ("id", True), "titel": ("str", True), "nachricht": ("text", True)},
         writes=True)
    async def _rpc_selfroles_create(self, args, actor):
        gid, cid, titel, nachricht = args["guild_id"], args["channel_id"], args["titel"], args["nachricht"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt", 404)
        import cogs.selfroles as sr
        d = sr.gdata(gid)
        if len(d) >= getattr(sr, "PANEL_LIMIT", 25):
            raise _Denied("Maximale Anzahl Selfrole-Panels erreicht", 400)
        pid = secrets.token_hex(4)
        while pid in d:
            pid = secrets.token_hex(4)
        view = sr.build_panel_view(pid, titel, nachricht, {})
        try:
            msg = await ch.send(view=view)
        except discord.Forbidden:
            raise _Denied("Keine Berechtigung, in diesem Kanal zu posten", 403)
        d[pid] = {
            "name": (titel or "Selfroles")[:80], "titel": titel, "nachricht": nachricht,
            "channel": cid, "message": msg.id, "posted_channel": cid, "roles": {},
        }
        sr.save_data(sr.selfrole_data)
        log.info("webapi: Selfroles-Panel %s erstellt Guild %s Kanal %s durch %s", pid, gid, cid, actor)
        return {"guild_id": str(gid), "message_id": pid, "channel_id": str(cid)}

    @rpc("selfroles.panel.delete", {"guild_id": ("id", True), "message_id": ("str", True)}, writes=True)
    async def _rpc_selfroles_delete(self, args, actor):
        gid, pid = args["guild_id"], args["message_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        sr, panel = self._sr_panel(gid, pid)
        sr.gdata(gid).pop(pid, None)
        sr.save_data(sr.selfrole_data)
        ch = g.get_channel(panel.get("posted_channel") or 0)
        if ch is not None and panel.get("message"):
            try:
                msg = await ch.fetch_message(int(panel["message"]))
                await msg.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass
        log.info("webapi: Selfroles-Panel %s gelöscht Guild %s durch %s", pid, gid, actor)
        return {"guild_id": str(gid), "message_id": pid}

    @rpc("selfroles.panel.role.add",
         {"guild_id": ("id", True), "message_id": ("str", True), "role_id": ("id", True),
          "label": ("str", True), "emoji": ("str", False)},
         writes=True)
    async def _rpc_selfroles_role_add(self, args, actor):
        gid, pid, rid, label = args["guild_id"], args["message_id"], args["role_id"], args["label"]
        emoji = args.get("emoji") or None
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        sr, panel = self._sr_panel(gid, pid)
        role = g.get_role(rid)
        if role is None:
            raise _Denied("Rolle unbekannt", 404)
        sicher, grund = sr.rolle_ist_sicher(role, g.me)
        if not sicher:
            raise _Denied(f"Rolle nicht erlaubt: {grund}", 400)
        await self._role_guard(g, role, actor)
        if len(panel["roles"]) >= sr.MAX_ROLES:
            raise _Denied(f"Maximal {sr.MAX_ROLES} Rollen pro Panel", 400)
        if any(int(r["role_id"]) == rid for r in panel["roles"].values()):
            raise _Denied("Rolle bereits im Panel", 400)
        panel["roles"][f"role_{rid}"] = {"role_id": rid, "label": label[:80], "emoji": emoji}
        sr.save_data(sr.selfrole_data)
        await sr._sync_panel_message(g, pid, panel)
        log.info("webapi: Selfroles-Rolle %s zu Panel %s Guild %s durch %s", rid, pid, gid, actor)
        return {"guild_id": str(gid), "message_id": pid, "roles": len(panel["roles"])}

    @rpc("selfroles.panel.role.remove",
         {"guild_id": ("id", True), "message_id": ("str", True), "role_key": ("str", True)},
         writes=True)
    async def _rpc_selfroles_role_remove(self, args, actor):
        gid, pid, key = args["guild_id"], args["message_id"], args["role_key"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        sr, panel = self._sr_panel(gid, pid)
        panel["roles"].pop(key, None)
        sr.save_data(sr.selfrole_data)
        await sr._sync_panel_message(g, pid, panel)
        log.info("webapi: Selfroles-Rolle %s von Panel %s Guild %s entfernt durch %s", key, pid, gid, actor)
        return {"guild_id": str(gid), "message_id": pid, "roles": len(panel["roles"])}

    # -- Tags / Autoresponder ---------------------------------------------------

    @rpc("tags.list", {"guild_id": ("id", True)})
    async def _rpc_tags_list(self, args, actor):
        gid = args["guild_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        _, conf = tg._guild_conf(gid)
        tags = []
        for n, t in sorted(conf["tags"].items()):
            e = tg.normalize(t)
            tags.append({"name": n, "content": e["content"], "uses": e["uses"],
                         "embed": e["embed"], "cooldown": e["cooldown"],
                         "roles": [str(r) for r in e["roles"]]})
        responders = [{"trigger": k, "reply": v} for k, v in sorted(conf["responders"].items())]
        return {"guild_id": str(gid), "tags": tags, "responders": responders,
                "max_tags": tg.MAX_TAGS, "max_responders": tg.MAX_RESPONDERS,
                "max_cooldown": tg.MAX_COOLDOWN, "max_roles": tg.MAX_TAG_ROLES}

    @staticmethod
    def _tags_options(args, guild, tg):
        """Prüft die optionalen Tag-Einstellungen (Panel/Rollen/Cooldown) und gibt
        nur die Felder zurück, die der Client wirklich geschickt hat -- so kann
        ein Update einzelne Einstellungen ändern, ohne die anderen zu verlieren."""
        out = {}
        if "embed" in args:
            slug = args["embed"]
            if slug:
                import cogs.embeds as em
                if em.designs(guild.id).get(slug) is None:
                    raise _Denied("Panel unbekannt", 404)
                out["embed"] = slug
            else:
                out["embed"] = None          # ausdrueckliches Loeschen der Zuordnung
        if "cooldown" in args:
            cd = args["cooldown"]
            if not (0 <= cd <= tg.MAX_COOLDOWN):
                raise _Denied(f"Cooldown muss zwischen 0 und {tg.MAX_COOLDOWN} liegen", 400)
            out["cooldown"] = cd
        if "roles" in args:
            roles = args["roles"] or []
            if len(roles) > tg.MAX_TAG_ROLES:
                raise _Denied(f"Maximal {tg.MAX_TAG_ROLES} Rollen", 400)
            for rid in roles:
                if guild.get_role(rid) is None:
                    raise _Denied("Rolle unbekannt", 404)
            out["roles"] = roles
        return out

    @rpc("tags.create",
         {"guild_id": ("id", True), "name": ("str", True), "content": ("text", True),
          "embed": ("str", False, True), "cooldown": ("int", False),
          "roles": ("id_list", False)},
         writes=True)
    async def _rpc_tags_create(self, args, actor):
        gid, name, content = args["guild_id"], args["name"], args["content"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        opts = self._tags_options(args, g, tg)
        d, conf = tg._guild_conf(gid)
        key = name.lower().strip()[:50]
        if not key:
            raise _Denied("Name darf nicht leer sein", 400)
        if key in conf["tags"]:
            raise _Denied(f"Tag {key!r} existiert bereits", 400)
        if len(conf["tags"]) >= tg.MAX_TAGS:
            raise _Denied(f"Maximal {tg.MAX_TAGS} Tags", 400)
        entry = {"content": content[:1900], "uses": 0, "author": actor,
                 "embed": None, "roles": [], "cooldown": 0}
        entry.update(opts)
        conf["tags"][key] = entry
        storage.save_doc(tg.NS, d)
        log.info("webapi: Tag %s erstellt Guild %s durch %s", key, gid, actor)
        return {"guild_id": str(gid), "name": key, "tag": self._tags_brief(key, tg.normalize(entry))}

    @staticmethod
    def _tags_brief(name, e):
        return {"name": name, "content": e["content"], "uses": e["uses"],
                "embed": e["embed"], "cooldown": e["cooldown"],
                "roles": [str(r) for r in e["roles"]]}

    @rpc("tags.update",
         {"guild_id": ("id", True), "name": ("str", True), "content": ("text", False),
          "embed": ("str", False, True), "cooldown": ("int", False),
          "roles": ("id_list", False)},
         writes=True)
    async def _rpc_tags_update(self, args, actor):
        """Ändert einen bestehenden Tag. Nur mitgeschickte Felder werden angefasst
        -- Inhalt ändern, ohne Rollen und Cooldown mitschicken zu müssen."""
        gid, name = args["guild_id"], args["name"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        opts = self._tags_options(args, g, tg)
        d, conf = tg._guild_conf(gid)
        key = name.lower().strip()[:50]
        raw = conf["tags"].get(key)
        if raw is None:
            raise _Denied("Tag unbekannt", 404)
        entry = tg.normalize(raw)
        if "content" in args:
            entry["content"] = args["content"][:1900]
        entry.update(opts)
        conf["tags"][key] = entry
        storage.save_doc(tg.NS, d)
        log.info("webapi: Tag %s geändert Guild %s durch %s", key, gid, actor)
        return {"guild_id": str(gid), "name": key, "tag": self._tags_brief(key, entry)}

    @rpc("tags.delete", {"guild_id": ("id", True), "name": ("str", True)}, writes=True)
    async def _rpc_tags_delete(self, args, actor):
        gid, name = args["guild_id"], args["name"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        d, conf = tg._guild_conf(gid)
        if conf["tags"].pop(name.lower(), None) is None:
            raise _Denied("Tag unbekannt", 404)
        storage.save_doc(tg.NS, d)
        log.info("webapi: Tag %s gelöscht Guild %s durch %s", name, gid, actor)
        return {"guild_id": str(gid), "name": name.lower()}

    @rpc("tags.responder.add",
         {"guild_id": ("id", True), "trigger": ("str", True), "reply": ("text", True)}, writes=True)
    async def _rpc_tags_responder_add(self, args, actor):
        gid, trigger, reply = args["guild_id"], args["trigger"], args["reply"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        d, conf = tg._guild_conf(gid)
        key = trigger.lower().strip()[:100]
        if not key:
            raise _Denied("Auslöser darf nicht leer sein", 400)
        if key not in conf["responders"] and len(conf["responders"]) >= tg.MAX_RESPONDERS:
            raise _Denied(f"Maximal {tg.MAX_RESPONDERS} Auto-Antworten", 400)
        conf["responders"][key] = reply[:1000]
        storage.save_doc(tg.NS, d)
        log.info("webapi: Autoresponder %s gesetzt Guild %s durch %s", key, gid, actor)
        return {"guild_id": str(gid), "trigger": key}

    @rpc("tags.responder.remove", {"guild_id": ("id", True), "trigger": ("str", True)}, writes=True)
    async def _rpc_tags_responder_remove(self, args, actor):
        gid, trigger = args["guild_id"], args["trigger"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.tags as tg
        d, conf = tg._guild_conf(gid)
        if conf["responders"].pop(trigger.lower(), None) is None:
            raise _Denied("Auto-Antwort unbekannt", 404)
        storage.save_doc(tg.NS, d)
        log.info("webapi: Autoresponder %s entfernt Guild %s durch %s", trigger, gid, actor)
        return {"guild_id": str(gid), "trigger": trigger.lower()}

    # -- Embed-Baukasten ----------------------------------------------------------
    # Der Editor lebt im Dashboard; hier liegt nur Speichern/Posten. Die
    # inhaltliche Prüfung macht IMMER cogs.embeds.validate_blocks -- das
    # Dashboard spiegelt dieselben Grenzen nur, um dem Nutzer einen konkreten
    # Grund zeigen zu koennen (Fehlergruende gehen von hier nie an den Client).

    def _embeds_guild(self, gid):
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        return g

    @staticmethod
    def _embeds_brief(slug, v):
        return {
            "slug": slug,
            "name": v.get("name", slug),
            "accent": int(v.get("accent") or 0x5865F2),
            "blocks": len(v.get("blocks") or []),
            "posts": len(v.get("posts") or {}),
            "updated": v.get("updated"),
        }

    @rpc("embeds.list", {"guild_id": ("id", True)})
    async def _rpc_embeds_list(self, args, actor):
        gid = args["guild_id"]
        self._embeds_guild(gid)
        import cogs.embeds as em
        ds = em.designs(gid)
        return {
            "guild_id": str(gid),
            "max": em.MAX_DESIGNS,
            "designs": [self._embeds_brief(k, v) for k, v in sorted(ds.items())],
        }

    @rpc("embeds.get", {"guild_id": ("id", True), "slug": ("str", True)})
    async def _rpc_embeds_get(self, args, actor):
        gid, slug = args["guild_id"], args["slug"]
        self._embeds_guild(gid)
        import cogs.embeds as em
        v = em.designs(gid).get(slug)
        if v is None:
            raise _Denied("Vorlage unbekannt", 404)
        out = self._embeds_brief(slug, v)
        out["blocks"] = v.get("blocks") or []
        out["posted_in"] = sorted({str(c) for c in (v.get("posts") or {}).values()})
        return {"guild_id": str(gid), "design": out}

    @rpc("embeds.save",
         {"guild_id": ("id", True), "slug": ("str", False), "name": ("str", True),
          "accent": ("int", False), "blocks": ("json", True)},
         writes=True)
    async def _rpc_embeds_save(self, args, actor):
        gid, name = args["guild_id"], args["name"].strip()
        self._embeds_guild(gid)
        import cogs.embeds as em
        if not name or len(name) > em.MAX_NAME:
            raise _Denied("Name fehlt oder ist zu lang", 400)
        try:
            blocks = em.validate_blocks(args["blocks"])
        except ValueError as e:
            raise _Denied(f"Bloecke: {e}", 400)
        accent = args.get("accent")
        if accent is not None and not (0 <= accent <= 0xFFFFFF):
            raise _Denied("accent ausserhalb 0..0xFFFFFF", 400)

        d = em._all()
        conf = em.guild_conf(d, gid)
        slug = args.get("slug")
        if slug:
            if slug not in conf["designs"]:
                raise _Denied("Vorlage unbekannt", 404)
        else:
            base = em.slugify(name)
            slug = base
            n = 2
            while slug in conf["designs"]:
                slug = f"{base}-{n}"[:32]
                n += 1
            if len(conf["designs"]) >= em.MAX_DESIGNS:
                raise _Denied(f"Maximal {em.MAX_DESIGNS} Vorlagen", 400)
        entry = conf["designs"].setdefault(slug, {})
        entry.update({"name": name, "accent": int(accent) if accent is not None
                      else int(entry.get("accent") or em.ACCENT_DEFAULT),
                      "blocks": blocks, "author": actor, "updated": time.time()})
        entry.setdefault("posts", {})
        em._save(d)
        log.info("webapi: Embed-Vorlage %s gespeichert Guild %s durch %s", slug, gid, actor)
        return {"guild_id": str(gid), "design": self._embeds_brief(slug, entry)}

    @rpc("embeds.delete", {"guild_id": ("id", True), "slug": ("str", True)}, writes=True)
    async def _rpc_embeds_delete(self, args, actor):
        gid, slug = args["guild_id"], args["slug"]
        self._embeds_guild(gid)
        import cogs.embeds as em
        d = em._all()
        conf = em.guild_conf(d, gid)
        if conf["designs"].pop(slug, None) is None:
            raise _Denied("Vorlage unbekannt", 404)
        em._save(d)
        log.info("webapi: Embed-Vorlage %s geloescht Guild %s durch %s", slug, gid, actor)
        return {"guild_id": str(gid), "slug": slug}

    @rpc("embeds.post",
         {"guild_id": ("id", True), "slug": ("str", True), "channel_id": ("id", True)},
         writes=True)
    async def _rpc_embeds_post(self, args, actor):
        gid, slug, cid = args["guild_id"], args["slug"], args["channel_id"]
        g = self._embeds_guild(gid)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt", 404)
        import cogs.embeds as em
        design = em.designs(gid).get(slug)
        if design is None:
            raise _Denied("Vorlage unbekannt", 404)
        if not design.get("blocks"):
            raise _Denied("Vorlage ist leer", 400)
        try:
            msg = await em.post_design(ch, design)
        except discord.Forbidden:
            raise _Denied("Keine Berechtigung, in diesem Kanal zu posten", 403)
        em.remember_post(gid, slug, cid, msg.id)
        log.info("webapi: Embed-Vorlage %s gepostet Guild %s Kanal %s durch %s",
                 slug, gid, cid, actor)
        return {"guild_id": str(gid), "slug": slug, "channel_id": str(cid),
                "message_id": str(msg.id)}

    @rpc("embeds.sync", {"guild_id": ("id", True), "slug": ("str", True)}, writes=True)
    async def _rpc_embeds_sync(self, args, actor):
        gid, slug = args["guild_id"], args["slug"]
        g = self._embeds_guild(gid)
        import cogs.embeds as em
        if em.designs(gid).get(slug) is None:
            raise _Denied("Vorlage unbekannt", 404)
        ok, gone = await em.sync_design(g, slug)
        log.info("webapi: Embed-Vorlage %s gesynct Guild %s (%s ok, %s weg) durch %s",
                 slug, gid, ok, gone, actor)
        return {"guild_id": str(gid), "slug": slug, "updated": ok, "gone": gone}

    # -- Starboard --------------------------------------------------------------

    @rpc("starboard.status", {"guild_id": ("id", True)})
    async def _rpc_starboard_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.starboard as sb
        conf = sb._all().get(str(gid), {})
        ch = g.get_channel(conf.get("channel")) if conf.get("channel") else None
        return {
            "guild_id": str(gid),
            "channel": {"id": str(conf["channel"]), "name": ch.name if ch else None} if conf.get("channel") else None,
            "threshold": int(conf.get("threshold", 3)),
            "emoji": conf.get("emoji", "⭐"),
        }

    @rpc("starboard.set",
         {"guild_id": ("id", True), "channel_id": ("id", False), "threshold": ("int", False), "emoji": ("str", False)},
         writes=True)
    async def _rpc_starboard_set(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.starboard as sb
        d = sb._all()
        conf = d.setdefault(str(gid), {})
        if "channel_id" in args:
            ch = g.get_channel(args["channel_id"])
            if ch is None:
                raise _Denied("Kanal unbekannt", 404)
            conf["channel"] = args["channel_id"]
        if "threshold" in args:
            if not (1 <= args["threshold"] <= 100):
                raise _Denied("Schwelle muss zwischen 1 und 100 liegen", 400)
            conf["threshold"] = args["threshold"]
        if "emoji" in args:
            if not args["emoji"]:
                raise _Denied("Emoji darf nicht leer sein", 400)
            conf["emoji"] = args["emoji"][:32]
        sb._save(d)
        log.info("webapi: Starboard-Config Guild %s durch %s", gid, actor)
        return {"guild_id": str(gid), "channel_id": str(conf.get("channel") or "") or None,
                "threshold": conf.get("threshold", 3), "emoji": conf.get("emoji", "⭐")}

    # --- Der EINE interne Team-Bereich ---------------------------------------
    # Das Team-Dashboard im Web ist NICHT pro Server, sondern der interne
    # Bereich des IronShield-Teams. Welcher Server das Team definiert (Mitglieder,
    # Team-Rollen, Verwaltungs-Freigaben, Dienst-Schichten, Ankündigungen), steht
    # EINMAL in der Datenbank; gearbeitet wird auf genau diesem Datensatz, damit
    # Web und das /team-Menü in Discord dasselbe zeigen.
    _TEAM_NS = "webapi_team"

    @staticmethod
    def _team_guild_id():
        import storage
        cfg = storage.load_doc(WebAPI._TEAM_NS, {}) or {}
        gid = cfg.get("guild_id")
        if not gid:
            gid = os.getenv("WEBAPI_TEAM_GUILD", "").strip()
        try:
            return int(gid) if gid else None
        except (TypeError, ValueError):
            return None

    def _team_guild(self):
        """Der Server, der das IronShield-Team definiert — oder None."""
        gid = self._team_guild_id()
        return self.bot.get_guild(gid) if gid else None

    @rpc("team.config.get")
    async def _rpc_team_config_get(self, args, actor):
        g = self._team_guild()
        return {
            "guild_id": (str(g.id) if g else (str(self._team_guild_id()) if self._team_guild_id() else None)),
            "guild_name": (g.name if g else None),
            "resolved": g is not None,
        }

    # scope="super" MUSS hier ausdrücklich stehen: der Decorator leitet den
    # Scope sonst aus dem Vorhandensein von "guild_id" ab und käme auf "guild".
    # Das hieße, jeder Administrator IRGENDEINES Servers, auf dem der Bot ist,
    # könnte den Team-Server der gesamten Installation auf seinen eigenen
    # umbiegen — und damit den internen Bereich kapern. Nur Bot-Owner.
    @rpc("team.config.set", {"guild_id": ("id", True)}, writes=True, scope="super")
    async def _rpc_team_config_set(self, args, actor):
        import storage
        g = self.bot.get_guild(args["guild_id"])
        if g is None:
            raise _Denied("Guild unbekannt (ist der Bot dort?)", 404)
        storage.save_doc(self._TEAM_NS, {"guild_id": int(g.id)})
        return await self._rpc_team_config_get({}, actor)

    # -- Team-Dashboard (Web-Oberfläche für cogs/team_dashboard.py) ---------------
    # Bewusst KEIN eigener Datenspeicher: gelesen und geschrieben wird derselbe
    # Datensatz, den auch das /team-Menü in Discord benutzt (Namespace
    # "team_dashboard:<guild_id>"). Wer im Team ist, entscheidet ebenfalls das
    # bestehende System (members / sync_roles / verwaltung_access) — damit gibt es
    # keine zweite Mitgliederliste, die auseinanderlaufen kann.

    def _resolve_team_guild(self, args):
        """Guild für ein team.*-Kommando: übergebene guild_id, sonst der
        konfigurierte Team-Server. Fehlt beides, ist der Bereich nicht
        eingerichtet — das ist ein klarer Fehler, keine leere Seite."""
        gid = args.get("guild_id") or self._team_guild_id()
        if not gid:
            raise _Denied("Team-Bereich nicht eingerichtet (team.config.set)", 409)
        g = self.bot.get_guild(int(gid))
        if g is None:
            raise _Denied("Team-Server unbekannt (ist der Bot dort?)", 404)
        return g

    @staticmethod
    def _team_audit(data, actor, title, text=""):
        """Ereignis ins Team-Protokoll schreiben — IN den bereits geladenen
        Datensatz, gespeichert wird vom Aufrufer.

        Nötig, weil `_log_event` im Cog nur bei Aufnahme/Entfernung/Verwarnung
        greift. Aktionen, die es nur im Panel gibt (Ankündigung, Notiz,
        Ressource, Termin, Abmeldung), tauchten sonst nirgends auf — das
        Protokoll blieb leer, obwohl gearbeitet wurde.
        """
        log = data.setdefault("audit", [])
        log.append({
            "id": uuid.uuid4().hex, "ts": int(time.time()),
            "title": str(title)[:120],
            "text": (f"<@{actor}> " + str(text))[:600] if text else f"<@{actor}>",
        })
        if len(log) > 300:
            del log[:-300]

    @staticmethod
    def _team_mod():
        import cogs.team_dashboard as td
        return td

    async def _team_role(self, guild, actor):
        """Rolle des Actors im Team dieser Guild.

        "manage" = darf verwalten (Bot-Owner, Guild-Owner, Administrator oder
        ausdrücklich freigeschaltet), "member" = Team-Mitglied (auch über
        Auto-Sync-Rolle), None = gehört nicht zum Team.
        """
        if actor in ACTORS:
            return "manage"
        td = self._team_mod()
        data = td.load(guild.id)
        member = guild.get_member(actor)
        if member is None:
            return None
        if guild.owner_id == actor or member.guild_permissions.administrator:
            return "manage"
        if actor in [int(x) for x in (data.get("verwaltung_access") or [])]:
            return "manage"
        if actor in [int(x) for x in (data.get("members") or [])]:
            return "member"
        sync = {int(x) for x in (data.get("sync_roles") or [])}
        if sync and any(r.id in sync for r in member.roles):
            return "member"
        return None

    def _team_role_cached(self, guild, actor):
        """Wie _team_role, aber OHNE die Bot-Owner-Abkuerzung und garantiert
        cache-only. Fuer team.guilds, das ueber alle Guilds des Bots laeuft:
        dort waere "Bot-Owner sieht alles" keine Hilfe, sondern eine Liste mit
        hunderten Servern statt der eigenen Team-Server.
        """
        member = guild.get_member(actor)
        if member is None:
            return None, False
        td = self._team_mod()
        data = td.load(guild.id)
        # "eingerichtet" = das Team-System wurde auf diesem Server schon benutzt.
        configured = bool(data.get("members") or data.get("sync_roles")
                          or data.get("verwaltung_access"))
        if guild.owner_id == actor or member.guild_permissions.administrator:
            return "manage", configured
        if actor in [int(x) for x in (data.get("verwaltung_access") or [])]:
            return "manage", configured
        if actor in [int(x) for x in (data.get("members") or [])]:
            return "member", configured
        sync = {int(x) for x in (data.get("sync_roles") or [])}
        if sync and any(r.id in sync for r in member.roles):
            return "member", configured
        return None, configured

    def _team_ticket_stats(self, g, actor):
        """Kennzahlen der offenen Tickets EINER Guild fuer den Team-Bereich.

        Bewusst dieselbe Datenquelle wie tickets.inbox (cogs/ticketsystem.py),
        aber ohne die vollen Ticket-Objekte: der Ueberblick braucht nur Zahlen,
        und team.guilds ruft das fuer jeden Team-Server einmal auf.
        Liefert None, wenn das Ticketsystem hier nichts kennt.
        """
        try:
            import cogs.ticketsystem as ts
            d = ts.gdata(g.id)
        except Exception:
            return None
        panels = d.get("panels") or {}
        if not panels:
            return None
        claimed = d.get("claimed_tickets") or {}
        meta_all = d.get("meta") or {}
        now = time.time()
        total = unclaimed = mine = overdue = 0
        for pid, p in panels.items():
            for cid in list((p.get("open_tickets") or {}).values()):
                cid_s = str(cid)
                meta = meta_all.get(cid_s)
                if meta is None or g.get_channel(int(cid)) is None:
                    continue        # Kanal von Hand geloescht / Altdaten
                total += 1
                owner = claimed.get(cid_s)
                if owner:
                    if str(owner) == str(actor):
                        mine += 1
                    continue
                unclaimed += 1
                prio = meta.get("priority", ts.DEFAULT_PRIORITY)
                if prio not in ts.PRIORITY_LEVELS:
                    prio = ts.DEFAULT_PRIORITY
                dl = ts._sla_deadline_ts(g.id, pid, prio, meta.get("sla_since"))
                if dl and dl < now:
                    overdue += 1
        stats = d.get("stats") or {}
        return {
            "open": total, "unclaimed": unclaimed, "mine": mine,
            "overdue": overdue, "closed_total": int(stats.get("closed_total", 0) or 0),
        }

    @rpc("team.guilds", scope="self")
    async def _rpc_team_guilds(self, args, actor):
        """Alle Server, auf denen dieser Actor zum Team gehoert.

        Das ist die Grundlage dafuer, dass JEDE Guild ihren eigenen
        Team-Bereich hat statt einem einzigen globalen: das Web fragt hier,
        wohin es den Angemeldeten ueberhaupt lassen darf, und ruft danach die
        bestehenden team.*-Kommandos mit genau dieser guild_id.

        scope="self", weil der Handler selbst filtert -- er liefert
        ausschliesslich Server, auf denen der Actor Team-Mitglied oder
        Verwaltung ist. Alles cache-only (kein fetch_member): der Bot ist auf
        ueber 900 Servern, ein REST-Fallback pro Server wuerde den Request
        sprengen.
        """
        primary = self._team_guild_id()
        items = []
        for g in self.bot.guilds:
            role, configured = self._team_role_cached(g, actor)
            is_support = self._support_authorized_cached(g, actor)
            if role is None:
                # Ticket-Personal ohne Eintrag im Team-System: bekommt den
                # Server trotzdem zu sehen, aber nur den Ticket-Arbeitsplatz.
                # Ohne das muesste jemand, der auf 12 Servern Tickets bearbeitet,
                # 12 Links auswendig kennen -- genau das soll die Liste loesen.
                if not is_support:
                    continue
                role = "support"
            # Server ohne eingerichtetes Team zeigen wir nur der Verwaltung --
            # fuer sie ist es ein Angebot ("hier koennt ihr starten"), fuer ein
            # Mitglied waere es nur Rauschen.
            elif not configured and role != "manage":
                continue
            td = self._team_mod()
            data = td.load(g.id)
            shifts = data.get("shifts") or {}
            warns = data.get("warns") or {}
            tickets = None
            if role in ("manage", "support") or is_support:
                tickets = self._team_ticket_stats(g, actor)
            items.append({
                **self._guild_dict(g),
                "role": role,
                "can_manage": role == "manage",
                "can_support": bool(is_support or role == "manage"),
                "team_access": role != "support",   # darf die team.*-Kommandos
                "configured": configured,
                "primary": bool(primary and int(primary) == g.id),
                "team_members": len(data.get("members") or []),
                "on_duty": len(shifts.get("on_duty") or {}),
                "absences": len(data.get("abmeldungen") or []),
                "infos": len(data.get("infos") or []),
                "events": len(data.get("events") or []),
                "warns_total": sum(self._warn_count(v) for v in warns.values()),
                "activity_check": bool((data.get("activity_check") or {}).get("active")),
                "tickets": tickets,
            })
        # Reihenfolge = Nuetzlichkeit: eingerichtete Team-Server zuerst, darin
        # der Haupt-Team-Server, dann die mit den meisten Team-Mitgliedern.
        items.sort(key=lambda x: (x["role"] == "support", not x["configured"],
                                  not x["primary"], -x["team_members"],
                                  (x["name"] or "").lower()))
        return {"total": len(items), "items": items,
                "primary": (str(primary) if primary else None)}

    @staticmethod
    def _warn_count(value):
        """Anzahl Verwarnungen aus dem Team-Datensatz.

        WICHTIG: `data["warns"]` ist im Bot ein ZÄHLER pro Nutzer
        (`{uid: 2}`), keine Liste (siehe cogs/team_dashboard.py,
        do_team_warn). Diese Funktion nimmt beides an, damit ein späterer
        Umbau auf Einzeleinträge hier nichts kaputt macht.
        """
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int):
            return max(0, value)
        try:
            return len(value)
        except TypeError:
            return 0

    @staticmethod
    def _team_person(guild, uid):
        m = guild.get_member(int(uid))
        return {
            "id": str(uid),
            "name": (m.display_name if m else None),
            "avatar": (m.display_avatar.url if m else None),
            "left": m is None,          # im Team eingetragen, aber nicht mehr auf dem Server
        }

    @rpc("team.me", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_me(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td._load_rolled(g.id)
        on_duty = data.get("shifts", {}).get("on_duty", {}) or {}
        role = await self._team_role(g, actor)
        return {
            "guild_id": str(g.id),
            "guild_name": g.name,
            "role": role,
            "can_manage": role == "manage",
            "on_duty": str(actor) in on_duty,
            "since": int(on_duty.get(str(actor), 0)) or None,
        }

    @rpc("team.overview", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_overview(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td._load_rolled(g.id)
        shifts = data.get("shifts", {}) or {}
        on_duty = shifts.get("on_duty", {}) or {}
        warns = data.get("warns", {}) or {}
        ac = data.get("activity_check", {}) or {}
        can_support = bool(await self._support_authorized(g, actor))
        return {
            "guild_id": str(g.id),
            "members": len(data.get("members") or []),
            "on_duty": [
                {**self._team_person(g, uid), "since": int(ts or 0)}
                for uid, ts in list(on_duty.items())[:25]
            ],
            "absences": len(data.get("abmeldungen") or []),
            "infos": len(data.get("infos") or []),
            "events": len(data.get("events") or []),
            "warns_total": sum(self._warn_count(v) for v in warns.values()),
            "activity_check": {
                "active": bool(ac.get("active")),
                "confirmed": len(ac.get("confirmed") or []),
                "started_at": int(ac.get("started_at") or 0),
            },
            # Tickets gehoeren in den Team-Ueberblick: das ist die Arbeit, die
            # gerade offen liegt. Nur fuer Leute, die auch an Tickets duerfen --
            # sonst stuende hier eine Zahl, auf die man nicht klicken kann.
            "can_support": can_support,
            "tickets": self._team_ticket_stats(g, actor) if can_support else None,
        }

    @rpc("team.members", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_members(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td._load_rolled(g.id)
        shifts = data.get("shifts", {}) or {}
        on_duty = shifts.get("on_duty", {}) or {}
        totals = shifts.get("totals", {}) or {}
        warns = data.get("warns", {}) or {}
        absent = {}
        for a in data.get("abmeldungen") or []:
            if a.get("user_id"):
                absent[str(a["user_id"])] = a.get("bis") or ""
        # Rang-Leiter (Auto-Sync-Rollen, niedrig -> hoch). Sie ist die Grundlage
        # fuer Uprank/Downrank im Panel: ohne Leiter zeigt die Oberflaeche die
        # Knoepfe gar nicht erst an, statt sie ins Leere laufen zu lassen.
        ladder = td._rank_ladder(g, data)
        items = []
        for uid in data.get("members") or []:
            p = self._team_person(g, uid)
            key = str(uid)
            m = g.get_member(int(uid))
            idx = td._current_rank_index(m, ladder) if (m and ladder) else -1
            items.append({
                **p,
                "on_duty": key in on_duty,
                "since": int(on_duty.get(key, 0)) or None,
                "today_s": int(totals.get(key, 0) or 0),
                "warns": self._warn_count(warns.get(key)),
                "absent_until": absent.get(key) or None,
                "rank": (ladder[idx].name if idx >= 0 else None),
                "rank_index": idx,
                "can_up": bool(ladder) and m is not None and idx < len(ladder) - 1,
                "can_down": bool(ladder) and m is not None and idx >= 0,
            })
        items.sort(key=lambda x: ((x["name"] or "~").lower()))
        return {
            "guild_id": str(g.id), "items": items, "total": len(items),
            "ladder": [{"id": str(r.id), "name": r.name} for r in ladder],
        }

    @rpc("team.infos.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_infos(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        items = []
        for i in data.get("infos") or []:
            # "titel"/"kategorie"/"read_by" sind Ergänzungen der Web-Oberfläche;
            # ältere Einträge (aus /team in Discord) haben nur "text" und werden
            # deshalb mit Standardwerten ausgeliefert.
            read_by = [str(x) for x in (i.get("read_by") or [])]
            items.append({
                "id": i.get("id"),
                "title": i.get("titel") or "",
                "text": i.get("text") or "",
                "category": i.get("kategorie") or "info",
                "ts": int(i.get("ts") or 0),
                "read_by": len(read_by),
                "read_by_me": str(actor) in read_by,
                "readers": [self._team_person(g, x) for x in read_by[:30]],
                "author": self._team_person(g, i["author_id"]) if i.get("author_id") else None,
            })
        items.sort(key=lambda x: -x["ts"])
        return {"guild_id": str(g.id), "items": items}

    @rpc("team.infos.read",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         scope="team")
    async def _rpc_team_infos_read(self, args, actor):
        """Als gelesen markieren — darf JEDES Team-Mitglied für sich selbst,
        deshalb bewusst ohne writes=True (das würde Verwaltungsrechte
        verlangen). Geändert wird ausschließlich der eigene Eintrag."""
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        for i in data.get("infos") or []:
            if i.get("id") == args["entry_id"]:
                rb = [str(x) for x in (i.get("read_by") or [])]
                if str(actor) not in rb:
                    rb.append(str(actor))
                i["read_by"] = rb
                break
        td.save(g.id, data)
        return await self._rpc_team_infos({"guild_id": g.id}, actor)

    @rpc("team.infos.add",
         {"guild_id": ("id", False), "text": ("text", True),
          "title": ("str", False), "category": ("str", False)},
         writes=True, scope="team")
    async def _rpc_team_infos_add(self, args, actor):
        g = self._resolve_team_guild(args)
        text = (args["text"] or "").strip()
        if not text:
            raise _Denied("Text leer", 400)
        cat = (args.get("category") or "info").lower()
        if cat not in ("info", "wichtig", "event"):
            cat = "info"
        td = self._team_mod()
        data = td.load(g.id)
        data.setdefault("infos", []).append({
            "id": td._new_id(), "text": text[:1800],
            "titel": (args.get("title") or "").strip()[:120],
            "kategorie": cat, "ts": int(time.time()),
            "read_by": [str(actor)],          # wer sie schreibt, hat sie gelesen
            "author_id": actor,
        })
        self._team_audit(data, actor, "📣 Ankündigung veröffentlicht", text[:80])
        td.save(g.id, data)
        return await self._rpc_team_infos({"guild_id": g.id}, actor)

    @rpc("team.infos.remove",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         writes=True, scope="team")
    async def _rpc_team_infos_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        data["infos"] = [i for i in (data.get("infos") or []) if i.get("id") != args["entry_id"]]
        self._team_audit(data, actor, "🗑 Ankündigung entfernt")
        td.save(g.id, data)
        return await self._rpc_team_infos({"guild_id": g.id}, actor)

    # --- Alt-Abmeldungen aus Discord lesbar machen -------------------------
    # Über /team eingetragene Abmeldungen sind Freitext. In der Praxis steht da
    # alles Mögliche: "14.06.2026", "23 7 26 bis 20 8 26", "22.06-10.07",
    # "Bis zum Wochenende", "In 2 Tagen". Außerdem fehlt bei alten Einträgen die
    # user_id — die Erwähnung <@123> steckt aber im Text.
    # Deshalb: Person aus dem Text herausziehen und, WENN eindeutig, ein echtes
    # Datum erkennen. Gelingt das nicht, bleibt der Originaltext stehen und wird
    # in der Oberfläche als "unklar" gekennzeichnet, statt etwas zu erfinden.
    _MONTHS_DE = {
        "januar": 1, "jan": 1, "februar": 2, "feb": 2, "märz": 3, "maerz": 3, "mrz": 3,
        "april": 4, "apr": 4, "mai": 5, "juni": 6, "jun": 6, "juli": 7, "jul": 7,
        "august": 8, "aug": 8, "september": 9, "sep": 9, "sept": 9, "oktober": 10,
        "okt": 10, "november": 11, "nov": 11, "dezember": 12, "dez": 12,
    }

    @classmethod
    def _parse_de_date(cls, text):
        """Letztes erkennbares Datum aus einem Freitext als "JJJJ-MM-TT".

        Vorgehen: den Text zuerst an Bereichs-Trennern ("bis", "-", "–")
        zerlegen und den LETZTEN Abschnitt nehmen, der ein Datum enthält. Ohne
        diese Trennung liest "22.06-10.07" als "22.06.2010" — die "-10" landet
        sonst in der Jahres-Gruppe.

        Gibt None zurück, wenn nichts eindeutig Erkennbares drinsteht
        ("Bis zum Wochenende", "In 2 Tagen") — dann wird nichts erfunden.
        """
        if not text:
            return None
        t = text.strip().lower()
        if re.match(r"^\d{4}-\d{2}-\d{2}$", t):
            return t

        # An "bis" und an Bindestrichen ZWISCHEN Ziffern trennen (nicht an
        # Bindestrichen innerhalb eines Datums wie "23-7-26" — die stehen nach
        # einer Ziffer UND vor einer Ziffer, deshalb zusätzlich die Punkt-Form
        # als Grenze verlangen).
        parts = re.split(r"\bbis\b|[–—]|(?<=\d{2})\s*-\s*(?=\d{1,2}[.\s])", t)
        for seg in reversed([p for p in parts if p and p.strip()]):
            d = cls._date_in_segment(seg)
            if d:
                return d
        return None

    @classmethod
    def _date_in_segment(cls, t):
        """Letztes Datum innerhalb EINES Abschnitts."""
        found = []

        def year(y):
            y = int(y)
            if y < 100:
                y += 2000
            return y if 2000 <= y <= 2099 else None

        # 14.06.2026 / 8.8.26 / 22.06 / 23 7 26
        for m in re.finditer(r"\b(\d{1,2})\s*[.\-/ ]\s*(\d{1,2})(?:\s*[.\-/ ]\s*(\d{2,4}))?\b", t):
            d, mo, y = int(m.group(1)), int(m.group(2)), m.group(3)
            if not (1 <= d <= 31 and 1 <= mo <= 12):
                continue
            found.append((m.start(), d, mo, year(y) if y else None))

        # 14. August 2026 / 30 Juli 25
        for m in re.finditer(r"\b(\d{1,2})\.?\s+([a-zäöü]+)\.?(?:\s+(\d{2,4}))?\b", t):
            mo = cls._MONTHS_DE.get(m.group(2))
            d = int(m.group(1))
            if not mo or not (1 <= d <= 31):
                continue
            found.append((m.start(), d, mo, year(m.group(3)) if m.group(3) else None))

        if not found:
            return None
        _, d, mo, yy = max(found, key=lambda x: x[0])
        if yy is None:
            yy = time.gmtime().tm_year
        return f"{yy:04d}-{mo:02d}-{d:02d}"

    @staticmethod
    def _split_legacy_absence(text):
        """Aus '👤 <@123> 📅 Bis: X 📝 Grund: Y' die Teile herausziehen."""
        uid = None
        m = re.search(r"<@!?(\d{15,20})>", text or "")
        if m:
            uid = int(m.group(1))
        bis = grund = ""
        mb = re.search(r"bis\s*:?\s*(.*?)(?:📝|grund\s*:|$)", text or "", re.I | re.S)
        if mb:
            bis = mb.group(1).strip(" .·—-\n")
        mg = re.search(r"grund\s*:?\s*(.*)$", text or "", re.I | re.S)
        if mg:
            grund = mg.group(1).strip(" .·—-\n")
        return uid, bis, grund

    @rpc("team.absences.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_absences(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        items = []
        for a in data.get("abmeldungen") or []:
            uid = a.get("user_id")
            bis = a.get("bis") or ""
            grund = a.get("grund") or ""
            legacy = a.get("legacy_text") or ""
            if legacy:
                # Alt-Eintrag: Person, Bis und Grund stecken im Fließtext.
                luid, lbis, lgrund = self._split_legacy_absence(legacy)
                uid = uid or luid
                bis = bis or lbis
                grund = grund or lgrund
            iso = a.get("bis_date") or ""
            guessed = False
            if not iso and bis:
                iso = self._parse_de_date(bis) or ""
                guessed = bool(iso)
            items.append({
                "id": a.get("id"),
                "person": self._team_person(g, uid) if uid else None,
                # "von"/"bis_date" sind ISO-Felder der Web-Oberfläche; "bis" ist
                # der bestehende Freitext aus /team in Discord.
                "from": a.get("von") or "",
                "until_date": iso,
                "until": bis,
                "date_guessed": guessed,     # aus Freitext erkannt, nicht eingegeben
                "reason": grund or legacy,
            })
        # Nach Enddatum sortieren; alles ohne erkennbares Datum ans Ende.
        items.sort(key=lambda x: (x["until_date"] == "", x["until_date"]))
        return {"guild_id": str(g.id), "items": items}

    @rpc("team.absences.fix",
         {"guild_id": ("id", False), "entry_id": ("str", True),
          "until": ("str", True), "from": ("str", False), "reason": ("text", False)},
         writes=True, scope="team")
    async def _rpc_team_absences_fix(self, args, actor):
        """Korrigiert einen Alt-Eintrag auf ein echtes Datum.

        Nötig, weil über /team in Discord Freitext eingetragen wurde
        ("Bis zum Wochenende", "In 2 Tagen") — damit lässt sich nicht rechnen.
        Der Originaltext bleibt als Grund erhalten, es geht nichts verloren.
        """
        g = self._resolve_team_guild(args)
        iso = r"^\d{4}-\d{2}-\d{2}$"
        until = (args["until"] or "").strip()
        frm = (args.get("from") or "").strip()
        if not re.match(iso, until):
            raise _Denied("Enddatum muss JJJJ-MM-TT sein", 400)
        if frm and not re.match(iso, frm):
            raise _Denied("Startdatum muss JJJJ-MM-TT sein", 400)
        if frm and until < frm:
            raise _Denied("Ende liegt vor dem Beginn", 400)
        td = self._team_mod()
        data = td.load(g.id)
        for a in data.get("abmeldungen") or []:
            if a.get("id") == args["entry_id"]:
                if a.get("legacy_text") and not a.get("user_id"):
                    luid, _, lgrund = self._split_legacy_absence(a["legacy_text"])
                    if luid:
                        a["user_id"] = luid
                    if lgrund and not a.get("grund"):
                        a["grund"] = lgrund
                a["bis_date"] = until
                a["bis"] = until
                if frm:
                    a["von"] = frm
                if args.get("reason"):
                    a["grund"] = (args["reason"] or "")[:500]
                break
        else:
            raise _Denied("Eintrag nicht gefunden", 404)
        self._team_audit(data, actor, "✏️ Abwesenheits-Datum korrigiert", f"bis {until}")
        td.save(g.id, data)
        return await self._rpc_team_absences({"guild_id": g.id}, actor)

    # Bewusst OHNE writes=True: der Eintrag entsteht für den Aufrufer selbst
    # (user_id = actor). Mit writes hätte sich ein normales Team-Mitglied nicht
    # abmelden können — genau das, wozu die Oberfläche auffordert.
    @rpc("team.absences.add",
         {"guild_id": ("id", False), "until": ("str", True), "reason": ("text", False),
          "from": ("str", False)},
         scope="team")
    async def _rpc_team_absences_add(self, args, actor):
        g = self._resolve_team_guild(args)
        until = (args["until"] or "").strip()
        frm = (args.get("from") or "").strip()
        iso = r"^\d{4}-\d{2}-\d{2}$"
        if not re.match(iso, until):
            raise _Denied("Enddatum muss JJJJ-MM-TT sein", 400)
        if frm and not re.match(iso, frm):
            raise _Denied("Startdatum muss JJJJ-MM-TT sein", 400)
        if frm and until < frm:
            raise _Denied("Ende liegt vor dem Beginn", 400)
        td = self._team_mod()
        data = td.load(g.id)
        data.setdefault("abmeldungen", []).append({
            "id": td._new_id(), "user_id": actor,
            "von": frm, "bis_date": until,
            # "bis" bleibt der Freitext, den /team in Discord anzeigt.
            "bis": until, "grund": (args.get("reason") or "")[:500],
        })
        self._team_audit(data, actor, "🌴 Abwesenheit eingetragen", f"bis {until}")
        td.save(g.id, data)
        return await self._rpc_team_absences({"guild_id": g.id}, actor)

    # Wie beim Anlegen ohne writes=True — die Rechteprüfung steckt im Handler:
    # die EIGENE Abmeldung darf jeder löschen, fremde nur die Verwaltung.
    @rpc("team.absences.remove",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         scope="team")
    async def _rpc_team_absences_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        eintrag = next((a for a in (data.get("abmeldungen") or [])
                        if a.get("id") == args["entry_id"]), None)
        if eintrag is None:
            raise _Denied("Eintrag nicht gefunden", 404)
        if str(eintrag.get("user_id")) != str(actor):
            if await self._team_role(g, actor) != "manage" and actor not in ACTORS:
                raise _Denied("Nur eigene Abmeldungen löschbar", 403)
        data["abmeldungen"] = [a for a in (data.get("abmeldungen") or [])
                               if a.get("id") != args["entry_id"]]
        self._team_audit(data, actor, "🗑 Abwesenheit gelöscht")
        td.save(g.id, data)
        return await self._rpc_team_absences({"guild_id": g.id}, actor)

    @rpc("team.events.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_events(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        items = []
        for e in data.get("events") or []:
            # "date"/"time"/"end_date" sind die strukturierten Felder der
            # Web-Oberfläche (ISO, damit sich ein Kalender daraus bauen lässt).
            # Ältere Einträge haben nur den Freitext "when" — der bleibt als
            # Anzeigetext erhalten, date ist dann leer.
            items.append({
                "id": e.get("id"),
                "title": e.get("title") or "",
                "date": e.get("date") or "",
                "time": e.get("time") or "",
                "end_date": e.get("end_date") or "",
                "when": e.get("when") or "",
                "note": e.get("note") or "",
                "author": self._team_person(g, e["author_id"]) if e.get("author_id") else None,
            })
        # Nach echtem Datum sortieren; Einträge ohne Datum ans Ende.
        items.sort(key=lambda x: (x["date"] == "", x["date"], x["time"]))
        return {"guild_id": str(g.id), "items": items}

    @rpc("team.events.add",
         {"guild_id": ("id", False), "title": ("str", True), "date": ("str", True),
          "time": ("str", False), "end_date": ("str", False), "note": ("text", False)},
         writes=True, scope="team")
    async def _rpc_team_events_add(self, args, actor):
        g = self._resolve_team_guild(args)
        title = (args["title"] or "").strip()
        if not title:
            raise _Denied("Titel leer", 400)
        date = (args["date"] or "").strip()
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            raise _Denied("Datum muss JJJJ-MM-TT sein", 400)
        time_s = (args.get("time") or "").strip()
        if time_s and not re.match(r"^\d{2}:\d{2}$", time_s):
            raise _Denied("Uhrzeit muss SS:MM sein", 400)
        end = (args.get("end_date") or "").strip()
        if end and not re.match(r"^\d{4}-\d{2}-\d{2}$", end):
            raise _Denied("Enddatum muss JJJJ-MM-TT sein", 400)
        if end and end < date:
            raise _Denied("Enddatum liegt vor dem Beginn", 400)
        td = self._team_mod()
        data = td.load(g.id)
        # "events" ist neu in diesem Datensatz; die Lazy-Migration des Cogs
        # arbeitet mit setdefault und lässt unbekannte Schlüssel unangetastet.
        data.setdefault("events", []).append({
            "id": td._new_id(), "title": title[:120],
            "date": date, "time": time_s, "end_date": end,
            # "when" bleibt als lesbarer Text für /team in Discord.
            "when": f"{date}{' ' + time_s if time_s else ''}",
            "note": (args.get("note") or "")[:500], "author_id": actor,
        })
        self._team_audit(data, actor, "📅 Termin eingetragen", f"{title} ({date})")
        td.save(g.id, data)
        return await self._rpc_team_events({"guild_id": g.id}, actor)

    @rpc("team.events.remove",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         writes=True, scope="team")
    async def _rpc_team_events_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        data["events"] = [e for e in (data.get("events") or []) if e.get("id") != args["entry_id"]]
        self._team_audit(data, actor, "🗑 Termin entfernt")
        td.save(g.id, data)
        return await self._rpc_team_events({"guild_id": g.id}, actor)

    # --- Schreibende Team-Verwaltung (Gegenstück zu /team in Discord) -------
    # Alle folgenden Kommandos rufen die FUNKTIONEN DES COGS auf
    # (do_team_add / do_team_remove / do_team_warn / do_team_unwarn), nicht
    # eigene Logik. Dadurch passiert im Panel exakt dasselbe wie im Discord-
    # Menü: Direktnachricht an die betroffene Person, Eintrag im Team-Log und
    # die Regel "3 Verwarnungen = Entfernung aus dem Team". Zwei Umsetzungen
    # derselben Regel würden sonst früher oder später auseinanderlaufen.
    #
    # Rechte: writes=True im team-Scope heißt Verwaltung — Server-Owner,
    # Discord-Administrator oder ausdrücklich freigeschaltet
    # (data["verwaltung_access"]). Genau die Rechte also, die auch /team verlangt.

    @rpc("team.members.search",
         {"guild_id": ("id", False), "q": ("str", False)}, scope="team")
    async def _rpc_team_member_search(self, args, actor):
        """Mitglieder des Team-Servers suchen (für die Auswahl beim Aufnehmen)."""
        g = self._resolve_team_guild(args)
        q = (args.get("q") or "").strip().lower()
        td = self._team_mod()
        in_team = {int(x) for x in (td.load(g.id).get("members") or [])}
        out = []
        for m in g.members:
            if m.bot:
                continue
            if q and q not in m.display_name.lower() and q not in m.name.lower() and q != str(m.id):
                continue
            out.append({
                "id": str(m.id), "name": m.display_name,
                "avatar": m.display_avatar.url, "left": False,
                "in_team": m.id in in_team,
            })
            if len(out) >= 25:
                break
        out.sort(key=lambda x: x["name"].lower())
        return {"items": out, "total": len(out)}

    @rpc("team.roles.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_roles(self, args, actor):
        """Rollen des Team-Servers (zum Aufnehmen ganzer Rollen)."""
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        sync = {int(x) for x in (td.load(g.id).get("sync_roles") or [])}
        roles = [r for r in g.roles if not r.is_default() and not r.managed]
        roles.sort(key=lambda r: r.position, reverse=True)
        return {"items": [{"id": str(r.id), "name": r.name,
                           "members": len(r.members), "sync": r.id in sync}
                          for r in roles[:100]]}

    @rpc("team.members.add",
         {"guild_id": ("id", False), "user_id": ("id", False), "role_id": ("id", False)},
         writes=True, scope="team")
    async def _rpc_team_member_add(self, args, actor):
        """Mitglied ODER ganze Rolle ins Team aufnehmen (wie /team in Discord).

        Bei einer Rolle aktiviert der Cog sie zusätzlich als Auto-Sync-Rolle —
        wer sie künftig bekommt, landet von selbst im Team.
        """
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        uid, rid = args.get("user_id"), args.get("role_id")
        if not uid and not rid:
            raise _Denied("user_id oder role_id nötig", 400)
        target = g.get_member(uid) if uid else g.get_role(rid)
        if target is None:
            raise _Denied("Mitglied/Rolle nicht auf dem Server gefunden", 404)
        added = await td.do_team_add(g, target, actor=actor)
        res = await self._rpc_team_members({"guild_id": g.id}, actor)
        res["added"] = int(added)
        return res

    @rpc("team.members.remove",
         {"guild_id": ("id", False), "user_id": ("id", True), "reason": ("text", True)},
         writes=True, scope="team")
    async def _rpc_team_member_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        reason = (args["reason"] or "").strip()
        if not reason:
            raise _Denied("Grund nötig", 400)
        member = g.get_member(args["user_id"])
        if member is None:
            # Nicht mehr auf dem Server: nur austragen, ohne Direktnachricht —
            # der Cog käme an create_dm nicht vorbei. Die Schicht MUSS trotzdem
            # beendet werden, sonst bleibt die Person dauerhaft als "im Dienst"
            # stehen und lässt sich von dort nicht mehr entfernen (sie taucht
            # in der Mitgliederliste ja nicht mehr auf). Protokolliert wird
            # ebenfalls — eine Entfernung darf nirgends unsichtbar passieren.
            data = td.load(g.id)
            if args["user_id"] in (data.get("members") or []):
                data["members"].remove(args["user_id"])
            td._end_shift(data, str(args["user_id"]))
            self._team_audit(data, actor, "➖ Mitglied entfernt",
                             f"<@{args['user_id']}> (nicht mehr auf dem Server) — Grund: {reason[:200]}")
            td.save(g.id, data)
            return await self._rpc_team_members({"guild_id": g.id}, actor)
        await td.do_team_remove(g, member, reason[:400], actor=actor)
        return await self._rpc_team_members({"guild_id": g.id}, actor)

    @staticmethod
    def _plain_discord_text(guild, text):
        """Discord-Text fuer die Weboberflaeche lesbar machen.

        Die Meldungen des Cogs sind fuer Discord geschrieben: <@123>/<@&123>
        werden dort zu Namen aufgeloest, im Browser stuenden sie als Rohtext da.
        Hier also Mentions durch Namen ersetzen und **fett** entfernen.
        """
        def role(mm):
            r = guild.get_role(int(mm.group(1)))
            return f"@{r.name}" if r else "@Rolle"

        def user(mm):
            m = guild.get_member(int(mm.group(1)))
            return f"@{m.display_name}" if m else "@Unbekannt"

        out = re.sub(r"<@&(\d+)>", role, str(text))
        out = re.sub(r"<@!?(\d+)>", user, out)
        return out.replace("**", "")

    @rpc("team.rank.apply",
         {"guild_id": ("id", False), "user_id": ("id", True), "direction": ("int", True),
          "reason": ("text", True)},
         writes=True, scope="team")
    async def _rpc_team_rank_apply(self, args, actor):
        """Uprank (+1) / Downrank (-1) — dieselbe Aktion wie die Knoepfe unter
        /team in Discord: Rang-Rolle tauschen, Team-Log schreiben, Person per
        Direktnachricht informieren. Der Grund ist Pflicht, genau wie im Modal.

        Die Rang-Leiter kommt aus den Auto-Sync-Rollen (Rollen-Position
        niedrig -> hoch); der gemeinsame Kern liegt im Cog (`do_team_rank`),
        damit Panel und Web nie auseinanderlaufen.
        """
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        reason = (args["reason"] or "").strip()
        if not reason:
            raise _Denied("Grund noetig", 400)
        direction = 1 if int(args["direction"]) > 0 else -1
        member = g.get_member(args["user_id"])
        if member is None:
            raise _Denied("Mitglied nicht auf dem Server", 404)
        try:
            title, body, _colour = await td.do_team_rank(g, member, direction,
                                                         reason[:400], actor=actor)
        except td.RankError as e:
            # Fachliche Absagen (kein Rang mehr frei, Bot-Rolle zu niedrig, keine
            # Rang-Rollen hinterlegt) sind Bedienfehler, keine Serverfehler —
            # als 409 mit dem fertigen Text aus dem Cog zurueck.
            raise _Denied(self._plain_discord_text(g, f"{e.title} — {e.text}"), 409)
        res = await self._rpc_team_members({"guild_id": g.id}, actor)
        res["message"] = title
        res["detail"] = self._plain_discord_text(g, body)
        return res

    @rpc("team.warn.add",
         {"guild_id": ("id", False), "user_id": ("id", True), "reason": ("text", True),
          "severity": ("str", False)},
         writes=True, scope="team")
    async def _rpc_team_warn_add(self, args, actor):
        """Verwarnung vergeben — inklusive der 3/3-Regel des Cogs."""
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        reason = (args["reason"] or "").strip()
        if not reason:
            raise _Denied("Grund nötig", 400)
        member = g.get_member(args["user_id"])
        if member is None:
            raise _Denied("Mitglied nicht auf dem Server", 404)
        sev = (args.get("severity") or "mittel").lower()
        if sev not in ("niedrig", "mittel", "hoch"):
            sev = "mittel"
        status, count = await td.do_team_warn(g, member, reason[:400], actor=actor)
        # Grund und Schweregrad zusätzlich festhalten: der Cog speichert nur
        # einen Zähler (0-3), der Grund ging bisher nur per DM raus und war
        # später nirgends mehr nachlesbar.
        data = td.load(g.id)
        wl = data.setdefault("warn_log", [])
        wl.append({
            "id": td._new_id(), "user_id": args["user_id"], "reason": reason[:400],
            "severity": sev, "actor_id": actor, "ts": int(time.time()),
            "removed": status == "removed",
        })
        if len(wl) > 300:
            del wl[:-300]
        td.save(g.id, data)
        res = await self._rpc_team_warnings({"guild_id": g.id}, actor)
        res["status"] = status           # "warned" oder "removed" (bei 3/3)
        res["count"] = count
        return res

    @rpc("team.warn.remove",
         {"guild_id": ("id", False), "user_id": ("id", True)},
         writes=True, scope="team")
    async def _rpc_team_warn_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        member = g.get_member(args["user_id"])
        if member is None:
            raise _Denied("Mitglied nicht auf dem Server", 404)
        await td.do_team_unwarn(g, member)
        return await self._rpc_team_warnings({"guild_id": g.id}, actor)

    @rpc("team.activity.start", {"guild_id": ("id", False)}, writes=True, scope="team")
    async def _rpc_team_activity_start(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        td.do_activity_start(g.id, actor)
        return await self._rpc_team_overview({"guild_id": g.id}, actor)

    @rpc("team.activity.stop", {"guild_id": ("id", False)}, writes=True, scope="team")
    async def _rpc_team_activity_stop(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        td.do_activity_stop(g.id)
        return await self._rpc_team_overview({"guild_id": g.id}, actor)

    # --- Protokoll, Chat, Profile ------------------------------------------

    @rpc("team.audit.list", {"guild_id": ("id", False), "limit": ("int", False)}, scope="team")
    async def _rpc_team_audit(self, args, actor):
        """Protokoll der Team-Änderungen.

        Gespeist aus `_log_event` im Cog — deshalb steht hier auch das drin, was
        direkt in Discord über /team gemacht wurde, nicht nur die Aktionen aus
        dem Panel.
        """
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        limit = max(1, min(int(args.get("limit") or 100), 300))
        items = list(data.get("audit") or [])[-limit:]
        items.reverse()

        # Erwähnungen zu Namen auflösen — im Protokoll stand sonst die rohe
        # ID (`<@123456789012345678>`), was niemand lesen kann. Namen werden
        # einmal pro Anfrage nachgeschlagen und dann wiederverwendet.
        namen = {}

        def _name(m):
            uid = m.group(1)
            if uid not in namen:
                mem = g.get_member(int(uid))
                namen[uid] = mem.display_name if mem else f"Unbekannt ({uid})"
            return "@" + namen[uid]

        out = []
        for a in items:
            out.append({**a, "text": re.sub(r"<@!?(\d{15,20})>", _name, a.get("text") or "")})
        return {"guild_id": str(g.id), "items": out, "total": len(data.get("audit") or [])}

    @rpc("team.audit.clear", {"guild_id": ("id", False)}, writes=True, scope="team")
    async def _rpc_team_audit_clear(self, args, actor):
        """Protokoll leeren (nur Verwaltung)."""
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        n = len(data.get("audit") or [])
        data["audit"] = []
        self._team_audit(data, actor, "🧹 Protokoll geleert", f"{n} Einträge entfernt")
        td.save(g.id, data)
        return await self._rpc_team_audit({"guild_id": g.id}, actor)

    @rpc("team.login.record", {"guild_id": ("id", False), "logout": ("bool", False)}, scope="self")
    async def _rpc_team_login_record(self, args, actor):
        """Hält eine Anmeldung am Web-Panel im Team-Protokoll fest.

        Wird vom Web nach erfolgreichem Discord-Login aufgerufen. scope="self",
        weil zu diesem Zeitpunkt noch niemand geprüft hat, ob der Actor
        überhaupt zum Team gehört — das passiert hier: gehört er nicht dazu,
        wird nichts geschrieben (er sieht das Panel ohnehin nicht).

        Mehrfach-Einträge werden unterdrückt: meldet sich jemand innerhalb von
        10 Minuten erneut an (Seite neu geöffnet, Token erneuert), entsteht
        kein zweiter Eintrag.
        """
        gid = args.get("guild_id") or self._team_guild_id()
        if not gid:
            return {"logged": False, "reason": "kein Team-Server eingerichtet"}
        g = self.bot.get_guild(int(gid))
        if g is None:
            return {"logged": False, "reason": "Team-Server unbekannt"}
        if await self._team_role(g, actor) is None:
            return {"logged": False, "reason": "kein Team-Mitglied"}

        td = self._team_mod()
        data = td.load(g.id)
        now = int(time.time())
        event = "🔓 Am Panel abgemeldet" if args.get("logout") else "🔑 Am Panel angemeldet"
        marke = f"<@{actor}>"
        # Gegen GENAU dieses Ereignis entdoppeln: sonst würde eine Abmeldung
        # gegen frühere Anmeldungen geprüft und stillschweigend verschluckt.
        for a in reversed(data.get("audit") or []):
            if now - int(a.get("ts") or 0) > 600:
                break
            if a.get("title") == event and marke in (a.get("text") or ""):
                return {"logged": False, "reason": "kürzlich schon erfasst"}

        self._team_audit(data, actor, event)
        td.save(g.id, data)
        return {"logged": True}

    # --- Team-Chat ---------------------------------------------------------
    @rpc("team.chat.list", {"guild_id": ("id", False), "after": ("str", False)}, scope="team")
    async def _rpc_team_chat_list(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        msgs = list(data.get("chat") or [])
        after = (args.get("after") or "").strip()
        if after:
            # Nur das Neue nachliefern (die Oberfläche fragt regelmäßig nach).
            ids = [m.get("id") for m in msgs]
            if after in ids:
                msgs = msgs[ids.index(after) + 1:]
        out = []
        for m in msgs[-200:]:
            out.append({
                "id": m.get("id"),
                "text": m.get("text") or "",
                "ts": int(m.get("ts") or 0),
                "author": self._team_person(g, m["user_id"]) if m.get("user_id") else None,
                "mine": str(m.get("user_id")) == str(actor),
                "mentions": [self._team_person(g, x) for x in (m.get("mentions") or [])[:10]],
            })
        return {"guild_id": str(g.id), "items": out}

    @rpc("team.chat.post", {"guild_id": ("id", False), "text": ("text", True)}, scope="team")
    async def _rpc_team_chat_post(self, args, actor):
        """Nachricht schreiben — darf JEDES Team-Mitglied (deshalb ohne
        writes=True, das würde Verwaltungsrechte verlangen)."""
        g = self._resolve_team_guild(args)
        text = (args["text"] or "").strip()
        if not text:
            raise _Denied("Nachricht leer", 400)
        td = self._team_mod()
        data = td.load(g.id)
        chat = data.setdefault("chat", [])
        chat.append({
            "id": td._new_id(), "user_id": actor, "ts": int(time.time()),
            "text": text[:1000],
            # Erwähnungen als IDs mitspeichern, damit die Oberfläche sie
            # hervorheben kann, ohne den Text erneut zu zerlegen.
            "mentions": [int(x) for x in re.findall(r"<@!?(\d{15,20})>", text)][:10],
        })
        if len(chat) > 400:
            del chat[:-400]
        td.save(g.id, data)
        return await self._rpc_team_chat_list({"guild_id": g.id}, actor)

    @rpc("team.chat.delete",
         {"guild_id": ("id", False), "entry_id": ("str", True)}, scope="team")
    async def _rpc_team_chat_delete(self, args, actor):
        """Löschen darf man die EIGENE Nachricht; die Verwaltung jede."""
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        role = await self._team_role(g, actor)
        chat = data.get("chat") or []
        for m in chat:
            if m.get("id") == args["entry_id"]:
                if str(m.get("user_id")) != str(actor) and role != "manage" and actor not in ACTORS:
                    raise _Denied("Nur eigene Nachrichten löschbar", 403)
                chat.remove(m)
                break
        else:
            raise _Denied("Nachricht nicht gefunden", 404)
        td.save(g.id, data)
        return await self._rpc_team_chat_list({"guild_id": g.id}, actor)

    # --- Eigenes Profil ----------------------------------------------------
    @rpc("team.profile.get", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_profile_get(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        prof = (td.load(g.id).get("profiles") or {}).get(str(actor)) or {}
        return {
            "status": prof.get("status") or "",
            "accent": prof.get("accent") or "",
            "person": self._team_person(g, actor),
        }

    @rpc("team.profile.set",
         {"guild_id": ("id", False), "status": ("str", False), "accent": ("str", False)},
         scope="team")
    async def _rpc_team_profile_set(self, args, actor):
        """Eigenes Profil — jedes Team-Mitglied für sich, daher ohne writes."""
        g = self._resolve_team_guild(args)
        accent = (args.get("accent") or "").strip()
        if accent and not re.match(r"^#[0-9a-fA-F]{6}$", accent):
            raise _Denied("Farbe muss #RRGGBB sein", 400)
        td = self._team_mod()
        data = td.load(g.id)
        profs = data.setdefault("profiles", {})
        profs[str(actor)] = {
            "status": (args.get("status") or "").strip()[:80],
            "accent": accent,
        }
        td.save(g.id, data)
        return await self._rpc_team_profile_get({"guild_id": g.id}, actor)

    # --- Notizen ---------------------------------------------------------
    @rpc("team.notes.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_notes(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        items = [{
            "id": n.get("id"),
            "text": n.get("text") or "",
            "pinned": bool(n.get("pinned")),
            "ts": int(n.get("ts") or 0),
            "author": self._team_person(g, n["author_id"]) if n.get("author_id") else None,
        } for n in (data.get("notes") or [])]
        # Angeheftete zuerst, danach das Neueste.
        items.sort(key=lambda x: (not x["pinned"], -x["ts"]))
        return {"guild_id": str(g.id), "items": items}

    @rpc("team.notes.add",
         {"guild_id": ("id", False), "text": ("text", True), "pinned": ("bool", False)},
         writes=True, scope="team")
    async def _rpc_team_notes_add(self, args, actor):
        g = self._resolve_team_guild(args)
        text = (args["text"] or "").strip()
        if not text:
            raise _Denied("Text leer", 400)
        td = self._team_mod()
        data = td.load(g.id)
        data.setdefault("notes", []).append({
            "id": td._new_id(), "text": text[:2000],
            "pinned": bool(args.get("pinned")), "ts": int(time.time()), "author_id": actor,
        })
        self._team_audit(data, actor, "📝 Notiz angelegt", text[:80])
        td.save(g.id, data)
        return await self._rpc_team_notes({"guild_id": g.id}, actor)

    @rpc("team.notes.remove",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         writes=True, scope="team")
    async def _rpc_team_notes_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        data["notes"] = [n for n in (data.get("notes") or []) if n.get("id") != args["entry_id"]]
        self._team_audit(data, actor, "🗑 Notiz gelöscht")
        td.save(g.id, data)
        return await self._rpc_team_notes({"guild_id": g.id}, actor)

    # --- Ressourcen (Link-Sammlung) --------------------------------------
    @rpc("team.resources.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_resources(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        items = [{
            "id": r.get("id"),
            "title": r.get("title") or "",
            "url": r.get("url") or "",
            "author": self._team_person(g, r["author_id"]) if r.get("author_id") else None,
        } for r in (data.get("resources") or [])]
        return {"guild_id": str(g.id), "items": items}

    @rpc("team.resources.add",
         {"guild_id": ("id", False), "title": ("str", True), "url": ("str", True)},
         writes=True, scope="team")
    async def _rpc_team_resources_add(self, args, actor):
        g = self._resolve_team_guild(args)
        url = (args["url"] or "").strip()
        # NUR http/https. Ohne diese Prüfung könnte jemand `javascript:...`
        # eintragen, das bei einem Klick im Browser des nächsten Team-Mitglieds
        # ausgeführt würde — genau dieser Fehler steckt im alten Team-Dashboard
        # (Befund 3 des Audits vom 24.08.2026).
        if not re.match(r"^https?://[^\s<>\"']{3,500}$", url, re.I):
            raise _Denied("Nur http(s)-Adressen erlaubt", 400)
        title = (args["title"] or "").strip()
        if not title:
            raise _Denied("Titel leer", 400)
        td = self._team_mod()
        data = td.load(g.id)
        data.setdefault("resources", []).append({
            "id": td._new_id(), "title": title[:120], "url": url, "author_id": actor,
        })
        self._team_audit(data, actor, "🔗 Ressource hinzugefügt", title[:80])
        td.save(g.id, data)
        return await self._rpc_team_resources({"guild_id": g.id}, actor)

    @rpc("team.resources.remove",
         {"guild_id": ("id", False), "entry_id": ("str", True)},
         writes=True, scope="team")
    async def _rpc_team_resources_remove(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        data["resources"] = [r for r in (data.get("resources") or [])
                             if r.get("id") != args["entry_id"]]
        self._team_audit(data, actor, "🗑 Ressource entfernt")
        td.save(g.id, data)
        return await self._rpc_team_resources({"guild_id": g.id}, actor)

    # --- Verwarnungen (Zähler des Team-Systems, 3 = Entfernung) ----------
    @rpc("team.warnings.list", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_warnings(self, args, actor):
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        data = td.load(g.id)
        warns = data.get("warns", {}) or {}
        # Verlauf pro Person: Grund, Schweregrad, wer und wann.
        hist = {}
        for w in (data.get("warn_log") or []):
            hist.setdefault(str(w.get("user_id")), []).append({
                "id": w.get("id"),
                "reason": w.get("reason") or "",
                "severity": w.get("severity") or "mittel",
                "ts": int(w.get("ts") or 0),
                "by": self._team_person(g, w["actor_id"]) if w.get("actor_id") else None,
                "removed": bool(w.get("removed")),
            })
        items = []
        for uid, v in warns.items():
            n = self._warn_count(v)
            if n <= 0:
                continue
            items.append({
                **self._team_person(g, uid),
                "count": n, "limit": 3,
                "history": sorted(hist.get(str(uid), []), key=lambda x: -x["ts"])[:10],
            })
        items.sort(key=lambda x: -x["count"])
        # Menschen, die bereits entfernt wurden, tauchen im Zähler nicht mehr
        # auf — ihr Verlauf bleibt aber als Vorgeschichte erhalten.
        past = []
        for uid, entries in hist.items():
            if uid in {str(k) for k in warns} or not any(e["removed"] for e in entries):
                continue
            past.append({
                **self._team_person(g, uid),
                "count": 0, "limit": 3,
                "history": sorted(entries, key=lambda x: -x["ts"])[:10],
            })
        return {"guild_id": str(g.id), "items": items, "past": past, "limit": 3}

    @rpc("team.shift.toggle", {"guild_id": ("id", False)}, scope="team")
    async def _rpc_team_shift_toggle(self, args, actor):
        """An-/Abmelden vom Dienst — darf JEDES Team-Mitglied für sich selbst.

        Deshalb bewusst ohne writes=True: writes würde im team-Scope Verwaltungs-
        rechte verlangen, und ein Supporter muss seinen eigenen Dienst starten
        können. Geändert wird ausschließlich der eigene Eintrag.
        """
        g = self._resolve_team_guild(args)
        td = self._team_mod()
        # _load_rolled statt load: bei Tageswechsel werden die Tages-Summen
        # zurückgesetzt, bevor gerechnet wird. Sonst bucht eine Abmeldung am
        # nächsten Morgen die ganze Nacht auf "heute" — und der nächste
        # Aufruf des Discord-Panels wirft diese Summe stillschweigend weg.
        data = td._load_rolled(g.id)
        shifts = data.setdefault("shifts", {"on_duty": {}, "totals": {}, "day": ""})
        on_duty = shifts.setdefault("on_duty", {})
        totals = shifts.setdefault("totals", {})
        key = str(actor)
        now = int(time.time())
        if key in on_duty:
            started = int(on_duty.pop(key) or now)
            totals[key] = int(totals.get(key, 0) or 0) + max(0, now - started)
        else:
            on_duty[key] = now
        td.save(g.id, data)
        return await self._rpc_team_me({"guild_id": g.id}, actor)

    # -- Team-Liste ---------------------------------------------------------------

    @rpc("teamlist.status", {"guild_id": ("id", True)})
    async def _rpc_teamlist_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.mod_teamlist as tl
        data = tl.load_data().get(str(gid), {})
        ch = g.get_channel(data.get("channel")) if data.get("channel") else None
        role_ids = data.get("roles") or []
        roles = [{"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                 for rid in role_ids]
        return {
            "guild_id": str(gid),
            "channel": {"id": str(data["channel"]), "name": ch.name if ch else None} if data.get("channel") else None,
            "roles": roles,
        }

    @rpc("teamlist.set",
         {"guild_id": ("id", True), "channel_id": ("id", True), "role_ids": ("id_list", True)}, writes=True)
    async def _rpc_teamlist_set(self, args, actor):
        gid, cid, role_ids = args["guild_id"], args["channel_id"], args["role_ids"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        channel = g.get_channel(cid)
        if channel is None:
            raise _Denied("Kanal unbekannt", 404)
        import cogs.mod_teamlist as tl
        import hashlib
        data = tl.load_data()
        gid_s = str(gid)
        old = data.get(gid_s, {})
        old_channel = g.get_channel(old.get("channel")) if old.get("channel") else None
        old_message_ids = tl._message_ids(old)

        if not g.chunked:
            await g.chunk()
        team_text = tl.build_team_text(g, role_ids)
        views = tl.create_team_views(g, role_ids)
        try:
            messages = []
            for view in views:
                msg = await channel.send(view=view)
                messages.append(msg.id)
        except discord.Forbidden:
            raise _Denied("Keine Berechtigung, in diesem Kanal zu posten", 403)

        if old_channel is not None:
            for mid in old_message_ids:
                try:
                    m = await old_channel.fetch_message(int(mid))
                    await m.delete()
                except (discord.NotFound, discord.Forbidden, discord.HTTPException, ValueError):
                    pass

        data[gid_s] = {
            "channel": cid, "messages": messages, "roles": list(role_ids),
            "_hash": hashlib.md5(team_text.encode("utf-8")).hexdigest(),
        }
        tl.save_data(data)
        log.info("webapi: Teamliste gesetzt Guild %s Kanal %s (%d Rollen) durch %s", gid, cid, len(role_ids), actor)
        return {"guild_id": gid_s, "channel_id": str(cid), "roles": len(role_ids), "messages": len(messages)}

    # -- Tickets: Support-Rollen / SLA / Bereiche -------------------------------

    @rpc("tickets.config.get", {"guild_id": ("id", True)})
    async def _rpc_tickets_config_get(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)
        support_roles = [{"id": str(rid), "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                         for rid in (d.get("support_roles") or [])]
        panels = []
        for pid, p in (d.get("panels") or {}).items():
            log_ch = g.get_channel(p.get("log_channel")) if p.get("log_channel") else None
            sla = p.get("sla") or {}
            sla_role = g.get_role(sla.get("role")) if sla.get("role") else None
            post_ch = g.get_channel(p.get("channel")) if p.get("channel") else None
            panels.append({
                "pid": pid, "name": p.get("name", "Support"),
                "reasons": list(p.get("reasons") or []),
                "titel": p.get("panel_title") or "",
                "nachricht": p.get("panel_text") or "",
                "post_channel": {"id": str(post_ch.id), "name": post_ch.name} if post_ch else None,
                "log_channel": {"id": str(p["log_channel"]), "name": log_ch.name if log_ch else None}
                               if p.get("log_channel") else None,
                "sla": {
                    "minutes": sla.get("minutes"),
                    "role": {"id": str(sla["role"]), "name": sla_role.name if sla_role else None}
                            if sla.get("role") else None,
                },
            })
        return {"guild_id": str(gid), "support_roles": support_roles, "panels": panels}

    @rpc("tickets.support_roles.add", {"guild_id": ("id", True), "role_id": ("id", True)}, writes=True)
    async def _rpc_tickets_support_roles_add(self, args, actor):
        gid, rid = args["guild_id"], args["role_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        if g.get_role(rid) is None:
            raise _Denied("Rolle unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)
        if rid not in d["support_roles"]:
            d["support_roles"].append(rid)
            ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Support-Rolle +%s Guild %s durch %s", rid, gid, actor)
        return {"guild_id": str(gid), "role_id": str(rid)}

    @rpc("tickets.support_roles.remove", {"guild_id": ("id", True), "role_id": ("id", True)}, writes=True)
    async def _rpc_tickets_support_roles_remove(self, args, actor):
        gid, rid = args["guild_id"], args["role_id"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)
        if rid in d["support_roles"]:
            d["support_roles"].remove(rid)
            ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Support-Rolle -%s Guild %s durch %s", rid, gid, actor)
        return {"guild_id": str(gid), "role_id": str(rid)}

    @rpc("tickets.panel.set_log_channel",
         {"guild_id": ("id", True), "pid": ("str", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_tickets_set_log_channel(self, args, actor):
        gid, pid, cid = args["guild_id"], args["pid"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt", 404)
        import cogs.ticketsystem as ts
        p = ts.gpanel(gid, pid)
        p["log_channel"] = cid
        ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Log-Kanal Guild %s Panel %s -> %s durch %s", gid, pid, cid, actor)
        return {"guild_id": str(gid), "pid": pid, "channel_id": str(cid), "name": ch.name}

    @rpc("tickets.panel.set_sla",
         {"guild_id": ("id", True), "pid": ("str", True), "minutes": ("int", False, True),
          "role_id": ("id", False, True)},
         writes=True)
    async def _rpc_tickets_set_sla(self, args, actor):
        gid, pid = args["guild_id"], args["pid"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        p = ts.gpanel(gid, pid)
        sla = p.setdefault("sla", {"minutes": None, "role": None})
        if "minutes" in args:
            m = args["minutes"]
            if m is not None and not (1 <= m <= 100000):
                raise _Denied("Minuten außerhalb des gültigen Bereichs", 400)
            sla["minutes"] = m
        if "role_id" in args:
            rid = args["role_id"]
            if rid is not None and g.get_role(rid) is None:
                raise _Denied("Rolle unbekannt", 404)
            sla["role"] = rid
        ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-SLA Guild %s Panel %s durch %s", gid, pid, actor)
        return {"guild_id": str(gid), "pid": pid, "minutes": sla.get("minutes"),
                "role_id": str(sla["role"]) if sla.get("role") else None}

    @rpc("tickets.panel.reason.add", {"guild_id": ("id", True), "pid": ("str", True), "reason": ("str", True)},
         writes=True)
    async def _rpc_tickets_reason_add(self, args, actor):
        gid, pid, reason = args["guild_id"], args["pid"], args["reason"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        p = ts.gpanel(gid, pid)
        reason = reason.strip()[:100]
        if not reason:
            raise _Denied("Bereich darf nicht leer sein", 400)
        if reason in p["reasons"]:
            raise _Denied("Bereich existiert bereits", 400)
        if len(p["reasons"]) >= 20:
            raise _Denied("Maximal 20 Bereiche pro Panel", 400)
        p["reasons"].append(reason)
        ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Bereich %r zu Panel %s Guild %s durch %s", reason, pid, gid, actor)
        return {"guild_id": str(gid), "pid": pid, "reasons": p["reasons"]}

    @rpc("tickets.panel.reason.remove", {"guild_id": ("id", True), "pid": ("str", True), "reason": ("str", True)},
         writes=True)
    async def _rpc_tickets_reason_remove(self, args, actor):
        gid, pid, reason = args["guild_id"], args["pid"], args["reason"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        p = ts.gpanel(gid, pid)
        if reason in p["reasons"]:
            p["reasons"].remove(reason)
            ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Bereich %r von Panel %s Guild %s entfernt durch %s", reason, pid, gid, actor)
        return {"guild_id": str(gid), "pid": pid, "reasons": p["reasons"]}

    @rpc("tickets.panel.set_message",
         {"guild_id": ("id", True), "pid": ("str", True), "titel": ("str", True), "nachricht": ("text", True)},
         writes=True)
    async def _rpc_tickets_set_message(self, args, actor):
        gid, pid = args["guild_id"], args["pid"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        titel = args["titel"].strip()[:100]
        nachricht = args["nachricht"].strip()[:2000]
        if not titel or not nachricht:
            raise _Denied("Titel und Nachricht dürfen nicht leer sein", 400)
        import cogs.ticketsystem as ts
        p = ts.gpanel(gid, pid)
        p["panel_title"] = titel
        p["panel_text"] = nachricht
        ts.save_data(ts.ticket_data)
        log.info("webapi: Ticket-Panel-Text Guild %s Panel %s geändert durch %s", gid, pid, actor)
        return {"guild_id": str(gid), "pid": pid, "titel": titel, "nachricht": nachricht}

    @rpc("tickets.panel.post", {"guild_id": ("id", True), "pid": ("str", True), "channel_id": ("id", True)},
         writes=True)
    async def _rpc_tickets_post(self, args, actor):
        """Postet das Ticket-Panel direkt aus dem Dashboard -- bisher ging das
        nur über /ticket setup in Discord. Postet immer NEU (kein In-Place-Edit
        wie im Discord-Setup-Assistenten) -- einfacher, aber ein erneutes Posten
        legt ein zusätzliches Panel an, bis das alte manuell gelöscht wird."""
        gid, pid, cid = args["guild_id"], args["pid"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        ch = g.get_channel(cid)
        if ch is None:
            raise _Denied("Kanal unbekannt", 404)
        import cogs.ticketsystem as ts
        import panels
        p = ts.gpanel(gid, pid)
        if not p.get("reasons"):
            raise _Denied("Panel braucht mindestens einen Bereich", 400)
        cleaned_limits = {r: v for r, v in (p.get("limits") or {}).items() if r in p["reasons"] and v}
        view = ts.TicketPanel(
            gid, titel=p.get("panel_title") or "Support-Tickets",
            nachricht=p.get("panel_text") or "Wähle unten einen Bereich, um ein Ticket zu öffnen.",
            reasons=p["reasons"], pid=pid, limits=cleaned_limits, bild=p.get("image"),
        )
        try:
            msg = await ch.send(view=view, files=[view.image_file] if view.image_file else [])
        except discord.Forbidden:
            raise _Denied("Keine Berechtigung, in diesem Kanal zu posten", 403)
        d = ts.gdata(gid)
        for mid in [m for m, mp in list(d["panel_msgs"].items()) if mp == pid]:
            d["panel_msgs"].pop(mid, None)
        d["panel_msgs"][str(msg.id)] = pid
        p["channel"] = cid
        ts.save_data(ts.ticket_data)
        if pid == "default":
            panels.register("ticket", gid, cid, msg.id)
        log.info("webapi: Ticket-Panel gepostet Guild %s Panel %s Kanal %s durch %s", gid, pid, cid, actor)
        return {"guild_id": str(gid), "pid": pid, "channel_id": str(cid), "message_id": str(msg.id)}

    # -- Einladungs-Tracker -------------------------------------------------------

    @rpc("invites.status", {"guild_id": ("id", True)})
    async def _rpc_invites_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.invitetracker as it
        conf = it._conf(gid)
        ch = g.get_channel(conf.get("log")) if conf.get("log") else None
        return {
            "guild_id": str(gid),
            "enabled": bool(conf.get("enabled", True)),
            "fake_days": int(conf.get("fake_days", it.FAKE_DAYS_DEFAULT)),
            "log_channel": {"id": str(conf["log"]), "name": ch.name if ch else None} if conf.get("log") else None,
        }

    @rpc("invites.set_log_channel", {"guild_id": ("id", True), "channel_id": ("id", False, True)}, writes=True)
    async def _rpc_invites_set_log_channel(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.invitetracker as it
        conf = it._conf(gid)
        cid = args.get("channel_id")
        if cid is not None and g.get_channel(cid) is None:
            raise _Denied("Kanal unbekannt", 404)
        conf["log"] = cid
        it._save_conf(gid, conf)
        log.info("webapi: Invite-Log-Kanal Guild %s -> %s durch %s", gid, cid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid) if cid else None}

    @rpc("invites.set_fake_days", {"guild_id": ("id", True), "days": ("int", True)}, writes=True)
    async def _rpc_invites_set_fake_days(self, args, actor):
        gid, days = args["guild_id"], args["days"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        if days not in (0, 1, 3, 7, 14, 30):
            raise _Denied("Ungültiger Wert (0/1/3/7/14/30)", 400)
        import cogs.invitetracker as it
        conf = it._conf(gid)
        conf["fake_days"] = days
        it._save_conf(gid, conf)
        log.info("webapi: Invite-Fake-Days Guild %s -> %s durch %s", gid, days, actor)
        return {"guild_id": str(gid), "fake_days": days}

    @rpc("invites.toggle", {"guild_id": ("id", True), "enabled": ("bool", True)}, writes=True)
    async def _rpc_invites_toggle(self, args, actor):
        gid, enabled = args["guild_id"], args["enabled"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.invitetracker as it
        conf = it._conf(gid)
        conf["enabled"] = enabled
        it._save_conf(gid, conf)
        log.info("webapi: Invite-Tracking Guild %s -> %s durch %s", gid, enabled, actor)
        return {"guild_id": str(gid), "enabled": enabled}

    @rpc("invites.leaderboard", {"guild_id": ("id", True)})
    async def _rpc_invites_leaderboard(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.invitetracker as it
        rows = it._leaderboard(gid)[:25]
        out = []
        for uid, counts, valid in rows:
            member = g.get_member(int(uid)) if str(uid).isdigit() else None
            out.append({
                "user_id": str(uid), "name": member.display_name if member else None,
                "valid": valid, "joins": counts["joins"], "left": counts["left"],
                "fake": counts["fake"], "bonus": counts["bonus"],
            })
        return {"guild_id": str(gid), "leaderboard": out}

    # -- Musik, Roleplay, Global-Chat, Partnerschaft (Welle 2) ----------------

    @rpc("music.status", {"guild_id": ("id", True)})
    async def _rpc_music_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        cog = self.bot.get_cog("Music")
        if cog is None:
            raise _Denied("Musik-Modul nicht geladen", 404)
        c = cog._gconf(gid)
        dj = g.get_role(c["dj_role"]) if c["dj_role"] else None
        ch = g.get_channel(c["music_channel"]) if c["music_channel"] else None
        return {
            "guild_id": str(gid),
            "dj_role": {"id": str(dj.id), "name": dj.name} if dj else None,
            "volume_pct": int(c["volume_pct"]),
            "twentyfourseven": bool(c["twentyfourseven"]),
            "music_channel": {"id": str(ch.id), "name": ch.name} if ch else None,
        }

    @rpc("music.set",
         {"guild_id": ("id", True), "dj_role_id": ("id", False, True),
          "volume_pct": ("int", False), "twentyfourseven": ("bool", False),
          "music_channel_id": ("id", False, True)},
         writes=True)
    async def _rpc_music_set(self, args, actor):
        # Konfig liegt (anders als bei den meisten anderen Modulen) im RAM der
        # Cog-Instanz (cog.config), nicht frisch aus der DB gelesen -- deshalb
        # MUSS über den Cog gegangen werden, ein direktes storage.save_doc hier
        # würde vom laufenden Musik-Player erst nach einem Neustart gesehen.
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        # Kanal- und Rollen-ID müssen zu DIESER Guild gehören (nullable: None löscht).
        if args.get("music_channel_id") is not None and g.get_channel(args["music_channel_id"]) is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        if args.get("dj_role_id") is not None and g.get_role(args["dj_role_id"]) is None:
            raise _Denied("Rolle unbekannt (nicht auf dieser Guild)", 404)
        cog = self.bot.get_cog("Music")
        if cog is None:
            raise _Denied("Musik-Modul nicht geladen", 404)
        c = cog._gconf(gid)
        if "dj_role_id" in args:
            c["dj_role"] = args["dj_role_id"]
        if "volume_pct" in args:
            v = args["volume_pct"]
            if not (0 <= v <= 200):
                raise _Denied("volume_pct muss 0–200 sein", 400)
            c["volume_pct"] = v
        if "twentyfourseven" in args:
            c["twentyfourseven"] = args["twentyfourseven"]
        if "music_channel_id" in args:
            c["music_channel"] = args["music_channel_id"]
        cog._save()
        return await self._rpc_music_status({"guild_id": gid}, actor)

    @rpc("roleplay.status", {"guild_id": ("id", True)})
    async def _rpc_roleplay_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        cog = self.bot.get_cog("Roleplay")
        if cog is None:
            raise _Denied("Roleplay-Modul nicht geladen", 404)
        conf = cog.data.get(str(gid), {})
        ch = g.get_channel(conf.get("channel_id")) if conf.get("channel_id") else None
        roles = []
        for rid in conf.get("allowed_roles", []):
            r = g.get_role(rid)
            roles.append({"id": str(rid), "name": r.name if r else None})
        users = []
        for uid in conf.get("allowed_users", []):
            m = g.get_member(uid)
            users.append({"id": str(uid), "name": m.display_name if m else None})
        return {
            "guild_id": str(gid),
            "server_name": conf.get("server_name") or "",
            "server_code": conf.get("server_code") or "",
            "server_description": conf.get("server_description") or "",
            "channel": {"id": str(ch.id), "name": ch.name} if ch else None,
            "allowed_roles": roles,
            "allowed_users": users,
        }

    @rpc("roleplay.set",
         {"guild_id": ("id", True), "server_name": ("str", False), "server_code": ("str", False),
          "server_description": ("str", False), "channel_id": ("id", False)},
         writes=True)
    async def _rpc_roleplay_set(self, args, actor):
        gid = args["guild_id"]
        cog = self.bot.get_cog("Roleplay")
        if cog is None:
            raise _Denied("Roleplay-Modul nicht geladen", 404)
        conf = cog.data.setdefault(str(gid), {})
        if "server_name" in args:
            conf["server_name"] = args["server_name"]
        if "server_code" in args:
            conf["server_code"] = args["server_code"]
        if "server_description" in args:
            if args["server_description"]:
                conf["server_description"] = args["server_description"]
            else:
                conf.pop("server_description", None)
        if "channel_id" in args:
            if conf.get("channel_id") != args["channel_id"]:
                conf.pop("announce_message_id", None)
            conf["channel_id"] = args["channel_id"]
        await cog.save()
        return await self._rpc_roleplay_status({"guild_id": gid}, actor)

    @rpc("roleplay.access.set",
         {"guild_id": ("id", True), "role_ids": ("id_list", False), "user_ids": ("id_list", False)},
         writes=True)
    async def _rpc_roleplay_access_set(self, args, actor):
        """Ersetzt (nicht ergänzt) die komplette Zugriffsliste -- passend zum
        Discord-seitigen MentionableSelect, der die Auswahl auch komplett ersetzt."""
        gid = args["guild_id"]
        cog = self.bot.get_cog("Roleplay")
        if cog is None:
            raise _Denied("Roleplay-Modul nicht geladen", 404)
        conf = cog.data.setdefault(str(gid), {})
        if "role_ids" in args:
            conf["allowed_roles"] = args["role_ids"]
        if "user_ids" in args:
            conf["allowed_users"] = args["user_ids"]
        await cog.save()
        return await self._rpc_roleplay_status({"guild_id": gid}, actor)

    @rpc("globalchat.status", {"guild_id": ("id", True)})
    async def _rpc_globalchat_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        d = storage.load_doc("globalchat", {})
        conf = d.get(str(gid)) or {}
        ch_id = conf.get("channel")
        ch = g.get_channel(ch_id) if ch_id else None
        return {
            "guild_id": str(gid),
            "channel": {"id": str(ch.id), "name": ch.name} if ch else None,
        }

    @rpc("globalchat.set_channel", {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_globalchat_set_channel(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        # Kanal muss zu DIESER Guild gehören (Audit 04.09. Befund 5, neu eingespielt
        # 24.09.): sonst schreibt der Global-Chat per Webhook in einen fremden Server.
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        if g.get_channel(cid) is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        d = storage.load_doc("globalchat", {})
        d.setdefault(str(gid), {})["channel"] = cid
        storage.save_doc("globalchat", d)
        return await self._rpc_globalchat_status({"guild_id": gid}, actor)

    @rpc("partnerschaft.status", {"guild_id": ("id", True)})
    async def _rpc_partnerschaft_status(self, args, actor):
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        ch_id = data.get("channel_id")
        ch = g.get_channel(ch_id) if ch_id else None
        return {
            "guild_id": str(gid),
            "channel": {"id": str(ch.id), "name": ch.name} if ch else None,
            "partners": [{"id": p["id"], "name": p.get("name"), "invite": p.get("invite"),
                          "beschreibung": p.get("beschreibung")} for p in data.get("partners", [])],
            "authorized": [{"id": str(u["id"]), "name": u.get("name")} for u in data.get("authorized", [])],
        }

    @rpc("partnerschaft.set_channel", {"guild_id": ("id", True), "channel_id": ("id", True)}, writes=True)
    async def _rpc_partnerschaft_set_channel(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        if g.get_channel(cid) is None:
            raise _Denied("Kanal unbekannt (nicht auf dieser Guild)", 404)
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        data["channel_id"] = cid
        ps.save(gid, data)
        return await self._rpc_partnerschaft_status({"guild_id": gid}, actor)

    @rpc("partnerschaft.partner.add",
         {"guild_id": ("id", True), "name": ("str", True), "invite": ("str", True),
          "beschreibung": ("str", False)},
         writes=True)
    async def _rpc_partnerschaft_partner_add(self, args, actor):
        gid = args["guild_id"]
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        data["partners"].append({
            "id": ps._new_id(), "name": args["name"], "invite": args["invite"],
            "beschreibung": args.get("beschreibung") or "",
            "added_by": actor, "added_at": int(time.time()),
        })
        ps.save(gid, data)
        return await self._rpc_partnerschaft_status({"guild_id": gid}, actor)

    @rpc("partnerschaft.partner.remove", {"guild_id": ("id", True), "partner_id": ("str", True)}, writes=True)
    async def _rpc_partnerschaft_partner_remove(self, args, actor):
        gid, pid = args["guild_id"], args["partner_id"]
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        data["partners"] = [p for p in data["partners"] if p.get("id") != pid]
        ps.save(gid, data)
        return await self._rpc_partnerschaft_status({"guild_id": gid}, actor)

    @rpc("partnerschaft.authorized.add", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_partnerschaft_authorized_add(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        g = self.bot.get_guild(gid)
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        if not any(u.get("id") == uid for u in data["authorized"]):
            m = g.get_member(uid) if g else None
            data["authorized"].append({"id": uid, "name": m.display_name if m else None})
            ps.save(gid, data)
        return await self._rpc_partnerschaft_status({"guild_id": gid}, actor)

    @rpc("partnerschaft.authorized.remove", {"guild_id": ("id", True), "user_id": ("id", True)}, writes=True)
    async def _rpc_partnerschaft_authorized_remove(self, args, actor):
        gid, uid = args["guild_id"], args["user_id"]
        import cogs.partnerschaft as ps
        data = ps.load(gid)
        data["authorized"] = [u for u in data["authorized"] if u.get("id") != uid]
        ps.save(gid, data)
        return await self._rpc_partnerschaft_status({"guild_id": gid}, actor)


    # -- Ticket-Inbox: der Support-Arbeitsplatz im Web --------------------------
    # Bisher konnte das Dashboard Tickets nur ZÄHLEN (tickets.overview) und
    # KONFIGURIEREN (tickets.config.*). Die folgenden Kommandos machen daraus
    # einen echten zweiten Arbeitsplatz NEBEN Discord: gleiche Tickets, gleiche
    # Daten (cogs/ticketsystem.py -> ticket_data), gleiche Aktionen.
    #
    # Zwei Regeln, die hier alles zusammenhalten:
    #   1. KEINE eigene Ticket-Logik. Jede Aktion ruft dieselben Helfer wie der
    #      Button in Discord (claimed_tickets, _lock_ticket_channel,
    #      build_ticket_view, _execute_ticket_close). Sonst laufen Web und
    #      Discord auseinander, sobald sich das Ticketsystem ändert.
    #   2. Jede Web-Aktion ist im Ticket-KANAL sichtbar (Notiz-Container bzw.
    #      Nachricht) und aktualisiert den Ticket-Container. Im Kanal darf nie
    #      unklar sein, wer etwas getan hat — nur der Weg war ein anderer.

    @staticmethod
    def _ticket_component_text(components):
        """Sammelt den Text aus Components-V2-Nachrichten (Container/TextDisplay).

        Ticket-Container und alle Status-Meldungen des Ticketsystems tragen ihren
        Text NICHT in `content`, sondern in Komponenten — ohne dieses Auslesen
        wäre der Verlauf im Web löchrig (kein Eröffnungs-Container, keine
        Übernahme-/Prioritäts-Meldung), obwohl in Discord alles zu sehen ist.
        """
        out = []

        def walk(items, depth=0):
            if depth > 6:
                return
            for it in items or []:
                txt = getattr(it, "content", None)
                if isinstance(txt, str) and txt.strip():
                    out.append(txt.strip())
                for attr in ("children", "items", "components"):
                    sub = getattr(it, attr, None)
                    if isinstance(sub, (list, tuple)):
                        walk(sub, depth + 1)

        walk(components)
        return "\n".join(out).strip()

    def _ticket_ctx(self, gid, channel_id):
        """Guild, Kanal, ticketsystem-Modul, Guild-Daten und Meta eines Tickets.

        Wirft _Denied, wenn der Kanal in DIESER Guild kein bekanntes Ticket ist —
        damit kann über eine untergeschobene Kanal-ID kein Kommando in einen
        beliebigen anderen Kanal schreiben oder ihn auslesen.
        """
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)
        meta = d["meta"].get(str(channel_id))
        if meta is None:
            raise _Denied("Kanal ist kein Ticket dieser Guild", 404)
        ch = g.get_channel(channel_id)
        if ch is None:
            raise _Denied("Ticket-Kanal existiert nicht mehr", 404)
        return g, ch, ts, d, meta

    @staticmethod
    def _ticket_entry(g, ts, d, cid, meta):
        """Ein Ticket als flaches Listen-Element fürs Web (ohne API-Calls!).

        Bewusst nur Daten, die aus ticket_data + Gateway-Cache kommen: die Inbox
        listet bei einer großen Guild dutzende Tickets, ein REST-Call pro Ticket
        (z.B. für den letzten Beitrag) würde das Laden unbrauchbar langsam machen.
        Die letzte Aktivität kommt deshalb aus der Snowflake der letzten Nachricht.
        """
        pid = meta.get("panel_id", "default")
        pconf = (d.get("panels") or {}).get(pid) or {}
        prio = meta.get("priority", ts.DEFAULT_PRIORITY)
        if prio not in ts.PRIORITY_LEVELS:
            prio = ts.DEFAULT_PRIORITY
        claimer_id = (d.get("claimed_tickets") or {}).get(cid)
        claimer = g.get_member(claimer_id) if claimer_id else None
        opener_id = meta.get("opener")
        opener = g.get_member(opener_id) if opener_id else None
        ch = g.get_channel(int(cid))
        last = None
        if ch is not None and getattr(ch, "last_message_id", None):
            try:
                last = discord.utils.snowflake_time(ch.last_message_id).isoformat()
            except (ValueError, OverflowError, OSError):
                last = None
        # SLA nur für UNübernommene Tickets — genau wie im Ticket-Container:
        # sobald jemand dran ist, ist die Reaktionsfrist erfüllt.
        deadline = None
        if not claimer_id:
            deadline = ts._sla_deadline_ts(g.id, pid, prio, meta.get("sla_since"))
        return {
            "channel_id": cid,
            "channel": ch.name if ch else None,
            "number": meta.get("number"),
            "panel": {"id": pid, "name": pconf.get("name") or pid},
            "reasons": [(ln[2:] if ln.startswith("• ") else ln).strip()
                        for ln in (meta.get("reason") or "").splitlines() if ln.strip()],
            "priority": prio,
            "opener": {
                "id": str(opener_id) if opener_id else None,
                "name": opener.display_name if opener else None,
                "avatar": ts._opener_avatar(g, opener_id) if opener_id else None,
            },
            "claimed_by": ({"id": str(claimer_id),
                            "name": claimer.display_name if claimer else None}
                           if claimer_id else None),
            "created": meta.get("created"),
            "last_activity": last,
            "notes": len(meta.get("notes") or []),
            "sla_deadline": deadline,
            "sla_overdue": bool(deadline and deadline < time.time()),
        }

    async def _ticket_refresh_container(self, ch, g, ts, d, cid, meta):
        """Zieht den Ticket-Container im Kanal auf den neuen Stand (best-effort).

        Genau das macht in Discord `interaction.response.edit_message` nach einem
        Klick. Ohne diesen Schritt würde eine Web-Aktion im Kanal unsichtbar
        bleiben und der Container z.B. weiter "Offen" anzeigen.
        """
        mid = meta.get("panel_msg_id")
        if not mid:
            return
        try:
            await ch.get_partial_message(int(mid)).edit(
                view=ts.build_ticket_view(
                    meta.get("number", 0), meta.get("opener"), meta.get("reason", "—"),
                    claimed_by=(d.get("claimed_tickets") or {}).get(cid), guild_id=g.id,
                    priority=meta.get("priority", ts.DEFAULT_PRIORITY),
                    notes_count=len(meta.get("notes") or []),
                    pid=meta.get("panel_id", "default"), created=meta.get("created"),
                    sla_since=meta.get("sla_since"),
                    opener_avatar_url=ts._opener_avatar(g, meta.get("opener"))))
        except (discord.HTTPException, ValueError, TypeError) as e:
            log.warning("webapi: Ticket-Container %s nicht aktualisiert: %s", cid, e)

    async def _ticket_notice(self, ch, ts, title, body):
        """Postet eine Status-Meldung im Ticket-Kanal — im gleichen Look wie die
        Meldungen, die ein Klick in Discord erzeugt, plus Herkunfts-Hinweis."""
        try:
            await ch.send(view=ts._notice_view(title, f"{body}\n-# über das Web-Dashboard"),
                          allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as e:
            log.warning("webapi: Ticket-Meldung nicht gepostet: %s", e)

    @rpc("tickets.inbox", {"guild_id": ("id", True)}, scope="support")
    async def _rpc_tickets_inbox(self, args, actor):
        """Alle OFFENEN Tickets der Guild + alles, was die Inbox zum Anzeigen und
        Filtern braucht (Panels, Prioritätsstufen, Kennzahlen) in EINEM Call."""
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        import cogs.ticketsystem as ts
        d = ts.gdata(gid)

        items, stale = [], 0
        for pid, p in (d.get("panels") or {}).items():
            for cid in list((p.get("open_tickets") or {}).values()):
                cid_s = str(cid)
                meta = d["meta"].get(cid_s)
                if meta is None or g.get_channel(int(cid)) is None:
                    stale += 1      # Kanal von Hand gelöscht / Altdaten -> nicht anzeigen
                    continue
                items.append(self._ticket_entry(g, ts, d, cid_s, meta))
        # Reihenfolge = Arbeitsreihenfolge: überfällig zuerst, dann nach
        # Dringlichkeit, dann das älteste Ticket oben (First-In-First-Out).
        items.sort(key=lambda x: (
            0 if x["sla_overdue"] else 1,
            -ts._PRIORITY_RANK.get(x["priority"], 1),
            x["created"] or "",
        ))

        ratings = [r.get("stars") for r in (d.get("ratings") or []) if isinstance(r.get("stars"), int)]
        stats = d.get("stats") or {}
        claims = sorted(((uid, n) for uid, n in (stats.get("claims") or {}).items()),
                        key=lambda kv: -kv[1])[:5]
        return {
            "guild_id": str(gid),
            "tickets": items,
            "stale": stale,
            "panels": [{"id": pid, "name": (p.get("name") or pid),
                        "quick_replies": [{"label": q.get("label") or "", "text": q.get("text") or ""}
                                          for q in (p.get("quick_replies") or [])][:25]}
                       for pid, p in (d.get("panels") or {}).items()],
            "priorities": [{"key": k, "label": ts._priority_label(k, gid), "emoji": v["emoji"]}
                           for k, v in ts.PRIORITY_LEVELS.items()],
            "support_roles": [{"id": str(rid),
                               "name": (g.get_role(rid).name if g.get_role(rid) else None)}
                              for rid in (d.get("support_roles") or [])],
            "counter": d.get("counter", 0),
            "closed_total": stats.get("closed_total", 0),
            "top_claims": [{"id": uid,
                            "name": (g.get_member(int(uid)).display_name
                                     if uid.isdigit() and g.get_member(int(uid)) else None),
                            "count": n} for uid, n in claims],
            "rating": ({"avg": round(sum(ratings) / len(ratings), 2), "count": len(ratings)}
                       if ratings else None),
        }

    @rpc("tickets.thread",
         {"guild_id": ("id", True), "channel_id": ("id", True), "limit": ("int", False)},
         scope="support")
    async def _rpc_tickets_thread(self, args, actor):
        """Der Gesprächsverlauf EINES Tickets + Metadaten, interne Notizen und die
        Schnellantworten seines Panels."""
        gid, cid = args["guild_id"], args["channel_id"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        cid_s = str(cid)
        limit = max(10, min(args.get("limit") or 60, 150))

        msgs = []
        try:
            async for m in ch.history(limit=limit, oldest_first=False):
                content = (m.clean_content or "").strip()
                if not content:
                    content = self._ticket_component_text(getattr(m, "components", None))
                if not content:
                    # Embed-Nachrichten (Alt-Panels, KI-Antworten) als letzte Quelle
                    parts = []
                    for e in m.embeds:
                        t, dsc = (e.title or "").strip(), (e.description or "").strip()
                        if t or dsc:
                            parts.append(f"**{t}**\n{dsc}".strip())
                    content = "\n\n".join(parts).strip()
                atts = [{"name": a.filename, "url": a.url, "size": a.size} for a in m.attachments]
                if not content and not atts:
                    continue        # rein interaktive Nachricht (nur Buttons) -> nichts zu zeigen
                msgs.append({
                    "id": str(m.id),
                    "ts": m.created_at.isoformat(),
                    "author": {
                        "id": str(m.author.id),
                        "name": m.author.display_name,
                        "avatar": (m.author.display_avatar.url if m.author.display_avatar else None),
                        "bot": bool(m.author.bot),
                        "is_opener": m.author.id == meta.get("opener"),
                    },
                    "text": content[:4000],
                    "attachments": atts[:10],
                })
        except discord.Forbidden:
            raise _Denied("Bot darf den Ticket-Kanal nicht lesen", 403)
        except discord.HTTPException as e:
            raise _Denied(f"Discord-Fehler beim Lesen: {e}", 502)
        msgs.reverse()

        pid = meta.get("panel_id", "default")
        pconf = (d.get("panels") or {}).get(pid) or {}
        notes = [{"author": str(n.get("author")),
                  "name": (g.get_member(int(n["author"])).display_name
                           if str(n.get("author", "")).isdigit() and g.get_member(int(n["author"])) else None),
                  "ts": n.get("ts"), "text": n.get("text") or ""}
                 for n in (meta.get("notes") or [])][-30:]
        return {
            "guild_id": str(gid),
            "ticket": self._ticket_entry(g, ts, d, cid_s, meta),
            "messages": msgs,
            "truncated": len(msgs) >= limit,
            "notes": notes,
            "quick_replies": [{"label": q.get("label") or "", "text": q.get("text") or ""}
                              for q in (pconf.get("quick_replies") or [])][:25],
        }

    @rpc("tickets.reply",
         {"guild_id": ("id", True), "channel_id": ("id", True), "text": ("text", True)},
         writes=True, scope="support")
    async def _rpc_tickets_reply(self, args, actor):
        """Antwort ins Ticket schreiben.

        Bewusst als NORMALE Nachricht (kein Container): so steht sie im Verlauf,
        im Transcript des Erstellers und in der KI-Zusammenfassung genauso da wie
        eine in Discord getippte Antwort. Erwähnungen sind unterdrückt — über das
        Dashboard soll niemand @everyone auslösen können.
        """
        gid, cid = args["guild_id"], args["channel_id"]
        text = (args["text"] or "").strip()
        if not text:
            raise _Denied("Leere Antwort", 400)
        if len(text) > 1700:
            raise _Denied("Antwort zu lang (max. 1700 Zeichen)", 400)
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        who = g.get_member(actor)
        name = who.display_name if who else (await self._safe_fetch_user(actor))
        try:
            msg = await ch.send(f"💬 **{name}**\n{text}\n-# über das Web-Dashboard",
                                allowed_mentions=discord.AllowedMentions.none())
        except discord.Forbidden:
            raise _Denied("Bot darf im Ticket-Kanal nicht schreiben", 403)
        except discord.HTTPException as e:
            raise _Denied(f"Discord-Fehler beim Senden: {e}", 502)
        log.info("webapi: Ticket-Antwort in %s (Guild %s) durch %s", cid, gid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid), "message_id": str(msg.id)}

    @rpc("tickets.claim", {"guild_id": ("id", True), "channel_id": ("id", True)},
         writes=True, scope="support")
    async def _rpc_tickets_claim(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        cid_s = str(cid)
        claimed = d["claimed_tickets"]
        if cid_s in claimed and claimed[cid_s] != actor:
            raise _Denied("Ticket ist bereits von jemand anderem übernommen", 409)
        if cid_s not in claimed:
            claimed[cid_s] = actor
            meta.pop("sla_warned", None)      # übernommen -> SLA erfüllt
            ts.save_data(ts.ticket_data)
            await self._ticket_refresh_container(ch, g, ts, d, cid_s, meta)
            await self._ticket_notice(
                ch, ts, ts.i18n.t("ticket.claimed_title", guild_id=gid),
                ts.i18n.t("ticket.claimed_body", guild_id=gid, who=f"<@{actor}>"))
            # Schreibsperre wie in Discord: ab jetzt nur noch Bearbeiter + Ersteller.
            await ts._lock_ticket_channel(ch, gid, actor)
            log.info("webapi: Ticket %s (Guild %s) übernommen durch %s", cid, gid, actor)
        return {"guild_id": str(gid), "ticket": self._ticket_entry(g, ts, d, cid_s, meta)}

    @rpc("tickets.unclaim", {"guild_id": ("id", True), "channel_id": ("id", True)},
         writes=True, scope="support")
    async def _rpc_tickets_unclaim(self, args, actor):
        gid, cid = args["guild_id"], args["channel_id"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        cid_s = str(cid)
        claimed = d["claimed_tickets"]
        if cid_s in claimed:
            from datetime import datetime, timezone
            del claimed[cid_s]
            # Wieder unbeantwortet -> SLA-Frist neu starten (siehe UnclaimButton).
            meta["sla_since"] = datetime.now(timezone.utc).isoformat()
            meta.pop("sla_warned", None)
            ts.save_data(ts.ticket_data)
            await self._ticket_refresh_container(ch, g, ts, d, cid_s, meta)
            await self._ticket_notice(
                ch, ts, ts.i18n.t("ticket.unclaimed_title", guild_id=gid),
                ts.i18n.t("ticket.unclaimed_body", guild_id=gid))
            await ts._unlock_ticket_channel(ch, gid)
            log.info("webapi: Ticket %s (Guild %s) freigegeben durch %s", cid, gid, actor)
        return {"guild_id": str(gid), "ticket": self._ticket_entry(g, ts, d, cid_s, meta)}

    @rpc("tickets.priority.set",
         {"guild_id": ("id", True), "channel_id": ("id", True), "level": ("str", True)},
         writes=True, scope="support")
    async def _rpc_tickets_priority(self, args, actor):
        gid, cid, level = args["guild_id"], args["channel_id"], args["level"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        if level not in ts.PRIORITY_LEVELS:
            raise _Denied(f"Unbekannte Prioritätsstufe {level!r}", 400)
        cid_s = str(cid)
        if meta.get("priority") != level:
            meta["priority"] = level
            meta.pop("sla_warned", None)     # kürzere Frist sofort neu prüfen lassen
            ts.save_data(ts.ticket_data)
            await self._ticket_refresh_container(ch, g, ts, d, cid_s, meta)
            lvl = ts.PRIORITY_LEVELS[level]
            await self._ticket_notice(
                ch, ts, ts.i18n.t("ticket.priority_set_title", guild_id=gid),
                ts.i18n.t("ticket.priority_set_body", guild_id=gid, who=f"<@{actor}>",
                          emoji=lvl["emoji"], level=ts._priority_label(level, gid)))
            log.info("webapi: Ticket %s (Guild %s) Priorität -> %s durch %s", cid, gid, level, actor)
        return {"guild_id": str(gid), "ticket": self._ticket_entry(g, ts, d, cid_s, meta)}

    @rpc("tickets.note.add",
         {"guild_id": ("id", True), "channel_id": ("id", True), "text": ("text", True)},
         writes=True, scope="support")
    async def _rpc_tickets_note_add(self, args, actor):
        """Interne Notiz — landet NIE im Kanal (der Ersteller sieht sie nicht),
        genau wie die Notizen aus dem Discord-Modal."""
        gid, cid = args["guild_id"], args["channel_id"]
        text = (args["text"] or "").strip()
        if not text:
            raise _Denied("Leere Notiz", 400)
        if len(text) > 500:
            raise _Denied("Notiz zu lang (max. 500 Zeichen)", 400)
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        from datetime import datetime, timezone
        notes = meta.setdefault("notes", [])
        notes.append({"author": actor, "text": text,
                      "ts": datetime.now(timezone.utc).isoformat()})
        if len(notes) > 200:
            del notes[:-200]
        ts.save_data(ts.ticket_data)
        # Nur der Notiz-ZÄHLER am Container ändert sich — der Inhalt bleibt intern.
        await self._ticket_refresh_container(ch, g, ts, d, str(cid), meta)
        log.info("webapi: interne Ticket-Notiz in %s (Guild %s) durch %s", cid, gid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid), "notes": len(notes)}

    @rpc("tickets.transcript", {"guild_id": ("id", True), "channel_id": ("id", True)},
         scope="support")
    async def _rpc_tickets_transcript(self, args, actor):
        """Transcript des laufenden Tickets — dieselbe Funktion, die beim Schließen
        die Datei für Log-Kanal und Ersteller-DM erzeugt."""
        gid, cid = args["guild_id"], args["channel_id"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        try:
            text = await ts.build_transcript(ch)
        except discord.Forbidden:
            raise _Denied("Bot darf den Ticket-Kanal nicht lesen", 403)
        num = meta.get("number")
        return {
            "guild_id": str(gid),
            "channel_id": str(cid),
            "filename": f"transcript-{ch.name}.txt",
            "number": num,
            "text": text[:200000],
        }

    @rpc("tickets.close", {"guild_id": ("id", True), "channel_id": ("id", True)},
         writes=True, scope="support")
    async def _rpc_tickets_close(self, args, actor):
        """Ticket schließen: Transcript, Log-Post, DM an den Ersteller, Bewertung,
        Kanal-Löschung — exakt der Weg des roten Buttons in Discord.

        Läuft im HINTERGRUND, weil der komplette Ablauf (inkl. optionaler
        KI-Zusammenfassung) länger dauern kann als das 10-Sekunden-Zeitfenster
        des Dashboard-Requests. Der Kanal bekommt vorher eine sichtbare Meldung,
        damit für die Beteiligten in Discord nichts unangekündigt verschwindet.
        """
        gid, cid = args["guild_id"], args["channel_id"]
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        closer = f"<@{actor}>"
        await self._ticket_notice(ch, ts, ts.i18n.t("ticket.closing_title", guild_id=gid),
                                  ts.i18n.t("ticket.closing_body", guild_id=gid))

        async def _run():
            try:
                await ts._execute_ticket_close(ch, closer, guild_id=gid)
            except Exception:
                log.exception("webapi: Ticket-Schließen fehlgeschlagen (Kanal %s)", cid)

        ts._spawn_bg(_run())
        log.info("webapi: Ticket %s (Guild %s) wird geschlossen durch %s", cid, gid, actor)
        return {"guild_id": str(gid), "channel_id": str(cid), "closing": True}


    # -- Support-Zugang (Ticket-Arbeitsplatz für das Team) ----------------------
    # Der Rest des Dashboards ist Owner/Admin-Sache. Am Ticket arbeitet in Discord
    # aber das SUPPORT-TEAM — wer dort eine konfigurierte Support-Rolle hat, darf
    # Tickets übernehmen, beantworten und schließen (ticketsystem.is_support).
    # Genau diese Menge bekommt hier Zugang, kein zweites Rechte-Modell: Quelle
    # ist ausschließlich `support_roles` aus cogs/ticketsystem.py.

    def _cache(self, name):
        """Instanz-Cache, der einen Hot-Reload ohne __init__-Lauf übersteht."""
        d = getattr(self, name, None)
        if d is None:
            d = {}
            setattr(self, name, d)
        return d

    @staticmethod
    def _support_role_ids(guild_id):
        try:
            import cogs.ticketsystem as ts
            return set(ts.get_support_roles(guild_id) or [])
        except Exception:
            return set()          # Ticketsystem nicht da -> niemand ist Support

    def _support_authorized_cached(self, guild: discord.Guild, actor: int) -> bool:
        """Support-Prüfung OHNE API-Call — nur Gateway-Cache. Für guilds.mine,
        das über alle Guilds des Bots läuft (siehe _guild_authorized_cached)."""
        roles = self._support_role_ids(guild.id)
        if not roles:
            return False
        m = guild.get_member(actor)
        return bool(m and any(r.id in roles for r in m.roles))

    async def _support_authorized(self, guild: discord.Guild, actor: int) -> bool:
        """Darf actor in dieser Guild an Tickets arbeiten? Admin/Owner ODER
        Support-Rolle — dieselben zwei Wege wie ticketsystem.is_support.
        Mit kurzem TTL-Cache: die Inbox fragt im Sekundentakt nach."""
        if await self._guild_authorized(guild, actor):
            return True
        key = (guild.id, actor)
        now = time.monotonic()
        cache = self._cache("_support_cache")
        hit = cache.get(key)
        if hit is not None and now - hit[1] < AUTHZ_TTL:
            return hit[0]
        roles = self._support_role_ids(guild.id)
        ok = False
        if roles:
            m = guild.get_member(actor)
            if m is None:
                # chunk_guilds_at_startup=False -> Cache-Miss ist kein "nicht da"
                try:
                    m = await guild.fetch_member(actor)
                except (discord.NotFound, discord.HTTPException):
                    m = None
            ok = bool(m and any(r.id in roles for r in m.roles))
        cache[key] = (ok, now)
        return ok

    @rpc("guild.brief", {"guild_id": ("id", True)}, scope="support")
    async def _rpc_guild_brief(self, args, actor):
        """Nur Name/Icon/Größe — für die Kopfzeile des Ticket-Arbeitsplatzes.
        Bewusst NICHT guild.get: Support-Personal braucht keine vollständige
        Kanal- und Rollenliste des Servers."""
        g = self.bot.get_guild(args["guild_id"])
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        return self._guild_dict(g)

    # -- KI-Assistenz fürs Dashboard -------------------------------------------
    # Der Browser sieht NIE Anbieter, Modell, Endpunkt oder Schlüssel: er schickt
    # nur eine Aufgabe ("summary"/"draft") und bekommt Text zurück. Den Prompt
    # baut ausschließlich der Bot (kein durchgereichter Freitext-Prompt), damit
    # das Dashboard kein offener LLM-Zugang wird. Kostenbremse: Modul-Gate,
    # Konfigurations-Check und ein eigener Zähler pro Actor.
    AI_RATE = 15                 # Aufrufe …
    AI_RATE_WINDOW = 300         # … pro Actor in 5 Minuten

    # --- Datenschutz-Gate ----------------------------------------------------
    # KEIN Ticketinhalt geht an die KI, bevor ein Admin des jeweiligen Servers
    # der Verarbeitung ausdrücklich zugestimmt hat. Die Zustimmung ist
    # PRO SERVER, widerrufbar, versioniert (ändert sich der Hinweistext
    # inhaltlich, wird neu zugestimmt) und wird mit Zeitpunkt und Person
    # festgehalten -- der Server-Admin ist für die Daten seiner Mitglieder
    # verantwortlich, also muss nachvollziehbar sein, wer das freigegeben hat.
    # Namespace bewusst neutral ("ai_consent"), damit die Discord-Seite später
    # denselben Datensatz lesen kann statt eine zweite Wahrheit zu haben.
    AI_CONSENT_NS = "ai_consent"
    AI_CONSENT_VERSION = 1

    @classmethod
    def _ai_consent_get(cls, gid):
        rec = (storage.load_doc(cls.AI_CONSENT_NS, {}) or {}).get(str(gid)) or {}
        accepted = bool(rec.get("accepted")) and rec.get("version") == cls.AI_CONSENT_VERSION
        return accepted, rec

    def _ai_consent_required(self, gid):
        accepted, _rec = self._ai_consent_get(gid)
        if not accepted:
            # 428 (Precondition Required) statt 403: die Oberfläche soll den
            # Unterschied "nicht erlaubt" vs. "Zustimmung fehlt noch" kennen.
            raise _Denied("KI-Zustimmung für diesen Server fehlt", 428)

    @rpc("ai.consent.get", {"guild_id": ("id", True)}, scope="support")
    async def _rpc_ai_consent_get(self, args, actor):
        """Zustand des Datenschutz-Gates. Lesend auch fürs Support-Team, damit
        die Inbox erklären kann, warum die KI-Knöpfe (noch) nicht gehen."""
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        accepted, rec = self._ai_consent_get(gid)
        who = rec.get("by")
        m = g.get_member(int(who)) if str(who or "").isdigit() else None
        import ai as aimod
        return {
            "guild_id": str(gid),
            "accepted": accepted,
            "version": self.AI_CONSENT_VERSION,
            "accepted_version": rec.get("version"),
            "accepted_at": rec.get("at"),
            "accepted_by": ({"id": str(who), "name": m.display_name if m else None}
                            if who else None),
            # Damit die Oberfläche gar keine Knöpfe anbietet, wo die KI ohnehin
            # nicht laufen kann (Modul aus oder serverseitig nicht eingerichtet).
            "module_enabled": bool(modules.is_module_enabled(gid, "ai")),
            "available": bool(aimod.is_configured()),
            "can_decide": bool(actor in ACTORS or await self._guild_authorized(g, actor)),
        }

    @rpc("ai.consent.set", {"guild_id": ("id", True), "accepted": ("bool", True)},
         writes=True)
    async def _rpc_ai_consent_set(self, args, actor):
        """Zustimmung erteilen oder widerrufen. Bewusst guild-Scope (Owner/
        Administrator): das ist eine Entscheidung des Server-Verantwortlichen,
        nicht des Support-Personals."""
        gid, accepted = args["guild_id"], args["accepted"]
        if self.bot.get_guild(gid) is None:
            raise _Denied("Guild unbekannt", 404)
        from datetime import datetime, timezone
        doc = storage.load_doc(self.AI_CONSENT_NS, {}) or {}
        if accepted:
            doc[str(gid)] = {"accepted": True, "version": self.AI_CONSENT_VERSION,
                             "by": str(actor), "at": datetime.now(timezone.utc).isoformat()}
        else:
            # Widerruf protokollieren statt den Eintrag zu löschen -- sonst ist
            # später nicht mehr erkennbar, dass bewusst widerrufen wurde.
            doc[str(gid)] = {"accepted": False, "version": None,
                             "by": str(actor), "at": datetime.now(timezone.utc).isoformat(),
                             "revoked": True}
        storage.save_doc(self.AI_CONSENT_NS, doc)
        log.info("webapi: KI-Zustimmung Guild %s -> %s durch %s", gid, accepted, actor)
        return await self._rpc_ai_consent_get({"guild_id": gid}, actor)

    def _ai_rate_ok(self, actor):
        bucket = self._cache("_ai_hits").setdefault(actor, deque())
        now = time.time()
        while bucket and now - bucket[0] > self.AI_RATE_WINDOW:
            bucket.popleft()
        if len(bucket) >= self.AI_RATE:
            return False
        bucket.append(now)
        return True

    def _ai_guard(self, gid, actor):
        """Gemeinsame Vorprüfung aller KI-Kommandos. Reihenfolge mit Absicht:
        Zustimmung ZUERST -- solange die fehlt, wird nicht einmal geprüft, ob
        eine KI erreichbar wäre, und es verlässt kein Byte den Bot."""
        self._ai_consent_required(gid)
        if not modules.is_module_enabled(gid, "ai"):
            raise _Denied("KI-Modul auf diesem Server nicht aktiv", 409)
        import ai as aimod
        if not aimod.is_configured():
            raise _Denied("KI nicht konfiguriert", 503)
        if not self._ai_rate_ok(actor):
            raise _Denied("KI-Rate-Limit", 429)
        return aimod

    # Grundhaltung für jeden Entwurf: Der Text geht NICHT direkt raus, ein Mensch
    # prüft ihn. Und er verrät nichts über die Technik dahinter — dieselbe Regel
    # wie im Discord-Assistenten (cogs/ai_tools.py).
    _AI_DRAFT_DE = (
        "Du bist die interne Assistenz des IronShield-Support-Teams. Formuliere einen "
        "ANTWORTENTWURF an die Person, die das Ticket eröffnet hat. Der Entwurf wird von "
        "einem Menschen geprüft und erst dann gesendet.\n"
        "Regeln: höchstens 6 Sätze, sachlich und freundlich, kein Werbe-Sprech, keine "
        "Emoji-Girlanden. Erfinde KEINE Fakten, keine Fristen und keine Zusagen. Fehlt eine "
        "Information, frage im Entwurf danach. Sprich die Person direkt an, ohne Anrede-"
        "Floskeln aus dem Nichts. Antworte NUR mit dem Entwurfstext, ohne Vorrede, ohne "
        "Anführungszeichen. Nenne niemals ein KI-Modell, einen Anbieter oder die Technik "
        "dahinter."
    )
    _AI_DRAFT_EN = (
        "You are the internal assistant of the IronShield support team. Write a DRAFT REPLY "
        "to the person who opened the ticket. A human reviews the draft before it is sent.\n"
        "Rules: at most 6 sentences, factual and friendly, no marketing speak, no emoji "
        "spam. Do NOT invent facts, deadlines or promises. If information is missing, ask "
        "for it in the draft. Address the person directly. Reply with the draft text ONLY — "
        "no preamble, no quotation marks. Never name an AI model, provider or the "
        "technology behind you."
    )

    @rpc("ai.ticket",
         {"guild_id": ("id", True), "channel_id": ("id", True), "task": ("str", True),
          "hint": ("str", False)},
         scope="support")
    async def _rpc_ai_ticket(self, args, actor):
        """KI-Hilfe AM TICKET: "summary" (worum geht es?) oder "draft"
        (Antwortentwurf). Grundlage ist dasselbe Transcript, das beim Schließen
        erzeugt wird — kein separater, zweiter Datenweg."""
        gid, cid, task = args["guild_id"], args["channel_id"], args["task"]
        if task not in ("summary", "draft"):
            raise _Denied(f"Unbekannte Aufgabe {task!r}", 400)
        hint = (args.get("hint") or "").strip()
        if len(hint) > 200:
            raise _Denied("Hinweis zu lang (max. 200 Zeichen)", 400)
        g, ch, ts, d, meta = self._ticket_ctx(gid, cid)
        aimod = self._ai_guard(gid, actor)

        try:
            transcript = await ts.build_transcript(ch)
        except discord.Forbidden:
            raise _Denied("Bot darf den Ticket-Kanal nicht lesen", 403)
        loc = ts.i18n.get_locale(gid)

        if task == "summary":
            out = await aimod.summarize_ticket(transcript, loc)
        else:
            system = self._AI_DRAFT_EN if loc == "en" else self._AI_DRAFT_DE
            reason = (meta.get("reason") or "").replace("\n", ", ")
            # Vom Team freigegebenes Server-Wissen mitgeben (cogs/supportwissen.py):
            # der Entwurf soll dieselben verbindlichen Auskünfte nutzen wie die
            # Ticket-KI, statt Sachfragen offen zu lassen, die das Team längst
            # beantwortet hat. Als Suchbegriff dienen Bereich + Hinweis des
            # Support-Mitglieds.
            try:
                import cogs.supportwissen as sw
                wissen = sw.wissen_block(gid, f"{reason} {hint}".strip(), loc)
                if wissen:
                    system += wissen
            except Exception as e:
                log.warning("webapi: Support-Wissen nicht verfügbar: %s", e)
            head = ("TICKET AREA" if loc == "en" else "TICKET-BEREICH") + f": {reason}\n"
            body = ("TICKET HISTORY" if loc == "en" else "TICKET-VERLAUF") + \
                   f":\n{transcript[-6000:]}"
            if hint:
                body += "\n\n" + ("INSTRUCTION FROM THE SUPPORT MEMBER (follow it): "
                                  if loc == "en" else
                                  "VORGABE DES SUPPORT-MITGLIEDS (halte dich daran): ") + hint
            out = await aimod.complete(system, head + body, max_tokens=350,
                                       temperature=0.4, fallback=True)
        out = (out or "").strip()
        if not out:
            raise _Denied("KI lieferte keine Antwort", 502)
        log.info("webapi: KI-%s für Ticket %s (Guild %s) durch %s", task, cid, gid, actor)
        # Bewusst nur Text: kein Modell, kein Anbieter, keine Nutzungsdaten.
        return {"task": task, "text": out[:1800]}

    _AI_CHECK_DE = (
        "Du bist die interne Assistenz für IronShield-Serveradmins. Du bekommst den "
        "Konfigurationsstand eines Discord-Servers. Nenne die 3 bis 5 wirkungsvollsten "
        "nächsten Schritte — konkret, in Stichpunkten mit '- ' beginnend, je ein Satz "
        "Begründung. Beziehe dich NUR auf die unten aufgeführten Module und Fakten und "
        "erfinde keine Befehle oder Funktionen. Wenn wenig zu verbessern ist, sag das "
        "klar. Kein Werbe-Sprech. Nenne niemals ein KI-Modell oder einen Anbieter."
    )
    _AI_CHECK_EN = (
        "You are the internal assistant for IronShield server admins. You receive the "
        "configuration state of a Discord server. Name the 3 to 5 most effective next "
        "steps — concrete, as bullet points starting with '- ', one sentence of reasoning "
        "each. Refer ONLY to the modules and facts listed below and do not invent commands "
        "or features. If there is little to improve, say so plainly. No marketing speak. "
        "Never name an AI model or provider."
    )

    @rpc("ai.guild_check", {"guild_id": ("id", True)})
    async def _rpc_ai_guild_check(self, args, actor):
        """"Was fehlt auf meinem Server?" — Vorschläge aus dem ECHTEN Zustand
        (Module an/aus, Ticket-/Log-Konfiguration), nicht aus einer Broschüre.
        Admin-Sache, deshalb der normale guild-Scope."""
        gid = args["guild_id"]
        g = self.bot.get_guild(gid)
        if g is None:
            raise _Denied("Guild unbekannt", 404)
        aimod = self._ai_guard(gid, actor)

        state = modules.enabled_map(gid)
        on, off = [], []
        for cat, mods in modules.by_category().items():
            for m in mods:
                (on if state.get(m["key"], m["default"]) else off).append(m["label"]["de"])
        facts = [f"Server: {g.name} ({g.member_count or 0} Mitglieder)",
                 "Aktive Module: " + (", ".join(on) or "keine"),
                 "Ausgeschaltete Module: " + (", ".join(off) or "keine")]
        try:
            import cogs.ticketsystem as ts
            td = ts.gdata(gid)
            panels = td.get("panels") or {}
            open_n = sum(len((p.get("open_tickets") or {})) for p in panels.values())
            facts.append(f"Tickets: {len(panels)} Panel(s), {open_n} offen, "
                         f"{len(td.get('support_roles') or [])} Support-Rolle(n), "
                         f"Log-Kanal: {'ja' if td.get('log_channel') else 'nein'}")
        except Exception:
            pass
        import i18n
        loc = i18n.get_locale(gid)
        system = self._AI_CHECK_EN if loc == "en" else self._AI_CHECK_DE
        out = await aimod.complete(system, "\n".join(facts), max_tokens=400,
                                   temperature=0.4, fallback=True)
        out = (out or "").strip()
        if not out:
            raise _Denied("KI lieferte keine Antwort", 502)
        log.info("webapi: KI-Serverprüfung Guild %s durch %s", gid, actor)
        return {"text": out[:1800]}


def _hierarchy_ok(target, me):
    """Ziel-vs-Bot-Hierarchie für Moderations-Aktionen vom Dashboard.

    Anders als im Discord-Menü (mod.py:_hierarchy_ok) gibt es hier keinen
    Actor-vs-Ziel-Vergleich: der Actor ist ein Bot-Owner ohne Guild-Rolle,
    kein Server-Moderator. Nur Owner-Schutz und Bot-Fähigkeit zählen.
    """
    if target.id == target.guild.owner_id:
        return False, "Ziel ist der Server-Owner"
    if me is not None and target.top_role >= me.top_role:
        return False, "Ziel steht über/gleich der höchsten Bot-Rolle"
    return True, None


class _ActorProxy:
    """Leichtgewichtiger Platzhalter für warnsystem.do_warn(moderator=...),
    das nur `.name` liest — ein echtes discord.Member/User ist hier nicht
    nötig, der Dashboard-Actor hat keine Guild-Mitgliedschaft vorausgesetzt."""

    def __init__(self, name):
        self.name = name


class _Denied(Exception):
    """Abweisung mit HTTP-Status. Grund geht nur ins Log, nie an den Client."""

    def __init__(self, reason, status=403):
        super().__init__(reason)
        self.reason = reason
        self.status = status


async def setup(bot):
    await bot.add_cog(WebAPI(bot))
