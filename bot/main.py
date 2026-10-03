#!/usr/bin/env python3
"""Iron Shield ticket bot and private PHP-to-bot HTTP bridge."""

from __future__ import annotations

import hmac
import json
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import discord
from discord.ext import commands


SCRIPT_DIR = Path(__file__).resolve().parent


def load_env_file() -> None:
    for env_path in (SCRIPT_DIR / ".env", SCRIPT_DIR.parent / ".env"):
        if not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


load_env_file()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
WEBHOOK_SECRET = (os.getenv("DASHBOARD_BRIDGE_SECRET") or os.getenv("BOT_WEBHOOK_SECRET") or "").strip()
HTTP_HOST = os.getenv("BOT_HTTP_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("BOT_HTTP_PORT", "8765"))
TLS_CERTFILE = os.getenv("BOT_TLS_CERTFILE", "").strip()
TLS_KEYFILE = os.getenv("BOT_TLS_KEYFILE", "").strip()
TRUSTED_TLS_PROXY = os.getenv("BOT_TRUSTED_TLS_PROXY", "0") == "1"


def required_configuration() -> None:
    if not BOT_TOKEN:
        raise SystemExit("ERROR: DISCORD_BOT_TOKEN fehlt. Setze die Variable im Hosting-Panel oder lege eine private .env neben main.py an.")
    if len(WEBHOOK_SECRET) < 32:
        raise SystemExit("ERROR: DASHBOARD_BRIDGE_SECRET oder BOT_WEBHOOK_SECRET muss mindestens 32 Zeichen lang sein.")
    if HTTP_HOST not in {"127.0.0.1", "0.0.0.0"}:
        raise SystemExit("ERROR: BOT_HTTP_HOST muss 127.0.0.1 oder 0.0.0.0 sein.")
    if HTTP_HOST == "0.0.0.0" and not ((TLS_CERTFILE and TLS_KEYFILE) or TRUSTED_TLS_PROXY):
        raise SystemExit("ERROR: Externer Bot-Zugriff benötigt direktes TLS oder einen vertrauenswürdigen TLS-Reverse-Proxy.")


class IronShieldBot(commands.Bot):
    def __init__(self) -> None:
        # The dashboard cleanup must receive the guild and channel lists from Discord.
        # This is a non-privileged intent; message content and member intents stay off.
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(command_prefix="!", intents=intents)
        self.http_server: ThreadingHTTPServer | None = None

    async def setup_hook(self) -> None:
        bot = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "IronShieldBotBridge/1.0"

            def log_message(self, fmt: str, *args: Any) -> None:
                print("[bot-http] " + (fmt % args), flush=True)

            def _reply(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path != "/health":
                    self._reply(404, {"error": "not_found"})
                    return
                if not bot.is_ready():
                    self._reply(503, {"ready": False})
                    return
                self._reply(200, {"ready": True})

            def do_POST(self) -> None:
                provided = self.headers.get("X-IronShield-Bot-Secret", "")
                if not hmac.compare_digest(provided, WEBHOOK_SECRET):
                    self._reply(403, {"error": "unauthorized"})
                    return
                if self.path != "/ticket":
                    self._reply(404, {"error": "not_found"})
                    return
                # Discord publishing is intentionally disabled: this endpoint never
                # creates threads or posts ticket content in any server.
                self._reply(410, {"error": "discord_publishing_disabled"})

        self.http_server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler)
        self.http_server.daemon_threads = True
        if TLS_CERTFILE and TLS_KEYFILE:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(TLS_CERTFILE, TLS_KEYFILE)
            self.http_server.socket = tls_context.wrap_socket(self.http_server.socket, server_side=True)
        threading.Thread(target=self.http_server.serve_forever, name="ticket-http", daemon=True).start()
        protocol = "https" if TLS_CERTFILE and TLS_KEYFILE else "http"
        print(f"[bot-http] {protocol} bridge listening on {HTTP_HOST}:{HTTP_PORT}", flush=True)
        await self.load_extension("cogs.ironshield_dashboard")

    async def on_ready(self) -> None:
        print(f"[discord] logged in as {self.user}", flush=True)

    async def close(self) -> None:
        if self.http_server is not None:
            self.http_server.shutdown()
            self.http_server.server_close()
        await super().close()


def main() -> None:
    required_configuration()
    bot = IronShieldBot()
    bot.run(BOT_TOKEN, log_handler=None)


if __name__ == "__main__":
    main()
