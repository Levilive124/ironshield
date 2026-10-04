"""HTTPS synchronization between the ticket Cog and the IronShield website."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp
import discord
from discord.ext import commands


GUILD_SETTING_KEYS = {
    "support_roles", "blocked_roles", "log_channel", "user_history_enabled",
    "tags", "tags_enabled", "archive_categories", "archive_enabled",
    "business_hours_enabled", "business_hours", "business_hours_tz",
}
PANEL_SETTING_KEYS = {
    "name", "panel_title", "panel_text", "channel", "category", "reasons", "log_channel", "limits",
    "reason_priority", "image", "ai_chat", "sla", "rating_channel",
    "quick_replies", "auto_close", "style", "channel_prefix", "reason_emoji",
    "reason_greeting", "close_reasons", "close_reasons_enabled", "intake_questions",
    "intake_enabled", "cooldown_seconds", "cooldown_enabled", "keyword_priority",
    "keyword_priority_enabled", "reminder_minutes", "reminder_enabled", "buttons",
    "escalation_enabled", "escalation", "auto_tag_enabled", "tag_keywords",
    "ai_actions_enabled",
}
RUNTIME_PANEL_KEYS = {"open_tickets", "cooldown_last"}


def _bridge_secret_from_environment() -> str:
    secret = (os.getenv("DASHBOARD_BRIDGE_SECRET") or os.getenv("BOT_WEBHOOK_SECRET") or "").strip()
    if secret:
        return secret
    # Existing bot hosts often expose only predefined panel variables. Allow
    # the dedicated secret to live in a private .env beside the bot's cogs.
    env_path = Path(__file__).resolve().parent.parent / ".env"
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in {"DASHBOARD_BRIDGE_SECRET", "BOT_WEBHOOK_SECRET"}:
                secret = value.strip().strip("\"'")
                if secret:
                    return secret
    except OSError:
        pass
    return ""


class IronShieldDashboardCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.sync_task: asyncio.Task[None] | None = None
        self.sync_connected = False
        self._sync_error_logged = False
        self._http_session: aiohttp.ClientSession | None = None
        self._legacy_channels_removed = False
        self._legacy_message_cleanup_done: set[int] = set()
        self._legacy_cleanup_retry_at = 0.0
        self._legacy_cleanup_retry_delay = 60.0
        self._ticket_module_error_logged = False
        self._settings_sync_cursor = 0

    def _ticket_module(self) -> Any:
        cog = self.bot.get_cog("TicketSystemCog")
        if cog is not None:
            module = sys.modules.get(cog.__class__.__module__)
            if module is not None and hasattr(module, "ticket_data"):
                return module
        for name, module in tuple(sys.modules.items()):
            if name.endswith("ticketsystem") and hasattr(module, "ticket_data") and hasattr(module, "gpanel"):
                return module
        raise RuntimeError("TicketSystemCog ist noch nicht geladen. Lade den Dashboard-Cog nach ticketsystem.py.")

    def _snapshot(self, module: Any, guild_id: int) -> dict[str, Any]:
        guild = module.gdata(guild_id)
        global_settings = {key: guild[key] for key in GUILD_SETTING_KEYS if key in guild}
        panels = {}
        for panel_id in guild.get("panels", {}):
            panel = module.gpanel(guild_id, panel_id)
            panels[str(panel_id)] = {key: panel[key] for key in PANEL_SETTING_KEYS if key in panel}
        return {"guild": global_settings, "panels": panels, "delete_panels": []}

    @staticmethod
    def _validate_update(current: dict[str, Any], incoming: Any, allowed: set[str]) -> dict[str, Any]:
        if not isinstance(incoming, dict):
            raise ValueError("Einstellungen müssen ein JSON-Objekt sein.")
        result = {}
        for key, value in incoming.items():
            if key not in allowed:
                raise ValueError(f"Nicht editierbares oder unbekanntes Feld: {key}")
            if key in current:
                old = current[key]
                if isinstance(old, bool) and not isinstance(value, bool):
                    raise ValueError(f"{key} muss true oder false sein.")
                if isinstance(old, list) and not isinstance(value, list):
                    raise ValueError(f"{key} muss eine Liste sein.")
                if isinstance(old, dict) and not isinstance(value, dict):
                    raise ValueError(f"{key} muss ein Objekt sein.")
                if isinstance(old, int) and not isinstance(old, bool) and value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                    raise ValueError(f"{key} muss eine Zahl oder null sein.")
                if isinstance(old, str) and value is not None and not isinstance(value, str):
                    raise ValueError(f"{key} muss Text oder null sein.")
            id_fields = {"channel", "category", "log_channel", "rating_channel", "role"}
            if key in id_fields and value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError(f"{key} muss eine Discord-ID als Zahl oder null sein.")
            if key in {"support_roles", "blocked_roles", "archive_categories"} and any(not isinstance(item, int) or isinstance(item, bool) for item in value):
                raise ValueError(f"{key} muss Discord-IDs als Zahlen enthalten.")
            if key == "reasons" and any(not isinstance(item, str) for item in value):
                raise ValueError("reasons muss eine Liste aus Texten sein.")
            result[key] = value
        return result

    async def _apply_settings(self, guild_id: int, settings: Any) -> None:
        if not isinstance(settings, dict) or not isinstance(settings.get("guild"), dict) or not isinstance(settings.get("panels"), dict):
            raise ValueError("Erwartet wird {guild: {...}, panels: {...}}.")
        module = self._ticket_module()
        if self.bot.get_guild(guild_id) is None:
            raise ValueError("Der Bot ist nicht auf diesem Discord-Server.")
        guild = module.gdata(guild_id)
        backup = copy.deepcopy(guild)
        validated_guild = self._validate_update(guild, settings["guild"], GUILD_SETTING_KEYS)
        submitted_panels = settings["panels"]
        known_panels = guild.get("panels", {})
        delete_panels = settings.get("delete_panels", [])
        if not isinstance(delete_panels, list) or any(not isinstance(pid, str) for pid in delete_panels):
            raise ValueError("delete_panels muss eine Liste von Panel-IDs sein.")
        removed_panels = {str(pid) for pid in known_panels} - set(submitted_panels)
        if removed_panels != set(delete_panels):
            raise ValueError("Panels bitte über delete_panels ausdrücklich zur Löschung markieren.")
        if len(submitted_panels) > 25:
            raise ValueError("Discord unterstützt höchstens 25 Ticket-Panels pro Server.")
        validated_panels = {}
        try:
            for panel_id, changes in submitted_panels.items():
                if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", str(panel_id)):
                    raise ValueError("Panel-IDs dürfen nur Buchstaben, Zahlen, _ und - enthalten (maximal 80 Zeichen).")
                panel = module.gpanel(guild_id, panel_id)
                validated_panels[panel_id] = self._validate_update(panel, changes, PANEL_SETTING_KEYS)
        except Exception:
            module.ticket_data[str(guild_id)] = backup
            raise

        try:
            guild.update(validated_guild)
            for panel_id, changes in validated_panels.items():
                panel = module.gpanel(guild_id, panel_id)
                panel.update(changes)
                for key in RUNTIME_PANEL_KEYS:
                    if key in backup.get("panels", {}).get(panel_id, {}):
                        panel[key] = backup["panels"][panel_id][key]
            panel_messages = guild.setdefault("panel_msgs", {})
            for panel_id in delete_panels:
                panel = guild.get("panels", {}).get(panel_id, {})
                if panel.get("open_tickets"):
                    raise ValueError(f"Panel {panel_id} hat noch offene Tickets und kann nicht gelöscht werden.")
                for message_id, mapped_panel in list(panel_messages.items()):
                    if str(mapped_panel) == panel_id:
                        panel_messages.pop(message_id, None)
                guild["panels"].pop(panel_id, None)
            await module.save_data_async(module.ticket_data)
        except Exception:
            module.ticket_data[str(guild_id)] = backup
            raise

    async def cog_load(self) -> None:
        if not self.bot.intents.guilds:
            raise RuntimeError("Dashboard-Cog benötigt discord.Intents.guilds = True, um alle Serverkanäle prüfen zu können.")
        self.sync_task = asyncio.create_task(self._sync_loop(), name="ironshield-dashboard-sync")
        print("[ironshield-dashboard] Direkte Website-Synchronisierung geladen; warte auf Discord-Login.", flush=True)

    async def _remove_legacy_relay_channels(self) -> bool:
        # Only remove the channel that carries our explicit marker. This avoids touching
        # ordinary server channels with similar names.
        marker = "ironshield-dashboard-relay:v1"
        complete = True
        guilds = list(self.bot.guilds)
        removed = 0
        matched = 0
        for guild in guilds:
            # guild.channels includes the initial channel inventory received with the
            # GUILDS intent, including announcement/forum channel types with a topic.
            for channel in list(guild.channels):
                if marker not in (getattr(channel, "topic", "") or ""):
                    continue
                matched += 1
                try:
                    # Deleting the channel removes its messages in one operation and
                    # avoids a request for every historical message in the common case.
                    await channel.delete(reason="Alten IronShield Dashboard-Relay entfernen; Synchronisierung läuft jetzt direkt über HTTPS.")
                    print(f"[ironshield-dashboard] Alter Dashboard-Relay-Kanal in {guild.name} samt Nachrichten gelöscht.", flush=True)
                    removed += 1
                    continue
                except discord.Forbidden:
                    # If channel deletion is forbidden, clean our messages once as a
                    # fallback. Do not rescan the full history on every sync poll.
                    pass
                except discord.HTTPException as error:
                    print(f"[ironshield-dashboard] Discord hat das Löschen des alten Relay-Kanals in {guild.name} abgelehnt: {error}", flush=True)
                    complete = False
                    continue

                if self.bot.user is not None and channel.id not in self._legacy_message_cleanup_done:
                    self._legacy_message_cleanup_done.add(channel.id)
                    try:
                        async for message in channel.history(limit=None):
                            if message.author.id == self.bot.user.id:
                                try:
                                    await message.delete()
                                except (discord.NotFound, discord.Forbidden):
                                    continue
                    except (discord.Forbidden, discord.HTTPException) as error:
                        print(f"[ironshield-dashboard] Alte eigene Nachrichten in {guild.name} konnten nicht einzeln gelöscht werden: {error}", flush=True)
                print(f"[ironshield-dashboard] Für den alten Relay-Kanal in {guild.name} fehlt 'Kanäle verwalten'; eigene Nachrichten wurden einmalig bereinigt.", flush=True)
                complete = False
        print(f"[ironshield-dashboard] Relay-Bereinigung geprüft: {len(guilds)} Server, {matched} markierte Kanäle gefunden, {removed} Kanäle gelöscht.", flush=True)
        return complete

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild) -> None:
        # If the bot is added to another server while running, inspect that server too.
        self._legacy_channels_removed = False
        self._legacy_cleanup_retry_at = 0.0

    async def _bridge_request(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        configured_url = os.getenv("PUBLIC_SITE_URL", "").strip()
        configured_host = (urlsplit(configured_url).hostname or "").lower()
        # Novium is retired for the dashboard. A stale host-panel variable must
        # not send the bot's HTTPS requests back to the old website.
        if not configured_url or configured_host == "ironshield.novium.link":
            configured_url = "https://bot-ironshield-dash.vercel.app"
        parsed_url = urlsplit(configured_url)
        try:
            port = parsed_url.port
        except ValueError as error:
            raise RuntimeError("PUBLIC_SITE_URL enthält einen ungültigen Port.") from error
        hostname = parsed_url.hostname or ""
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False
        if (parsed_url.scheme.lower() != "https"
                or not hostname
                or is_ip_address
                or parsed_url.username is not None
                or parsed_url.password is not None
                or port not in (None, 443)
                or parsed_url.path not in ("", "/")
                or parsed_url.query
                or parsed_url.fragment):
            raise RuntimeError("PUBLIC_SITE_URL muss eine HTTPS-Domain ohne IP, Zugangsdaten, abweichenden Port, Pfad oder Query sein.")
        # Keep the configured HTTPS hostname intact so aiohttp sends it as TLS SNI.
        base_url = f"https://{parsed_url.netloc}"
        # This is a dedicated website-bridge secret, never a Discord bot token.
        # Migrate existing deployments that already share a dedicated random
        # BOT_WEBHOOK_SECRET; neither variable may contain the Discord token.
        bridge_secret = _bridge_secret_from_environment()
        if not base_url.startswith("https://"):
            raise RuntimeError("PUBLIC_SITE_URL muss für die Dashboard-Synchronisierung eine HTTPS-Adresse sein.")
        if len(bridge_secret) < 32:
            raise RuntimeError("DASHBOARD_BRIDGE_SECRET fehlt/ist zu kurz (alternativ BOT_WEBHOOK_SECRET mit mindestens 32 zufälligen Zeichen). Niemals den Discord-Token verwenden.")
        if self._http_session is None or self._http_session.closed:
            timeout = aiohttp.ClientTimeout(total=12, connect=5, sock_read=8)
            # Use aiohttp's default connector and verified SSL context; this keeps
            # hostname/SNI handling on its standard path for the configured host.
            self._http_session = aiohttp.ClientSession(timeout=timeout)
        url = f"{base_url}/api/index.php?route=dashboard_bridge&action={action}"
        async with self._http_session.post(url, json=payload, headers={"X-IronShield-Dashboard-Secret": bridge_secret}) as response:
            try:
                result = await response.json(content_type=None)
            except (aiohttp.ContentTypeError, json.JSONDecodeError):
                result = {}
            if response.status != 200 or not isinstance(result, dict):
                reason = str(result.get("error", "Website hat eine ungültige Antwort gesendet.")) if isinstance(result, dict) else "Website hat eine ungültige Antwort gesendet."
                raise RuntimeError(f"Website-Synchronisierung antwortet mit HTTP {response.status}: {reason}")
            return result

    async def _process_commands(self, commands_from_web: Any) -> None:
        if not isinstance(commands_from_web, list):
            return
        for command in commands_from_web:
            if not isinstance(command, dict):
                continue
            guild_id_text = str(command.get("guild_id", ""))
            command_id = str(command.get("command_id", ""))
            if not re.fullmatch(r"\d{15,22}", guild_id_text) or not re.fullmatch(r"[a-f0-9]{32}", command_id):
                continue
            guild_id = int(guild_id_text)
            try:
                await self._apply_settings(guild_id, command.get("settings"))
                await self._bridge_request("ack", {"guild_id": guild_id_text, "command_id": command_id, "ok": True})
                print(f"[ironshield-dashboard] Ticket-Einstellungen für Guild {guild_id} übernommen.", flush=True)
            except Exception as error:
                print(f"[ironshield-dashboard] Web-Auftrag für Guild {guild_id} fehlgeschlagen: {error}", flush=True)
                try:
                    await self._bridge_request("ack", {
                        "guild_id": guild_id_text,
                        "command_id": command_id,
                        "ok": False,
                        "error": str(error)[:500],
                    })
                except Exception as ack_error:
                    print(f"[ironshield-dashboard] Fehlerstatus für Guild {guild_id} konnte nicht an die Website gemeldet werden: {ack_error}", flush=True)

    async def _sync_loop(self) -> None:
        while True:
            try:
                if not self.bot.is_ready():
                    await asyncio.sleep(2)
                    continue
                if not self._legacy_channels_removed and asyncio.get_running_loop().time() >= self._legacy_cleanup_retry_at:
                    self._legacy_channels_removed = await self._remove_legacy_relay_channels()
                    if self._legacy_channels_removed:
                        self._legacy_cleanup_retry_delay = 60.0
                    else:
                        self._legacy_cleanup_retry_at = asyncio.get_running_loop().time() + self._legacy_cleanup_retry_delay
                        self._legacy_cleanup_retry_delay = min(self._legacy_cleanup_retry_delay * 2, 900.0)
                # Keep the presence/status heartbeat independent of the ticket Cog.
                # A missing or temporarily broken ticket extension must not make the
                # whole bot appear offline in the website dashboard.
                guilds = list(self.bot.guilds)
                try:
                    module = self._ticket_module()
                    self._ticket_module_error_logged = False
                    # Keep each HTTPS request small. Some large bots are in more
                    # than a thousand guilds, and the website intentionally caps
                    # bridge requests at 2 MiB. Guild presence is sent in full;
                    # settings are refreshed in rotating batches.
                    batch_size = min(100, len(guilds))
                    if guilds:
                        start = self._settings_sync_cursor % len(guilds)
                        batch = (guilds[start:start + batch_size]
                                 if start + batch_size <= len(guilds)
                                 else guilds[start:] + guilds[:batch_size - (len(guilds) - start)])
                        self._settings_sync_cursor = (start + len(batch)) % len(guilds)
                    else:
                        batch = []
                    settings = {str(guild.id): self._snapshot(module, guild.id) for guild in batch}
                except Exception as error:
                    module = None
                    settings = {}
                    if not self._ticket_module_error_logged:
                        print(f"[ironshield-dashboard] Ticket-Einstellungen derzeit nicht verfügbar; Status wird trotzdem gemeldet: {error}", flush=True)
                        self._ticket_module_error_logged = True
                snapshot = {
                    "bot_id": str(self.bot.user.id) if self.bot.user else "",
                    "guild_ids": [str(guild.id) for guild in guilds],
                    "settings": settings,
                }
                result = await self._bridge_request("poll", snapshot)
                await self._process_commands(result.get("commands", []))
                if not self.sync_connected:
                    print(f"[ironshield-dashboard] Website-Synchronisierung verbunden; {len(guilds)} Server erkannt, Einstellungen werden in Portionen von 100 aktualisiert.", flush=True)
                self.sync_connected = True
                self._sync_error_logged = False
                await asyncio.sleep(15)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self.sync_connected = False
                if not self._sync_error_logged:
                    print(f"[ironshield-dashboard] Website-Synchronisierung fehlgeschlagen (API /api/index.php?route=dashboard_bridge&action=poll): {error}", flush=True)
                    traceback.print_exc()
                    self._sync_error_logged = True
                await asyncio.sleep(30)

    async def cog_unload(self) -> None:
        if self.sync_task is not None:
            self.sync_task.cancel()
            self.sync_task = None
        if self._http_session is not None and not self._http_session.closed:
            await self._http_session.close()


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(IronShieldDashboardCog(bot))
