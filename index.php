<?php
declare(strict_types=1);

function load_env_file(string $path): void
{
    if (!is_file($path)) return;
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        if (!str_contains($line, '=')) continue;
        [$key, $value] = explode('=', $line, 2);
        $key = trim($key);
        $value = trim(trim($value), "\"'");
        if ($key !== '' && getenv($key) === false) putenv("$key=$value");
    }
}

load_env_file(__DIR__ . '/.env');
define('IRONSHIELD_APP', true);
require_once __DIR__ . '/bot/discord.php';
require_once __DIR__ . '/includes/storage.php';
$route = (string)($_GET['route'] ?? '');
if (strtolower((string)(getenv('VERCEL') ?: '')) === '1' && !ironshield_storage_enabled() && $route !== '') {
    json_response(503, ['error' => 'DATABASE_URL ist auf Vercel erforderlich, damit Sitzungen, Tickets und Dashboard-Einstellungen dauerhaft gespeichert werden.']);
}
if (PHP_SAPI === 'cli-server' && !defined('IRONSHIELD_API_ENTRY')) {
    $requestPath = rawurldecode((string)(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/'));
    if (preg_match('#(?:^|/)\.(?!well-known(?:/|$))#', $requestPath) === 1) {
        http_response_code(404);
        exit;
    }
    if ($requestPath === '/api/index.php') return false;
    $publicRoot = realpath(__DIR__);
    $requestedFile = realpath(__DIR__ . $requestPath);
    $allowedStaticExtensions = ['html', 'js', 'css', 'png', 'webp', 'svg', 'ico'];
    if ($publicRoot !== false
        && $requestedFile !== false
        && is_file($requestedFile)
        && str_starts_with($requestedFile, $publicRoot . DIRECTORY_SEPARATOR)
        && in_array(strtolower(pathinfo($requestedFile, PATHINFO_EXTENSION)), $allowedStaticExtensions, true)) return false;
    if ($requestPath !== '/' && $requestPath !== '/index.php') {
        http_response_code(404);
        exit;
    }
}
$forwardedProto = strtolower(trim(explode(',', (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''))[0]));
$requestHost = strtolower((string)(parse_url('https://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST) ?: ''));
$secureCookie = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') || $forwardedProto === 'https' || $requestHost === 'ironshield.novium.link';
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
ini_set('session.gc_maxlifetime', '28800');
session_name('is_sess');
session_set_cookie_params(['lifetime' => 28800, 'path' => '/', 'secure' => $secureCookie, 'httponly' => true, 'samesite' => 'Lax']);
if (ironshield_storage_enabled()) session_set_save_handler(new IronShieldPostgresSessionHandler(), true);
session_start();
if (isset($_SESSION['last_activity']) && time() - (int)$_SESSION['last_activity'] > 28800) {
    $_SESSION = [];
    session_regenerate_id(true);
}
$_SESSION['last_activity'] = time();

function config(string $key, string $default = ''): string
{
    $value = getenv($key);
    return $value === false ? $default : $value;
}

function discord_redirect_uri(): string
{
    $host = strtolower((string)(parse_url('https://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST) ?: ''));
    if ($host === 'ironshield.novium.link') return 'https://ironshield.novium.link/api/index.php?route=callback';
    if (in_array($host, ['localhost', '127.0.0.1'], true)) return 'http://' . $host . ':8000/api/index.php?route=callback';
    return config('DISCORD_REDIRECT_URI');
}

function oauth_state_cookie_name(string $state): string
{
    return 'is_oauth_' . substr(hash('sha256', $state), 0, 24);
}

function json_response(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function failure_page(string $message, int $status = 500): never
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    readfile(__DIR__ . '/error.html');
    exit;
}

function clear_oauth_state_cookie(bool $secureCookie): void
{
    setcookie('is_state', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $secureCookie, 'httponly' => true, 'samesite' => 'Lax']);
}

function discord_request(string $path, string $authorization, string $method = 'GET', ?array $form = null, int $timeoutSeconds = 20): array
{
    $headers = ['User-Agent: IronShieldDashboard/1.0', 'Accept: application/json'];
    if ($authorization !== '') $headers[] = "Authorization: $authorization";
    $content = '';
    if ($form !== null) {
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        $content = http_build_query($form);
    }
    $context = stream_context_create(['http' => ['method' => $method, 'header' => implode("\r\n", $headers), 'content' => $content, 'ignore_errors' => true, 'timeout' => max(2, min(20, $timeoutSeconds))]]);
    $raw = @file_get_contents('https://discord.com/api/v10' . $path, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d+)/', $header, $matches)) $status = (int)$matches[1];
    }
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if ($status < 200 || $status >= 300 || !is_array($data)) {
        $message = is_array($data) ? ($data['message'] ?? "Discord antwortet mit Status $status.") : "Discord ist gerade nicht erreichbar (Status $status).";
        throw new RuntimeException((string)$message, $status);
    }
    return $data;
}

function dashboard_bot_webapi_request(string $command, array $args, string $actor): array
{
    if (!extension_loaded('openssl')) throw new RuntimeException('PHP-OpenSSL ist auf dem Website-Host nicht aktiviert.');
    if (preg_match('/^\d{15,20}$/', $actor) !== 1) throw new RuntimeException('Discord-Nutzer-ID ist ungültig.');

    $baseUrl = rtrim(trim(config('DASHBOARD_WEBAPI_URL')), '/');
    $secretPath = trim(config('DASHBOARD_WEBAPI_PATH'));
    $hmacKey = config('DASHBOARD_WEBAPI_HMAC');
    $serverCaFile = trim(config('DASHBOARD_WEBAPI_SERVER_CA_FILE'));
    $clientCert = trim(config('DASHBOARD_WEBAPI_CLIENT_CERT_FILE'));
    $clientKey = trim(config('DASHBOARD_WEBAPI_CLIENT_KEY_FILE'));
    $parts = parse_url($baseUrl);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
        || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
        || isset($parts['query']) || isset($parts['fragment']) || isset($parts['path'])) {
        throw new RuntimeException('DASHBOARD_WEBAPI_URL muss eine HTTPS-Basisadresse ohne Pfad sein.');
    }
    if (preg_match('/^[a-f0-9]{64}$/i', $secretPath) !== 1 || strlen($hmacKey) < 32) {
        throw new RuntimeException('Bot-WebAPI-Pfad oder HMAC-Schlüssel ist nicht konfiguriert.');
    }
    if (!is_readable($serverCaFile) || !is_readable($clientCert) || ($clientKey !== '' && !is_readable($clientKey))) {
        throw new RuntimeException('Bot-WebAPI-CA oder Client-Zertifikat ist auf dem Website-Host nicht lesbar.');
    }

    $body = json_encode(['cmd' => $command, 'args' => $args], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $timestamp = (string)time();
    $nonce = bin2hex(random_bytes(16));
    $canonical = implode("\n", ['v1', $timestamp, $nonce, $actor, hash('sha256', $body)]);
    $signature = hash_hmac('sha256', $canonical, $hmacKey);
    $headers = [
        'Content-Type: application/json',
        'Accept: application/json',
        'X-IS-Ts: ' . $timestamp,
        'X-IS-Nonce: ' . $nonce,
        'X-IS-Actor: ' . $actor,
        'X-IS-Sig: ' . $signature,
    ];
    $ssl = [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'peer_name' => (string)$parts['host'],
        'SNI_enabled' => true,
        'cafile' => $serverCaFile,
        'local_cert' => $clientCert,
        'allow_self_signed' => false,
    ];
    if ($clientKey !== '') $ssl['local_pk'] = $clientKey;
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => $body,
            'ignore_errors' => true,
            'timeout' => 12,
            'protocol_version' => 1.1,
        ],
        'ssl' => $ssl,
    ]);
    $url = $baseUrl . '/' . $secretPath . '/rpc';
    $raw = @file_get_contents($url, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d+)/', $header, $matches) === 1) $status = (int)$matches[1];
    }
    $response = is_string($raw) ? json_decode($raw, true) : null;
    if ($status < 200 || $status >= 300 || !is_array($response) || empty($response['ok']) || !is_array($response['data'] ?? null)) {
        throw new RuntimeException('Bot-WebAPI antwortet nicht erfolgreich (HTTP ' . $status . '). Prüfe mTLS, HMAC, Actor-Freigabe und Bot-Log.');
    }
    return $response['data'];
}

$clientId = config('DISCORD_CLIENT_ID', '1479835689284669461');
$botClientId = trim(config('DISCORD_BOT_CLIENT_ID')) ?: $clientId;

function guild_can_manage(array $guild): bool
{
    $rawPermissions = $guild['permissions'] ?? $guild['permissions_new'] ?? '0';
    $permissions = is_numeric($rawPermissions) ? (int)$rawPermissions : 0;
    return !empty($guild['owner']) || (($permissions & 0x28) !== 0);
}

function dashboard_bridge_file(): string
{
    $directory = __DIR__ . DIRECTORY_SEPARATOR . '.ironshield-private';
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) throw new RuntimeException('Privater Dashboard-Speicher konnte nicht angelegt werden.');
    return $directory . DIRECTORY_SEPARATOR . 'dashboard-bridge.json';
}

function dashboard_bot_token(): string
{
    return trim(config('DASHBOARD_BOT_TOKEN'));
}

function dashboard_bridge_secret(): string
{
    // Keep compatibility with the long-standing, separately generated bridge
    // secret while deployments migrate to the explicit dashboard variable.
    return trim(config('DASHBOARD_BRIDGE_SECRET') ?: config('BOT_WEBHOOK_SECRET'));
}

function dashboard_bridge_change(callable $callback): mixed
{
    if (ironshield_storage_enabled()) {
        return ironshield_state_change('dashboard_bridge', ['guild_ids' => [], 'checked_guild_ids' => [], 'settings' => [], 'pending' => [], 'last_seen' => 0, 'token_verified_at' => 0, 'bot_id' => ''], $callback, true);
    }
    $handle = @fopen(dashboard_bridge_file(), 'c+');
    if ($handle === false || !flock($handle, LOCK_EX)) throw new RuntimeException('Privater Dashboard-Speicher ist nicht verfügbar.');
    rewind($handle);
    $state = json_decode(stream_get_contents($handle) ?: '', true);
    if (!is_array($state)) $state = ['guild_ids' => [], 'checked_guild_ids' => [], 'settings' => [], 'pending' => [], 'last_seen' => 0, 'token_verified_at' => 0, 'bot_id' => ''];
    try {
        $result = $callback($state);
        rewind($handle);
        ftruncate($handle, 0);
        $encoded = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $length = strlen($encoded);
        $written = 0;
        while ($written < $length) {
            $chunk = fwrite($handle, substr($encoded, $written));
            if ($chunk === false || $chunk === 0) throw new RuntimeException('Dashboard-Speicher konnte nicht vollständig geschrieben werden.');
            $written += $chunk;
        }
        if (!fflush($handle)) throw new RuntimeException('Dashboard-Speicher konnte nicht dauerhaft gesichert werden.');
        flock($handle, LOCK_UN);
        fclose($handle);
        return $result;
    } catch (Throwable $error) {
        flock($handle, LOCK_UN);
        fclose($handle);
        throw $error;
    }
}

function dashboard_bridge_read(bool $forceRefresh = false, array $guildIdsToCheck = [], ?string $settingsGuildId = null): array
{
    $token = dashboard_bot_token();
    $cached = dashboard_bridge_change(static fn(array &$state): array => $state);
    if (!$forceRefresh) return $cached;
    if (strlen($token) < 32) return dashboard_bridge_change(static function (array &$state): array { $state['relay_error'] = 'DASHBOARD_BOT_TOKEN fehlt oder ist ungültig in den Umgebungsvariablen der Website.'; $state['cache_fetched_at'] = time(); return $state; });
    $state = $cached;
    $state['guild_ids'] = array_values(array_unique(array_map('strval', $state['guild_ids'] ?? [])));
    $state['checked_guild_ids'] = array_values(array_unique(array_map('strval', $state['checked_guild_ids'] ?? [])));
    $state['guild_checked_at'] = is_array($state['guild_checked_at'] ?? null) ? $state['guild_checked_at'] : [];
    $state['settings'] = is_array($state['settings'] ?? null) ? $state['settings'] : [];
    $state['pending'] = is_array($state['pending'] ?? null) ? $state['pending'] : [];
    $state['cache_fetched_at'] = time();
    if ((int)($state['token_verified_at'] ?? 0) < time() - 90 || !preg_match('/^\d{15,22}$/', (string)($state['bot_id'] ?? ''))) {
        try {
            $identity = discord_request('/users/@me', 'Bot ' . $token, 'GET', null, 4);
            $verifiedBotId = (string)($identity['id'] ?? '');
            $expected = trim(config('DISCORD_BOT_CLIENT_ID'));
            if (!preg_match('/^\d{15,22}$/', $verifiedBotId) || ($expected !== '' && !hash_equals($expected, $verifiedBotId))) throw new RuntimeException('Der Website-Token gehört zu einer anderen Bot-Anwendung.');
            $state['bot_id'] = $verifiedBotId;
            $state['token_verified_at'] = time();
        } catch (Throwable $error) {
            $message = $error->getCode() === 401
                ? 'Discord hat den Bot-Token auf dem Website-Host abgelehnt (401). Setze dort denselben gültigen Token als DASHBOARD_BOT_TOKEN wie beim Bot.'
                : $error->getMessage();
            return dashboard_bridge_change(static function (array &$stored) use ($message): array { $stored['relay_error'] = $message; $stored['token_verified_at'] = 0; $stored['cache_fetched_at'] = time(); return $stored; });
        }
    }

    $now = time();
    $requested = array_values(array_unique(array_filter(array_map('strval', $guildIdsToCheck), static fn(string $id): bool => preg_match('/^\d{15,22}$/', $id) === 1)));
    foreach ($requested as $guildId) {
        if ((int)($state['guild_checked_at'][$guildId] ?? 0) > $now - 60 && ($settingsGuildId !== $guildId || isset($state['settings'][$guildId]))) continue;
        if (preg_match('/^\d{15,22}$/', $guildId) !== 1) continue;
        try {
            $botGuild = discord_request('/guilds/' . rawurlencode($guildId), 'Bot ' . $token, 'GET', null, 3);
            if ((string)($botGuild['id'] ?? '') !== $guildId) continue;
        } catch (RuntimeException $error) {
            if (in_array($error->getCode(), [403, 404], true)) {
                $state['checked_guild_ids'][] = $guildId;
                $state['guild_checked_at'][$guildId] = time();
                $state['guild_ids'] = array_values(array_diff($state['guild_ids'], [$guildId]));
            }
            continue;
        } catch (Throwable) {
            continue;
        }
        // Each request verifies only its small batch; the browser can render
        // the rest of the dashboard while later batches are checked.
        $state['checked_guild_ids'][] = $guildId;
        $state['guild_ids'][] = $guildId;
        $state['guild_checked_at'][$guildId] = time();
    }
    $state['guild_ids'] = array_values(array_unique($state['guild_ids']));
    $state['checked_guild_ids'] = array_values(array_unique($state['checked_guild_ids']));
    $state['cache_fetched_at'] = time();
    return dashboard_bridge_change(static function (array &$stored) use ($state): array {
        $latestLastSeen = (int)($stored['last_seen'] ?? 0);
        $latestPending = is_array($stored['pending'] ?? null) ? $stored['pending'] : [];
        $latestBotState = [];
        if ($latestLastSeen > (int)($state['last_seen'] ?? 0)) {
            foreach (['guild_ids', 'settings', 'bot_id', 'last_seen', 'bridge_secret_verified_at', 'bridge_secret_hash'] as $key) {
                if (array_key_exists($key, $stored)) $latestBotState[$key] = $stored[$key];
            }
        }
        $stored = array_merge($stored, $state, $latestBotState);
        $stored['pending'] = $latestPending;
        $stored['settings'] = is_array($stored['settings'] ?? null) ? $stored['settings'] : [];
        foreach ($latestPending as $guildId => $command) {
            if (is_array($command) && is_array($command['settings'] ?? null)) $stored['settings'][(string)$guildId] = $command['settings'];
        }
        unset($stored['relay_error']);
        return $stored;
    });
}

if ($route === 'dashboard_refresh') {
    if (empty($_SESSION['user'])) json_response(401, ['error' => 'login_required']);
    $webApiActor = (string)($_SESSION['user']['id'] ?? '');
    $expectedGuilds = array_values(array_filter(array_map(static fn(array $guild): string => (string)($guild['id'] ?? ''), $_SESSION['discord_guilds'] ?? [])));
    $requestedGuild = (string)($_GET['guild'] ?? '');
    $cache = dashboard_bridge_read();
    $checkedAt = is_array($cache['guild_checked_at'] ?? null) ? $cache['guild_checked_at'] : [];
    $staleGuilds = array_values(array_filter($expectedGuilds, static fn(string $id): bool => (int)($checkedAt[$id] ?? 0) <= time() - 60));
    $relayStatusStale = (int)($cache['last_seen'] ?? 0) <= time() - 45;
    $settingsGuildId = in_array($requestedGuild, $expectedGuilds, true) ? $requestedGuild : null;
    if ($settingsGuildId !== null) $batchGuilds = [$settingsGuildId];
    elseif ($staleGuilds) $batchGuilds = array_slice($staleGuilds, 0, 3);
    elseif ($relayStatusStale) {
        $cachedBotGuilds = array_values(array_intersect($expectedGuilds, array_map('strval', $cache['guild_ids'] ?? [])));
        $batchGuilds = $cachedBotGuilds ? [reset($cachedBotGuilds)] : array_slice($expectedGuilds, 0, 3);
    } else $batchGuilds = [];
    session_write_close();
    $state = dashboard_bridge_read(true, $batchGuilds, $settingsGuildId);
    $webApiConfigured = config('DASHBOARD_WEBAPI_URL') !== '';
    $webApiOnline = false;
    $webApiError = '';
    if ($webApiConfigured) {
        try {
            $webApiStatus = dashboard_bot_webapi_request('status.public', [], $webApiActor);
            $webApiOnline = !empty($webApiStatus['online']);
        } catch (Throwable $error) {
            $webApiError = $error->getMessage();
        }
    }
    $lastSeen = (int)($state['last_seen'] ?? 0);
    $checkedGuilds = array_map('strval', $state['checked_guild_ids'] ?? []);
    $guildCheckedAt = is_array($state['guild_checked_at'] ?? null) ? $state['guild_checked_at'] : [];
    $staleRemaining = array_values(array_filter($expectedGuilds, static fn(string $id): bool => (int)($guildCheckedAt[$id] ?? 0) <= time() - 60));
    $presentGuilds = array_map('strval', $state['guild_ids'] ?? []);
    $pendingBatchGuilds = array_values(array_intersect($batchGuilds, $staleRemaining));
    json_response(200, [
        'connected' => $webApiConfigured ? $webApiOnline : $lastSeen >= time() - 90,
        'last_seen' => $webApiConfigured ? ($webApiOnline ? time() : 0) : $lastSeen,
        'connection_error' => $webApiError,
        'relay_refresh_needed' => $lastSeen <= time() - 45 && $settingsGuildId === null,
        'verified' => (int)($state['token_verified_at'] ?? 0) >= time() - 90,
        'check_complete' => count($staleRemaining) === 0,
        'target_checked' => $settingsGuildId !== null && (int)($guildCheckedAt[$settingsGuildId] ?? 0) > time() - 60,
        'bot_present' => $settingsGuildId !== null && in_array($settingsGuildId, $presentGuilds, true),
        'settings_loaded' => $settingsGuildId !== null && isset($state['settings'][$settingsGuildId]),
        'batch_guild_ids' => $batchGuilds,
        'pending_guild_ids' => $pendingBatchGuilds,
        'checked_guild_ids' => $checkedGuilds,
        'guild_ids' => $presentGuilds,
        'guild_count' => count($state['guild_ids'] ?? []),
        'error' => $webApiConfigured ? $webApiError : (string)($state['relay_error'] ?? ''),
    ]);
}

if ($route === 'dashboard_bridge') {
    $providedSecret = (string)($_SERVER['HTTP_X_IRONSHIELD_DASHBOARD_SECRET'] ?? '');
    $expectedSecret = dashboard_bridge_secret();
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_response(405, ['error' => 'method_not_allowed']);
    if (strlen($expectedSecret) < 32) json_response(503, ['error' => 'dashboard_bridge_secret_missing']);
    if (!hash_equals($expectedSecret, $providedSecret)) json_response(403, ['error' => 'unauthorized']);
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 2 * 1024 * 1024) json_response(413, ['error' => 'request_too_large']);
    $input = fopen('php://input', 'rb');
    $rawPayload = $input === false ? false : stream_get_contents($input, 2 * 1024 * 1024 + 1);
    if (is_resource($input)) fclose($input);
    if (!is_string($rawPayload) || strlen($rawPayload) > 2 * 1024 * 1024) json_response(413, ['error' => 'request_too_large']);
    $payload = json_decode($rawPayload, true);
    if (!is_array($payload)) json_response(400, ['error' => 'invalid_json']);
    $action = (string)($_GET['action'] ?? '');
    if (!in_array($action, ['poll', 'ack'], true)) json_response(404, ['error' => 'not_found']);
    $bridgeSnapshot = dashboard_bridge_read();
    $knownBridgeBotId = (string)($bridgeSnapshot['bot_id'] ?? '');
    $knownBridgeLastSeen = (int)($bridgeSnapshot['last_seen'] ?? 0);
    $declaredBotId = (string)($payload['bot_id'] ?? '');
    $expectedBotId = trim(config('DISCORD_BOT_CLIENT_ID')) ?: $clientId;
    if ($action === 'poll' && $expectedBotId !== '' && !hash_equals($expectedBotId, $declaredBotId)) json_response(403, ['error' => 'wrong_bot']);
    if ($action === 'poll' && $expectedBotId === '' && $knownBridgeBotId !== '' && !hash_equals($knownBridgeBotId, $declaredBotId)) {
        $staleConnection = $knownBridgeLastSeen < time() - 90;
        if ($action !== 'poll' || !$staleConnection) json_response(403, ['error' => 'wrong_bot']);
    }
    if ($action === 'poll' && preg_match('/^\d{15,22}$/', $declaredBotId) !== 1) json_response(400, ['error' => 'invalid_bot_id']);
    try {
        if ($action === 'poll') {
            $result = dashboard_bridge_change(static function (array &$state) use ($payload): array {
                $guildIds = $payload['guild_ids'] ?? [];
                $settings = $payload['settings'] ?? [];
                if (!is_array($guildIds) || !is_array($settings)) throw new InvalidArgumentException('invalid_sync_data');
                $state['guild_ids'] = array_values(array_unique(array_filter(array_map('strval', $guildIds), static fn(string $id): bool => preg_match('/^\d{15,22}$/', $id) === 1)));
                $storedSettings = is_array($state['settings'] ?? null) ? $state['settings'] : [];
                foreach ($settings as $guildId => $guildSettings) {
                    $guildId = (string)$guildId;
                    if (!isset($state['pending'][$guildId])) $storedSettings[$guildId] = $guildSettings;
                }
                $state['settings'] = array_intersect_key($storedSettings, array_flip($state['guild_ids']));
                $state['bot_id'] = preg_match('/^\d{15,22}$/', (string)($payload['bot_id'] ?? '')) === 1 ? (string)$payload['bot_id'] : '';
                $state['last_seen'] = time();
                $state['bridge_secret_verified_at'] = time();
                $state['bridge_secret_hash'] = hash('sha256', (string)($_SERVER['HTTP_X_IRONSHIELD_DASHBOARD_SECRET'] ?? ''));
                unset($state['relay_error']);
                $commands = array_values(array_filter($state['pending'] ?? [], static fn($command): bool => is_array($command) && ($command['status'] ?? 'queued') === 'queued'));
                return ['commands' => $commands];
            });
            session_write_close();
            json_response(200, $result);
        }
        if ($action === 'ack') {
            $result = dashboard_bridge_change(static function (array &$state) use ($payload): array {
                $guildId = (string)($payload['guild_id'] ?? '');
                $commandId = (string)($payload['command_id'] ?? '');
                $pending = $state['pending'][$guildId] ?? null;
                if (is_array($pending) && hash_equals((string)($pending['command_id'] ?? ''), $commandId)) {
                    $ok = ($payload['ok'] ?? false) === true;
                    $state['command_results'][$guildId] = [
                        'command_id' => $commandId,
                        'ok' => $ok,
                        'message' => $ok ? 'Der Bot hat die Einstellungen übernommen und gespeichert.' : substr((string)($payload['error'] ?? 'Der Bot konnte die Einstellungen nicht speichern.'), 0, 500),
                        'updated_at' => time(),
                    ];
                    if ($ok) unset($state['pending'][$guildId]);
                    else $state['pending'][$guildId]['status'] = 'failed';
                }
                return ['acknowledged' => true];
            });
            session_write_close();
            json_response(200, $result);
        }
    } catch (Throwable $error) {
        session_write_close();
        json_response(400, ['error' => $error->getMessage()]);
    }
}

function text_initial(string $value): string
{
    if (preg_match('/^./u', $value, $match) === 1) return $match[0];
    return substr($value, 0, 1);
}

if ($route === 'dashboard_module_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $guildId = (string)($_POST['guild_id'] ?? '');
    $moduleKey = (string)($_POST['module_key'] ?? '');
    $enabledRaw = (string)($_POST['enabled'] ?? '');
    $guild = null;
    foreach (($_SESSION['discord_guilds'] ?? []) as $item) if (($item['id'] ?? '') === $guildId) $guild = $item;
    if (empty($_SESSION['user']) || !$guild || (empty($guild['manage']) && !guild_can_manage($guild))
        || !hash_equals((string)($_SESSION['csrf'] ?? ''), (string)($_POST['csrf'] ?? ''))
        || preg_match('/^\d{15,22}$/', $guildId) !== 1
        || preg_match('/^[a-z0-9_-]{1,80}$/', $moduleKey) !== 1
        || !in_array($enabledRaw, ['0', '1'], true)) {
        failure_page('Diese Bot-Einstellung darf nicht geändert werden. Bitte melde dich erneut an.', 403);
    }
    try {
        dashboard_bot_webapi_request('modules.set', [
            'guild_id' => $guildId,
            'key' => $moduleKey,
            'enabled' => $enabledRaw === '1',
        ], (string)$_SESSION['user']['id']);
        $_SESSION['dashboard_notice'] = 'Bot-Modul wurde aktualisiert.';
    } catch (Throwable $error) {
        $_SESSION['dashboard_error'] = $error->getMessage();
    }
    header('Location: /dashboard.html?guild=' . rawurlencode($guildId), true, 303);
    exit;
}

if ($route === 'dashboard_tickets_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $guildId = (string)($_POST['guild_id'] ?? '');
    $guild = null;
    foreach (($_SESSION['discord_guilds'] ?? []) as $item) if (($item['id'] ?? '') === $guildId) $guild = $item;
    if (empty($_SESSION['user']) || !$guild || (empty($guild['manage']) && !guild_can_manage($guild)) || !hash_equals((string)($_SESSION['csrf'] ?? ''), (string)($_POST['csrf'] ?? ''))) failure_page('Du darfst diesen Server nicht verwalten. Bitte melde dich erneut an.', 403);
    $settings = json_decode((string)($_POST['settings'] ?? ''));
    if (!($settings instanceof stdClass)) $_SESSION['dashboard_error'] = 'Die Ticket-Einstellungen enthalten kein gültiges JSON-Objekt.';
    else try {
        if (strlen(dashboard_bridge_secret()) < 32) throw new RuntimeException('Auf Website und Bot muss derselbe DASHBOARD_BRIDGE_SECRET (oder vorübergehend BOT_WEBHOOK_SECRET) gesetzt sein.');
        $command = json_encode(['guild_id' => $guildId, 'command_id' => bin2hex(random_bytes(16)), 'settings' => json_decode(json_encode($settings, JSON_THROW_ON_ERROR), true)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $commandData = json_decode($command, true, 32, JSON_THROW_ON_ERROR);
        dashboard_bridge_change(static function (array &$state) use ($guildId, $commandData): array {
            $state['pending'] = is_array($state['pending'] ?? null) ? $state['pending'] : [];
            $commandData['status'] = 'queued';
            $state['pending'][$guildId] = $commandData;
            $state['command_results'] = is_array($state['command_results'] ?? null) ? $state['command_results'] : [];
            unset($state['command_results'][$guildId]);
            $state['settings'] = is_array($state['settings'] ?? null) ? $state['settings'] : [];
            $state['settings'][$guildId] = $commandData['settings'];
            return [];
        });
        $_SESSION['dashboard_notice'] = 'Einstellungen sicher in der Website-Warteschlange gespeichert. Der Bot bestätigt die Übernahme beim nächsten Abgleich.';
    } catch (Throwable $error) { $_SESSION['dashboard_error'] = $error->getMessage(); }
    header('Location: /dashboard.html?guild=' . rawurlencode($guildId), true, 303); exit;
}

if ($route === 'dashboard_options') {
    $guildId = (string)($_GET['guild'] ?? '');
    $guild = null;
    foreach (($_SESSION['discord_guilds'] ?? []) as $item) if ((string)($item['id'] ?? '') === $guildId) $guild = $item;
    if (empty($_SESSION['user']) || !$guild || (empty($guild['manage']) && !guild_can_manage($guild)) || preg_match('/^\d{15,22}$/', $guildId) !== 1) json_response(403, ['error' => 'forbidden']);
    try {
        $token = dashboard_bot_token();
        if (strlen($token) < 32) throw new RuntimeException('Bot-Verbindung ist nicht verfügbar.');
            $channels = discord_request('/guilds/' . rawurlencode($guildId) . '/channels', 'Bot ' . $token, 'GET', null, 5);
            $roles = discord_request('/guilds/' . rawurlencode($guildId) . '/roles', 'Bot ' . $token, 'GET', null, 5);
        $channelOptions = [];
        foreach ($channels as $channel) if (is_array($channel) && in_array((int)($channel['type'] ?? -1), [0, 5, 15], true)) $channelOptions[] = ['id' => (string)$channel['id'], 'name' => (string)($channel['name'] ?? 'Kanal'), 'type' => (int)$channel['type']];
        $categoryOptions = [];
        foreach ($channels as $channel) if (is_array($channel) && (int)($channel['type'] ?? -1) === 4) $categoryOptions[] = ['id' => (string)$channel['id'], 'name' => (string)($channel['name'] ?? 'Kategorie')];
        $roleOptions = [];
        foreach ($roles as $role) if (is_array($role) && !empty($role['id']) && (string)$role['id'] !== $guildId && empty($role['managed'])) $roleOptions[] = ['id' => (string)$role['id'], 'name' => (string)($role['name'] ?? 'Rolle')];
        json_response(200, ['channels' => $channelOptions, 'categories' => $categoryOptions, 'roles' => $roleOptions]);
    } catch (Throwable $error) { json_response(502, ['error' => 'Discord-Auswahl konnte nicht geladen werden: ' . $error->getMessage()]); }
}

if ($route === 'dashboard_data') {
    if (empty($_SESSION['user'])) json_response(401, ['error' => 'login_required']);
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24));
    $guilds = is_array($_SESSION['discord_guilds'] ?? null) ? $_SESSION['discord_guilds'] : [];
    $state = dashboard_bridge_read();
    $checkedGuildIds = array_map('strval', $state['checked_guild_ids'] ?? []);
    $presentGuildIds = array_map('strval', $state['guild_ids'] ?? []);
    $botTokenVerified = (int)($state['token_verified_at'] ?? 0) >= time() - 90;
    $lastSeen = (int)($state['last_seen'] ?? 0);
    $connected = $lastSeen >= time() - 90;
    $connectionError = '';
    $actorId = (string)($_SESSION['user']['id'] ?? '');
    if (config('DASHBOARD_WEBAPI_URL') !== '') {
        try {
            $status = dashboard_bot_webapi_request('status.public', [], $actorId);
            $connected = !empty($status['online']);
            if ($connected) $lastSeen = time();
        } catch (Throwable $error) {
            $connectionError = $error->getMessage();
            $connected = false;
        }
    }
    $guildData = [];
    foreach ($guilds as $guild) {
        if (!is_array($guild) || empty($guild['id'])) continue;
        $id = (string)$guild['id'];
        $guildData[] = [
            'id' => $id,
            'name' => (string)($guild['name'] ?? 'Discord-Server'),
            'icon' => !empty($guild['icon']) ? 'https://cdn.discordapp.com/icons/' . rawurlencode($id) . '/' . rawurlencode((string)$guild['icon']) . '.png?size=96' : '',
            'manage' => !empty($guild['manage']) || guild_can_manage($guild),
            'checked' => $botTokenVerified && in_array($id, $checkedGuildIds, true),
            'present' => $botTokenVerified && in_array($id, $presentGuildIds, true),
        ];
    }
    $selectedGuildId = (string)($_GET['guild'] ?? '');
    $selected = null;
    foreach ($guildData as $guild) if ($guild['id'] === $selectedGuildId) { $selected = $guild; break; }
    $ticketSettings = null;
    if ($selected && $selected['manage'] && $selected['present']) {
        $candidate = $state['settings'][$selectedGuildId] ?? null;
        if (is_array($candidate) && isset($candidate['guild'], $candidate['panels'])) $ticketSettings = $candidate;
    }
    $modules = null;
    $modulesError = '';
    if ($selected && $selected['manage']) {
        if (config('DASHBOARD_WEBAPI_URL') === '') $modulesError = 'Die direkte Bot-WebAPI ist auf dem Website-Host noch nicht konfiguriert.';
        else {
            try { $modules = dashboard_bot_webapi_request('modules.list', ['guild_id' => $selectedGuildId], $actorId); }
            catch (Throwable $error) { $modulesError = $error->getMessage(); }
        }
    }
    $relayError = (string)($state['relay_error'] ?? '');
    json_response(200, [
        'user' => ['id' => $actorId, 'username' => (string)($_SESSION['user']['username'] ?? '')],
        'csrf' => (string)$_SESSION['csrf'],
        'guilds' => $guildData,
        'selected' => $selected,
        'connected' => $connected,
        'last_seen' => $lastSeen,
        'connection_error' => $connectionError,
        'relay_error' => $relayError,
        'bot_token_verified' => $botTokenVerified,
        'ticket_settings' => $ticketSettings,
        'modules' => $modules,
        'modules_error' => $modulesError,
        'invite_base' => 'https://discord.com/oauth2/authorize?' . http_build_query(['client_id' => $botClientId, 'permissions' => (string)(1024 + 65536), 'scope' => 'bot applications.commands']),
    ]);
}

if ($route === 'dashboard' && !empty($_SESSION['user'])) {
    $target = '/dashboard.html';
    if (isset($_GET['guild'])) $target .= '?guild=' . rawurlencode((string)$_GET['guild']);
    header('Location: ' . $target, true, 302);
    exit;
}

if ($route === 'dashboard') {
    header('Location: /api/index.php?route=dashboard_login', true, 302);
    exit;
}

require_once __DIR__ . '/includes/team.php';
if ($route === 'public_announcements') {
    try {
        $announcements = team_store(static function (array &$data): array {
            $now = time();
            $items = array_values(array_filter($data['announcements'] ?? [], static fn($item): bool => is_array($item) && (empty($item['expiresAt']) || (int)$item['expiresAt'] > $now)));
            return array_slice(array_reverse($items), 0, 6);
        });
        json_response(200, ['announcements' => array_map(static fn(array $item): array => ['title' => (string)($item['title'] ?? ''), 'body' => (string)($item['body'] ?? ''), 'created_by' => (string)($item['createdBy'] ?? ''), 'created_at' => (int)($item['createdAt'] ?? 0)], $announcements)]);
    } catch (Throwable $error) {
        error_log('Public announcements unavailable: ' . get_class($error));
        json_response(503, ['error' => 'Ankündigungen sind vorübergehend nicht verfügbar.']);
    }
}
if ($route === 'team_data') {
    try { team_bootstrap_admin(); }
    catch (Throwable $error) { error_log('Iron Shield data bootstrap failed: ' . get_class($error)); json_response(503, ['error' => 'Support-Datenspeicher ist nicht verfügbar.']); }
    $view = (string)($_GET['view'] ?? 'support');
    if (!in_array($view, ['support', 'ticket', 'team', 'team_login'], true)) json_response(400, ['error' => 'invalid_view']);
    if (empty($_SESSION['team_csrf'])) $_SESSION['team_csrf'] = bin2hex(random_bytes(24));
    $staff = team_user();
    $discordUser = $_SESSION['user'] ?? null;
    $result = [
        'view' => $view,
        'csrf' => team_csrf(),
        'max_attachment_bytes' => strtolower((string)(getenv('VERCEL') ?: '')) === '1' ? 4 * 1024 * 1024 : 15 * 1024 * 1024,
        'staff' => $staff,
        'discord_user' => is_array($discordUser) ? ['id' => (string)($discordUser['id'] ?? ''), 'username' => (string)($discordUser['username'] ?? '')] : null,
        'guilds' => is_array($_SESSION['discord_guilds'] ?? null) ? array_map(static fn(array $guild): array => ['id' => (string)($guild['id'] ?? ''), 'name' => (string)($guild['name'] ?? '')], array_filter($_SESSION['discord_guilds'], 'is_array')) : [],
        'announcements' => [],
    ];
    if ($view === 'team_login') json_response(200, ['view' => $view, 'csrf' => team_csrf(), 'signed_in' => $staff !== null]);
    if ($view === 'team' && !$staff) json_response(401, ['error' => 'team_login_required']);
    if ($view === 'support' && !$staff && !$discordUser) json_response(401, ['error' => 'login_required']);
    $store = team_store(static function (array &$data): array { return ['users' => $data['users'] ?? [], 'tickets' => $data['tickets'] ?? [], 'announcements' => $data['announcements'] ?? []]; });
    if ($view === 'team' || $view === 'support') {
        $canViewAll = $staff !== null && team_has('tickets_view');
        $result['tickets'] = array_values(array_filter($store['tickets'], static fn($ticket): bool => is_array($ticket) && ($canViewAll || ($discordUser && (string)($ticket['ownerId'] ?? '') === (string)($discordUser['id'] ?? '')))));
        usort($result['tickets'], static fn(array $a, array $b): int => (int)($b['updatedAt'] ?? 0) <=> (int)($a['updatedAt'] ?? 0));
        if ($view === 'team') {
            $result['permissions'] = $staff['permissions'] ?? [];
            $result['is_admin'] = !empty($staff['admin']);
            $result['can_manage_users'] = team_has('users_manage');
            $result['can_manage_announcements'] = team_has('announcements_manage');
            $result['users'] = array_map(static fn(array $user): array => ['id' => (string)($user['id'] ?? ''), 'username' => (string)($user['username'] ?? ''), 'displayName' => (string)($user['displayName'] ?? $user['username'] ?? ''), 'admin' => !empty($user['admin']), 'permissions' => $user['permissions'] ?? [], 'createdAt' => (int)($user['createdAt'] ?? 0)], array_filter($store['users'], 'is_array'));
            $result['stats'] = ['users' => count($store['users']), 'tickets' => count($store['tickets']), 'announcements' => count($store['announcements'])];
            if (team_has('announcements_manage')) $result['announcements'] = array_values(array_filter($store['announcements'], 'is_array'));
            if (is_array($_SESSION['team_password_notice'] ?? null)) { $result['password_notice'] = $_SESSION['team_password_notice']; unset($_SESSION['team_password_notice']); }
        }
    } else {
        $id = (string)($_GET['id'] ?? '');
        if (!preg_match('/^[a-f0-9]{16}$/', $id)) json_response(400, ['error' => 'invalid_ticket_id']);
        $ticket = null;
        foreach ($store['tickets'] as $entry) if (is_array($entry) && (string)($entry['id'] ?? '') === $id) { $ticket = $entry; break; }
        $canRead = is_array($ticket) && (($staff && team_has('tickets_view')) || ($discordUser && (string)($ticket['ownerId'] ?? '') === (string)($discordUser['id'] ?? '')));
        if (!$canRead) json_response(404, ['error' => 'ticket_not_found']);
        $result['ticket'] = $ticket;
        $result['can_reply'] = ($staff && team_has('tickets_reply')) || $discordUser !== null;
        $result['can_claim'] = $staff !== null && ($ticket['status'] ?? '') === 'open';
        $result['can_close'] = ($staff !== null || ($discordUser && (string)($ticket['ownerId'] ?? '') === (string)($discordUser['id'] ?? ''))) && ($ticket['status'] ?? '') === 'open';
    }
    json_response(200, $result);
}
if (in_array($route, ['team_login', 'team', 'team_logout', 'team_create_user', 'team_permissions', 'team_reset_password', 'support', 'ticket', 'ticket_create', 'ticket_reply', 'ticket_close', 'ticket_claim', 'ticket_attachment', 'ticket_poll', 'announcement_create', 'announcement_delete'], true)) {
    try {
        team_bootstrap_admin();
        team_handle_request($route);
    } catch (Throwable $error) {
        error_log('Iron Shield team portal: ' . $error->getMessage());
        team_redirect(in_array($route, ['team_login', 'team_logout', 'team_create_user', 'team_permissions', 'team_reset_password', 'announcement_create', 'announcement_delete'], true) ? 'team' : 'support', $error->getMessage());
    }
}

if ($route === 'login' || $route === 'dashboard_login') {
    $_SESSION['oauth_next'] = $route === 'dashboard_login' ? 'dashboard' : 'support';
    $redirectUri = discord_redirect_uri();
    if (config('DISCORD_CLIENT_SECRET') === '' || $redirectUri === '') failure_page('Discord-Login noch nicht eingerichtet. Ergänze DISCORD_CLIENT_SECRET und DISCORD_REDIRECT_URI in der Hosting-Konfiguration.', 503);
    $state = bin2hex(random_bytes(24));
    $stateCookie = oauth_state_cookie_name($state);
    foreach (($_SESSION['oauth_states'] ?? []) as $oldCookie => $oldEntry) {
        if (!is_array($oldEntry) || time() - (int)($oldEntry['createdAt'] ?? 0) > 600) unset($_SESSION['oauth_states'][$oldCookie]);
    }
    $_SESSION['oauth_states'][$stateCookie] = ['value' => $state, 'createdAt' => time(), 'next' => $_SESSION['oauth_next']];
    setcookie($stateCookie, $state, ['expires' => time() + 600, 'path' => '/', 'secure' => $secureCookie, 'httponly' => true, 'samesite' => 'Lax']);
    $query = http_build_query(['client_id' => $clientId, 'redirect_uri' => $redirectUri, 'response_type' => 'code', 'scope' => 'identify guilds', 'state' => $state]);
    header('Location: https://discord.com/oauth2/authorize?' . $query, true, 302);
    exit;
}

if ($route === 'callback') {
    $returnedState = (string)($_GET['state'] ?? '');
    $stateCookie = $returnedState !== '' ? oauth_state_cookie_name($returnedState) : '';
    $sessionState = $stateCookie !== '' ? ($_SESSION['oauth_states'][$stateCookie] ?? null) : null;
    $sessionStateIsFresh = is_array($sessionState) && (time() - (int)($sessionState['createdAt'] ?? 0)) <= 600;
    $savedState = $stateCookie !== '' ? (string)($_COOKIE[$stateCookie] ?? ($sessionStateIsFresh ? ($sessionState['value'] ?? '') : '')) : '';
    if ($stateCookie !== '') unset($_SESSION['oauth_states'][$stateCookie]);
    if ($stateCookie !== '') setcookie($stateCookie, '', ['expires' => time() - 3600, 'path' => '/', 'secure' => $secureCookie, 'httponly' => true, 'samesite' => 'Lax']);
    if ($returnedState === '' || $savedState === '' || !hash_equals($savedState, $returnedState)) failure_page('Der Rücksprung von Discord konnte nicht diesem Login zugeordnet werden. Starte den Login einmal neu. Falls der Fehler bleibt, lade die neueste index.php auf den Webspace und prüfe, dass du durchgehend dieselbe HTTPS-Adresse verwendest.', 400);
    if (isset($_GET['error'])) failure_page('Die Discord-Anmeldung wurde abgebrochen.', 400);
    $code = (string)($_GET['code'] ?? '');
    $redirectUri = discord_redirect_uri();
    if ($code === '' || config('DISCORD_CLIENT_SECRET') === '' || $redirectUri === '') failure_page('Die OAuth-Konfiguration ist unvollständig.', 503);
    try {
        $tokens = discord_request('/oauth2/token', '', 'POST', ['client_id' => $clientId, 'client_secret' => config('DISCORD_CLIENT_SECRET'), 'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $redirectUri]);
        if (empty($tokens['access_token'])) failure_page('Discord konnte den Login-Code nicht bestätigen. Bitte prüfe Client-Secret und Redirect-URL.', 502);
        $user = discord_request('/users/@me', 'Bearer ' . $tokens['access_token']);
        $guilds = [];
        try {
            $after = '';
            do {
                $path = '/users/@me/guilds?limit=200' . ($after !== '' ? '&after=' . rawurlencode($after) : '');
                $page = discord_request($path, 'Bearer ' . $tokens['access_token']);
                if (!$page) break;
                $guilds = array_merge($guilds, $page);
                $after = (string)($page[count($page) - 1]['id'] ?? '');
            } while (count($page) === 200 && $after !== '');
        } catch (Throwable $guildError) {
            error_log('Discord guild list fetch failed: ' . $guildError->getMessage());
        }
        session_regenerate_id(true);
        $_SESSION['user'] = ['id' => $user['id'], 'username' => ($user['global_name'] ?? '') ?: ($user['username'] ?? 'Discord'), 'avatar' => $user['avatar'] ?? null];
        $_SESSION['discord_guilds'] = array_values(array_map(static fn(array $guild): array => ['id' => (string)($guild['id'] ?? ''), 'name' => (string)($guild['name'] ?? ''), 'icon' => (string)($guild['icon'] ?? ''), 'owner' => !empty($guild['owner']), 'permissions' => (string)($guild['permissions'] ?? $guild['permissions_new'] ?? '0'), 'manage' => guild_can_manage($guild)], array_filter($guilds, static fn($guild): bool => is_array($guild) && !empty($guild['id']) && !empty($guild['name']))));
        unset($_SESSION['oauth_next']);
        header('Location: ' . (($sessionState['next'] ?? '') === 'dashboard' ? '/dashboard.html' : '/support.html'), true, 302);
        exit;
    } catch (Throwable $error) {
        error_log('Discord OAuth callback failed: ' . $error->getMessage());
        failure_page('Die Verbindung zu Discord ist fehlgeschlagen. Bitte prüfe Client Secret, Callback-URL und PHP-HTTPS-Unterstützung.', 502);
    }
}

if ($route === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals((string)($_SESSION['csrf'] ?? ''), (string)($_POST['csrf'] ?? ''))) json_response(403, ['error' => 'Ungültige Sitzung. Bitte Seite neu laden.']);
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', ['expires' => time() - 42000, 'path' => $params['path'], 'domain' => $params['domain'], 'secure' => $params['secure'], 'httponly' => $params['httponly'], 'samesite' => 'Lax']);
    }
    session_destroy();
    header('Location: /support.html', true, 303);
    exit;
}

if ($route === '') {
    header('Location: /index.html', true, 302);
    exit;
}

json_response(404, ['error' => 'route_not_found']);
