<?php
declare(strict_types=1);

function team_data_dir(): string
{
    $projectData = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.ironshield-private';
    $stableHome = is_dir('/home/container') ? '/home/container/.ironshield-private' : $projectData;
    $configured = trim(config('TEAM_DATA_DIR'));
    if ($configured !== '') {
        $temporaryRoot = rtrim(sys_get_temp_dir(), '/\\');
        $normalized = rtrim($configured, '/\\');
        if ($normalized === $temporaryRoot || str_starts_with($normalized, $temporaryRoot . DIRECTORY_SEPARATOR)) {
            error_log('TEAM_DATA_DIR points to temporary storage; using the persistent server data directory instead.');
            return $stableHome;
        }
        return $normalized;
    }
    return $stableHome;
}

function team_migrate_legacy_store(string $directory): void
{
    $migrationMarker = $directory . DIRECTORY_SEPARATOR . '.legacy-migration-v1';
    $destination = $directory . DIRECTORY_SEPARATOR . 'store.json';
    $migrationLock = @fopen($directory . DIRECTORY_SEPARATOR . 'store-migration.lock', 'c+');
    if ($migrationLock === false || !flock($migrationLock, LOCK_EX)) {
        if (is_resource($migrationLock)) fclose($migrationLock);
        throw new RuntimeException('Die Kontodaten werden gerade wiederhergestellt. Bitte versuche es gleich erneut.');
    }
    try {
        $markerExists = is_file($migrationMarker);
        $destinationExists = is_file($destination);
        $currentContents = $destinationExists ? @file_get_contents($destination) : false;
        $decodedCurrent = is_string($currentContents) ? json_decode($currentContents, true) : null;
        $destinationValid = is_array($decodedCurrent);

        // After a redeploy the configured primary directory may be empty while
        // the durable mirror still has the account database. A migration marker
        // must not prevent recovery from that mirror.
        $hasSavedAccounts = $destinationValid && is_array($decodedCurrent['users'] ?? null) && count($decodedCurrent['users']) > 0;
        if ($markerExists && $destinationValid && $hasSavedAccounts) return;
        if ($destinationExists && !$destinationValid) {
            $corruptCopy = $destination . '.corrupt-' . gmdate('Ymd-His');
            if (!@copy($destination, $corruptCopy)) throw new RuntimeException('Die beschädigte Kontodatei konnte nicht vor der Wiederherstellung gesichert werden.');
            @chmod($corruptCopy, 0600);
        }

    $currentData = ['users' => [], 'tickets' => [], 'announcements' => []];
    if ($destinationValid) {
        $currentData = array_replace($currentData, $decodedCurrent);
    }
    $projectBackup = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.ironshield-private';
    $serverBackup = is_dir('/home/container') ? '/home/container/.ironshield-private' : $projectBackup;
    $sources = [$projectBackup, $serverBackup];
    $legacyDirectory = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'ironshield-team-' . substr(hash('sha256', __DIR__), 0, 16);
    $sources[] = $legacyDirectory;
    $sourceStoreFound = false;
    foreach (array_unique($sources) as $sourceDirectory) {
        $sourceStore = $sourceDirectory . DIRECTORY_SEPARATOR . 'store.json';
        if (!is_file($sourceStore) || realpath($sourceDirectory) === realpath($directory)) continue;
        $sourceLock = @fopen($sourceDirectory . DIRECTORY_SEPARATOR . 'store.lock', 'c+');
        if ($sourceLock === false || !flock($sourceLock, LOCK_SH)) {
            if (is_resource($sourceLock)) fclose($sourceLock);
            throw new RuntimeException('Der bisherige Team-Datenspeicher konnte nicht sicher übernommen werden.');
        }
        try {
            $contents = @file_get_contents($sourceStore);
            $decoded = is_string($contents) ? json_decode($contents, true) : null;
            if (!is_string($contents) || !is_array($decoded)) throw new RuntimeException('Der bisherige Team-Datenspeicher ist nicht lesbar.');
            $sourceStoreFound = true;
            $sourceAttachments = $sourceDirectory . DIRECTORY_SEPARATOR . 'attachments';
            if (is_dir($sourceAttachments)) {
                $destinationAttachments = $directory . DIRECTORY_SEPARATOR . 'attachments';
                if (!is_dir($destinationAttachments) && !@mkdir($destinationAttachments, 0700, true) && !is_dir($destinationAttachments)) throw new RuntimeException('Ticket-Anhänge konnten nicht in den dauerhaften Speicher übernommen werden.');
                foreach (new DirectoryIterator($sourceAttachments) as $file) {
                    if ($file->isDot() || !$file->isFile() || $file->isLink()) continue;
                    $target = $destinationAttachments . DIRECTORY_SEPARATOR . $file->getFilename();
                    if (!is_file($target) && !@copy($file->getPathname(), $target)) throw new RuntimeException('Ein Ticket-Anhang konnte nicht übernommen werden.');
                    @chmod($target, 0600);
                }
            }

            $changed = !$destinationValid;
            $collectionsToImport = ($markerExists && $destinationValid)
                ? ['users']
                : ['users', 'tickets', 'announcements'];
            foreach ($collectionsToImport as $collection) {
                if (!is_array($decoded[$collection] ?? null)) continue;
                $currentData[$collection] = is_array($currentData[$collection] ?? null) ? $currentData[$collection] : [];
                foreach ($decoded[$collection] as $sourceRecord) {
                    if (!is_array($sourceRecord)) continue;
                    $duplicate = false;
                    foreach ($currentData[$collection] as $currentRecord) {
                        if (!is_array($currentRecord)) continue;
                        if ($collection === 'users') {
                            $sameId = (string)($currentRecord['id'] ?? '') !== '' && (string)($currentRecord['id'] ?? '') === (string)($sourceRecord['id'] ?? '');
                            $sameUsername = (string)($currentRecord['username'] ?? '') !== '' && strcasecmp((string)$currentRecord['username'], (string)($sourceRecord['username'] ?? '')) === 0;
                            if ($sameId || $sameUsername) { $duplicate = true; break; }
                        } elseif ((string)($currentRecord['id'] ?? '') !== '' && (string)($currentRecord['id'] ?? '') === (string)($sourceRecord['id'] ?? '')) {
                            $duplicate = true; break;
                        }
                    }
                    if (!$duplicate) { $currentData[$collection][] = $sourceRecord; $changed = true; }
                }
            }
            foreach ($decoded as $key => $value) if (!in_array($key, ['users', 'tickets', 'announcements'], true) && !array_key_exists($key, $currentData)) { $currentData[$key] = $value; $changed = true; }
            if ($changed) {
                $merged = json_encode($currentData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
                $temporary = $destination . '.' . bin2hex(random_bytes(5)) . '.migration';
                if (@file_put_contents($temporary, $merged, LOCK_EX) === false || !@rename($temporary, $destination)) {
                    @unlink($temporary);
                    throw new RuntimeException('Der bisherige Team-Datenspeicher konnte nicht übernommen werden.');
                }
                @chmod($destination, 0600);
                $destinationExists = true;
            }
        } finally {
            flock($sourceLock, LOCK_UN);
            fclose($sourceLock);
        }
    }
    if ($sourceStoreFound && !$markerExists) {
        if (@file_put_contents($migrationMarker, 'completed ' . gmdate(DATE_ATOM) . "\n", LOCK_EX) === false) {
            throw new RuntimeException('Die Datenmigration konnte nicht als abgeschlossen markiert werden.');
        }
        @chmod($migrationMarker, 0600);
    } elseif (!$sourceStoreFound && $markerExists && !$destinationValid) {
        throw new RuntimeException('Der aktive Kontospeicher fehlt oder ist beschädigt und es wurde keine lesbare Sicherung gefunden.');
    }
    } finally {
        flock($migrationLock, LOCK_UN);
        fclose($migrationLock);
    }
}

function team_sync_persistent_backup(string $primaryDirectory): void
{
    $backupDirectory = is_dir('/home/container') ? '/home/container/.ironshield-private' : dirname(__DIR__) . DIRECTORY_SEPARATOR . '.ironshield-private';
    $primaryReal = realpath($primaryDirectory);
    $backupReal = realpath($backupDirectory);
    if (($primaryReal !== false && $backupReal !== false && $primaryReal === $backupReal) || rtrim($primaryDirectory, '/\\') === rtrim($backupDirectory, '/\\')) return;
    if (!is_dir($backupDirectory) && !@mkdir($backupDirectory, 0700, true) && !is_dir($backupDirectory)) throw new RuntimeException('Die zusätzliche dauerhafte Datensicherung konnte nicht angelegt werden.');
    @chmod($backupDirectory, 0700);
    $documentRoot = realpath(dirname(__DIR__));
    $backupReal = realpath($backupDirectory);
    if ($documentRoot !== false && $backupReal !== false && str_starts_with($backupReal, $documentRoot . DIRECTORY_SEPARATOR)) {
        if (!is_file($backupDirectory . DIRECTORY_SEPARATOR . '.htaccess')) @file_put_contents($backupDirectory . DIRECTORY_SEPARATOR . '.htaccess', "Require all denied\nDeny from all\n");
        if (!is_file($backupDirectory . DIRECTORY_SEPARATOR . 'web.config')) @file_put_contents($backupDirectory . DIRECTORY_SEPARATOR . 'web.config', '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>');
    }
    $lock = @fopen($backupDirectory . DIRECTORY_SEPARATOR . 'store.lock', 'c+');
    if ($lock === false || !flock($lock, LOCK_EX)) { if (is_resource($lock)) fclose($lock); throw new RuntimeException('Die zusätzliche Datensicherung ist gesperrt.'); }
    try {
        $primaryAttachments = $primaryDirectory . DIRECTORY_SEPARATOR . 'attachments';
        if (is_dir($primaryAttachments)) {
            $backupAttachments = $backupDirectory . DIRECTORY_SEPARATOR . 'attachments';
            if (!is_dir($backupAttachments) && !@mkdir($backupAttachments, 0700, true) && !is_dir($backupAttachments)) throw new RuntimeException('Ticket-Anhänge konnten nicht zusätzlich gesichert werden.');
            foreach (new DirectoryIterator($primaryAttachments) as $file) {
                if ($file->isDot() || !$file->isFile() || $file->isLink()) continue;
                $target = $backupAttachments . DIRECTORY_SEPARATOR . $file->getFilename();
                if (!is_file($target) && !@copy($file->getPathname(), $target)) throw new RuntimeException('Ein Ticket-Anhang konnte nicht zusätzlich gesichert werden.');
                @chmod($target, 0600);
            }
        }
        $contents = @file_get_contents($primaryDirectory . DIRECTORY_SEPARATOR . 'store.json');
        if (!is_string($contents) || !is_array(json_decode($contents, true))) throw new RuntimeException('Die Hauptdatei für Teamdaten konnte nicht zusätzlich gesichert werden.');
        $temporary = $backupDirectory . DIRECTORY_SEPARATOR . 'store.json.' . bin2hex(random_bytes(5)) . '.tmp';
        if (@file_put_contents($temporary, $contents, LOCK_EX) === false || !@rename($temporary, $backupDirectory . DIRECTORY_SEPARATOR . 'store.json')) {
            @unlink($temporary);
            throw new RuntimeException('Die zusätzliche Datensicherung konnte nicht abgeschlossen werden.');
        }
        @chmod($backupDirectory . DIRECTORY_SEPARATOR . 'store.json', 0600);
        $migrationMarker = $primaryDirectory . DIRECTORY_SEPARATOR . '.legacy-migration-v1';
        if (is_file($migrationMarker)) {
            $backupMarker = $backupDirectory . DIRECTORY_SEPARATOR . '.legacy-migration-v1';
            if (!is_file($backupMarker) && @copy($migrationMarker, $backupMarker)) @chmod($backupMarker, 0600);
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function team_store(callable $callback, bool $write = false): mixed
{
    if (ironshield_storage_enabled()) {
        return ironshield_state_change('team_store', ['users' => [], 'tickets' => [], 'announcements' => []], $callback, $write);
    }
    $directory = team_data_dir();
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Der private Team-Datenspeicher konnte nicht angelegt werden.');
    }
    @chmod($directory, 0700);
    team_migrate_legacy_store($directory);
    $documentRoot = realpath(dirname(__DIR__));
    $realDirectory = realpath($directory);
    if ($documentRoot !== false && $realDirectory !== false && str_starts_with($realDirectory, $documentRoot . DIRECTORY_SEPARATOR)) {
        $denyFile = $directory . DIRECTORY_SEPARATOR . '.htaccess';
        if (!is_file($denyFile)) @file_put_contents($denyFile, "Require all denied\nDeny from all\n");
        $webConfig = $directory . DIRECTORY_SEPARATOR . 'web.config';
        if (!is_file($webConfig)) @file_put_contents($webConfig, '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>');
    }
    $lock = fopen($directory . '/store.lock', 'c+');
    if ($lock === false || !flock($lock, $write ? LOCK_EX : LOCK_SH)) throw new RuntimeException('Der Team-Datenspeicher ist gerade nicht verfügbar.');
    try {
        $path = $directory . '/store.json';
        $data = ['users' => [], 'tickets' => [], 'announcements' => []];
        if (is_file($path)) {
            $decoded = json_decode((string)file_get_contents($path), true);
            if (!is_array($decoded)) throw new RuntimeException('Der Team-Datenspeicher ist beschädigt.');
            $data = array_replace($data, $decoded);
        }
        $result = $callback($data);
        if ($write) {
            $temporary = $path . '.' . bin2hex(random_bytes(5)) . '.tmp';
            $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            if (file_put_contents($temporary, $json, LOCK_EX) === false || !@rename($temporary, $path)) {
                @unlink($temporary);
                throw new RuntimeException('Änderungen konnten nicht gespeichert werden.');
            }
            @chmod($path, 0600);
            team_sync_persistent_backup($directory);
        }
        return $result;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function team_permissions(bool $admin = false): array
{
    return ['tickets_view' => true, 'tickets_reply' => true, 'users_manage' => $admin, 'announcements_manage' => false];
}

function team_bootstrap_admin(): void
{
    team_store(static function (array &$data): void {
        foreach ($data['users'] as &$existingUser) if (is_array($existingUser)) unset($existingUser['mustChangePassword']);
        unset($existingUser);
        $username = trim(config('TEAM_ADMIN_USERNAME'));
        $password = config('TEAM_ADMIN_PASSWORD');
        if ($username === '' || strlen($password) < 10) return;
        if ($data['users']) {
            foreach ($data['users'] as $entry) if (strcasecmp((string)($entry['username'] ?? ''), $username) === 0 && !empty($entry['admin'])) return;
            foreach ($data['users'] as &$entry) if (!empty($entry['admin'])) {
                $entry['username'] = $username;
                $entry['passwordHash'] = password_hash($password, PASSWORD_DEFAULT);
                $entry['permissions'] = team_permissions(true);
                unset($entry);
                return;
            }
            unset($entry);
            return;
        }
        $data['users'][] = ['id' => bin2hex(random_bytes(12)), 'displayName' => $username, 'username' => $username, 'passwordHash' => password_hash($password, PASSWORD_DEFAULT), 'permissions' => team_permissions(true), 'admin' => true, 'createdAt' => time()];
    }, true);
}

function team_user(): ?array
{
    return is_array($_SESSION['team_user'] ?? null) ? $_SESSION['team_user'] : null;
}

function team_has(string $permission): bool
{
    if (in_array($permission, ['tickets_view', 'tickets_reply'], true)) return team_user() !== null;
    if ($permission === 'announcements_manage' && !empty(team_user()['admin'])) return true;
    return (bool)(team_user()['permissions'][$permission] ?? false);
}

function team_csrf(): string
{
    if (empty($_SESSION['team_csrf'])) $_SESSION['team_csrf'] = bin2hex(random_bytes(24));
    return (string)$_SESSION['team_csrf'];
}

function team_verify_csrf(): void
{
    $given = (string)($_POST['csrf'] ?? '');
    if ($given === '' || !hash_equals(team_csrf(), $given)) throw new RuntimeException('Sitzung abgelaufen. Bitte lade die Seite neu und versuche es erneut.');
}

function team_e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function team_length(string $value): int
{
    $count = preg_match_all('/./us', $value);
    return $count === false ? strlen($value) : $count;
}

function team_save_attachments(): array
{
    $files = $_FILES['attachments'] ?? null;
    if (!is_array($files) || !isset($files['name']) || !is_array($files['name'])) return [];
    $allowed = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif', 'image/webp' => 'webp', 'video/mp4' => 'mp4', 'video/webm' => 'webm', 'video/quicktime' => 'mov'];
    $pending = [];
    $totalSize = 0;
    foreach ($files['name'] as $index => $originalName) {
        $error = (int)($files['error'][$index] ?? UPLOAD_ERR_NO_FILE);
        if ($error === UPLOAD_ERR_NO_FILE) continue;
        if ($error !== UPLOAD_ERR_OK) throw new RuntimeException($error === UPLOAD_ERR_INI_SIZE || $error === UPLOAD_ERR_FORM_SIZE ? 'Eine Datei ist zu groß. Pro Datei sind maximal 5 MB erlaubt.' : 'Mindestens eine Datei konnte nicht hochgeladen werden.');
        $size = (int)($files['size'][$index] ?? 0);
        $totalSize += $size;
        $temporaryPath = (string)($files['tmp_name'][$index] ?? '');
        if ($size < 1 || $size > 5 * 1024 * 1024 || !is_uploaded_file($temporaryPath)) throw new RuntimeException('Dateien müssen echte Uploads mit maximal 5 MB sein.');
        $pending[] = [$index, (string)$originalName, $temporaryPath, $size];
    }
    if (count($pending) > 3) throw new RuntimeException('Du kannst höchstens 3 Medien pro Nachricht anhängen.');
    if (strtolower((string)(getenv('VERCEL') ?: '')) === '1' && $totalSize > 4 * 1024 * 1024) throw new RuntimeException('Vercel erlaubt maximal 4 MB Anhänge pro Nachricht. Bitte hänge weniger oder kleinere Dateien an.');
    if (!$pending) return [];
    $directory = team_data_dir() . DIRECTORY_SEPARATOR . 'attachments';
    if (!ironshield_storage_enabled() && !is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) throw new RuntimeException('Der private Medienordner konnte nicht angelegt werden.');
    if (!ironshield_storage_enabled()) @chmod($directory, 0700);
    $saved = [];
    try {
        foreach ($pending as [$index, $originalName, $temporaryPath, $size]) {
            $mime = team_detect_mime($temporaryPath);
            if (!isset($allowed[$mime])) throw new RuntimeException('Erlaubt sind Bilder (JPG, PNG, GIF, WebP) und Videos (MP4, WebM, MOV).');
            $id = bin2hex(random_bytes(20));
            $safeName = team_safe_filename($originalName);
            if (ironshield_storage_enabled()) {
                $bytes = @file_get_contents($temporaryPath);
                if (!is_string($bytes) || strlen($bytes) !== $size) throw new RuntimeException('Eine Datei konnte nicht sicher gelesen werden.');
                ironshield_attachment_save($id, $mime, $safeName, $bytes);
            } else {
                $storedPath = $directory . DIRECTORY_SEPARATOR . $id . '.' . $allowed[$mime];
                if (!move_uploaded_file($temporaryPath, $storedPath)) throw new RuntimeException('Eine Datei konnte nicht sicher gespeichert werden.');
                @chmod($storedPath, 0600);
            }
            $saved[] = ['id' => $id, 'name' => $safeName, 'mime' => $mime, 'size' => $size];
        }
    } catch (Throwable $error) {
        foreach ($saved as $attachment) {
            if (ironshield_storage_enabled()) ironshield_attachment_delete((string)$attachment['id']);
            else @unlink($directory . DIRECTORY_SEPARATOR . $attachment['id'] . '.' . $allowed[$attachment['mime']]);
        }
        throw $error;
    }
    return $saved;
}

function team_detect_mime(string $path): string
{
    if (class_exists('finfo')) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        return (string)($finfo->file($path) ?: '');
    }
    $image = @getimagesize($path);
    if (is_array($image) && isset($image['mime'])) return (string)$image['mime'];
    $handle = @fopen($path, 'rb');
    $header = $handle === false ? '' : (string)fread($handle, 16);
    if (is_resource($handle)) fclose($handle);
    if (str_starts_with($header, "\x1A\x45\xDF\xA3")) return 'video/webm';
    if (substr($header, 4, 4) === 'ftyp') return substr($header, 8, 4) === 'qt  ' ? 'video/quicktime' : 'video/mp4';
    return '';
}

function team_safe_filename(string $filename): string
{
    $filename = basename(str_replace('\\', '/', $filename));
    $filename = preg_replace('/[\x00-\x1F\x7F]/u', '', $filename) ?? 'Anhang';
    return substr($filename !== '' ? $filename : 'Anhang', 0, 180);
}

function team_ticket_category(string $category): string
{
    return match ($category) {
        'security' => 'Sicherheit / Schutz',
        'technical' => 'Technischer Support',
        'bug' => 'Fehler melden',
        'other' => 'Sonstiges',
        default => 'Allgemeine Frage',
    };
}

function team_redirect(string $route, string $message = ''): never
{
    $staticPages = ['team_login' => '/team-login.html', 'team' => '/team.html', 'support' => '/support.html', 'ticket' => '/ticket.html'];
    $url = $staticPages[$route] ?? ('/api/index.php?route=' . rawurlencode($route));
    if ($message !== '') $url .= (str_contains($url, '?') ? '&' : '?') . 'message=' . rawurlencode($message);
    header('Location: ' . $url, true, 303);
    exit;
}

function team_handle_request(string $route): void
{
    if ($route === 'team_login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        team_verify_csrf();
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $user = team_store(static function (array &$data) use ($username): ?array {
            foreach ($data['users'] as $entry) if (is_array($entry) && strcasecmp((string)$entry['username'], $username) === 0) return $entry;
            return null;
        });
        if (!$user || !password_verify($password, (string)$user['passwordHash'])) team_redirect('team_login', 'Anmeldung fehlgeschlagen.');
        session_regenerate_id(true);
        $_SESSION['team_user'] = ['id' => $user['id'], 'username' => $user['username'], 'displayName' => $user['displayName'] ?? $user['username'], 'admin' => (bool)$user['admin'], 'permissions' => $user['permissions']];
        unset($_SESSION['user'], $_SESSION['access_token'], $_SESSION['refresh_token'], $_SESSION['token_expires_at']);
        team_redirect('team');
    }
    if ($route === 'team_logout' && $_SERVER['REQUEST_METHOD'] === 'POST') { team_verify_csrf(); unset($_SESSION['team_user']); team_redirect('team_login', 'Du wurdest abgemeldet.'); }
    if (!str_starts_with($route, 'team') && !in_array($route, ['support', 'ticket', 'ticket_create', 'ticket_reply', 'ticket_close', 'ticket_claim', 'ticket_attachment', 'ticket_poll', 'announcement_create', 'announcement_delete'], true)) return;
    if ($route === 'ticket_poll' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $id = (string)($_GET['id'] ?? '');
        $after = max(0, (int)($_GET['after'] ?? 0));
        if (!preg_match('/^[a-f0-9]{16}$/', $id)) json_response(400, ['error' => 'Ungültige Ticket-ID.']);
        $staff = team_user(); $discordUser = $_SESSION['user'] ?? null;
        $ticket = team_store(static function (array &$data) use ($id, $staff, $discordUser): ?array {
            foreach ($data['tickets'] as $entry) if (($entry['id'] ?? '') === $id && (($staff && team_has('tickets_view')) || (!$staff && $discordUser && ($entry['ownerId'] ?? '') === $discordUser['id']))) return $entry;
            return null;
        });
        if (!$ticket) json_response(404, ['error' => 'Ticket nicht gefunden oder kein Zugriff.']);
        $messages = is_array($ticket['messages'] ?? null) ? $ticket['messages'] : [];
        $newMessages = [];
        foreach (array_slice($messages, $after, null, true) as $message) {
            $newMessages[] = ['authorName' => (string)($message['authorName'] ?? 'Nutzer'), 'team' => !empty($message['team']), 'body' => (string)($message['body'] ?? ''), 'createdAt' => (int)($message['createdAt'] ?? time()), 'attachments' => is_array($message['attachments'] ?? null) ? $message['attachments'] : []];
        }
        json_response(200, ['messages' => $newMessages, 'count' => count($messages), 'status' => (string)($ticket['status'] ?? 'closed')]);
    }
    if ($route === 'ticket_attachment') {
        $id = (string)($_GET['id'] ?? ''); $attachmentId = (string)($_GET['file'] ?? '');
        $staff = team_user(); $discordUser = $_SESSION['user'] ?? null;
        if (!preg_match('/^[a-f0-9]{16}$/', $id) || !preg_match('/^[a-f0-9]{40}$/', $attachmentId)) { http_response_code(404); exit; }
        $attachment = team_store(static function (array &$data) use ($id, $attachmentId, $staff, $discordUser): ?array {
            foreach ($data['tickets'] as $ticket) if (($ticket['id'] ?? '') === $id && (($staff && team_has('tickets_view')) || (!$staff && $discordUser && ($ticket['ownerId'] ?? '') === $discordUser['id']))) {
                foreach ($ticket['messages'] ?? [] as $message) foreach ($message['attachments'] ?? [] as $item) if (($item['id'] ?? '') === $attachmentId) return $item;
            }
            return null;
        });
        $extensions = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif', 'image/webp' => 'webp', 'video/mp4' => 'mp4', 'video/webm' => 'webm', 'video/quicktime' => 'mov'];
        $mime = is_array($attachment) ? (string)($attachment['mime'] ?? '') : '';
        if (!isset($extensions[$mime])) { http_response_code(404); exit; }
        if (ironshield_storage_enabled()) {
            $stored = ironshield_attachment_get($attachmentId);
            if (!is_array($stored) || !hash_equals($mime, (string)$stored['mime'])) { http_response_code(404); exit; }
            $bytes = $stored['data'];
        } else {
            $path = team_data_dir() . DIRECTORY_SEPARATOR . 'attachments' . DIRECTORY_SEPARATOR . $attachmentId . '.' . $extensions[$mime];
            if (!is_file($path) || team_detect_mime($path) !== $mime) { http_response_code(404); exit; }
            $bytes = @file_get_contents($path);
            if (!is_string($bytes)) { http_response_code(404); exit; }
        }
        $filename = rawurlencode(team_safe_filename((string)($attachment['name'] ?? 'Anhang')));
        header('Content-Type: ' . $mime); header('Content-Length: ' . (string)strlen($bytes)); header('Content-Disposition: inline; filename="attachment"; filename*=UTF-8\'\'' . $filename);
        header('Cache-Control: private, no-store, max-age=0'); header('X-Content-Type-Options: nosniff'); header("Content-Security-Policy: default-src 'none'; img-src 'self'; media-src 'self'; sandbox");
        echo $bytes; exit;
    }
    if (in_array($route, ['team_create_user', 'team_permissions', 'team_reset_password', 'ticket_create', 'ticket_reply', 'ticket_close', 'ticket_claim', 'announcement_create', 'announcement_delete'], true) && $_SERVER['REQUEST_METHOD'] === 'POST') {
        team_verify_csrf();
        if ($route === 'announcement_create') {
            if (!team_has('announcements_manage')) team_redirect('team', 'Du darfst keine Ankündigungen veröffentlichen.');
            $title = trim((string)($_POST['title'] ?? '')); $body = trim((string)($_POST['body'] ?? '')); $expiresInput = trim((string)($_POST['expires_at'] ?? ''));
            $expiresAt = null;
            if ($expiresInput !== '') {
                $expires = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i', $expiresInput, new DateTimeZone('Europe/Berlin'));
                $dateErrors = DateTimeImmutable::getLastErrors();
                if (!$expires || ($dateErrors !== false && ($dateErrors['warning_count'] > 0 || $dateErrors['error_count'] > 0)) || $expires->getTimestamp() <= time()) team_redirect('team', 'Bitte wähle einen gültigen Ablaufzeitpunkt in der Zukunft.');
                $expiresAt = $expires->getTimestamp();
            }
            if (team_length($title) < 2 || team_length($title) > 100 || $body === '' || team_length($body) > 2000) team_redirect('team', 'Titel und Text prüfen (Titel 2–100, Text höchstens 2.000 Zeichen).');
            $staff = team_user(); $announcement = ['id' => bin2hex(random_bytes(8)), 'title' => $title, 'body' => $body, 'createdBy' => (string)($staff['displayName'] ?? $staff['username']), 'createdAt' => time(), 'expiresAt' => $expiresAt];
            team_store(static function (array &$data) use ($announcement): void { $data['announcements'] ??= []; $data['announcements'][] = $announcement; }, true);
            team_redirect('team', 'Ankündigung wurde veröffentlicht.');
        }
        if ($route === 'announcement_delete') {
            if (!team_has('announcements_manage')) team_redirect('team', 'Du darfst keine Ankündigungen verwalten.');
            $id = (string)($_POST['id'] ?? '');
            team_store(static function (array &$data) use ($id): void { $data['announcements'] = array_values(array_filter($data['announcements'] ?? [], static fn($item) => (string)($item['id'] ?? '') !== $id)); }, true);
            team_redirect('team', 'Ankündigung wurde entfernt.');
        }
        if ($route === 'team_create_user') {
            if (!team_has('users_manage')) team_redirect('team', 'Du darfst keine Teamkonten verwalten.');
            $displayName = trim((string)($_POST['display_name'] ?? '')); $username = trim((string)($_POST['username'] ?? '')); $password = (string)($_POST['password'] ?? '');
            if (team_length($displayName) < 2 || team_length($displayName) > 60 || !preg_match('/^[A-Za-z0-9_.-]{3,32}$/', $username) || strlen($password) < 12 || strlen($password) > 200) team_redirect('team', 'Bitte Namen, Benutzername und Passwort prüfen (Name 2–60, Benutzername 3–32, Passwort mindestens 12 Zeichen).');
            team_store(static function (array &$data) use ($displayName, $username, $password): void {
                foreach ($data['users'] as $entry) if (strcasecmp((string)$entry['username'], $username) === 0) throw new RuntimeException('Dieser Teamname ist bereits vergeben.');
                $permissions = team_permissions(); $permissions['users_manage'] = in_array('users_manage', $_POST['permissions'] ?? [], true); $permissions['announcements_manage'] = in_array('announcements_manage', $_POST['permissions'] ?? [], true);
                $data['users'][] = ['id' => bin2hex(random_bytes(12)), 'displayName' => $displayName, 'username' => $username, 'passwordHash' => password_hash($password, PASSWORD_DEFAULT), 'permissions' => $permissions, 'admin' => false, 'createdAt' => time()];
            }, true);
            team_redirect('team', 'Teamkonto wurde angelegt.');
        }
        if ($route === 'team_permissions') {
            if (!team_has('users_manage')) team_redirect('team', 'Du darfst keine Rechte ändern.');
            $id = (string)($_POST['id'] ?? '');
            team_store(static function (array &$data) use ($id): void {
                foreach ($data['users'] as &$entry) if (($entry['id'] ?? '') === $id && empty($entry['admin'])) { $entry['permissions']['tickets_view'] = true; $entry['permissions']['tickets_reply'] = true; $entry['permissions']['users_manage'] = in_array('users_manage', $_POST['permissions'] ?? [], true); $entry['permissions']['announcements_manage'] = in_array('announcements_manage', $_POST['permissions'] ?? [], true); break; }
                unset($entry);
            }, true);
            team_redirect('team', 'Rechte wurden gespeichert.');
        }
        if ($route === 'team_reset_password') {
            if (!team_has('users_manage')) team_redirect('team', 'Du darfst keine Passwörter zurücksetzen.');
            $id = (string)($_POST['id'] ?? '');
            $temporaryPassword = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
            $resetUser = team_store(static function (array &$data) use ($id, $temporaryPassword): ?array {
                foreach ($data['users'] as &$entry) if (($entry['id'] ?? '') === $id && empty($entry['admin'])) {
                    $entry['passwordHash'] = password_hash($temporaryPassword, PASSWORD_DEFAULT);
                    $userInfo = ['username' => (string)$entry['username'], 'displayName' => (string)($entry['displayName'] ?? $entry['username'])];
                    unset($entry);
                    return $userInfo;
                }
                unset($entry); return null;
            }, true);
            if (!$resetUser) team_redirect('team', 'Teamkonto wurde nicht gefunden oder kann nicht zurückgesetzt werden.');
            $_SESSION['team_password_notice'] = ['username' => $resetUser['username'], 'displayName' => $resetUser['displayName'], 'password' => $temporaryPassword];
            team_redirect('team', 'Neues Passwort erstellt. Kopiere es jetzt sicher.');
        }
        if ($route === 'ticket_create') {
            if (empty($_SESSION['user'])) team_redirect('login');
            $subject = trim((string)($_POST['subject'] ?? '')); $body = trim((string)($_POST['body'] ?? ''));
            $categories = ['security', 'technical', 'bug', 'question', 'other'];
            $category = (string)($_POST['category'] ?? 'question');
            $priority = (string)($_POST['priority'] ?? 'normal');
            $serverId = trim((string)($_POST['server_id'] ?? ''));
            $serverName = '';
            if ($serverId !== '') {
                foreach (($_SESSION['discord_guilds'] ?? []) as $guild) {
                    if (is_array($guild) && (string)($guild['id'] ?? '') === $serverId) { $serverName = (string)($guild['name'] ?? ''); break; }
                }
                if ($serverName === '') team_redirect('support', 'Bitte wähle einen Server aus deiner Discord-Serverliste. Melde dich gegebenenfalls erneut an.');
            }
            $tried = trim((string)($_POST['tried'] ?? ''));
            if ($subject === '' || team_length($subject) > 120 || $body === '' || team_length($body) > 10000 || !in_array($category, $categories, true) || !in_array($priority, ['normal', 'high'], true) || team_length($serverName) > 100 || ($serverId !== '' && !preg_match('/^\d{15,22}$/', $serverId)) || team_length($tried) > 3000) team_redirect('support', 'Bitte prüfe die Angaben. Betreff max. 120, Nachricht max. 10.000 und Zusatzinfos max. 3.000 Zeichen.');
            $attachments = team_save_attachments();
            $id = bin2hex(random_bytes(8)); $owner = $_SESSION['user']; $now = time();
            $ticket = ['id' => $id, 'subject' => $subject, 'category' => $category, 'priority' => $priority, 'serverName' => $serverName, 'serverId' => $serverId, 'tried' => $tried, 'ownerId' => $owner['id'], 'ownerName' => $owner['username'], 'assignedTo' => null, 'assignedName' => null, 'status' => 'open', 'createdAt' => $now, 'updatedAt' => $now, 'messages' => [['authorId' => $owner['id'], 'authorName' => $owner['username'], 'team' => false, 'body' => $body, 'attachments' => $attachments, 'createdAt' => $now]]];
            team_store(static function (array &$data) use ($ticket): void { $data['tickets'][] = $ticket; }, true);
            header('Location: /ticket.html?id=' . rawurlencode($id) . '&message=' . rawurlencode('Ticket wurde gespeichert. Es wurde nichts an Discord gesendet oder dort erstellt.'), true, 303);
            exit;
        }
        if ($route === 'ticket_reply') {
            $id = (string)($_POST['id'] ?? ''); $body = trim((string)($_POST['body'] ?? ''));
            $staff = team_user(); $discordUser = $_SESSION['user'] ?? null;
            if (($staff && !team_has('tickets_reply')) || (!$staff && !$discordUser)) team_redirect('support', 'Du darfst hier nicht antworten.');
            if ($body === '' || team_length($body) > 10000) { header('Location: /ticket.html?id=' . rawurlencode($id) . '&message=' . rawurlencode('Nachricht ist leer oder zu lang.'), true, 303); exit; }
            $attachments = team_save_attachments();
            team_store(static function (array &$data) use ($id, $body, $staff, $discordUser, $attachments): void {
                foreach ($data['tickets'] as &$ticket) if (($ticket['id'] ?? '') === $id) {
                    if (!$staff && ($ticket['ownerId'] ?? '') !== ($discordUser['id'] ?? '')) throw new RuntimeException('Dieses Ticket gehört einem anderen Discord-Konto.');
                    if (($ticket['status'] ?? '') !== 'open') throw new RuntimeException('Dieses Ticket ist geschlossen.');
                    $author = $staff ?? $discordUser;
                    if ($staff && empty($ticket['assignedTo'])) { $ticket['assignedTo'] = $staff['id']; $ticket['assignedName'] = $staff['displayName'] ?? $staff['username']; }
                    $ticket['messages'][] = ['authorId' => $author['id'], 'authorName' => $staff ? ($staff['displayName'] ?? $staff['username']) : $author['username'], 'team' => $staff !== null, 'body' => $body, 'attachments' => $attachments, 'createdAt' => time()]; $ticket['updatedAt'] = time();
                    return;
                }
                throw new RuntimeException('Ticket wurde nicht gefunden.');
            }, true);
            header('Location: /ticket.html?id=' . rawurlencode($id) . '&message=' . rawurlencode('Antwort wurde gesendet.'), true, 303); exit;
        }
        if ($route === 'ticket_claim') {
            $staff = team_user(); $id = (string)($_POST['id'] ?? '');
            if (!$staff) team_redirect('team_login', 'Bitte melde dich im Team an.');
            team_store(static function (array &$data) use ($id, $staff): void {
                foreach ($data['tickets'] as &$ticket) if (($ticket['id'] ?? '') === $id) {
                    if (($ticket['status'] ?? '') !== 'open') throw new RuntimeException('Geschlossene Tickets können nicht übernommen werden.');
                    $ticket['assignedTo'] = $staff['id']; $ticket['assignedName'] = $staff['displayName'] ?? $staff['username']; $ticket['updatedAt'] = time();
                    return;
                }
                throw new RuntimeException('Ticket wurde nicht gefunden.');
            }, true);
            header('Location: /ticket.html?id=' . rawurlencode($id) . '&message=' . rawurlencode('Ticket wurde dir zugewiesen.'), true, 303); exit;
        }
        if ($route === 'ticket_close') {
            $id = (string)($_POST['id'] ?? '');
            $staff = team_user(); $discordUser = $_SESSION['user'] ?? null;
            team_store(static function (array &$data) use ($id, $staff, $discordUser): void {
                foreach ($data['tickets'] as &$ticket) if (($ticket['id'] ?? '') === $id) {
                    if (!$staff && (!$discordUser || ($ticket['ownerId'] ?? '') !== ($discordUser['id'] ?? ''))) throw new RuntimeException('Du darfst nur eigene Tickets schließen.');
                    $ticket['status'] = 'closed'; $ticket['updatedAt'] = time(); return;
                }
                throw new RuntimeException('Ticket wurde nicht gefunden.');
            }, true);
            header('Location: /ticket.html?id=' . rawurlencode($id) . '&message=' . rawurlencode('Ticket geschlossen.'), true, 303); exit;
        }
    }
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $pageRoutes = ['team_login' => '/team-login.html', 'team' => '/team.html', 'support' => '/support.html', 'ticket' => '/ticket.html'];
        if (isset($pageRoutes[$route])) {
            $target = $pageRoutes[$route];
            $query = [];
            if ($route === 'ticket' && isset($_GET['id'])) $query['id'] = (string)$_GET['id'];
            if (isset($_GET['message'])) $query['message'] = (string)$_GET['message'];
            if ($query) $target .= '?' . http_build_query($query);
            header('Location: ' . $target, true, 302);
            exit;
        }
    }
}
