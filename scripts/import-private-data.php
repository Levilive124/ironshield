<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/includes/storage.php';

$source = isset($argv[1]) ? rtrim((string)$argv[1], DIRECTORY_SEPARATOR . '/\\') : dirname(__DIR__) . DIRECTORY_SEPARATOR . '.ironshield-private';
$storePath = $source . DIRECTORY_SEPARATOR . 'store.json';
if (!is_file($storePath) || !ironshield_storage_enabled()) {
    fwrite(STDERR, "Übergabe abgebrochen: store.json fehlt oder DATABASE_URL ist nicht gesetzt.\n");
    exit(1);
}
$raw = file_get_contents($storePath);
$legacy = is_string($raw) ? json_decode($raw, true) : null;
if (!is_array($legacy)) {
    fwrite(STDERR, "Übergabe abgebrochen: store.json ist kein gültiges JSON.\n");
    exit(1);
}
$realSource = realpath($source) ?: $source;
$migrationKey = 'private-data-' . hash('sha256', $realSource . ':' . hash_file('sha256', $storePath));
$pdo = ironshield_database();
$pdo->beginTransaction();
try {
    $mark = $pdo->prepare('INSERT INTO ironshield_migrations (migration_key) VALUES (:key) ON CONFLICT DO NOTHING');
    $mark->execute(['key' => $migrationKey]);
    if ($mark->rowCount() === 0) {
        $pdo->rollBack();
        fwrite(STDOUT, "Dieser Datenstand wurde bereits importiert.\n");
        exit(0);
    }

    $defaults = ['users' => [], 'tickets' => [], 'announcements' => []];
    $insertState = $pdo->prepare('INSERT INTO ironshield_state (state_key, payload) VALUES (:key, CAST(:payload AS JSONB)) ON CONFLICT DO NOTHING');
    $insertState->execute(['key' => 'team_store', 'payload' => json_encode($defaults, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
    $selectState = $pdo->prepare('SELECT payload FROM ironshield_state WHERE state_key = :key FOR UPDATE');
    $selectState->execute(['key' => 'team_store']);
    $current = json_decode((string)$selectState->fetchColumn(), true);
    if (!is_array($current)) throw new RuntimeException('Zielzustand ist beschädigt.');
    foreach (['users', 'tickets', 'announcements'] as $collection) {
        $current[$collection] = is_array($current[$collection] ?? null) ? $current[$collection] : [];
        foreach (($legacy[$collection] ?? []) as $record) {
            if (!is_array($record)) continue;
            $id = (string)($record['id'] ?? '');
            $duplicate = false;
            foreach ($current[$collection] as $existing) {
                if (!is_array($existing)) continue;
                if (($id !== '' && (string)($existing['id'] ?? '') === $id)
                    || ($collection === 'users' && (string)($record['username'] ?? '') !== '' && strcasecmp((string)($existing['username'] ?? ''), (string)$record['username']) === 0)) {
                    $duplicate = true;
                    break;
                }
            }
            if (!$duplicate) $current[$collection][] = $record;
        }
    }
    foreach ($legacy as $key => $value) if (!array_key_exists($key, $current)) $current[$key] = $value;
    $saveState = $pdo->prepare('UPDATE ironshield_state SET payload = CAST(:payload AS JSONB), updated_at = NOW() WHERE state_key = :key');
    $saveState->execute(['key' => 'team_store', 'payload' => json_encode($current, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);

    $attachmentMeta = [];
    foreach (($legacy['tickets'] ?? []) as $ticket) foreach (($ticket['messages'] ?? []) as $message) foreach (($message['attachments'] ?? []) as $item) {
        if (is_array($item) && preg_match('/^[a-f0-9]{40}$/', (string)($item['id'] ?? ''))) $attachmentMeta[(string)$item['id']] = $item;
    }
    $mimeByExtension = ['jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif', 'webp' => 'image/webp', 'mp4' => 'video/mp4', 'webm' => 'video/webm', 'mov' => 'video/quicktime'];
    $attachmentDir = $source . DIRECTORY_SEPARATOR . 'attachments';
    if (is_dir($attachmentDir)) {
        $saveAttachment = $pdo->prepare('INSERT INTO ironshield_attachments (attachment_id, mime, filename, data) VALUES (:id, :mime, :filename, :data) ON CONFLICT (attachment_id) DO NOTHING');
        foreach (new DirectoryIterator($attachmentDir) as $file) {
            if ($file->isDot() || !$file->isFile() || $file->isLink()) continue;
            if (preg_match('/^([a-f0-9]{40})\.([a-z0-9]+)$/i', $file->getFilename(), $matches) !== 1) continue;
            $id = strtolower($matches[1]);
            $extension = strtolower($matches[2]);
            if (!isset($mimeByExtension[$extension]) || $file->getSize() > 5 * 1024 * 1024) continue;
            $meta = $attachmentMeta[$id] ?? null;
            if (!is_array($meta) || (string)($meta['mime'] ?? '') !== $mimeByExtension[$extension]) continue;
            $bytes = file_get_contents($file->getPathname());
            if (!is_string($bytes) || strlen($bytes) !== $file->getSize()) throw new RuntimeException('Ein privater Anhang konnte nicht gelesen werden.');
            $saveAttachment->bindValue(':id', $id);
            $saveAttachment->bindValue(':mime', $mimeByExtension[$extension]);
            $saveAttachment->bindValue(':filename', (string)($meta['name'] ?? 'Anhang'));
            $saveAttachment->bindValue(':data', $bytes, PDO::PARAM_LOB);
            $saveAttachment->execute();
        }
    }

    $bridgePath = $source . DIRECTORY_SEPARATOR . 'dashboard-bridge.json';
    if (is_file($bridgePath)) {
        $bridge = json_decode((string)file_get_contents($bridgePath), true);
        if (is_array($bridge)) {
            $bridgeDefault = ['guild_ids' => [], 'checked_guild_ids' => [], 'settings' => [], 'pending' => [], 'last_seen' => 0, 'token_verified_at' => 0, 'bot_id' => ''];
            $insertState->execute(['key' => 'dashboard_bridge', 'payload' => json_encode($bridgeDefault, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
            $selectState->execute(['key' => 'dashboard_bridge']);
            $currentBridge = json_decode((string)$selectState->fetchColumn(), true);
            if (!is_array($currentBridge)) throw new RuntimeException('Dashboard-Zielzustand ist beschädigt.');
            foreach ($bridge as $key => $value) if (!array_key_exists($key, $currentBridge) || $currentBridge[$key] === [] || $currentBridge[$key] === null) $currentBridge[$key] = $value;
            $saveState->execute(['key' => 'dashboard_bridge', 'payload' => json_encode($currentBridge, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
        }
    }
    $pdo->commit();
    fwrite(STDOUT, "Privater Datenstand wurde importiert. Die Quelldateien wurden nicht verändert.\n");
} catch (Throwable $error) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR, "Import fehlgeschlagen; Datenbanktransaktion wurde zurückgerollt.\n");
    error_log('Iron Shield private-data import failed: ' . get_class($error));
    exit(1);
}
