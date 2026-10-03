<?php
declare(strict_types=1);

function ironshield_storage_enabled(): bool
{
    return trim((string)(getenv('DATABASE_URL') ?: '')) !== '';
}

function ironshield_database(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $url = trim((string)(getenv('DATABASE_URL') ?: ''));
    if ($url === '') throw new RuntimeException('Der dauerhafte Datenbankspeicher ist nicht eingerichtet.');
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['host']) || empty($parts['path'])) throw new RuntimeException('DATABASE_URL ist ungültig.');
    $database = rawurldecode(ltrim((string)$parts['path'], '/'));
    if ($database === '') throw new RuntimeException('DATABASE_URL enthält keinen Datenbanknamen.');
    $dsn = 'pgsql:host=' . $parts['host'] . ';port=' . (int)($parts['port'] ?? 5432) . ';dbname=' . $database . ';sslmode=require';
    try {
        $pdo = new PDO($dsn, rawurldecode((string)($parts['user'] ?? '')), rawurldecode((string)($parts['pass'] ?? '')), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec("CREATE TABLE IF NOT EXISTS ironshield_state (state_key TEXT PRIMARY KEY, payload JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
        $pdo->exec("CREATE TABLE IF NOT EXISTS ironshield_sessions (session_id TEXT PRIMARY KEY, payload TEXT NOT NULL, last_activity BIGINT NOT NULL, expires_at BIGINT NOT NULL)");
        $pdo->exec("CREATE INDEX IF NOT EXISTS ironshield_sessions_expires_idx ON ironshield_sessions (expires_at)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS ironshield_attachments (attachment_id TEXT PRIMARY KEY, mime TEXT NOT NULL, filename TEXT NOT NULL, data BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
        $pdo->exec("CREATE TABLE IF NOT EXISTS ironshield_migrations (migration_key TEXT PRIMARY KEY, completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
    } catch (Throwable $error) {
        $pdo = null;
        error_log('Iron Shield database connection/setup failed: ' . get_class($error));
        throw new RuntimeException('Der dauerhafte Datenbankspeicher ist gerade nicht verfügbar.');
    }
    return $pdo;
}

function ironshield_state_change(string $key, array $default, callable $callback, bool $write): mixed
{
    $pdo = ironshield_database();
    $pdo->beginTransaction();
    try {
        $insert = $pdo->prepare('INSERT INTO ironshield_state (state_key, payload) VALUES (:key, CAST(:payload AS JSONB)) ON CONFLICT (state_key) DO NOTHING');
        $insert->execute(['key' => $key, 'payload' => json_encode($default, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
        $select = $pdo->prepare('SELECT payload FROM ironshield_state WHERE state_key = :key' . ($write ? ' FOR UPDATE' : ''));
        $select->execute(['key' => $key]);
        $row = $select->fetch();
        $state = is_array($row) ? json_decode((string)$row['payload'], true) : null;
        if (!is_array($state)) throw new RuntimeException('Der gespeicherte Website-Zustand ist beschädigt.');
        $result = $callback($state);
        if ($write) {
            $update = $pdo->prepare('UPDATE ironshield_state SET payload = CAST(:payload AS JSONB), updated_at = NOW() WHERE state_key = :key');
            $update->execute(['key' => $key, 'payload' => json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)]);
        }
        $pdo->commit();
        return $result;
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $error;
    }
}

function ironshield_attachment_save(string $id, string $mime, string $filename, string $bytes): void
{
    $statement = ironshield_database()->prepare('INSERT INTO ironshield_attachments (attachment_id, mime, filename, data) VALUES (:id, :mime, :filename, :data)');
    $statement->bindValue(':id', $id);
    $statement->bindValue(':mime', $mime);
    $statement->bindValue(':filename', $filename);
    $statement->bindValue(':data', $bytes, PDO::PARAM_LOB);
    $statement->execute();
}

function ironshield_attachment_get(string $id): ?array
{
    $statement = ironshield_database()->prepare('SELECT mime, filename, data FROM ironshield_attachments WHERE attachment_id = :id');
    $statement->execute(['id' => $id]);
    $row = $statement->fetch();
    if (!is_array($row)) return null;
    $bytes = $row['data'];
    if (is_resource($bytes)) $bytes = stream_get_contents($bytes);
    return is_string($bytes) ? ['mime' => (string)$row['mime'], 'filename' => (string)$row['filename'], 'data' => $bytes] : null;
}

function ironshield_attachment_delete(string $id): void
{
    $statement = ironshield_database()->prepare('DELETE FROM ironshield_attachments WHERE attachment_id = :id');
    $statement->execute(['id' => $id]);
}

final class IronShieldPostgresSessionHandler implements SessionHandlerInterface
{
    private ?string $lockedId = null;
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool
    {
        if ($this->lockedId !== null) {
            $statement = ironshield_database()->prepare('SELECT pg_advisory_unlock(hashtext(:id))');
            $statement->execute(['id' => $this->lockedId]);
            $this->lockedId = null;
        }
        return true;
    }

    public function read(string $id): string|false
    {
        $lock = ironshield_database()->prepare('SELECT pg_advisory_lock(hashtext(:id))');
        $lock->execute(['id' => $id]);
        $this->lockedId = $id;
        $statement = ironshield_database()->prepare('SELECT payload FROM ironshield_sessions WHERE session_id = :id AND expires_at > :now');
        $statement->execute(['id' => $id, 'now' => time()]);
        $row = $statement->fetch();
        return is_array($row) ? (string)$row['payload'] : '';
    }

    public function write(string $id, string $data): bool
    {
        $now = time();
        $statement = ironshield_database()->prepare('INSERT INTO ironshield_sessions (session_id, payload, last_activity, expires_at) VALUES (:id, :payload, :now, :expires) ON CONFLICT (session_id) DO UPDATE SET payload = EXCLUDED.payload, last_activity = EXCLUDED.last_activity, expires_at = EXCLUDED.expires_at');
        $saved = $statement->execute(['id' => $id, 'payload' => $data, 'now' => $now, 'expires' => $now + 28800]);
        $this->close();
        return $saved;
    }

    public function destroy(string $id): bool
    {
        $statement = ironshield_database()->prepare('DELETE FROM ironshield_sessions WHERE session_id = :id');
        $deleted = $statement->execute(['id' => $id]);
        $this->close();
        return $deleted;
    }

    public function gc(int $max_lifetime): int|false
    {
        $statement = ironshield_database()->prepare('DELETE FROM ironshield_sessions WHERE expires_at <= :now');
        return $statement->execute(['now' => time()]) ? $statement->rowCount() : false;
    }
}
