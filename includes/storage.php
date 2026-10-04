<?php
declare(strict_types=1);

function ironshield_storage_enabled(): bool
{
    return trim((string)(getenv('DATABASE_URL') ?: '')) !== '';
}

function ironshield_database_connection(): PDO
{
    $url = trim((string)(getenv('DATABASE_URL') ?: ''));
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['host']) || empty($parts['path'])) throw new RuntimeException('DATABASE_URL ist ungültig.');
    $database = rawurldecode(ltrim((string)$parts['path'], '/'));
    if ($database === '') throw new RuntimeException('DATABASE_URL enthält keinen Datenbanknamen.');
    $dsn = 'pgsql:host=' . $parts['host'] . ';port=' . (int)($parts['port'] ?? 5432) . ';dbname=' . $database . ';sslmode=require';
    // Some PHP/libpq builds do not send TLS SNI. Neon can route these clients
    // when the endpoint ID is supplied as a libpq connection option.
    $host = strtolower((string)$parts['host']);
    if (str_ends_with($host, '.neon.tech')) {
        $endpointId = explode('.', $host, 2)[0];
        $endpointId = preg_replace('/-pooler$/', '', $endpointId) ?? '';
        if (preg_match('/^ep-[a-z0-9-]+$/', $endpointId) === 1) {
            $dsn .= ';options=endpoint=' . $endpointId;
        }
    }
    try {
        return new PDO($dsn, rawurldecode((string)($parts['user'] ?? '')), rawurldecode((string)($parts['pass'] ?? '')), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } catch (Throwable $error) {
        $sqlState = $error instanceof PDOException && isset($error->errorInfo[0])
            ? (string)$error->errorInfo[0]
            : (string)$error->getCode();
        error_log('Iron Shield database connection failed: ' . get_class($error) . ($sqlState !== '' ? ' SQLSTATE ' . $sqlState : ''));
        $diagnostic = $sqlState !== '' ? ' (SQLSTATE ' . $sqlState . ')' : '';
        throw new RuntimeException('Der dauerhafte Datenbankspeicher ist gerade nicht verfügbar.' . $diagnostic, 0, $error);
    }
}

function ironshield_database(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $pdo = ironshield_database_connection();
    try {
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
    private ?PDO $sessionPdo = null;
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool
    {
        if ($this->sessionPdo instanceof PDO) {
            try {
                if ($this->sessionPdo->inTransaction()) $this->sessionPdo->commit();
            } catch (Throwable $error) {
                if ($this->sessionPdo->inTransaction()) $this->sessionPdo->rollBack();
                error_log('Iron Shield database session close failed: ' . get_class($error));
                $this->sessionPdo = null;
                return false;
            }
            $this->sessionPdo = null;
        }
        return true;
    }

    private function lockSession(string $id): PDO
    {
        if ($this->sessionPdo instanceof PDO && $this->sessionPdo->inTransaction()) return $this->sessionPdo;
        // Create/check the schema through the application connection first. Keep
        // the session lock in its own transaction so transaction-pooler URLs
        // retain one backend for the whole PHP session lifecycle.
        ironshield_database();
        $this->sessionPdo = ironshield_database_connection();
        $this->sessionPdo->beginTransaction();
        try {
            $lock = $this->sessionPdo->prepare('SELECT pg_advisory_xact_lock(918274, hashtext(:id))');
            $lock->execute(['id' => $id]);
            return $this->sessionPdo;
        } catch (Throwable $error) {
            if ($this->sessionPdo->inTransaction()) $this->sessionPdo->rollBack();
            $this->sessionPdo = null;
            throw $error;
        }
    }

    public function read(string $id): string|false
    {
        $pdo = $this->lockSession($id);
        $statement = $pdo->prepare('SELECT payload FROM ironshield_sessions WHERE session_id = :id AND expires_at > :now');
        $statement->execute(['id' => $id, 'now' => time()]);
        $row = $statement->fetch();
        return is_array($row) ? (string)$row['payload'] : '';
    }

    public function write(string $id, string $data): bool
    {
        $now = time();
        $pdo = $this->lockSession($id);
        try {
            $statement = $pdo->prepare('INSERT INTO ironshield_sessions (session_id, payload, last_activity, expires_at) VALUES (:id, :payload, :now, :expires) ON CONFLICT (session_id) DO UPDATE SET payload = EXCLUDED.payload, last_activity = EXCLUDED.last_activity, expires_at = EXCLUDED.expires_at');
            $saved = $statement->execute(['id' => $id, 'payload' => $data, 'now' => $now, 'expires' => $now + 28800]);
            $pdo->commit();
            $this->sessionPdo = null;
            return $saved;
        } catch (Throwable $error) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $this->sessionPdo = null;
            throw $error;
        }
    }

    public function destroy(string $id): bool
    {
        $pdo = $this->lockSession($id);
        try {
            $statement = $pdo->prepare('DELETE FROM ironshield_sessions WHERE session_id = :id');
            $deleted = $statement->execute(['id' => $id]);
            $pdo->commit();
            $this->sessionPdo = null;
            return $deleted;
        } catch (Throwable $error) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            $this->sessionPdo = null;
            throw $error;
        }
    }

    public function gc(int $max_lifetime): int|false
    {
        $statement = ironshield_database()->prepare('DELETE FROM ironshield_sessions WHERE expires_at <= :now');
        return $statement->execute(['now' => time()]) ? $statement->rowCount() : false;
    }
}
