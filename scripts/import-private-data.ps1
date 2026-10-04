$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$php = Join-Path $projectRoot '.runtime\php\php.exe'
$pdoPgsql = Join-Path $projectRoot '.runtime\php\ext\php_pdo_pgsql.dll'
$envFile = Join-Path $projectRoot '.env'
$sourceStore = Join-Path $projectRoot '.ironshield-private\store.json'
$importer = Join-Path $PSScriptRoot 'import-private-data.php'

if (-not (Test-Path -LiteralPath $php -PathType Leaf)) {
    throw 'Die mitgelieferte PHP-CLI fehlt unter .runtime\php\php.exe.'
}
if (-not (Test-Path -LiteralPath $pdoPgsql -PathType Leaf)) {
    throw 'Die PostgreSQL-Erweiterung fehlt unter .runtime\php\ext\php_pdo_pgsql.dll.'
}
if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw 'Die lokale .env-Datei fehlt. Lege sie im Projektordner an und setze dort DATABASE_URL.'
}
if (-not (Test-Path -LiteralPath $sourceStore -PathType Leaf)) {
    throw 'Die private Sicherung .ironshield-private\store.json wurde nicht gefunden.'
}

$databaseUrlConfigured = $false
foreach ($line in Get-Content -LiteralPath $envFile) {
    if ($line -match '^\s*DATABASE_URL\s*=\s*(.*?)\s*$') {
        $databaseUrlConfigured = $Matches[1].Trim('"', "'").Length -gt 0
        break
    }
}
if (-not $databaseUrlConfigured) {
    throw 'DATABASE_URL ist in der lokalen .env leer. Trage dort die Verbindungs-URL derselben PostgreSQL-Datenbank ein, die Vercel Production verwendet.'
}

Push-Location $projectRoot
try {
    & $php '-d' 'extension=php_pdo_pgsql.dll' $importer
    if ($LASTEXITCODE -ne 0) {
        throw "Der Datenimport wurde mit Fehlercode $LASTEXITCODE beendet. Die PHP-Ausgabe oben enthält die Diagnose."
    }
}
finally {
    Pop-Location
}
