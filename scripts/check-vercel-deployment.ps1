param(
    [string]$BaseUrl = 'https://bot-ironshield-dash.vercel.app'
)

$ErrorActionPreference = 'Stop'
$base = [Uri]($BaseUrl.TrimEnd('/') + '/')
if ($base.Scheme -ne 'https') {
    throw 'BaseUrl muss eine HTTPS-Adresse sein.'
}

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)

function Get-Response([string]$Path) {
    $uri = [Uri]::new($base, $Path)
    $response = $client.GetAsync($uri).GetAwaiter().GetResult()
    try {
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [pscustomobject]@{
            Status = [int]$response.StatusCode
            ContentType = [string]$response.Content.Headers.ContentType
            Body = $body
            Location = if ($response.Headers.Location) { [string]$response.Headers.Location } else { '' }
        }
    }
    finally {
        $response.Dispose()
    }
}

try {
    Write-Host "Prüfe $($base.Host) ..."

    $health = Get-Response 'api/health.php'
    $healthJson = $null
    if ($health.ContentType -match 'application/json') {
        try { $healthJson = $health.Body | ConvertFrom-Json } catch { }
    }
    if ($health.Status -eq 200 -and $healthJson.ok -eq $true -and $healthJson.service -eq 'ironshield-api') {
        Write-Host 'PHP-API: OK (health.php liefert JSON).' -ForegroundColor Green
    }
    else {
        Write-Host "PHP-API: FEHLER (HTTP $($health.Status), Content-Type: $($health.ContentType))." -ForegroundColor Red
        if ($health.Status -eq 403) { Write-Host 'Vercel blockiert diese Anfrage. Deployment Protection bzw. Zugriffsschutz prüfen.' }
        elseif ($health.ContentType -notmatch 'application/json') { Write-Host 'Vercel liefert statt der PHP-Funktion eine HTML-Seite.' }
    }

    $data = Get-Response 'api/index.php?route=dashboard_data'
    $dataJson = $null
    if ($data.ContentType -match 'application/json') {
        try { $dataJson = $data.Body | ConvertFrom-Json } catch { }
    }
    if ($dataJson.error -eq 'login_required') {
        Write-Host 'Dashboard-API: OK (erwartetes login_required ohne Anmeldung).' -ForegroundColor Green
    }
    elseif ($dataJson.error -eq 'DATABASE_URL ist auf Vercel erforderlich, damit Sitzungen, Tickets und Dashboard-Einstellungen dauerhaft gespeichert werden.') {
        Write-Host 'Dashboard-API: DATABASE_URL fehlt in der Vercel-Production-Umgebung.' -ForegroundColor Yellow
    }
    elseif ($dataJson) {
        Write-Host "Dashboard-API: HTTP $($data.Status), JSON-Fehler: $($dataJson.error)" -ForegroundColor Yellow
    }
    else {
        Write-Host "Dashboard-API: FEHLER (HTTP $($data.Status), Content-Type: $($data.ContentType))." -ForegroundColor Red
    }

    $login = Get-Response 'api/index.php?route=dashboard_login'
    if ($login.Status -in 301, 302, 303, 307, 308 -and $login.Location) {
        $authorization = [Uri]$login.Location
        $redirectUri = ''
        if ($authorization.IsAbsoluteUri) {
            foreach ($pair in $authorization.Query.TrimStart('?').Split('&')) {
                $parts = $pair.Split('=', 2)
                if ($parts.Count -eq 2 -and [System.Net.WebUtility]::UrlDecode($parts[0]) -eq 'redirect_uri') {
                    $redirectUri = [System.Net.WebUtility]::UrlDecode($parts[1])
                    break
                }
            }
        }
        if ($redirectUri -eq '') {
            Write-Host 'Discord-Login: Redirect-URL fehlt im OAuth-Link.' -ForegroundColor Red
        }
        elseif ($redirectUri -like 'https://ironshield.novium.link/*') {
            Write-Host "Discord-Login: ALT - Vercel sendet noch zu $redirectUri" -ForegroundColor Red
        }
        elseif ($redirectUri -like "$($base.AbsoluteUri)*") {
            Write-Host "Discord-Login: Vercel-Callback wird verwendet: $redirectUri" -ForegroundColor Green
        }
        else {
            Write-Host "Discord-Login: unerwarteter Callback: $redirectUri" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Discord-Login: konnte Callback nicht auslesen (HTTP $($login.Status), Content-Type: $($login.ContentType))." -ForegroundColor Yellow
    }
}
finally {
    $client.Dispose()
    $handler.Dispose()
}
