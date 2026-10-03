<?php
declare(strict_types=1);

$allowedPages = ['datenschutz' => '/datenschutz.html', 'nutzungsbedingungen' => '/nutzungsbedingungen.html', 'impressum' => '/impressum.html'];
$page = (string)($_GET['seite'] ?? 'datenschutz');
header('Cache-Control: no-store');
header('Location: ' . ($allowedPages[$page] ?? $allowedPages['datenschutz']), true, 302);
exit;
