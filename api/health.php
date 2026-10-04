<?php
declare(strict_types=1);

// A lightweight probe that confirms Vercel is executing the PHP API runtime.
// It intentionally does not initialize sessions, read environment variables,
// or connect to the database.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');

echo json_encode([
    'ok' => true,
    'service' => 'ironshield-api',
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
