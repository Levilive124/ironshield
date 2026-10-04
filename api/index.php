<?php
declare(strict_types=1);

// Vercel PHP function entry point for authenticated APIs and OAuth callbacks.
define('IRONSHIELD_API_ENTRY', true);
require dirname(__DIR__) . '/index.php';
