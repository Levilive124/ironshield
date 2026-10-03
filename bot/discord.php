<?php
declare(strict_types=1);

if (!defined('IRONSHIELD_APP')) {
    http_response_code(404);
    exit;
}

/** Discord ticket publishing is disabled by request; this function never contacts Discord. */
function ironshield_bot_create_ticket_thread(array $ticket): array
{
    throw new RuntimeException('Discord-Veröffentlichung ist deaktiviert. Das Ticket bleibt ausschließlich auf der Website.');
}
