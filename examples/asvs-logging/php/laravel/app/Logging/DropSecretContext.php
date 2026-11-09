<?php

namespace App\Logging;

use Bower\BowerEvents;
use Illuminate\Log\Logger;
use Monolog\LogRecord;

// Laravel `tap` for the json channel: drops secret-named context keys (ASVS 5.0 V16.2.5).
final class DropSecretContext
{
    public function __invoke(Logger $logger): void
    {
        $logger->getLogger()->pushProcessor(static fn (LogRecord $record): LogRecord => $record->with(
            context: array_filter(
                $record->context,
                static fn ($key) => !BowerEvents::isSecret((string) $key),
                ARRAY_FILTER_USE_KEY,
            ),
        ));
    }
}
