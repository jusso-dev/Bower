<?php

// Merge into config/logging.php: a JSON channel for application logs. Security events go to
// Bower, not to this channel. JSON encoding escapes CR and LF (ASVS 5.0 V16.4.1).
return [
    'channels' => [
        'json' => [
            'driver' => 'monolog',
            'handler' => Monolog\Handler\StreamHandler::class,
            'with' => ['stream' => 'php://stderr'],
            'formatter' => Monolog\Formatter\JsonFormatter::class,
            'processors' => [
                // Strip secret-named context keys before they reach any handler (V16.2.5).
                static function (Monolog\LogRecord $record): Monolog\LogRecord {
                    $context = array_filter($record->context, static fn ($key) => !Bower\BowerEvents::isSecret((string) $key), ARRAY_FILTER_USE_KEY);
                    return $record->with(context: $context);
                },
            ],
        ],
    ],
];
