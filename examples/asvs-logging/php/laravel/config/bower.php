<?php

// Read TRUSTED_PROXIES here, not with env() at runtime: after `php artisan config:cache`
// Laravel no longer loads .env and env() outside config files returns null.
return [
    'trusted_proxies' => env('TRUSTED_PROXIES', ''),
];
