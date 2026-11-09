<?php
// A plain PHP app with the same request context and events as the Laravel example, so the event
// path can be run without Laravel:
//   BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... php -S 127.0.0.1:8000 server.php
declare(strict_types=1);
require __DIR__ . '/BowerEvents.php';

use Bower\BowerEvents;

$traceparent = $_SERVER['HTTP_TRACEPARENT'] ?? '';
$requestId = strlen($traceparent) === 55 ? substr($traceparent, 3, 32) : BowerEvents::uuid();
$trusted = array_values(array_filter(array_map('trim', explode(',', getenv('TRUSTED_PROXIES') ?: ''))));
$clientIp = BowerEvents::clientIp($_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null, $trusted);
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
header('X-Request-Id: ' . $requestId);
header('Content-Type: application/json');

$emit = static function (array $spec) use ($requestId, $clientIp, $path): void {
    $app = ['name' => getenv('BOWER_APP_NAME') ?: 'php-example', 'environment' => getenv('APP_ENV') ?: 'development', 'version' => '1.0.0'];
    $event = BowerEvents::build($app, $spec + ['sourceIp' => $clientIp, 'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? null, 'route' => $path,
        'request' => ['correlationId' => $requestId, 'method' => $_SERVER['REQUEST_METHOD'], 'path' => $path]]);
    register_shutdown_function(static fn () => BowerEvents::send($event));
};

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/login') {
    $body = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($body)) {
        $emit(['eventCategory' => 'application-security', 'eventType' => 'input_validation_failure', 'eventAction' => 'validation.reject',
            'eventResult' => 'failure', 'eventSeverity' => 'low', 'reason' => 'MalformedJson']);
        http_response_code(400);
        echo '{"error":"bad request"}';
        return;
    }
    $username = (string) ($body['username'] ?? '');
    if (!hash_equals('demo:demo-password', $username . ':' . (string) ($body['password'] ?? ''))) {
        $emit(['eventCategory' => 'authentication', 'eventType' => 'authentication_failure', 'eventAction' => 'authentication.attempt',
            'eventResult' => 'failure', 'eventSeverity' => 'low', 'reason' => 'InvalidCredentials', 'actor' => ['username' => $username]]);
        http_response_code(401);
        echo '{"error":"invalid credentials"}';
        return;
    }
    $emit(['eventCategory' => 'authentication', 'eventType' => 'authentication_success', 'eventAction' => 'authentication.login',
        'eventResult' => 'success', 'actor' => ['userId' => 'user-demo', 'username' => $username], 'labels' => ['authMethod' => 'password']]);
    http_response_code(204);
    return;
}
if ($path === '/admin/users') {
    $emit(['eventCategory' => 'authorisation', 'eventType' => 'authorisation_failure', 'eventAction' => 'authz.function',
        'eventResult' => 'denied', 'eventSeverity' => 'medium', 'actor' => ['userId' => 'user-demo', 'role' => 'member'],
        'target' => ['type' => 'function', 'id' => 'admin.users.list']]);
    http_response_code(403);
    echo '{"error":"forbidden"}';
    return;
}
http_response_code(404);
