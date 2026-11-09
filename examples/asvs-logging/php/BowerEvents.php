<?php

declare(strict_types=1);

namespace Bower;

/**
 * Bower security events for PHP apps (Laravel, Symfony). No dependencies beyond ext-json and
 * ext-curl. Builds Bower envelope 1.0.0 events, sanitises them before they leave the process
 * and posts them to a Bower collector. The collector redacts again; this is defence in depth.
 */
final class BowerEvents
{
    public const SCHEMA_VERSION = '1.0.0';
    private const CONTROL = '/[\x{0000}-\x{001f}\x{007f}\x{2028}\x{2029}]+/u';
    private const SECRET_FRAGMENTS = ['password', 'passwd', 'passphrase', 'secret', 'token', 'apikey', 'cookie',
        'authorization', 'credential', 'privatekey', 'signature'];
    private const SECRET_NAMES = ['body', 'rawbody', 'requestbody', 'responsebody', 'headers', 'payload', 'otp', 'otpcode',
        'totp', 'mfacode', 'verificationcode', 'recoverycode', 'backupcode', 'stacktrace', 'exceptionmessage', 'statement',
        'querytext', 'sqltext', 'querystring', 'rawquery'];
    private const LIMITS = ['eventOutcomeReason' => 1024, 'path' => 2048];

    public static function isSecret(string $name): bool
    {
        $normal = preg_replace('/[^a-z0-9]/', '', strtolower($name));
        if (in_array($normal, self::SECRET_NAMES, true)) {
            return true;
        }
        foreach (self::SECRET_FRAGMENTS as $fragment) {
            if (str_contains($normal, $fragment)) {
                return true;
            }
        }
        return false;
    }

    private static function isList(array $value): bool
    {
        return array_is_list($value) && $value !== [];
    }

    public static function clean(mixed $value, string $key = ''): mixed
    {
        if (is_string($value)) {
            return mb_substr(preg_replace(self::CONTROL, ' ', $value), 0, self::LIMITS[$key] ?? 256);
        }
        if (is_array($value) && self::isList($value)) {
            return array_map(fn ($item) => self::clean($item), array_slice($value, 0, 64));
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $name => $item) {
                $name = (string) $name;
                if (self::isSecret($name) || $item === null) {
                    continue;
                }
                $cleaned = self::clean($item, $name);
                if (is_array($cleaned) && $cleaned === []) {
                    continue;
                }
                $out[mb_substr(preg_replace(self::CONTROL, ' ', $name), 0, 128)] = $cleaned;
            }
            return $out;
        }
        return $value;
    }

    /** UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2). */
    public static function formatTime(\DateTimeInterface $time): string
    {
        return \DateTimeImmutable::createFromInterface($time)->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
    }

    public static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /**
     * @param array<string,mixed> $app  name, environment, version, instance
     * @param array<string,mixed> $spec eventType, eventCategory, eventAction, eventResult, eventSeverity, reason, actor,
     *                                  target, sourceIp, userAgent, route, tenantId, request, labels, attributes, change
     */
    public static function build(array $app, array $spec, ?string $eventId = null, ?\DateTimeInterface $now = null): array
    {
        $application = [];
        foreach (['name', 'environment', 'version', 'instance'] as $key) {
            if (!empty($app[$key])) {
                $application[$key] = $app[$key];
            }
        }
        if (!empty($spec['tenantId'])) {
            $application['tenantId'] = $spec['tenantId'];
        }
        $event = [
            'schemaVersion' => self::SCHEMA_VERSION,
            'eventId' => $eventId ?? self::uuid(),
            'timeGenerated' => self::formatTime($now ?? new \DateTimeImmutable()),
            'eventCategory' => $spec['eventCategory'],
            'eventType' => $spec['eventType'],
            'eventAction' => $spec['eventAction'],
            'eventResult' => $spec['eventResult'],
            'eventSeverity' => $spec['eventSeverity'] ?? 'informational',
            'application' => $application,
        ];
        if (!empty($spec['reason'])) {
            $event['eventOutcomeReason'] = $spec['reason'];
        }
        foreach (['actor', 'target'] as $part) {
            if (!empty($spec[$part])) {
                $event[$part] = $spec[$part];
            }
        }
        if (!empty($spec['sourceIp'])) {
            $event['source'] = ['ipAddress' => $spec['sourceIp']];
        }
        $request = $spec['request'] ?? [];
        if (!empty($request['path'])) {
            $request['path'] = preg_split('/[?#]/', $request['path'], 2)[0];
        }
        if ($request !== []) {
            $event['request'] = $request;
        }
        $labels = $spec['labels'] ?? [];
        if (!empty($spec['userAgent'])) {
            $labels['userAgent'] = $spec['userAgent'];
        }
        if (!empty($spec['route'])) {
            $labels['route'] = $spec['route'];
        }
        if ($labels !== []) {
            $event['labels'] = array_map('strval', $labels);
        }
        if (!empty($spec['attributes'])) {
            $event['attributes'] = $spec['attributes'];
        }
        $change = $spec['change'] ?? [];
        // Before and after values of settings and credentials never leave the process.
        if ($change !== [] && $spec['eventType'] !== 'role_membership_changed') {
            $change = array_key_exists('field', $change) ? ['field' => $change['field']] : [];
        }
        if ($change !== []) {
            $event['change'] = $change;
        }
        return self::clean($event);
    }

    /**
     * Original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For is read only when the
     * direct peer is a trusted proxy, right to left, skipping trusted hops.
     *
     * @param list<string> $trustedProxies CIDRs
     */
    public static function clientIp(string $remote, ?string $forwardedFor, array $trustedProxies): string
    {
        $trusted = static function (string $address) use ($trustedProxies): bool {
            $ip = @inet_pton($address);
            if ($ip === false) {
                return false;
            }
            foreach ($trustedProxies as $cidr) {
                [$network, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
                $net = @inet_pton($network);
                if ($net === false || strlen($net) !== strlen($ip)) {
                    continue;
                }
                $bits = $bits === null ? strlen($ip) * 8 : (int) $bits;
                $bytes = intdiv($bits, 8);
                $rest = $bits % 8;
                if (substr($ip, 0, $bytes) !== substr($net, 0, $bytes)) {
                    continue;
                }
                if ($rest === 0 || ((ord($ip[$bytes]) ^ ord($net[$bytes])) & (0xff << (8 - $rest)) & 0xff) === 0) {
                    return true;
                }
            }
            return false;
        };
        if ($forwardedFor === null || $forwardedFor === '' || !$trusted($remote)) {
            return $remote;
        }
        $hops = array_values(array_filter(array_map('trim', explode(',', $forwardedFor)), fn ($h) => $h !== ''));
        foreach (array_reverse($hops) as $hop) {
            if (!$trusted($hop)) {
                $packed = @inet_pton($hop);
                return $packed === false ? $remote : inet_ntop($packed);
            }
        }
        return $hops[0] ?? $remote;
    }

    /** Posts one event; returns the HTTP status or null. Never throws into the request path. */
    public static function send(array $event, ?string $endpoint = null, ?string $token = null, float $timeout = 2.0): ?int
    {
        $endpoint = rtrim($endpoint ?? (getenv('BOWER_COLLECTOR_URL') ?: 'http://127.0.0.1:4319'), '/');
        $token ??= getenv('BOWER_INGEST_TOKEN') ?: null;
        $curl = curl_init($endpoint . '/v1/events');
        $headers = ['Content-Type: application/json'];
        if ($token) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }
        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($event, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
        ]);
        $ok = curl_exec($curl) !== false;
        $status = $ok ? (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE) : null;
        curl_close($curl);
        return $status;
    }
}
