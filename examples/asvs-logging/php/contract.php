<?php
// Print the contract events and proxy results as JSON lines (see ../contract).
declare(strict_types=1);
require __DIR__ . '/BowerEvents.php';

use Bower\BowerEvents;

function sortKeys(mixed $v): mixed
{
    if (!is_array($v)) {
        return $v;
    }
    if (array_is_list($v)) {
        return array_map('sortKeys', $v);
    }
    ksort($v, SORT_STRING);
    return array_map('sortKeys', $v);
}

// Python json.dumps(sort_keys=True): ", " and ": " separators, \uXXXX for non-ASCII.
function pyJson(mixed $v): string
{
    $json = json_encode(sortKeys($v), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    return preg_replace(['/":/', '/,"/'], ['": ', ', "'], $json);
}

$cases = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
$now = new DateTimeImmutable($cases['now']);
foreach ($cases['cases'] as $c) {
    echo pyJson(BowerEvents::build($cases['app'], $c['spec'], $c['eventId'], $now)), "\n";
}
foreach ($cases['proxyCases'] as $c) {
    echo pyJson(['clientIp' => BowerEvents::clientIp($c['remote'], $c['forwardedFor'], $c['trusted'])]), "\n";
}
