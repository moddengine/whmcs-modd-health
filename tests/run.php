<?php

declare(strict_types=1);

require_once __DIR__ . '/../modules/addons/modd_health/lib/Core.php';

use ModdHealth\Core;

$settings = Core::defaults();
$settings['products']['email'] = [1];
$settings['products']['legacy'] = [2];
$settings['hosting_ipv4'] = ['192.0.2.10'];
$settings['email'] = [
    'mx_pattern' => '^mx\\.example$',
    'spf_pattern' => '^v=spf1',
    'dkim_selectors' => ['default'],
    'dkim_cname_pattern' => '^dkim\\.example$',
];
Core::validateSettings($settings, true);

$duplicate = $settings;
$duplicate['products']['container'] = [2];
expectException(static fn () => Core::validateSettings($duplicate, true), 'more than one');

$badIP = $settings;
$badIP['hosting_ipv4'] = ['999.1.1.1'];
expectException(static fn () => Core::validateSettings($badIP, true), 'Invalid hosting');

$badRegex = $settings;
$badRegex['email']['mx_pattern'] = '(?=unsupported)';
expectException(static fn () => Core::validateSettings($badRegex, true), 'unsupported');

$result = [
    'dns' => [
        'nameservers' => ['ns1.example', 'ns2.example'],
        'authorities' => [
            ['records' => ['a' => ['192.0.2.10'], 'edm:mx' => ['mx.example'], 'edm:spf' => ['v=spf1 -all'], 'notify:mx' => ['mx.example'], 'notify:spf' => ['v=spf1 -all']]],
        ],
    ],
    'checks' => [
        ['name' => 'authoritative_dns', 'healthy' => false, 'message' => 'incorrect IP in A record'],
        ['name' => 'http', 'healthy' => false, 'message' => 'health check URL failed'],
    ],
];
$summary = Core::dnsSummary($result, 'container');
assert(str_contains($summary, 'Nameservers: ns1.example, ns2.example'));
assert(str_contains($summary, 'A: 192.0.2.10'));
assert(str_contains($summary, 'edm: UP'));
assert(Core::reasons($result) === ['incorrect IP in A record', 'health check URL failed']);
assert(Core::escape('<script>') === '&lt;script&gt;');

echo "PHP checks passed\n";

function expectException(callable $callback, string $contains): void
{
    try {
        $callback();
    } catch (RuntimeException $e) {
        assert(str_contains($e->getMessage(), $contains));
        return;
    }
    throw new RuntimeException('Expected exception containing: ' . $contains);
}
