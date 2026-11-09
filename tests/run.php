<?php

declare(strict_types=1);

require_once __DIR__ . '/../modules/addons/modd_health/lib/Core.php';

use ModdHealth\Core;

$settings = Core::defaults();
$settings['products']['email'] = [1];
$settings['products']['legacy'] = [2];
$settings['hosting_ipv4'] = ['192.0.2.10'];
$settings['email'] = [
    'mx_pattern' => '^mx\\.{domain}$',
    'spf_pattern' => '^v=spf1',
    'dkim_selectors' => ['default'],
    'dkim_cname_pattern' => '^dkim\\.example$',
];
Core::validateSettings($settings, true);

$posted = Core::settingsFromPost([
    'products_email' => ['3'],
    'hosting_ipv4' => "192.0.2.2\ninvalid",
    'mx_pattern' => 'invalid pattern',
    'spf_pattern' => '^v=spf1',
    'dkim_selectors' => 'default',
    'dkim_cname_pattern' => '^dkim\\.example$',
    'legacy_url_template' => 'https://{domain}/legacy',
    'container_url_template' => 'https://{domain}/container',
    'database_tls' => 'required',
]);
assert($posted['products']['email'] === [3]);
assert($posted['hosting_ipv4'] === ['192.0.2.2', 'invalid']);
assert($posted['email']['mx_pattern'] === 'invalid pattern');
assert($posted['container']['url_template'] === 'https://{domain}/container');
assert($posted['database_tls'] === 'required');

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
assert(Core::dnsSummaryHTML('Nameservers: ns1.modd.net.au, ns2.modd.net.au; A: 203.88.104.34; edm: UP') === '<strong>Nameservers:</strong> <span class="text-success">ns1.modd.net.au</span>, <span class="text-success">ns2.modd.net.au</span>; <strong>A:</strong> 203.88.104.34; <strong>edm:</strong> UP');
assert(Core::dnsSummaryHTML('A: <script>') === '<strong>A:</strong> &lt;script&gt;');
assert(Core::reasons($result) === ['incorrect IP in A record', 'health check URL failed']);
assert(Core::nameservers(['dns' => ['nameservers' => ['ns1.modd.net.au.', 'NS2.EXAMPLE']]]) === [
    ['name' => 'ns1.modd.net.au.', 'preferred' => true],
    ['name' => 'NS2.EXAMPLE', 'preferred' => false],
]);
assert(Core::nameservers(['dns' => ['nameservers' => ['n2.modd.net.au']]])[0]['preferred']);
assert(Core::escape('<script>') === '&lt;script&gt;');

$modern = $result;
$modern['dns']['authorities'] = [[
    'healthy' => true,
    'records' => ['mx' => ['mx.example'], 'spf' => ['v=spf1 -all'], 'dmarc' => ['v=DMARC1; p=none']],
    'checks' => [
        ['name' => 'mx', 'healthy' => true],
        ['name' => 'spf', 'healthy' => true],
        ['name' => 'dmarc', 'healthy' => true],
    ],
    'dmarc_policy_domain' => 'example.com',
]];
foreach (['email', 'legacy', 'container'] as $profile) {
    $summary = Core::dnsSummary($modern, $profile);
    assert(str_contains($summary, 'MX: mx.example'));
    assert(str_contains($summary, 'SPF: valid'));
    assert(str_contains($summary, 'DMARC: valid (policy: example.com)'));
}
$modern['dns']['authorities'][0]['checks'][1] = ['name' => 'spf', 'healthy' => false, 'message' => 'duplicate SPF <script>'];
$summary = Core::dnsSummary($modern, 'legacy');
assert(str_contains($summary, 'SPF: invalid (duplicate SPF <script>)'));
assert(str_contains(Core::dnsSummaryHTML($summary), '&lt;script&gt;'));
$modern['dns']['authorities'][0]['checks'][1] = ['name' => 'spf', 'healthy' => true, 'message' => 'not applicable (no mail service)'];
$modern['dns']['authorities'][0]['checks'][2] = ['name' => 'dmarc', 'healthy' => true, 'message' => 'not applicable (no mail service)'];
$modern['dns']['authorities'][0]['records']['mx'] = [];
unset($modern['dns']['authorities'][0]['dmarc_policy_domain']);
assert(str_contains(Core::dnsSummary($modern, 'legacy'), 'DMARC: not applicable (no mail service)'));
$modern['dns']['authorities'][0]['records']['notify:mx'] = ['mx.example'];
$modern['dns']['authorities'][0]['records']['notify:spf'] = ['v=spf1 broken'];
$modern['dns']['authorities'][0]['checks'][] = ['name' => 'notify:spf', 'healthy' => false];
assert(str_contains(Core::dnsSummary($modern, 'container'), 'notify: DOWN'));
// A healthy complete authority wins over a partial response.
$partial = $modern['dns']['authorities'][0];
$partial['healthy'] = false;
$partial['checks'][1] = ['name' => 'spf', 'healthy' => false];
$modern['dns']['authorities'][] = $partial;
assert(str_contains(Core::dnsSummary($modern, 'legacy'), 'SPF: not applicable'));
assert(!str_contains(Core::dnsSummary($result, 'legacy'), 'DMARC:'));

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
