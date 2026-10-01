<?php

declare(strict_types=1);

namespace ModdHealth;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use Throwable;
use WHMCS\Database\Capsule;

final class Core
{
    public const MODULE = 'modd_health';

    /** @return array<string,mixed> */
    public static function defaults(): array
    {
        return [
            'products' => ['email' => [], 'legacy' => [], 'container' => []],
            'hosting_ipv4' => [],
            'email' => ['mx_pattern' => '', 'spf_pattern' => '', 'dkim_selectors' => [], 'dkim_cname_pattern' => ''],
            'legacy' => ['url_template' => 'https://{domain}/~/health/check'],
            'container' => ['url_template' => 'https://{domain}/~/health/check'],
            'database_tls' => 'disabled',
        ];
    }

    /** @return array{settings:array<string,mixed>,webhook_ciphertext:string} */
    public static function load(): array
    {
        $row = Capsule::table('mod_modd_health_config')->where('id', 1)->first();
        if (!$row) {
            return ['settings' => self::defaults(), 'webhook_ciphertext' => ''];
        }
        $decoded = json_decode((string) $row->settings_json, true);
        return [
            'settings' => is_array($decoded) ? array_replace_recursive(self::defaults(), $decoded) : self::defaults(),
            'webhook_ciphertext' => (string) ($row->webhook_ciphertext ?? ''),
        ];
    }

    /** @param array<string,mixed> $post */
    public static function save(array $post): void
    {
        $current = self::load();
        $settings = self::settingsFromPost($post);
        $webhook = trim((string) ($post['webhook_url'] ?? ''));
        $ciphertext = $current['webhook_ciphertext'];
        if (isset($post['clear_webhook'])) {
            $ciphertext = '';
        } elseif ($webhook !== '') {
            self::validateHTTPS($webhook, false);
            $response = localAPI('EncryptPassword', ['password2' => $webhook]);
            if (($response['result'] ?? '') !== 'success' || !is_string($response['password'] ?? null)) {
                throw new RuntimeException('WHMCS could not encrypt the Google Chat webhook.');
            }
            $ciphertext = $response['password'];
        }
        self::validateSettings($settings, $ciphertext !== '');
        $configuredIDs = array_merge($settings['products']['email'], $settings['products']['legacy'], $settings['products']['container']);
        if (Capsule::table('tblproducts')->whereIn('id', $configuredIDs)->count() !== count($configuredIDs)) {
            throw new RuntimeException('One or more selected products no longer exist.');
        }
        [$code, , $error] = self::runChecker(['--validate-config'], self::checkerConfigurationJSON($settings));
        if ($code !== 0) {
            throw new RuntimeException('Checker rejected the configuration: ' . self::oneLine($error));
        }
        Capsule::table('mod_modd_health_config')->updateOrInsert(
            ['id' => 1],
            ['settings_json' => self::json($settings), 'webhook_ciphertext' => $ciphertext, 'updated_at' => gmdate('Y-m-d H:i:s')]
        );
    }

    /**
     * @param array<string,mixed> $post
     * @return array<string,mixed>
     */
    public static function settingsFromPost(array $post): array
    {
        return [
            'products' => [
                'email' => self::ids($post['products_email'] ?? []),
                'legacy' => self::ids($post['products_legacy'] ?? []),
                'container' => self::ids($post['products_container'] ?? []),
            ],
            'hosting_ipv4' => self::lines((string) ($post['hosting_ipv4'] ?? '')),
            'email' => [
                'mx_pattern' => trim((string) ($post['mx_pattern'] ?? '')),
                'spf_pattern' => trim((string) ($post['spf_pattern'] ?? '')),
                'dkim_selectors' => self::lines((string) ($post['dkim_selectors'] ?? '')),
                'dkim_cname_pattern' => trim((string) ($post['dkim_cname_pattern'] ?? '')),
            ],
            'legacy' => ['url_template' => trim((string) ($post['legacy_url_template'] ?? ''))],
            'container' => ['url_template' => trim((string) ($post['container_url_template'] ?? ''))],
            'database_tls' => (string) ($post['database_tls'] ?? 'disabled'),
        ];
    }

    /** @param array<string,mixed> $settings */
    public static function validateSettings(array $settings, bool $hasWebhook): void
    {
        $profiles = $settings['products'] ?? [];
        $all = [];
        foreach (['email', 'legacy', 'container'] as $profile) {
            foreach (self::ids(is_array($profiles) ? ($profiles[$profile] ?? []) : []) as $id) {
                if (isset($all[$id])) {
                    throw new RuntimeException("Product {$id} is assigned to more than one health profile.");
                }
                $all[$id] = true;
            }
        }
        if ($all === []) {
            throw new RuntimeException('Select at least one product.');
        }
        if (!$hasWebhook) {
            throw new RuntimeException('A Google Chat webhook is required.');
        }
        $ips = is_array($settings['hosting_ipv4'] ?? null) ? $settings['hosting_ipv4'] : [];
        if (($profiles['legacy'] ?? []) !== [] || ($profiles['container'] ?? []) !== []) {
            if ($ips === []) {
                throw new RuntimeException('At least one permitted hosting IPv4 address is required.');
            }
            foreach ($ips as $ip) {
                if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                    throw new RuntimeException("Invalid hosting IPv4 address: {$ip}");
                }
            }
        }
        $email = is_array($settings['email'] ?? null) ? $settings['email'] : [];
        foreach (['mx_pattern', 'spf_pattern', 'dkim_cname_pattern'] as $field) {
            self::validateRE2((string) ($email[$field] ?? ''), $field);
        }
        if (self::lines(implode("\n", is_array($email['dkim_selectors'] ?? null) ? $email['dkim_selectors'] : [])) === []) {
            throw new RuntimeException('At least one DKIM selector is required.');
        }
        self::validateTemplate((string) (($settings['legacy']['url_template'] ?? '')));
        self::validateTemplate((string) (($settings['container']['url_template'] ?? '')));
        if (!in_array($settings['database_tls'] ?? '', ['disabled', 'preferred', 'required'], true)) {
            throw new RuntimeException('Invalid database TLS mode.');
        }
    }

    /** @return list<object> */
    public static function products(): array
    {
        return Capsule::table('tblproducts')
            ->leftJoin('tblproductgroups', 'tblproductgroups.id', '=', 'tblproducts.gid')
            ->orderBy('tblproductgroups.order')
            ->orderBy('tblproducts.order')
            ->get(['tblproducts.id', 'tblproducts.name', 'tblproducts.hidden', 'tblproductgroups.name as group_name'])
            ->all();
    }

    /** @return array<string,mixed> */
    public static function buildJob(): array
    {
        $stored = self::load();
        self::validateSettings($stored['settings'], $stored['webhook_ciphertext'] !== '');
        $webhookResult = localAPI('DecryptPassword', ['password2' => $stored['webhook_ciphertext']]);
        if (($webhookResult['result'] ?? '') !== 'success' || !is_string($webhookResult['password'] ?? null)) {
            throw new RuntimeException('WHMCS could not decrypt the Google Chat webhook.');
        }
        $settings = $stored['settings'];
        $profileByProduct = [];
        foreach (['email', 'legacy', 'container'] as $profile) {
            foreach (self::ids($settings['products'][$profile] ?? []) as $id) {
                $profileByProduct[$id] = $profile;
            }
        }
        $rows = Capsule::table('tblhosting')
            ->where('domainstatus', 'Active')
            ->where('domain', '<>', '')
            ->whereIn('packageid', array_keys($profileByProduct))
            ->get(['id', 'userid', 'packageid', 'domain']);
        $sites = [];
        foreach ($rows as $row) {
            $domain = strtolower(rtrim(trim((string) $row->domain), '.'));
            if (!self::validDomain($domain)) {
                throw new RuntimeException("Service {$row->id} has an invalid domain.");
            }
            $sites[] = [
                'service_id' => (int) $row->id,
                'client_id' => (int) $row->userid,
                'product_id' => (int) $row->packageid,
                'domain' => $domain,
                'profile' => $profileByProduct[(int) $row->packageid],
            ];
        }
        $db = Capsule::connection()->getConfig();
        $socket = (string) ($db['unix_socket'] ?? '');
        return [
            'schema' => 1,
            'run_id' => bin2hex(random_bytes(16)),
            'schedule_window_seconds' => 300,
            'site_timeout_seconds' => 60,
            'database' => [
                'network' => $socket !== '' ? 'unix' : 'tcp',
                'host' => (string) ($db['host'] ?? 'localhost'),
                'port' => (int) ($db['port'] ?? 3306),
                'socket' => $socket,
                'name' => (string) ($db['database'] ?? ''),
                'username' => (string) ($db['username'] ?? ''),
                'password' => (string) ($db['password'] ?? ''),
                'tls' => (string) $settings['database_tls'],
            ],
            'webhook_url' => $webhookResult['password'],
            'configuration' => self::checkerConfiguration($settings),
            'sites' => $sites,
        ];
    }

    /**
     * @param list<string> $arguments
     * @return array{0:int,1:string,2:string}
     */
    public static function runChecker(array $arguments, string $stdin): array
    {
        $binary = self::binaryPath();
        if (!is_file($binary) || !is_executable($binary)) {
            throw new RuntimeException("Checker binary is missing or not executable: {$binary}");
        }
        $command = array_merge([$binary], $arguments);
        $pipes = [];
        $process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start the checker process.');
        }
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), (string) $stdout, (string) $stderr];
    }

    public static function binaryPath(): string
    {
        $arch = strtolower(php_uname('m'));
        $suffix = match ($arch) {
            'x86_64', 'amd64' => 'amd64',
            'aarch64', 'arm64' => 'arm64',
            default => throw new RuntimeException("Unsupported architecture: {$arch}"),
        };
        return dirname(__DIR__) . '/bin/modd-health-checker-linux-' . $suffix;
    }

    /** @return array{dns:string,health:string,nameservers:list<array{name:string,preferred:bool}>}|null */
    public static function serviceStatus(int $serviceID): ?array
    {
        if ($serviceID < 1 || !Capsule::schema()->hasTable('mod_modd_health_state')) {
            return null;
        }
        $row = Capsule::table('mod_modd_health_state')->where('service_id', $serviceID)->first();
        if (!$row) {
            $service = Capsule::table('tblhosting')->where('id', $serviceID)->first(['packageid']);
            if (!$service) {
                return null;
            }
            $products = self::load()['settings']['products'];
            $selected = array_merge($products['email'] ?? [], $products['legacy'] ?? [], $products['container'] ?? []);
            if (!in_array((int) $service->packageid, $selected, true)) {
                return null;
            }
            return ['dns' => 'Pending first check', 'health' => 'Pending first check', 'nameservers' => []];
        }
        $result = json_decode((string) $row->checks_json, true);
        if (!is_array($result)) {
            $result = [];
        }
        $down = (string) $row->stable_state === 'failed' || (string) $row->observed_state === 'failed';
        if (!$down) {
            $health = 'UP';
        } else {
            $since = self::formatTime((string) ($row->first_failure_at ?? ''));
            $reasons = self::reasons($result);
            if ((string) $row->stable_state === 'failed' && (string) $row->observed_state === 'healthy') {
                $reasons = ['recovery pending confirmation'];
            }
            $health = 'Down since ' . $since . ' (reason: ' . implode('; ', $reasons ?: ['required health checks failed']) . ')';
        }
        return ['dns' => self::dnsSummary($result, (string) $row->profile), 'health' => $health, 'nameservers' => self::nameservers($result)];
    }

    /**
     * @param array<string,mixed> $result
     * @return list<array{name:string,preferred:bool}>
     */
    public static function nameservers(array $result): array
    {
        $nameservers = $result['dns']['nameservers'] ?? [];
        if (!is_array($nameservers)) {
            return [];
        }
        return array_values(array_map(static fn (string $name): array => [
            'name' => $name,
            'preferred' => in_array(strtolower(rtrim($name, '.')), ['ns1.modd.net.au', 'n2.modd.net.au'], true),
        ], array_filter($nameservers, 'is_string')));
    }

    /** @param array<string,mixed> $result */
    public static function dnsSummary(array $result, string $profile): string
    {
        $dns = is_array($result['dns'] ?? null) ? $result['dns'] : [];
        $nameservers = is_array($dns['nameservers'] ?? null) ? $dns['nameservers'] : [];
        $parts = ['Nameservers: ' . ($nameservers === [] ? 'none' : implode(', ', $nameservers))];
        $authorities = is_array($dns['authorities'] ?? null) ? $dns['authorities'] : [];
        $records = [];
        foreach ($authorities as $authority) {
            if (!is_array($authority) || !is_array($authority['records'] ?? null)) {
                continue;
            }
            foreach ($authority['records'] as $key => $values) {
                foreach (is_array($values) ? $values : [] as $value) {
                    $records[(string) $key][(string) $value] = true;
                }
            }
        }
        if ($profile === 'email') {
            $parts[] = 'MX: ' . self::recordText($records, 'mx');
            $parts[] = 'SPF: ' . (($records['spf'] ?? []) !== [] ? 'present' : 'missing');
            $selectors = [];
            foreach (array_keys($records) as $key) {
                if (str_starts_with($key, 'dkim:')) {
                    $selectors[] = substr($key, 5) . ' UP';
                }
            }
            $parts[] = 'DKIM: ' . ($selectors === [] ? 'missing' : implode(', ', $selectors));
        } else {
            $parts[] = 'A: ' . self::recordText($records, 'a');
            if ($profile === 'container') {
                foreach (['edm', 'notify'] as $prefix) {
                    $up = false;
                    foreach ($authorities as $authority) {
                        $authorityRecords = is_array($authority) && is_array($authority['records'] ?? null) ? $authority['records'] : [];
                        $up = $up || (($authorityRecords[$prefix . ':mx'] ?? []) !== [] && ($authorityRecords[$prefix . ':spf'] ?? []) !== []);
                    }
                    $parts[] = $prefix . ': ' . ($up ? 'UP' : 'DOWN');
                }
            }
        }
        $warnings = [];
        foreach ($authorities as $authority) {
            if (is_array($authority) && empty($authority['healthy'])) {
                $warnings[] = (string) ($authority['nameserver'] ?? 'nameserver') . ' failed';
            }
        }
        if ($warnings !== []) {
            $parts[] = 'Warnings: ' . implode(', ', array_values(array_unique($warnings)));
        }
        return implode('; ', $parts);
    }

    /**
     * @param array<string,mixed> $result
     * @return list<string>
     */
    public static function reasons(array $result): array
    {
        $reasons = [];
        foreach (is_array($result['checks'] ?? null) ? $result['checks'] : [] as $check) {
            if (is_array($check) && empty($check['healthy']) && is_string($check['message'] ?? null) && $check['message'] !== '') {
                $reasons[$check['message']] = true;
            }
        }
        return array_keys($reasons);
    }

    public static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * @param array<string,mixed> $settings
     * @return array<string,mixed>
     */
    public static function checkerConfiguration(array $settings): array
    {
        return [
            'hosting_ipv4' => array_values($settings['hosting_ipv4']),
            'email' => $settings['email'],
            'legacy' => $settings['legacy'],
            'container' => $settings['container'],
        ];
    }

    /** @param array<string,mixed> $settings */
    private static function checkerConfigurationJSON(array $settings): string
    {
        return self::json(self::checkerConfiguration($settings));
    }

    /**
     * @param mixed $value
     * @return list<int>
     */
    private static function ids($value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $ids = [];
        foreach ($value as $id) {
            if (filter_var($id, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) !== false) {
                $ids[(int) $id] = true;
            }
        }
        $result = array_keys($ids);
        sort($result);
        return $result;
    }

    /** @return list<string> */
    private static function lines(string $value): array
    {
        $lines = preg_split('/[\r\n,]+/', $value) ?: [];
        $lines = array_values(array_unique(array_filter(array_map('trim', $lines), static fn (string $line): bool => $line !== '')));
        sort($lines);
        return $lines;
    }

    private static function validateRE2(string $pattern, string $name): void
    {
        if ($pattern === '') {
            throw new RuntimeException("{$name} is required.");
        }
        if (str_contains($pattern, '(?') || preg_match('/\\\\[1-9]/', $pattern)) {
            throw new RuntimeException("{$name} uses a construct unsupported by Go RE2.");
        }
        if (@preg_match('~' . str_replace('~', '\\~', $pattern) . '~', '') === false) {
            throw new RuntimeException("{$name} is not a valid regular expression.");
        }
    }

    private static function validateTemplate(string $template): void
    {
        if (substr_count($template, '{domain}') !== 1) {
            throw new RuntimeException('Each health URL template must contain {domain} exactly once.');
        }
        if (str_contains(str_replace('{domain}', '', $template), '{')) {
            throw new RuntimeException('Health URL templates may contain only the {domain} placeholder.');
        }
        self::validateHTTPS(str_replace('{domain}', 'example.com', $template), true);
    }

    private static function validateHTTPS(string $value, bool $template): void
    {
        $parts = parse_url($value);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['fragment'])) {
            throw new RuntimeException('URLs must use HTTPS and contain no credentials or fragment.');
        }
        if (!$template && str_contains($value, '{')) {
            throw new RuntimeException('The Google Chat webhook cannot contain placeholders.');
        }
    }

    private static function validDomain(string $domain): bool
    {
        if (strlen($domain) > 253 || !str_contains($domain, '.')) {
            return false;
        }
        foreach (explode('.', $domain) as $label) {
            if (preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label) !== 1) {
                return false;
            }
        }
        return true;
    }

    /** @param array<string,mixed> $value */
    private static function json(array $value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        return $json;
    }

    private static function oneLine(string $value): string
    {
        return trim((string) preg_replace('/\s+/', ' ', $value));
    }

    private static function formatTime(string $value): string
    {
        if ($value === '') {
            return 'unknown';
        }
        try {
            return (new DateTimeImmutable($value, new DateTimeZone('UTC')))
                ->setTimezone(new DateTimeZone(date_default_timezone_get()))
                ->format('d j Y H:i:s');
        } catch (Throwable $e) {
            return 'unknown';
        }
    }

    /** @param array<string,array<string,bool>> $records */
    private static function recordText(array $records, string $key): string
    {
        $values = array_keys($records[$key] ?? []);
        sort($values);
        return $values === [] ? 'none' : implode(', ', $values);
    }
}
