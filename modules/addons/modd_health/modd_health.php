<?php

declare(strict_types=1);

use ModdHealth\Core;
use WHMCS\Database\Capsule;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/Core.php';

/** @return array<string,mixed> */
function modd_health_config(): array
{
    return [
        'name' => 'Modd Health',
        'description' => 'Authoritative DNS and HTTPS health monitoring for selected WHMCS products.',
        'author' => 'ModdEngine',
        'language' => 'english',
        'version' => '0.0.1',
        'fields' => [],
    ];
}

/** @return array{status:string,description:string} */
function modd_health_activate(): array
{
    try {
        if (!Capsule::schema()->hasTable('mod_modd_health_config')) {
            Capsule::schema()->create('mod_modd_health_config', static function ($table): void {
                $table->unsignedTinyInteger('id')->primary();
                $table->mediumText('settings_json');
                $table->text('webhook_ciphertext')->nullable();
                $table->dateTime('updated_at')->nullable();
            });
        }
        if (!Capsule::schema()->hasTable('mod_modd_health_state')) {
            Capsule::schema()->create('mod_modd_health_state', static function ($table): void {
                $table->unsignedBigInteger('service_id')->primary();
                $table->unsignedBigInteger('client_id')->index();
                $table->unsignedBigInteger('product_id')->index();
                $table->string('domain', 253);
                $table->string('profile', 32);
                $table->string('stable_state', 16)->default('unknown');
                $table->string('observed_state', 16);
                $table->unsignedInteger('consecutive_count')->default(0);
                $table->mediumText('checks_json');
                $table->dateTime('first_failure_at')->nullable()->index();
                $table->dateTime('confirmed_failure_at')->nullable();
                $table->dateTime('last_checked_at');
                $table->dateTime('updated_at');
                $table->string('pending_notification', 16)->nullable();
                $table->text('last_notification_error')->nullable();
                $table->dateTime('last_notification_at')->nullable();
            });
        }
        return ['status' => 'success', 'description' => 'Modd Health activated. Configure products and health expectations before installing the cron entry.'];
    } catch (Throwable $e) {
        return ['status' => 'error', 'description' => 'Unable to activate Modd Health: ' . $e->getMessage()];
    }
}

/** @return array{status:string,description:string} */
function modd_health_deactivate(): array
{
    return ['status' => 'success', 'description' => 'Modd Health deactivated. Configuration and health state were retained.'];
}

/** @param array<string,mixed> $vars */
function modd_health_output(array $vars): void
{
    $notices = [];
    $errors = [];
    $tab = ($_GET['tab'] ?? '') === 'failures' ? 'failures' : 'configuration';
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        try {
            if (check_token('WHMCS.admin.default') === false) {
                throw new RuntimeException('Invalid or expired CSRF token.');
            }
            Core::save($_POST);
            $notices[] = 'Configuration saved and validated by the checker.';
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }
    $moduleLink = (string) $vars['modulelink'];
    echo '<style>.mh-nav{margin-bottom:18px}.mh-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:16px}.mh-card{border:1px solid #ddd;padding:14px;border-radius:4px}.mh-card label{display:block;font-weight:normal}.mh-field{margin:12px 0}.mh-field input[type=text],.mh-field input[type=password],.mh-field textarea,.mh-field select{width:100%;max-width:760px}.mh-notice,.mh-error{padding:10px;margin:8px 0}.mh-notice{background:#eaf7ea}.mh-error{background:#fdeaea}.mh-table{width:100%;border-collapse:collapse}.mh-table th,.mh-table td{padding:9px;border-bottom:1px solid #ddd;vertical-align:top}.mh-reasons{margin:0;padding-left:18px}@media(max-width:900px){.mh-grid{grid-template-columns:1fr}}</style>';
    echo '<h2>Modd Health</h2><div class="mh-nav"><a class="btn btn-' . ($tab === 'configuration' ? 'primary' : 'default') . '" href="' . Core::escape($moduleLink) . '&amp;tab=configuration">Configuration</a> <a class="btn btn-' . ($tab === 'failures' ? 'primary' : 'default') . '" href="' . Core::escape($moduleLink) . '&amp;tab=failures">Unhealthy sites</a></div>';
    foreach ($notices as $notice) {
        echo '<div class="mh-notice">' . Core::escape($notice) . '</div>';
    }
    foreach ($errors as $error) {
        echo '<div class="mh-error">' . Core::escape($error) . '</div>';
    }
    if ($tab === 'failures') {
        modd_health_render_failures();
        return;
    }
    modd_health_render_configuration($moduleLink);
}

function modd_health_render_configuration(string $moduleLink): void
{
    $stored = Core::load();
    $settings = $stored['settings'];
    $selected = $settings['products'];
    $token = generate_token('plain');
    echo '<form method="post" action="' . Core::escape($moduleLink) . '&amp;tab=configuration"><input type="hidden" name="token" value="' . Core::escape($token) . '">';
    echo '<h3>Products</h3><p>Each product may belong to one profile only.</p><div class="mh-grid">';
    foreach (['email' => 'Email Hosting', 'legacy' => 'Legacy Hosting', 'container' => 'Modd Container Hosting'] as $profile => $label) {
        echo '<div class="mh-card"><strong>' . Core::escape($label) . '</strong>';
        foreach (Core::products() as $product) {
            $checked = in_array((int) $product->id, $selected[$profile] ?? [], true) ? ' checked' : '';
            $hidden = !empty($product->hidden) ? ' (hidden)' : '';
            echo '<label><input type="checkbox" name="products_' . $profile . '[]" value="' . (int) $product->id . '"' . $checked . '> ' . Core::escape((string) $product->group_name . ' — ' . (string) $product->name . $hidden) . ' (#' . (int) $product->id . ')</label>';
        }
        echo '</div>';
    }
    echo '</div>';
    modd_health_textarea('hosting_ipv4', 'Permitted hosting IPv4 addresses', implode("\n", $settings['hosting_ipv4']), 'One IPv4 address per line. Shared by Legacy and Container profiles.');
    modd_health_input('mx_pattern', 'Email MX RE2 pattern', (string) $settings['email']['mx_pattern']);
    modd_health_input('spf_pattern', 'Email SPF RE2 pattern', (string) $settings['email']['spf_pattern']);
    modd_health_textarea('dkim_selectors', 'DKIM selectors', implode("\n", $settings['email']['dkim_selectors']), 'One selector per line.');
    modd_health_input('dkim_cname_pattern', 'DKIM CNAME RE2 pattern', (string) $settings['email']['dkim_cname_pattern']);
    modd_health_input('legacy_url_template', 'Legacy health URL', (string) $settings['legacy']['url_template']);
    modd_health_input('container_url_template', 'Container health URL', (string) $settings['container']['url_template']);
    echo '<div class="mh-field"><label><strong>Database TLS</strong><br><select name="database_tls">';
    foreach (['disabled' => 'Disabled', 'preferred' => 'Preferred (allow fallback)', 'required' => 'Required and verified'] as $value => $label) {
        echo '<option value="' . $value . '"' . ($settings['database_tls'] === $value ? ' selected' : '') . '>' . Core::escape($label) . '</option>';
    }
    echo '</select></label></div>';
    echo '<div class="mh-field"><label><strong>Google Chat webhook</strong><br><input autocomplete="new-password" type="password" name="webhook_url" value="" placeholder="' . ($stored['webhook_ciphertext'] !== '' ? 'Configured — leave blank to preserve' : 'Required') . '"></label><label><input type="checkbox" name="clear_webhook" value="1"> Clear stored webhook</label></div>';
    echo '<button class="btn btn-primary" type="submit">Save and validate</button></form>';
}

function modd_health_render_failures(): void
{
    $rows = Capsule::table('mod_modd_health_state')
        ->where(static function ($query): void {
            $query->where('observed_state', 'failed')->orWhere('stable_state', 'failed');
        })
        ->orderBy('first_failure_at')
        ->get();
    if ($rows->isEmpty()) {
        echo '<p>No sites are currently marked unhealthy.</p>';
        return;
    }
    echo '<table class="mh-table"><thead><tr><th>Status</th><th>Domain</th><th>Service</th><th>Profile</th><th>Reasons</th><th>Observations</th><th>First observed</th><th>Last checked</th></tr></thead><tbody>';
    foreach ($rows as $row) {
        $status = (string) $row->stable_state === 'failed'
            ? ((string) $row->observed_state === 'healthy' ? 'Recovery pending' : 'Confirmed failure')
            : 'Pending confirmation';
        $result = json_decode((string) $row->checks_json, true);
        $reasons = is_array($result) ? Core::reasons($result) : [];
        if ($status === 'Recovery pending') {
            $reasons = ['All checks healthy; awaiting confirmation'];
        }
        echo '<tr><td>' . Core::escape($status) . '</td>';
        echo '<td><a target="_blank" rel="noopener noreferrer" href="https://' . Core::escape((string) $row->domain) . '">' . Core::escape((string) $row->domain) . '</a></td>';
        echo '<td><a href="clientsservices.php?id=' . (int) $row->service_id . '">#' . (int) $row->service_id . '</a><br>Product #' . (int) $row->product_id . '</td>';
        echo '<td>' . Core::escape((string) $row->profile) . '</td><td><ul class="mh-reasons">';
        foreach ($reasons as $reason) {
            echo '<li>' . Core::escape($reason) . '</li>';
        }
        echo '</ul></td><td>' . (int) $row->consecutive_count . '</td><td>' . Core::escape((string) $row->first_failure_at) . '</td><td>' . Core::escape((string) $row->last_checked_at) . '</td></tr>';
    }
    echo '</tbody></table>';
}

function modd_health_input(string $name, string $label, string $value): void
{
    echo '<div class="mh-field"><label><strong>' . Core::escape($label) . '</strong><br><input type="text" name="' . Core::escape($name) . '" value="' . Core::escape($value) . '"></label></div>';
}

function modd_health_textarea(string $name, string $label, string $value, string $help): void
{
    echo '<div class="mh-field"><label><strong>' . Core::escape($label) . '</strong><br><textarea rows="4" name="' . Core::escape($name) . '">' . Core::escape($value) . '</textarea></label><small>' . Core::escape($help) . '</small></div>';
}
