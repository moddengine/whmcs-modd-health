<?php

declare(strict_types=1);

use ModdHealth\Core;
use WHMCS\Database\Capsule;
use WHMCS\Module\AbstractWidget;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/Core.php';

add_hook('AdminClientServicesTabFields', 1, static function (array $vars): array {
    $status = Core::serviceStatus((int) ($vars['id'] ?? $vars['serviceid'] ?? 0));
    if ($status === null) {
        return [];
    }
    $nameservers = $status['nameservers'] === [] ? 'none' : implode(', ', array_map(
        static fn (array $nameserver): string => '<span' . ($nameserver['preferred'] ? ' class="text-success"' : '') . '>' . Core::escape($nameserver['name']) . '</span>',
        $status['nameservers']
    ));
    return [
        'Nameservers' => $nameservers,
        'DNS Status' => '<span class="modd-health-dns">' . Core::escape($status['dns']) . '</span>',
        'Health Status' => '<strong class="modd-health-state">' . Core::escape($status['health']) . '</strong>',
    ];
});

add_hook('ClientAreaFooterOutput', 1, static function (array $vars): string {
    if (($vars['filename'] ?? '') !== 'clientareaproductdetails') {
        return '';
    }
    $serviceID = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    $clientID = (int) ($_SESSION['uid'] ?? 0);
    if (!$serviceID || !$clientID) {
        return '';
    }
    $ownsService = Capsule::table('tblhosting')->where('id', $serviceID)->where('userid', $clientID)->exists();
    $status = $ownsService ? Core::serviceStatus((int) $serviceID) : null;
    if ($status === null) {
        return '';
    }
    $payload = json_encode(['nameservers' => $status['nameservers'], 'rows' => ['DNS Status' => $status['dns'], 'Health Status' => $status['health']]], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
    return '<script>(()=>{const data=' . $payload . ';let table=document.querySelector("#tabOverview table, .product-details table");if(!table){const host=document.querySelector("#tabOverview .product-details, #tabOverview, .product-details");if(!host)return;table=document.createElement("table");table.className="table table-striped modd-health-table";host.appendChild(table)}const body=table.tBodies[0]||table.appendChild(document.createElement("tbody")),addRow=(label,value)=>{const tr=document.createElement("tr"),th=document.createElement("th"),td=document.createElement("td");th.textContent=label;if(typeof value==="string")td.textContent=value;else value.forEach((nameserver,index)=>{if(index)td.append(", ");const span=document.createElement("span");span.textContent=nameserver.name;if(nameserver.preferred)span.className="text-success";td.append(span)});tr.className="modd-health-row";tr.append(th,td);body.appendChild(tr)};addRow("Nameservers",data.nameservers.length?data.nameservers:"none");for(const [label,value] of Object.entries(data.rows))addRow(label,value)})();</script>';
});

add_hook('AdminHomeWidgets', 1, static function (): ModdHealthDashboardWidget {
    return new ModdHealthDashboardWidget();
});

final class ModdHealthDashboardWidget extends AbstractWidget
{
    /** @var string */
    protected $title = 'Modd Health';
    /** @var string */
    protected $description = 'Current monitored site health';
    /** @var int */
    protected $weight = 120;
    /** @var int */
    protected $columns = 1;
    /** @var bool */
    protected $cache = false;
    /** @var string */
    protected $requiredPermission = 'Configure Addon Modules';

    /** @return array{up:int,down:int,error?:bool} */
    public function getData(): array
    {
        try {
            $up = Capsule::table('mod_modd_health_state')->where('stable_state', 'healthy')->where('observed_state', 'healthy')->count();
            $down = Capsule::table('mod_modd_health_state')->where(static function ($query): void {
                $query->where('stable_state', 'failed')->orWhere('observed_state', 'failed');
            })->count();
            return ['up' => $up, 'down' => $down];
        } catch (Throwable $e) {
            return ['up' => 0, 'down' => 0, 'error' => true];
        }
    }

    /** @param array{up?:int,down?:int,error?:bool} $data */
    public function generateOutput($data): string
    {
        $up = (int) ($data['up'] ?? 0);
        $down = (int) ($data['down'] ?? 0);
        $error = !empty($data['error']) ? '<p class="text-danger">Unable to read health state.</p>' : '';
        return '<div class="widget-content-padded"><p><strong>' . $up . '</strong> sites UP<br><strong>' . $down . '</strong> sites DOWN</p>'
            . $error . '<a class="btn btn-default btn-sm" href="addonmodules.php?module=modd_health&amp;tab=failures&amp;status=down">View unhealthy sites</a></div>';
    }
}
