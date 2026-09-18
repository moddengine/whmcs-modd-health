<?php

declare(strict_types=1);

use ModdHealth\Core;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "modd_health cron must run from the command line.\n");
    exit(2);
}

require_once dirname(__DIR__, 3) . '/init.php';
require_once __DIR__ . '/lib/Core.php';

$lockPath = sys_get_temp_dir() . '/modd-health-' . hash('sha256', dirname(__DIR__, 3)) . '.lock';
$lock = fopen($lockPath, 'c');
if ($lock === false) {
    fwrite(STDERR, "modd_health: unable to open execution lock.\n");
    exit(1);
}
if (!flock($lock, LOCK_EX | LOCK_NB)) {
    fclose($lock);
    exit(0);
}

try {
    $job = json_encode(Core::buildJob(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    [$code, $stdout, $stderr] = Core::runChecker([], $job);
    fwrite(STDOUT, $stdout);
    if ($code !== 0) {
        $message = trim((string) preg_replace('/\s+/', ' ', $stderr));
        logActivity('[Modd Health] Checker failed: ' . substr($message, 0, 1000));
        fwrite(STDERR, $stderr);
    }
    exit($code);
} catch (Throwable $e) {
    $message = trim((string) preg_replace('/\s+/', ' ', $e->getMessage()));
    logActivity('[Modd Health] Cron failed: ' . substr($message, 0, 1000));
    fwrite(STDERR, "modd_health: {$message}\n");
    exit(1);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}
