<?php

declare(strict_types=1);

namespace WHMCS\Database {
    final class Capsule
    {
        public static function table(string $table): mixed {}
        public static function schema(): mixed {}
        public static function connection(): mixed {}
    }
}

namespace WHMCS\Module {
    abstract class AbstractWidget {}
}

namespace {
    function add_hook(string $hook, int $priority, callable $callback): void {}
    function check_token(string $namespace): bool {}
    function generate_token(string $type): string {}
    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    function localAPI(string $command, array $parameters): array {}
    function logActivity(string $message): void {}
}
