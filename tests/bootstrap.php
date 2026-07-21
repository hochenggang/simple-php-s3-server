<?php

// S3Gateway\Tests bootstrap

// Load Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Helper: set env var in both putenv and $_SERVER for testability
function s3gw_test_env(string $key, string $value): void
{
    putenv("{$key}={$value}");
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

function s3gw_test_unset_env(string $key): void
{
    putenv($key);
    unset($_ENV[$key], $_SERVER[$key]);
}
