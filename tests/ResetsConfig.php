<?php

namespace S3Gateway\Tests;

use S3Gateway\Config;

/**
 * Helper trait to reset Config cache and set test data directory
 */
trait ResetsConfig
{
    protected function resetConfig(string $dataDir): void
    {
        // Reset Config static cache
        $ref = new \ReflectionClass(Config::class);
        $configProp = $ref->getProperty('config');
        $configProp->setValue(null, ['DATA_DIR' => $dataDir]);

        $keysProp = $ref->getProperty('accessKeys');
        $keysProp->setValue(null, []);
    }

    /**
     * Set a config value directly in Config's static cache
     */
    protected function setConfigValue(string $key, string $value): void
    {
        $ref = new \ReflectionClass(Config::class);
        $configProp = $ref->getProperty('config');
        $current = $configProp->getValue();
        if ($current === null) {
            $current = [];
        }
        $current[$key] = $value;
        $configProp->setValue(null, $current);
    }

    protected function cleanupDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            if ($file->isDir()) {
                @rmdir($file->getPathname());
            } else {
                @unlink($file->getPathname());
            }
        }
        @rmdir($dir);
    }
}
