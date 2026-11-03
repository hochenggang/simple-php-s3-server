<?php

namespace S3Gateway\Storage;

use S3Gateway\Config;

final class StorageFactory
{
    public static function create(): Storage
    {
        $class = (string) Config::get('STORAGE_CLASS', FileStorage::class);
        if (!is_a($class, Storage::class, true)) {
            throw new \InvalidArgumentException('STORAGE_CLASS must implement ' . Storage::class);
        }
        return new $class();
    }
}
