<?php

namespace S3Gateway\Storage;

use Symfony\Component\Filesystem\Path;

/**
 * Content ETags and client metadata of stored files, kept in small JSON
 * sidecar files.
 *
 * Objects map to DATA_DIR/.meta/{bucket}/{path}.json (bucket names cannot
 * start with a dot, so this tree never collides with a bucket). Multipart
 * parts keep their sidecar inside the upload directory as "{n}.meta.json",
 * so removing the upload directory removes it too.
 *
 * Each sidecar records the inode, size and mtime of the file it describes.
 * A missing or stale sidecar (crash between write and record, files changed
 * on disk, data written by older versions) is repaired by hashing the file;
 * its metadata cannot be recovered and is dropped.
 */
class SidecarStore
{
    private const BUFFER_SIZE = 65536;

    private PathResolver $pathResolver;

    public function __construct(PathResolver $pathResolver)
    {
        $this->pathResolver = $pathResolver;
    }

    /** S3 ETag of a multipart object: MD5 over the binary part MD5s, plus "-{count}". */
    public static function multipartEtag(array $partMd5s): string
    {
        $binary = '';
        foreach ($partMd5s as $md5) {
            $binary .= hex2bin($md5);
        }
        return md5($binary) . '-' . count($partMd5s);
    }

    /** ETag of $path, or null if it is not a file. */
    public function get(string $path): ?string
    {
        return $this->read($path)['etag'] ?? null;
    }

    /** Client metadata of $path; empty when none was recorded. */
    public function metadata(string $path): ObjectMetadata
    {
        return ObjectMetadata::fromArray($this->read($path)['metadata'] ?? []);
    }

    /** Record the ETag and metadata of a file that was just written. */
    public function record(string $path, string $etag, ?ObjectMetadata $metadata = null): void
    {
        $stat = $this->stat($path);
        if ($stat === null) {
            return;
        }
        $sidecar = $this->sidecarPath($path);
        if (!$this->pathResolver->ensureParentDir($sidecar)) {
            return;
        }
        $data = ['etag' => $etag] + $stat;
        if ($metadata !== null) {
            $data['metadata'] = $metadata->toArray();
        }
        $tmp = $sidecar . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, json_encode($data)) === false || !@rename($tmp, $sidecar)) {
            @unlink($tmp);
        }
    }

    /**
     * Valid sidecar data of $path, repairing a missing or stale sidecar.
     *
     * @return array{etag:string,metadata?:array}|null null if $path is not a file
     */
    private function read(string $path): ?array
    {
        $stat = $this->stat($path);
        if ($stat === null) {
            return null;
        }
        $data = json_decode((string)@file_get_contents($this->sidecarPath($path)), true);
        if (is_array($data) && is_string($data['etag'] ?? null)
            && ($data['ino'] ?? null) === $stat['ino']
            && ($data['size'] ?? null) === $stat['size']
            && ($data['mtime'] ?? null) === $stat['mtime']) {
            return $data;
        }
        $md5 = @md5_file($path);
        if ($md5 === false) {
            return null;
        }
        $this->record($path, $md5);
        return ['etag' => $md5];
    }

    /** Remove the sidecar of a deleted object and its now-empty directories. */
    public function forget(string $bucket, string $path): void
    {
        $sidecar = $this->sidecarPath($path);
        @unlink($sidecar);
        $stop = $this->pathResolver->normalize(Path::join($this->metaRoot(), $bucket));
        $dir = $this->pathResolver->normalize(dirname($sidecar));
        // Check emptiness first: the application's error handler logs failed
        // rmdir() calls even when suppressed.
        while (str_starts_with($dir, $stop . '/') && @scandir($dir) === ['.', '..'] && @rmdir($dir)) {
            $dir = $this->pathResolver->normalize(dirname($dir));
        }
    }

    /** Remove all sidecars of a deleted bucket. */
    public function forgetBucket(string $bucket): void
    {
        $dir = Path::join($this->metaRoot(), $bucket);
        if (!is_dir($dir)) {
            return;
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $file) {
            $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
        }
        @rmdir($dir);
    }

    /**
     * Copy $input to $output in bounded blocks and return the MD5 of the
     * copied bytes, or null on a read or write error.
     *
     * @param resource $input
     * @param resource $output
     */
    public static function copyWithMd5($input, $output): ?string
    {
        $context = hash_init('md5');
        while (!feof($input)) {
            $block = fread($input, self::BUFFER_SIZE);
            if ($block === false) {
                return null;
            }
            if ($block === '') {
                continue;
            }
            hash_update($context, $block);
            for ($offset = 0, $length = strlen($block); $offset < $length; $offset += $written) {
                $written = fwrite($output, substr($block, $offset));
                if ($written === false || $written === 0) {
                    return null;
                }
            }
        }
        return hash_final($context);
    }

    private function metaRoot(): string
    {
        return Path::join($this->pathResolver->getDataDir(), '.meta');
    }

    private function sidecarPath(string $path): string
    {
        $path = $this->pathResolver->normalize($path);
        if (str_contains($path, '/.multipart/')) {
            return $path . '.meta.json';
        }
        $relative = $this->pathResolver->getRelativePath($this->pathResolver->getDataDir(), $path);
        return Path::join($this->metaRoot(), $relative . '.json');
    }

    /** @return array{ino:int,size:int,mtime:int}|null */
    private function stat(string $path): ?array
    {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            return null;
        }
        $stat = @stat($path);
        if ($stat === false) {
            return null;
        }
        return ['ino' => $stat['ino'], 'size' => $stat['size'], 'mtime' => $stat['mtime']];
    }
}
