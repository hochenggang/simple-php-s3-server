# Storage backends

`Storage` defines bucket and object operations. `FileStorage` remains the default,
preserving the existing filesystem layout and metadata. Controllers use backend
metadata and streams rather than filesystem paths.

To select another backend, set `STORAGE_CLASS` in the configuration's `[general]`
section to an autoloadable class implementing `Storage`. Its constructor must
accept no required arguments. Applications can also inject a backend into
`Router`. No configuration changes are needed for filesystem storage.

## Streams and metadata

- `putObjectFromStream` reads from the input's current position and leaves it open.
  It returns committed object metadata, or `null` on failure.
- `openObject` returns a readable stream positioned at the requested offset, or
  `false` if it cannot open the object. The caller closes the stream. It need not
  be seekable; the response reads at most the requested length.
- Metadata contains `size`, `mtime`, `mime`, and an unquoted `etag`. Bucket creation
  timestamps also come from the backend.
- Filesystem writes use a temporary sibling file and rename it into place after
  copying the input successfully.

The HTTP request and authentication code still buffers request bodies. The backend
stream interface does not by itself provide bounded-memory HTTP uploads.

## Multipart uploads

Backends can implement `MultipartStorage` to support multipart uploads and expired
upload cleanup. Other backends return S3 `NotImplemented` (HTTP 501) for multipart
operations. `cleanup_multipart.php` delegates expiration and removal to the selected
backend.
