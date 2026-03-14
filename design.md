# Design Document

## Core Objective

Implement a pure local filesystem-based S3-compatible API gateway using PHP.

## Supported Operations

### Bucket

- List
- Create
- Delete

### Object

- Put
- Get
- Head
- Delete
- DeleteMultiple
- List

### Multipart Upload

- Create
- UploadPart
- Complete
- Abort
- ListParts

## Design Principles

**Keep it minimal.** Advanced features such as ACL, versioning, and other non-essential functionalities are explicitly excluded.

Full suport for S3V4 Sign Authorization for headers.**authorization.**

Particial surport for of presign url authorization of GET object requests.

## Storage Layout

| Type            | Path                                                      |
| --------------- | --------------------------------------------------------- |
| Objects         | `{base_path}/{bucket}/{key}`                              |
| Multipart Parts | `{base_path}/{bucket}/.multipart/{uploadId}/{partNumber}` |

## Metadata Strategy

**No independent metadata storage.** All metadata is read directly from the filesystem when needed, using the actual file properties.

## Implementation Goals

- **Stable Storage:** Ensure reliable file persistence
- **Robust Authentication:** Secure and standards-compliant auth
- **Reliable Transfer:** Handle data transmission correctly
- **Clean Code:** Write elegant, maintainable code

