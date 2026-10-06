# Files channels

Status: implemented 2026-10-06 (design note 4.13 item 9). Node-local feature: files channels are not federated
beyond the normal room access (remote members use the room's node like for every other channel).

## 1. Model

A channel of kind `files` is a file browser instead of a chat:

- It is **never end-to-end encrypted**: `encrypted` is always `false` (creating one with `encrypted: true` or
  switching it on answers `400 channel.files_unencrypted`), it has no MLS group and no messages (the message
  routes answer `400 channel.no_text`, like voice channels). Clients show a permanent banner "Files in this
  channel are not end-to-end encrypted" (and, for an external store, "stored on external storage: <kind>"),
  analogous to PROTOCOL.md §8.
- On the node the files use the storage encryption at rest of design note 4.12 (per-file key wrapped with
  `keys/storage.key`): the node can read them, the disk or backup alone cannot.
- Channel settings work as for other channels (name, topic, category, permission overrides, "no bots",
  delete). Deleting the channel or the room deletes every stored file (external objects in the background).

Entries (`file_entries`): `id` (ULID), `channel_id`, `parent_id` (folder, `null` at the top level), `kind`
(`folder` | `file`), `name`, `mime`, `size`, `sha256` (base64url, of the plaintext), `created_by` (user id),
`created_at`, `updated_at`. The folder tree lives only in the database; the bytes of a file are stored under
its id, so rename and move never touch the bytes.

## 2. Names

A name is normalised to NFC and trimmed; it has 1–255 characters, contains no `/` or `\`, no control
characters and no bidirectional controls (U+200E/F, U+202A–202E, U+2066–2069, U+061C), and is not `.` or
`..` (`400 files.name_invalid`). Names are unique per folder case-insensitively (lowercase key; files and
folders share the namespace): `409 files.name_taken`. Names are display data only; they never become paths.

## 3. Routes

All under `/api/v1/rooms/{room_id}/channels/{channel_id}/files`; a channel of another kind answers
`400 channel.not_files`.

| Route | Right | Notes |
|---|---|---|
| `GET ?parent=&q=&limit=&after=` | `view_channel` | Folder listing (folders first, then by name), or with `q` a case-insensitive substring search across the channel (`%`/`_` are literal). `limit` 1–200 (default 100), cursor `after` = last entry id → `{ entries, next_after, path }` (`path`: the folder chain, top first) |
| `GET {id}` | `view_channel` | `{ entry, path }` |
| `POST folders {parent_id, name}` | `attach_files` | `201 FileEntry`; nesting at most 32 levels (`400 files.too_deep`) |
| `POST upload` | `attach_files` | Raw body (streamed); `Tavrn-File-Name` (UTF-8, percent-encoded), `Tavrn-Parent` (folder id, absent = top), `Content-Type`; `Tavrn-Conflict: rename` stores a taken name as `name (2).ext` instead of 409. External stores need `Content-Length` (`400 files.length_required`). Not limited by the 30-second API timeout (6 hours) |
| `GET {id}/download` | `view_channel` | Content, single byte `Range` → `206` with `Content-Range` (`416` when unsatisfiable, multi-ranges are served whole); always `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Accept-Ranges: bytes`, `ETag` = sha256. Only raster images, audio, video, PDF and `text/plain` keep their type, everything else (SVG, HTML …) is `application/octet-stream` |
| `PATCH {id} {name?, parent_id?}` | own: `attach_files`; others': `manage_files` | Rename and/or move (`parent_id: null` = top). Moving a folder into itself or a subfolder: `400 files.move_into_self`; depth limit as above |
| `DELETE {id}` | own: `attach_files`; as soon as any entry of someone else is inside: `manage_files` | Folders recursively → `{ files, folders, bytes }`; audit log `files.delete` with the counts |
| `GET usage` | `view_channel` | `{ enabled, used_bytes, limit_bytes, files, folders, max_upload_bytes, backend, encrypt_files, can_upload, can_manage, can_configure, allowed_categories, executables_allowed }` |
| `GET backend` | `manage_channels` + `manage_files` | `{ kind, url, username, password_set, access_key, secret_key_set, region, bucket, prefix, encrypt_files, external_allowed, private_allowed, has_files, updated_at }`; secrets are never returned |
| `PUT backend` | `manage_channels` + `manage_files` | See §5; audit log `files.backend` (kind, host, encryption; no credentials) |
| `POST backend/test` | `manage_channels` + `manage_files` | Body as for PUT (empty secrets use the stored ones) or empty for the stored configuration → `{ ok, kind }` or a problem |

Error codes besides the above: `files.not_found`, `files.parent_not_found`, `files.parent_not_folder`,
`files.is_folder`, `files.cursor_invalid`, `files.search_invalid`, `files.upload_forbidden`,
`files.manage_forbidden`, `files.too_many_entries` (100 000 entries per channel), `files.disabled`,
`files.quota_exceeded`, `upload.too_large`, `upload.type_forbidden`, `upload.aborted`, `files.backend_*`.

Bots have no access (the routes are not in `APP_ROUTES`, APPLICATIONS.md §2.3).

Realtime: `files.update { room_id, channel_id, parent_id }` to the room after every change of a folder's
content (create, upload, rename, move: old and new parent, delete); `files.backend { room_id, channel_id,
backend }` after a backend change. Clients refresh the open folder.

## 4. Limits

- `files_channels.enabled` (entitlement of the room owner, node default `TAVRN_FILES_CHANNELS=on`): `0` refuses
  creating files channels, uploads and new folders with `403 files.disabled`; browsing, downloads, renames and
  deletes keep working.
- Upload size: the uploader's `upload.max_bytes` (as for attachments) → `413 upload.too_large`.
- Channel total: `files_channels.max_bytes` of the room (`0` = unlimited) → `413 files.quota_exceeded`. Files
  channels do not count towards `storage.max_bytes_per_room` (attachments) and are exempt from attachment
  retention.
- Upload categories per role/override and the executable rule (`TAVRN_UPLOAD_ALLOW_EXECUTABLES`) apply as for
  attachments (PROTOCOL.md §7a): the node classifies the first 64 KiB of the stream (content first, then
  name, then type). SVG content is stored as `image/svg+xml` and only ever downloaded.
- The size limits are enforced while streaming; a refused or aborted upload leaves nothing behind.

## 5. External storage

Off by default: `TAVRN_FILES_EXTERNAL=on` allows members with `manage_channels` + `manage_files` to keep a
channel's files on a WebDAV or S3-compatible store:

```json
PUT …/files/backend
{ "kind": "webdav", "url": "https://cloud.example.com/remote.php/dav/files/me/", "username": "me",
  "password": "…", "prefix": "tavrn/<channel id>/", "encrypt_files": false }
{ "kind": "s3", "url": "https://s3.eu-central-1.amazonaws.com", "bucket": "team-files", "region": "eu-central-1",
  "access_key": "…", "secret_key": "…", "prefix": "share/", "encrypt_files": true }
{ "kind": "internal" }
```

- The configuration (URL and credentials) is stored encrypted with the node's `keys/secrets.key`
  (`HKDF-SHA256(info = "tavrn files backend v1")`, AES-256-GCM bound to the channel id). Secrets are never
  returned, logged or written to the audit log; an empty secret in a PUT keeps the stored one.
- Object key = prefix + entry id (S3: path-style `<endpoint>/<bucket>/<prefix><id>`; WebDAV:
  `<url><prefix><id>`, the prefix collections are created with `MKCOL`). Renames and moves are metadata-only,
  so no `MOVE`/copy is ever needed. The node uses `PROPFIND`/`HEAD` (test), `MKCOL`, `PUT`, `GET` (with `Range`)
  and `DELETE`. S3 requests are signed with AWS Signature V4 (`UNSIGNED-PAYLOAD`, hand-written, tested against
  the AWS examples).
- The node proxies uploads and downloads as streams (bounded memory, a `Content-Length` is required for
  uploads). Entries are still tracked in `file_entries`; the node never lists the store.
- `encrypt_files`: new files are wrapped with the storage format of design note 4.12 before they are written (file
  key in `blob_keys`, wrapped with `storage.key`); downloads are unwrapped, ranges fetch only the needed chunks.
  **Such files are unreadable outside tavrn** (and lost without `storage.key`). Without it the files are stored
  as they are, so the share stays usable with other clients. The toggle applies to new uploads; each entry
  remembers how it was stored.
- Switching the store (kind, URL, bucket or prefix) is only allowed while the channel has no files
  (`409 files.backend_not_empty`); credentials and the toggle can change any time.
- SSRF rules as for link previews: `https` only, no credentials/query in the URL, IP literals and every DNS
  answer must be public unicast addresses (the vetting resolver that reqwest connects with, no second
  lookup), redirects are never followed, 10 s connect and 60 s read timeouts. `TAVRN_FILES_EXTERNAL_PRIVATE=on`
  allows private/loopback addresses and plain `http` (self-hosted stores in the LAN; logged as a warning).
  Refusals: `400 files.backend_https_required`, `400 files.backend_address_forbidden`; store errors
  `502 files.backend_failed` / `files.backend_unreachable`. Backend changes and tests are limited to 20 per
  user and 10 minutes.
- With `TAVRN_FILES_EXTERNAL=off` existing external channels answer `403 files.external_disabled` until it is
  switched on again (nothing is deleted).
- FTP/SFTP and consumer clouds are not supported.

## 6. Housekeeping

The hourly orphan sweep deletes stored files no row knows (also for files channels) and entries whose stored
file is missing (older than 24 hours). Attachment retention never touches files channel entries (they are not
in `blobs`).

## 7. Security notes

- Path traversal: names are never paths; storage paths and object keys are ULIDs.
- Content sniffing: downloads are attachments with `nosniff` and a sandboxing CSP; only safe types keep
  their `Content-Type`; clients open media through blob URLs typed by `safeBlobType`.
- DoS: listings are paginated (≤ 200), folders nest ≤ 32 levels, a channel holds ≤ 100 000 entries (bounds every
  recursive walk), uploads are streamed with the size limits applied on the fly.
- Credentials: encrypted at rest, write-only in the API, never in logs or the audit log.
