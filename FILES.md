# Files channels

Status: implemented 2026-10-06 (design note 4.13 item 9); end-to-end encryption (§8, capability `files.e2ee`)
2026-10-09. Node-local feature: files channels are not federated beyond the normal room access (remote members use
the room's node like for every other channel).

## 1. Model

A channel of kind `files` is a file browser instead of a chat. It has no messages (the message routes answer
`400 channel.no_text`, like voice channels). It is either:

- **End-to-end encrypted** (§8, the default for new files channels on nodes with `files.e2ee`): the channel has an
  MLS group like a text channel; names, types, folder names and contents are encrypted by the clients, the node
  stores ciphertext and the few plaintext fields of §8.2.
- **Not end-to-end encrypted**: no MLS group. Clients show a permanent banner "Files in this channel are not
  end-to-end encrypted" (and, for an external store, "stored on external storage: \<kind>"), analogous to
  PROTOCOL.md §8. On the node the files use the storage encryption at rest of design note 4.12 (per-file key
  wrapped with `keys/storage.key`): the node can read them, the disk or backup alone cannot.

`encrypted` is chosen when the channel is created (`POST /rooms/{id}/channels { kind: "files", encrypted }`, absent =
`true`) and **cannot be changed afterwards**: `PATCH …/channels/{id} { encrypted }` with a different value answers
`400 channel.encryption_fixed` (there is no re-encryption; a new channel and a new upload are the way to switch).
Nodes without `files.e2ee` create only unencrypted files channels (they answered `encrypted: true` with
`400 channel.files_unencrypted`); clients show files channels of such nodes as unencrypted.

Channel settings work as for other channels (name, topic, category, permission overrides, "no bots", history for
new members (§8.7), delete (§9)).

Entries (`file_entries`): `id` (ULID), `channel_id`, `parent_id` (folder, `null` at the top level), `kind`
(`folder` | `file`), `name`, `mime`, `size`, `sha256` (base64url, of the plaintext), `created_by` (user id),
`created_at`, `updated_at`. The folder tree lives only in the database; the bytes of a file are stored under
its id, so rename and move never touch the bytes. In encrypted channels `name` and `mime` are empty and `size` and
`sha256` describe the stored ciphertext; the rest is in the entry record (§8.2).

## 2. Names

A name is normalised to NFC and trimmed; it has 1–255 characters, contains no `/` or `\`, no control
characters and no bidirectional controls (U+200E/F, U+202A–202E, U+2066–2069, U+061C), and is not `.` or
`..` (`400 files.name_invalid`). Names are unique per folder case-insensitively (lowercase key; files and
folders share the namespace): `409 files.name_taken`. Names are display data only; they never become paths.
In encrypted channels the node never sees names: clients apply these rules to the decrypted record (§8.4) and avoid
duplicates themselves (§8.5).

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
| `GET mine?limit=&after=` | `view_channel` | The requester's own entries (files and folders they created), oldest first, cursor = last id: `{ entries, next_after, files, folders, bytes }` with the totals of all own entries. Never carries names or records, so it works without keys (§8.8) |
| `GET records?epoch=&since=&after=&limit=` | `view_channel` | Encrypted channels: entries with a record, ordered by the time the record was written (`record_at`, then id), optionally only of epoch `epoch` and/or written at or after `since` (RFC 3339); cursor `after` = last entry id of the previous page; `limit` 1–200 (default 100) → `{ entries, next_after }`; only records inside the requester's history window (§8.7). For the key checks of history shares and the clients' search sync (`SEARCH.md` §3.6) |
| `PUT {id}/thumbnail` | own: `attach_files`; others': `manage_files` | Encrypted channels: the client-made thumbnail of a file as ciphertext (§8.3, part `thumbnail`), raw body, at most 1 MiB → `204`; replaces an earlier one |
| `GET {id}/thumbnail` | `view_channel` | The thumbnail ciphertext (`application/octet-stream`, attachment, `nosniff`); `404 files.no_thumbnail` |
| `GET usage` | `view_channel` | `{ enabled, used_bytes, limit_bytes, files, folders, max_upload_bytes, backend, backend_host, backend_prefix, encrypt_files, encrypted, can_upload, can_manage, can_configure, allowed_categories, executables_allowed }`; `backend_host` and `backend_prefix` (external stores: the store's host and the object prefix, `""` otherwise) only for members with `manage_channels`, for the deletion dialog (§9) |
| `GET backend` | `manage_channels` + `manage_files` | `{ kind, url, username, password_set, access_key, secret_key_set, region, bucket, prefix, encrypt_files, external_allowed, private_allowed, has_files, updated_at }`; secrets are never returned |
| `PUT backend` | `manage_channels` + `manage_files` | See §5; audit log `files.backend` (kind, host, encryption; no credentials) |
| `POST backend/test` | `manage_channels` + `manage_files` | Body as for PUT (empty secrets use the stored ones) or empty for the stored configuration → `{ ok, kind }` or a problem |

Encrypted channels change some routes (§8.5). Error codes besides the above: `files.not_found`, `files.parent_not_found`, `files.parent_not_folder`,
`files.is_folder`, `files.cursor_invalid`, `files.search_invalid`, `files.upload_forbidden`,
`files.manage_forbidden`, `files.too_many_entries` (100 000 entries per channel), `files.disabled`,
`files.quota_exceeded`, `upload.too_large`, `upload.type_forbidden`, `upload.aborted`, `files.backend_*`, and for
encrypted channels `files.record_invalid`, `files.id_invalid`, `files.id_taken`, `files.encrypted`,
`files.search_unavailable`, `files.no_thumbnail`, `files.thumbnail_too_large`, `files.not_encrypted`.

Bots have no access (the routes are not in `APP_ROUTES`, APPLICATIONS.md §2.3).

Realtime: `files.update { room_id, channel_id, parent_id }` to the room members who can view the channel after every change of a folder's
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
  remembers how it was stored. **End-to-end encrypted channels** (§8) store the clients' ciphertext as it is:
  `encrypt_files` is always `false` for them (`true` is refused with `400 files.backend_invalid`), and an external
  store of such a channel holds nothing readable (object keys are entry ids, objects are §8.3 ciphertext).
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

The hourly orphan sweep deletes stored files no row knows (also for files channels and their thumbnails) and
entries whose stored file is missing (older than 24 hours). Attachment retention never touches files channel entries
(they are not in `blobs`).

Objects on an external store that have to go (deleted entries, deleted channels and rooms, §9) are first recorded in
a queue of pending external deletes (object key, the store's sealed configuration, attempts); a background task
deletes them right away, and the hourly housekeeping retries those that failed (store unreachable, 5xx) with an
exponential back-off for 7 days before it gives up and logs the object key. `404` from the store counts as done.
The queue holds the configuration sealed as in §5, so deleting a channel does not lose the credentials needed to
clean up after it; `TAVRN_FILES_EXTERNAL=off` pauses the queue.

## 7. Security notes

- Path traversal: names are never paths; storage paths and object keys are ULIDs.
- Content sniffing: downloads are attachments with `nosniff` and a sandboxing CSP; only safe types keep
  their `Content-Type`; clients open media through blob URLs typed by `safeBlobType`.
- DoS: listings are paginated (≤ 200), folders nest ≤ 32 levels, a channel holds ≤ 100 000 entries (bounds every
  recursive walk), uploads are streamed with the size limits applied on the fly.
- Credentials: encrypted at rest, write-only in the API, never in logs or the audit log.
- Encrypted channels: see §8.9.

## 8. End-to-end encrypted files channels (`files.e2ee`)

Nodes announce `files.e2ee` when they implement this section. Clients that do not know it show an encrypted files
channel as a channel they cannot open ("This files channel is end-to-end encrypted; update the app").

### 8.1 Group

An encrypted files channel is a conversation with its own MLS group exactly like a text channel (`ENCRYPTION.md` §4:
the same delivery-service routes, entitlement = room members with `view_channel`, removals on leave, kick, ban and
lost access, ghost checks). The group is created by the first client that needs it (opening the channel with
`attach_files`; the node requires `attach_files` instead of `send_messages` to create the group of a files channel);
members without it join by external commit once the group exists.

### 8.2 What the node stores

Per entry in plaintext only what it needs: `id`, `kind` (`file` | `folder`), `parent_id`, `created_by`,
`created_at`, `updated_at`, `size` and `sha256` of the **ciphertext**, whether there is a thumbnail and its
ciphertext size, and the entry record: `record` (ciphertext, §8.4), `record_epoch`, `record_author` (address),
`record_device_id`, `record_at` (when it was written). Never a name, a type, a folder name or content; `name` and
`mime` are empty strings in the API. Quotas, the entry limit, the orphan sweep, deletes and the audit log work on
these fields (the audit log of a delete names the entry id instead of the name).

The folder tree (`parent_id`) and the number, sizes and times of entries stay visible to the node, like the
metadata of messages (`ENCRYPTION.md` §5.4).

### 8.3 Content encryption (chunked AEAD)

Every file gets a random 32-byte `file_key`. A file's content (part `content`) and its client-made thumbnail (part
`thumbnail`, optional) are encrypted separately in chunks of 1 MiB:

```text
part_key  = HKDF-SHA256(IKM = file_key, salt = 32 zero bytes, info = "tavrn file chunk v1" || 0x00 || part, L = 32)
chunks    = max(1, ceil(n / 2^20))                  # n = plaintext bytes of the part; an empty part is one empty chunk
chunk_i   = plaintext[i · 2^20 .. min((i + 1) · 2^20, n))
nonce_i   = 0x00000000 || u64(i)                    # 12 bytes, i = 0 … chunks − 1
aad_i     = "tavrn file chunk v1" || 0x00 || u8(last)    # last = 1 for i = chunks − 1, else 0
stored    = AES-256-GCM(part_key, nonce_i, aad_i, chunk_0) || … || AES-256-GCM(part_key, nonce_i, aad_i, chunk_last)
```

Each encrypted chunk is the chunk plus its 16-byte tag, so `stored` has `n + 16 · chunks` bytes; a reader derives
`chunks = max(1, ceil(stored / (2^20 + 16)))` and `n = stored − 16 · chunks` and refuses sizes for which `n` is
negative or the last chunk would be empty while `chunks > 1`. The nonce makes every chunk position-bound (no
reordering), the `last` flag makes truncation at a chunk boundary fail, the per-part key keeps content and thumbnail
apart, and a fresh `file_key` per file keeps nonces unique. Clients stream: uploads encrypt chunk by chunk, downloads
decrypt chunk by chunk, and a plaintext range `[a, b]` is read as the ciphertext range of chunks `a >> 20 … b >> 20`
(`Range: bytes=<first · (2^20 + 16)>-<min((last + 1) · (2^20 + 16), stored) − 1>`), which the node serves like any
range (§3). Test vectors: `testvectors/encryption.json`, `file_chunks`.

### 8.4 Entry record

The name, the type and the file key travel in the entry record: content format 1 of `ENCRYPTION.md` §5.2 (AES-256-GCM
under the channel's content key of the current epoch, signed by the writing device) whose JSON is

```json
{ "type": "files.entry", "v": 1, "entry": "01J…", "kind": "file", "name": "Quarterly report.pdf",
  "mime": "application/pdf", "size": 23, "key": "<base64url file_key>",
  "thumbnail": { "mime": "image/webp", "width": 320, "height": 180 } }
{ "type": "files.entry", "v": 1, "entry": "01J…", "kind": "folder", "name": "Reports" }
```

- `author`/`device_id` of the content format are `record_author`/`record_device_id`, `epoch` is `record_epoch`.
- `entry` and `kind` MUST equal the entry the node lists the record with (a node cannot move a record to another
  entry); for files `size` (plaintext bytes) MUST match the stored ciphertext size (§8.3) and `key` MUST be 32 bytes.
  `name` MUST pass the rules of §2; `mime` is a lowercase `type/subtype` (anything else is shown as
  `application/octet-stream`); `thumbnail` is optional (the bytes are `GET {id}/thumbnail`, part `thumbnail`), its
  `mime` must be a raster image type. Clients refuse every other record as damaged and show the entry as "cannot be
  decrypted" (it can still be deleted). Unknown fields are ignored. Test vectors: `file_record`.
- The record does not repeat the folder path: the path is the chain of the parents' records, so moving a folder stays
  one metadata change (`PATCH parent_id`) as in unencrypted channels.
- Records are checked by the node like message content (`ENCRYPTION.md` §5.3): base64url, version `0x01`, at least
  `1 + 8 + 12 + 16 + 64` and at most 8 KiB of bytes (`400 files.record_invalid`), `record_epoch` equal to the header's
  epoch and not newer than the group (`400 message.epoch_mismatch` / `message.epoch_unknown`), not older than the
  group's current epoch or the one before it within 60 s of its commit (`409 mls.epoch_stale`), the session's device
  attested (`403 e2ee.device_not_attested`). The node sets `record_author`, `record_device_id` and `record_at` from
  the session.

### 8.5 Routes in encrypted channels

The routes of §3 apply with these differences:

- `POST folders { parent_id, id, record, record_epoch }`: the client chooses the entry id (a ULID whose time is
  within one day of the node's clock, `400 files.id_invalid`; `409 files.id_taken`) because the record names it.
  `name` is refused (`400 files.encrypted`).
- `POST upload`: the body is the ciphertext (§8.3); headers `Tavrn-Entry-Id`, `Tavrn-Record` (the record, base64url),
  `Tavrn-Record-Epoch`, `Tavrn-Parent`, `Tavrn-Upload-Category` (declared by the client as for encrypted attachments,
  PROTOCOL.md §7a; the node checks it against the uploader's categories and the executable rule, cooperative
  enforcement). `Tavrn-File-Name` and `Tavrn-Conflict` are refused (`400 files.encrypted`), `Content-Type` is
  ignored. Size limits and quotas apply to the ciphertext.
- `PATCH {id} { record?, record_epoch?, parent_id? }`: a rename writes a new record (any member who may modify the
  entry, §3, re-encrypts it under the current epoch); `name` is refused (`400 files.encrypted`). A move changes only
  `parent_id`.
- `GET ?q=` answers `400 files.search_unavailable`: search runs on the clients (`SEARCH.md` §3.6). Listings are ordered
  folders first, then by id; clients sort by name after decrypting. The node cannot check name uniqueness: clients
  check the decrypted folder before they upload or rename and number duplicates (`name (2).ext`) themselves.
- `GET {id}/download` is always `application/octet-stream` with `Content-Disposition: attachment; filename="<id>"`.
- Thumbnails: `PUT`/`GET {id}/thumbnail` (§3). Thumbnails are always kept in the node's own storage (also for channels
  on an external store) and count towards the channel's quota; they go with the entry.
- Unencrypted channels answer `GET records` and the thumbnail routes with `400 files.not_encrypted`.

### 8.6 Clients

- Upload: create `file_key`, encrypt the stream (§8.3), make a thumbnail locally for raster images and videos when the
  platform can (at most 320 px, WebP or JPEG), write the record, upload, then `PUT` the thumbnail.
- Browse: list a folder, decrypt every record (MLS epoch keys of the channel; unknown epochs are fetched from the
  history backup and shares like for messages), sort by name. Entries whose record cannot be decrypted are listed as
  locked with size and date only.
- Download and preview: fetch the ciphertext (ranges for media seeking), decrypt chunk by chunk, open media through
  blob URLs typed by `safeBlobType`; SVG is never rendered.
- Records are encrypted under the **current** epoch of the channel (the owning tab of a browser, like other
  state-changing MLS calls); decryption is local.

### 8.7 History for new members

Entry records are keyed per epoch like messages, so the channel's `history_for_new_members` and the history key
shares of `ENCRYPTION.md` §7b decide which older entries a later member can open. Unlike text channels, a files
channel shares **everything or nothing** from before a member's join: its policy is `all` (the **default** for files
channels, set at creation) or `since_join`; `days:<n>` is refused with `400 channel.history_policy_invalid`. With
`all`, the sharing devices hand a new member every epoch key they still hold (so every file whose record they can
read), as far back as possible; with `since_join`, the keys of the epochs of the records written since the member's
join (before its device first entered the channel's group).

- The node serves a record only inside the requester's window (`ENCRYPTION.md` §7b, measured on `record_at`): entries
  whose record is older come with `record`, `record_epoch`, `record_author` and `record_device_id` set to `null` in
  folder listings, `GET mine` and `GET {id}`, and `GET records` leaves them out. Their ciphertext stays downloadable (it is useless without the
  record), and the owner can still delete them (§8.8).
- A new member is marked `history_pending` when there are entry records in its window from before its device's first
  leaf in the group (in addition to the messages rule of §7b; under `since_join` the records since its join).
  Recipients check a shared key against a record of that epoch from `GET records?epoch=<n>` (preferring records whose
  author is not the sharer) instead of a message.
- Renaming an entry writes a new record under the current epoch, so its file key becomes readable for every current
  member (as it already is for those who could read the old record).

### 8.8 Deleting without keys

A member who lost their keys (no key backup, reset identity, a locked device) or who cannot read old records any
more (§8.7) can still remove their own uploads: `GET mine` lists the requester's entries with ids, kinds, sizes and
dates (never records) plus the totals, and `DELETE {id}` works on ownership as before (own entries `attach_files`;
folders with entries of others `manage_files`). Clients offer "Your files: n entries, x MB" with single and bulk
deletion when the channel cannot be decrypted on this device.

### 8.9 Security notes

- The node and an external store see ciphertext, sizes, times, the tree shape and who uploaded; they never see names,
  types, folder names or contents, and cannot forge or swap records (device signature, the entry id inside the
  record, the file key binding the content).
- A node can withhold, delete or roll back entries and records (denial of service) and serve an old record of the same
  entry (a rename undone); it cannot make a client accept another entry's record or content.
- Members read what members read (`ENCRYPTION.md` §11); a removed member keeps the file keys it had and loses access
  to entries written after its removal (new records are under epochs it does not know).
- Upload categories and the executable rule are cooperative (declared by the client); size limits and quotas are
  enforced on the ciphertext.

## 9. Deleting a files channel or a room

`DELETE /rooms/{id}/channels/{channel_id}` and `DELETE /rooms/{id}` remove every entry of the channel's (or the
room's) files channels:

- Files in the node's storage (and every thumbnail) are deleted at once.
- Objects on an external store are deleted in the background through the queue of §6 (retried hourly for 7 days if the
  store is unreachable), with the credentials stored for the channel.
- `?keep_external=true` keeps the objects of **unencrypted** external channels on the store (the entries and the
  configuration are deleted; the objects stay usable with other clients unless they were stored with
  `encrypt_files`). It is ignored for encrypted channels: their objects are unreadable without the channel's keys,
  so they are always deleted. The audit log of the deletion records `keep_external` and the number of kept objects.

Clients ask for a typed confirmation (the channel's or room's name) and say what happens: the counts (files,
folders, bytes from `GET usage`), where the files are ("stored on this node" or "stored on \<kind> at \<host>") and the
consequence ("All files are deleted permanently"; external: "The objects under \<prefix> are deleted from the
external store", with the "Keep the objects on the external store" option only for unencrypted external channels).
The room deletion dialog lists its files channels with the same information.
