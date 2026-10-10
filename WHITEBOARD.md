# tavrn whiteboard (`whiteboard`, draft v1)

This document specifies the shared whiteboard of tavrn, a drawing board that every participant renders locally while
only encrypted changes travel between them.

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). Normative for nodes and clients (design note 4.10). A whiteboard is a shared drawing
board in any conversation (voice or text channel, DM, group DM). It is not streamed as video: every
participant renders it locally and only changes travel, as **ephemeral events** encrypted like messages
(`ENCRYPTION.md` §5) and never stored. The reference client uses [Excalidraw](https://excalidraw.com)
(MIT); the element format below is Excalidraw's. Error format, ids and addresses: `PROTOCOL.md`.

## 1. Overview

```text
owner device ──POST /conversations/{id}/ephemeral──▶ node ──WS `ephemeral`──▶ every member with read access
                                                       │                       (except the sending device)
                                     whiteboard.open / grant / close: the node keeps a tiny session
                                                       └──WS `whiteboard.session`──▶ the same audience
```

- **The owner's device is the source of truth.** The user who opens the board ("owner") presents it from one
  device. Viewers apply only what that device sends; granted editors *propose* changes, the owner's device
  applies them and re-broadcasts them as its own. Everything else a client receives is ignored.
- **Joining is on demand.** Members see that a board is open (`whiteboard.session`, a thumbnail) and join it
  when they want; joining asks the owner's device for a snapshot.
- **The node sees** sizes and timing of the events, their types, the sender, and the session state (owner,
  device, "open for everyone", granted addresses, start time). It never sees content of encrypted
  conversations and never stores ephemeral events.

## 2. Node API

### 2.1 `POST /api/v1/conversations/{conversation_id}/ephemeral`

Body `{ type, content, session? }` → `200 { session }`.

- `type`: `cursor` or `whiteboard.<name>` with `<name>` of `[a-z_]`, 1–32 characters
  (`400 ephemeral.type_invalid`).
- `content`: in encrypted conversations the base64url content format of `ENCRYPTION.md` §5.2, checked like a
  message (§5.3: header, epoch known to the node, sending device attested: `400 ephemeral.ciphertext_invalid`,
  `400 ephemeral.epoch_unknown`, `403 e2ee.device_not_attested`); in plaintext conversations a JSON object;
  anything else `400 ephemeral.encryption_mismatch`. At most 64 KiB (the ciphertext string or the serialized
  object): `413 ephemeral.too_large`.
- Who: room members who may view the channel (`403 room.not_member`, `403 channel.view_forbidden`) and are not
  in a timeout (`403 member.timed_out`: cursors and strokes are writing, `permissions.md` step 5), members of
  a DM or group DM (`404 conversation.not_found` for everybody else) that accepted it (`403
  conversation.request_pending`), not in a blocked 1:1 DM (`403 dm.blocked`).
- Rate: 30 events per second and sender (user), `429` with `Retry-After`.
- Fan-out: WebSocket event `ephemeral` `{ conversation_id, type, from: { user, device_id }, content }` to every
  user with read access (the channel's viewers computed from roles and overrides, cached for 2 s; the accepted
  members of a DM or group DM), on all their connections **except the sending device**. `device_id` is the
  device id other clients know (the home device id of users of other nodes), as in MLS identities. Ephemeral
  events are not replayed after reconnects and never stored.
- `session` in the answer: the session after `whiteboard.open`, `whiteboard.grant` and `whiteboard.close`
  (null after closing and for all other types).

### 2.2 The session (the only ephemeral state the node reads)

The node keeps, in memory and per conversation, the session derived from three event types. It reads only
their `type` and their plaintext `session` field `{ open_for_all, grants }` (grants: at most 100 user addresses,
normalized to lowercase; `400 whiteboard.grants_invalid`), never their content.

| Event | Who | Effect |
|---|---|---|
| `whiteboard.open` | needs `use_whiteboard` (voice channels also `connect`; DMs and group DMs always; never in the welcome channel; `403 whiteboard.open_forbidden`; phase 4E, before: `send_messages`) | no live session: the sender's device starts one (owner, device, `session` state or locked); the owner's own session: keepalive, moves the session to this device and takes the `session` state if given; someone else's live session: `409 whiteboard.session_exists` (meta: that session) |
| `whiteboard.grant` | the owner, or in room channels a member with `manage_whiteboard` (`403 whiteboard.not_owner`) | replaces `open_for_all` and `grants` (`400 whiteboard.state_missing` without `session`) |
| `whiteboard.close` | the owner, or in room channels a member with `manage_whiteboard` (`403 whiteboard.close_forbidden`; phase 4E, before: `manage_channels`) | ends the session |

Without a live session `grant` and `close` answer `404 whiteboard.no_session`. Every other event of the owner
also keeps the session alive; a session whose owner sent nothing for **90 seconds** ends by itself (swept
every 15 s). Every change is announced as WebSocket event `whiteboard.session` `{ conversation_id, session }`
(`session` null when it ended) to the same audience as ephemeral events, on all connections (the sender's
too). A node restart ends all sessions; the owner's next keepalive opens it again.

`GET /api/v1/conversations/{conversation_id}/whiteboard` → `{ session }` with
`WhiteboardSession = { conversation_id, owner, owner_id, device_id, open_for_all, grants, started_at }` for
everybody with read access.

### 2.3 Scene library: `/api/v1/users/me/whiteboards` (home node only)

The owner's personal library of scenes, encrypted by the client (§5). Remote users get `403
federation.local_only`. A scene is `{ id, name, size, thumbnail_size, created_at, updated_at }`:

- `GET /users/me/whiteboards` → `{ items, max_scenes, max_scene_bytes }`, most recently changed first.
- `PUT /users/me/whiteboards/{scene_id}`: raw body = the encrypted scene (version byte `0x01`, at least 29 bytes,
  at most 5 MB; `400 whiteboard.blob_invalid`, `413 whiteboard.scene_too_large`), name in the header
  `Tavrn-Scene-Name` (percent-encoded UTF-8, 1–64 characters without control characters,
  `400 whiteboard.scene_name_invalid`). Creates the scene (`201`, name required) or replaces its blob (`200`,
  name optional). `scene_id` is a canonical (uppercase) ULID chosen by the client (`400
  whiteboard.scene_id_invalid`). At most `TAVRN_WHITEBOARD_MAX_SCENES` (default 50) scenes per user
  (`403 whiteboard.scene_limit`).
- `GET /users/me/whiteboards/{scene_id}` → the encrypted blob; `PATCH` `{ name }` renames; `DELETE` → `204`;
  `404 whiteboard.scene_not_found`.
- `PUT|GET /users/me/whiteboards/{scene_id}/thumbnail`: the encrypted thumbnail (same format, at most 64 KiB,
  `413 whiteboard.thumbnail_too_large`, `404 whiteboard.thumbnail_not_found`).
- Writes are rate-limited per user. An identity reset deletes the scenes (they are encrypted under the old
  backup key).

### 2.4 Background images: `POST /api/v1/users/me/whiteboards/background` (home node only)

Raw image body → the converted still image (`image/webp`; PNG/JPEG without ffmpeg). The image goes through the
media pipeline (`PROTOCOL.md` §6b: format by magic bytes, ≤ 20 MB, fit into 1280 px, metadata removed, the
same errors) and is **not stored**: the client puts the result into its encrypted board (§3.4).

## 3. Sync protocol (clients)

Every ephemeral payload is a JSON object whose `type` equals the event type; a payload with another `type` is
dropped (this binds the encrypted content to the event, since the content AAD does not cover the type).
Identities are `<user address>/<device id>`.

### 3.1 Event types

| Type | Sender | Payload | Receivers |
|---|---|---|---|
| `whiteboard.open` | owner device | `{}` + node `session` state; every 30 s as keepalive | joined viewers answer `whiteboard.here` |
| `whiteboard.grant` | owner device | `{}` + node `session` state | (the node's `whiteboard.session` carries the state) |
| `whiteboard.close` | owner or moderator | `{}` | session ends (`whiteboard.session` null) |
| `whiteboard.update` | owner device | `{ elements, background? }`: changed elements | joined viewers and editors |
| `whiteboard.snapshot` | owner device | `{ to, replace, elements, background }`: the whole scene without deleted elements; `to`: identities or null (everyone) | the addressed joined devices; `replace` (a scene was loaded) for everyone |
| `whiteboard.files` | owner device; editor → owner | `{ to, files: [{ id, mimeType, dataURL, created }] }` | viewers from the owner; the owner from editors (re-broadcasts them) |
| `whiteboard.propose` | granted editor | `{ elements }` | only the owner device applies them |
| `whiteboard.request` | joining device | `{}` | the owner answers with a snapshot (requests within 300 ms together) |
| `whiteboard.here` / `whiteboard.leave` | viewers | `{}` | the owner's participant list |
| `whiteboard.thumbnail` | owner device | `{ data }`: `data:image/webp;base64,…` ≤ 60 000 characters, at most every 5 s after changes | everyone (tiles, badges), also before joining |
| `whiteboard.chunk` | owner device; editor → owner | `{ id, index, total, data }`: part of a larger payload | reassembled, then handled as the inner payload |
| `cursor` | joined devices | `{ x, y }` (scene coordinates) at most ~10/s | joined devices show named cursors |

### 3.2 Elements, versions and authority

Elements are Excalidraw elements (`id`, `type`, `version`, `versionNonce`, fractional `index`, `isDeleted`, …).
Every change increments `version` and changes `versionNonce`, so a sender's diff is "every element whose
`version:versionNonce` differs from what was sent or received before"; deletions are updates with
`isDeleted: true`. Receivers reconcile per element: a higher `version` wins; at the same version with another
nonce viewers take the owner's state and the owner keeps its own against proposals.

- Viewers accept `update`, `snapshot`, `files`, `thumbnail` and chunks **only from the owner's device** (the
  session's `owner` and `device_id`).
- The owner accepts `propose`, `files` and chunks from devices of users who may edit (`open_for_all` or in
  `grants`, by user address) and broadcasts what it accepted in its next `update`; editors therefore never
  need to trust each other.
- Untrusted input is validated before use: known element types, integer versions, at most 20 000 elements,
  256 KiB per element; images only as `data:` URLs of `image/png|jpeg|webp|gif|svg+xml`, ≤ 6 MB, ≤ 64;
  backgrounds only `#rgb`, `#rrggbb`, `#rrggbbaa` or `transparent`.

### 3.3 Rates and chunking

Clients throttle element diffs to ~20 per second and cursors to ~10 per second and stay below the node's limit
(the reference client sends at most 28 events per second, cursors only with budget to spare, and retries after
`429`). A payload whose JSON exceeds 40 000 bytes is split into `whiteboard.chunk` events of 30 000 bytes
(base64url); receivers reassemble at most 4 payloads per sender at a time, at most 16 MB each, and drop
incomplete ones after 30 s.

### 3.4 Late joiners, background, export

Joining sends `whiteboard.request` (repeated after 5 s, at most three times, until a snapshot arrives); a
viewer that cannot decrypt an event of the owner (an epoch it has no key for) asks again. The background is a
color (`background`) or an image element marked `customData.tavrnBackground`, locked and placed at the back;
its image comes from §2.4. Export (PNG/SVG) and "share to channel" (an ordinary encrypted attachment,
`ENCRYPTION.md` §6) happen on the client.

### 3.5 On the voice stage (reference client)

In a voice channel the board is presented like a screen share: the tile of the owner's device (identity
`<owner>/<device_id>`, else any tile of the owner) shows a badge and the latest `whiteboard.thumbnail`, others
join on demand from the tile and see the board as a large stage tile. A user presents either a screen share or a
board: starting one ends the other (after a confirmation). Joined viewers are known to the owner from their
`whiteboard.request`, `whiteboard.here` and cursors; the node is not involved.

## 4. Trust model

- Confidentiality: in encrypted conversations the payloads are content-encrypted for the channel's MLS group;
  the node and non-members learn nothing but sizes, timing, types, senders and the session state (§1).
- Integrity: each payload is signed by the sending device (`ENCRYPTION.md` §5.2), so a viewer knows that an
  update comes from the owner's device. The node can at most lie about **who presents** (the session it
  reports): content is always attributed to the device that signed it, and the board is labeled with the
  owner the node names.
- Plaintext channels: payloads are plain JSON objects; their sender is only as trustworthy as the node.
- Editing rights are enforced by the owner's device, not by the node: proposals of users without the right are
  never applied, and viewers never apply anything that does not come from the owner's device.

## 5. Scene encryption

Scenes and thumbnails are encrypted under the backup key exactly like history backups (`ENCRYPTION.md` §7, §7a):
`blob = 0x01 || nonce(12) || AES-256-GCM(backup_key, nonce, aad, plaintext)` with
`aad = "tavrn whiteboard v1" || 0x00 || scene id || 0x00 || part`, `part` = `scene` or `thumbnail`
(`tavrn_crypto::encrypt_scene`, `@tavrn/crypto` `encryptScene`/`decryptScene`). The scene plaintext is
`{"v":1,"elements":[…],"files":[…],"background":"#…"}`, the thumbnail a WebP image. Only the scene's name,
sizes and dates are visible to the home node.
