# tavrn end-to-end encryption (`e2ee.mls1`, draft v1)

This document specifies the end-to-end encryption of tavrn, from account keys and devices through MLS groups and
the content formats to backups, history for new members, secret storage and identity resets.

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). This document is normative for nodes and clients that announce the capability
`e2ee.mls1`. It refines the design notes on encryption (section 5) and `PROTOCOL.md` sections 7 and 8. The reference
implementation is the crate `tavrn-crypto` (repository `tavrn-crypto`, also published to JavaScript as `@tavrn/crypto`);
`testvectors/encryption.json` contains reference values for every format defined here.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## 0. Conventions

- `||` is concatenation. Integers are unsigned big-endian. `u64(x)` is 8 bytes.
- `str16(s)` is `u16(len(s)) || s` with `s` encoded as UTF-8 (length in bytes).
- base64url means RFC 4648 §5 **without padding**. All binary values in JSON use it.
- Ed25519 is RFC 8032 (pure). Verifiers use strict verification (reject non-canonical signatures and
  small-order keys). AES-256-GCM uses 12-byte nonces and 16-byte tags (tag appended to the ciphertext).
  HKDF is RFC 5869 with SHA-256.

### 0.1 Identifiers

| Name | Form | Example |
|---|---|---|
| user address | `<username>@<domain>` (PROTOCOL.md §1) | `alice@node.example` |
| device id | ULID, 26 characters, upper-case Crockford base32 | `01J9ZK3G5M8Q2W4E6R8T0Y2VA1` |
| device identity | `<user address>/<device id>` | `alice@node.example/01J9ZK3G5M8Q2W4E6R8T0Y2VA1` |
| conversation id | `<node domain>/<conversation ULID>` | `node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00` |

The API addresses conversations by their bare ULID (`conversation_id` in the envelope and in paths); all
cryptographic structures use the **qualified** conversation id above, where the domain is the node that
hosts the conversation. This keeps MLS groups of different nodes apart and prevents one node from planting
a group for a conversation of another node. Implementations MUST reject malformed identifiers.

## 1. Overview

```text
recovery key (32 bytes, only with the user) ─┐   passkey PRF output (per credential) ─┐
                                              ▼                                        ▼
                         secret storage on the home node: master secret wrapped per method (§2.4)
master secret (32 bytes, on the user's trusted devices; wrapped copies on the home node)
 ├─ HKDF → identity key (Ed25519)  ── signs ──► device keys (one Ed25519 key per device)
 └─ HKDF → backup key (AES-256)                       │
                                                      ▼
conversation = MLS group (RFC 9420); leaf = device (basic credential = device identity,
                                                    signature key = device key)
 └─ every epoch: MLS exporter → content key (AES-256-GCM)
      ├─ message content: AES-256-GCM, signed by the device key
      └─ backup: (conversation, epoch, content key) encrypted with the backup key, stored on the home node
attachment: random per-file key, AES-256-GCM; key travels inside the encrypted content
```

The node is the MLS delivery service: it stores and orders handshake messages, stores the current
GroupInfo and routes Welcome messages. It never holds key material that would let it read content.

## 2. Account keys

### 2.1 Master secret and derived keys

The master secret is 32 bytes from a cryptographically secure RNG, created by the client at
registration (or at an identity reset, §9). Derivation:

```text
PRK          = HKDF-Extract(salt = "tavrn master v1", IKM = master_secret)
identity_sk  = HKDF-Expand(PRK, info = "tavrn identity key v1", L = 32)   # Ed25519 secret key (seed)
backup_key   = HKDF-Expand(PRK, info = "tavrn backup key v1",   L = 32)   # AES-256-GCM key
identity_wrap_key = HKDF-Expand(PRK, info = "tavrn identity wrap v1", L = 32)   # AES-256-GCM key (§9a)
```

`identity_sk` is **generation 0** of the account's identity key. A rotation (§9a) replaces the signing identity by a
random key that is stored on the home node wrapped under `identity_wrap_key`; the master secret, the backup key and
all epoch keys stay. The *current* identity key is therefore the derived one, or the one unwrapped from the newest
`identity_blob` when the keys document reaches it from the derived key through its continuity chain.

Clients additionally derive a **local storage key** per device, under which they encrypt everything
cryptographic they keep locally (MLS client state, epoch keys, message cache); it never leaves the device:

```text
local_key    = HKDF-Expand(PRK, info = "tavrn local storage key v1" || 0x00 || str16(device_id), L = 32)
```

The salt and info strings are ASCII without terminator. `identity_pk` is the Ed25519 public key of
`identity_sk`. The master secret MUST NOT be sent to any node in plaintext; the home node only stores
copies wrapped with keys it never sees (§2.4). Clients keep it in local storage of trusted devices so
that these devices can attest further devices and read history; a new device or a browser with cleared
data unwraps it from the secret storage.

### 2.2 Key file

The key file encoding is shared by the master secret (version byte `0x01`, this section) and the
recovery key (`0x02`, §2.4). Since the secret storage exists, clients use the **recovery key** as the
user-facing backup; exporting the master secret as a key file is an optional expert feature. The
master secret key file is a text file named `tavrn-key-<username>.txt`:

```text
# tavrn security key v1 - keep this file secret and safe
# Account: alice@node.example
# Whoever has this file can read your encrypted messages.
key: <base64url( 0x01 || master_secret(32) || checksum(4) )>
words: <24 words>
```

- `checksum` = the first 4 bytes of `SHA-256(0x01 || master_secret)`; `0x01` is the format version.
- `words` is the BIP-39 mnemonic (English word list) of the master secret taken as 256 bits of entropy,
  including BIP-39's own 8-bit checksum. It is **not** a BIP-39 seed (no PBKDF2 step); it is just a second,
  human-transcribable encoding of the same 32 bytes.

Parsing rules (MUST): input longer than 4096 characters is rejected; lines are trimmed; empty lines and
lines starting with `#` are ignored; a line starting with `key:` or `words:` carries the respective
encoding; if neither prefix is present, the remaining text is taken as a bare word list (if it contains
spaces) or as a bare `key` value. Words are case-insensitive and may be separated by any whitespace. If both
encodings are present they MUST decode to the same secret. Errors: malformed text, checksum mismatch
(`key` checksum or BIP-39 checksum), a `key` value of the other kind (`0x01` where a recovery key is
expected or `0x02` where a master secret is expected: `key_file_wrong_kind`), any other version byte
(`unsupported_version`). Word lists carry no version byte and decode as either kind; using the wrong
one simply fails to unwrap (§2.4).

### 2.3 What the home node stores

The home node stores `identity_pk` and `identity_reset_at` (null until the first reset) per user, and
the wrapped copies of the master secret (§2.4).

- `PUT /api/v1/users/me/identity` `{ "identity_public_key": "<base64url>" }`: sets the key once. If a key
  is already set the node answers `409 e2ee.identity_exists`; replacing it is only possible through the
  reset (§9).
- `GET /api/v1/users/{username}/keys` (public, no authentication; also the federation lookup):
  ```json
  {
    "user": "alice@node.example",
    "kind": "user",
    "identity_public_key": "<base64url>",
    "identity_reset_at": null,
    "identity_generation": 0,
    "continuity": [],
    "devices": [
      { "device_id": "01J…", "device_public_key": "<base64url>", "identity_signature": "<base64url>",
        "created_at": "2026-10-04T12:00:00Z", "share_public_key": "<base64url>", "share_key_signature": "<base64url>" }
    ]
  }
  ```
  Only devices attested under the current identity key are listed, each with its share key (§3.1; both fields null
  while the device has not published one). `identity_generation` is 0 for the key derived
  from the master secret and n after n rotations; `continuity` is the chain of continuity statements `{ old_key,
  new_key, at, sig_old, sig_new }`, oldest first (§9a), empty until the first rotation and after a reset. A room node
  answering for a remote user from its key cache returns an empty chain and `identity_generation: null`: clients ask
  the user's home node. `kind` is the account kind (`user`, `bot`, …):
  clients take it from the user's home node, so a room node cannot disguise a bot (`APPLICATIONS.md` §3.5).
- **Retired devices.** Deleting a device (settings, logout with `forget_device`, stale-device housekeeping, a
  revoked bot token) keeps its attested key in a separate list, so the history it wrote stays verifiable (§5.2).
  The keys answer carries them as `"retired": [{ "device_id", "device_public_key", "identity_signature",
  "attested_identity_key", "deleted_at" }]`. Retired devices are never active: no sessions, KeyPackages, claims,
  adds or commits, and they are not in the device list. Devices deleted before nodes kept them can be attested
  again by a device of the same user from the device's MLS leaf (its signature key is the device key, §4.5 rule 1):
  `POST /api/v1/users/me/devices/retired { device_id, public_key, identity_signature }`; the node verifies the
  attestation with the current identity key and refuses ids of active devices (`409 device.active`), ids it never
  deleted itself (`404 device.unknown`, see tombstones below) and a second, different key for the same id
  (`409 device.retired_conflict`).
- **Device tombstones.** Whenever the home node deletes a local device (all the paths above) it records the id with
  the user and the deletion time (`device_tombstones`); devices that were already retired got one at the upgrade.
  Re-attestation accepts only ids with a tombstone of the same user, so a hostile node hosting a conversation cannot
  plant a leaf under the user's address and get it shown as a "removed device" of that user. Tombstones are pruned
  after `TAVRN_DEVICE_STALE_DAYS` (kept forever when that is 0); after that a deleted device can no longer be
  attested again.
- **Rotation.** `POST /api/v1/users/me/identity/rotate` and `GET /api/v1/users/me/identity/blob` (§9a).

### 2.4 Secret storage (wrapped master secret)

The home node stores the master secret **wrapped** (encrypted) once per unlock method, so that a new
device or a browser with cleared data can get it back. It never sees a key that unwraps it, and the
password is never involved. Unlock methods:

| Method label | Wrapping key from | Availability |
|---|---|---|
| `recovery` | the recovery key | always (created at registration) |
| `passkey:<credential id>` | the WebAuthn PRF output of that credential | optional, for every credential with PRF support |

`<credential id>` is the base64url WebAuthn credential id (1–1364 characters of `[A-Za-z0-9_-]`).

**Recovery key.** 32 bytes from a cryptographically secure RNG, created by the client, never sent to a
node. It is shown to the user once as 24 BIP-39 words (primary form) and as a compact string; a
download is optional. The user MUST confirm having saved it (clients SHOULD ask for some of the words
again). Encoding (same rules as the key file, §2.2, with version byte `0x02`):

```text
# tavrn recovery key v1 - keep this key secret and safe
# Account: alice@node.example
# Together with your login it unlocks your encrypted messages on new devices.
key: <base64url( 0x02 || recovery_key(32) || checksum(4) )>        # the compact string
words: <24 words>                                                   # BIP-39 of recovery_key
```

`checksum` = the first 4 bytes of `SHA-256(0x02 || recovery_key)`. Regenerating the recovery key
re-wraps the **same** master secret and replaces the `recovery` entry; it is not an identity reset.

**Wrapping keys** (HKDF-SHA256, "salt = none" is RFC 5869's default of 32 zero bytes):

```text
recovery_wrap_key = HKDF(salt = none, IKM = recovery_key, info = "tavrn secret storage recovery v1", L = 32)
passkey_wrap_key  = HKDF(salt = none, IKM = prf_output,   info = "tavrn secret storage passkey v1",  L = 32)
```

`prf_output` is the 32-byte `clientExtensionResults.prf.results.first` of a WebAuthn ceremony (create
or get) with the input `extensions.prf.eval.first = UTF-8("tavrn secret storage prf v1")` (base64url
`dGF2cm4gc2VjcmV0IHN0b3JhZ2UgcHJmIHYx`). The same input is used for every credential; the output is
specific to the credential and the relying party. The node puts this input into every WebAuthn option
set it serves (PROTOCOL.md §5a), so one ceremony can log in and unlock at the same time.

**Entry** (61 bytes, uploaded and served as base64url):

```text
wrapped = 0x01 || nonce(12) || AES-256-GCM(wrap_key, nonce, aad, master_secret(32))
aad     = "tavrn secret storage v1" || 0x00 || str16(user address) || str16(method label)
```

The AAD binds an entry to its account and method: the node cannot move an entry to another user or
method. Unwrapping fails (`decryption_failed`) for a wrong key, account or method, or modified bytes.

**Node API** (full session only, i.e. password **and** second factor; owner only):

- `GET /api/v1/users/me/secret-storage` → `{ "items": [ { "method", "wrapped", "params", "updated_at" } ] }`.
- `PUT /api/v1/users/me/secret-storage/recovery` and
  `PUT /api/v1/users/me/secret-storage/passkey/{credential_id}` with `{ "wrapped": "<base64url>",
  "params": { … } }` → `204`; stores or replaces the entry. `params` is a JSON object of at most 2 KiB
  that the node stores verbatim (clients MAY record e.g. the client version; nothing secret). The node
  checks that `wrapped` is exactly 61 bytes with version `0x01` (`400 secret_storage.invalid`), the
  params (`400 secret_storage.params_invalid`, `413 secret_storage.params_too_large`), that the
  credential belongs to the user (`404 webauthn.not_found`), and rate-limits writes (`429`). The
  entry is the proof that the credential's PRF works: storing it marks the credential as
  `prf_supported`, also when its registration did not announce the extension (some platform
  authenticators report it only at assertion time, or gain it with a system update).
- `DELETE /api/v1/users/me/secret-storage/passkey/{credential_id}` → `204` (`404
  secret_storage.not_found`). Deleting the WebAuthn credential deletes its entry as well; the identity
  reset (§9) deletes all entries. There is no password entry and no route for one.

**Client rules.**

- A PRF result MUST NOT leave the client: remove `clientExtensionResults.prf.results` from the
  credential JSON before posting it. The node rejects such requests with `400 webauthn.prf_output_sent`. The
  one exception is the sealed unlock material of a connect app session (`FEDERATION.md` §8 step 3): sealed to
  the app's own key, which the node never sees.
- After unwrapping, the client MUST check the master secret against the account's identity key published by the
  home node (`GET /users/{username}/keys`): the derived key (§2.1) equals the published key, **or** the published
  key is reachable from the derived key through a valid continuity chain of that document (§9a) and the
  `identity_blob` (`GET /users/me/identity/blob`) unwraps with the master secret to exactly the published key. In
  every other case (no chain, a broken link, a blob that does not unwrap or holds another key) the entry is stale or
  forged and MUST NOT be used.
- The master secret is kept in local storage of trusted devices only (in browsers: IndexedDB, wrapped
  with a non-extractable WebCrypto key where available); the recovery key is never stored.

**Client flows.**

1. *Registration* (PROTOCOL.md §5a for the authentication part): password → second-factor enrollment
   (TOTP or passkey; the session starts here) → recovery key generated, shown, confirmed → master secret
   generated, `PUT /users/me/identity`, `PUT …/secret-storage/recovery` → device key generated and
   attested, KeyPackages uploaded (§3) → master secret stored locally → the account is usable. If the
   enrolled passkey reported PRF support, the client additionally evaluates the PRF (at creation if the
   browser returned results, otherwise with one `get()` for that credential) and uploads
   `…/secret-storage/passkey/{credential_id}`.
2. *New device or cleared browser*: log in (password and second factor, or passkey-only) →
   `GET /users/me/secret-storage` → if the login used a PRF passkey with an entry, derive
   `passkey_wrap_key` from the PRF output of that same ceremony; otherwise ask for the recovery key
   (words, compact string or file) → unwrap → check the identity key → continue with §8. A native app whose
   ceremony ran on the home node's page (connect app session) receives the PRF output and credential id of that
   ceremony as sealed unlock material, encrypted to a key only the app holds (`FEDERATION.md` §8 step 3), and
   continues the same way.
3. *Regenerate the recovery key* (settings, on a trusted device): new recovery key, wrap, `PUT
   …/recovery`, show and confirm the new words. The old recovery key stops working.
4. *Add a passkey later*: register it (PROTOCOL.md §5a); if PRF is supported, evaluate the PRF and upload
   its entry. *Remove a passkey*: its entry goes with it.
5. *Password change*: nothing to do; the secret storage does not depend on the password.
6. *Everything lost* (no trusted device, no recovery key, no PRF passkey): identity reset (§9).

**Old entries stay valid.** Regenerating the recovery key (flow 3) or removing a passkey (flow 4) replaces or deletes
that entry on the node, but it does not invalidate a copy made before: whoever kept an old entry (a backup of the
node's database, an earlier download) together with the old recovery key or the PRF output of the removed passkey can
still unwrap the master secret from it, because the master secret itself did not change. Only an identity reset (§9)
creates a new master secret and so makes every old entry worthless. Clients say this where the user regenerates a
recovery key or removes a passkey because it may have leaked, and offer the reset for that case.

## 3. Devices

**Bot devices** (`APPLICATIONS.md` §3): every app token is bound to exactly one bot device (`dev`); the bot process
attests that device with the bot's identity key and keeps its KeyPackages uploaded like any device. Bots have
no secret storage and no recovery key; their master secret lives in a key file of the bot process (§2.2 format).
Revoking a token deletes its device (`devices.changed`, `mls.remove_needed`); resetting it keeps the device.
### 3.1 Device key and attestation

Every device generates its own Ed25519 key pair; the secret key never leaves the device. The device key
is the device's MLS signature key and signs encrypted content (§5). The account binds it with an
**identity signature**:

```text
attestation_message = "tavrn device attestation v1" || 0x00
                      || device_public_key(32) || str16(device_id) || str16(user_address)
identity_signature  = Ed25519-Sign(identity_sk, attestation_message)
```

A device key is immutable: a new key means a new device (new device id). Exception: an identity reset
(§9) keeps the device keys and only renews the attestations.

- `PUT /api/v1/users/me/devices/{device_id}/key` `{ "device_public_key", "identity_signature", "share_public_key"?,
  "share_key_signature"? }`: only for the device of the current session. The node MUST verify the signature against
  the stored `identity_pk` and refuse to overwrite an existing key (`409 e2ee.device_key_exists`). The share key
  fields (below) come together or not at all and are checked before anything is stored (`400
  e2ee.share_key_invalid`; another share key than the stored one: `409 e2ee.share_key_exists`).

**Share key.** Every device also has an X25519 key pair, its **share key**, to which other devices seal secrets for
it alone (history shares, §7b). It lives exactly like the device key: stored with it in the device's local storage,
kept by an identity reset (§9), never moved to another device; a new device has a new pair. The reference
implementation derives it from the device secret key (32-byte Ed25519 seed):

```text
share_secret = HKDF-SHA256(salt = "" (empty), IKM = device secret key, info = "tavrn device share key v1", L = 32)
share_public = X25519(share_secret, 9)                 # share_secret used as libsodium stores X25519 secret keys
share_key_signature = Ed25519-Sign(device_sk, "tavrn device share key v1" || 0x00
                                   || share_public(32) || device_public_key(32) || str16(device_id))
```

Other implementations MAY generate a random pair and store it next to the device key instead; others only ever see
the public key and the signature. The share key is published with the device key (above) or, by devices attested
before share keys existed, once with `PUT /api/v1/users/me/devices/{device_id}/share-key` `{ share_public_key,
share_key_signature }` (the session's attested device only, `403 e2ee.wrong_device` / `403 e2ee.device_not_attested`;
the node verifies the signature against the stored device key, `400 e2ee.share_key_invalid`; the same key again is
`204`, another one `409 e2ee.share_key_exists`: share keys are immutable). It is served wherever the device's
attestation is served (the keys document, §2.3, also through the key cache of room nodes, `FEDERATION.md` §3.5) as
`share_public_key` and `share_key_signature`. Clients use a share key only after verifying the device's attestation
(§3.3) **and** this signature with the attested device key; room nodes drop share keys whose signature does not verify
(the device stays). Test vector: `device_share_key` (device secret, share key pair, signing input, signature;
`tavrn_crypto::share`, `@tavrn/crypto` `Client.shareKey`, `verifyDeviceShareKey`).

### 3.2 KeyPackages

KeyPackages are single-use MLS messages (`MLSMessage` with wire format `mls_key_package`) of the
ciphersuite in §4.1 whose leaf carries the device identity and the device key.

- `POST /api/v1/users/me/devices/{device_id}/key-packages` `{ "key_packages": ["<base64url>", …] }`.
  The node MUST validate each one (signature, ciphersuite) and check that the credential identity equals
  `<session user>/<device_id>` and the leaf signature key equals the attested device key
  (`tavrn_crypto::ds::inspect_key_package`). At most 100 are stored per device (`409
  e2ee.key_package_limit`), each at most 4 KiB; exact duplicates are stored once.
- `GET /api/v1/users/me/devices/{device_id}/key-packages` → `{ "count": n }`. Clients keep at least 10
  uploaded and top up when fewer than 5 are left.
- `POST /api/v1/users/{username}/key-packages/claim` (authenticated, rate-limited) →
  `{ "key_packages": [ { "device_id", "key_package" } ] }`: one KeyPackage per attested device; each
  returned KeyPackage is deleted (single use). Devices without a KeyPackage are omitted. On the node hosting
  a conversation the route also accepts foreign addresses, served only through the S2S claim proxy to the
  user's home node (`FEDERATION.md` §3.5). The home node limits claims per requesting user and target user and, for
  requesters who share no room, DM, group DM or friendship with the target, per source (the home node itself, or one
  requesting node) and target user, so that claims in many names neither drain a user's KeyPackages nor lock out the
  people who legitimately add them (reference node: `TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR`, default 60 per source,
  ten times that per target over all sources; related requesters and a user's claims for their own devices do not
  count; beyond the budget `429`).

### 3.3 Verifying other users' devices

Clients pin `identity_pk` per user address on first use (TOFU). For every device they encounter (MLS
roster, message author), clients MUST verify the attestation against the pinned identity key and that the
MLS leaf signature key equals `device_public_key`. A changed identity key of a known contact is shown as
"security key changed" (design note 5.3) and re-pinned only after the notice was shown.

Until the user **acknowledges** that warning (or verifies the new key, FEDERATION.md §10.2), devices attested under the
new key do not count: the client does not add them to DMs and group DMs (§4.2, no KeyPackage is claimed, no Welcome
sent), and the ghost check reports their leaves with the reason `key_changed` (§4.6), which holds back sending like
every ghost warning. A home node that swaps a user's key therefore cannot place a device of its own in that user's
conversations before the other side saw the warning. Acknowledging makes the devices count at once: the client adds
the missing devices to the DMs and group DMs and checks the rosters again. The devices' messages are shown meanwhile
(with the warning next to the author); only membership waits.

Exception, the **rotation** (§9a): when the keys document of the user's home node carries a continuity chain that
leads from the pinned key to the published one with valid statements, the client pins the new key at once and shows
a soft, dismissable notice ("security key rotated, signed by the previous key") instead of the blocking warning;
attestations under the new key count immediately (MLS roster checks, message authors). A **verified** contact
(FEDERATION.md §10.2) whose key rotated this way drops to "verification needs a refresh": not blocking, dismissable,
the safety-number comparison verifies it again, because a thief of the old key could have signed the statement too.
Retired devices (§2.3) are verified under their `attested_identity_key` when that key is the current one or lies on
the valid chain before it.

The `system.key_changed` entries the nodes write into welcome channels (PROTOCOL.md §7) are informational only: a
client never pins, re-pins or acknowledges a key because of such an entry. It may take one as a reason to look the
user's keys up again on their home node; what it shows comes from its own pin.

### 3.4 Device proof at login

A login on a browser or program that still holds a device of the account continues that device instead of creating
a new one (PROTOCOL.md §5b). The client signs a single-use nonce of the node (`POST /auth/device-nonce`) with the
device key:

```text
login_proof_message = "tavrn device login v1" || 0x00 || str16(device_id) || str16(user_address) || str16(nonce)
proof               = Ed25519-Sign(device_sk, login_proof_message)
```

The node accepts it only for a local device of the authenticated user whose key is attested under the current
identity key, and spends the nonce. The proof binds device, account and nonce: it cannot be replayed, moved to
another account or used to take over another user's device. Without the device key (e.g. "lock on close", the key
store cannot be opened before the unlock) there is no proof and the login creates a new device; the client then
deletes the old device once it discards its local data, so its leaves do not linger (§4.7).

## 4. MLS groups

### 4.1 Parameters

- MLS 1.0 (RFC 9420), ciphersuite `0x0001` `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` only. Groups,
  GroupInfos, Welcomes and KeyPackages of any other ciphersuite MUST be rejected.
- Credential: basic credential, `identity` = UTF-8 device identity (§0.1). Leaf signature key = device key.
- Group id = UTF-8 bytes of the qualified conversation id. One group per conversation (channel, DM,
  group DM); voice channels use the group of the channel.
- All handshake messages (commits) are sent as `PublicMessage`, so the node can validate them (the
  "pure plaintext" wire format policy for handshake messages). MLS application messages are **not used**;
  content is encrypted as in §5.
- Every GroupInfo published to the node carries the `ratchet_tree` and `external_pub` extensions, so any
  authorized device can join by external commit without further help.
- Commits MAY contain only Add, Remove and (for external commits) ExternalInit proposals, by value, plus an
  update path. Standalone proposals, proposals by reference, PSKs, ReInit, GroupContextExtensions and all
  other proposal types MUST be rejected by nodes and clients in v1.
- KeyPackage lifetimes follow the MLS library default (at most 12 weeks). Leaves added through a KeyPackage
  keep that lifetime in the tree, so clients skip the leaf lifetime check when joining by Welcome or
  external commit (all signatures are still verified); the node checks lifetimes only once, when the group
  is created.

### 4.2 Operations

| Situation | Operation |
|---|---|
| New conversation | the creator creates the group (epoch 0) and uploads its GroupInfo |
| DM, group DM, private channel invite | a member claims the invitee's KeyPackages and commits Adds; Welcome per added device |
| Public channel, new device of a member | the device joins by external commit with the node's GroupInfo |
| Leave, kick, ban, permission loss, device removed, identity reset | a member commits Removes of the affected leaves |
| Rotate the content key | any member commits an empty commit with update path ("self update") |
| Local state lost | the device rejoins by external commit; a leaf with the same signature key is removed automatically in the same commit |

Clients SHOULD rotate (self update) at least weekly in active conversations and after a member was
removed if they did not commit the removal themselves.

Claimed KeyPackages reach the client through the node hosting the conversation (§3.5 of `FEDERATION.md`). Before an
Add, a client MUST check that the KeyPackage's leaf carries the basic credential `<address>/<device id>` of the device
it was claimed for and exactly that device's attested key (§3.3), and drops it otherwise.

### 4.3 Commit protocol (client)

Commits are two-phase. The client creates a commit, which stays **pending** locally, and posts it together
with the GroupInfo of the resulting epoch:

1. `2xx`: the client merges its pending commit and is at the new epoch.
2. `409 mls.epoch_conflict`: another commit won the epoch. The client discards its pending commit (a
   rejected external join deletes the local group), fetches and processes the missing commits and retries
   if the operation is still needed.
3. Unknown outcome (network failure): the client fetches the log from its epoch. If the commit stored for
   its epoch is its own, processing it merges the pending commit (OpenMLS reports this as an own pending
   commit); otherwise it proceeds as in 2. For external joins the client compares the stored commit bytes
   with the ones it sent.

Clients process the handshake log strictly in epoch order. A commit for an epoch older than the local one
is skipped (`stale_epoch`); a newer one means commits are missing (`future_epoch`). A commit that fails
validation stops processing; the client then rejoins by external commit and warns the user. Clients apply the
identity rule of §4.4 themselves: a member's commit whose update-path leaf carries another identity than the
committer's is refused (`invalid_credential`), whatever the node accepted.

### 4.4 Delivery service (node)

The node hosting the conversation implements, under `/api/v1/conversations/{conversation_id}/mls`:

- `POST …/group` `{ "group_info" }`: creates the group state. Only allowed while no group exists (first
  wins, otherwise `409 mls.group_exists`) and only for a member allowed to post in the conversation. The
  GroupInfo MUST be for epoch 0, contain exactly the uploader's device, and pass
  `tavrn_crypto::ds::DsGroup::create`.
- `GET …/group-info` → `{ "epoch": n, "group_info": "<base64url>" }`: the latest GroupInfo. Readable by
  every device that may join (members of the conversation; for room channels everyone with read access).
- `POST …/commits` `{ "epoch": n, "commit": "<base64url>", "group_info": "<base64url>",
  "welcome": "<base64url>" | null }` → `201 { "epoch": n + 1 }`. The node:
  1. rejects the request unless `epoch` equals the current epoch (`409 mls.epoch_conflict`, body carries
     the current epoch); the first commit for an epoch wins, enforced by a unique key
     `(conversation, epoch)` in the same transaction that updates the group state;
  2. validates commit and GroupInfo with `DsGroup::process_commit` (signature, epoch, allowed proposals,
     credentials, GroupInfo signed by the committer and matching the new epoch and ratchet tree). **A leaf never
     changes its identity:** the update-path leaf of a member's commit MUST carry the committer's identity, and after
     the commit no two leaves may share a signature key (OpenMLS checks key uniqueness only for added KeyPackages);
     such a commit is refused as `400 mls.invalid`;
  3. applies the authorization rules of §4.5 to the returned summary (committer, external join, added and
     removed identities), answering `403 mls.forbidden` on violation;
  4. stores the commit in the handshake log at `epoch`, replaces the stored GroupInfo and DS state, stores
     the Welcome for every added device and emits the WebSocket events `mls.commit`
     `{ conversation_id, epoch }` to the members and `mls.welcome` to the added devices.
- `GET …/messages?since_epoch=n&limit=100` → `{ "items": [ { "epoch", "commit" } ], "next" }`: the handshake
  log in ascending epoch order, starting at `since_epoch`. The node keeps at least the last 1000 epochs or
  90 days; a client that is further behind (the first returned commit is newer than its epoch) rejoins by
  external commit. **Retention of the reference node:** an hourly housekeeping job deletes commits that are
  both older than 90 days and not among the newest 1000 epochs of their conversation, and pending Welcomes
  older than 30 days (a device that never fetched its Welcome rejoins by external commit as well).
- `GET /api/v1/mls/welcomes` → `{ "items": [ { "id", "conversation_id", "epoch", "welcome", "created_at" } ] }` and
  `DELETE /api/v1/mls/welcomes/{id}`: Welcomes addressed to the authenticated device (also for devices of
  federated users, who talk to the conversation's node directly). After `join_by_welcome` the client MUST
  check that the returned conversation id names this node and the expected conversation.

Event details (PROTOCOL.md §6): `mls.commit` carries the epoch the group is at *after* the commit (and is also
sent with epoch 0 when the group is created); `mls.welcome` `{ conversation_id, epoch }` is addressed to the
added devices only. A `409 mls.epoch_conflict` carries the current epoch in `meta.epoch`. Other errors:
`400 mls.invalid` (validation failed), `400 mls.welcome_missing`, `400 mls.not_encrypted` (group for an
unencrypted channel), `404 mls.no_group`, `413 mls.too_large` (each MLS message at most 1 MiB),
`403 e2ee.device_not_attested`, `429` (commits are rate-limited per device).

The node stores per conversation: the DS state (`DsGroup::export_state`), the latest GroupInfo with its
epoch, the handshake log and pending Welcomes. Encrypted messages are stored as before (PROTOCOL.md §7).

### 4.5 Who may commit (node rules)

The node checks every accepted commit; clients additionally verify all MLS signatures and device
attestations. With `C` = committer identity from the summary:

1. `C` MUST be the authenticated device (`<session user>/<session device>`), its leaf signature key MUST be
   the attested device key, and the attestation MUST be valid under the current identity key
   (identity reset: §9).
2. **External join** (`external_join = true`): allowed if the user may be in the conversation (member of
   the DM/group DM, or room member with read access to the channel; node admins who are not room members are
   not entitled, so they never appear as ghost members). A member moved into a voice channel by a moderator has
   read access to it while the moved participation lasts (`VOICE.md` §7 "Moved participations"), even without
   `view_channel`; when it ends the node announces their leaves with `mls.remove_needed`. Bots are never entitled in a channel whose effective
   "no bots" flag is set (`APPLICATIONS.md` §3.5): the node refuses their GroupInfo requests and commits with
   `403 mls.forbidden`. It MAY remove only leaves with the identity `C` itself
   (rejoin after state loss), and it MUST remove every leaf that carries `C`'s signature key (`403 mls.forbidden`
   otherwise): a device is in the group at most once. A leaf with the identity `C` but another key is tolerated at
   the join (OpenMLS external commits remove only the leaf with the joiner's key): it is an unattested ghost that
   housekeeping lists and any member may remove (rule 4). Clients remove such leaves by identity *and* key.
3. **Add**: every added identity MUST be an attested device of a user who may be in the conversation. For
   DMs, group DMs and private channels, adding devices of another user additionally requires that the user
   was invited according to the room or conversation rules; adding further devices of one's own user is
   always allowed. Devices of a bot are not entitled in a "no bots" channel (`403 mls.forbidden`); setting the
   flag emits `mls.remove_needed` for the bots' leaves.
4. **Remove**: a leaf may be removed if its user is no longer entitled to the conversation (left, kicked,
   banned, lost read permission), its device was deleted or is not attested under the current identity key,
   its signature key is not the attested key of the device it names (any member may remove such a leaf;
   housekeeping lists it as `unattested`, §4.7), or it belongs to the committer's own user. Removing a leaf of an entitled user's attested device is
   refused: membership is decided by the node's room rules (kick/ban go through the normal API first), MLS
   follows. When membership ends, the node emits `mls.remove_needed` `{ conversation_id, identities }` to the
   members' devices; the first valid commit wins.
5. **Self update** (no proposals): any member.

### 4.6 Ghost member detection (client)

After processing commits and whenever a conversation is opened, the client compares the MLS roster with
the member list served by the node and the device attestations:

- every leaf identity's user MUST be in the node's member list of the conversation;
- every leaf MUST have a valid attestation under the user's pinned identity key, with matching signature key;
- no identity may appear twice;
- a leaf attested under a changed identity key whose warning the user has not acknowledged yet (§3.3) is reported
  with the reason `key_changed`; it is no ghost once the user acknowledged the change.

- a leaf whose user is a bot (`kind` from the user's home node, §2.3) in a conversation whose effective "no bots"
  flag is set is a ghost member, even if the node lists the bot as a member (`APPLICATIONS.md` §3.5). The effective
  flag includes the room setting `bots_in_encrypted_channels`: in a `per_channel` room every encrypted channel without
  `bots_allowed` counts as "no bots". Clients compute it from the room and channel settings themselves and OR it with
  the node's `no_bots_effective`.

A leaf that names an attested device but carries another signature key is unattested, whichever of the two leaves
comes first in the roster; a second leaf with the attested key is a duplicate.

Any violation MUST be shown as a visible warning naming the unknown device ("An unknown device is part of
this conversation"), and the client MUST NOT encrypt any content for the conversation (messages and edits, thread
titles, forum posts, file records, whiteboard scenes and other ephemeral content) until the user acknowledged that
leaf. Only the user's explicit acknowledgement counts: running the check and showing its result is not one, and an
acknowledgement covers one leaf, by identity **and** signature key: a leaf that appears later, also under an
acknowledged device id with another key, needs its own. Implementations SHOULD enforce this in the component that
encrypts, so that a view that does not show the warning fails closed. Members without any leaf are not an error (they
have not joined yet); their messages cannot exist.

Unattended clients (bots, `APPLICATIONS.md`) have nobody to acknowledge a warning and decide by an operator setting
instead. The safe default accepts only leaves of devices that were attested and are now retired (deleted, removal
pending, §2.3) and refuses to encrypt for anything else (a key never attested, an identity key that changed without
a continuity chain from the pinned key, a non-member), reporting the conversation and the leaves; rotations with a
valid chain (§9a) are no violation. An operator MAY opt into sending anyway, in which case every accepted leaf is
logged.

### 4.7 Removing ghost leaves (client)

A leaf has to go when its device was deleted or is no longer attested, or its user is no longer entitled. The node
records such leaves as **pending removals** when it emits `mls.remove_needed` (device deleted, identity reset,
membership ended, "no bots") and when its hourly housekeeping finds leaves of devices that no longer exist; rows
disappear when a commit removes the leaf, when the leaf is no longer in the roster, or after 90 days. Members list
them with `GET /conversations/{id}/mls/pending-removals`, users their own leaves of all conversations with
`GET /mls/pending-removals` (PROTOCOL.md §5b).

Clients remove only leaves they verified themselves (§4.6 ghost check) and only on the paths the node allows (§4.5
rule 4, still enforced by the node):

1. any device of the same user removes that user's other ghost leaves (own-user rule);
2. any member removes leaves whose device is deleted or not attested;
3. leaves of users who are no longer members are removed by members who may manage the conversation (DMs and group
   DMs: every member; channels: kick, ban or manage channels).

Before an own leaf goes whose device has no retired attestation yet (deleted before nodes kept them), the client
attests it again as retired from the leaf key (§2.3), so the device's history stays readable; if that fails for
network reasons the leaf stays for a later try. A client MUST do this only for a device id and key the account
attested itself, as recorded in its trust record (§7: this device, and own devices whose attestation the client
verified under the own identity key); a roster key alone is no evidence, since the hosting node can plant a leaf under
the user's address with a key of its own. Any other own ghost leaf is removed without a new attestation, and messages
of such a device stay unverifiable.

Removals name each leaf by identity **and** signature key, so a leaf that names a genuine device with another key is
removed while the genuine leaf stays.

Cleanup runs when a conversation is opened, when a voice channel is joined, on `mls.remove_needed` and after
(re)connecting when the node lists pending removals of own leaves. One cleanup runs per conversation at a time. To
avoid competing commits, the lowest device id among the online devices that may commit the removal tries first
(voice: the participants; otherwise every valid leaf; a device that may not commit one of the removals, or that the
client knows to be offline, does not count); every other device waits 10 seconds and tries only if the leaf is still
there. A voice join never waits for that election: the joining device removes at once when it is the elected one,
otherwise it joins on the current epoch (the self update that renews the voice key follows) and the cleanup runs in
the background after the join, so a removal may land after the join's commit. An epoch conflict is retried after the missing
commits, at most three times with backoff; a leaf the node refused is not tried again in that session. The ghost
warning tells a deleted device whose removal is pending ("device was removed, cleanup pending") apart from a
genuinely unknown device and disappears with the leaf.

## 5. Message content

### 5.1 Content key

For every epoch: `content_key = MLS-Exporter("tavrn content v1", context = "" (empty), length = 32)`.
Clients store `(conversation id, epoch, content_key)` for every epoch they were a member of; they need old
keys to read history and back them up (§7).

### 5.2 Format

The envelope field `content` (PROTOCOL.md §7, `encrypted = true`, `format = 1`) is:

```text
content    = base64url( 0x01 || u64(epoch) || nonce(12) || ciphertext )
ciphertext = AES-256-GCM(key = content_key(epoch), nonce, aad, plaintext)   # includes the 16-byte tag
aad        = 0x01 || str16(conversation id) || u64(epoch) || str16(author) || str16(device_id)
plaintext  = signature(64) || json
signature  = Ed25519-Sign(device key, "tavrn content signature v1" || 0x00 || aad || nonce || json)
```

- `nonce` is 12 random bytes per message. `author` is the envelope's `author` (user address), `device_id`
  the envelope's `device_id` (the device that sent or last edited the message), `epoch` MUST equal the
  envelope's `epoch`.
- `json` is the UTF-8 JSON content object of PROTOCOL.md §7 (it MUST be an object).
- **Signed context.** The AAD binds conversation, epoch, author and device, but not the envelope fields `thread_id`
  and `reply_to_id`. Senders of a message therefore put them into the signed JSON as
  `"ctx": { "thread_id": <thread id or null>, "reply_to": <message id or null> }`, exactly the values the envelope
  will carry (edits repeat the message's values). Receivers compare `ctx`, when present, with the envelope they were
  served: a different value, or a malformed `ctx` (not an object with exactly these two fields, each a string or
  null), is shown as `envelope_mismatch`, like a bad signature, never as content; clients do not show `ctx` itself.
  This keeps the node from moving an encrypted reply into another thread or the main channel, or pointing it at
  another message (plaintext signatures cover the same fields, FEDERATION.md §10.3). Content without `ctx` (older
  clients) is accepted as before; the node cannot see `ctx` and accepts both forms. A sender that cannot know the
  thread id (a new thread on a node that does not announce `threads.client_ids`, PROTOCOL.md §7e) omits `ctx`.
  History shares and ephemeral events carry no `ctx`. Test vector: `content_context`.
- **Answers of applications** (`APPLICATIONS.md` §5.7): a bot's replies and follow-ups to an interaction carry a third
  field, `"ctx": { "thread_id", "reply_to": null, "interaction": "<interaction id>" }`. Receivers compare `interaction`
  with the envelope's `interaction.id` (stored answers) or the `interaction_id` of an ephemeral reply; a different
  value, or `interaction` on content whose envelope names no interaction, is `envelope_mismatch`. So the node cannot
  present a bot's answer to one invocation as the answer to another (or to someone else's command). `ctx` with exactly
  `thread_id` and `reply_to` stays valid for answers (older bots), as does an answer without `ctx`.
- **Thread titles** carry `"ctx": { "thread_id": "<thread id>" }` (exactly this field, a string) when the setting
  device knows the thread id: a rename always, a new thread where the client chooses the id (`threads.client_ids`,
  PROTOCOL.md §7e). Receivers compare it with the thread whose title they render; a different value or a malformed
  `ctx` is `envelope_mismatch` (shown like any title that cannot be read), so the node cannot swap encrypted titles
  between threads. A title without `ctx` (older clients, nodes without client ids) is accepted as before.
- **Poll votes** (`PROTOCOL.md` §7g) are vote records, not messages: content format 1 of `{ "type": "poll.vote",
  "choices" | "answers", "voted_at", "ctx": { "poll": "<message id>", "poll_hash": "<hex>" } }` under the current
  epoch, `author` the voter and `device_id` the voting device (the record's `user` and `device_id`). `ctx` has
  exactly these two fields (strings) and replaces the message context: `poll` binds the vote to the poll message,
  `poll_hash` (lowercase hex SHA-256 of the RFC 8785 (JCS) form of the poll's content object without its `ctx`
  member) to the poll's exact content, so an edited poll leaves earlier votes visibly stale. Receivers compare
  `poll` with the message whose votes they load (a different value or a malformed `ctx` is `envelope_mismatch`, the
  vote is not counted) and the hash with the poll they render. Content of `type = "poll.vote"` is never shown as a
  message, and a vote record whose content has another `type` is `invalid`: the node cannot serve one as the other.
  Test vector: `poll_vote` in `testvectors/polls.json` (the poll, its JCS form and hash, an encrypted vote and a
  plaintext signed vote).
- Senders always use the current epoch of their local group. Before encrypting, the client processes the handshake log
  (§4.3); when that fails (network error, a node error), it does **not** send: the composer shows the error and offers
  to retry, so a message never goes out under an epoch that removed members may still hold. The ghost check (§4.6) runs
  again after commits were processed there, since a processed commit may have brought a new device.
- Receivers look up the content key of the header epoch, decrypt, verify the signature with the author
  device's key and then parse the JSON. The device key is taken from the current MLS roster (leaf
  `<author>/<device_id>`); if the device is no longer a member (history), from its verified attestation
  (§3.3). A deleted device is verified with its **retired** attestation (§2.3) under the pinned identity key, only
  for messages whose server time (`created_at`) is not later than its `deleted_at` plus 5 minutes of slack; clients
  show such messages normally with a subtle note ("sent from a device that was later removed"). Ephemeral events
  (no server time) never come from retired devices. Any failure is shown as such, never as content, with the reason
  told apart: no key for the epoch (`missing_key`), sending device not confirmed (`unknown_device`), bad signature,
  a signed context that does not match the envelope (`envelope_mismatch`), replay, or damaged/undecryptable content.
- A second message with the same `(epoch, nonce)` is a replay and MUST be shown as a duplicate or hidden.
- Edits are encrypted the same way under the current epoch.
- Thread titles in encrypted channels (`PROTOCOL.md` §7e) use the same format with the JSON object
  `{ "type": "thread.title", "body": "…", "ctx"?: { "thread_id" } }`; `author` and `device_id` are the thread's
  `title_author` and `title_device_id`, `epoch` its `title_epoch`.

### 5.3 Node checks

The node cannot decrypt. For `encrypted = true` it MUST check that `content` is valid base64url, at least
`1 + 8 + 12 + 16 + 64` bytes, version `0x01`, that the header epoch equals the envelope `epoch` and is not
newer than the group's current epoch, that the sending device is attested (§3.1) and the usual size limits
(`tavrn_crypto::content_header`). The plaintext/ciphertext rules of PROTOCOL.md §7 stay unchanged.

The node accepts new content (messages and their edits, thread titles, interaction responses, records of files
channels, poll votes) only under the group's **current** epoch, or under the epoch before it within 60 seconds after
the commit that ended that epoch (content that was encrypted while the commit was on its way). Older content is refused with
`409 mls.epoch_stale` (`meta.epoch` = the current epoch), a newer epoch with `400 message.epoch_unknown` as before. A
client that gets `mls.epoch_stale` processes the missing commits and encrypts again. This bounds how long a removed
member's key (the epoch before its removal) can still be used to post, and keeps a lagging client from writing under
keys that new members cannot read.

### 5.4 Security properties

- Confidentiality against the node and everyone who was not a member in the message's epoch.
- Authenticity per device: a member who knows the epoch key cannot forge messages of other devices; the
  AAD and the signature bind conversation, epoch, author and device, so the node cannot move a message to
  another conversation, epoch or author.
- Post-compromise security through MLS: after a compromised device is removed or updated, new epochs are
  safe. Forward secrecy is per epoch with respect to the MLS state; because clients keep content keys for
  history (and back them up), a compromised device or backup key exposes the history it holds (the usual
  trade-off of group encryption schemes that keep message keys in a key backup, design note 5.3).
- New members cannot read messages from before their join, unless the channel's history policy lets members
  share older keys with them (§7b); removed members cannot read messages after their removal.
- The node sees metadata: conversation, author, device, timestamps, epoch, ciphertext sizes, `mentions`
  (deliberately plaintext, PROTOCOL.md §7), reactions, poll votes (who voted on which message and when, their
  ciphertext sizes) and poll close times, pins, reply and thread references, attachment count, sizes and ciphertext
  hashes, membership changes (commits are public messages), the URLs of link
  previews, which are fetched only when the user enables them, and the size and update times of the user's trust
  record (§7), which grow with the number of contacts.
- Every message of an encrypted conversation is encrypted by its sender. A plaintext message there (other than the
  node's own `system.*` entries) can only come from the node: clients MUST NOT show it as the author's content
  (nor its attachments, reply references or notification previews), whatever `device_id` or signature it carries.

## 5a. Voice frame keys

Voice, video and screen shares (`VOICE.md`) are encrypted per frame by the clients (WebRTC
insertable streams / LiveKit's E2EE); the node and the SFU only forward ciphertext. Every voice channel is a
conversation with its own MLS group, managed exactly like a text channel's (§4: same delivery service routes,
same authorization; the group exists before the first voice join, created by the first client that needs it).

- **Key per epoch:** `frame_key(epoch) = MLS-Exporter("tavrn voice frame v1", context = "" (empty), length = 32)`
  (`tavrn_crypto::Client::export_voice_key`, `@tavrn/crypto` `Client.exportVoiceKey`). It differs from the
  content key of the same epoch (§5.1, other label). Only the group's current epoch can be derived; a client in
  voice derives the key right after every epoch change it processes and keeps earlier keys in the key ring.
  Voice keys are never stored, backed up or sent anywhere (there is no voice history).
- **Key index:** `key_index = epoch mod 256`. LiveKit carries the key index in a one-byte frame trailer and its key
  ring holds at most 256 keys, so the ring of the last 256 epochs is addressed without collisions.
- **Handing keys to LiveKit:** the client uses one shared key for all participants (`sharedKey: true`) with a key ring
  of 256 (`keyringSize: 256`), no automatic ratcheting (`ratchetWindowSize: 0`) and no key invalidation on
  decryption failures (`failureTolerance: -1`), i.e. the settings of LiveKit's `ExternalE2EEKeyProvider` plus
  `keyringSize: 256`. The 32 key bytes are imported as raw HKDF key material (LiveKit's
  `createKeyMaterialFromBuffer`) and set with `keyIndex = epoch mod 256` (a subclass of `ExternalE2EEKeyProvider`
  or `BaseKeyProvider` calling `onSetEncryptionKey(material, undefined, keyIndex)`; the stock `setKey` only fills
  index 0). LiveKit derives the AES-GCM frame key from it with its default salt (`LKFrameEncryptionKey`) and key size
  (128 bit); all tavrn clients MUST keep these defaults, so every SDK interoperates. Setting a key with an index makes
  it the sending key; receivers pick the key by the index in each frame.
- **Screen publishers** (`VOICE.md` §4b): a device that publishes its screen from a native SDK as a second LiveKit
  participant (`<user>/<device>#screen`) encrypts it with the device's own frame key of the current epoch, at the same
  key index and with the same key provider settings. The device's client hands every epoch's 32 bytes to its native
  part over the app's local bridge (never through the node, LiveKit or a network) as soon as it derived them; the
  screen publisher is no MLS member, derives nothing and never subscribes. Nothing changes for receivers.
- **When the key changes:** every commit of the channel's group creates a new epoch and therefore a new key:
  adds and removes (a kicked or banned member is removed from the group, `mls.remove_needed`), external joins
  of new devices and self updates. A client SHOULD commit a self update when it joins voice (§4.2), so every voice
  session starts on a fresh key; the other participants switch keys as soon as they process the commit
  (`mls.commit`; the node also puts the current epoch into `voice.state` and the join response). Leaving voice
  needs no commit: the leaver stays a group member and could derive the key anyway (see "Who can listen"). Frames that arrive under an index whose key a receiver has not
  derived yet are dropped until it has; the overlap is short and needs no further coordination.
- **Who can listen:** whoever holds the frame key of an epoch, i.e. every device in the channel's MLS group at that
  epoch: the room members with read access to the channel (§4.5), not only those currently in voice. Receiving the
  media additionally needs a LiveKit token, which the node issues only to members with `connect` or a moved
  participation (`VOICE.md` §3, §7). Against the node, LiveKit and network observers the media stays confidential and authentic
  to the group; within the group, frames are not authenticated per sender (shared key, as in LiveKit's E2EE).
- **What stays visible:** who is in which voice channel and when, mute/deafen/stream/camera flags, track types,
  packet sizes and timing (from which speaking activity can be inferred). LiveKit sees the unencrypted codec
  headers it needs for routing (the first bytes of VP8 frames, the Opus TOC byte).

## 5b. Inbox keys of write-only webhooks

Webhooks post into encrypted channels without being able to read them (`APPLICATIONS.md` §6.1a). Per conversation
and epoch the members derive an X25519 key pair; a webhook message is a sealed box to its public key.

- **Derivation:** `inbox_secret(epoch) = HKDF-Expand(PRK = content_key(epoch), info = "tavrn webhook inbox v1",
  L = 32)` (HKDF-SHA256, the content key of §5.1 as the pseudorandom key), used as an X25519 secret key exactly as
  libsodium stores one (clamped when used); `inbox_public(epoch) = X25519(inbox_secret, 9)`
  (`tavrn_crypto::sealed::inbox_secret` / `inbox_public_key`, `@tavrn/crypto` `inboxPublicKey`,
  `Client.inboxKey`). Every member of the epoch derives the same pair; it differs from every other key of the epoch
  (own label) and from every other epoch's pair.
- **Why from the content key:** the content key already is the epoch's MLS exporter output, so this stays one HKDF per
  epoch, like the voice frame key, without an exporter call on the MLS path; and everything that carries content keys
  carries the inbox keys with them: the history backup (§7) and history shares for new members (§7b). Readers of a
  sealed post are exactly the readers of the epoch's messages.
- **Publishing:** after every commit it made itself (adds, removes, external join, self update, the group's creation)
  the device publishes `inbox_public` of the new epoch with `PUT /conversations/{id}/inbox-key { epoch, public_key,
  signature }`, but only in channels whose `has_webhooks` is set; `signature = Ed25519-Sign(device key,
  "tavrn webhook inbox key v1" || 0x00 || str16(qualified conversation id) || u64(epoch) || public_key)`. Clients that
  hold the group also publish the current key once when a channel gets webhooks (and on loading the room), and the
  creator of a webhook right after creating it. The node checks the signature against the attested key of the
  session's device, entitlement to the channel and `epoch ≤` the group's epoch, and keeps only the newest epoch.
- **Sealed box:** libsodium `crypto_box_seal` (ephemeral X25519 key pair; nonce = BLAKE2b-192(ephemeral public ||
  recipient public); XSalsa20-Poly1305; output `ephemeral public(32) || ciphertext || tag(16)`), so any libsodium
  binding can seal (the webhook guide of `tavrn-node` has Node.js, Python and Go snippets). The plaintext is the UTF-8 JSON
  `{ "content": { "type": "text", "body", "embeds"? }, "username"? }`. The stored message carries `encrypted = true`,
  `epoch` and `content = { "type": "webhook.sealed", "epoch", "sealed": "<base64url>", "sealed_by": "sender" |
  "node" }`; there is no device signature (the node vouches for the webhook, as for plaintext webhook messages).
- **Reading:** look up the content key of the message's epoch (current state, backup, share), derive the inbox secret,
  `crypto_box_seal_open`, then check the payload (`APPLICATIONS.md` §6.1a). An unknown epoch is `missing_key`, a box
  that does not open or a payload that is not webhook text is shown as undecryptable.
- **Test vectors:** `testvectors/encryption.json`, `webhook_inbox` (content key, inbox secret and public key,
  the signing input and a device signature, a box with a fixed ephemeral key and its payload).

**Security argument.** The inbox secret is a PRF output keyed with the content key, which only devices in the MLS group
at that epoch (and members it was shared with under the history policy) know; the node holds the public key only.
A sealed box is IND-CCA2 secure for its recipient (libsodium's construction), so the node, the webhook's service and
anyone with the URL can seal but not open. Removing a member starts a new epoch whose pair the removed member cannot
derive, so later posts are closed to it once the new key is published. Using the content key also as HKDF key next to
its use as AES-256-GCM key is a standard key-derivation use of a uniformly random 32-byte secret with a distinct label;
no output of one use is ever an input of the other.

**What it does not protect against.**

- A malicious node can serve its own public key to a sender (`GET …/inbox-key`) and open what is sealed to it. The
  sender cannot tell (members could, by comparing it with their own derivation; the reference client does not do this
  yet), and a sender may pin the key it got if its channel's membership is stable.
- In `node` mode the node sees each plaintext once, at receipt (the mode is chosen explicitly, and the UI says so).
- A member can publish a wrong key for an epoch (the node cannot check the derivation); posts sealed to it are
  unreadable until the next epoch's key is published. Any member can disrupt a channel more directly anyway.
- Right after a commit the node may still seal with, and senders may still use, the previous epoch's key until the new
  one arrives (seconds at most); such posts say their epoch and are readable by that epoch's members.
- Who posts when, the sizes, mentions of node-sealed posts and the webhook's name stay visible metadata.

## 5c. Files of encrypted files channels

End-to-end encrypted files channels (`FILES.md` §8, capability `files.e2ee`) have an MLS group like a text channel.
Every file gets its own random 32-byte key; the content and a client-made thumbnail are encrypted in 1 MiB chunks
with AES-256-GCM under keys derived from it (`FILES.md` §8.3, test vectors `file_chunks`), so uploads and downloads
stream and ranges keep working. The file key, the name and the type travel in an **entry record**, content format 1
(§5.2) with the JSON object `{ "type": "files.entry", … }` under the channel's current epoch, signed by the writing
device (`FILES.md` §8.4, test vectors `file_record`); folders have records with their name. The node stores the
ciphertext, the record and the few plaintext fields of `FILES.md` §8.2. History for new members (§7b) applies to
entry records as to messages (`FILES.md` §8.7).

## 6. Encrypted attachments

1. The client creates a random 32-byte file key and 12-byte nonce and encrypts the whole file in one shot:
   `blob = AES-256-GCM(file_key, nonce, aad = "tavrn file v1", file)`.
2. It uploads `blob` (`POST …/uploads`); the node sees only the ciphertext, its size and hash.
3. The encrypted content carries the metadata:
   ```json
   { "type": "text", "body": "…",
     "attachments": [ { "id": "01J…", "name": "photo.png", "mime": "image/png", "size": 12345,
                        "key": "<base64url>", "nonce": "<base64url>", "sha256": "<base64url of SHA-256(blob)>" } ] }
   ```
   `size` is the plaintext size. In the envelope of an encrypted message the `attachments` entries carry
   only `id`, `size` (ciphertext size) and `sha256` (of the blob); `name` is empty and `mime` is
   `application/octet-stream`. An optional `"spoiler": true` (design note 4.13, PROTOCOL.md §7b) asks readers to
   hide the attachment until clicked; any other value means false.
4. Receivers download the blob, MUST check its SHA-256 against `sha256`, then decrypt.

One-shot encryption is acceptable because uploads are limited by the node's `upload_max_bytes`; chunked
(streaming) encryption for very large files is a later format version. Thumbnails, if any, are separate
encrypted attachments.

The node's encryption at rest (design note 4.12) does not change any of this: it wraps the stored blob a second
time with a node-held per-file key and returns the uploaded ciphertext byte for byte, so `size` and `sha256`
in the envelope keep describing the blob the client uploaded. Clients never render an attachment whose
decrypted `mime` is `image/svg+xml` (or whose `name` ends in `.svg`) inline (PROTOCOL.md §7a).

## 7. History backup

The client backs up its content keys per conversation to the home node, encrypted with the backup key:

```text
blob      = 0x01 || nonce(12) || AES-256-GCM(backup_key, nonce, aad, plaintext)
aad       = "tavrn backup v1" || 0x00 || conversation id
plaintext = {"v":1,"conversation":"node.example/01J…","keys":{"41":"<base64url key>","42":"…"}}
```

`keys` maps the epoch (decimal string) to its content key; unknown fields are rejected, a different
`conversation` inside the plaintext is an error.

- `PUT /api/v1/users/me/backups/{domain}/{conversation_ulid}` (body: the blob,
  `application/octet-stream`, at most 1 MiB) with `If-Match` on the previous `ETag` (`412
  backup.etag_mismatch` on mismatch; the first upload is sent without `If-Match`, and `If-Match` on a backup
  that does not exist is a mismatch as well). The node checks only the version byte and minimum length and
  keeps at most 1000 backups per account;
  `GET` of the same path returns the blob with its `ETag`; `GET /api/v1/users/me/backups` lists
  `{ conversation, size, updated_at }`. Only the owner can read or write them.
- Clients upload after new epoch keys arrive (debounced). Before uploading they download the current blob,
  merge it (keys are never overwritten) and upload with `If-Match`, so that several devices do not lose
  each other's keys.
- A new device with the master secret (§2.4, §8) downloads all backups and can read the whole history of every
  conversation, as far as some device of the user had the keys.

**Trust record.** The client keeps the pinned identity keys of other users (§3.3), the verified contacts
(`FEDERATION.md` §10.2) and the account's own devices it attested (device id → device key, §4.7) as one more backup,
so that they survive a sign-out and reach every device of the account:

```text
blob      = 0x01 || nonce(12) || AES-256-GCM(backup_key, nonce, aad, plaintext)
aad       = "tavrn trust v1" || 0x00 || account address
plaintext = {"v":1,"pins":{"<address>":{"key":"<base64url identity key>","changed":true?,"rotated":true?}},
             "verified":{"<address>":{…verified contact…}},"devices":{"<device id>":"<base64url device key>"}}
```

It is stored with the backup routes under the home node's domain and the conversation ULID
`00000000000000000000000000` (time 0, never a conversation), merged like the other backups (entries are added, an
entry a device holds is never replaced by the stored one; `If-Match`). A new device restores it before the
conversation backups and before it pins any key on first use; a restore whose trust record could not be fetched is
tried again. A pin this device took on first use before that first sync that differs from the stored one is a
changed key (§3.3) unless the user's
continuity chain (§9a) leads from the stored key to it (a rotation; the other direction means the stored pin is newer
and is taken). The node can neither read nor forge the record; serving an older blob or none only loses entries,
which then pin on first use again. An identity reset deletes it with the backups.

## 7a. Whiteboard scenes

The personal whiteboard scene library (`WHITEBOARD.md` §2.3, §5) uses the backup key like §7, with its own AAD
that binds every blob to its scene and its role:

```text
blob = 0x01 || nonce(12) || AES-256-GCM(backup_key, nonce, aad, plaintext)
aad  = "tavrn whiteboard v1" || 0x00 || scene id || 0x00 || part        # part = "scene" | "thumbnail"
```

The scene id is the client-chosen ULID of the scene (uppercase); the scene plaintext is the JSON scene, the
thumbnail plaintext a small image. The node checks only the version byte and the sizes. An identity reset (§9)
deletes the scenes with the backups. Ephemeral whiteboard events themselves are content-encrypted like messages
(§5, with the inner `type` equal to the event type).

## 7b. History for new members

Per-epoch content keys (§5.1) let members hand older keys to a member who joined later: existing members encrypt
the keys of past epochs to the new member's devices, the approach to "room keys for past messages" known from
other messaging protocols. The node stays zero-knowledge: it only stores and routes encrypted shares and enforces
who may send what to whom.

**Policy.** Room channels carry `history_for_new_members` (PROTOCOL.md §6, "History for new members"):

| Value | New members get |
|---|---|
| `since_join` (default) | nothing from before their join (every message since, see below) |
| `days:<n>`, 1 ≤ n ≤ 3650 | the messages of the `n` days before their join |
| `all` | the whole history |

Members additionally need permission bit 34 `read_history` (default for `@everyone`, `permissions.md`); without it
the history starts at their join whatever the policy says. Two layers apply the rule:

1. **Node.** `GET …/messages` serves encrypted messages older than the member's window start only as the policy
   and the bit allow (window start = the room membership's `joined_at`, minus `n` days for `days:<n>`, none for
   `all`; a re-join starts a new window). Owners and administrators follow the same rule: it is about keys, not
   trust. Plaintext messages are never cut. DMs are not cut (both participants are members from the start);
   group DM members always start at their own join (`since_join`, no shares). The same window applies wherever the
   node serves or acts on a single encrypted message: a message outside it is `404 message.not_found` for reactions,
   reactors, pins and unpins, and `GET …/pins` lists only pinned messages inside it.
2. **Clients.** A sharing client applies the same window before it sends keys, and a recipient can only check a
   key against messages its node serves it (below), so a key outside the window is never accepted.

The window is about the room membership, not about devices: a member's device enters a channel's MLS group only when
it first opens the channel (or when its client joins the groups of a room proactively, below), and the epochs between
the room join and that first leaf are part of the member's history under every policy, `since_join` included. Their
keys reach the device only through a share, so the node marks such members pending and members share those epochs
like older ones. Clients keep that gap small: when a room is loaded they join the groups of its encrypted channels
that the user may view (text, announcement, forum and files channels; one after the other, never creating a group),
not only when a channel is opened.

A hostile member can always copy history it can read; E2EE never protects against members.

**Pending members.** After accepting a commit in which a user gets their first leaf in the group (external join
of a user without a leaf, or Adds), the node marks the membership `history_pending` for that conversation when
the channel is encrypted, the user has `view_channel` and `read_history`, and there are encrypted messages inside the
user's window from before this commit: from before the room join as far as the policy reaches, and those posted
between the room join and the device's first leaf (under `since_join` only the latter). It emits `history.pending
{ conversation_id, user, since }` to the room (`since` = the membership's `joined_at`). A membership is marked at
most once (another device of the same member joining does not mark it again); the mark is cleared when the
member acknowledges a share and expires after 30 days.

- `GET /api/v1/conversations/{id}/history-pending` → `{ items: [ { user, since, key_reset_at, min_epoch } ] }` (members
  only; at most 100, marks of the current memberships of the last 30 days; empty for DMs and plaintext channels;
  `key_reset_at` and `min_epoch` are null except after a key reset, "History after a key reset" below).

**Shares.** Routes on the node hosting the conversation (members of other nodes use their federated session
there, as for every conversation route):

- `POST /api/v1/conversations/{id}/history-keys` `{ to_user, epoch_from, epoch_to, ciphertext, v?, boxes? }` →
  `201 { id }`.
  The sender must be entitled (§4.5) with an attested device (`403 e2ee.device_not_attested`). The conversation
  must be an encrypted room channel (`400 history.not_encrypted`; DMs and group DMs `403 history.forbidden`), whatever
  its policy: under `since_join` the recipient's window starts at its join, the node serves it nothing older and its
  client accepts no key it cannot check against a served message (Receiving step 4). `to_user` is an address of
  another member with
  `view_channel` and `read_history` (`403 history.forbidden`; oneself `400 history.self`). `0 ≤ epoch_from ≤
  epoch_to ≤` the group's epoch and at most 1000 epochs (`400 history.invalid`); `ciphertext` is content format 1
  (§5.2) under a known epoch (`400 history.invalid`), at most 64 KiB measured on the base64url string
  (`413 history.too_large`). `v` is the share
  format, 1 (default) or 2 ("Format v2" below, capability `history.shares2`); a format 2 share carries `boxes`, an
  object of device id → base64url sealed key, 1 to 20 entries, each box at most 128 bytes, every device id an
  attested device of `to_user` (under its current identity key) with a share key (§3.1); a format 1 share carries no
  `boxes`; anything else is `400 history.invalid`. At most 20 shares per recipient and conversation within 24 hours,
  acknowledged ones included (`429`). The recipient's connections get `history.keys_available { conversation_id }`.
- `GET /api/v1/conversations/{id}/history-keys` → `{ items: [ { id, from_user, from_device, epoch_from, epoch_to,
  ciphertext, created_at, v, box } ] }`: the unacknowledged shares addressed to the requester (oldest first, at most
  100); nobody else sees them. Format 1 shares are served to every device of the recipient with `box: null`; a format
  2 share only to the devices it has a box for, each with **its own** box and never the others'.
- `DELETE /api/v1/conversations/{id}/history-keys/{share_id}` → `204`: the recipient acknowledges a share (one
  acknowledgement per user, from any of its devices; `404 history.share_not_found` otherwise); the node drops its
  ciphertext and boxes and clears the member's pending mark. Housekeeping deletes acknowledged shares after a day and
  every share (with its boxes) after 30 days.

**Payload.** The plaintext is the RFC 8785 (JCS) form of

```json
{ "type": "history_keys", "v": 1, "conversation": "node.example/01J…", "to": "bob@other.example",
  "epochs": [ [41, "<base64url content key>"], [42, "…"] ] }
```

encrypted and signed exactly like message content (§5.2) under the group's **current** epoch by the sharing
device (`author` = `from_user`, `device_id` = `from_device`): only current members can read it, and the device
signature covers the canonical JSON. It is never sent as a message and never stored as one. Format 1 is
**removed**: clients MUST NOT send it (any leaf of the group could read it, an unattested one included) and only
still read format 1 shares that older clients left on a node.

**Format v2 (capability `history.shares2`).** The payload is the same object with `"v": 2`. The sharing device
encrypts and signs it exactly like content format 1 (§5.2: same AAD, bound to the conversation, the device signature
inside), but under a **fresh random 32-byte share key** instead of the epoch's content key; the header epoch is the
group's current epoch, so the node applies its usual checks (it cannot tell the two formats apart by the ciphertext).
It then seals the share key with libsodium `crypto_box_seal` (§5b) to the share key (§3.1) of every device of the
recipient that is in the current MLS roster and has a verified share key: `boxes = { "<device id>": base64url(
crypto_box_seal(share key, share_public)) }` (80 bytes each), and zeroes the share key. Test vector:
`history_share_v2` (payload, share key, ciphertext, a recipient device's share key pair and a box with a fixed
ephemeral key; `Client.encryptShare`, `sealShareKey`, `Client.openShareBox`, `decryptContentWithKey`).

**Sharing (client).**

0. Format: a client sends format 2 only, when the node announces `history.shares2` **and** every device of the
   recipient in the current roster has a share key whose signature verifies with its attested device key (§3.1,
   §3.3); otherwise it sends nothing (the member stays pending). The same rule holds for restore shares ("History
   after a key reset" below).

1. The device that committed a member's Add shares right away. Otherwise, on `history.pending` and when a member
   opens the channel, clients read `…/history-pending`; per waiting member every candidate device (devices in the
   current roster whose user is online, the own one included, the recipient's excluded) computes its rank in the
   sorted list of device identities. Rank 0 shares at once; rank `k` waits `k × 60 s` and shares only if the member
   is still pending. Nothing is shared before a device of the recipient is in the group.
2. Epochs: `all` → every epoch the device holds older than the current one; `days:<n>` → from the oldest epoch of the
   encrypted messages after `joined_at − n days` (`GET …/messages?after=<ULID floor>&limit=20&threads=all`: thread
   messages, such as forum posts, are content of the channel too); `since_join` → the same from `joined_at` (the
   epochs of the messages posted since the member's join), and none when there are no such messages. Chunks of at most
   500 epochs and a range of at most 1000 epochs; with nothing to send the device posts one empty share (`epochs: []`,
   `epoch_from = epoch_to =` current epoch), which still clears the pending mark. The `since` of the pending mark
   comes from the node: a client never lets the window of an automatic share start more than 30 days (the lifetime of
   a pending mark) before it first saw the member waiting with a leaf in the group, whatever `since` the node reports.

**Receiving (client).** On `history.keys_available` and when opening the channel, the recipient fetches its
shares and for each:

1. rejects it unless `from_user/from_device` is a leaf of the current roster;
2. decrypts and verifies it like message content (§5.2; the device key from the verified attestation, §3.3); a
   share it cannot decrypt yet (missing epoch) is retried later, any other failure rejects it. A format 2 share
   (`v: 2`) is accepted only when its `box` opens with the device's own share secret to a 32-byte key; that key takes
   the place of the epoch's content key here (nothing is missing then), and it is zeroed after use;
3. rejects it unless the payload has exactly the fields above, `type`, `v` (equal to the share's `v`),
   `conversation` and `to` match, and every epoch is an integer within `[epoch_from, epoch_to]`, listed once, with a
   32-byte key;
4. **checks every key it does not hold yet** against a stored message of that epoch (`GET …/messages?epoch=n`,
   preferring a message whose author is not the sharer): the key must open the message's AES-256-GCM ciphertext
   (same AAD, nonce and tag, §5.2) **and** the decrypted content's signature must verify with the key of its author
   device (attested, or retired for its time, §5.2): a tag alone proves nothing, whoever knows a key can make one.
   A message whose author device the recipient cannot verify at all (neither attested nor retired, such as its own
   device from before an identity reset, §2.3) tells nothing and is passed over for the next message of the epoch, the
   sharer's own last. Keys that fail, or whose epoch has no such message in the recipient's window, are dropped (a
   poisoned key never reaches the store);
5. stores the accepted keys only in the key store, exactly like its own epoch keys (`Client.importEpochKey`; never
   overwriting a known key), which also puts them into the history backup (§7);
6. acknowledges the share.

Rejected shares are not acknowledged (they expire); clients log only that a share or key was rejected, never ids,
payloads or keys. Keys never appear in message objects, the decrypted-message cache, query caches, logs or the UI.
While its own pending mark is set, a member's client shows "Older messages are being unlocked…" at the top of the
channel; afterwards the history loads lazily as before.

Earlier nodes marked nobody pending under `since_join` and refused shares there (`403 history.forbidden`): their
`…/history-pending` is empty in such channels, so current clients send nothing and nothing changes for them.

**Security notes.**

- Forward secrecy towards new members is given up exactly to the extent of the policy; the principle "key lost =
  old messages gone" (design note 5.3) is untouched, it concerns the user's own keys.
- The node learns that a share happened (who to whom, the epoch range, its size), not its content. It cannot
  forge a share (device signature), redirect one (`to` and `conversation` are inside the signed payload and the
  ciphertext is bound to the conversation by the AAD) or plant keys (the per-key check against stored, signed
  messages).
- **Who can read a share.** A format 2 share is readable only by the recipient devices it carries a box for: the share
  key is fresh and sealed to their share keys, whose signatures by the attested device keys the sharer verified, so
  neither the node nor other members (who know the epoch's content key) can open it, and the node cannot add a
  device of its own (it would need a device attested by the recipient's identity key and a share key signed by that
  device). A format 1 share was encrypted under the group's current epoch, so every device in the group at that epoch
  could decrypt it, including a leaf the node planted; that is why format 1 is no longer sent.
- A replayed share only repeats keys the recipient already validated or holds; keys are never overwritten.
- A member could post a message under a forged key and then "prove" that key with it; the recipient therefore
  prefers messages of other authors for the check. The residual risk equals what any member can do anyway (show
  fake content), and only in epochs where the forger is the sole author.
- A hostile client sharing without permission is stopped by the node (recipient without `read_history`,
  non-members); size and rate limits bound abuse. Under `since_join` it could hand a member keys of epochs from
  before the join: the node never serves the member those messages and the member's client drops every key it cannot
  check against a served message. An epoch that spans the join opens messages from both sides of it, but the node
  serves only those inside the window.
- Narrowing the policy does not revoke keys already shared (clients say so in the setting); the change is in
  the audit log.

**History after a key reset (capability `history.restore`).** An identity reset (§9) gives the user new keys but
keeps the memberships, so the window above would let the other members' clients share the old epoch keys
automatically, and whoever took over the account (a password reset, a SIM swap) would read the whole history. Nodes
that announce `history.restore` (together with `e2ee.mls1`) therefore restore history after a reset only by an
explicit, logged decision of a member with permission bit 37 `restore_history` (`permissions.md`):

1. **Reset window.** When a member's identity key changes without a continuity statement (a reset, §9, or any change
   that is not a rotation, §9a: exactly when the node writes `system.key_changed { rotated: false }`, PROTOCOL.md §7)
   the node sets `key_reset_at = now` on every room membership of the user that it hosts (again at every further
   reset) and drops an earlier restore of that membership. Room nodes do the same for members of other nodes when they
   learn the new key (`identity.changed`, or a refetch of the keys document, FEDERATION.md §5.2), so the node hosting
   the conversation, which enforces every rule below, knows the reset of every member. A rotation (§9a) keeps the
   master secret and the old history and sets nothing. A new membership (a re-join) starts without `key_reset_at`.
   For a membership with `key_reset_at`:
   - The member's history window (`GET …/messages`, and the records of files channels, `FILES.md` §8.7) additionally
     starts at `key_reset_at`, until a restore of the membership is approved; from then on the normal window applies
     again.
   - The **reset epoch** of a conversation is the epoch its group had at the reset; the node records it per encrypted
     room channel of the membership at that moment (no group yet: nothing before the reset). Epochs up to and
     including it are the **pre-reset range**, whatever the channel's kind (messages, the entry records of files
     channels, `FILES.md` §8.7); the automatic window of the member starts after it, never earlier, whatever the
     policy.
   - Pending marks: when a device of the user joins the group after the reset (`view_channel` and `read_history` as
     above, whatever the policy) and there are encrypted messages since `key_reset_at`, the node marks the member
     pending once per reset, also if the user still had (now unattested) leaves in the group. `history.pending` and
     the items of `…/history-pending` then carry `since = key_reset_at`, `key_reset_at` and `min_epoch` (reset epoch
     + 1, null without a pre-reset range); for other members `key_reset_at` and `min_epoch` are null.
   - A share to the member whose `epoch_from` is at most the reset epoch is a **restore share**. The node accepts it
     only from a member who holds `restore_history` in the channel while the membership has a restore approved within
     the last 30 days (below); otherwise `403 history.forbidden`. Restore shares are accepted under `since_join` too and
     need the recipient's `view_channel` only: its message window (the normal window again after the approval) limits
     which keys its client accepts. Everything else about shares (attested device, sizes, rate limit) applies as above.
2. **Request.** The room setting `history_restore` is `request` (default) or `off` (`PATCH /rooms/{room_id}`,
   `manage_room`, never a bot; `400 validation.enum`; audited in `room.update` with `meta.history_restore`). Routes on the
   room's node (members of other nodes use their federated session there):
   - `POST /api/v1/rooms/{room_id}/history-requests` `{ message? }` → `201 HistoryRequest`: a member asks for its history
     from before the reset; `message` at most 500 characters. The membership needs `key_reset_at` without an approved
     restore (`409 history.nothing_to_restore`), the room `history_restore = request` (`403 history.restore_disabled`), no
     open request of the member in the room (`409 history.request_open`); bots cannot ask (`403 history.forbidden`); at
     most 5 requests per member and room within 24 hours (`429`). Audit `history.restore_requested` (target the member);
     event `history.request { room_id, request }` to the owner and the members whose roles hold `restore_history` or
     `administrator`.
   - `GET /api/v1/rooms/{room_id}/history-requests/mine` → `{ key_reset_at, restored_at, request }`: the requester's own
     state (`request` = its latest request of the current membership or null; the times null when not set).
   - `DELETE /api/v1/rooms/{room_id}/history-requests/{request_id}` → `204`: the requester cancels its open request
     (`404 history.request_not_found` otherwise). Open requests are cancelled as well when the membership ends.
   - `GET /api/v1/rooms/{room_id}/history-requests` → `{ items: [HistoryRequest] }`: the open requests (oldest first, at
     most 100); `restore_history` required (`403 history.forbidden`).

   `HistoryRequest` = `{ id, room_id, user, display_name, message, status, joined_at, key_reset_at, created_at,
   decided_at, decided_by, reason, partial, channels }`: `status` is `open`, `approved`, `denied` or `cancelled`;
   `decided_by` an address; `channels` (filled for members with `restore_history`, else empty) lists every encrypted
   channel of the room the requester may view, whatever its kind (text, announcement, forum, files; voice channels
   store no content and are left out), as `{ channel_id, kind, window_start, reset_epoch }`: `window_start` is the
   requester's normal window start in that channel (the policy and `read_history` from `joined_at`; null =
   everything), `reset_epoch` the recorded reset epoch (null: nothing before the reset).
3. **Decision.** `restore_history` is never granted to `@everyone`, no app-token scope covers it, and the owner and
   `administrator` hold it as always.
   - `POST /api/v1/rooms/{room_id}/history-requests/{request_id}/approve` `{ partial? }` → `200 HistoryRequest`. The request
     must be open (`409 history.request_decided`; unknown `404 history.request_not_found`), its member still a member
     with `key_reset_at` (`409 history.nothing_to_restore`), the setting `request` (`403 history.restore_disabled`), and
     nobody approves their own request (`403 history.forbidden`): a taken-over account of a moderator must not unlock
     itself. The node records the restore on the membership (`restored_at`; the cut is lifted and restore shares are
     accepted for 30 days), writes the audit entry `history.restore_approved` (`meta { user, by }`) and
     `system.history_restored { user, by }` into the welcome channel and sends `history.request_decided { room_id,
     request }` to the requester and to the members who got `history.request`. `partial: true` tells the requester that
     the approving device does not hold every key of the window.
   - `POST /api/v1/rooms/{room_id}/history-requests/{request_id}/deny` `{ reason }` → `200 HistoryRequest`: `reason` 1–500
     characters (`400 validation.length`); the same checks except the setting; audit `history.restore_denied` (`meta
     { user, by, reason }`), `system.history_restore_denied { user, by }` (the reason stays in the audit log and in the
     request, which the requester sees) and `history.request_decided`.

   **Approval is the key share itself.** Right after approving, the approver's client sends restore shares (format 2
   under the rule of "Sharing" step 0) from its device for every encrypted channel of `channels` that it can read and in which a device of the requester is in the
   group: every epoch it holds from the oldest epoch of the channel's encrypted content after `window_start` (messages:
   `GET …/messages?after=<ULID floor>&limit=20&threads=all`; files channels: `GET …/records?since=<window start>&limit=1`, `FILES.md`
   §8.7; everything for null) up to the epoch before the current one, chunked as in "Sharing" step 2. Before approving it shows the request, the requester, its join date, the channels and epoch ranges
   that will be shared and whether its device holds all of them (`partial`), and recommends verifying the person's
   identity on another channel (a call, in person): an approval gives whoever controls the account now everything the
   member could read before. Other members with `restore_history` may fill gaps while the restore is valid.
4. **Clients.** A sharing client applies the reset window itself, also with nodes that do not announce
   `history.restore`: a recipient whose keys document (§2.3) shows an `identity_reset_at` later than the pending item's
   `since` is treated as if `key_reset_at` were that time, and without `min_epoch` the client shares nothing up to the
   epoch of the newest encrypted content before the reset (`GET …/messages?before=<ULID floor>&limit=1&threads=all`; nothing at
   all when it cannot tell). Such a member
   gets automatic shares only from the reset on. The requester's client shows its state (`…/mine`) with the request form
   in a room whose encrypted history it lost (in the channel view and in the file browser of files channels),
   receives the restore shares like any other share (also under `since_join`), and afterwards says which messages or
   entries stayed locked (`partial`, or keys that did not arrive).

Compatibility: nodes without `history.restore` keep the behaviour above, where clients that implement rule 4 still
share nothing from before a reset; clients without it send pre-reset shares that nodes with `history.restore` refuse.

## 8. New device

1. Sign in (password and second factor, or passkey-only; PROTOCOL.md §5a). The node creates the device id, or the
   session continues a device the client proves to hold (§3.4).
2. Get the master secret: from the secret storage (§2.4, recovery key or PRF passkey) or from a key file.
   Generate the device key, attest the device (§3.1) and upload the key and KeyPackages.
3. Download the backups (§7), then join every conversation from the conversation index by external commit.

A device without the master secret cannot be attested, cannot join encrypted conversations and shows
the user how to unlock with the recovery key or a passkey.

## 9. Identity reset

When the master secret is lost (no trusted device, no recovery key, no PRF passkey):

1. The user signs in (password and second factor) and confirms the reset (re-entering the password).
2. The client creates a new master secret and a new recovery key (§2.4) and calls
   `POST /api/v1/users/me/identity/reset` `{ "identity_public_key", "password" }`. Accounts without a
   password (SSO accounts, `APPLICATIONS.md` §8.4) confirm with a fresh SSO login instead: the client runs
   the SSO flow with `purpose: "reauth"` and sends `{ "identity_public_key", "reauth_token" }` (5 minutes,
   single use, bound to the account; the provider must confirm the identity linked to it). The node accepts any
   valid reauth token of the session here (PROTOCOL.md §5c: from a login of the last five minutes, a password, a
   passkey or an SSO confirmation; in the body or the `Tavrn-Reauth` header), not only the two confirmations
   above.
3. The node sets the new identity key and `identity_reset_at = now`, deletes all device attestations,
   KeyPackages, backups, whiteboard scenes (§7a) and secret storage entries of the user and notifies the user's contacts
   (`identity.changed`) and sets `key_reset_at` on the user's room memberships (in the same transaction as the key
   change, so a reset never takes effect without it), which stops the
   automatic history sharing of §7b for everything before the reset ("History after a key reset"). The client uploads the new `recovery` entry (and passkey entries) afterwards.
4. Each device of the user re-attests its **existing** device key under the new identity key (devices keep
   their keys; a device that is not re-attested is invalid), uploads new KeyPackages and rejoins all
   groups by external commit, which replaces its old leaf.

After the reset the node MUST reject commits, KeyPackages and encrypted messages from devices without a
valid attestation under the current identity key (`403 e2ee.device_not_attested`) and MUST reject commits
that add such devices. Leaves of non-attested devices are removed by housekeeping commits (§4.5 rule 4).
Contacts see "security key changed". Old backups are gone and old history stays unreadable unless a member with
`restore_history` restores it on request (§7b); everything else works immediately.

**Bots** (`APPLICATIONS.md` §3.4) cannot reset themselves (the route needs a password). Their owner calls
`POST /api/v1/applications/{id}/identity/reset` (full session): the node clears the bot's identity key, sets
`identity_reset_at`, deletes its device attestations, KeyPackages and backups, emits `identity.changed` locally,
`mls.remove_needed` for its leaves and `devices.changed` to other nodes. The new key is not part of the call: the
bot process sets it with `PUT /users/me/identity` on its next start, and the node then announces it with
`identity.changed` (locally and S2S).

## 9a. Rotation with continuity

For "my key may be exposed, but I still hold it": the account gets a new signing identity while everything else
stays (master secret, recovery key, backup key, epoch keys, device keys, MLS state; old history stays readable).

1. On a device holding the master secret and the current identity key, the user confirms (re-authentication,
   PROTOCOL.md §5c). The client fetches its own keys document; every listed device must verify under the current
   key, otherwise the document and the local state disagree and the client stops with an error.
2. The client generates a random Ed25519 key `new_sk` and signs the **continuity statement**
   ```text
   statement = { "old_key": base64url(old_pk), "new_key": base64url(new_pk), "at": "<RFC 3339 now>" }
   message   = "tavrn identity continuity v1" || JCS(statement)          # RFC 8785
   sig_old   = Ed25519-Sign(old_sk, message);  sig_new = Ed25519-Sign(new_sk, message)
   ```
   wraps the new key for the home node
   ```text
   identity_blob = 0x01 || nonce(12) || AES-256-GCM(identity_wrap_key, nonce, aad = UTF-8(user address), new seed(32))
   ```
   and attests every active device's existing key with `new_sk` (§3.1).
3. `POST /api/v1/users/me/identity/rotate` (full session, `Tavrn-Reauth`; local users, not bots) with
   `{ new_identity_public_key, continuity: { old_key, new_key, at, sig_old, sig_new }, identity_blob,
   attestations: [{ device_id, identity_signature }] }`. The node checks both signatures (strict Ed25519),
   `old_key` = the current key, `new_key` = the new key (`400 e2ee.continuity_invalid`), `at` within ±5 minutes
   (`400 e2ee.continuity_stale`), the blob (61 bytes, version 1, `400 e2ee.identity_blob_invalid`) and that every
   active device has a valid attestation under the new key and no other device is listed
   (`400 e2ee.rotation_incomplete`). At most one rotation per user and hour (`429`); bots are refused (`403`, the
   owner resets them, §9); a key that changed meanwhile is `409 e2ee.identity_changed`. Then, atomically: the new
   key, the new attestations (retired devices keep theirs), the statement appended to the chain (generation n) and
   the blob. The node answers `{ identity_public_key, identity_generation }`, sends `identity.rotated` to the user
   and the contacts (PROTOCOL.md §6), writes `system.key_changed { rotated: true }` into the welcome channels of the
   user's rooms and sends `devices.changed` to the other nodes (FEDERATION.md §5.2), which refetch the keys document,
   find the chain and write their own entries.
4. `GET /api/v1/users/me/identity/blob` (own session) → `{ identity_blob, identity_generation, identity_public_key }`;
   `404 e2ee.identity_blob_not_found` at generation 0. The user's other devices pick the rotation up on their next
   start or on `identity.rotated`: derive, check the chain from the derived key to the published key, unwrap the
   blob, check its public key, and continue with their device key and MLS state. A new device unlocks the same way
   (§2.4 client rules).

An identity reset (§9) deletes the chain and the blob: the new master secret's derived key is generation 0 again.

**What it protects against.** Contacts follow a voluntary key change without the "security key changed" warning,
and the old key stops attesting devices: a device attested later under the old key is not accepted, and a
copy of the old key alone no longer signs anything clients accept as current.

**What it does not protect against.** A thief who holds the old identity key can sign a continuity statement to a
key of their own just as well (they cannot use the route without the account's session and re-authentication, but a
hostile home node can publish such a chain). Therefore verified contacts drop to "verification needs a refresh"
after every rotation, and a user who believes the old key is compromised uses the reset (§9), which warns everyone.
The rotation never protects history the old key's thief could already read: that needs the master secret, which a
rotation keeps.

## 10. Versions and capabilities

- `e2ee.mls1` (PROTOCOL.md §3) means this document: ciphersuite `0x0001`, content format 1.
- `history.shares2`: the node accepts and serves history shares of format 2 (§7b) and device share keys (§3.1).
- `history.restore`: after a key reset the node lets history from before the reset be shared only by request and
  approval (§7b "History after a key reset", permission bit 37 `restore_history`).
- `files.e2ee`: files channels may be end-to-end encrypted (§5c, `FILES.md` §8).
- Version bytes: key file `0x01`, recovery key `0x02`, wrapped master secret `0x01`, identity blob `0x01`,
  content `0x01`, backup `0x01`. Unknown versions MUST be rejected; new versions are introduced together with a new
  capability or envelope `format`.
- A different ciphersuite or exporter label requires a new capability (`e2ee.mls2`).

## 11. Threat model

Consistent with design note 5.4:

- **Passive or curious operator**: reads no content, attachment contents, file names, backups or the
  wrapped master secret (the wrapping keys are 256-bit secrets it never sees; there is no
  password-derived key to brute-force).
- **Actively malicious operator** cannot create commits itself (it is not a member), but it can serve a fake
  identity key for users of its own node and so introduce a "ghost" device of such a user. This is visible:
  the device appears in the MLS roster and the member list, and known contacts see a changed security
  key (§3.3, §4.6). It can drop, delay or withhold messages and commits (denial of service), replay a message
  within the same conversation (detected, §5.2) and see the metadata listed in §5.4.
- **Malicious member**: reads what members read; cannot forge other devices' messages; can disturb the group
  (for example with a commit whose MLS membership tag is invalid, which the node cannot check). Clients
  detect failed processing and rejoin by external commit.
- **Forced rejoin**: together with the node, a malicious member can make the other devices rejoin (a broken commit,
  §4.3) and serve them a GroupInfo of its own making. The rejoined group is still checked like every group: the ghost
  check (§4.6) verifies every leaf against the node's member list and the pinned identity keys (TOFU, §3.3, with
  `key_changed` leaves held back until acknowledged), so a device of a non-member or under an unknown key is shown,
  not trusted. The new epochs' keys are fresh, so the rejoin exposes no history; what remains is denial of service
  and what any member can do anyway.
- **The web client is code served by a node.** A malicious node can serve a modified web client and read
  everything that client decrypts. This is the inherent limit of browser-based E2EE; the native apps
  and reproducible builds mitigate it.
- **Endpoints**: a compromised device reads what its user reads. Losing every way to the master secret
  (trusted devices, recovery key, PRF passkeys) leads to the reset (§9); history is lost, nothing else.
- **Account takeover**: the secret storage is served only to full sessions (password and second
  factor). An attacker with a full session still needs the recovery key or the user's authenticator to
  unwrap it.

## 12. Reference implementation

`tavrn-crypto` (its `README.md`) maps this document to code:

| Section | Rust (`tavrn_crypto`) | JavaScript (`@tavrn/crypto`) |
|---|---|---|
| §2 | `MasterSecret::{generate, to_key_file, from_key_file, identity_public_key, backup_key, local_storage_key}` | `MasterSecret` (`localStorageKey`) |
| §2.4 | `RecoveryKey::{generate, to_words, to_compact, to_text, from_text, wrapping_key}`, `secret_storage::{wrap_master_secret, unwrap_master_secret, passkey_wrapping_key, passkey_method, PRF_INPUT}` | `RecoveryKey`, `wrapMasterSecret`, `unwrapMasterSecret`, `passkeyWrappingKey`, `passkeyMethod`, `secretStoragePrfInput` |
| §3 | `Device`, `attest_device`, `verify_device_attestation`, `ds::inspect_key_package` | `Client.create`, `MasterSecret.attestDevice`, `verifyDeviceAttestation` |
| §3.1 share key | `Device::{share_secret, share_public_key, share_key_signature}`, `share::{share_secret, share_key_signing_input, verify_share_key}` | `Client.shareKey`, `verifyDeviceShareKey`, `deviceShareSecretKey`, `sharePublicKey` |
| §9a | `IdentityKey::{generate, from_master, from_seed, attest_device}`, `wrap_identity_key`, `unwrap_identity_key`, `sign_continuity`, `verify_continuity`, `continuity_reaches` | `IdentityKey`, `wrapIdentityKey`, `unwrapIdentityKey`, `signContinuity`, `verifyContinuity`, `continuityReaches`; flows in `@tavrn/e2ee` (`identity.ts`, repository `tavrn-js`) |
| §4 | `Client::{create_group, add_members, remove_members, self_update, join_by_external_commit, join_by_welcome, merge_pending_commit, discard_pending_commit, process_handshake, roster}`, `ds::DsGroup` | `Client` |
| §5 | `Client::{encrypt_content, decrypt_content}`, `content_header` | `Client.encryptContent`, `decryptContent`, `contentEpoch` |
| §6 | `encrypt_file`, `decrypt_file` | `encryptFile`, `decryptFile` |
| §5c | (not in the crypto core: WebCrypto in `@tavrn/e2ee`, `files.ts`) | `encryptFileStream`, `decryptFileChunks`, `encryptFileRecord`, `decryptFileRecord` (`@tavrn/e2ee`) |
| §5a | `Client::export_voice_key`, `content::VOICE_EXPORTER_LABEL` | `Client.exportVoiceKey` |
| §7 | `Client::{export_backup, import_backup, export_epoch_key, import_epoch_key}` | same, camelCase |
| §7b | `Client::{known_epochs, export_epoch_key, import_epoch_key, encrypt_content, decrypt_content, encrypt_share, open_share_box}`, `share::{seal_share_key, open_share_box, decrypt_content_with_key}` | same, camelCase, plus `sealShareKey`, `decryptContentWithKey`; flows in `@tavrn/e2ee` (`HistorySync`, `history.ts`) |
