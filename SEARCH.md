# tavrn message search (`search.v1`, draft v1)

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`).
Normative for nodes; the client part (§3) describes the reference implementation (`@tavrn/e2ee`, `tavrn-web`) and the
guarantees other clients must keep. Routes and error codes: `PROTOCOL.md` §7d. Background: design note 4.4.

## 1. What is searched where

| Content | Searched by | Index |
|---|---|---|
| Plaintext messages of **unencrypted** room channels (text, `/me` actions, webhook embeds, attachment file names) | the node hosting the room | the node's full-text index (§2) |
| Messages of **encrypted** channels, DMs and group DMs (text and attachment file names after decryption) | each client on its own device | the local encrypted index (§3) |
| Entries of **encrypted files channels** (name, folder path, type; `FILES.md` §8) | each client on its own device | the local encrypted index (§3.6) |
| Entries of unencrypted files channels | the node, per channel (`FILES.md` §3, `GET …/files?q=`) | the node's database |
| File contents, images, voice, whiteboards | nobody | – |

The node never searches encrypted content and never sees a query of the local index. DMs and group DMs are always
end-to-end encrypted, so there is no node search for conversations outside rooms. One search box in the client
runs both paths and merges the results newest first (§4).

## 2. Node search

### 2.1 Index

One row per searchable message in `message_search` (`message_id`, `conversation_id`, `author_id`, `terms`). `terms`
is computed by the node: the words of the searchable text (maximal runs of letters and digits after Unicode NFKC and
lowercasing, at most 64 characters each, at most 8000 characters of text per message) plus a diacritic-folded variant
of every word (`müller` → `muller`, `ß` → `ss`). PostgreSQL searches it through a generated column
`to_tsvector('simple', terms)` with a GIN index (no extension needed, nothing language-specific); SQLite (development
nodes) through an FTS5 external-content table with `unicode61 remove_diacritics 0`. Both are created at startup.

Rows are written when a message is sent, edited (replaced) or posted by a webhook, and only when the message is
plaintext (`encrypted = false`), its conversation is an unencrypted room channel and the content type is `text` or
`action` (system messages are never indexed). A message's row goes with the message (`ON DELETE CASCADE`: deletes,
moderation purges, retention, channel and room deletion). Switching a channel to encrypted deletes all its rows;
switching it back indexes its plaintext messages again (in the background). At startup the node indexes plaintext
channel messages it has not indexed yet (resumable; nodes that had messages before the search existed or ran with
`TAVRN_SEARCH_ENABLED=false`).

### 2.2 Queries

- The query is split into words exactly like `terms`; every word becomes a quoted prefix term (`'word':*` joined
  with `&` for PostgreSQL, `"word"*` for FTS5) bound as a parameter. Quotes, parentheses, `*`, `OR`, `NEAR`, `:`, `&`,
  `|`, `!` and `-` are never interpreted: they separate words or are words. All words are required.
- Scope: the room's unencrypted text channels (not voice, files or the welcome channel) where the caller has
  `view_channel` (bots: capped by their scopes and "no bots"); without `read_history` only messages from the caller's
  join on (`id >= ULID floor of joined_at`). Node admins who are not members see everything they could list.
- Order newest first (message id) or by relevance (`ts_rank` / BM25); filters by channel, author, time and
  attachments; at most 50 results per page.
- Snippets are made by the node from the stored content: about 60 characters of context on each side of the first
  match, every matching word wrapped in U+0001 … U+0002, line breaks as spaces, U+0001/U+0002 in the text removed.
  They are plain text; clients render the markers as highlights and escape everything else.
- `searched: { kind: "node", channels }` says how many channels the answer covers.
- Rate limit `TAVRN_SEARCH_RATE_PER_MINUTE` per user (default 30); the request log never contains the query string.

## 3. Local encrypted index

### 3.1 Keys

The index key material comes from the device's **local storage key** (`ENCRYPTION.md` §2.1, the key that already
protects the key store) through HKDF-SHA-256 with a 32-byte zero salt:

- `info = "tavrn search index v1 mac"` → HMAC-SHA-256 key `K_mac`,
- `info = "tavrn search index v1 enc"` → AES-256-GCM key `K_enc`.

Both are non-extractable WebCrypto keys held in memory only while the key store is unlocked. With "lock on close"
the index cannot be opened in a new tab before the user unlocks; signing out deletes the index with the other local
data. A locked store refuses every index operation.

### 3.2 Format

A key-value store with three stores (`docs`, `postings`, `meta`); keys are strings, values bytes. Every key is a
token `hex(HMAC(K_mac, part₁ ‖ 0x00 ‖ part₂ …))[0..32]`, every value `iv(12) ‖ AES-GCM(K_enc, JSON, aad = store ‖
0x00 ‖ key)`. Nothing else is stored.

| Store | Key parts | Sealed value |
|---|---|---|
| `docs` | `"doc"`, conversation, message id | conversation, message id, time, author address, text (≤ 4000 characters), file names, room id, the message's lookup keys |
| `postings` | `"tok"`, conversation, lookup key | sorted message ids |
| `meta` | `"conv"`, conversation | count, bytes, oldest/newest time, "complete" flag, sync state, message ids per UTC day |
| `meta` | `"list"` | the indexed conversations |

Conversations are named by their qualified id `<hosting node>/<id>`. Lookup keys of a text (and of its file names):
for every word (letters, digits and combining marks after NFKC and lowercasing) and its diacritic-folded variant,
`x:<word>` for words shorter than 3 characters and `p:<prefix>` for every prefix of 3 to 8 characters (code points);
runs of Han, Hiragana, Katakana and Hangul give their unigrams and bigrams as `x:` keys; at most 512 keys per message.
Postings are per conversation, so the same word in two conversations gives unrelated keys.

A query is split the same way: words of 3 or more characters look up `p:<first 8 characters>`, shorter ones
`x:<word>`, CJK runs their grams; all terms must match. Candidates are verified against the decrypted text (prefixes
longer than 8 characters, truncated-HMAC collisions), filtered (conversations, author, time, file) and returned newest
first with a snippet built like the node's (§2.2).

### 3.3 Budget

Browsers keep a bounded index: per conversation the last **90 days**, and at most **200 MB** in total over the
bounded conversations (oldest messages evicted first, by UTC day). A conversation with **"keep the full history on
this device"** (a device-local setting, stored sealed in its `meta` record, default off) has neither limit. Turning
it off applies the window and the cap right away. Accounting is approximate (sealed doc size plus 32 bytes per
posting entry). Native apps (phase 6) plug a SQLite backend into the same interface and keep everything.

### 3.4 What goes in

- **Display:** every encrypted message the client decrypts to show it (text, embed titles and descriptions,
  attachment file names). Edits replace the entry, deletes remove it, a moderation purge drops the conversation
  (it is filled again by the sync).
- **Background sync** (only while the key store is unlocked, throttled to one page of 100 messages at a time with a
  pause, slower in a hidden tab): conversations with "keep the full history" are paged back to their start and kept
  current; every other encrypted conversation the device has opened (an MLS group on this device) is paged back to
  the start of the window. Messages this device cannot decrypt are skipped. Pages respect the lazy-history rules:
  nothing is loaded at start-up for every conversation.

### 3.5 Privacy guarantees

- Without the local storage key a copy of the index (a stolen IndexedDB, a backup of the profile) reveals the number
  and approximate sizes of its records, nothing else: no words, prefixes, file names, authors, conversation or
  message ids (tested by dumping the backend after indexing and searching).
- Keys and lookup keys are not linkable across devices (the local storage key is per device) or across
  conversations (postings are keyed per conversation).
- The index never leaves the device; queries never reach a node.
- An attacker with the unlocked device (the local key in memory) can read the index like the messages themselves;
  "lock on close" limits that to the open session.

### 3.6 Files of encrypted files channels

Entries of encrypted files channels (`FILES.md` §8) go into the same index, as docs of the files channel's
conversation keyed by the entry id (a ULID, so newest-first ordering works as for messages):

- **Doc:** the conversation, the entry id, the time (= the entry's `created_at`, the upload date), the uploader (the
  address of `created_by`, else the record's author), the text (the entry's name and its folder path, so both are
  searchable), the room, and a sealed file part: kind, name, folder path, MIME type, category (PROTOCOL.md §7a table),
  plaintext size and whether there is a thumbnail. Thumbnail bytes are never copied into the index: results reference
  the entry, and the client fetches and decrypts the thumbnail from its preview cache or the node when it shows it.
- **What goes in:** every record the client decrypts (browsing a folder, opening an entry, the background sync). The
  background sync pages through `GET …/files/records` (`FILES.md` §3) of every encrypted files channel the device has
  a group for, under the same throttling and lock rules as for messages, and resolves folder paths from the folder
  records (fetching a missing parent with `GET …/files/{id}`).
- **Updates and deletes:** a renamed entry is indexed again when its new record is decrypted (browsing or the sync,
  which meets every rewritten record again in the record order); a moved entry when its new folder is browsed. Entries
  below a renamed or moved folder keep their old path in the index until they are decrypted again. Entries this
  client deletes are removed; a result whose entry is gone (`404`) is removed when it is opened. "Clear the local
  index" and signing out remove them like messages.
- **Budget:** the window of §3.3 is measured on the upload date (entries uploaded more than 90 days ago are evicted
  first and not added again, unless the channel keeps its full history); entries count towards the 200 MB cap.
- **Queries and filters:** the same terms as for messages; filters by type category (`images`, `audio`, `video`,
  `documents`, `archives`, `other`), by uploader and by upload date (the author and time filters of messages).
  Folders are found by their name and path but have no type.
- **Presentation:** the results appear in their own "Files" group with name, folder, size, upload date, uploader and
  the thumbnail; choosing one opens the files channel at the entry's folder with the entry selected.

The privacy guarantees of §3.5 hold unchanged: names, paths, types and sizes are only inside sealed docs.

## 4. Client presentation

One search box: in the conversation header (a field on desktop, an icon on phones that opens a full-screen panel).
Scopes "this room" (node search of the room plus the local index of its encrypted channels; "this conversation" in
DMs) and "everywhere" (node search per room the user is in, at most 20 rooms, plus the whole local index). Result
rows show author, channel, time and the snippet; choosing one opens the conversation at that message
(`GET …/messages?around=<id>`, PROTOCOL.md §7) with a brief highlight. The status line says what was searched, e.g.
"node searched 2 unencrypted channels in 1 room · last 90 days of 3 encrypted conversations on this device · 2
encrypted conversations not synced yet", and that rooms beyond the fan-out cap or unreachable nodes were not searched.
