# Moderation: reports, auto-moderation, ownership transfer

Status: implemented (design note 4.6). Capabilities: `reports.v1` (§1) and `automod.v1` (§2), announced by every node
that implements them; clients show the "Report" entries and the "Auto-moderation" room settings only for nodes that
announce them. Everything here is node-local (other nodes never see a report or a rule) except where it says so.

The moderation tools that existed before (timeouts, kicks, bans, purge, the audit log, the flood detection of §2.1)
are unchanged; this document adds reports with evidence (§1), content filters for unencrypted conversations (§2),
the protection of the welcome channel's entries (§3) and the transfer of a room's ownership (§4).

## 1. Reports (`reports.v1`)

A report tells the people who moderate a place that something there breaks its rules. Any authenticated user can
report: local users and users of other nodes with a federated session on the node (`FEDERATION.md` §8), never bots
(`403 report.bot_forbidden`, app tokens never reach the routes, `APPLICATIONS.md` §2.3). Reports are never
anonymous: moderators see who reported. The reported user is never told that, or by whom, they were reported.

### 1.1 Targets and routing

`POST /reports` → `201 ReportCreated { id, status, merged: false }` (or `200` with `merged: true`, §1.3):

| Field | Rule |
|---|---|
| `kind` | `message`, `user` or `room` |
| `conversation_id`, `message_id` | `message`: both required (ULIDs) |
| `node` | `message` only: the domain hosting the conversation when it is not this node (DMs and group DMs on another node, see below); omitted or this node's domain otherwise |
| `user` | `user`: the reported address (required); `message` on another node: the author's address (required) |
| `room_id` | `room`: the reported room (required); `user`: optional context, a room of this node the reporter belongs to |
| `category` | `spam`, `harassment`, `illegal`, `sexual`, `violence` or `other` |
| `detail` | free text, at most 2000 characters (may be empty) |
| `evidence` | only for messages of encrypted conversations, §1.2 |

Who handles a report (`scope`):

- **`room`**: a message in a room channel, or a user reported with a room as context. The room's moderators (the owner
  and every member holding `moderate_members` or `administrator`) see it, and the node admins of the node hosting the
  room. A report about the room's owner goes to the node admins only (`scope: node`): moderators cannot act against
  the owner. Moderators never see reports about themselves. Every moderator of the room sees a room report with its
  snapshot or evidence, also when the channel is hidden from some of them: the reporter chose to tell the room's
  moderators.
- **`node`**: a message in a DM or group DM, a user without room context, a room. The node admins of the node the
  report was sent to see it. Clients send a report to the node that hosts the conversation or room (room channels:
  the room's node, through the federated session if it is another node), and DM and group DM reports always to the
  reporter's **home node**: a DM lives on the node of its creator (`PROTOCOL.md` §8a), so a report about a DM on
  another node names that node in `node` and the author in `user`; the home node stores it with the reporter's
  evidence only (it has no copy of the message) and its admins can act against local accounts or block the peer.
  A user of another node can send `node` reports to this node only about conversations and rooms of this node.

Checks: the reporter must be able to read the reported message (the usual access errors of the conversation,
`403 room.not_member`, `channel.view_forbidden`, `404 conversation.not_found`; `404 message.not_found` for a message
that is not in it), must belong to the room given as
context (`403 room.not_member`), and a reported room must be one the reporter belongs to or a public room of this node
(`404 room.not_found` otherwise). Reporting oneself is `400 report.self`; an unknown user `404 user.not_found`;
anything malformed `400 report.target_invalid`, `report.category_invalid` or `validation.length`.

Reports about a **remote user in a local room** stay on the room's node: forwarding a report to the user's home node
is future work (a later `reports.v2`).

### 1.2 Evidence

The node cannot read encrypted messages, so a report about one would show moderators nothing but metadata. The
reporter can therefore **release** the plaintext deliberately:

- `evidence` is a list of at most 11 entries, the reported message and up to 10 messages before it in the same
  conversation, each `{ message_id, author, device_id, created_at, text, attachments }`: `author` an address,
  `device_id` the sending device as the envelope names it (may be null), `created_at` RFC 3339, `text` the decrypted
  body (at most 4000 characters; empty for messages without text), `attachments` the file names (at most 10, each at
  most 255 characters; never the files). The reported message must be in the list (`400 report.evidence_invalid`),
  at most 64 KiB in total.
- Clients show a **consent dialog** before sending: what will be sent (each entry with author, time and text), that
  the node's moderators and admins will read it in plaintext, and a checkbox per context message so the reporter can
  leave messages out. The reported message itself cannot be left out; a report without evidence stays possible.
- The node stores evidence exactly as received and marks the report `evidence_source: "reporter"`. It makes no claim
  that the evidence is authentic (the reporter could have edited it): moderators see it with a clear "released by
  the reporter" label and the envelope metadata the node has (author, device, time, epoch) to compare.
- Evidence is refused for messages of **unencrypted** conversations (`400 report.evidence_not_allowed`): the node
  links the message instead and stores a **snapshot** of its content at report time `{ author, created_at, text,
  attachments }` (messages can be deleted before a moderator looks).

Evidence and snapshot are deleted with the report (§1.5).

### 1.3 Duplicates and limits

A report of the same target (`message`: the message; `user`: the address and the room context; `room`: the room) by
the same reporter while an earlier one is still `open` is **merged** into it: category, detail and evidence are
replaced, `updated_at` moves, no new event is sent, and the answer is `200` with `merged: true`. Every user may send
`TAVRN_REPORTS_RATE_PER_HOUR` (default 10) new reports per hour (`429` with `retry_after_secs`); a merge counts
when the limit is reached as well, so a full limit refuses both.

### 1.4 The moderation inbox

| Route | Who | |
|---|---|---|
| `GET /rooms/{room_id}/reports?status=&limit=&before=` | `moderate_members` (owner, node admins) | the room's reports (`scope: room`), newest first → `ReportList { reports, open }` |
| `GET /admin/reports?status=&scope=&limit=&before=` | node admins | every report of the node (`scope` filters `room` or `node`) → `ReportList` |
| `GET /reports/{report_id}` | whoever may see it | one report with its evidence |
| `PATCH /reports/{report_id} { status?, assignee_id?, note? }` | whoever may see it | `status`: `open`, `resolved`, `dismissed`; `assignee_id`: a moderator who may see the report, or null; `note`: the resolution note (at most 2000 characters) → `ModerationReport` |
| `DELETE /reports/{report_id}` | node admins | deletes the report and its evidence at once → `204` |
| `POST /reports/{report_id}/actions` | whoever may see it, with the permission the action needs | the action shortcuts below |

`status` filters by state (default: all), `limit` 1–100 (default 50), `before` a report id (paging). `ReportList.open`
counts the open reports of the list's scope (badges). List entries carry `evidence_count` but not the evidence
itself. A `ModerationReport` is `{ id, source, scope, kind, room_id, room_name, conversation_id, conversation_kind,
node, message_id, message_exists, target, target_address, reporter, category, detail, snapshot, evidence,
evidence_count, evidence_source, status, assignee, note, actions, created_at, updated_at, resolved_at }` with
`target`, `reporter` and `assignee` as public users (`target` null for an address this node does not know, `reporter`
null for `source: automod`, §2.4), `conversation_kind` `channel`, `dm` or `group`, and `actions` the list of action
shortcuts taken `[{ action, actor, at, minutes? }]`.

**Action shortcuts.** `POST /reports/{id}/actions { action, minutes?, reason?, confirm_token?, resolve? }` runs the
existing moderation route on the report's target with the caller's permissions, exactly as if the caller had called it
(same checks, same errors, same events), and records the report id in that route's audit entry
(`meta.report_id`) and the action in the report:

| `action` | `scope: room` | `scope: node` (node admins) |
|---|---|---|
| `delete_message` | `DELETE …/messages/{message_id}` (`manage_messages`) | the message of a local DM or group DM is deleted (audited as `message.delete`) |
| `timeout` | `PUT /rooms/{id}/members/{user_id}/timeout { minutes }` (1–40320) | – |
| `kick` | `DELETE /rooms/{id}/members/{user_id}` | – |
| `ban` | `POST /rooms/{id}/bans { subject: <address> }` | `POST /admin/bans { subject: <address> }` (node ban) |
| `purge` | `POST /rooms/{id}/moderation/purge { author_id }` over every channel | `POST /admin/users/{id}/purge` |

`purge` is two-step like the routes it calls: without `confirm_token` it answers with the count and a token, with it
it deletes. `reason` goes to the route (kick, ban, timeout). `resolve: true` also sets the report `resolved`. The
answer is `ReportActionResult { report, purge }` (`purge` = the `PurgeResponse` of a purge). An action that does not
fit the report is `400 report.action_invalid` (no message, no user, `timeout` outside a room, …); the target being
on another node is `409 report.target_remote`.

### 1.5 Events and retention

- `report.create` `{ report: { id, scope, source, kind, room_id, room_name, conversation_id, category, created_at } }`
  goes to the online users who may see the report, except the reporter (no detail, no evidence). Clients refresh their
  inbox badge and may show "New report in <room>" through their normal notification path (the user's notification
  settings apply; reports are never pushed).
- `report.update` `{ id, scope, room_id, status }` goes to the same audience after a change, an action or a deletion
  (`status: "deleted"`).
- Resolved and dismissed reports, with their evidence and snapshot, are deleted `TAVRN_REPORTS_RETENTION_DAYS` (default
  90, 1–36500) days after they were closed. Open reports are kept. Deleting a room deletes its reports; an account
  erased after its grace period (`LEGAL.md` §3.2) takes its own reports with it.

## 2. Auto-moderation (`automod.v1`)

### 2.1 Flood detection (all channels)

More than `TAVRN_AUTOMOD_BURST_LIMIT` (default 10, 0 = off) messages of one member in one room channel within 5
seconds count as a flood, encrypted or not (it only needs metadata): the burst is deleted, the member gets a timeout of
`TAVRN_AUTOMOD_TIMEOUT_MINUTES` (default 10), the send answers `403 automod.spam`, and the room's moderators get
`moderation.alert { kind: "spam" }` and an audit entry `automod.spam`. Owners, node admins and members with
`moderate_members` are exempt.

### 2.2 Content rules (unencrypted conversations only)

The node can only filter what it can read: content rules apply to messages of **unencrypted** conversations, never to
ciphertext. Encrypted channels, DMs and group DMs (always encrypted) are not filtered, and clients say so in the
rules editor.

**Room rules** (`manage_room`): `GET /rooms/{room_id}/automod` → `AutomodSettings { rules, burst, node }`, `PUT
/rooms/{room_id}/automod { rules }` replaces the whole list (audited as `automod.rules`, `room.update` is not sent).
`burst` is the node's flood setting (§2.1, read-only), `node` says whether node rules are active (§2.3). Moderators
(`moderate_members`) may read the settings. At most 20 rules per room, each:

| Field | Rule |
|---|---|
| `id` | assigned by the node (kept when a rule is sent back with it) |
| `name` | 1–64 characters, unique in the room; named in the error a blocked sender sees |
| `enabled` | default `true` |
| `terms` | at most 500 words or phrases, each 1–100 characters; `*` matches any run of non-space characters (`spam*`, `*coin`, `fr*e`, at most 5 per term; in a phrase with spaces only at its start or end) |
| `whole_word` | the match must start and end at a word boundary (letters, digits and `_` are word characters) |
| `links` | `off`, `block_all` (any link), `allow_list` (links to other domains than `domains`), `block_list` (links to `domains`) |
| `domains` | at most 500 domains; a domain also covers its subdomains |
| `exempt_roles`, `exempt_channels` | role and channel ids of the room the rule does not apply to |
| `action` | `block`, `delete` or `timeout` |
| `timeout_minutes` | `timeout` only: 1–40320 |

A rule needs terms or a link filter (`400 automod.rules_invalid` names the rule and the problem otherwise). Matching
is case-insensitive on the NFKC form of the text, with whitespace runs folded to one space. A link is an `http://` or
`https://` URL or a `www.` host; `block_list` also matches a listed domain written without a scheme.

What is checked: on send **and** edit, the text fields of the content (`body`, embed and link preview texts and URLs;
not the GIF of the configured provider) and the file names of the message's attachments. Owners and node admins are
exempt from room rules, as are members holding an exempt role and messages in exempt channels; webhooks and system
messages are not checked.

Actions of the first matching rule (rules are checked in their order):

- `block`: the send or edit is refused with `403 automod.blocked` and `meta { rule, scope: "room" }`; nothing is
  stored. Clients show the error in the composer, naming the rule.
- `delete`: the message is accepted (`201`) but never shown to anyone else: the node deletes it right away and sends
  only `message.delete` (an edit: the message is deleted).
- `timeout`: like `delete`, and the author gets a timeout of `timeout_minutes`.

### 2.3 Node rules (operator)

`TAVRN_AUTOMOD_WORDS_FILE` (a file with one term per line, the syntax of §2.2, matched as whole words; empty lines
and lines starting with `#` are ignored; at most 10000 terms) and `TAVRN_AUTOMOD_LINKS` (`off` or the path of a file
with one blocked domain per line) apply to every unencrypted conversation of the node, room channels and unencrypted
DMs alike, with the action `block` and no exemptions: `403 automod.blocked` with `meta { rule: "node", scope: "node"
}`. Node rules are checked before room rules.

### 2.4 Alerts

Every match (room or node rule, any action) writes an audit entry `automod.content` in the room (`target` the author's
address, `reason` the rule's name, `meta { rule, scope, kind: word|link, matched, action, channel_id, message_id? }`
with the matched term or domain, **never the message text**) and sends `moderation.alert { room_id, channel_id, user,
kind: "content", rule, scope, matched, action, at }` to the room's moderators (room rules) or to the node admins
(node rules). It also opens or updates an inbox entry: a report with `source: automod`, `kind: user`, the author as
target and `scope` of the rule, whose `detail` names the rule, the match and the action. Further matches of the same
author while that report is open update it instead of adding new ones.

## 3. The welcome channel's entries

The entries the node writes into the welcome channel (`PROTOCOL.md` §7, the room's security log) cannot be deleted by
anyone, owners, moderators and node admins included: `DELETE …/messages/{id}` answers `403 message.system_protected`,
purges skip the welcome channel even when it is named, and the report actions cannot remove them. Only the deletion of
the account an entry is about (`LEGAL.md` §3.2) and a node's message retention remove them. Clients do not offer
"Delete" for them.

## 4. Room ownership transfer

`POST /rooms/{room_id}/transfer { user_id }` → `200 RoomDetail`: the owner hands the room to another member. Only the
owner (`403 room.owner_required`); the request needs a reauth token (`PROTOCOL.md` §5c, `403 auth.reauth_required`).
The new owner must be a member, a local user of the room's node and not a bot (`400 room.transfer_invalid`). The
former owner stays a member with their roles. The node writes the audit entry `room.transfer` (`target` the new
owner's address, `meta { from, to }`) and sends `room.update` to the room.

The account deletion (`LEGAL.md` §3.2) still refuses accounts that own rooms (`409 account.owns_rooms` with
`meta.rooms`); clients offer to transfer each room (or delete it) right in the deletion dialog and then repeat the
deletion.

## 5. Operator settings

| Variable | Default | |
|---|---|---|
| `TAVRN_REPORTS_RATE_PER_HOUR` | `10` | reports per user and hour (1–1000) |
| `TAVRN_REPORTS_RETENTION_DAYS` | `90` | days resolved and dismissed reports are kept (1–36500) |
| `TAVRN_AUTOMOD_BURST_LIMIT` | `10` | flood detection, §2.1 (0 = off) |
| `TAVRN_AUTOMOD_TIMEOUT_MINUTES` | `10` | timeout after a flood |
| `TAVRN_AUTOMOD_WORDS_FILE` | – | node word list, §2.3 |
| `TAVRN_AUTOMOD_LINKS` | `off` | `off` or a domain blocklist file, §2.3 |
