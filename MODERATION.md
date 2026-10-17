# Moderation: reports, auto-moderation, ownership transfer

This document specifies reports with evidence, auto-moderation of unencrypted conversations, the protected entries of
the welcome channel, room ownership transfer and age gates.

Status: implemented (design note 4.6). Capabilities: `reports.v1` (§1), `reports.v2` (§1.6) and `automod.v1` (§2),
announced by every node that implements them; clients show the "Report" entries, the "Forward" action and the
"Auto-moderation" room settings only for nodes that announce them. Everything here is node-local (other nodes never
see a report or a rule) except where it says so: a report about a user of another node can be forwarded to that
user's home node (§1.6).

The moderation tools that existed before (timeouts, kicks, bans, purge, the audit log, the flood detection of §2.1)
are unchanged; this document adds reports with evidence (§1), content filters for unencrypted conversations (§2),
the protection of the welcome channel's entries (§3) and the transfer of a room's ownership (§4).

## 1. Reports (`reports.v1`)

A report tells the people who moderate a place that something there breaks its rules. Any authenticated user can
report: local users and users of other nodes with a federated session on the node (`FEDERATION.md` §2.5), never bots
(`403 report.bot_forbidden`, app tokens never reach the route, `APPLICATIONS.md` §2.5). Moderation bots may read the
room's inbox, metadata only (§1.4a). Reports are never anonymous: moderators see who reported. The reported user is never told that, or by whom, they were reported.

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
  moderators (see "Why every moderator sees the context" below).
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

**Why every moderator sees the context.** A room report, with its snapshot or released evidence, reaches every
moderator holding `moderate_members` (and the node admins), even when the reported message lives in a channel that is
hidden from some of them. This is deliberate: moderation needs the context. A moderator who decides about a timeout,
kick or ban has to see what was reported, and the reporter addressed the room's moderators as a whole, not the
readers of one channel. Restricting reports to moderators who can view the channel would leave reports from private
channels with fewer or no moderators, would make the inbox and its badge differ between moderators of the same room,
and would protect nothing the reporter wanted protected (the reporter chose to release it to the moderators). Rooms
that need a separate moderation team for a private area use a separate room.

Reports about a **remote user** (a user of another node in a local room, the author of a DM on another node) stay on
the node they were sent to; its admins can forward them to the user's home node, whose admins are the ones able to act
on the account (§1.6).

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
| `GET /rooms/{room_id}/reports?status=&limit=&before=` | `moderate_members` (owner, node admins; bots read-only, §1.4a) | the room's reports (`scope: room`), newest first → `ReportList { reports, open }` |
| `GET /admin/reports?status=&scope=&limit=&before=` | node admins | every report of the node (`scope` filters `room` or `node`) → `ReportList` |
| `GET /reports/{report_id}` | whoever may see it (bots: §1.4a) | one report with its evidence |
| `PATCH /reports/{report_id} { status?, assignee_id?, note? }` | whoever may see it | `status`: `open`, `resolved`, `dismissed`; `assignee_id`: a moderator who may see the report, or null; `note`: the resolution note (at most 2000 characters) → `ModerationReport` |
| `DELETE /reports/{report_id}` | node admins | deletes the report and its evidence at once → `204` |
| `POST /reports/{report_id}/actions` | whoever may see it, with the permission the action needs | the action shortcuts below |
| `POST /reports/{report_id}/forward` | node admins | forwards the report to the reported user's home node (§1.6) → `ModerationReport` |

`status` filters by state (default: all), `limit` 1–100 (default 50), `before` a report id (paging). `ReportList.open`
counts the open reports of the list's scope (badges). List entries carry `evidence_count` but not the evidence
itself. A `ModerationReport` is `{ id, source, scope, kind, room_id, room_name, conversation_id, conversation_kind,
node, message_id, message_exists, target, target_address, reporter, category, detail, snapshot, evidence,
evidence_count, evidence_source, status, assignee, note, actions, forwarded, origin, created_at, updated_at,
resolved_at }` with `source` `user`, `automod` (§2.4) or `forward` (§1.6), `target`, `reporter` and `assignee` as
public users (`target` null for an address this node does not know, `reporter` null for `source: automod` and
`source: forward`), `conversation_kind` `channel`, `dm` or `group`, `actions` the list of action shortcuts taken
`[{ action, actor, at, minutes? }]`, `forwarded` `{ node, at, by }` once a node admin forwarded the report (§1.6, `by`
the admin's address; null otherwise) and `origin` `{ node, report_id, reporter, reported_at }` for a report another
node forwarded here (§1.6; null otherwise).

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

### 1.4a Moderation bots (read-only)

A bot with the app token scope `moderation` (`APPLICATIONS.md` §2.4) that holds `moderate_members` in a room reads
that room's inbox, so it can triage reports (a summary in a moderators' channel, an escalation after several reports
about one user). It reads; it never writes:

- `GET /rooms/{room_id}/reports?status=&limit=&before=` → `AppReportList { reports, open }` and `GET /reports/{report_id}`
  → `AppReport`, with the parameters and paging of §1.4, for the room's reports (`scope: room`) only and with the rules
  of every moderator: never reports about the bot itself, never reports about the room's owner (those are `scope:
  node`), and never reports about the bot's owner or the owner's other bots (as its owner would not see them; also
  no `report.*` events about them). Node reports, reports of other rooms and the admin inbox answer as for everyone who may not see them (`404
  report.not_found`; `/admin/*` is closed to app tokens). Without `moderation` the route table refuses (`403
  app.scope_missing`); without `moderate_members`, also in a "no bots" room (`APPLICATIONS.md` §3.5), the list is `403
  report.view_forbidden` and a report `404 report.not_found`.
- Creating reports, triage (`PATCH /reports/{id}`), the action shortcuts, forwarding and deleting stay closed to bots
  (`403 app.bot_forbidden` from the route table; the handlers refuse bots with `403 report.bot_forbidden` as well).
  Acting stays with people, so a leaked bot token cannot close reports about itself or its owner.

**Metadata only.** An app token always gets the reduced shape `AppReport { id, source, scope, kind, room_id,
room_name, conversation_id, conversation_kind, message_id, message_exists, target, target_address, reporter, category,
evidence_count, action_count, status, created_at, updated_at, resolved_at }`, never a `ModerationReport`. `detail`,
`snapshot`, `evidence`, `note`, `assignee`, `actions`, `forwarded` and `origin` are left out: the reporter released the
reason and the content to the room's moderators (§1.2), not to programs. A bot that may read the channel
(`messages:read`) can fetch the reported message by `message_id` under its own access rules, like any other message.
`target` is the reported user as a public user (null for an address this node does not know), `action_count` the
number of action shortcuts taken.

`reporter` is never the reporter's address but a pseudonym of the format of §1.6 (1–64 characters of
`[A-Za-z0-9_-]`): stable per reporter, bot and room, so the bot can tell repeated reports of one person from reports
of many, and unlinkable between bots, between rooms and to the pseudonyms of forwarded reports (the reference node
uses the keyed hash of §1.6 with the bot's address and the room id in place of the receiving node); null for
`source: automod`.

The events of §1.5 reach these bots as well (`report.create`, `report.update` of the room, with `moderation` in the
token's scopes, `APPLICATIONS.md` §2.6), in the shape every moderator gets: neither carries a detail, evidence or the
reporter. Web pushes of reports never go to bots.

### 1.5 Events and retention

- `report.create` `{ report: { id, scope, source, kind, room_id, room_name, conversation_id, category, created_at } }`
  goes to the online users who may see the report, except the reporter (no detail, no evidence, no reporter), and to
  the moderation bots of the room (§1.4a). Clients refresh their
  inbox badge and may show "New report in \<room>" through their normal notification path (the user's notification
  settings apply). Those without an open connection get a web push of type `report` with the report's kind and room
  only (`PROTOCOL.md` §6d), unless they turned the notification setting `reports` off (`PROTOCOL.md` §6c, default
  on); at most one per room and moderator every 30 seconds.
- `report.update` `{ id, scope, room_id, status }` goes to the same audience after a change, an action or a deletion
  (`status: "deleted"`).
- Resolved and dismissed reports, with their evidence and snapshot, are deleted `TAVRN_REPORTS_RETENTION_DAYS` (default
  90, 1–36500) days after they were closed. Open reports are kept. Deleting a room deletes its reports; an account
  erased after its grace period (`LEGAL.md` §3.2) takes its own reports with it.

### 1.6 Forwarding to the home node (`reports.v2`)

A report about a user of another node reaches the people who moderate the place where it happened, but only the
admins of the user's **home node** can act on the account (disable it, ban it node-wide, purge it). The admins of the
node that holds the report can therefore forward it there. Nodes announce `reports.v2` while federation is enabled
(`FEDERATION.md` §11.4); it adds the route below and the inbox type `report.forward` (`FEDERATION.md` §5.2).
`reports.v1` is unchanged, and a node without `reports.v2` ignores the type like every unknown inbox type.

**Forwarding.** `POST /reports/{report_id}/forward` (empty body) → `200 ModerationReport` with `forwarded { node, at,
by }`. Node admins only (`403 auth.node_admin_required`), for a report they can see (`404 report.not_found`):

- only reports by users (`source: user`) about a user (`kind: message` or `user`); automod entries, reports about
  rooms and reports that were forwarded here are `400 report.forward_invalid`;
- the reported user must belong to another node (`409 report.target_local`), and that node must announce `reports.v2`
  in its discovery document (`409 report.forward_unsupported`); the federation checks of `FEDERATION.md` apply
  (`403 federation.disabled`, `federation.peer_blocked`, `502 federation.peer_unreachable`, …);
- it is **idempotent**: a report that was forwarded already answers `200` with its `forwarded` unchanged, and nothing
  is sent again.

The node queues `report.forward` to the user's home node in its federation outbox (retries as in `FEDERATION.md`
§5.3); `forwarded` records the decision, not the delivery. Forwarding changes nothing else: the report keeps its status
and stays in the inbox, and moderators keep acting on it here. The reporter is told nothing, on either node; the
reported user is never told either (§1).

**What is forwarded** (the payload of `report.forward`): the original report's `report_id`, `kind`, `category`,
`detail`, `created_at`, `message_id` (message reports), the `snapshot` of a plaintext message or the `evidence` the
reporter released (§1.2), and `reporter`. Room names, room and conversation ids, the reporter's address and the
moderators' notes and actions are not forwarded.

**The reporter stays pseudonymous to the home node.** `reporter` is an opaque pseudonym (1–64 characters of
`[A-Za-z0-9_-]`), never the address: stable per reporter and receiving node, so the home node can tell repeated
reports of one person from reports of many, and unlinkable between receiving nodes (the reference node derives it with
a keyed hash of its secret, the receiving domain and the address). The home node of the reported user may be run by
that very user (a one-person node), and the reported user must never learn who reported them (§1). For the same
reason the authors of evidence entries and of the snapshot other than the reported user are replaced by pseudonyms
of this report only (stable within the report, never the `reporter` pseudonym, so the reporter's own entries look
like everybody else's), and their `message_id` and `device_id` are left out (a message id would let a member of the
conversation look the author up); the reported user's entries keep address, message id and device. The text itself
is forwarded as released, with its time: a member of the conversation may still recognise a message by its content,
so clients tell the forwarding admin that the home node's admins will read the reason, the snapshot and the
evidence, and that released context of a small conversation can point to its author. When the message would exceed the inbox limit of 64 KiB
the sending node leaves out the oldest context entries of the evidence, never the reported message.

**Receiving.** The home node checks the message like every inbox message (node token, `FEDERATION.md` §5.1), then:

- `to` is the reported user's address and must be a user of this node (`404 federation.recipient_unknown`), `from`
  the sending node's domain (`403 federation.type_forbidden` otherwise);
- the payload is checked like a report (category, `detail` at most 2000 characters, the snapshot and the evidence by
  the limits of §1.2 with pseudonyms allowed as authors, the reported message part of the evidence; `400
  federation.envelope_invalid`);
- at most `TAVRN_REPORTS_INBOUND_PER_HOUR` (default 20) forwarded reports per sending registrable domain (its
  subdomains share the budget) and five times as many from all domains per hour (`429`, checked before the message
  counts as received, so the sender's retry brings it later);
- duplicates by origin node and original report id are accepted (`202`) and change nothing.

The report lands in the node admins' inbox (`GET /admin/reports`) as `source: forward`, `scope: node`, the local user
as `target`, `reporter: null` and `origin { node, report_id, reporter, reported_at }` (the sending node, the original
id, the pseudonym, the original `created_at`); `node` names the origin, since the reported content lives there: `delete_message` answers `409
report.target_remote`, while the account actions (`ban` as a node ban, `purge`) work as for every node report. It
sends `report.create` (`source: "forward"`) and the report push to the node admins like a new report (§1.5). Triage,
deletion and retention (§1.5) are those of every report and independent of the origin's copy; nothing is reported
back to the origin.

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
messages are not checked. A bot's interaction replies and follow-ups (`APPLICATIONS.md` §5.7) are checked like its
other messages. `delete` and `timeout` rules act only on members ranked below the member who last saved the rules
(their highest role at that time; the owner and node admins outrank everyone), as that member's own moderation
would (`permissions.md` "Hierarchy"); `block` rules apply to everyone not exempt. Nodes bound the matching work per
message; a message that would need more than any ordinary one is refused like a `block` hit (`403 automod.blocked`).

Actions of the first matching rule (rules are checked in their order):

- `block`: the send or edit is refused with `403 automod.blocked` and `meta { rule, scope: "room" }`; nothing is
  stored. Clients show the error in the composer, naming the rule.
- `delete`: the message is accepted (`201`) but never shown to anyone else: the node deletes it right away and sends
  only `message.delete` (an edit: the message is deleted).
- `timeout`: like `delete`, and the author gets a timeout of `timeout_minutes`, announced with `member.update` as a
  moderator's timeout is (also the timeout of the flood limit, §2.1).

### 2.3 Node rules (operator)

`TAVRN_AUTOMOD_WORDS_FILE` (a file with one term per line, the syntax of §2.2, matched as whole words; empty lines
and lines starting with `#` are ignored; at most 10000 terms) and `TAVRN_AUTOMOD_LINKS` (`off` or the path of a file
with one blocked domain per line) apply to every unencrypted conversation of the node, room channels and unencrypted
DMs alike, with the action `block` and no exemptions: `403 automod.blocked` with `meta { rule: "node", scope: "node"
}`. Node rules are checked before room rules. The node reads both files at start and again every hour and on `SIGHUP`;
it validates them like at start and keeps the previous lists when a file is invalid or unreadable.

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
purges skip the welcome channel even when it is named, and the report actions cannot remove them; message retention
(`PROTOCOL.md` §7f) skips them too. Only the deletion of the account an entry is about (`LEGAL.md` §3.2) removes
them. Clients do not offer
"Delete" for them. The security notices the node writes into a channel instead of the welcome channel (`system.bot_*`
about a channel `@everyone` cannot view, `PROTOCOL.md` §7) are protected the same way: no deletion (the bot they name
included), purges and retention skip them; they go with their channel.

**History restore after a key reset** (`ENCRYPTION.md` §7b, capability `history.restore`). A member who reset their
security key loses the encrypted history from before the reset; it comes back only when a member with
`restore_history` (owner and `administrator` by default) approves the member's request in the room settings, and the
approval (`system.history_restored`) or denial (`system.history_restore_denied`) is a welcome channel entry like the
key change itself. Moderators should treat the request like a password reset at a help desk: a reset is exactly what
someone who took over the account would do, and an approval gives them everything the member could read before. Verify
the person's identity on another channel before approving (a call, in person, or a channel you already trust; never
only a message from the account itself, and never a code the account sends), and deny with a reason when in doubt;
nobody can approve their own request.

## 4. Room ownership transfer

`POST /rooms/{room_id}/transfer { user_id }` → `200 RoomDetail`: the owner hands the room to another member. Only the
owner (`403 room.owner_required`); the request needs a reauth token (`PROTOCOL.md` §5c, `403 auth.reauth_required`).
The new owner must be a member, a local user of the room's node and not a bot (`400 room.transfer_invalid`). The
former owner stays a member with their roles. The node writes the audit entry `room.transfer` (`target` the new
owner's address, `meta { from, to }`) and sends `room.update` to the room.

The account deletion (`LEGAL.md` §3.2) still refuses accounts that own rooms (`409 account.owns_rooms` with
`meta.rooms`); clients offer to transfer each room (or delete it) right in the deletion dialog and then repeat the
deletion.

## 4a. Age gates (`age.v1`)

Room and channel settings carry an age gate (`age_gate: none | adults_only`, normative: `PROTOCOL.md` §5e). Holders
of `manage_room` gate a room, holders of `manage_channels` a channel (a channel can be stricter than its room, never
looser); only an adult can switch a gate on, and every change is in the audit log (`room.age_gate`,
`channel.age_gate`). The gate is enforced by the hosting node for every member, moderators, owners and node admins
included: someone below the gate cannot read, search, report from or moderate the content of a gated channel,
because they cannot see it. Users below the gate never find a gated room in Discover and cannot join it, not even
with an invite; existing members of a room that becomes gated keep their membership but every channel is locked
for them. Nobody but the user's home node learns the user's age or status: moderators see neither, and a refused
join is visible only to the person refused.

## 5. Operator settings

| Variable | Default | |
|---|---|---|
| `TAVRN_REPORTS_RATE_PER_HOUR` | `10` | reports per user and hour (1–1000) |
| `TAVRN_REPORTS_RETENTION_DAYS` | `90` | days resolved and dismissed reports are kept (1–36500) |
| `TAVRN_REPORTS_INBOUND_PER_HOUR` | `20` | reports forwarded by other nodes per sending registrable domain and hour, five times as many in total (1–1000), §1.6 |
| `TAVRN_AUTOMOD_BURST_LIMIT` | `10` | flood detection, §2.1 (0 = off) |
| `TAVRN_AUTOMOD_TIMEOUT_MINUTES` | `10` | timeout after a flood |
| `TAVRN_AUTOMOD_WORDS_FILE` | – | node word list, §2.3 |
| `TAVRN_AUTOMOD_LINKS` | `off` | `off` or a domain blocklist file, §2.3 |
| `TAVRN_MINIMUM_AGE` | `16` | minimum age for registration (13–99), `PROTOCOL.md` §5e |
