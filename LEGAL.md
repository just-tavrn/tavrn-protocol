# Legal compliance: notices, legal pages, data rights

Status: implemented (design note 4.14 items 1–3). Everything here is optional for operators: a node without notices,
documents or deletions behaves as before.

> **No legal advice.** This document describes what the software does and which rules it was built against. It does
> not tell an operator which laws apply to their node or whether their setup complies. The operator of a node is
> responsible for it; the templates shipped with the node (`tavrn-node`) are starting points to be reviewed with a lawyer.

## 0. What the operator can and cannot see

The node holds some data in plaintext (accounts, profiles, unencrypted channels, file names in unencrypted channels,
metadata of everything) and some only as ciphertext (messages, files and calls of end-to-end encrypted
conversations: `ENCRYPTION.md`). Nothing in this document decrypts anything:

- A notice can name an encrypted message or file (link or id). The admin page shows that it is encrypted, its
  metadata (author, time, size, room and channel name) and never its content; the admin can still remove it or act
  against the account.
- The data export lists encrypted messages with their metadata only; the user's own devices hold the content.
- Deleting an account removes ciphertext the same way it removes plaintext.

## 1. Takedown notices (DMCA notice-and-takedown, DSA notice and action)

### 1.1 The public form

`TAVRN_LEGAL_NOTICES=on` opens `POST /api/v1/legal/notices` (no account needed) and the web page `/legal/notice`.
`GET /node` announces it as `legal.notices: { enabled, contact }`; `contact` (name, postal address, e-mail of the
designated contact) is set by node admins in the "Legal" tab (`PUT /admin/legal/contact`, stored in `node_settings`).

| Field | Rule | Why |
|---|---|---|
| `basis` | `copyright` \| `illegal` \| `terms` | which procedure applies |
| `work` | 1–5000 characters | identification of the work (DMCA §512(c)(3)(A)(ii)) or of the content (DSA Art. 16(2)(a)) |
| `explanation` | required for `illegal` and `terms`, ≤ 5000 | "sufficiently substantiated explanation" (DSA Art. 16(2)(a)) |
| `locations` | 1–20 `{ kind: message \| attachment \| room \| profile \| other, value }`, values ≤ 500 | exact electronic location (DMCA §512(c)(3)(A)(iii), DSA Art. 16(2)(b)) |
| `reporter_name`, `reporter_email` | required; the e-mail is checked (no header injection) | contact details (DMCA (iv), DSA (c)) |
| `reporter_address`, `reporter_phone` | optional | DMCA asks for "information reasonably sufficient to contact" |
| `good_faith`, `accuracy` | must be `true` | DMCA (v), (vi); DSA (d) |
| `perjury` | must be `true` for `copyright` only ("under penalty of perjury, authorized to act") | DMCA (vi) |
| `signature` | typed full name, 1–200 | DMCA (i) |
| `captcha_token` | required when the node has a captcha provider | abuse |

Limits: body ≤ 32 KiB (`413`), `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR` per client address (default 5, `429`). A
disabled form answers `404 legal.notices_disabled`.

The answer is `201 { case_id, state: "received", mailed }`. The reporter gets a confirmation mail with a **private
status link** `<public url>/legal/notice/<case_id>?token=<random>`; only the token's hash is stored.
`GET /api/v1/legal/notices/{case_id}?token=` shows `{ case_id, state, basis, created_at, updated_at,
decision_reason }`, never the reporter's or the uploader's data. Unknown cases, malformed ids, missing and wrong
tokens all answer the same `404 legal.notice_not_found` (constant-time comparison; 60 lookups per hour and address),
so case ids cannot be probed.

Location values are resolved on submission: a message link of the web client (`…/rooms/<room>/channels/<channel>
?message=<id>`) or a bare id, an attachment id, a room link or id, a user address (also `/u/<address>`). A link of
the form `/n/<domain>/…` or with the host of another tavrn node names content of that node (`local: false`, `node`);
everything else is looked up here (`local`, `author`, `conversation_id`, `room_id`).

### 1.2 Cases and states

`legal_notices` (one row per case, id = ULID), `legal_notice_events` (the trail: every step with actor and time),
`legal_counter_notices`. States: `received` → `in_review` → `actioned` | `rejected`, `counter_notice` while a
counter-notice waits for the decision. Every step mails the side it concerns and is logged in the trail and in the
node audit log (`legal.*` actions).

Admin routes (node admins with a session; admin API tokens are refused: `403 admin_token.route_forbidden`):

| Route | |
|---|---|
| `GET /admin/legal/notices?state&basis&q&limit&before` | list, newest first; `q` searches reporter, work, target and id (wildcards literal) |
| `GET /admin/legal/notices/{case_id}` | the case, its trail, counter-notices, `content` (inline plaintext per location; for encrypted content only `encrypted: true` and metadata), `repeat_count`, `repeat_threshold`, `repeat_suggest_disable` |
| `POST /admin/legal/notices/{case_id}/actions` | `{ action, reason, statement, locations?, user_id?, node?, state? }` |
| `POST /admin/legal/notices/{case_id}/counter-notice/decision` | `{ decision: restore \| uphold, reason }` |
| `GET /admin/legal/notices/export` | every kept case with trail and counter-notices as one JSON file |

Actions:

- `remove_content` (needs `statement`): deletes reported messages with their files (`message.delete` to the
  conversation), removes the file of a reported attachment (the row stays as expired, the message shows the file as
  gone), clears a reported local profile (avatar, header, bio, links, status; display name = username). Rooms are
  not removed by this action. Content on other nodes is skipped (forward instead). Sets the case's target user,
  `counter_deadline` (`TAVRN_LEGAL_COUNTER_NOTICE_DAYS`) and state `actioned`; `409 legal.nothing_removed` when
  nothing local could be removed.
- `disable_account` (needs `statement`): disables the local account (sessions end, its bots stop), state `actioned`.
- `reject` (needs `reason`, which the reporter receives): state `rejected`.
- `forward` (`node` optional): sends S2S `legal.notice` (§1.5) to the nodes hosting reported content.
- `set_state`: any state, e.g. reopening.

Removal is final: the node keeps no copy of removed content. A counter-notice decided `restore` re-enables an account
the case disabled; removed content can be posted again by the uploader.

### 1.3 Repeat infringers

`repeat_count` counts the kept cases in state `actioned` whose target is the user. At `TAVRN_LEGAL_REPEAT_THRESHOLD`
(default 3) the admin page suggests disabling the account (DMCA §512(i) asks for a repeat-infringer policy). Nothing
happens automatically.

### 1.4 Statement of reasons and counter-notice

`remove_content` and `disable_account` send the uploader a statement of reasons (DSA Art. 17): the decision, the
basis of the notice, the admin's text (facts, legal ground or terms clause) and the redress the node adds (a person
decided, counter-notice until the deadline, out-of-court dispute settlement, courts). It is stored with the case,
delivered as WS `legal.statement { case_id, decision, counter_deadline }` (the web client adds a notification) and
mailed when the account has an e-mail address. The reporter's data is never shown to the uploader.

The uploader sees their cases at `GET /users/me/legal-notices` (`statement`, `counter_deadline`, `can_counter`) and
may answer once per case before the deadline: `POST /users/me/legal-notices/{case_id}/counter-notice { name, address,
statement, consent, signature }` (copyright cases need the address and `consent` to jurisdiction, DMCA §512(g)(3)).
The reporter receives the counter-notice (DMCA §512(g)(2)(B)); the case is `counter_notice` until the admin decides
(`restore` → `rejected`, `uphold` → `actioned`); both sides get the decision. Errors: `404 legal.notice_not_found`
(not the uploader), `409 legal.counter_closed`, `409 legal.counter_exists`, `400 legal.counter_incomplete`.

### 1.5 Forwarding to the content's node

Content of a room hosted on another node lives there; only that node can remove it. `forward` sends S2S
`legal.notice` (FEDERATION.md §5.2) with the case data (basis, work, explanation, the locations of that node, the
reporter's name and contact, the statements, the signature). The receiving node opens a case of its own in state
`received` with `origin` and `origin_case` recorded (a replay is a no-op), mails the reporter, and decides itself —
also when its own public form is off. The reporter is told about the forwarding; the form says that details may be
forwarded.

### 1.6 Retention

Every change sets `retain_until` to now + `TAVRN_LEGAL_NOTICE_RETENTION_DAYS` (default 1095 = 3 years);
housekeeping deletes cases (with trail and counter-notices) after that. Cases stay through an account deletion with
the target pseudonymised (§3.3).

## 2. Legal pages and terms

Node admins write the imprint, the privacy policy, the terms of service and an optional cookie/notice text in
Markdown ("Legal" tab, `PUT /admin/legal/documents/{kind} { markdown, lang }`, ≤ 200 KiB). Every publish is a new
version (`legal_document_versions` keeps every text with its time and admin; versions never repeat, also after
`DELETE /admin/legal/documents/{kind}`). The node renders the Markdown once at publish time: raw HTML becomes text,
images become their alt text (no third-party requests), links keep only `http(s):`, `mailto:`, same-site paths and
fragments. The web client renders the same Markdown with its message sanitizer (marked + DOMPurify, document
allow-list).

- `GET /legal/pages`, `GET /legal/pages/{kind}` (public JSON), `GET /node` → `legal.pages`.
- `/legal/{imprint|privacy|terms|cookies}`: standalone HTML page (no JavaScript, CSP `default-src 'none'`, the app's
  dark style, `lang` from the document or `en`) for crawlers, mails and other clients. Other paths below `/legal/`
  belong to the web client (`/legal` overview, `/legal/notice`).
- The web client links "Legal" under the sign-in, registration, invite, connect and password-reset cards and offers
  "Legal & privacy" in the user menu and the settings: every document is two clicks away from every screen.
- `GET /admin/legal/templates/{kind}?locale=en|de`: the non-binding templates shipped with the node with `{{node_domain}}`,
  `{{node_name}}`, `{{operator_name}}`, `{{operator_address}}`, `{{contact_email}}`, `{{effective_date}}` filled
  from the configuration and the contact; `[[OPERATOR: …]]` notes stay for the operator.

**Terms acceptance.** When terms are published, registration needs `accept_terms` = the current version
(`400 legal.terms_not_accepted`); the acceptance is stored with its time (`terms_acceptances`). A new version asks
every local user once after sign-in (`GET /users/me/terms` → `pending`; `POST /users/me/terms/accept { version }`).
`TAVRN_LEGAL_TERMS_MODE` decides what declining means: `notice` (default) only shows the dialog (the client hides it
for that version on that device), `require` refuses every authenticated route except the terms routes, logout and the
legal pages with `403 legal.terms_required` (and closes WebSockets) until the user accepts; declining signs out. SSO
accounts are created without a form: they see the dialog (or the refusal) at their first sign-in like everyone. Remote
users accept their home node's terms; bots have none.

## 3. GDPR data rights

### 3.1 Access and portability (Art. 15, 20)

`GET /users/me/data` (no reauth): a summary for the "My data" page in the profile settings — categories with counts
and the oldest entry, the nodes the account is shared with (federation tokens issued, conversations hosted
elsewhere), the applications with access (own applications, bots in the user's rooms), and the retention settings of
the node.

`GET /users/me/export` (reauth token): a JSON archive (`format: "tavrn.export.v1"`): account, profile, notification
settings, devices, sessions (times only), second factors (kinds and names only), single sign-on links, rooms with
roles, rooms owned, conversations with their members' addresses, friends, friend requests, blocks, attachments
(metadata; names only from unencrypted conversations), reactions, personal emojis, sounds and whiteboards (names),
applications, terms acceptances, the account's node-level audit entries and entries naming it, notices about its
content (no reporter data), shared nodes, retention, and the messages it wrote (plaintext content; encrypted ones as
metadata). Never in it: password hash, TOTP secret, recovery codes, passkey keys, refresh tokens, secret storage and
key backups, identity and device keys, KeyPackages, ciphertext, file bytes, other users' messages or profiles.

**Streamed, no background job (decision).** The archive is streamed: the account sections are built at once, the
messages follow page by page (500) straight from the database. Memory stays flat for any account size, the response
starts immediately (the 30-second request timeout does not apply to the body), no temporary file and no download
token are needed. The web client saves the answer as `tavrn-export-<username>-<date>.json`.

### 3.2 Erasure (Art. 17): `DELETE /users/me`

Body `{ confirm: <username>, delete_messages }`, reauth token required (`403 auth.reauth_required`),
`400 account.confirm_mismatch`, `409 account.owns_rooms` (`meta.rooms`: transfer the rooms to another member,
`POST /rooms/{id}/transfer` of `MODERATION.md` §4, or delete them first), `409 account.deleted`, `403 federation.local_only` for remote users. The deletion is
immediate (no admin step) and answers `202` with `{ id, state, delete_messages, messages_total, messages_done,
purge_after, status_token }`; `GET /account-deletions/{id}?token=` shows the progress (same `404` for every miss).

Owner decisions (2026-10-06):

1. **Default: the account goes, messages stay as "Deleted user".** A new tombstone row (`deleted-<16 hex>@<domain>`,
   display name "Deleted user", disabled) takes over the account's messages, pins, uploads, room emojis and sounds,
   issued bans and invites, open notices and audit entries. Device ids and signatures are stripped from the
   messages, so nothing in the envelopes links back to the account; replies and threads keep their place. Messages
   carry `author_deleted: true`; clients show "Deleted user" (translated) without avatar, profile or link. Entries the
   node wrote about the user (welcome channel joins and leaves, key changes) are deleted because they carry the name.
2. **"Also delete my messages and files"** (`delete_messages: true`): a background job replaces the content of every
   message of the tombstone (plaintext and ciphertext) with `{"type":"system.deleted"}` (`encrypted: false`, mentions,
   epoch, device id and signature cleared), deletes their attachments (rows and files) and search terms, in batches of
   500 with progress in `messages_done`; clients get `message.redact { conversation_id, ids }` per batch and drop the
   content from caches and local search indexes. Housekeeping resumes a job a restart interrupted.
3. **Federation:** `user.deleted { delete_messages }` goes to every node that knows the user (§3.3).
4. **Always deleted at once:** profile (avatar, header, background, bio, links, status), presence, linked accounts
   for normal use, devices and keys (MLS leaves get `mls.remove_needed` through the existing removal paths),
   sessions and federated sessions, secret storage and key backups, friends, friend requests and blocks, room and DM
   memberships, personal emojis, sounds and whiteboards, notification settings, read markers, second factors,
   applications (owner cascade: tokens, devices, memberships; the bots stay as tombstones), admin tokens, terms
   acceptances. **Kept pseudonymised** with their own retention: audit log entries (actor id and the address in their
   texts become the tombstone's) and open legal notices (target = tombstone).
5. **Undo:** the account row stays disabled with only what an undo needs — username (reserved), password hash,
   e-mail, single sign-on link — for `TAVRN_ACCOUNT_DELETE_GRACE_DAYS` (default 30). `POST /admin/users/{id}/undelete`
   moves the references back (messages, uploads, …; content deleted by the job stays deleted) and re-enables the
   login; the user signs in again, sets up a second factor and a new key; memberships, friends and devices do not
   come back. Afterwards housekeeping erases the row (everything still tied to it cascades) and the username is free.
6. **Access** is self-service (§3.1).

Node admins act on a user's request with the same rules: `GET /admin/users/{id}/export`, `POST
/admin/users/{id}/delete { confirm, delete_messages }` (both need the admin's reauth token, are audited as
`admin.user_export` / `admin.user_delete`, and refuse admin API tokens), `GET /admin/account-deletions` (progress
and undo). The account gets a mail when it has an e-mail address.

### 3.3 Other nodes

`user.deleted` (FEDERATION.md §5.2) goes to the domains the account obtained federation tokens for, the home
domains of its friends and DM contacts, and the nodes of its conversation index. The receiving node tombstones its
stub the same way (memberships, sessions, devices, keys, friendships go; messages move to a "Deleted user" tombstone
with stripped envelopes; content and files are deleted when `delete_messages`), records `federation.user_deleted`
with the origin in its audit log and removes the stub. **Each node is its own controller:** the home node requests
the deletion and logs that it sent it; it cannot enforce what another node does. An undo on the home node does not
undo anything on other nodes.

## 4. Which rules apply where (orientation, not advice)

- **EU, Digital Services Act (Regulation (EU) 2022/2065).** Hosting services need a notice-and-action mechanism
  (Art. 16), statements of reasons (Art. 17), points of contact (Art. 11, 12). Online platforms additionally need an
  internal complaint-handling system (Art. 20) and measures against misuse (Art. 23). Small nodes may be exempt from
  some platform duties (Art. 19); the operator decides. The counter-notice here doubles as the complaint route.
- **EU, GDPR (Regulation (EU) 2016/679).** Each node is the controller of the data it holds (Art. 4(7)); access and
  portability (Art. 15, 20) and erasure (Art. 17) are self-service; the privacy policy (Art. 13) is the operator's.
  Forwarding notices and deletion requests to other nodes discloses personal data to other controllers.
- **US, DMCA §512 (17 U.S.C. §512).** The safe harbour for user content needs a designated agent registered with the
  US Copyright Office (§512(c)(2)), notice-and-takedown (§512(c)(3)), counter-notices with the 10–14 business day
  restore window decided by the operator (§512(g)) and a repeat-infringer policy (§512(i)).
- **Germany.** Imprint: § 5 DDG (Digitale-Dienste-Gesetz) and § 18 Abs. 2 MStV; storage on end devices: § 25 TDDDG
  (the app stores only what is strictly necessary: session tokens and the encrypted key store); accessibility: BFSG
  for some commercial operators (design note 4.14 item 4). The NetzDG notice procedures were replaced by the DSA.

## 5. Operator settings

| Variable | Default | |
|---|---|---|
| `TAVRN_LEGAL_NOTICES` | `off` | the public notice form |
| `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR` | `5` (1000 in `--dev`) | notices per client address and hour |
| `TAVRN_LEGAL_NOTICE_RETENTION_DAYS` | `1095` | days a case is kept after its last change (30–36500) |
| `TAVRN_LEGAL_REPEAT_THRESHOLD` | `3` | actioned cases after which the admin page suggests disabling (1–100) |
| `TAVRN_LEGAL_COUNTER_NOTICE_DAYS` | `14` | counter-notice window (1–365) |
| `TAVRN_LEGAL_TERMS_MODE` | `notice` | `notice` or `require` |
| `TAVRN_ACCOUNT_DELETE_GRACE_DAYS` | `30` | undo window of deletions, username reservation (1–365) |

Templates (shipped with `tavrn-node`): `privacy-template.en.md`, `privacy-template.de.md`, `imprint-template.de.md`,
`terms-template.en.md`. They start with a "template, not legal advice" notice. Fields the operator must check before
publishing: the controller and data protection officer, hosting provider and location, the optional third parties
actually used (SMTP, Turnstile with its transfer basis, GIF provider, OIDC provider, external file storage, Valkey),
attachment, log, audit log and backup retention, the supervisory authority, the minimum age, and in the imprint the
postal address (no P.O. box), representatives, register and VAT numbers and the person responsible under § 18 MStV.
