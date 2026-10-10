# Permissions (bit positions, normative)

Permissions are a 64-bit mask, transported over the API as a decimal string. Bit positions are **never**
reassigned; new permissions get new positions. Reference implementations: `permissions.rs` in `tavrn-node` (Rust)
and `permissions.ts` in `@tavrn/sdk` (`tavrn-js`, TypeScript); both must pass `testvectors/permissions.json`.

| Bit | Name | Meaning |
|---|---|---|
| 0 | `view_channel` | See the channel and read its history. Without it no other permission applies in the channel. |
| 1 | `send_messages` | Send messages |
| 2 | `manage_messages` | Delete other people's messages, bypass slowmode |
| 3 | `attach_files` | Attach files |
| 4 | `add_reactions` | Add reactions |
| 5 | `mention_everyone` | Mention `@everyone` and `@here` |
| 6 | `create_threads` | Start threads and write in them (text and announcement channels; forum posts need `send_messages` only, `PROTOCOL.md` §7e) |
| 7 | `manage_channels` | Create, edit and delete channels and categories (including the encryption switch) |
| 8 | `manage_roles` | Manage roles and overrides (only below your own highest role, only permissions you hold) |
| 9 | `manage_room` | Room settings, invites |
| 10 | `create_invites` | Create invite links |
| 11 | `kick_members` | Remove members |
| 12 | `ban_members` | Ban members and domains |
| 13 | `moderate_members` | Timeouts; receives auto-moderation alerts |
| 14 | `purge` | Bulk deletion (time range, author, channel history) |
| 15 | `view_audit_log` | Read the audit log |
| 16 | `connect` | Join a voice channel |
| 17 | `speak` | Speak |
| 18 | `stream` | Share screen or window |
| 19 | `mute_members` | Mute others |
| 20 | `move_members` | Move others between voice channels, also into channels they may not view or connect to (they see the channel while connected) |
| 21 | `use_soundboard` | Use the soundboard |
| 22 | `manage_emojis` | Manage custom emojis and sounds |
| 23 | `change_nickname` | Change own nickname |
| 24 | `manage_nicknames` | Change other people's nicknames |
| 25 | `pin_messages` | Pin messages |
| 26 | `use_camera` | Share the camera |
| 27 | `use_whiteboard` | Open a whiteboard in the channel (voice channels also need `connect`); viewing a board only needs read access (phase 4E) |
| 28 | `manage_whiteboard` | Close any whiteboard and change who may edit someone else's board (phase 4E) |
| 29 | `manage_webhooks` | Manage the channel's webhooks (reserved in phase 4E, routes in phase 5, `APPLICATIONS.md` §6) |
| 30 | `priority_speaker` | May activate priority speaking in voice channels (others are ducked while they hold the key, design note 4.13) |
| 31 | `use_external_emojis` | Use custom emojis of other rooms and personal emojis in this room (default for `@everyone`, design note 4.13) |
| 32 | `use_external_sounds` | Play soundboard clips of other rooms and personal clips in this room (default for `@everyone`, design note 4.13) |
| 33 | `manage_files` | Files channels: rename, move and delete entries of others (own entries need `attach_files`, which also uploads and creates folders), configure the storage backend together with `manage_channels` (design note 4.13, `FILES.md`) |
| 34 | `read_history` | Encrypted channels: read messages from before joining as far as the channel's `history_for_new_members` policy allows, and receive their keys from other members (default for `@everyone`, design note 4.13 item 11, `ENCRYPTION.md` §7b). Without it the history starts at the member's join. Plaintext messages are not affected. |
| 35 | `manage_applications` | Install and remove applications (bots) in the room and edit the room's command settings (`APPLICATIONS.md` §4.2, §4.3, §5.3). The managed role of an installation additionally needs `manage_roles`, and the bot never gets more than the installer holds. Covered by the app token scope `rooms:manage`; bots still cannot install bots. |
| 36 | `manage_threads` | Rename, archive, lock and delete other people's threads and edit the tags of any forum post (`PROTOCOL.md` §7e). Covered by the app token scope `moderation`. |
| 37 | `restore_history` | Encrypted channels: decide about requests to restore a member's history after a key reset and send the keys from before the reset (`ENCRYPTION.md` §7b "History after a key reset"). Default: nobody besides the owner and `administrator`; no app-token scope covers it. |
| 62 | `administrator` | All permissions, overrides are ignored |

Default permissions of `@everyone` in new rooms: `view_channel`, `send_messages`, `attach_files`, `add_reactions`,
`create_threads`, `create_invites`, `connect`, `speak`, `stream`, `use_camera`, `use_soundboard`, `change_nickname`,
`use_whiteboard`, `use_external_emojis`, `use_external_sounds`, `read_history`. Migration 0060 added `use_whiteboard` to
the `@everyone` role of every existing room, so boards keep working where they did; `read_history` is added once to
the `@everyone` role of every room that existed before it (startup fixup, recorded in `node_settings` so a later
removal by the room is kept). `manage_applications` (bit 35) replaced `manage_room` as the right to install applications:
a startup fixup grants it once to every role that held `manage_room` when the bit was introduced (marker
`fixup.manage_applications`), so nobody loses the ability; rooms may narrow it afterwards. `manage_threads` (bit 36)
is granted the same way once to every role that held `manage_messages` when it was introduced (marker
`fixup.manage_threads`), so moderators keep moderating threads.

`change_nickname` covers the whole per-room profile (nickname, avatar and bio in that room, `PROTOCOL.md` §6b);
`manage_nicknames` lets moderators change or reset the per-room profiles of members below them.

## System channels

The welcome channel (`kind = "system"`, `system_name = "welcome"`) is the room's security log (`PROTOCOL.md` §7). It
is visible and read-only for every member, owners and administrators included. After the evaluation below (the
input flag `system_channel`):

- `SYSTEM_CHANNEL_FORCED` = `view_channel` | `read_history` is added: no override (on the channel or its category,
  for `@everyone`, a role or the member), no missing room-level bit and no timeout can hide the channel or its
  history;
- `SYSTEM_CHANNEL_DENIED` = `send_messages` | `attach_files` | `create_threads` | `mention_everyone` |
  `pin_messages` | `use_whiteboard` is removed;
- then the bot branch applies as everywhere (a bot in a "no bots" zone still has nothing).

The room cannot switch the channel off (the former setting `welcome_channel_enabled` is gone); reactions follow the
normal bits. Its entries cannot be deleted by anyone, `manage_messages`, owners and node admins included
(`MODERATION.md` §3). The shared test vectors
(`testvectors/permissions.json`) cover the forced and the denied bits.

## Upload categories

Which kinds of files a member may attach is a per-role setting, not a permission bit (`PROTOCOL.md` §7a): roles
carry `allowed_upload_categories` (null = not set), overrides carry `upload_allow` / `upload_deny`. Evaluation:
the member's highest role (by position) with a value decides, else `@everyone`; then the same layers as below
(the category's overrides, then the channel's own on top), each in the same order (`@everyone` override, all role
overrides deny-then-allow, the member override); an upload category that a layer neither allows nor denies keeps
the value of the layer below. Owners, node admins and `administrator` may upload every category; executables additionally
need the node setting.

## Restricted for @everyone

Management-class permissions can never be granted to `@everyone`, neither in the role itself nor through an
`@everyone` override (allow) on a category or channel (design note 4.11). Nodes refuse such updates with
`400 role.everyone_restricted`; clients grey the bits out for `@everyone` and explain why. Reference constant:
`EVERYONE_RESTRICTED` in `@tavrn/sdk`.

| Bit | Name |
|---|---|
| 2 | `manage_messages` |
| 7 | `manage_channels` |
| 8 | `manage_roles` |
| 9 | `manage_room` |
| 11 | `kick_members` |
| 12 | `ban_members` |
| 13 | `moderate_members` |
| 14 | `purge` |
| 15 | `view_audit_log` |
| 19 | `mute_members` |
| 20 | `move_members` |
| 22 | `manage_emojis` (emojis and soundboard sounds) |
| 24 | `manage_nicknames` |
| 28 | `manage_whiteboard` |
| 29 | `manage_webhooks` |
| 33 | `manage_files` |
| 35 | `manage_applications` |
| 36 | `manage_threads` |
| 37 | `restore_history` |
| 62 | `administrator` |

New management-class bits are added to this list when they are introduced. Denying any of them to `@everyone`
stays allowed. The same constant lives in the node (`tavrn-node`, value `4611686268363406212`).

Nodes remove these bits from existing `@everyone` roles and `@everyone` overrides at start (idempotent) and record
every removal in the room's audit log as `role.everyone_restricted` (`meta`: `kind` role|override, `removed`,
`names`).

## Channel-scoped bits

Overrides (on categories and on channels) may only carry bits that mean something inside a channel. A
`PUT /rooms/{room_id}/overrides` whose `allow` or `deny` contains another bit is refused with
`400 permissions.not_channel_scoped` (`meta.names`: the refused bit names); room-level bits are granted through
roles only. Reference constant: `CHANNEL_SCOPED` in the node (`tavrn-node`) and in `@tavrn/sdk`, value
`103049789951`. Clients list only these bits in override editors.

| Bit | Name |
|---|---|
| 0 | `view_channel` |
| 1 | `send_messages` |
| 2 | `manage_messages` |
| 3 | `attach_files` |
| 4 | `add_reactions` |
| 5 | `mention_everyone` |
| 6 | `create_threads` |
| 7 | `manage_channels` |
| 8 | `manage_roles` |
| 16 | `connect` |
| 17 | `speak` |
| 18 | `stream` |
| 19 | `mute_members` |
| 20 | `move_members` |
| 21 | `use_soundboard` |
| 25 | `pin_messages` |
| 26 | `use_camera` |
| 27 | `use_whiteboard` |
| 28 | `manage_whiteboard` |
| 29 | `manage_webhooks` |
| 30 | `priority_speaker` |
| 31 | `use_external_emojis` |
| 32 | `use_external_sounds` |
| 33 | `manage_files` |
| 34 | `read_history` |
| 36 | `manage_threads` |

Room-level only (roles, never overrides): `administrator`, `manage_room`, `create_invites`, `kick_members`,
`ban_members`, `moderate_members`, `purge`, `view_audit_log`, `manage_emojis`, `change_nickname`, `manage_nicknames`,
`manage_applications`, `restore_history` (bit 37: a decision about a member's history in the room's encrypted
channels, not a right inside one channel). New bits state whether they are channel-scoped when they are introduced. The `@everyone` restriction above
applies to overrides as well: a channel-scoped bit in `EVERYONE_RESTRICTED` still cannot be allowed for `@everyone`.

Nodes remove bits outside `CHANNEL_SCOPED` from the `allow` and `deny` masks of existing overrides at start
(idempotent; an override left with nothing is deleted) and record every change in the room's audit log as
`role.override_restricted` (`target`: the category or channel id; `meta`: `target_type`, `subject_type`,
`subject_id`, `removed`, `names`).

## Evaluation

The evaluation is layered (since 2026-10-09; it replaced the earlier "synced with its category" rule, see
"Changes" below): role base → category overrides → channel overrides.

1. `base = everyone | OR(member's roles)`. Owner, node admin or `administrator` → all permissions, done.
2. **Category layer**: if the channel belongs to a category, the category's overrides apply to `base`.
3. **Channel layer**: the channel's own overrides apply to the result of step 2.
   Order inside each layer: `@everyone` override (deny, then allow) → all role overrides of the member (all denies
   first, then all allows, each unioned) → member override (deny, then allow). Only the bits of `CHANNEL_SCOPED`
   (below) of an override take part; other bits in stored data are ignored.
   A bit that an override neither allows nor denies (the neutral state "–") inherits the value of the layer below:
   a channel override always wins over the category, which wins over the role base.
4. If `view_channel` is missing afterwards, the result is 0.
5. Members in timeout keep only `view_channel` and `read_history` (a timeout limits writing, not reading).
   Typing notices need `send_messages`; ephemeral events (cursors, whiteboard strokes) are refused in a timeout
   (`403 member.timed_out`, `WHITEBOARD.md` §2.1).

Age gates (`PROTOCOL.md` §5e) come before this evaluation: in a channel whose effective `age_gate` is
`adults_only`, a member below it (a minor or a user of unknown age) has 0, owners and node admins included. The gate
is not an input of `testvectors/permissions.json`; implementations apply it around the evaluation.

**Moved participations** (`VOICE.md` §7): in the voice channel into which a moderator moved a member, from the move
until the moved participation ends, `view_channel`, `read_history` and `connect` are added after step 3 (before
step 4), whatever the overrides deny. Steps 4 and 5, the bot cap and the age gate apply as usual, so a timeout
still leaves only reading. Like the age gate this is node state, not an input of the test vectors.

Example: the `@everyone` role lacks `view_channel`, the category has no override for it ("–"), and the channel
allows `view_channel` for `@everyone`: every member sees that channel. A category is a container, not a permission
target for viewing: clients show it as soon as at least one of its channels is visible. A category that allows
`view_channel` and a channel in it that denies it: the channel is hidden. The shared test vectors cover these
cases ("Layered: …").

**Moving channels.** A channel that leaves its category (the category is deleted, or the channel moves to another
category or to none) would lose the category layer. The node first writes the category's overrides into the
channel's own: per subject, a bit the channel's override sets stays, a bit it leaves neutral takes the category's
value; a bit the channel's `@everyone` override decides is decided for everybody in the channel layer and is not
copied. One layer cannot express every pair of layers (a category allow for one role and a channel deny for another
role a member also holds: in one layer the allow would win), so a member who would still gain a permission gets a
member override denying it. Nothing becomes visible or allowed that was not; the result may be narrower. Audited as
`channel.overrides_copied` (`{ category_id, to, overrides, members_denied }`), announced as `override.update`.
Moving a channel without a category **into** one applies the category's overrides underneath the channel's from
then on; when that grants anybody more than before, the actor needs `manage_roles` in that category
(`403 role.manage_forbidden`), as for setting those overrides.

Hierarchy: roles have a position (`@everyone` = 0). Members can only manage or assign roles below their own
highest position, only grant permissions they hold themselves, and only kick, ban or time out members whose
highest role is lower. Owners outrank everything, node admins as well.

## Bots (`APPLICATIONS.md` §2.4, §3.5)

The evaluation input carries three more fields: `kind` (the account kind, default `user`), `no_bots` (the channel's
effective "no bots" flag, see below) and `scopes` (the effective scopes of the bot's token;
absent = all scopes). For every `kind` except `user` (bots, webhooks and kinds a client does not know, fail
closed) the result of steps 1–5 is capped afterwards:

6. `no_bots` set → 0, whatever roles, overrides, ownership or administrator say.
7. Otherwise `perms ∩ (ALWAYS ∪ ⋃ bits(scope))` with `ALWAYS = view_channel | change_nickname` and the scope bits
   of `APPLICATIONS.md` §2.4. Owner and administrator expand to all bits first, so a bot's administrator role is
   masked by its scopes; `administrator` itself is never part of any scope.
8. If `view_channel` is missing afterwards, the result is 0.

Room-level permissions of a bot (`my_permissions`) are capped the same way with the room's flag.

**Effective "no bots" flag** of a channel (`APPLICATIONS.md` §3.5): `room.no_bots ∨ category.no_bots ∨
channel.no_bots ∨ (channel encrypted ∧ ¬channel.bots_allowed ∧ room.bots_in_encrypted_channels ≠ "allowed")`. The room
setting `bots_in_encrypted_channels` is `per_channel` (default of new rooms; every encrypted channel is closed to bots
unless the channel allows them) or `allowed` (rooms that existed before the setting; encrypted channels follow the
flags only); unknown values count as `per_channel`. `bots_allowed` never opens a channel that one of the three flags
closes. Reference: `no_bots_effective` / `noBotsEffective`, vectors in `testvectors/no_bots.json`. Reference: `SCOPES`,
`scope_mask` and `cap_bot` in the node (`tavrn-node`) and `@tavrn/sdk`; test vectors with `kind`,
`no_bots` and `scopes` in `testvectors/permissions.json`.

## Changes

- **2026-10-11, moved participations**: a member moved into a voice channel by a moderator with `move_members`
  holds `view_channel`, `read_history` and `connect` there while the moved participation lasts ("Evaluation"
  above, `VOICE.md` §7); before, a move needed `connect` of the member in the target.

- **2026-10-09, layered overrides**: the evaluation applies the category's overrides and then the
  channel's own on top (above) instead of either the category's (a channel "synced with its category") or the
  channel's. The channel field `sync_with_category` is removed: `GET` no longer returns it, `PATCH` ignores it
  (accepted and ignored for one release, then unknown). A channel without own overrides behaves exactly as a synced
  channel did; a channel with own overrides now also inherits its category's overrides underneath. Overrides carry
  `CHANNEL_SCOPED` bits only (`400 permissions.not_channel_scoped`, start-up strip with `role.override_restricted`).
  Node and client ship together in this development phase, so there is no capability for the change.
- **2026-10-09, moving channels**: deleting a category or moving a channel out of it copies the category's
  overrides into the channel ("Moving channels" above); moving a channel into a category that grants more needs
  `manage_roles`. Before, a private channel became public when its category was deleted.
