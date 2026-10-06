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
| 6 | `create_threads` | Create threads |
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
| 20 | `move_members` | Move others between voice channels |
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
| 62 | `administrator` | All permissions, overrides are ignored |

Default permissions of `@everyone` in new rooms: `view_channel`, `send_messages`, `attach_files`, `add_reactions`,
`create_threads`, `create_invites`, `connect`, `speak`, `stream`, `use_camera`, `use_soundboard`, `change_nickname`,
`use_whiteboard`, `use_external_emojis`, `use_external_sounds`, `read_history`. Migration 0060 added `use_whiteboard` to
the `@everyone` role of every existing room, so boards keep working where they did; `read_history` is added once to
the `@everyone` role of every room that existed before it (startup fixup, recorded in `node_settings` so a later
removal by the room is kept). `manage_applications` (bit 35) replaced `manage_room` as the right to install applications:
a startup fixup grants it once to every role that held `manage_room` when the bit was introduced (marker
`fixup.manage_applications`), so nobody loses the ability; rooms may narrow it afterwards.

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

The room cannot switch the channel off (the former setting `welcome_channel_enabled` is gone); reactions and the
deletion of entries by moderators follow the normal bits. The shared test vectors
(`testvectors/permissions.json`) cover the forced and the denied bits.

## Upload categories

Which kinds of files a member may attach is a per-role setting, not a permission bit (`PROTOCOL.md` §7a): roles
carry `allowed_upload_categories` (null = not set), overrides carry `upload_allow` / `upload_deny`. Evaluation:
the member's highest role (by position) with a value decides, else `@everyone`; then the overrides chosen by the
same synchronisation rule as below, in the same order (`@everyone` override, all role overrides deny-then-allow,
the member override). Owners, node admins and `administrator` may upload every category; executables additionally
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
| 62 | `administrator` |

New management-class bits are added to this list when they are introduced. Denying any of them to `@everyone`
stays allowed. The same constant lives in the node (`tavrn-node`, value `4611686062204976004`).

Nodes remove these bits from existing `@everyone` roles and `@everyone` overrides at start (idempotent) and record
every removal in the room's audit log as `role.everyone_restricted` (`meta`: `kind` role|override, `removed`,
`names`).

## Evaluation

1. `base = everyone | OR(member's roles)`. Owner, node admin or `administrator` → all permissions, done.
2. Overrides: if the channel is **synced with its category**, the category's overrides apply; otherwise only
   the channel's own overrides. Setting a channel override automatically unsyncs the channel (as is common today).
3. Order within the overrides: `@everyone` override (deny, then allow) → all role overrides of the member
   (all denies first, then all allows, each unioned) → member override (deny, then allow).
4. If `view_channel` is missing afterwards, the result is 0.
5. Members in timeout keep only `view_channel` and `read_history` (a timeout limits writing, not reading).

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
