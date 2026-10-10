# Changelog

Changes of the protocol that implementations must follow, newest first. Versions are the tags of this repository
(`README.md` "Versioning and capabilities").

## Unreleased

- **Moving members into channels they may not view or connect to** (`VOICE.md` §7 "Moved participations",
  `permissions.md`, `PROTOCOL.md` §6, `ENCRYPTION.md` §4.5). `…/voice/members/{address}/move` and
  `/voice/move-all` need only the mover's permissions; `voice.target_forbidden` now means "below the target's age
  gate" (before: no `connect` in the target). Each move leaves a single-use grant (60 seconds) that entitles the
  member's next join of the target without `connect` and beyond its `user_limit`; the participation that follows is
  marked `moved: true` in `VoiceParticipant` (new field) and lasts until the member leaves or is removed (a rejoin
  within the reconnect grace period keeps it). Meanwhile the member views the channel (`channel.create` before
  `voice.move`, its events, `GET /rooms/{id}`, its MLS group, reading its messages) and the access watcher and the
  `/rtc` proxy accept them without `view_channel` or `connect`; when it ends they get `channel.delete
  { hidden: true }` and their leaves are announced with `mls.remove_needed`. No self-rejoin without `connect`.
- **History since the join under `since_join`** (`ENCRYPTION.md` §7b, `PROTOCOL.md` §6, `FILES.md` §8.7). The history
  window belongs to the room membership: messages (and entry records of files channels) posted after a member's room
  join but before its device first entered the channel's MLS group are part of the member's history under every
  policy. Nodes therefore mark such members `history_pending` also under `since_join` (encrypted content in the window
  from before the device's first leaf; `view_channel` and `read_history` as before), list them in `…/history-pending`
  and accept `POST …/history-keys` under `since_join` (no more `403 history.forbidden` for the policy; the recipient's
  window still bounds what its node serves and its client accepts). Sharing clients send the epochs of the encrypted
  messages since the recipient's join; every window lookup of a sharing client includes thread messages (`GET
  …/messages?…&threads=all`), so forum posts count. Clients join the groups of a room's encrypted channels the user
  may view when the room is loaded, one after the other, so the gap stays small.
- **History shares v2 and signed titles and answers** (`ENCRYPTION.md`, capability `history.shares2`). Every device
  has an X25519 share key, signed by its device key, published with the device key (`PUT
  /users/me/devices/{id}/key` gets `share_public_key` and `share_key_signature`) or once with the new `PUT
  /users/me/devices/{id}/share-key` (`409 e2ee.share_key_exists`, `400 e2ee.share_key_invalid`), and served in the
  keys document next to the attestation (§3.1). History shares of format 2 encrypt the payload (`"v": 2`) under a
  fresh key and seal it to every roster device of the recipient: `POST …/history-keys` takes `v` and `boxes` (1–20,
  each at most 128 bytes, devices attested with a share key, `400 history.invalid`), `GET` returns `v` and the
  requesting device's own `box` and omits format 2 shares without one (§7b). Clients send format 2 when the node
  announces the capability and every roster device of the recipient has a verified share key, format 1 otherwise;
  format 1 is to be removed. Encrypted thread titles carry `ctx { thread_id }`, bot answers to interactions
  `ctx { thread_id, reply_to, interaction }`; a mismatch is `envelope_mismatch` (§5.2, `PROTOCOL.md` §7e,
  `APPLICATIONS.md` §5.7). New reference values in `testvectors/encryption.json`: `device_share_key`,
  `history_share_v2`.
- **Encryption review** (`ENCRYPTION.md`). Messages carry a signed context `ctx { thread_id, reply_to }` inside the
  encrypted JSON; receivers compare it with the envelope and show a mismatch as `envelope_mismatch` (content without
  `ctx` stays valid, §5.2). Devices under a changed, unacknowledged identity key are not added to DMs and are ghosts
  with the reason `key_changed` until the user acknowledges (§3.3, §4.6). Senders do not send after a failed
  catch-up; nodes accept new content only under the current epoch or the previous one within 60 seconds of its
  commit, otherwise `409 mls.epoch_stale` with `meta.epoch` (§5.3). The sample message of a history key check must
  carry a valid content signature; a message whose author device cannot be verified at all (the recipient's own
  device from before an identity reset) is passed over for the next one (§7b step 4). Notes: old secret-storage
  entries stay valid until an identity reset (§2.4), history shares are readable by every current member (§7b),
  forced rejoin (§11). New reference values in `testvectors/encryption.json`: `content_context`, `history_share`,
  `local_storage_key`, `whiteboard_scene`, `device_login`, `sealed_unlock`.
- **Authorization audit, round 2.** Metadata audiences (`PROTOCOL.md` §6 "Audiences of the room's metadata"):
  `channel.*` and a channel's `override.update` reach only the members to whom the channel is listed, `category.*`
  and a category's `override.update` those to whom the category is listed; members who gain a channel get
  `channel.create` (and `category.create`), members who lose one `channel.delete` / `category.delete` with the new
  field `hidden: true`. `GET /rooms/{id}` lists only the overrides of listed channels and categories. Moving
  channels (`permissions.md` "Moving channels"): deleting a category or moving a channel out of it copies the
  category's overrides into the channel (audit `channel.overrides_copied`); moving into a category that grants more
  needs `manage_roles`. Timeouts: typing needs `send_messages`, ephemeral events answer `403 member.timed_out`
  (`WHITEBOARD.md` §2.1). Voice participants who lose `view_channel` or `connect` are disconnected, members leaving
  a group DM leave its call (`VOICE.md` §5, §11). Federation (`FEDERATION.md` §1.5, §3.5, §5.2): per-domain limits
  only after the signature check, per address before it; the receiver's own users named as inviter, caller or claim
  requester must have signed in on the sending node; `notify` hints only for recipients who did.
- **Permissions: layered overrides** (`permissions.md` "Evaluation", "Channel-scoped bits", "Changes"). The
  evaluation applies the role base, then the category's overrides, then the channel's own overrides; a neutral bit
  inherits from the layer below. The channel field `sync_with_category` is removed (`GET` no longer returns it,
  `PATCH` ignores it for one release). Overrides carry only the bits of `CHANNEL_SCOPED` (value `103049789951`);
  others are refused with `400 permissions.not_channel_scoped`, and nodes strip them from existing overrides at start
  (audit action `role.override_restricted`). New and changed cases in `testvectors/permissions.json` ("Layered: …");
  the vectors no longer carry `sync_with_category`. Bit 37 `restore_history` is room-level, not channel-scoped.
