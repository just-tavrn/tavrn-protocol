# Changelog

Changes of the protocol that implementations must follow, newest first. Versions are the tags of this repository
(`README.md` "Versioning and capabilities").

## Unreleased

- **Encryption review** (`ENCRYPTION.md`). Messages carry a signed context `ctx { thread_id, reply_to }` inside the
  encrypted JSON; receivers compare it with the envelope and show a mismatch as `envelope_mismatch` (content without
  `ctx` stays valid, §5.2). Devices under a changed, unacknowledged identity key are not added to DMs and are ghosts
  with the reason `key_changed` until the user acknowledges (§3.3, §4.6). Senders do not send after a failed
  catch-up; nodes accept new content only under the current epoch or the previous one within 60 seconds of its
  commit, otherwise `409 mls.epoch_stale` with `meta.epoch` (§5.3). The sample message of a history key check must
  carry a valid content signature (§7b step 4). Notes: old secret-storage entries stay valid until an identity reset
  (§2.4), history shares are readable by every current member (§7b), forced rejoin (§11). New reference values in
  `testvectors/encryption.json`: `content_context`, `history_share`, `local_storage_key`, `whiteboard_scene`,
  `device_login`, `sealed_unlock`.
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
