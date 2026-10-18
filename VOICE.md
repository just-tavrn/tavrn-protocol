# tavrn voice, video and screen sharing (`voice`, draft v1)

This document specifies voice and video channels, screen sharing, the soundboard and calls in DMs, from the node's
policies and the join flow to the encrypted media and connectivity.

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). Normative for nodes and clients. Capabilities: `voice` (this document), `screenshare` (the
node allows screen sharing), `soundboard` (clips, §8). Media runs through [LiveKit](https://livekit.io), an open
source SFU the node starts as a child process (design note 3.4, §8); clients use a LiveKit SDK. Encryption of the
media: `ENCRYPTION.md` §5a. Error format, ids and addresses: `PROTOCOL.md`.

## 1. Overview

```text
client ──REST──▶ node: POST …/voice/join          → LiveKit token + limits + participants + MLS epoch
client ──WSS───▶ node /rtc ──(token checked)──▶ LiveKit 127.0.0.1:7880   (signaling, proxied)
client ══UDP═══▶ LiveKit TAVRN_RTC_UDP_PORT_RANGE                      (media, end-to-end encrypted)
        (fallbacks: ICE/TCP on TAVRN_RTC_TCP_PORT, embedded TURN over UDP or TLS through the proxy, §10.3)
LiveKit ─webhook─▶ node /api/v1/voice/webhook ──▶ voice.state to the room's members who can view the channel (WebSocket)
node ──every 30 s──▶ LiveKit room service (reconciliation, no ghosts)
```

- A voice channel is a room channel of kind `voice`. It always is a conversation with its own MLS group
  (`ENCRYPTION.md` §4, §5a); its text area works like a text channel.
- One LiveKit room per voice channel, named `<room id>:<channel id>`. One LiveKit participant per device, identity
  `<user address>/<device id>` (for users of other nodes: their home device id), which is also the device's MLS
  leaf identity. A device is in at most one voice channel of a node; joining another channel leaves the old one.
  A device may add one *screen publisher* to its participation (identity `<user address>/<device id>#screen`,
  §4b): a second LiveKit participant that only publishes the device's screen share, for apps whose own WebRTC cannot
  take the platform's screen capture.
- The node is the only issuer of LiveKit tokens and the only way to LiveKit's signaling. Users of other nodes
  join voice channels on the hosting node with their federated session there (`FEDERATION.md`), like any other
  room API.

## 2. Node policies

`/.well-known/tavrn` → `policies` (and `GET /api/v1/node` → `voice`, same values):

```json
"policies": {
  "voice_enabled": true,
  "voice_max_bitrate_kbps": 192,
  "voice_max_participants": 50,
  "screenshare": { "enabled": true, "max_resolution": "1080p", "max_fps": 30 },
  "camera": { "enabled": true, "max_resolution": "720p", "max_fps": 30 }
}
```

`GET /api/v1/node`: `"voice": { "enabled", "max_bitrate_kbps", "max_participants", "screenshare": {…}, "camera": {…} }`.
Capabilities: `voice` and `soundboard` while voice is enabled, `screenshare` while screen sharing is enabled too.
Operators set these with `TAVRN_VOICE_*`, `TAVRN_SCREENSHARE_*`, `TAVRN_CAMERA_*` (design note 8). Resolutions:
screen `720p`, `1080p`, `1440p`, `4k`; camera `360p`, `720p`, `1080p`. Frame rates 1–60.

Channel settings (`PATCH /rooms/{room_id}/channels/{channel_id}`, `manage_channels`): `bitrate_kbps` (8–512, at most
the node's `voice_max_bitrate_kbps`, else `400 channel.bitrate_too_high`; new voice channels default to
`min(64, node max)`) and `user_limit` (0 = unlimited, at most 99). The cap applies to a bitrate that is being set: a
channel whose stored bitrate is above a cap the operator lowered later keeps it (the join caps it, §3) and its other
settings stay editable. `TAVRN_VOICE_MAX_BITRATE_KBPS` defaults to 192, so every client preset of §4a is reachable;
operators lower it to save traffic.

## 2a. Channel status

A voice channel carries a **status**: one line of plain text (`status`, at most 128 characters after trimming, no
control characters, no line breaks; `""` = none) that tells the room what is going on in the channel right now
("Raid night", "Planning until 9", "AFK, back soon"). It is a field of its own next to the text channels' `topic`:
`topic` keeps its meaning (a description, up to 1024 characters, `manage_channels`), the status is short, changes
often and has its own permission, so the two are not merged. The field exists on every channel object (`""` on the
other kinds; setting it there is refused with `400 channel.status_not_voice`).

- **Changing it:** `PATCH /rooms/{room_id}/channels/{channel_id}` `{ "status": "…" }` needs `voice_status`
  (`permissions.md` bit 38, evaluated in the channel like every other bit) and nothing else: a request that
  carries only `status` is open to every member with the bit, in or outside the call, while a request that also
  changes other fields needs `manage_channels` as before. Without the bit: `403 channel.status_forbidden`. The same
  rate limit as every other channel update applies. Audit log entry `channel.voice_status` (`meta.status`, the new
  text, `target` the channel).
- **Propagation:** the channel object carries `status`; a change reaches the room with `channel.update` (the whole
  channel, like every other field) and so, over the home node's API, members of other nodes (`FEDERATION.md`).
- **Clients** show the status under the channel's name in the voice header and in the channel list's tooltip, and
  let members with the bit edit it in place (Enter saves, Escape cancels, a counter for the 128 characters).

## 3. Joining

`POST /api/v1/rooms/{room_id}/channels/{channel_id}/voice/join` (no body, or `{ "role": "device" }`; `{ "role":
"screen" }` asks for the device's screen publisher instead, §4b) → `200`:

```json
{
  "url": "wss://node.example",
  "token": "<LiveKit JWT>",
  "expires_at": "2026-10-05T12:10:00.000Z",
  "room": "01J…:01J…",
  "identity": "alice@node.example/01J…",
  "room_id": "01J…",
  "channel_id": "01J…",
  "epoch": 7,
  "limits": {
    "audio_bitrate_kbps": 64,
    "audio_fec": true,
    "screenshare": { "enabled": true, "max_resolution": "1080p", "max_fps": 30 },
    "camera": { "enabled": false, "max_resolution": "720p", "max_fps": 30 }
  },
  "participants": [ VoiceParticipant, … ],
  "reconnect_grace_secs": 45,
  "ice_aliases": []
}
```

- `url` is the LiveKit server URL: the node's own origin with `ws`/`wss` (`wss://<domain>`; in development
  `ws://<domain>:<port>`). LiveKit SDKs append `/rtc` (or `/rtc/v1`) themselves; pass `url` unchanged to
  `room.connect(url, token)`.
- `token` is valid for 10 minutes to *start* a connection; once connected, LiveKit refreshes it itself. Get a
  new one with another `join` for every new connection (reconnects within the SDK use LiveKit's refreshed token).
- `epoch` is the current epoch of the channel's MLS group, or `null` if the group does not exist yet: then the
  client creates it first (`ENCRYPTION.md` §4.2) and derives the frame key afterwards (§6 below).
- `participants` are the devices LiveKit reports as connected (§5), without the joining device.
- `reconnect_grace_secs` is how long the node keeps a dropped participant as `reconnecting` (§5a); clients
  rejoin automatically within this time.
- `ice_aliases` are extra addresses of the media server (§10.2): clients add every host candidate LiveKit sends
  once more with each alias of the same address family (same port). Empty unless the operator configured more
  addresses than LiveKit takes.
- `limits.audio_bitrate_kbps` = `min(channel bitrate, node maximum)`. `limits.audio_fec`: the node's media server
  negotiates Opus in-band forward error correction (`useinbandfec=1` in its answer), so publishers encode with it and
  a lost packet is partly recovered from the next one; clients that configure Opus themselves switch it on when the
  value is `true` (today always). Browsers do this from the negotiated SDP without an API call. `screenshare.enabled`/`camera.enabled` say
  whether *this participant* may publish them (node policy and permission). Clients MUST NOT publish beyond the
  limits (§4); LiveKit enforces the allowed track sources, the node enforces nothing else on media.

The node checks, in this order: voice enabled (`503 voice.disabled`), room exists (`404 room.not_found`), requester
is a room member (`403 room.not_member`; node admins who are not members cannot join voice), channel exists in the
room (`404 channel.not_found`) and is a voice channel (`400 voice.not_voice_channel`), rate limit
(`429`, 60 joins and state changes per user and minute), not banned (`403 room.banned`), `connect` in the channel
or a moderator's move into it (§7 "Moved participations") (`403 voice.connect_forbidden`; members in timeout keep
only `view_channel` and get this too, also after a move), capacity
(`409 voice.channel_full`, `meta.user_limit`): connected, reconnecting and reserved participants of other users ≥ the
channel's `user_limit` (members with `move_members` and moved members may exceed it) or ≥ `voice_max_participants`
(nobody may exceed that).

A successful join *reserves* a slot for the device for 60 seconds (counted for the limit, invisible to others) until
LiveKit reports the participant. **One voice session per user:** a join of another device of the same user replaces
the user's earlier device in every voice channel of the node; the node disconnects that device in LiveKit (it sees
`PARTICIPANT_REMOVED`). A join of the same device continues its entry (no duplicates, §5a).

**Token grants** (exactly these, nothing else):

| Grant | Value |
|---|---|
| `roomJoin`, `room` | `true`, `<room id>:<channel id>` |
| `canSubscribe` | `true` (listening needs only `connect`) |
| `canPublishSources` | `microphone` if `speak` and not server-muted (§7); `camera` if `use_camera` and camera policy; `screen_share` + `screen_share_audio` if `stream` and screen share policy |
| `canPublish` | `true` if any source is allowed, otherwise `false` (an empty source list would mean "everything" to LiveKit) |
| `canPublishData` | `true` with `speak` and not server-muted (whisper signals, §4c), or with `use_soundboard` (soundboard signals, §8); otherwise `false` |
| `canUpdateOwnMetadata` | `true` with `priority_speaker` (the `priority` attribute, §7a), otherwise `false` |
| `roomAdmin`, `roomCreate`, `roomList`, `roomRecord`, `hidden`, `recorder` | not set |
| `sub` (identity), TTL | `<user address>/<device id>`, 10 minutes |

**Signaling (`/rtc`).** `GET /rtc`, `/rtc/v1` (WebSocket) and `/rtc/validate`, `/rtc/v1/validate` (HTTP) on the
node's domain are forwarded to LiveKit only with a valid token (query `access_token` as the browser SDK sends it, or
`Authorization: Bearer` as native SDKs do; either way the node hands the checked token on to LiveKit as a bearer
header). The node verifies the signature with its LiveKit secret, the issuer, `exp`/`nbf`, that the
token joins a voice channel room, and that its holder is still a member with `connect` (or a moved participation
there, §7) and not banned (for a call,
§11: an accepted member of the conversation while its call runs; a connection-test token, §10.4: only its own test
room). Errors:
`401 voice.token_invalid`, `403 voice.connect_forbidden` (e.g. kicked after the token was issued), `404` for other
paths, `502 voice.unavailable` (LiveKit down), `503 voice.disabled`; LiveKit's own refusals are passed on
(`403 voice.connect_refused` with LiveKit's message). The SDK's own error handling (`ConnectionError`) applies.

## 4. Connecting and publishing (client)

1. Make sure the channel's MLS group exists and this device is a member (external join for public channels,
   `ENCRYPTION.md` §4.2); commit a self update (fresh key, `ENCRYPTION.md` §5a).
2. `POST …/voice/join`, then set up E2EE (§6) and `room.connect(url, token, { autoSubscribe: true })` with
   `e2ee: { keyProvider, worker }`, and `room.setE2EEEnabled(true)` before publishing.
3. Publish within the limits: microphone with `audioPreset`/`maxBitrate = limits.audio_bitrate_kbps * 1000`, Opus
   with DTX (off in music mode, §4a), in-band FEC when `limits.audio_fec`, RED off (it would carry every frame twice
   through the E2EE transform); camera with a resolution and frame rate not above `limits.camera` (simulcast on); screen
   share (`setScreenShareEnabled`) with `resolution`/`frameRate` not above `limits.screenshare`, screen audio
   allowed. Codecs: VP8 or H.264 (the node's LiveKit accepts Opus, RED, VP8 and H.264 only).
4. Report the own state with `PATCH …/voice/state` (§5) whenever the user mutes, deafens or starts/stops
   streaming or the camera.
5. Leave with `room.disconnect()` and `POST …/voice/leave`.

## 4a. Quality presets and music mode (client conventions)

Opus is the only audio codec (WebRTC's mandatory, royalty-free codec; 6–510 kbps; the best quality per bit for speech
and music). A channel has exactly one bitrate: with an SFU every listener receives what a speaker publishes (no
transcoding), so quality is a channel setting, not a per-listener preference. Clients offer these presets for
`bitrate_kbps` (nothing of this is stored by the node besides the number):

| Preset | kbps | Opus | Use |
|---|---|---|---|
| Saver | 8 | narrow-band, "telephone" | still intelligible, least traffic |
| Standard | 32 | wide-band speech | |
| High | 64 | full-band speech | the default of new channels (§2) |
| Studio | 128 | full-band, practically transparent for speech | |
| Music | 192 | stereo, full-band | music mode (below) |
| Custom | 8 – cap | | any other value |

A bitrate that equals a preset shows as that preset, any other as Custom. Presets above the node's
`voice_max_bitrate_kbps` are shown as limited by the node and cannot be chosen; a stored bitrate above the cap shows
the preset with the bitrate the join hands out. The voice panel shows the quality of the current call (preset name,
the kbps in a tooltip) from `limits.audio_bitrate_kbps`.

**Music mode** applies when `limits.audio_bitrate_kbps` ≥ 192 (the Music preset and larger custom values):

- Capture with `echoCancellation`, `noiseSuppression` and `autoGainControl` off and `channelCount: { ideal: 2 }`;
  the client's own noise suppression is skipped too. Voice activation, noise gate and push-to-talk stay as the user
  set them.
- **A mono microphone is never heard on one side only.** The capture is stereo only when the captured track reports
  `channelCount` 2; any other capture is mono and is published as mono Opus (listeners hear it in the middle). A
  two-channel capture whose one channel stays silent (a single microphone on a two-input interface: one channel below
  −70 dBFS while the other is above −60 dBFS) carries the live channel on both sides; it becomes stereo as soon as
  both channels carry signal (above −60 dBFS) for 250 ms. Until the first decision both sides carry the average of
  the two channels; a stereo capture falls back to the live channel after one side was silent for 2 s while the other
  carried signal.
- Publish: Opus stereo (`stereo=1`) only for a stereo capture, DTX off (it would cut quiet passages and reverb tails),
  RED off, `maxBitrate = limits.audio_bitrate_kbps × 1000`.
- Traffic: 192 kbps are about 86 MB per hour for every speaker and listener; the client says so next to the preset.

Calls in DMs (§11) are speech: their limits carry `min(64, node maximum)`.

## 4b. Screen publishers (native screen sharing)

Some clients cannot publish a screen share from the connection that carries their voice: Android's webview, for
example, has no `getDisplayMedia` and its WebRTC takes no video from the system's screen capture. Such a client
publishes the screen from a native LiveKit SDK as a **second participant bound to the same device**, the device's
*screen publisher*. It is the device's screen share, not a participant of its own.

**Join.** `POST …/voice/join` with `{ "role": "screen" }` (calls: `POST /conversations/{id}/call/join` with the same
body, §11.1). The node checks everything of §3 (calls: §11.1) and then, in this order:

- the requesting device has a participant in this channel or call (reserved, connected or reconnecting), else
  `409 voice.not_connected` (a screen publisher never comes alone);
- screen sharing is allowed for it: the `stream` permission in the channel and the node's screen share policy (calls:
  the policy), else `403 voice.stream_forbidden`;
- the device has no screen publisher yet: one that is connected or reconnecting, or reserved within the last 60
  seconds, refuses the join with `409 voice.screen_active` (one screen publisher per device; leave it first, below).

The answer is the `VoiceJoin` of §3 (calls: `CallJoin`) for identity **`<user address>/<device id>#screen`**, with the
owner's limits, and a token with exactly these grants:

| Grant | Value |
|---|---|
| `roomJoin`, `room` | as for the device |
| `canSubscribe` | `false` (it never receives anything) |
| `canPublishSources` | `screen_share`, `screen_share_audio` |
| `canPublish` | `true` |
| `canPublishData`, `canUpdateOwnMetadata` | `false` |
| `sub` (identity), TTL | `<user address>/<device id>#screen`, 10 minutes |

The `/rtc` proxy accepts its token like the device's (the holder needs `connect` there, §3). A screen publisher
**counts as its owner**: it takes no seat of the `user_limit`, `voice_max_participants`, `voice.max_participants` or
`call.full`, displaces nobody and consumes no move grant (§7); the user's one voice session (§3) is the owner's.

**Presence.** The screen publisher is a `VoiceParticipant` (§5) with `screen_of` = the owner's identity, listed
directly after its owner in `voice.state`, the join answers and `CallState`, with the owner's `user`, `user_id`,
`device_id`, `server_muted` and `moved`, `muted: true`, `deafened: false`, `camera: false` and `streaming` while its
`screen_share` track is published. The owner's `streaming` is `true` while either of them publishes a screen share.
Clients show a screen publisher as the owner's stream (the stream tile carries the owner's name; no participant tile,
row or count of its own) and subscribe to it like any stream; LiveKit participants whose identity ends in `#screen`
are treated the same before the node reports them.

**Lifetime.** It ends with its owner's participation: the owner's leave, a moderator's disconnect or move, the end
of the owner's reconnect grace period (§5a), another device of the user taking over (§3), a join of the owner
elsewhere, and everything of §5 "Leaving" remove the screen publisher as well, in the node's state and in LiveKit.
While the owner is only `reconnecting`, the screen publisher stays. Its own dropped connection follows §5a like any
participant's. `POST …/voice/leave` with `{ "role": "screen" }` (calls: `…/call/leave`) ends only the screen
publisher of the requesting device; without a body the device leaves with its screen publisher. A screen identity
whose owner is not in the channel is removed from LiveKit (webhook, reconciliation). `PATCH …/voice/state` stays the
device's own; a server mute (§7) does not touch the screen publisher (as it does not touch a device's screen share).

**Encryption.** The screen publisher encrypts with **its owner's frame key** (`ENCRYPTION.md` §5a): the same 32 bytes
of the same epoch at `keyIndex = epoch mod 256`, with the same key provider settings. It is not a member of the MLS
group and derives nothing itself: the owner's client hands each epoch's key to the native publisher over the app's
local bridge between its client and its native part (the Android app: the shell's `android_screen_share_*`
commands), right after deriving it, before its own connection uses it. The key never travels through the node,
LiveKit or any network. Like every client, the native publisher MUST NOT publish without a key; receivers decrypt
its frames with the channel's shared key as any other's.

## 4c. Whisper to participants of the same channel

Whisper uses server-authenticated routing authorizations, a second E2EE audio track and SFU subscription permissions. Nodes and clients implement capability `voice.whisper2`; senders MUST require the hosting node's capability and MUST NOT fall back to legacy `voice.whisper1` or ordinary broadcast. `speak` and no server mute are always required. Initiation additionally requires `whisper` (bit 41); replying to the last actually received whisper bypasses only this initiation bit. All permissions are evaluated in the current voice channel, including category/channel overrides.

Clients MUST filter all track names beginning with `whisper`; they never enter ordinary audio playback. An encrypted client signal alone grants neither playback nor reply rights. Recipient capability discovery is unchanged; an older selected receiver may hear the authorized audio, but no reply UI support is promised.

**Media and permissions.** Use the existing microphone capture graph, a second Opus publication with
`source: microphone`, `name: "whisper:<authorization id>"`, the channel's epoch frame key (§6) and the same audio bitrate/FEC limits
as the main microphone (§4/§4a). At most one whisper publication and one active recipient set per sender are
allowed. Recipients are full LiveKit device identities (`<address>/<device id>`, §3), never just addresses,
`#screen` publishers or participants of another channel. Resolve saved addresses against the currently connected
participants on every start; omit the sender itself and reject an empty set. A set MUST have no duplicates and
MUST fit the signal size limit below; do not silently send to a truncated group.

The sender MUST perform these steps in order:

1. Authorize the start/reply through §4d, then mute the main microphone publication (no audio packets, no renegotiation). Whisper press-and-hold opens the
   microphone gate even with push-to-talk; it never toggles the user's persistent mute setting.
2. Install restricted per-participant SFU subscription permissions **before** publishing/unmuting whisper.
   Keep every ordinary publication available to everyone, including participants that join later; allow only
   the selected identities to subscribe to the whisper publication. A new whisper track MUST remain silent until
   its track SID is covered by that permission list. Never publish audible whisper under unrestricted permissions.
3. Send the targeted reliable `whisper.start` below, then enable whisper audio only while the control is held.
   Receivers may get track and signal events in either order; they wait until both are present before playback.
4. Re-send the full SFU permission list on every participant join or departure and every own track publication or
   unpublication while restricted. If a selected participant leaves, end the whisper; a new press resolves the
   group again. To change recipients, end the current whisper before starting another.
5. On release/end, first mute and stop/unpublish the whisper track, then send targeted `whisper.end`, restore SFU
   subscription permissions to all, and restore the main microphone to the user's normal mute, deafen and
   voice-activation/push-to-talk state. Do not unmute a user who was muted or whose push-to-talk key is not held.

On **any failure** (track, encryption, signaling or permission update), clients MUST end whisper and execute the
same cleanup, including restoring normal main-track behavior. Cleanup is idempotent and MUST also run if the user
releases during an asynchronous start. Never restore unrestricted permissions while whisper can still transmit.
If stopping the track or restoring permissions cannot be confirmed, disconnect and rejoin with the ordinary
publication configuration; do not leave a live whisper track or a silently restricted main microphone behind.
Reconnect starts in ordinary voice mode; it MUST NOT resume a held whisper automatically.

A subscription-permission setter returning locally is not an SFU acknowledgement. Implementations MUST
establish deny-by-default for the new track before it can carry audio, using the SFU's documented and verified
signaling order or an acknowledged operation as a barrier. Merely waiting a fixed time is insufficient.
A later SID-specific grant may fail closed (the intended recipient hears nothing); it MUST NOT broaden
permissions for nonrecipients. Validate this boundary against the SFU with a nonrecipient explicitly attempting
to subscribe, independently of receiver UI filtering.

**Signal.** Use LiveKit reliable data, topic `tavrn.whisper`, UTF-8 JSON:

```json
{ "type": "whisper.start", "recipients": ["bob@node.example/01JDEVICE"] }
```

`type` is exactly `whisper.start` or `whisper.end`; `recipients` is the nonempty, duplicate-free array of full
recipient identities of this whisper. Send each packet only to that same set with `destinationIdentities`, never
broadcast. End names the same recipients as start. The complete encoded payload MUST be at most **512 bytes**;
senders MUST send at most **10 packets per rolling 10 seconds**, counting starts and ends together, and reserve
capacity for the end before starting. If the budget is exhausted, refuse a new start and restore normal voice.
Do not send heartbeats. The data channel grant does not authorize other topics or bypass `use_soundboard` (§8).

**Receiver filtering.** Receivers MUST drop malformed UTF-8/JSON, invalid types or recipient lists, oversized or
over-rate packets, packets on another topic or unreliable delivery, packets without a known currently connected
LiveKit sender in the same channel, and packets that do not name their own exact device identity. Use the
transport's sender identity, never a claimed JSON sender. Validate that recipients are current participants as
above. Ignore unknown extra JSON fields for forward compatibility. Track receipt alone never authorizes playback:
a track named `whisper:<id>` MUST be played only after the receiver has obtained the server receipt in §4d, verified its sender equals the transport publisher, and received a valid `whisper.start` naming this device.
An end without a start is harmless. Valid end, publisher leave/disconnect or server mute, whisper track
end/unpublish, local leave, deafen or reconnect clears playback authorization immediately. Keep authorization and its rate counter scoped to
the current connection, never persisted. A valid start may arrive before the publication; attach it only after
publication is available. No ordinary remote-audio auto-attach path may bypass this filter.

**Privacy and local state.** Nothing is added to `voice.state`, participant metadata, attributes or public track
metadata containing recipients. Only the sender and selected receivers show whisper markers or hear whisper cues;
outsiders see only an ordinary muted microphone, without a recipient or whisper signal. The SFU necessarily sees
track subscription permissions and destination identities; the epoch-key threat model is in `ENCRYPTION.md` §5a.
Clients do not duck other speakers while receiving a whisper. Whisper state and reply-to-last are ephemeral;
reply-to-last is cleared on leave and never modifies configured groups.

## 4d. Authenticated whisper initiation and reply

All paths below have prefix `/api/v1/rooms/{room_id}/channels/{channel_id}/voice/whisper`. Requests use the ordinary bearer session; the server derives the sender device from authentication, never the JSON body.

- `POST` with `{ "recipients": ["bob@node.example/DEVICE"] }` initiates a whisper. The nonempty list has at most 32 unique currently connected ordinary devices of the same channel, excluding self and screen publishers.
- `POST` with `{ "reply_to": "<authorization id>" }` replies. Recipients MUST be omitted/empty. The server selects only the original sender of this device's latest confirmed receipt. Forged ids, another device's receipt, changed channel/connection, expired receipts and arbitrary reply targets are rejected.
- Start returns `{id,sender,recipients,expires_at}`. It is valid for 30 seconds, at most one current authorization per sender. Only the sender receives the entire recipient list. Publish a GCM-encrypted microphone track named `whisper:<id>`; the SFU signaling proxy rejects legacy/unapproved whisper publication and applies recipient-only subscription permissions on the same ordered connection before publication. While the track exists, clients cannot widen these permissions. The proxy owns ordinary publication permissions too: ordinary/renamed media is always available to all authorized listeners; while whispering, outsiders receive ordinary track SIDs only, including newly published camera tracks. The existing E2EE frame key derivation is unchanged.
- After receiving the publication, the intended receiver calls `POST /{id}/receive` before attaching audio. The server requires a verified LiveKit `track_published` event, current authorization and matching devices/connections. The response is `{id,sender,expires_at,reply_expires_at}` and does not disclose other recipients. `expires_at` remains the original 30-second playback deadline. `reply_expires_at` is at most 120 seconds from authorization creation; repeated receipt validation never extends it. The reply window is bounded by both connections; a newer confirmed receipt replaces the previous one. Clients may retry briefly while the webhook is in flight, while keeping audio detached.
- On end, stop/unpublish first, await SFU removal confirmation, then `DELETE /{id}` (204). Only the authenticated original device may end its authorization. Replies to already ended whispers remain possible until the receipt expires, provided both devices remain in the same connections/channel.

The node stores sealed, expiring routing records in its node-scoped cache, shared between instances. Verified participant departures/rejoins invalidate connection generations, including reconnect grace. Generations bind actual SFU participant SIDs and join timestamps; bounded departure tombstones reject duplicate delayed joins, old lifecycle events do not replace newer connections, and ambiguous equal-timestamp different-SID events fail closed. Active publications recheck authorization and DB permissions every second; expiry, mute, role/override revocation or missing recipients disconnects the offending publisher from LiveKit, ending media as well as signaling. Clients MUST schedule stop/unpublication with at least a two-second safety margin before the deadline (at most 28 seconds per hold), rather than race the server expiry. A new authorization is required for longer holds. A failed signaling connection with a whisper still published is removed from the SFU; it cannot resume an old whisper through reconnect/SyncState. Room signaling uses binary protobuf, as supported by the official clients.

Servers see routing metadata but never E2EE media plaintext or frame keys. Receivers MUST also stop on deafen, leave, server mute, expiry and unpublication; they never trust client-provided recipient lists or session ids as server authority. `voice.state` and public participant metadata contain no whisper recipients.

## 5. Presence: who is in which channel

`VoiceParticipant`:

```json
{
  "user": "alice@node.example", "user_id": "01J…", "device_id": "01J…",
  "identity": "alice@node.example/01J…",
  "muted": false, "deafened": false, "streaming": false, "camera": false,
  "server_muted": false, "joined_at": "2026-10-05T12:00:00.000Z",
  "connection": "connected", "moved": false
}
```

A device's screen publisher (§4b) additionally carries `"screen_of": "alice@node.example/01J…"` (its owner's
identity); the field is absent for devices. Clients that do not know it would show it as another participant of the
same user.

`connection` is `connected` or `reconnecting` (§5a); clients treat unknown values as `connected` (`poor` is
reserved: participants of a call take the connection quality from LiveKit). `moved` is `true` while the participant
is here through a moderator's move (§7 "Moved participations"; clients may show "moved here"); absent from older
nodes, always `false` in calls.

- **Initial state:** `GET /api/v1/rooms/{room_id}/voice` → `{ "items": [VoiceChannelState, …] }`: every voice channel
  of the room with at least one participant that the requester can view (members only).
- **Initial state of all rooms:** `GET /api/v1/users/me/voice` →
  `{ "rooms": [ { "room_id": "01J…", "channels": [VoiceChannelState, …] }, … ] }`: the same for every room of this
  node the requester is a member of, in one request; rooms without such a channel are left out (empty `rooms` when
  voice is disabled). Clients call it once after `ready` and after every resync to show voice activity in their room
  list (who is in voice where, who streams) without loading each room; `voice.state` keeps it current. Members of
  rooms on other nodes ask each of those nodes with their session there. App tokens need the scope `voice`.
- **Changes:** WebSocket event `voice.state` to all room members who can view the channel, `data` = `VoiceChannelState`
  `{ room_id, channel_id, epoch, session_started_at, participants: [VoiceParticipant, …] }`, always the *complete*
  list of the channel (replace, do not merge; an empty list means the channel is empty).
- **Session start:** `session_started_at` (RFC 3339, or `null`) is when the current session of the channel began:
  set when a participant connects to an empty channel, kept while anybody is connected or reconnecting (§5a),
  whoever that is (the first participant may have left long ago), cleared with the last participant. Clients show
  a timer from it ("how long has this been going on") that is right for late joiners and for people outside the
  call. The channel's home node holds it with the participants (in memory, like them: a node restart restarts
  LiveKit and drops every participant, so there is nothing to persist), and every `VoiceChannelState` (`GET …/voice`,
  `GET /users/me/voice`, the join answer's state, `voice.state`) carries it. Nodes that do not know the field omit it;
  clients then show no timer.
- **Sources of truth:** LiveKit's webhooks (`participant_joined`, `participant_left`,
  `participant_connection_aborted`, `track_published`/`track_unpublished` for `streaming` and `camera`,
  `room_finished`), verified with the node's LiveKit secret, and a reconciliation with LiveKit's room service every
  30 seconds that removes participants LiveKit does not know (ghosts after crashes or lost webhooks) and adds
  those whose webhook was lost. LiveKit restarts drop everyone; clients reconnect with a new `join`.
- **Own state:** `PATCH /api/v1/rooms/{room_id}/channels/{channel_id}/voice/state`
  `{ "muted"?, "deafened"?, "streaming"?, "camera"? }` (booleans, unknown fields rejected) → `200 VoiceChannelState`.
  Allowed for the device's own reserved or connected participant (`409 voice.not_connected` otherwise). Unmuting
  while server-muted: `403 voice.server_muted`; `streaming: true` without permission/policy:
  `403 voice.stream_forbidden`; `camera: true` likewise `403 voice.camera_forbidden`. A deafened client SHOULD also
  mute itself. `muted`/`deafened` are reported by clients only (LiveKit has no webhook for them); `streaming`/`camera`
  are also set from LiveKit's track events.
- **Speaking** is not part of `voice.state` (it would be an event per syllable): clients take it from their own call
  (the reference client measures the decoded audio itself and falls back to LiveKit's `ActiveSpeakersChanged`, §9.1),
  which works for every participant of the call. Clients that are not in the call do not see who speaks.
- **Leaving:** `POST …/voice/leave` → `204` (always allowed, also when not connected; the node disconnects the device in
  LiveKit too, with its screen publisher, §4b; `{ "role": "screen" }` ends only the screen publisher). A client that hangs up calls it (LiveKit also reports `CLIENT_INITIATED`), so the participant is gone
  at once; a dropped connection gets the grace period of §5a. Leaving a room, being kicked, banned or timed out, a deleted channel or room end the voice connection
  automatically (the node removes the participants in LiveKit and sends `voice.state`, or `channel.delete` and
  `room.delete` for deletions). So does losing `view_channel` or `connect` in the channel through a role, override,
  membership or age change: the node checks the participants of a room after every event that changes who may view
  what, and all rooms with participants at least once a minute (changes without an event), and removes those who
  lost access (`voice.state`). A moved participation (§7) needs neither: only room membership, no timeout or ban,
  the channel's age gate and the channel's existence.

## 5a. Dropped connections and reconnects

Design note 4.5 item 7: a participant whose media connection drops is **not removed at once**:

- LiveKit's `participant_left`/`participant_connection_aborted` with a disconnect reason other than
  `CLIENT_INITIATED`, `PARTICIPANT_REMOVED`, `ROOM_DELETED` (removed at once) or `DUPLICATE_IDENTITY` (the same
  identity connected again: ignored), and a participant missing in the 30-second reconciliation, turn the participant
  into `connection: "reconnecting"` (announced in `voice.state`; flags, `joined_at` and the seat for the user limit are
  kept).
- A join and LiveKit report of the **same identity** (user and device) within the grace period continue the entry:
  `connected` again, never listed twice. The reconciliation does the same when LiveKit knows the identity again.
- After `TAVRN_VOICE_RECONNECT_GRACE_SECS` (default 45, 0–600, 0 = remove at once) the participant is removed and
  `voice.state` announces it as gone. The node checks for expired entries every fifth of the grace period (1–5 s).

Clients: LiveKit's own reconnect (`Reconnecting`/`Reconnected`) comes first; after a full disconnect the client joins
again (`voice/join`, a fresh token) with backoff for as long as the grace period lasts, without a new self update
(the MLS epoch stays), re-applying the frame key before publishing and keeping its mute/deafen state; the user can
cancel. Other participants are shown with a connection-problem indicator instead of the speaking ring (§9) and never as
speaking while reconnecting.

## 6. End-to-end encryption

Normative: `ENCRYPTION.md` §5a. Summary for the client: after every epoch change of the channel's group (and
right after joining) call `exportVoiceKey(conversation, epoch)` (`@tavrn/crypto`; `conversation` is the qualified
conversation id used for the group, as for text) and hand the 32 bytes to the LiveKit key provider as HKDF key
material at `keyIndex = epoch % 256` (shared key, `keyringSize: 256`, `ratchetWindowSize: 0`,
`failureTolerance: -1`). The epoch comes from the client's MLS state; `voice.state.epoch` and `join.epoch` tell
which epoch the node has, so a client that lags behind fetches the missing commits first. Clients MUST refuse to
publish without E2EE and SHOULD show the channel's lock icon and the same ghost-member check as in text
(`ENCRYPTION.md` §4.6) in the voice view.

## 7. Moderation

All under `/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/…`, `{address}` = user address of a
room member (`404 member.not_found` otherwise). The usual hierarchy rules apply (`403 member.is_owner`,
`member.is_node_admin`, `member.hierarchy`, see `permissions.md`). Every action is in the room's audit log.

| Action | Permission (bit) | Effect | Audit |
|---|---|---|---|
| `POST …/mute` `{ "muted": true \| false }` → `200 VoiceChannelState` | `mute_members` (19) in this channel, `403 voice.mute_forbidden` | Server mute in the **whole room**, stored (survives reconnects and restarts): `muted` and `server_muted` become `true`, the microphone grant is revoked in LiveKit immediately and missing from new tokens; `false` lifts it (the self mute stays the user's) | `voice.mute` / `voice.unmute` |
| `POST …/disconnect` → `204` | `move_members` (20), `403 voice.move_forbidden` | All devices of the member leave this channel (LiveKit `RemoveParticipant`); `404 voice.not_connected` if none was there. The member may rejoin. | `voice.disconnect` |
| `POST …/move` `{ "channel_id" }` → `204` | `move_members` in both channels | Disconnects the member here and sends `voice.move` `{ room_id, from_channel_id, channel_id, user_id }` to the member's connections; the client then joins `channel_id` normally (new token, new MLS group and frame key). The member needs no permission in the target, not even `view_channel` ("Moved participations" below); only the target's age gate holds (`403 voice.target_forbidden` for a member below it); `400 voice.not_voice_channel`, `400 voice.same_channel`, `404 voice.not_connected` | `voice.move` |

**Mass move** (design note 4.11): `POST /api/v1/rooms/{room_id}/voice/move-all`
`{ "to_channel_id", "from_channel_id"? }` → `200 { moved: [address], skipped: [{ user, reason }] }`. Without
`from_channel_id` everybody in any voice channel of the room moves (except those already in the target). Needs
`move_members` in the target (`403 voice.move_forbidden`) and in `from_channel_id`; participants of other channels
where the mover lacks it stay (`move_forbidden`). Each moved member is handled like `…/move` (disconnect plus
`voice.move`); members the mover may not moderate stay (`outranked`: owner, node admins, equal or higher roles; the
mover may move themselves), so do members below the target's age gate (`target_forbidden`) and everybody beyond
the target's user limit (`channel_full`) — a partial result is still `200`. `400 voice.not_voice_channel`,
`400 voice.same_channel`. One audit entry `voice.move_all` with the counts.

**Moved participations.** A member may be moved into a voice channel they may neither view
nor connect to; the moderator's `move_members` decides, not the member's permissions.

- **Grant.** With every move (`…/move`, `move-all`) the node records a *move grant* for the member and the target
  channel: valid for 60 seconds, one per user (a new move replaces it). The member's next `join` of that channel is
  entitled by it instead of `connect` and may exceed the channel's `user_limit` (as the mover may);
  `voice_max_participants`, bans and timeouts still refuse it. A join of another channel drops the grant.
- **Moved participation.** The first join consumes the grant; the participation that follows is *moved*
  (`VoiceParticipant.moved: true`) for as long as the member has a participant in the channel: a rejoin within the
  reconnect grace period (§5a) keeps it, leaving, being disconnected or removed, the end of the grace period or a
  join elsewhere ends it. Afterwards a join needs `connect` again: the member cannot come back by themselves.
- **Temporary view.** From the move until the grant expires unused or the participation ends, the member holds
  `view_channel`, `read_history` and `connect` in that channel whatever the overrides say (`permissions.md` "Moved
  participations"); all other bits (`speak`, `stream`, `send_messages`, …) follow their roles and overrides as
  usual, a timeout strips all but reading, and the channel's age gate still applies. So the member's connections get
  `channel.create` for the channel (with its category's `category.create` if needed) before `voice.move`, see the
  channel's `voice.state` and events, `GET /rooms/{id}` lists it, its MLS group is open to their devices
  (`ENCRYPTION.md` §4.5), and its messages are readable (writing still needs `send_messages`); this is intended.
  When it ends, the connections get `channel.delete` with `hidden: true` (`PROTOCOL.md` §6) and, if the member may
  not view the channel by their permissions, the node announces their leaves with `mls.remove_needed`.
- **Access checks.** The access watcher (§5) and the `/rtc` proxy accept a moved participant while they are a room
  member, not timed out or banned, and the channel exists.

There is no separate "deafen others" permission in v1 (`permissions.md` has none); moving with LiveKit's
`MoveParticipant` is not used because the target channel has another MLS group and therefore another frame key, so a
fresh connection is simpler and always correct.

## 7a. Priority speaker

Permission `priority_speaker` (bit 30, not restricted for `@everyone`, off by default; design note 4.13 item 3). While a
participant holds the priority key (voice settings, default none) or the toggle of the call controls (touch devices),
the client sets the LiveKit participant attribute **`priority = "1"`** and clears it (`""`) on release; with
push-to-talk the key also opens the microphone like the push-to-talk key. The node grants own attribute updates
(`canUpdateOwnMetadata`) only to members with the bit in the channel (§3); clients never put anything else into
attributes, metadata or the LiveKit name.

**Receivers** follow `ParticipantAttributesChanged` (and the attributes of participants already in the call) and
treat the attribute as a *claim*: it counts only after the client checked that the speaker's room permissions in
this channel contain `priority_speaker`, computed from the room's roles, overrides and the speaker's member entry
(`permissions.md`, the same computation as for the own permissions; unknown members: no). A hostile client
setting `priority=1` without the bit therefore ducks nobody. While at least one verified priority speaker is active,
every *other* remote audio track (microphones and screen share audio) is lowered to **25 %** with a linear **80 ms**
ramp, and restored with the same ramp on release. The ducking multiplies with the user's own per-user volume and
output volume (it is a gain of its own in front of them), so it never overwrites them; the priority speaker's own
playback is not ducked. The tile and the channel-list row of an active priority speaker get an accent border and a
megaphone glyph (with an accessible label) only while it is active.

## 8. Soundboard

Clips are room assets like custom emojis; playing them is client-side.

- `GET /api/v1/rooms/{room_id}/soundboard` → `[Sound]` (members), `Sound` =
  `{ id, room_id, name, mime, size, duration_ms, uploader_id, created_at }`.
- `GET …/soundboard/{sound_id}/audio` → the file (members; `Content-Type` = the clip's type, `nosniff`, sandbox CSP).
- `POST …/soundboard` (`manage_emojis`, bit 22 "custom emojis and sounds"; there is no separate bit): body = the
  audio file, `Content-Type: audio/<subtype>`, `Tavrn-Sound-Name` (1–32 characters, percent-encoded UTF-8),
  `Tavrn-Sound-Duration-Ms` (1–5000, declared by the client, which trims longer clips; the node cannot decode audio).
  At most 1 MiB and 50 clips per room. → `201 Sound`. Errors: `403 soundboard.manage_forbidden`,
  `400 soundboard.name_invalid`, `415 soundboard.type_not_allowed`, `400 soundboard.too_long`,
  `413 soundboard.too_large`, `403 soundboard.limit`, `409 soundboard.name_taken`.
- `DELETE …/soundboard/{sound_id}` (`manage_emojis`) → `204`, `404 soundboard.not_found`.
- Event `soundboard.update` `{ room_id }` to room members after every change. Audit `soundboard.create`/`.delete`.
- **Playing** needs `use_soundboard` (bit 21) and `speak` and is enforced by the client: it decodes the clip with
  WebAudio and mixes it into its own (end-to-end encrypted) microphone track, so everybody in the channel hears it and
  no extra track source is needed. Clips are stored unencrypted on the node, like emojis.
- **Signal** (design note 4.13 item 3): when a clip starts, the player's client sends a LiveKit data message, reliable,
  topic `tavrn.soundboard`, UTF-8 JSON `{ "type": "soundboard.play", "sound_id", "emoji"?, "duration_ms" }`
  (`duration_ms` 1–5000 like the clip limits, `emoji` = the sound's optional `emoji`: a Unicode emoji or a custom
  emoji token `<:name:id@node>`). Soundboard signals still need `use_soundboard` (§3), even when `speak` grants
  data for whisper. They are end-to-end encrypted by LiveKit with the call's frame key (data channel encryption of the `encryption` room option). Senders send at most 5
  signals per 10 s; receivers drop packets over 512 bytes, anything that does not validate and more than 5 signals
  per sender and 10 s, and show the emoji as an overlay on the sender's tile for `duration_ms` (custom emojis only
  when the room's emoji list resolves them, otherwise nothing). The signal only decorates: the audio still travels
  in the microphone track.
  Receivers MUST also verify the sender's effective `use_soundboard` and `speak` in the current channel from
  current room roles, overrides and membership (as for priority claims, §7a), and reject unknown or unauthorized
  senders. A general LiveKit data grant alone is not evidence of soundboard permission.

## 9. What the reference client shows

Part of the web client, responsive like the rest of the client:

- **Channel list:** voice channels show their participants (avatar, display name, mute/deafen/stream/camera icons,
  server mute in another color) from `GET …/voice` and `voice.state`, also for members who are not in the call; the
  user limit as `3/5`; joining by clicking the channel.
- **Room list and friends:** from `GET /users/me/voice` and `voice.state` (so only channels the user can view), a room
  icon carries a speaker badge while somebody is in voice there and a monitor badge while somebody streams; a hover
  card (also on keyboard focus; on touch the head of the room's long-press menu) lists who is in which voice channel.
  A friend in a voice channel the user can view is shown with that room and channel in the friends list, with a
  "Join" entry in the friend's menu; nothing is shown for channels or rooms the user cannot view.
- **Voice view:** one tile per participant (avatar, or the camera video when on), a **speaking indicator** (ring
  around the tile while LiveKit reports speech), mute/deafen icons and the display name; screen shares as large tiles
  that can be focused (enlarged) and opened in their own window (picture-in-picture or popout); simulcast picks the
  resolution by tile size. Every tile is 16:9 in a grid sized from the stage and the number of tiles (a focused share is
  a large tile above a strip of small ones); shares, cameras, the whiteboard and the whole stage can go fullscreen
  (Fullscreen API, `F`, Escape, a controls overlay with mute, deafen and leave). On phones the tiles become a
  **swipeable grid** (pages of up to 4), the controls a bottom bar.
- **Controls:** mute, deafen, camera, screen share (hidden when `limits.*.enabled` is false; the Android app shares
  through a screen publisher, §4b), soundboard (with
  `use_soundboard`), the priority speaker toggle (with `priority_speaker`, §7a), leave; device selection (microphone, speaker, camera); a connection quality indicator.
- **Participant menu** (design note 4.13 item 3): right-click, long press and the ⋯ button on a channel-list row and on a
  stage tile open the member list's dropdown (anchored at the pointer): profile, message, roles, per-user volume
  (0–200 %, in the own call), copy address and id, and with the respective permission server mute/unmute, disconnect,
  move to another voice channel, timeout, kick and ban (hierarchy-gated as in the member list); "server deafen" is
  shown disabled until it exists. Participants whose member entry is not loaded and members of other nodes get a
  reduced menu (volume, server mute, disconnect, move, copy). Following `voice.move` is automatic.
- **Order and colours:** participants are sorted by their highest role position, then by the shown name
  (`Intl.Collator`); names are the nickname, then the display name (the address's local part only for people the
  member list does not know) in the colour of the highest role with a colour, on rows, tiles and chat authors. The
  stage keeps its order while the membership is the same (no jumping while someone speaks). With `move_members` participants can be dragged
  onto another voice channel in the channel list, and a voice channel's context menu (right-click, long press or ⋯;
  the text channel menu plus these entries) moves everybody in voice there or everybody from there to another
  channel, after a confirmation naming how many move; the result
  (moved, stayed and why) shows as a toast.
- **Encryption:** the lock icon of the channel, a blocking warning if E2EE cannot be set up (no insertable streams),
  never a silent fallback to unencrypted media; ghost member warning as in text.
- **Errors:** the codes of §3, §4b, §5, §7 and §8 mapped to translated messages (`voice.channel_full` with the limit,
  `voice.connect_forbidden`, `voice.disabled`, `voice.unavailable` "voice server unreachable", …).
- **Connection problems** (§5a): a reconnecting participant gets a small amber "unplugged" glyph on the avatar in the
  channel list and on the stage tile (pulsing softly, opacity 0.55 → 1 over 1.6 s, static with reduced motion,
  tooltip "connection problems") instead of the speaking ring; a poor LiveKit connection quality shows static amber
  signal bars; on the stage the tile dims and a camera keeps its last frame. The own voice bar shows "reconnecting"
  with a cancel button.

### 9.0 Whisper controls (client conventions)

- Participant menu: "Whisper to" selects a person; "Add to whisper group…" adds them to a named group.
  Store groups **per room**, by user address, with a hold hotkey per group (`whisper:<group id>`). Resolve all
  connected devices of each address at start (§4c). Never reuse a group implicitly in another room.
- Settings "Voice & video" expose the groups and a separate "Reply to last whisperer" hold hotkey. The last
  valid start addressed to this device sets the reply target; it is independent of groups and cleared on leave.
- Desktop hotkeys and touch tile buttons are press-and-hold, with cancellation on blur, pointer cancellation,
  lost capture and leave. A whisper key never toggles. With push-to-talk it opens the gate for whisper only.
- Sender tile/voice bar: "Whispering to A, B", a distinct border and glyph; receivers: "Whispering to you" on the
  sender's tile. Provide accessible labels, keyboard operation and touch targets. Outsiders receive no marker.
- Soft `whisper_start` / `whisper_end` cues for sender and recipients, distinct from join/leave, with the existing
  per-cue switches and volume. No ducking of ordinary audio.
- Native engines need the same second track, E2EE and SFU permission semantics. Until supported, clients MAY
  offer whisper through the browser engine only, with an explicit fallback choice; never silently degrade to a
  broadcast track or unencrypted/native whisper.

### 9.1 Implementation notes (web client)

- Code: the `voice/` module of `tavrn-web` (session, key provider, audio pipeline, presence and settings stores, UI in `voice/ui/`),
  settings in `pages/settings/VoiceSettingsTab.tsx` and `SoundboardTab.tsx`. `livekit-client`, its E2EE worker, the
  RNNoise worklet (`@sapphi-red/web-noise-suppressor`) and `@livekit/track-processors` are loaded with dynamic
  imports on the first join or settings use, never with the text client.
- Join: `ensureJoined` on the channel's group (creation needs `send_messages`, as for text), a self update, `voice/join`,
  catch-up when `join.epoch` is ahead, the frame key of the current epoch into a `ExternalE2EEKeyProvider` subclass
  (`keyringSize: 256`, key set with `onSetEncryptionKey(material, undefined, epoch % 256)`, keys of older epochs
  ignored), `room.setE2EEEnabled(true)` and `connect`; the microphone is published only after LiveKit's worker
  confirmed encryption for the local participant (`ParticipantEncryptionStatusChanged`), with
  `maxBitrate = limits.audio_bitrate_kbps × 1000`, DTX on, RED off (E2EE), and in music mode stereo and DTX off
  (§4a). Every epoch event of the group re-keys.
- The published microphone track is the output of a WebAudio graph (input volume → optional RNNoise worklet → a
  gate worklet for voice activation, noise gate and push-to-talk → mix with soundboard clips); device and
  processing changes rewire the graph without republishing. The gate reports levels about ten times per second.
- Remote audio is played through LiveKit's Web Audio mix (`webAudioMix`), so per-user volumes go up to 200 % and the
  output device can be switched; deafen sets every remote volume to 0 and mutes the microphone.
- **Speaking detection (design note 4.13 item 3).** LiveKit's active-speaker updates come from the SFU (default update
  interval 400 ms with smoothing), so rings used to light up well over half a second late. Now:
  - the **own ring** follows the local gate worklet: it reports at once when the gate opens or closes and the level
    ten times per second, no round trip (nothing while muted, server-muted or with the gate closed);
  - **remote rings** come from one `AnalyserNode` (1024 samples, no smoothing) per subscribed remote microphone,
    read by a **single 50 ms loop** (no timer per track): RMS above −50 dBFS counts as speech, with a **150 ms hold**
    so the ring does not flicker between words. Remote audio plays through LiveKit's Web Audio mix on an
    AudioContext of the session; the analyser and the ducking gain (§7a) sit in the track's graph as pass-through
    nodes in front of LiveKit's volume gain (`setWebAudioPlugins`), i.e. after decryption (insertable streams work on
    encoded frames) and before the per-user volume, which therefore neither hides speakers nor is overwritten;
  - LiveKit's `ActiveSpeakersChanged` stays the **fallback** for remote rings without Web Audio, with
    `prefers-reduced-motion`, on weak devices (frame-drop detector) and while the AudioContext is not running.
  Everything goes through the same batcher (≤ 10 store writes per second, but a change after a quiet interval is
  written at once), so the UI is unchanged: a CSS `--level` variable (ring in the channel list, tile border,
  three-bar meter). Touch devices, reduced motion and weak machines get static rings.
  *Measured:* the unit test of the threshold/hold logic (`voice/speaking.test.ts`, every onset phase against the
  50 ms loop) gives an onset latency of 25.5 ms on average and 50 ms at most (56 ms for quiet −45 dBFS speech) and a
  release after 196 ms on average (221 ms at most, hold included). End to end in Playwright (`voice-round3.spec.ts`,
  two Chromium contexts on one machine, fake microphone, from the click on "unmute" until the listener's tile lights
  up, including the unmute itself and the SFU): 209–285 ms with the analysers versus 515–728 ms until LiveKit's
  active-speaker event named the speaker.
- Talking counts as activity for the automatic idle status (at most one report per 30 s while transmitting).
- Screen sharing asks for resolution, frame rate (within `limits.screenshare`) and audio before the browser's own
  picker; camera capture follows the "Voice & video" settings within `limits.camera` (simulcast, VP8).
- Background effects load MediaPipe's runtime from the node (`/mediapipe/…`) and the segmentation models shipped with
  the web client, never from a CDN. Settings (design note 4.11): blur strength 0–100 % (mapped onto the processor's
  blur radius 2–64, applied live) and quality `fast` (the lighter 144×256 landscape model, no smoothing),
  `balanced` (the 256×256 model with temporal smoothing of the mask) or `high` (stronger smoothing and a feathered
  edge); the smoothing is one WebGL pass on the segmenter's context between the model and the compositing.
  Replacement images are scaled and cropped to the camera's capture size first. The settings explain that in-browser
  segmentation stays approximate (busy backgrounds, low light, hands and hair). The frame-drop detector ignores the
  first 2.5 s after a start (model and shader warm-up made every machine look slow, which switched the effect off
  right away with the old message "this device dropped frames" — "Bilder verloren" in German) and pauses while the
  tab is hidden; when it fires, the toast and the settings name the measured time per frame against the budget and
  offer the "fast" quality.
- Notification sounds (`voice/cues.ts`, design note 4.9) are synthesized with WebAudio (no files): join/leave of anyone in
  the call (from `voice.state`, the joiner hears its own join), own mute/unmute and deafen/undeafen, own and others'
  stream or camera start/stop, connection lost/restored (own LiveKit reconnects and rejoins, others' `connection`).
  A cue volume, a switch per cue and "all off" live in the settings; while deafened only the own cues play.

## 10. Node implementation notes

- LiveKit runs as a child process of `tavrn-node serve` (also with `--dev`): config generated into
  `<data>/livekit.yaml` at every start (no secrets in it), API key and secret in `<data>/keys/livekit.key` (mode 0600,
  LiveKit's `key_file`), signaling bound to `127.0.0.1:TAVRN_LIVEKIT_PORT`, media on `TAVRN_RTC_UDP_PORT_RANGE`,
  optionally ICE over TCP and the embedded TURN server (§10.3), the announced addresses as in §10.2,
  `room.max_participants = TAVRN_VOICE_MAX_PARTICIPANTS`, webhooks to the node's own listener on the loopback
  interface. Crashes are restarted with an exponential backoff (1 s … 30 s), log lines are forwarded with the target
  `livekit`, shutdown sends SIGTERM. A missing binary with voice enabled stops the start with an install hint.
  The start is logged with every address and port clients must reach (`LiveKit starting media=…`).
- `GET /healthz` → `{ "status": "ok", "voice": "disabled" | "stopped" | "starting" | "running" | "restarting" }`, plus
  `"voice_problem": "<text>"` while a voice setup problem needs the operator (no announced hostname resolves, §10.2);
  `GET /readyz` → `{ "ready", "database", "livekit", "cache" }` (`livekit` = LiveKit answers locally, `null` without
  voice; `cache` = the shared Valkey answers and its event bus is subscribed, `null` without `TAVRN_CACHE_URL`).
- Participant state is kept in memory by one instance: the node process, or with several instances behind a load
  balancer the leader, to which the other instances relay through the shared cache (`TAVRN_CACHE_URL`). Dropped participants stay `reconnecting` for `TAVRN_VOICE_RECONNECT_GRACE_SECS` (§5a);
  a sweeper removes expired ones.

### 10.1 Connectivity settings

| Variable | Default | `livekit.yaml` | Meaning |
|---|---|---|---|
| `TAVRN_RTC_UDP_PORT_RANGE` | `61000-61100` | `rtc.port_range_start/end` | UDP media ports; published 1:1 and forwarded by the router. Outside the Linux ephemeral range (32768–60999) on purpose |
| `TAVRN_RTC_EXTERNAL_IP` | empty | `rtc.node_ip` | the public address (IPv4 or IPv6), or a hostname (§10.2) |
| `TAVRN_RTC_ADVERTISE_IPS` | empty | `rtc.node_ip` + client aliases | more addresses or hostnames, comma-separated (§10.2) |
| `TAVRN_RTC_ADVERTISE_PRIVATE` | `false` | – | addresses of hostnames may be private (LAN, ULA); off: public ones only (`--dev`: always allowed) |
| `TAVRN_RTC_STUN_SERVERS` | empty (LiveKit's) | `rtc.stun_servers` | `host:port` list for the detection |
| `TAVRN_RTC_TCP_PORT` | `7881` (`--dev`: 0) | `rtc.tcp_port`, `allow_tcp_fallback` | ICE over TCP; published and forwarded like the UDP range; 0 = off |
| `TAVRN_RTC_TURN_ENABLED` | `false` | `turn.enabled` | LiveKit's embedded TURN server (§10.3) |
| `TAVRN_RTC_TURN_UDP_PORT` | `3478` | `turn.udp_port` | TURN over UDP, published and forwarded; 0 = off |
| `TAVRN_RTC_TURN_TLS_PORT` | `5349` | `turn.tls_port`, `external_tls: true` | plain TCP behind the reverse proxy's TLS termination; clients use `turns:<domain>:443`; 0 = off |
| `TAVRN_RTC_TURN_DOMAIN` | `turn.<TAVRN_DOMAIN>` | `turn.domain` | the TURN/TLS name the proxy serves on port 443 |
| `TAVRN_RTC_TURN_RELAY_PORT_RANGE` | `30000-30999` | `turn.relay_range_*` | relay sockets inside the container (not published) |

The node validates all of them at start (addresses must be usable: no `0.0.0.0`, multicast or link-local, or
hostnames with at least one dot and a non-numeric top-level label; TCP ports
must not clash with `TAVRN_LISTEN`, `TAVRN_LIVEKIT_PORT` or each other; the TURN UDP port and relay range must not
overlap the media range).

### 10.2 Which addresses LiveKit announces

LiveKit's ICE candidates must carry addresses clients can reach. Inside a container the interfaces only have the
Docker network's private addresses (IPv4 `172.x`, and an IPv6 ULA `fd…` on IPv6-enabled networks), which are useless to
clients. The node therefore generates:

- **Explicit addresses** (`TAVRN_RTC_EXTERNAL_IP`, then `TAVRN_RTC_ADVERTISE_IPS` in order): the first IPv4 and the
  first IPv6 become `node_ip: "<v4>,<v6>"`; LiveKit announces every local address of that family as that address
  (the container's `172.x` becomes the public IPv4, its ULA the host's global IPv6). Every further address (LiveKit
  takes one per family) is returned to clients as `ice_aliases` in the join answers; the client adds each host
  candidate of the node once more with that address (same port, slightly lower priority). Typical use: the LAN
  address of the host for clients in the same network when the router has no NAT loopback ("hairpin").
- **No addresses** (production): `use_external_ip: true` — LiveKit asks STUN servers from every local address, IPv4
  and IPv6, and maps each local address to what STUN saw. `skip_external_ip_validation: true`, because LiveKit's
  self-check sends a packet to its own public address, which fails behind routers without NAT loopback although
  clients outside reach it; `external_ip_only: true` drops IPv4 addresses STUN could not map.
- **Development** (`--dev`) without addresses: the local interface addresses as they are.
- Outside development `rtc.ips.excludes` always lists link-local addresses (`fe80::/10`, `169.254.0.0/16`); with
  explicit addresses but no IPv6 among them also `fc00::/7`, so the container's ULA is not announced as it is.

**Hostnames** (dynamic DNS). ICE candidates always carry addresses (RFC 8445), so LiveKit cannot take a name. Entries
of `TAVRN_RTC_EXTERNAL_IP` and `TAVRN_RTC_ADVERTISE_IPS` may nevertheless be hostnames (`home.dyndns.example`): the node
resolves them before LiveKit starts and again every 60 seconds, or after the DNS TTL when that is longer (at most
every hour), A and AAAA, and puts all their addresses in place of the name (in configuration order, duplicates
dropped). Addresses of a hostname are announced only when public (`FEDERATION.md` §1.3 rule 3 ranges are left out)
unless `TAVRN_RTC_ADVERTISE_PRIVATE=true` or `--dev`; IP literals are taken as configured (LAN addresses stay
possible). When the resolved set changes the node logs it, rewrites `livekit.yaml` and restarts LiveKit through its
supervisor at once (no backoff); connected clients reconnect within the reconnect grace period (§5a), so their
sessions survive. A failing lookup keeps the host's last known addresses and logs a warning. A hostname that does not
resolve at start is left out with a warning and the other entries are used (voice never blocks the node); when no
address remains at all, LiveKit runs with the STUN detection (production) or the interface addresses (development)
and `/healthz` reports `voice_problem` until a name resolves.

**Dynamic addresses and proxies like Cloudflare.** Media ports cannot be proxied: HTTP reverse proxies and CDNs such as
Cloudflare forward neither UDP nor arbitrary TCP ports, so a media address must reach the host directly (a "grey
cloud", DNS-only record). Two robust setups for rotating addresses:

1. **Direct advertised addresses**: a dynamic-DNS hostname in `TAVRN_RTC_EXTERNAL_IP`/`TAVRN_RTC_ADVERTISE_IPS` with a
   low TTL (60–300 s); the node follows its changes as above. The media UDP range (and the ICE/TCP port) stays
   forwarded to the host.
2. **TURN with a hostname**: `TAVRN_RTC_TURN_ENABLED=true` with TURN over TLS `turns:turn.<host>:443` (§10.3). Clients
   resolve the TURN name themselves at every (re)connect, so a changed address takes effect at the next reconnect
   without any node involvement; keep the record's TTL low and DNS-only (not proxied) unless the proxy forwards raw
   TCP/TLS on 443 for that name (e.g. a layer-4 "spectrum"-style product).

Signaling (`/rtc` over the node's normal HTTPS) can stay behind the proxy in both cases.

IPv6 with Docker: the default bridge network has no IPv6, an IPv6-enabled network uses a private ULA. Publish the
media ports on the host's global IPv6 too (Docker does so for `ports:` entries without a host address when the
network has IPv6 and `ip6tables` is on) and either let STUN detect the global IPv6 or put it into
`TAVRN_RTC_ADVERTISE_IPS`. A changing IPv6 prefix speaks for the detection.

### 10.3 ICE over TCP and TURN

- **ICE/TCP** (`TAVRN_RTC_TCP_PORT`, default 7881): LiveKit listens on that TCP port in addition to the UDP range;
  clients fall back to it when UDP is blocked (`allow_tcp_fallback`). It must be published and forwarded like the
  UDP range.
- **TURN** (`TAVRN_RTC_TURN_ENABLED=true`): LiveKit's embedded TURN server relays media for clients behind strict NATs
  and firewalls that allow nothing but outgoing TLS. Clients get time-limited TURN credentials in LiveKit's join
  answer. TURN over UDP (`turn:<node_ip>:<udp port>`) needs that port published and forwarded; TURN over TLS
  (`turns:<TAVRN_RTC_TURN_DOMAIN>:443`) needs the reverse proxy to terminate TLS for that name on port 443 and forward
  plain TCP to `TAVRN_RTC_TURN_TLS_PORT` (the reverse proxy guide of `tavrn-node`); the node never handles TLS. The relay reaches
  LiveKit inside the container over the loopback interface: the node sets `enable_loopback_candidate` and
  `advertise_internal_ip` and allows relays only to `127.0.0.1/32` and `::1/128`
  (`allow_restricted_peer_cidrs`), never to other private addresses. Each participant may hold at most 12 relay
  allocations (LiveKit's quota).

### 10.4 Connection test

`POST /api/v1/voice/test` (any signed-in user, rate-limited like joins) → `200`:

```json
{ "url": "wss://node.example", "token": "<LiveKit JWT, 60 s>", "room": "test:01J…", "identity": "alice@node.example/01J…",
  "rtc": { "mode": "explicit" | "stun" | "local", "addresses": ["203.0.113.7", "2001:db8::7"], "ice_aliases": ["192.168.0.20"],
           "udp_ports": "61000-61100", "tcp_port": 7881, "turn_udp": false, "turn_tls": false } }
```

The token joins only its own empty room `test:<random id>`: hidden, subscribe-only, no data, no publishing; the
`/rtc` proxy accepts it for that room only, webhooks of test rooms are ignored, LiveKit drops the room a minute after
use. `503 voice.disabled`, `429 rate_limited`. The settings' **connection test** connects once without restrictions
(noting every candidate the node announced), then once per announced address over UDP, once per address over TCP and
once per TURN transport, each time allowing only that kind of candidate (and `iceTransportPolicy: relay` for TURN),
and reports per row whether it connected, over which candidate types and with which round trip, with a hint for
failures (UDP range not forwarded, NAT loopback missing for LAN clients, IPv6 not published, TCP port, TURN, or the
proxy not forwarding WebSockets on `/rtc`).

## 11. Calls in DMs and group DMs

A DM or group DM can hold one call at a time. It runs on the node hosting the conversation (the creator's home node,
`FEDERATION.md` §6.1) as LiveKit room `call:<conversation id>`, with the same end-to-end encryption as voice channels:
the frame keys come from the conversation's MLS group (`ENCRYPTION.md` §5a; the client commits a self update when it
joins). Participants and their identities work as in §1 and §5a (reservations, webhooks, reconnect grace,
reconciliation). Only members who accepted the conversation take part (message requests can neither call nor ring);
a member who leaves the group DM, is removed from it or deletes the account leaves its running call at once
(`call.update`; the call goes on for the others or ends as usual).
Calls live in the node's memory; a restart ends them.

### 11.1 Routes

All under `/api/v1/conversations/{conversation_id}/call`, for accepted members of a DM or group DM:

| Route | Answer | Effect |
|---|---|---|
| `POST …/start` | `200 CallJoin` | Starts a call (or joins the running one without ringing again): every other accepted member rings (§11.2); the answer is a LiveKit token like §3 |
| `POST …/join` | `200 CallJoin` | Answers/joins a running call; the user's devices stop ringing. `{ "role": "screen" }`: the device's screen publisher (§4b; no answer, no ring change) |
| `POST …/leave` | `204` | This device leaves (with its screen publisher). A DM call ends when one of the two hangs up after it was answered; a group call when the last one left. `{ "role": "screen" }`: only the screen publisher |
| `POST …/decline` | `204` | The user stops ringing; a DM call ends as missed; in a group the call ends as missed only when nobody answered and nobody else rings |
| `GET …` | `200 CallState` | `{ conversation_id, active, started_by, started_at, group, participants, ringing }` (`ringing` = addresses still ringing) |
| `PATCH …/state` | `200 CallState` | Own `muted`/`deafened`/`streaming`/`camera` as in §5 |

`CallJoin` = `{ url, token, expires_at, room: "call:<id>", identity, conversation_id, epoch, limits, participants,
reconnect_grace_secs, ice_aliases, call: CallState }`; the limits are the node's (DMs have no roles): audio at
`min(64, TAVRN_VOICE_MAX_BITRATE_KBPS)` (speech, §4a) with `audio_fec`, camera and screen share as the node policies allow. Errors: `400 call.not_direct`
(a room channel), `403 call.request_pending` (the requester has not accepted the conversation), `404
conversation.not_found`, `409 call.not_active` (join/decline without a call), `409 call.full`
(`TAVRN_VOICE_MAX_PARTICIPANTS`), `409 voice.not_connected` (state without a connection, or a screen publisher
without its device in the call), `403 voice.stream_forbidden` and `409 voice.screen_active` (screen publishers, §4b),
`429`, `503 voice.disabled`.

### 11.2 Ringing

- `call.ring` `{ conversation_id, node, from, started_at, group }` to the connections of every member that rings (on
  the hosting node). Members of other nodes without a connection there ring through their home node: the hosting node
  sends `notify` (`FEDERATION.md` §5.2) with `call: { state: "ring", from, started_at, group }`; the home node emits
  `call.ring` with `node` = the hosting node (rings older than 45 seconds are dropped), the client answers on the
  hosting node with a federated session. `call: { state: "end" }` stops the ringing there (answered, declined,
  ended or timed out); call hints are not coalesced like message hints.
- `call.update` `{ conversation_id, node, call: CallState }` to all accepted members on every change (start, ringing,
  participants, own state); `call.end` `{ conversation_id, node, reason, duration_secs }` with `reason` `ended` or
  `missed` when the call is over, `answered` or `declined` to the user's own devices when it stops ringing for them.
- **Ring time 45 s**: afterwards nobody rings any more; a call nobody answered ends as missed.
- Members who blocked the caller (or whom the caller blocked) are not rung; the home node also drops ring hints
  from callers its user blocked. A user may start at most 10 new calls per 10 minutes (`429`; joining a running
  call does not count).
- The caller's address in a ring hint is the hosting node's word (it hosts the conversation anyway); clients show
  the conversation as the hosting node reports it.
- System messages (plaintext, written by the node, like `system.encryption_changed`): `system.call.missed`
  `{ by, started_at }` and `system.call.ended` `{ by, started_at, duration_secs }` (`by` = who started the call; the
  author of the message is the caller). They count as unread for the others and raise `notify` hints like messages.

### 11.3 Reference client

- A "Call" button in the header of a DM or group DM (shows "Join call (n)" while one runs, "In call" for the own).
- Incoming calls: a banner on top of every page (portal, also on phones) with the caller, accept and decline, and a
  **ringtone** synthesized with WebAudio (`voice/cues.ts`): a friendly two-bar motif in C major pentatonic (G–C–E–G,
  E–D–C, soft sines with a quiet octave, 2.4 s loop) at a separate ring volume; group calls ring with a gentler, lower
  variant. It stops on accept, decline, `call.end` or after 45 s.
- The call view reuses the voice stage's tiles (avatar or camera, speaking glow, screen shares with focus) and its
  controls (mute, deafen, camera, screen, hang up); group calls list who is in; the members still ringing show as
  dashed tiles. Full screen on phones, a large panel on desktop; it can be minimized to the voice bar (phones: a small
  pill). One device is in at most one call or voice channel.
- The system messages render as localized entries with an icon ("Missed call from …", "Call from … ended · 2:31");
  every new ring also goes into the notification center (kind `call`, linking to the conversation).
