# tavrn federation (`federation.v1`, draft v1)

This document specifies how tavrn nodes find, authenticate and trust each other, and how a user of one node signs
in, joins rooms, writes DMs and keeps friends on another.

License: CC-BY-4.0 (this text; schemas, test vectors and permission tables Apache-2.0, see `LICENSE.md`). This document is normative for nodes and clients that announce the capability
`federation.v1`. It refines the design notes 4.1a, 4.2, 4.2b, 9b, 9c and 9d and **replaces**
`PROTOCOL.md` §9 (the route names there are superseded by the ones below). Encryption rules stay in
`ENCRYPTION.md`; this document only says how they apply to identities of other nodes.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119. Byte-string notation
(`||`, `u16`, `u64`, `str16`, base64url without padding) is the one of `ENCRYPTION.md` §0; additionally
`u8(x)` is one byte and `u32(x)` four bytes big-endian.

## 0. Principles and terms

- **A room lives on exactly one node; a user has exactly one home node.** Nothing is replicated. Clients
  talk directly to the node that hosts a room or conversation, with a session of *that* node.
- **Home node (H)**: the node of the account (`alice@h.example`). It authenticates the user (password +
  second factor, passkey, later SSO) and is the only authority for the user's profile, identity key,
  devices, KeyPackages, friends, blocks, backups, secret storage and conversation index.
- **Target node (T)**: any other node the user's client talks to. A room node (R) or the node hosting a
  DM is a target node.
- **Peer**: any other node. **Remote user** (on T): a user whose home node is not T.
- **Node token**: the JWT with `typ = "s2s"` (PROTOCOL.md §5) that authenticates a server-to-server
  request. It is called *node token* in prose; the claim value stays `s2s`.
- Server-to-server traffic is limited to: fetching public documents (`.well-known`, profiles, keys,
  directory), the inbox (signed notifications, §5) and the KeyPackage claim (§3.5). Everything a user does
  on another node goes through that node's normal client API with a **federated session** (§2.5).

Trust does not live in nodes (design note 9c): a node only vouches for its own users (signature of its node
key over `sub = <user>@<its domain>`), and every end-to-end property is verified by clients.

## 1. Node identity and discovery

### 1.1 Discovery document

The discovery document is `GET https://<domain>/.well-known/tavrn` (PROTOCOL.md §2). For federation it
MUST contain `tavrn` (protocol major `1`), `domain`, `api`, `ws`, `software`, `capabilities` (with
`federation` and `federation.v1` while federation is enabled, §11.4) and `keys`. `federation.v1` adds the
following optional fields; unknown fields are ignored:

```json
{
  "contact": "mailto:admin@node.example",
  "build": { "commit": "a1b2c3d", "image_digest": "sha256:…" },
  "federation": {
    "version": 1,
    "limits": { "federated_logins_per_minute": 60, "inbox_per_minute": 300, "max_remote_users": 10000 }
  }
}
```

`contact` and `build` are information, not proof (design note 9c). `federation.limits` publishes the
per-domain limits of §11.1 so peers can pace themselves and the conformance check (§9) knows what to expect.

### 1.2 Signing keys and rotation

- `keys` lists every currently valid node signing key as `{ kid, alg: "EdDSA", crv: "Ed25519", x }`
  (`x` = base64url of the 32-byte public key). `kid` is 1–64 characters of `[A-Za-z0-9._-]` and unique in
  the document; at most 10 keys. A `kid` MUST NOT ever be reused for a different key: peers treat a known `kid`
  with another key as a key conflict and block the node (§1.4). Derive `kid`s so that a lost key directory cannot
  produce one again (the reference node: the creation date plus a random suffix, `20261011-3f9a1c`; a date alone
  repeats when a node restores a backup without its keys and generates a new key on the same day).
- A node signs with its newest key. **Rotation**: add the new key (the reference node: a new file
  `/data/keys/node-<kid>.pem`) and restart; peers learn it on first use through the unknown-`kid`
  refresh (§1.4), so the new key can be used immediately. The old key MUST stay listed for at least
  **7 days** after it was last used for signing (the longest-lived signed object is a directory listing,
  48 hours, §7.3), then it is removed.
- **Compromise**: the operator removes the key at once and adds a new one. Peers stop accepting it at the
  latest when their cached document expires (at most 1 hour, §1.4); there is no stale use of keys.

### 1.3 Outbound HTTP client (all requests to peers)

Every request a node makes to another node (discovery, profiles, keys, avatars, directory, inbox,
KeyPackage claims) goes through one dedicated HTTP client with these rules (design note 9b):

1. **Target**: the discovery document at `https://<domain>/.well-known/tavrn`, every API path (`/api/v1/…`)
   at the `api` endpoint that document names (delegation, §1.4; resolution order in the decision table
   below), which may be on another host. `domain` MUST
   be a valid node domain (lowercase, IDNA A-labels, at least one dot, at most 253 characters, no port, no IP
   literal, no user info). URLs are always built by the node from the domain, its validated document and a
   path the node chooses; paths and hosts from other received payloads are never fetched. Endpoint hosts are
   domain names (IP literals only for development) and go through the same address checks (rule 3).
2. **TLS** verification is mandatory (system/webpki roots, hostname check). There is no switch to
   disable it. HTTP is used only for development peers (`TAVRN_FEDERATION_DEV_PEERS`, rule 8).
3. **SSRF protection**: the client resolves the domain itself and refuses the request
   (`federation.address_forbidden`) if **any** resolved address is in a non-public range: `0.0.0.0/8`,
   `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
   `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`,
   `240.0.0.0/4`, `192.88.99.0/24`, `::/128`, `::1/128`, `::/96` (IPv4-compatible), `2001::/32` (Teredo),
   `64:ff9b:1::/48` (local-use NAT64), `64:ff9b::/96`, `::ffff:0:0/96` and `2002::/16` (6to4; these three are
   checked against the embedded IPv4 address), `100::/64`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `ff00::/8`.
   The connection is then made to the **vetted address** (with SNI and `Host` = domain), never by resolving again, so DNS
   rebinding cannot switch the target. `TAVRN_FEDERATION_ALLOW_PRIVATE=true` lifts the range check (for
   development, tests and closed intranets; the node logs a warning at startup).
4. **Redirects**: at most 3, only to `https` on the **same host**; any other redirect is an error.
5. **Limits**: connect timeout 5 s, total timeout 10 s (inbox deliveries 15 s); response bodies are read
   with a hard cap and the request fails beyond it: discovery document 64 KiB, profile 16 KiB, user keys
   256 KiB, KeyPackage claim 512 KiB, avatar 1 MiB, directory page 1 MiB. At most 4 concurrent requests
   per peer and 64 overall; excess requests queue, first for a slot of their peer and only then for one of the
   node-wide slots (a slow peer never holds node-wide slots while it waits), at most
   `TAVRN_FEDERATION_PERMIT_TIMEOUT_SECS` (reference node default 10 s), then the request fails
   (`502 federation.peer_unreachable`).
6. **Headers**: `User-Agent: tavrn-node/<version> (+https://<own domain>)`, `Accept: application/json`;
   no cookies are sent or stored; environment proxy variables are ignored.
7. Only `200`–`299` responses are parsed. Content types other than `application/json` (or the image types
   of avatars) are refused.
8. **Development peers**: with `--dev` only, `TAVRN_FEDERATION_DEV_PEERS` maps domains to base URLs
   (`a.test=http://127.0.0.1:18081,b.test=http://127.0.0.1:18082`). Mapped domains bypass rules 1–3 for
   scheme and address; every other rule applies. The variable is refused at startup without `--dev`.

**Resolving a domain** (design note 4.2c; order and caching in §1.4). A node finds a peer's endpoints in the order
**well-known → SRV → direct domain**. The operator of a domain therefore needs EITHER the well-known on the
identity domain's website OR the `_tavrn._tcp` SRV record, never both:

| `https://<domain>/.well-known/tavrn` answers | `_tavrn._tcp.<domain>` SRV (if `TAVRN_FEDERATION_SRV_FALLBACK`, default on) | Result (`source` of `GET /federation/resolve/{domain}`) |
|---|---|---|
| `200`, valid, names `domain` | not consulted | the document's `api`/`ws`/`web` (`well_known`) |
| `200`, invalid or names another domain | not consulted | `502 federation.peer_invalid` |
| `404` (website without the document) | a target serves a document naming `domain`, over TLS valid for `domain` | that document's endpoints (`srv`) |
| `404` | the target's document names another domain or is invalid | `502 federation.peer_invalid` (no direct attempt) |
| `404` | a target resolves to a non-public address (rule 3) | `502 federation.address_forbidden` |
| `404` | no record, lookup failure, or no target reachable | `https://<domain>/api/v1`, `wss://<domain>/api/v1/ws`, web `https://<domain>` (`domain`), cached 5 minutes |
| no HTTPS server: connection refused or reset, DNS failure, TLS failure, timeout | a target serves a document naming `domain`, over TLS valid for `domain` | that document's endpoints (`srv`) |
| `404` or no HTTPS server | a target presents a certificate that is not valid for `domain` (only for itself) | `502 federation.peer_unreachable` |
| no HTTPS server | no usable record or no target reachable | `502 federation.peer_unreachable` |
| any other status (`5xx`, `401`, `403`, a refused redirect, …) | not consulted | `502 federation.peer_unreachable` |
| the domain resolves to a non-public address (rule 3) | not consulted | `502 federation.address_forbidden` |

SRV targets are tried lowest priority first, then highest weight, at most 3; they must be domain names (no IP
literals) and are vetted like any host (rule 3). The SRV record only says **where** to connect: the node connects to
the target's vetted addresses and port, but the TLS handshake and the request are for the identity domain (SNI
`<domain>`, `Host: <domain>:<port>`, `GET https://<domain>:<port>/.well-known/tavrn`), and the target's
certificate MUST be valid for `<domain>` (a SAN entry or a wildcard covering it suffices). A certificate valid only
for the target host is refused like any TLS failure. This is the rule of other federated systems with SRV
delegation, and it applies to every party that resolves through SRV, nodes and native apps alike.
With `TAVRN_FEDERATION_SRV_FALLBACK=false` the SRV column is skipped: a `404` goes straight to the direct domain,
a missing server is `federation.peer_unreachable`. Development peers (rule 8) use SRV only after a `404` (a
stopped development peer fails at once). Browsers cannot query DNS records; web clients get the same result
through the node they were loaded from (`GET /federation/resolve/{domain}`, §13.2 "Discovery for browsers").

**Failing cached endpoints.** A request to a cached endpoint that fails at the transport level (connection
refused or reset, timeout, TLS failure) or with `502`/`503`/`504` resolves the domain again at once instead of
waiting for the cache lifetime, at most once per domain and minute (a peer that is simply down causes no
amplification). If the endpoint moved, the new one replaces the cached one, a `GET` is repeated once on it, and
the peer's cached document (with its keys) is refetched on next use; signed `POST`s (inbox, claims) are not
repeated, the outbox retries them on the new endpoint. If the re-resolution fails or names the same endpoint,
the cached endpoint stays until its lifetime ends.

**Application URLs** (event subscriptions and the interactions URL, `APPLICATIONS.md` §6.3) are not node domains
but are fetched with the same address rules: rule 3 for every resolved address and for IP literals, the request
pinned to the vetted addresses, no proxies or cookies, the same `User-Agent`. Differences: the URL is the
owner's (`https://` only, no credentials or fragment, at most 2048 characters; `http://` only on development
nodes), **no redirects at all**, responses at most 64 KiB, timeouts 5 s (verification), 10 s (events) and 3 s
(invocations). `TAVRN_APP_ALLOW_PRIVATE_URLS` (default `true` only on development nodes) lifts the range check
for application URLs only.

### 1.4 Fetching and caching a peer's document

- **Resolution order** (design note 4.2c, PROTOCOL.md §2; decision table in §1.3):
  1. `https://<domain>/.well-known/tavrn`, always on the identity domain itself. Its `api`, `ws` and `web` may
     name another host (delegation: `tavrn.org` → `https://app.tavrn.org/api/v1`); every API request then goes
     there. The endpoints must be `https`/`wss` URLs without credentials, query or fragment (`http`/`ws` only
     in development); `api` ends in `/api/v1`.
  2. **No document** (`404`, or no HTTPS server at all: connection refused, DNS or TLS failure, timeout) and
     `TAVRN_FEDERATION_SRV_FALLBACK` (default on): the `_tavrn._tcp.<domain>` SRV records; the target must
     present a certificate valid for `domain` (§1.3) and its document must name `domain`.
  3. **Still nothing after a `404`**: the API is `https://<domain>/api/v1` (cached for the minimum lifetime), the
     last attempt. Any other HTTP status, a refused address or an invalid document is an error at every step.
- A node fetches a peer's document on first need and validates it: `tavrn` known, `domain` equal to the
  requested domain, keys well-formed (32-byte Ed25519 points, unique `kid`s, at most 10), endpoints as in the
  resolution order. An invalid document makes the peer unusable (`502 federation.peer_invalid`).
- Cache: in `known_nodes` (domain, document, keys, `fetched_at`, `expires_at`). TTL = the response's
  `Cache-Control: max-age` clamped to **5 minutes – 1 hour**. The API endpoint (the delegation) is cached with
  the same lifetime; a node that restarts takes it from the cached document. A failing cached endpoint is
  resolved again at once (§1.3, at most once a minute per domain). After expiry the document is refetched on
  next use; if that fails, the cached document is **not** used for verifying tokens (`502
  federation.peer_unreachable`), but MAY still be shown as information.
- **Unknown `kid`**: when a token names a `kid` that is not cached, the node refetches the document once,
  at most once per 5 minutes per peer (negative cache), then fails with `federation.token_invalid`.
- **Key consistency**: if a refetch returns a different key for a `kid` already seen, the node treats it as
  a hard failure (§9.4) and keeps the old cache entry blocked until an operator decides. The same holds when the
  document now comes from another source than before (`well_known` → `srv` or back) and shares **no** key with the
  keys seen before: a takeover looks exactly like that, a real move keeps at least one key during the change
  (§1.2). The peer's federated sessions on this node end with the block (§2.5).
- **Failed fetches**: a fetch that fails or returns an invalid document is remembered per domain for 60 seconds;
  during that time requests that need the domain's keys to check a signature (inbox, claims, federated logins)
  fail at once with the same error instead of fetching again, so unsigned requests naming a slow or foreign
  domain neither tie up the client nor make the node fetch other sites' URLs on demand. A request that found no free
  local connection slot in time is not a failure of the peer and is not remembered. Fetches for issuers the node
  has no cached document of, started by requests not verified yet, run in a few slots of their own
  (`TAVRN_FEDERATION_DISCOVERY_SLOTS`, reference node 12; when all are taken the request is refused at once with
  `503 federation.busy`), so requests naming many slow domains leave the other slots to known peers. Peers known
  only from requests whose signature never verified are capped (`TAVRN_FEDERATION_MAX_UNVERIFIED_PEERS`, reference
  node 1000; peers the node looked up itself, listed in its directory, with users or sign-ins never count): beyond
  it such requests naming new domains are refused with `503 federation.peer_limit` before any fetch. Cached peers
  unused for 30 days without users, sessions or directory entries are pruned.
- **Why DNS alone is never the trust anchor.** The node's signing keys are what every federation decision rests
  on, and plain DNS (no DNSSEC validation, any resolver on the path) can be spoofed by anyone on the network path
  of the fetching party. A spoofer can make the direct fetch fail (a black-hole address, an invalid certificate)
  and answer the SRV query with a host of their own. Without the certificate rule they would then hold valid keys
  for every user of the domain. With it, they also need a certificate for the identity domain itself, which DNS
  spoofing alone does not give; TLS for the identity domain stays the anchor whichever path found the server.
- Clients follow the same rules where a browser allows (HTTPS, size cap, `domain` check, resolution step 1;
  when the domain serves no document (`404`) or the browser cannot fetch it at all, e.g. without CORS headers,
  they ask the node they were loaded from, `GET /federation/resolve/{domain}`, which runs the whole order
  including SRV); they cache the endpoints per domain for at most 1 hour. Native apps that can query DNS (the
  desktop app, before its first sign-in, has no node to ask) run the whole order themselves: well-known, then SRV
  after a `404` or without an HTTPS server, then the direct domain after a `404` only. At the SRV step they connect
  to the target's host and port but make the request for the identity domain: TLS SNI and `Host` name `domain`, and
  the target's certificate MUST be valid for `domain` (the same rule as for nodes, §1.3); a certificate valid only
  for the target counts as a transport failure of that record, and with no record left the domain is unreachable.
  A TLS failure of the direct fetch may still lead to SRV: a forged DNS answer alone cannot hand the app another
  node, because a target cannot present a certificate for the domain without controlling it.
  The stored session of a node keeps both the identity domain (addresses, display) and its endpoints
  (requests).

### 1.5 Domain policy

Evaluated for every federated login, inbox message, claim and outbound request, in this order:

1. Federation disabled (`TAVRN_FEDERATION_ENABLED=false`) → `403 federation.disabled`.
2. Domain on the node blocklist (`TAVRN_FEDERATION_BLOCKLIST`, admin node bans `POST /admin/bans` with a
   domain subject, automatic blocks of §9.4) → `403 federation.peer_blocked`. The blocklist always wins. Entries
   of the blocklist and domain bans (node bans here, room bans in §3.3) also cover every subdomain of the named
   domain: a ban of `evil.example` refuses `a.evil.example`.
3. `TAVRN_FEDERATION_ALLOWLIST` non-empty and the domain not on it → `403 federation.peer_blocked`.
4. Per-domain rate limits (§11.1) → `429` with `Retry-After`. They are charged only for requests whose signature
   verified, so requests forged in a peer's name cannot use up its budget. Before the signature check (which may
   fetch the claimed issuer's keys) the receiver limits per client address: inbox and claims per address,
   federated logins per (domain, address) with the per-domain value (a peer's own burst of invalid logins, as the
   conformance check `rate.limits` of §9 sends, still reaches `429`).

Blocking a domain on H also means H refuses federation tokens for it, so H's users cannot use rooms on a
blocked node (clients show "Your home node does not federate with x.example"). Blocked domains are never
passed on in the directory (§7).

Outbound requests include everything a node sends or fetches on its own: outbox deliveries (§5.3), profile and
image mirroring (§2.7), key refreshes, claims and application documents. Outbox entries for a domain that fails
steps 1–3 are dropped as undeliverable when they come due, also those queued before the ban or block. Only the
conformance checks of §9, which decide automatic blocks and their end, still reach blocked peers.

## 2. Tokens and federated sessions

### 2.1 Common JWT rules

All tokens are compact JWTs with the header `{"alg":"EdDSA","typ":"JWT","kid":"<kid>"}` (the reference
implementation (`tavrn-node`) rejects every other header). The token kind is the **claim** `typ`.
Mandatory claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti` (ULID), `typ`. Verifiers MUST check, for
tokens of another node:

- `iss` is a valid domain, is not the verifier's own domain, passes the domain policy (§1.5), and the key
  for `kid` comes from the `.well-known` of exactly that domain (never from the request);
- signature (strict Ed25519), `typ`, `aud` = the verifier's own domain;
- **clock skew ±5 minutes**: `iat ≤ now + 300 s`, `exp > now`, and `exp − iat` at most the lifetime of the
  token kind;
- `jti` not seen before for this `iss` (stored until `exp + 300 s`).

### 2.2 Federation token (`typ = "federation"`)

Issued by H for one target node, proves "this client acts for `alice@h.example` with device D":

| Claim | Value |
|---|---|
| `iss` | H's domain |
| `sub` | the user address `alice@h.example`; its domain MUST equal `iss` (verifiers reject anything else with `federation.issuer_mismatch`) |
| `aud` | the target domain |
| `typ` | `"federation"` |
| `iat`, `exp` | `exp − iat ≤ 600` (10 minutes) |
| `jti` | ULID, single use |
| `kind` | `"user"` or `"bot"` |
| `owner` | bots only: the owner's address (same domain as `iss`) |
| `device` | the device ULID on H (the device of the session that requested the token) |
| `pv` | the user's current `profile_version` (§2.7), a signed hint for profile refreshes |
| `app` | bots only (`APPLICATIONS.md` §2.8): the application ULID on H; T shows the bot with `application_id = <iss>/<app>` |
| `scopes` | bots only: the effective scopes of the bot's app token (array of strings); T applies them like H. Absent (older H) = all scopes; T ignores scope strings it does not know. Users' tokens carry neither claim (`401 federation.token_invalid`) |
| `age_over_18` | `age.v1` (PROTOCOL.md §5e): `true` when H's account is 18 or older by its date of birth, `false` when it is younger, `null` when the account has no date of birth (`unknown`); bots carry their owner's value. Absent (older H) = `null`. Any other type makes the token invalid (`401 federation.token_invalid`) |

Note that `sub` of a federation token is an **address**, while `sub` of a session token is the
node-local user ULID.

**The age claim (`age.v1`).** `age_over_18` is the only age information that ever leaves the home node: never the
date of birth, never in the profile (§2.7), the directory or any event. H signs it into every federation token, so
the claim travels with each federated login, and a user who turns 18 is an adult on T from the next login. T
stores the claim of the latest federated login with the remote user (a stub user that never logged in has none),
treats `false` and `null` alike as "below 18", enforces its age gates with it at join, read, search, notifications
and voice exactly as for its own users (PROTOCOL.md §5e), and never exposes it: not in the federated session
response, not in `GET /users/me` on T, not to other users, not in errors (`403 age.restricted` names the gate,
never the status).

### 2.3 Node token (`typ = "s2s"`)

Authenticates one server-to-server POST:

| Claim | Value |
|---|---|
| `iss`, `sub` | the sending node's domain (both) |
| `aud` | the receiving node's domain |
| `typ` | `"s2s"` |
| `iat`, `exp` | `exp − iat ≤ 300` (5 minutes) |
| `jti` | ULID, single use |
| `htm`, `htu` | HTTP method and path (`"POST"`, `"/api/v1/federation/inbox"`), so a token cannot be replayed on another route |
| `body_sha256` | base64url SHA-256 of the exact request body bytes |

Sent as `Authorization: Bearer <token>`. The receiver checks §2.1, `htm`/`htu` against the request and the
body hash (`401 federation.body_hash_mismatch`) **before** parsing the body. A fresh token is created for
every attempt; retries resend identical body bytes.

### 2.4 Issuing a federation token (on H)

`POST /api/v1/federation/token` `{ "target": "community.example" }` → `200`
`{ "token": "<jwt>", "target": "community.example", "expires_in": 600 }`

- Auth: a full session (password **and** second factor, or passkey-only; pre-auth tokens are refused with
  `401 auth.second_factor_required` as everywhere) or, for bots, an app token. H issues tokens to its own bots
  only while `TAVRN_APPS_FEDERATE` is on (`403 federation.bots_refused`); the token then carries `kind = "bot"`,
  `owner`, `app` and `scopes` (§2.2). Federated sessions
  of remote users on H cannot request tokens (`403 federation.local_only`).
- `target` MUST be a valid domain (`400 federation.domain_invalid`) other than H itself (`400
  federation.target_self`) and pass H's domain policy (§1.5). H does not contact the target.
- H records `(user, device, target, last_issued_at)` in `federation_targets` (pruned after 30 days without
  a new token). This is the recipient list for revocations and key changes (§2.9, §5.2).
- Rate limit: 30 per minute per device (`429`).

### 2.5 Federated session (on T)

`POST /api/v1/auth/federated` `{ "token": "<federation jwt>", "device_name"?: "Firefox on Linux" }` →
`200` session response as in PROTOCOL.md §5a.1 (`status: "ok"`, `user`, `access_token`, `refresh_token`,
`expires_in`, `device_id`) plus `"session_expires_at"`.

T verifies, in this order: federation enabled; `iss` passes the domain policy; document and key of `iss`
(§1.4); §2.1; `typ = "federation"`; `sub` domain = `iss`; `kind`/`owner` consistent (`owner` domain = `iss`);
`jti` unused (`401 federation.token_replayed`); node-level bans of the user address, its domain and, for
bots, the owner (`403 federation.user_banned`); remote bots allowed (`TAVRN_FEDERATION_REMOTE_BOTS`, `403
federation.bots_refused`) and not on T's application blocklist (`403 app.blocked`, `APPLICATIONS.md` §4.4);
remote-user quotas (`403 federation.remote_limit`). There is **no password,
captcha or second factor on T**: H already enforced them before issuing the token.

T then creates or updates the remote user (§2.6, including the age claim of §2.2) and a device record for the home
device:

- The device identity used everywhere on T (session claim `dev`, MLS committer checks, Welcomes, message
  `device_id`) is the home device id from the token's `device` claim, because MLS credentials and
  attestations name `alice@h.example/<home device id>` (ENCRYPTION.md §0.1). T MUST key remote devices by
  `(user, home device id)` and store `home_domain`; a remote device id MUST NOT be able to collide with or
  take over a local device row (composite key or a separate local row id).
- One session per `(user, device)`: a new federated login of the same device revokes the previous session.
- Lifetimes: access token 1 hour (normal `typ = "session"` token of T); refresh token rotating as usual
  (`POST /auth/refresh`) but the session **ends 7 days after the federated login** regardless of
  refreshes (`session_expires_at`). Before that, the client renews by presenting a fresh federation token
  again. `auth.refresh_invalid` from T always means: get a new federation token.
- Errors: `401 federation.token_invalid` (malformed, signature, `aud`, `typ`, lifetime, unknown `kid`),
  `401 federation.token_expired`, `401 federation.token_replayed`, `401 federation.issuer_mismatch`,
  `403 federation.disabled`, `403 federation.peer_blocked`, `403 federation.user_banned`, `403
  federation.bots_refused`, `403 federation.remote_limit`, `403 federation.kind_mismatch` (§2.6), `502
  federation.peer_unreachable`, `502 federation.peer_invalid`, `429`.
- A peer blocked after a key conflict (§1.4) or by an operator loses its federated sessions here at once: every
  request of a remote user checks that the home domain is still usable (domain policy and peer status).

### 2.6 Remote users on a node

A remote user is a normal `users` row with `domain` = the home domain (never the local domain):
`password_hash`, `email`, `email_verified_at` are NULL, `is_node_admin` is always false (`TAVRN_ADMIN_USERS`
only matches local users), `kind` and `owner_id` (the owner is itself a remote user row) come from the
token. Profile fields are a mirror. Extra state lives in `remote_users`:
`(user_id, profile_version, profile_fetched_at, avatar_sha256, keys_fetched_at, last_login_at)`.

- Rows are created lazily: by a federated login, or as a **stub** when a local action names a remote
  address (friend request, DM, direct invite, ban, mention resolution). Creating a stub fetches the profile
  (§2.7); `404` there → `404 user.not_found`. A stub is a `user` without owner; the first federated login
  takes `kind` and `owner` from the verified token, so a bot that was first known as a stub becomes a bot with
  its owner (bot scopes, "no bots" and owner bans apply). The reverse, a `bot` row presented by a token of
  another kind, is refused with `403 federation.kind_mismatch`: it would lift the bot rules.
- Remote users are addressed by **address** across nodes. Their user ULID is node-local and differs on every
  node; clients MUST NOT compare user ids of different nodes.
- Quotas: at most `TAVRN_FEDERATION_MAX_REMOTE_USERS` remote users in total and
  `TAVRN_FEDERATION_MAX_REMOTE_USERS_PER_DOMAIN` per home domain. Stubs that an inbound message creates (the
  sender of a `friend.request`) may fill the total only up to a reserve kept for federated logins (reference
  node: a tenth of the total, at least one row), so that requests in invented names cannot lock out the users of
  other nodes.
- Housekeeping: a remote user without session, membership, friendship, conversation, ban or authored
  message for 90 days (`TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`) is deleted.
- Disabling a remote user on T (node admin) works like for local users and only affects T.

### 2.7 Profiles

H serves `GET /api/v1/users/{username}/profile` (public, exists) with the additional fields
`profile_version` (integer, incremented by H on every change of the public profile: display name, images,
bio, links, DM setting) and `avatar_sha256` (base64url, null without avatar), and the avatar bytes at the new
public route `GET /api/v1/users/{username}/avatar` (`image/png|jpeg|webp|gif`, at most 1 MiB, `404` without
avatar; for an animated avatar its still image).

The profile also names (design note 4.9, PROTOCOL.md §6b) every image variant by path on H and
hash: `avatar_still` + `avatar_sha256`, `avatar` + `avatar_animated_sha256` when `avatar_animated`,
`header_still` + `header_sha256`, `header` + `header_animated_sha256` when `header_animated`, plus `bio`,
`links` and the effective `dm_policy`. T accepts image paths only of the exact form `/api/v1/media/<ULID>`
(`/animated` for animated variants) on H, fetches a variant only when its hash changed (avatars ≤ 1 MiB,
headers ≤ 2 MiB), requires the hash and the magic bytes (raster images; animated variants animated WebP; never
SVG) to match and serves its own copy under its own media ids; old copies are deleted. Bio and links are
validated like local input and every link URL is derived again on T (a URL in the profile is ignored).
A profile without the new fields (older nodes) mirrors the avatar from `/users/{username}/avatar` and counts
as `dm_policy = friends`.

T refreshes its mirror when (a) a federation token carries a `pv` greater than the stored
`profile_version`, (b) the mirror is older than 24 hours and the user is displayed or logs in (background
refresh, the old mirror stays on failure), (c) a node admin requests it, (d) a `profile.changed` notification
of H (§5.2) names a `profile_version` greater than the stored one (background refresh, the old mirror stays on
failure). Without (d) a change would reach T only with the user's next federated login there, since clients keep
their federated session for days and request no new federation token in between. The response's `address` MUST
equal the requested user (otherwise `federation.peer_invalid`). T copies the avatar into its own blob storage
when `avatar_sha256` changed and serves it like a local avatar, so clients never load avatars from foreign
nodes (no IP leak, no mixed CSP sources).

### 2.8 What remote users can and cannot do on T

Everything of the normal client API that concerns T's rooms and conversations works unchanged: rooms,
invites, join/leave, channels, messages, reactions, pins, uploads, MLS delivery service, Welcomes,
WebSocket, voice. Account routes belong to H and are refused on T with `403 federation.local_only`:
password, factors, WebAuthn, secret storage, identity and identity reset, device keys and KeyPackage
uploads, backups, friends, blocks, conversation index, invites list, federation tokens, account invites,
admin routes, applications (`/applications` and everything below it, including the event subscription routes
`/applications/{id}/subscriptions*` of `APPLICATIONS.md` §6.2 and a remote bot's `/applications/me*`, which it uses
on its own home node), and creating DMs/group DMs (they live on the
initiator's home node, §6). Creating rooms follows `TAVRN_ROOM_CREATION` (`federated` allows remote users).

**Remote bots** (`APPLICATIONS.md` §2.8): T stores `app` and `scopes` with the federated session and applies the
bot route table and scope caps of `APPLICATIONS.md` §2.4–§2.7 on top of the local-only list, with a request
budget per remote bot (`TAVRN_APP_RATE_REQUESTS`). A remote bot is in a room of T only through an installation
on T (`APPLICATIONS.md` §4.2): `POST /rooms/{room_id}/applications` with `{ application: "<H>/<id>" }` makes T fetch
the application's public document from H (`GET /api/v1/applications/{id}/public`, CORS-open, at most 128 KiB, `bot`
and `owner` must be addresses of H) and create the bot's stub user (`kind = bot`, owner stub). Installations are
refused while `TAVRN_FEDERATION_REMOTE_BOTS=false` (`403 federation.bots_refused`) or when the bot is on T's
application blocklist (`403 app.blocked`, also for federated logins). Local-only on T besides the list above: the
node administration of applications (`/admin/applications*`) and the SSO routes (`/auth/oidc/*` with a linked
identity); `/applications/{id}/public` needs no session at all.

**Webhooks** (`APPLICATIONS.md` §6.1) are room resources: remote members holding `manage_webhooks` manage them on
T like local members. Webhook messages are local plaintext messages of T's channels; their pseudo users
(`kind = "webhook"`) never federate (no federation tokens, no profiles on other nodes beyond T's own
`GET /users/{address}/profile`). Event subscriptions are fed only by rooms on the bot's home node; on T a remote
bot receives events over the WebSocket of its federated session.

### 2.9 Revocation

H sends `session.revoke` (§5.2) to every domain in `federation_targets` of the user when a device is
deleted (`device` set), and with `device: null` when the password changes, all sessions are revoked, the
account is disabled or deleted, or an admin resets the second factor. T revokes the matching federated
sessions immediately and closes their WebSockets (code `4001`). Because delivery is best-effort, the
7-day session cap and the 10-minute token lifetime bound the window.

## 3. Rooms on other nodes

### 3.1 Flow

1. The client of `alice@h.example` learns a room on `community.example` (invite link
   `https://community.example/invite/<code>`, Discover, a `room.invite` notification).
2. It obtains a federation token from H (`target = community.example`) and a federated session at the room
   node (§2.5), unless it still holds one.
3. It uses **the normal room API of that node unchanged**: `GET /invites/{code}` or `GET /rooms/{id}/preview`
   (rules, privacy notice and legal notice, `PROTOCOL.md` §6b), `POST /invites/{code}/join` or
   `POST /rooms/{id}/join`, channels, messages, MLS (external join with the
   node's GroupInfo), WebSocket. Nothing in the room API changes for federation.
4. It adds an entry to its conversation index on H (§4).

### 3.2 Admission checks on the room node

In addition to the existing room rules (join mode, invite validity, room bans, rules acceptance), the room
node applies to remote users: the domain policy (§1.5) at federated login; node-level bans of the address,
its domain and (bots) the owner; room bans of the address, its domain and (bots) the owner; "no bots" zones
(design note 4.7); the per-domain rate limits of §11.1 (`TAVRN_FEDERATION_RATE_API` counts all API requests of
remote users of one domain, after each user's own share: one account cannot use up its domain's budget).

### 3.3 Domain bans

Room domain bans use the existing route `POST /api/v1/rooms/{room_id}/bans` with
`{ "subject": "evil.example", "reason" }` (subjects are `user@domain` or a domain; own domain refused with
`400 ban.own_domain`), listed under `GET …/bans` and lifted with `DELETE …/bans/{subject}`. Node-level
domain bans use `POST /api/v1/admin/bans` the same way. A separate `…/bans/domains` route is not
introduced. A domain ban covers the domain and all its subdomains (a ban of `evil.example` also matches
`a.evil.example` and `user@a.evil.example`), like the blocklist (§1.5). For federation a domain ban MUST
additionally:

- remove every current member whose address is in that domain and every bot whose owner is in that domain,
  with `member.leave` events and `mls.remove_needed` for their leaves (as a user ban does);
- refuse joins, federated logins (node level) and API access (room level) of that domain;
- optionally send `ban.notify` (§5.2) to the home domains of removed users (information only).

### 3.4 Direct invites

`POST /api/v1/rooms/{room_id}/invites/direct` `{ "user": "alice@h.example" }` (permission
`create_invites`) creates a single-use invite bound to that address (expiry 7 days) and returns `202
{ invite }`. For a local user the node stores it in the user's invite list and emits `room.invite`; for a
remote user it queues a `room.invite` notification to the user's home node (§5.2). Joining with a bound
invite requires the session user to be that address (`403 invite.wrong_user`). Rate limit: 20 per hour per
inviter.

### 3.5 Device keys and KeyPackages of remote users

The room node needs remote users' identity and device keys to apply ENCRYPTION.md §4.5, and their
KeyPackages when a member adds them to a DM, group DM or private channel.

- **Keys**: the room node fetches `GET https://<home>/api/v1/users/{username}/keys` (public), checks that
  `user` equals the requested address and verifies every attestation (ENCRYPTION.md §3.1) against the
  returned identity key, dropping invalid devices, and every device's share key against its device key, dropping
  invalid share keys (the device stays). Cache `remote_device_keys` with TTL **1 hour**; refetch
  (at most once per minute per user) when a device identity is not in the cache, on `identity.changed`
  and `devices.changed` (§5.2) and after TTL. If H is unreachable, an expired cache MAY be used for up to
  24 hours; beyond that requests that need it fail with `503 federation.keys_unavailable`.
- **Claim through the conversation's node**: clients always claim KeyPackages from the node hosting the
  conversation: `POST /api/v1/users/{address}/key-packages/claim` on that node accepts foreign addresses
  (`alice%40h.example`). For a local user it claims locally as today; for a remote user it performs the
  server-to-server claim below and returns the result unchanged (`{ "key_packages": [ { device_id,
  key_package } ] }`). The room node MUST validate each KeyPackage (`ds::inspect_key_package`: credential
  identity `alice@h.example/<device_id>`, leaf key = attested device key from the key cache) and drops
  invalid ones. KeyPackages are never cached (single use).
- **S2S claim** on H: `POST /api/v1/federation/key-packages/claim` with a node token (§2.3)
  `{ "user": "alice@h.example", "requester": "bob@b.example" }` → `200 { "key_packages": [ … ] }`, same
  semantics as the local claim (one per attested device, deleted on claim). `user` MUST be local to H
  (`404 user.not_found`); `requester` is the user on whose behalf the room node claims (any domain; a user of H
  itself only if they signed in on the room node, i.e. it is among their federation targets of §2.4, else `403
  federation.claim_refused`). H
  refuses with `403 federation.claim_refused` if `user` blocked `requester`, and rate-limits per requesting
  node (`TAVRN_FEDERATION_RATE_CLAIMS`) and per `(requester, user)` (10 per hour). Errors of H are passed
  through to the client as `502 federation.peer_unreachable` / the original `4xx` code.
- Clients MUST NOT rely on the room node's key view: for attestation checks and pinning (ENCRYPTION.md
  §3.3) they fetch keys of a remote user **directly from the user's home node** (CORS-open public route).

### 3.6 MLS authorization for remote identities (ENCRYPTION.md §4.5)

The rules apply unchanged with these definitions:

- The authenticated device of a federated session is `<sub address>/<home device id>`; rule 1 requires
  that the committer leaf has exactly this identity and the attested device key **as published by the
  user's home node** (key cache, §3.5), and that the attestation verifies under the identity key published
  by that home node.
- Rules 2–4 ("attested device", "not attested under the current identity key") are evaluated against the
  key cache. On a cache miss for a device identity the node refetches before deciding.
- The room node's view may **lag** up to the cache TTL behind H (an identity reset or device deletion not
  yet seen). This is acceptable because clients verify every leaf and every message signature against keys
  they fetched from the home node themselves and run the ghost member check (ENCRYPTION.md §4.6); a lagging
  node cannot make a forged device acceptable to clients, it can only accept a commit that clients then
  flag.
- A node MUST NOT accept, for a remote user, keys or attestations from any source other than that user's
  home node.

## 4. Conversation index and Home view

The home node keeps per user an index of all rooms and conversations the user belongs to, on any node.
**The client maintains it**; H does not learn memberships from room nodes and does not validate entries
against them.

- `GET /api/v1/users/me/conversations-index` → `200 { "version": 7, "items": [entry] }` with
  `ETag: "7"`.
- `PUT /api/v1/users/me/conversations-index` `{ "items": [entry] }` with `If-Match: "<version>"` replaces
  the whole list and returns the new version; a stale version fails with `412 index.version_conflict`
  (`meta.version` = current), after which the client merges and retries. Without `If-Match` the write is
  accepted (last writer wins).
- Entry:

  ```json
  { "node": "community.example", "kind": "room", "room_id": "01J…", "conversation_id": null,
    "joined_at": "2026-10-04T12:00:00Z" }
  { "node": "h.example", "kind": "dm", "room_id": null, "conversation_id": "01J…", "peer": "bob@b.example",
    "joined_at": "2026-10-04T12:00:00Z" }
  ```

  `kind` is `room` (`room_id` required, the room's channels come from the room API), `dm` or `group`
  (`conversation_id` required); `peer` is the other party of a `dm`. `node` is a valid domain (the own domain
  included: clients SHOULD keep local memberships in the index too, so the list is uniform). `(node, kind,
  room_id | conversation_id)` is unique. H stores unknown fields unchanged (forward compatibility).
- Limits: 2000 entries, 512 KiB body (`413 index.too_large`), `400 validation.*` for malformed entries.
  Only full sessions of local users (`403 federation.local_only` for remote users).
- Clients add an entry after a successful join or after accepting a DM/group DM, and remove it after leaving,
  being removed, or when the hosting node answers `404 room.not_found`/`conversation.not_found` (or `403
  room.banned`) for it. Entries of unreachable nodes are kept.
- The index is stored **in plaintext** on H. H already learns the user's target nodes when it issues
  federation tokens; encrypting the index with the backup key would make it disappear with an identity reset,
  exactly when a user needs it to rejoin everything.
- **New device**: after login and unlocking the master secret (ENCRYPTION.md §8), the client reads the index,
  obtains a federated session per node and joins every group by external commit.
- **Home view**: the client lists rooms and conversations of all nodes from the index, grouped by node with the
  node domain shown for foreign nodes, with unread and mention counts from each node's lists and WebSocket
  (one connection per active node, design note 4.4), and marks entries of unreachable nodes as "unreachable"
  without blocking the rest (design note 9).

Pending invitations are not index entries: they are stored by H in the user's **invite list**
(`GET /api/v1/users/me/invites` → `{ items: [ { id, kind: "room" | "conversation", node, room?,
conversation?, inviter, via?, invite_code?, received_at, expires_at } ] }`, `DELETE /api/v1/users/me/invites/{id}`
to dismiss; at most 200, oldest dropped, expired ones pruned). Accepting = joining on the hosting node, adding
the index entry and deleting the invite.

## 5. Server-to-server notifications

### 5.1 Inbox

`POST /api/v1/federation/inbox` with a node token (§2.3), body (at most **64 KiB**, `413
federation.payload_too_large`, checked before reading further):

```json
{ "id": "01J…", "type": "friend.request", "from": "alice@a.example", "to": "bob@b.example",
  "at": "2026-10-04T12:00:00Z", "payload": { … } }
```

- `id` is a ULID chosen by the sender, unique per sender; `at` the creation time (equal to the ULID time).
  Messages whose `id` time is more than 7 days old or more than 5 minutes in the future are refused with
  `400 federation.message_stale`.
- `to` is a user address of the receiving node or the receiving domain itself; `from` is a user address or
  the sending domain. Which `from` a sender may use is fixed per type (§5.2); a violation is answered with
  `403 federation.type_forbidden` and counts as a spoofing attempt (§9.4).
- Response `202 Accepted` (empty body) once the message is stored or recognized as a duplicate.
  Unknown `type` values are accepted with `202` and ignored (forward compatibility). Unknown local recipients:
  `404 federation.recipient_unknown`. Processing after `202` is asynchronous and idempotent by
  `(iss, id)`; the receiver keeps seen ids for **7 days** (`federation_inbox_seen`).
- Delivery is best-effort; senders retry (§5.3); receivers MUST tolerate duplicates and reordering.

### 5.2 Types

| Type | Sender (`iss`) | `from` → `to` | `payload` | Receiver behavior |
|---|---|---|---|---|
| `room.invite` | the room's node | inviter address (any domain) → user | `{ room: { node, id, name, description, icon_url, member_count }, invite_code, expires_at }` | Drop silently if the user blocked the inviter; store in the invite list; WS `room.invite` to the user. Limits: 10/hour per `(iss, to)` |
| `conversation.invite` | the conversation's node | inviter address (any domain) → user | `{ conversation: { node, id, kind, name, members: [address] }, requested?, shared_rooms? }` | Apply blocks and the recipient's `dm_policy` under the receiver node's bound (§6.1), then store in the invite list (with `requested` and `shared_rooms`) and emit WS `conversation.invite` |
| `friend.request` | the requester's home node | user (domain = `iss`) → user | `{ request_id, message? }` (message ≤ 256 characters) | §6.2; drop silently when blocked |
| `friend.accept` | the accepter's home node | user (domain = `iss`) → user | `{ request_id }` | §6.2 |
| `friend.remove` | the remover's home node | user (domain = `iss`) → user | `{ request_id }` (`null` = friendship ended) | §6.2 |
| `identity.changed` | the user's home node | user (domain = `iss`) → receiving domain | `{ identity_public_key, identity_reset_at }` | Invalidate and refetch the key cache; WS `identity.changed` (PROTOCOL.md §6) to local friends, DM/group DM co-members and the user's own sessions; `mls.remove_needed` for leaves no longer attested; `system.key_changed { rotated: false }` in the welcome channels of the user's rooms on the receiving node and `key_reset_at` on the user's memberships there (`ENCRYPTION.md` §7b "History after a key reset") |
| `devices.changed` | the user's home node | user (domain = `iss`) → receiving domain | `{}` | Refetch the key cache; `mls.remove_needed` for leaves of devices that disappeared. Also sent after an identity key rotation (`ENCRYPTION.md` §9a): a refetch that shows another identity key writes `system.key_changed` into the welcome channels of the user's rooms on the receiving node (`rotated` = the document's continuity chain leads from the cached key to the new one) and sends WS `identity.rotated` (or `identity.changed`) to local contacts |
| `session.revoke` | the user's home node | user (domain = `iss`) → receiving domain | `{ device: id \| null }` | §2.9 |
| `profile.changed` | the user's home node | user (domain = `iss`) → receiving domain | `{ profile_version }` (integer ≥ 0) | Only for a remote user the receiver already knows (no stub is created) and only when `profile_version` is greater than the mirror's stored version: refresh the mirror in the background (§2.7 (d)), the old mirror stays on failure; otherwise ignored (`202`). Limited per `(iss, user)` (reference node: 10 per 10 minutes); beyond the limit `429` with `Retry-After` before the message counts as received, so the sender's retry (§5.3) brings the change later. After a refresh that changed the mirror, WS `user.update` to the user's rooms and contacts on the receiving node |
| `node.announce` | the announcing node | domain = `iss` → receiving domain | §7.2 | §7.2 |
| `ban.notify` | the room's node | room node domain → user | `{ room: { node, id, name }, scope: "room" \| "node" }` | Information only (no enforcement): optional notice to the user, only if the user signed in on the sending node (otherwise dropped silently, `202`); no reason is transmitted |
| `notify` | the conversation's node | node domain → user | `{ node, conversation_id, room_id, mention: bool }` | Push hint without content: H forwards it as web push (PROTOCOL.md §6d) to the user's devices without a connection and as WS `notify` to the user's connections on H |
| `app.install` | the room's node | room node domain → bot address | `{ room: { node, id, name }, installed_by }` (`room.node` = `iss`) | H checks that the recipient is a bot with an enabled application (else `404 federation.recipient_unknown`), adds the room to the application's install index and emits WS `application.install` to the bot (`APPLICATIONS.md` §4.5) |
| `app.uninstall` | the room's node | room node domain → bot address | `{ room: { node, id }, reason }` (`room.node` = `iss`) | H removes the index entry and emits WS `application.uninstall` |
| `app.changed` | the bot's home node | bot address (domain = `iss`) → receiving domain | `{ application_id, commands_version, deleted }` | Only for a bot the receiver knows as that application: refetch its profile (name, avatar) and, from step 3, the commands; `deleted: true` uninstalls the bot from every local room and disables its stub (installations and logins refused) |
| `legal.notice` | the node that received a takedown notice | domain = `iss` → receiving domain | `{ case_id, basis, work, explanation, locations: [{ kind, value }], reporter: { name, email, address, phone }, good_faith, accuracy, perjury, signature, submitted_at }` | Opens a case of its own (state `received`, origin `iss` and `case_id` recorded, idempotent per origin case); the fields are checked like the public form (`400 federation.payload_invalid`). No confirmation mail at receipt (the address comes from the sender, which confirmed the notice itself); the reporter hears from the receiver once its admin acts. Accepted even when the receiver's public form is off (`LEGAL.md` §1.5), but only from a node with federation history (users of it known to the receiver for at least a day, receiver users signed in there, or listed in the receiver's directory; else `403 legal.forward_refused`) and at most 10 per sending registrable domain (subdomains share it) and 50 in total per hour (reference node, `TAVRN_LEGAL_NOTICE_INBOUND_PER_HOUR`; `429`), both checked before the message counts as received |
| `report.forward` | the node holding the report | domain = `iss` → the reported user | `{ report_id, kind, category, detail, created_at, reporter, message_id?, snapshot?, evidence? }` (`MODERATION.md` §1.6; `reporter` a pseudonym, never an address) | Only nodes announcing `reports.v2`. Checks the payload like a report (`400 federation.envelope_invalid`), stores it in the node admins' inbox as `source: forward` with `origin { node: iss, report_id, reporter, reported_at }`, idempotent per `(iss, report_id)`, `report.create` to the node admins; at most `TAVRN_REPORTS_INBOUND_PER_HOUR` per sending registrable domain and five times as many in total per hour (`429`, checked before the message counts as received). Nothing is answered back, the reporter and the reported user are told nothing |
| `user.deleted` | the user's home node | user (domain = `iss`) → receiving domain | `{ delete_messages: bool }` | The stub is tombstoned like a local deletion (`LEGAL.md` §3.3): memberships, sessions, devices and keys go, messages move to a "Deleted user" tombstone with device ids and signatures stripped, their content and files are deleted too when `delete_messages`; the request is recorded in the audit log (`federation.user_deleted`) and the stub row is removed |

Claims about the receiver's own users: a user address of the receiving node named as the inviter (`from` of
`room.invite` and `conversation.invite`) or as the caller of a ring hint (`call.from` of `notify`) must belong to a
user who signed in on the sending node (the sender is among their federation targets, §2.4); otherwise the sender
claims something that cannot have happened (`400 federation.envelope_invalid`). Addresses of the sending node and
of third nodes are accepted as before (their users act on the sending node through federated sessions the receiver
cannot see). `notify` hints, rings included, are accepted only for a recipient who signed in on the sending node
(a member of something there); others are dropped silently (`202`). The block filters apply as listed in the
table.

Third-node users are **unverified**: the sending node can name a user of a third node (a member of a group it
hosts) as inviter or caller, but it cannot vouch for that user. The receiver therefore treats such an inviter as a
stranger: friendship with the named user does not count, the recipient's `dm_policy` applies as to anyone else,
`requested` is always `true`, and the stored invitation carries `via` = the sending node (`room.invite` and
`conversation.invite`; the summary object and the invite list entry), so clients show the inviter "via" the sending node and
never present it as coming from a friend. A ring hint naming a third-node caller reaches the recipient's
connections as `call.ring { …, via }` in the same way.

Who sends what:
- `identity.changed`, `devices.changed`, `session.revoke`: H to every domain in `federation_targets` of the user
  (§2.4) plus the home domains of the user's friends and of members of DMs/group DMs hosted on H.
- `profile.changed`: H to the domains of `identity.changed` after every change of a user's public profile (§2.7:
  display name, images, bio, links, DM setting; never the private voice background), with the version current
  when the message is queued. Bursts are coalesced: H holds the message a few seconds before the first attempt
  (reference node: 5 seconds) and keeps at most one queued `profile.changed` per user and target; a newer one
  replaces a queued older one (keeping its due time), so a series of edits leaves as one message with the latest
  version. Bots are announced with `app.changed` instead. Nodes that do not know the type ignore it (§5.1); their
  mirrors keep following (a)–(c) of §2.7.
- `notify`: the conversation's node to the home node of a remote member who has **no open WebSocket** on that
  node, for messages matching the member's notification setting on that node (default: DMs, group DMs and
  mentions) in conversations the member can view (in room channels: `view_channel` at the time of the message,
  PROTOCOL.md §6; thread follows and mentions do not override it),
  coalesced to at most one per conversation and user per 60 seconds; remote users can turn it off per node
  (`PATCH /api/v1/users/me { push_relay: false }` on T). It never carries content, author or message id.
- `ban.notify`: optional, only when the room (or node) setting `notify_bans` is on (default off).
- `legal.notice`: the admin of a node that received a notice about content hosted elsewhere forwards it to the content's
  node (`POST /admin/legal/notices/{case_id}/actions { action: "forward" }`).
- `report.forward`: the admin of a node holding a report about a user of another node forwards it to that user's home
  node (`POST /reports/{report_id}/forward`, `MODERATION.md` §1.6), only when the home node announces `reports.v2`.
- `user.deleted`: H, when an account is deleted, to the domains of `identity.changed` plus the nodes of the user's
  conversation index (rooms and conversations hosted elsewhere). Compliance cannot be enforced: each node is its
  own controller (`LEGAL.md` §3.3).
- `app.install` / `app.uninstall`: the room's node to the bot's home node after every installation and uninstall of a
  remote bot (reason `deleted` is not sent back). `app.changed`: H to every other node in the application's install
  index when its name, avatar, scopes or requested permissions change and when it is deleted.

### 5.3 Outbox and retries

Outgoing notifications are written to `federation_outbox` in the same transaction as the change that causes
them: `(id, target, type, body, attempts, next_at, created_at, expires_at, last_error)` where `body` is the
exact JSON sent on every attempt.

- A background worker delivers due entries (at most 4 concurrent per target, 64 overall).
- **Retry schedule** after a failed attempt: 1 min, 5 min, 30 min, 2 h, 12 h, then every 12 h, each with
  ±10 % jitter; a larger `Retry-After` (429/503) is honored. Give up after **3 days** (`expires_at`); `notify`
  expires after 1 hour, `node.announce` after 1 day.
- Failures: network errors, timeouts, `408`, `429`, `5xx` → retry. `401` → retry once after 5 minutes (the
  peer may refresh our keys), then permanent. Every other `4xx` → permanent.
- A target that failed delays all of its queued entries until its next attempt (no hammering).
- Giving up: the entry is deleted, logged (`federation.undeliverable`), counted in the admin overview, and for
  user-visible actions (friend request, direct invite) the originating user is told
  (`friend.request` stays visible as "could not be delivered", can be retried by the user).

### 5.4 Ordering

There is no ordering guarantee. Friend messages for one pair of users are applied only if their `at` is newer
than the last applied friend message of that pair; key-cache messages always trigger a refetch, so their order
does not matter; `profile.changed` compares its version with the mirror's, so an older one arriving late changes
nothing; invites are independent.

## 6. Direct messages, group DMs and friends across nodes

### 6.1 Where a DM lives

**Decision: a DM or group DM lives on the home node of the user who creates it (the initiator).**

- The initiator's client calls its own home node: `POST /api/v1/conversations { kind, members }` with foreign
  addresses (`bob@b.example`). The errors `conversation.member_remote` and `friend.remote` are retired; with
  federation disabled the node answers `403 federation.disabled` instead.
- The node creates stubs for remote members (§2.6), checks friendship and `dm_policy` of **its** node, blocks
  it knows, and creates the conversation, then queues `conversation.invite` to every remote member's home node.
- The recipient's home node checks the recipient's blocks and the recipient's `dm_policy` under its own
  bound before showing the invitation; otherwise it drops it silently (`202`). So both nodes' policies apply.
  **Message requests (design note 4.9):** the hosting node makes non-friends `requested` members and
  says so in the invitation (`requested: true`) together with the rooms **of the hosting node** the two share
  (`shared_rooms: [{ node, id, name }]`, at most 10; a node vouches only for its own rooms, entries naming
  another node are dropped). The recipient's home node decides: friends (by its own records) → a normal
  invitation; `friends` → dropped; `everyone_shared` → shown as a request when the two share a room of this node
  or the hosting node vouched for one, else dropped; `everyone` → shown as a request. Requests appear in the
  recipient's "Message requests"; accepting or declining happens on the hosting node with the federated
  session (`POST /conversations/{id}/accept|decline`), a block on the home node. The hosting node uses the
  mirrored `dm_policy` of the recipient's profile (§2.7) only for an early `403 dm.friends_only`.
- The recipient's client accepts by obtaining a federated session at the hosting node and using the normal
  conversation API there; the initiator's client adds the recipient's devices to the MLS group with
  KeyPackages claimed through the hosting node (§3.5). Welcomes wait on the hosting node.
- Group DMs: any member may add members (also remote members acting through their federated session);
  the hosting node sends `conversation.invite` for new remote members. Creator rules stay as in PROTOCOL.md §8a.
- DM uniqueness across nodes: before creating a DM, clients MUST look for an existing `dm` entry with the same
  `peer` in the index. Races can produce two DMs on different nodes; clients then show the one with the latest
  message and keep the other reachable as an older conversation.
- The index entry records the hosting node (`node`), so the client always knows where to go.

**Alternatives rejected**: (a) the *recipient's* home node: better spam control, but group DMs have no single
recipient, a DM would need an extra S2S "create on my behalf" round-trip before the initiator can write, and
the initiator could not start a conversation while the recipient's node is offline. (b) a deterministic node
(e.g. the lexicographically smaller domain): no benefit over (a) and still arbitrary for group DMs. (c)
replicating DMs on both nodes: contradicts principle 1 of the design notes. Spam is handled on the recipient's side by
`dm_policy`, blocks and the per-domain limits, and a recipient never has to contact the initiator's node
before accepting.

### 6.2 Friends across nodes

Friendships and requests are stored on **both** home nodes (each node stores its local user's side with the
remote party as a stub user).

- `POST /users/me/friends/requests { user: "bob@b.example" }` on A stores an outgoing request and queues
  `friend.request { request_id }`. B stores the incoming request (remembering A's `request_id`) and emits
  `friend.request`; blocked senders are dropped silently. New incoming requests are limited per sending node and
  recipient (reference node: 10 per hour, as for invitations, and at most 20 pending requests from users of one
  node per recipient); requests beyond that are dropped silently. Senders that already have a request or a
  friendship with the recipient are not limited.
- Accepting on B stores the friendship and queues `friend.accept { request_id }`; A stores the friendship.
  Crossing requests: when a node receives `friend.request` while it has an outgoing request to the same user,
  both become friends and it answers with `friend.accept` (as the local rule of PROTOCOL.md §8a).
- Declining, withdrawing and unfriending queue `friend.remove` with the request id or `null`; the receiver
  deletes the matching request or friendship. Blocking also removes the friendship and sends `friend.remove`
  (the block itself is never disclosed).
- Remote friends appear with their full address everywhere (design note 9d).

## 7. Peer directory and Discover

### 7.1 Known nodes

Every node keeps `known_nodes`: domain, name, description, software, capabilities, registration mode,
public room count, listing opt-in, keys, `first_seen`, `last_seen`, `last_announce`, conformance record (§9.3),
block state. A domain enters the table only after its `.well-known` was fetched and validated (§1.4). A node not
seen for **48 hours** (no announce, not confirmed through a reference node's list) is removed with its rooms. At
most 10 000 entries; beyond that the least recently seen are dropped. (The reference node keeps the peer cache and
the directory in two tables, `federation_peers` and `directory_nodes`, §13.1.)

### 7.2 Announcing

- Shortly after startup and then every **6 hours** (±10 min jitter), and whenever a listing-relevant room setting
  changes, a node sends `node.announce` to every reference node (`TAVRN_REFERENCE_NODES`, empty by default; the
  example configuration names a public test node). Announces go to reference nodes only; other nodes learn of it
  through the reference nodes' lists.
- Payload: `{ domain, name, description, software: { name, version }, capabilities, registration,
  public_rooms, users? , listing: true }` (`users` only if the operator publishes it). Strings are length-capped
  (name 64, description 500).
- The receiver verifies the sender through its `.well-known` (signature of the node token, `domain` match),
  updates `known_nodes` and `last_seen`. Announces are limited to one per domain per 10 minutes.
- With `TAVRN_DIRECTORY_LISTING=false` a node does not announce itself and other nodes MUST NOT list it even if
  they know it from federation traffic; it still federates and may read directories.
- A node also pulls the peer lists of its reference nodes every 6 hours (`GET /api/v1/directory/nodes`) and
  verifies every new domain through its `.well-known` before adding it.

### 7.3 Directory routes (public, no authentication, CORS-open)

- `GET /api/v1/directory/nodes?limit=100&cursor=…` → `{ items: [ { domain, name, description, software,
  capabilities, registration, public_rooms, users?, last_seen, conformance: "pass" | "warn" | "fail" |
  "unknown" } ], next }`. Served from the node's own knowledge; blocked, delisted and non-listing nodes are
  never included.
- `GET /api/v1/directory/nodes/{domain}` → the same entry plus `keys` (`kid` and SHA-256 fingerprint) as this
  node sees them; clients compare it with their own fetch (§9.2).
- `GET /api/v1/directory/rooms?q=&node=&local=&limit=50&cursor=…` → `{ items: [ { node, room_id, name,
  description, icon_url, member_count, listing } ], next }`: the node's own discoverable rooms plus cached
  rooms of peers (`remote_rooms`), searchable by name/description; `local=true` returns only the node's own.
- Items carry `age_gate` (`none` or `adults_only`, PROTOCOL.md §5e). Rooms with a gate are listed only to requests
  with the session of an adult (the route accepts an optional `Authorization` header); for anonymous requests, and
  so for the directory refreshes of other nodes, they are absent. Gated rooms therefore never enter other nodes'
  `remote_rooms`; users of other nodes reach them through invite links.
- Rooms appear only when their owner (or a holder of `manage_room`) marked them **discoverable**
  (`PATCH /api/v1/rooms/{room_id} { discoverable: true }`, only for `join_mode = public`, audited). The
  `GET /api/v1/rooms/discover` returns only discoverable rooms. A node may rate-limit anonymous requests to it per
  client address (the reference node: 120 per minute, like the directory reads; `429` with `Retry-After`).
- **Signed listings**: `listing` is a JWT (`typ = "listing"`, `iss` = hosting node, `sub` = room id,
  `aud = "tavrn-directory"`, `exp` = `iat + 48 h`, claims `name`, `description`, `icon_sha256`,
  `member_count`) created by the hosting node. Relaying nodes pass it verbatim; a node accepts a peer's room
  only with a valid listing signed by that peer; clients MAY verify it and MUST then prefer its values.
- Each node refreshes the room lists of the peers it lists every 6 hours (`local=true`, at most 200 rooms per
  peer) and drops rooms whose listing expired. Total cached remote rooms: `TAVRN_DIRECTORY_MAX_ROOMS`.

### 7.4 Abuse controls

Node admins can delist a node or a single remote room (`POST /api/v1/admin/directory/delist { domain, room_id? }`,
`DELETE …` to undo); delisted entries are neither shown nor passed on. Blocked nodes and nodes with a
conformance result `fail` are never listed. Reference nodes are ordinary nodes with the same controls; because
every node aggregates for itself, a misbehaving reference node can only hide entries, not forge them (listings
are signed, domains are verified through `.well-known`). Operators may configure several reference nodes.

### 7.5 Discover page

The client asks only its current node (`/directory/rooms`), shows node domain, conformance badge and member
count, and joins through §3.1 (federated session, `POST /rooms/{id}/join`).

## 8. Signing in with an account of another node

Every node serves the web client; there is no central client (design note 3.2). The login page offers
**"Sign in with an account of another node"**:

1. The user enters `alice@home.example` (or just the identity domain `home.example`; the username is asked for
   later). The client validates the grammar, resolves the domain (§1.4: `https://home.example/.well-known/tavrn`
   from the browser, CORS-open, or through its own node), checks `tavrn = 1`, `domain = home.example` and
   `federation.v1`, and shows the home domain prominently from here on. The API, WebSocket and web client of
   the home node may live on another host (delegation): every request goes to the endpoints of the document,
   the address stays `alice@home.example`.
2. **Direct login**: the client performs the normal login **against the home node's API** (PROTOCOL.md §5a:
   password, then TOTP or recovery code) and obtains a home session for a new device. Then it obtains
   federation tokens for the node it was loaded from and for every other node it talks to (§2.4, §2.5).
3. **Passkeys, login captcha and SSO** cannot run cross-origin (a WebAuthn assertion is bound to the relying
   party id = home domain; a Turnstile widget to its hostnames). For those the client uses the **connect
   flow**: it redirects to `https://home.example/connect?origin=<own origin>&state=<random>&code_challenge=<S256>`
   (a page of the home node's web client). The user signs in there with any method and confirms "Sign in to the
   web client of visited.example?"; the home client calls `POST /api/v1/auth/connect/code { origin,
   code_challenge, device_name }` (full session and a reauth token in `Tavrn-Reauth`, `PROTOCOL.md` §5c: the code
   becomes a new long-lived session, so a session alone must not mint one; `403 auth.reauth_required` otherwise) →
   `{ code }` (single use, valid 2 minutes, bound to origin and challenge) and redirects to
   `<origin>/connect/callback?code=…&state=…&node=home.example`. The visiting client checks `state` and calls
   `POST https://home.example/api/v1/auth/connect/token { code, code_verifier }` → session response for a new
   device, without a reauth token (`reauth_token: null`: the exchange proves no credential; the visiting client
   confirms with `POST /auth/reauth` when it needs sudo mode). Errors: `400 connect.origin_invalid` (not `https://<valid domain>`;
   `http://` origins are accepted only with `--dev`), `400 connect.code_invalid`.

   **App sessions** (capability `connect.app`). A native app (the desktop app) has no `https://<domain>` origin to
   return to: its pages run on `tauri://localhost` or similar. It uses the same page and code, with an **app
   session** that it polls instead of a redirect:

   1. `POST /api/v1/auth/connect/session { code_challenge (S256), device_name?, purpose? }` →
      `{ session_id, expires_in: 600 }`. The app keeps the PKCE verifier; `session_id` is 32 random bytes in
      base64url (43 characters). `device_name` (at most 64 characters, default "Desktop app") names the device
      the exchange creates and is shown on the confirmation page. `purpose` is `"login"` (default: sign in, no
      authentication) or `"unlock"` (unlock only, see "Sealed unlock material" below: needs a full session of a
      local user, `401` without one, `403 federation.local_only` for remote users, `403 app.bot_forbidden` for bots, and binds the session
      to that user); any other value is `400 connect.purpose_invalid`.
   2. The app opens `https://<web>/connect?session=<session_id>&state=<random>[&method=…]#k=<public key>`
      (`web` of the home node's document) in a window of its own without any native API, or in the system
      browser. The user signs in there with any method (password and second factor, passkey, SSO, registration
      with captcha) and confirms "Sign in to <device_name>?". The page reads the session's device name and
      purpose with the poll route (status `pending`) before the confirmation and never afterwards.
      - `method` (optional) starts one sign-in method at once instead of showing the whole form: `passkey` (the
        passkey-only login), `sso` (single sign-on) or `register` (the registration; `mode=register` is the older
        spelling and means the same). The page then shows only a short "Signing in with a passkey…" state with
        "Use another method"; unknown values are ignored.
      - `#k=<base64url X25519 public key, 32 bytes>` (optional) is the app's key for sealed unlock material. It
        is in the URL **fragment**, which browsers never send to a server; the page reads it once, keeps it for
        the page's lifetime (also across the sign-in and an SSO round trip in the same window) and removes it
        from the address bar. A page that finds no valid key never seals anything.
   3. The home client calls `POST /api/v1/auth/connect/code { session_id, code_challenge?, device_name?,
      sealed_unlock? }` (full session; a `login` session also needs a reauth token in `Tavrn-Reauth`, `PROTOCOL.md`
      §5c, an `unlock` session does not, it issues no code). Exactly one of `origin` and `session_id` is given (both or neither: `400
      connect.target_invalid`). `code_challenge`, if given, must equal the session's (`400
      connect.challenge_invalid`); `device_name` is ignored (the session's name wins). The node issues the code
      as for an origin (single use, 2 minutes, bound to the session, the challenge and the confirming device) and
      stores it with the session instead of redirecting. The page shows "You are signed in; return to the app"
      and does not redirect. `sealed_unlock` (optional, below) is stored with the session as well. For an
      `unlock` session no code is issued: the confirming user must be the session's user (`403
      connect.user_mismatch`), `sealed_unlock` is required, and the answer is `204`.
   4. The app polls `GET /api/v1/auth/connect/session/{session_id}` (no authentication, `Cache-Control:
      no-store`), at most every 2 seconds:
      - `200 { status: "pending", device_name, purpose, expires_in }` until the user confirms;
      - `200 { status: "ready", code?, node, sealed_unlock?, expires_in }` **exactly once** after the
        confirmation (`code` for a `login` session, never for an `unlock` session; `sealed_unlock` when the page
        sent one; `node` = the home node's identity domain, `expires_in` = the code's lifetime left);
      - then, and once the session or its code expired, `410 connect.session_expired`;
      - `404 connect.session_invalid` for an id the node does not know (never issued, or expired longer than 10
        minutes ago).
   5. The app exchanges `POST /api/v1/auth/connect/token { code, code_verifier, device? }` → session response
      for a new device (or the device it proves to hold, ENCRYPTION.md §3.4), exactly as above. A code bound to an
      app session is accepted without an `Origin` check: the verifier alone proves the app (a code bound to an
      origin still requires that `Origin`).

   Lifetimes and limits: a session is pending for at most 10 minutes; once confirmed it lives as long as its code
   (2 minutes); a session is confirmed at most once (a second confirmation: `410 connect.session_expired`), and
   its code and sealed unlock material are handed out at most once. Creating sessions is rate-limited per client
   IP (reference node: 10 per minute, 1000 per minute for the whole node), polling per session (60 per minute) and
   per client IP (600 per minute), all `429` with `Retry-After`. Unknown, malformed or expired session ids at
   `POST /auth/connect/code`: `400 connect.session_invalid` or `410 connect.session_expired`. The exchange is
   audited like the origin flow (`user.connect`, target `app`, with the device name).

   Security: the session id only yields a code, and the code is useless without the verifier (PKCE S256), so a
   leaked session id (it is part of the page's URL) gives nothing. Codes and sessions are single use and short
   lived. The confirmation page names the device and warns that the user must only confirm a sign-in they
   started themselves in their own app just now (a session id can be sent to a victim like a phishing link, as
   in every device authorization flow). The window that shows the home node's page has no native API. Device
   keys for end-to-end encryption are created in the app after the exchange, never by the page; the page in
   session mode skips the encryption setup and unlocking. A later version may add an app-scheme callback
   (`tavrn://connect/callback`, RFC 8252) as an accelerator; polling stays the baseline. Nodes without
   `connect.app` offer only the origin flow; apps then fall back to password and TOTP and tell the user that
   passkeys, SSO and registrations with a captcha need a browser.

   **Sealed unlock material** (part of `connect.app`). A passkey with the PRF extension unlocks the master
   secret in the same ceremony that signs the user in (ENCRYPTION.md §2.4 flow 2), but the ceremony runs on the
   home node's page while the master secret is needed in the app. The page therefore hands the PRF output to the
   app, encrypted to a key only the app holds:

   - The app creates a fresh X25519 key pair for every app session and puts the public key into the fragment
     (`#k=`, step 2). The secret key never leaves the app and is dropped when the session ends.
   - After a passkey ceremony with a PRF result on the page (the passkey-only login, a passkey as second factor,
     on a page that is already signed in the passkey re-authentication `POST /auth/reauth` whose assertion also
     yields the reauth token of step 3, or, for an `unlock` session, an assertion just for the PRF), the page builds
     `sealed_unlock = base64url(crypto_box_seal(plaintext, k))`: libsodium's sealed box, the construction of the
     webhook inbox (ENCRYPTION.md §5b: ephemeral X25519 key, XSalsa20-Poly1305, `ephemeral public(32) ||
     ciphertext || tag(16)`). The plaintext is the UTF-8 JSON `{ "type": "tavrn.connect.unlock.v1",
     "session_id": "<the app session>", "credential_id": "<base64url credential id>", "prf_output":
     "<base64url, 32 bytes>" }`; `type` separates it from every other sealed payload and `session_id` binds it
     to this handoff (a sealed box has no associated data).
   - The node treats `sealed_unlock` as opaque: base64url without padding, 49 to 1024 bytes decoded (`400
     connect.sealed_unlock_invalid` otherwise, also when it comes with `origin`). It keeps it sealed in its cache
     with the session, hands it out with the one `ready` answer and deletes it then (or when the session
     expires). It never logs it.
   - The app opens the box, checks `type` and `session_id`, and unlocks the master secret with the secret storage
     entry `passkey:<credential_id>` exactly as a browser does with the PRF output of its own ceremony
     (ENCRYPTION.md §2.4, including the identity key check). Its device keys are created in the app as before.
     When the node returns no `sealed_unlock`, the box does not open, the content is invalid, or the entry does
     not unwrap, the app asks for the recovery key.
   - **`unlock` sessions** cover an app that is signed in (for example with password and TOTP) but locked: the
     app creates the session with its own session (`purpose: "unlock"`), opens the page with `method=passkey`,
     and the page, signed in as the same user (or after a sign-in there), runs only a passkey assertion with the
     secret storage PRF input and sends `sealed_unlock` without a code. The node refuses a confirming user other
     than the session's (`403 connect.user_mismatch`), so a link to someone else's unlock session is useless.
   - Detection: a node that knows `purpose` and `sealed_unlock` returns `purpose` in every `pending` answer; an
     app that created an `unlock` session polls once before opening the page and gives up (recovery key) when
     the answer lacks `purpose: "unlock"`. Older nodes ignore the unknown fields, so a `login` session simply
     yields no `sealed_unlock`.
   - Trust: the same as for the browser, where the home node's web client sees the PRF output anyway. The node
     itself only ever holds ciphertext it cannot open; the code stays bound to the PKCE verifier; the window
     without native API never sees the app's secret key. A confirmed phishing link of a `login` session (see
     "Security" above) now also hands over the unlock of the encrypted messages when the user signs in with a PRF
     passkey, so the confirmation page says so in its warning whenever it will seal ("Your passkey also unlocks your
     encrypted messages in this app"). `unlock` sessions cannot be phished across accounts (the node checks the
     user).
4. Unlocking the master secret on the visiting origin uses the **recovery key** (PRF passkeys are bound to the
   home domain); the local key store lives in the visiting origin's storage.
5. The client warns once: "This web client is served by visited.example. Its operator could change the code you
   are running; your own home node's client is the safer choice." (ENCRYPTION.md §11.)

After that the web client is simply a client of several nodes: one session per domain (home session, federated
sessions), each refreshed independently, one WebSocket per active node.

**CORS and CSP.** All routes under `/api/v1` and `/.well-known/tavrn` MUST answer CORS requests from any origin:
`Access-Control-Allow-Origin: *`, never `Access-Control-Allow-Credentials`, allowed headers at least
`Authorization`, `Content-Type`, `Idempotency-Key`, `If-Match`, `Tavrn-Client`, `Accept-Language` and the `Tavrn-*`
headers of the upload routes (the reference node mirrors whatever headers a preflight names, so a new header never
breaks a client of another origin, the desktop app included), every method, exposed headers `ETag`, `Retry-After`,
`Location`, `Content-Range`, `Content-Disposition`, preflight cache 600 s. Authentication is bearer tokens only (no cookies), so open CORS
gives other origins nothing they could not do with a token. The WebSocket does not check `Origin` (the token is
sent in `hello`). The web client's CSP keeps `connect-src 'self' https: wss:` (already set), which allows every
node; development builds that talk to `http://` dev peers need `http: ws:` there. `/connect` keeps
`frame-ancestors 'none'`.

## 9. Conformance checks against peers

Behavior is checked, not code (design note 9c).

### 9.1 Node checks

A node checks a peer after the first federation contact (asynchronously), then every 24 hours while it federates
with it, and on demand (`tavrn-node doctor --peer <domain>`, admin UI). The checks use a reserved **probe
account** `tavrn-conformance@<checker>` (system user with an identity key and two attested devices, no login;
the username `tavrn-conformance` is reserved on every node) and the following route on the peer:

`POST /api/v1/federation/conformance/room` (federated session of a `tavrn-conformance` user only) → `201
{ room_id, channel_id, conversation_id, expires_at }`: a throwaway, non-discoverable room with one encrypted
text channel, created regardless of `TAVRN_ROOM_CREATION`, deleted with everything after 15 minutes (or by
`DELETE …/conformance/room/{room_id}`); one at a time and at most 4 per day per checking domain.

| ID | Check | On failure |
|---|---|---|
| `wk.fetch` | `.well-known` reachable over HTTPS with valid TLS, within size and time limits | warn |
| `wk.schema` | valid document, `domain` matches, `tavrn` known, `federation.v1` present | warn (peer unusable) |
| `keys.consistent` | no `kid` maps to two different keys across fetches and across all resolved addresses | **hard** |
| `token.accept` | a valid federation token of the probe yields a session | warn |
| `token.bad_signature` | token signed by a wrong key is refused (`401`) | **hard** |
| `token.alg` | `alg: none` / `HS256` headers are refused | **hard** |
| `token.aud` | token for another audience is refused | **hard** |
| `token.expired` | expired token is refused | **hard** |
| `token.replay` | second use of the same `jti` is refused | **hard** |
| `token.issuer_mismatch` | validly signed token with `sub` of another domain is refused | **hard** |
| `s2s.unsigned` / `s2s.body_hash` | inbox refuses missing tokens and wrong `body_sha256` | **hard** |
| `mls.sequence` | scripted sequence generated with `tavrn-crypto` from fixed seeds: create group, add the second probe device via KeyPackages claimed through the peer (exercises §3.5 back to the checker), Welcome fetch, external rejoin, self update, encrypted message | warn |
| `mls.reject` | the peer refuses a commit with an invalid signature, a forbidden proposal type, a stale epoch, and the **replay** of an already accepted commit | **hard** (accepting) |
| `msg.plaintext` | plaintext in the encrypted channel is refused (`message.encryption_mismatch`) | **hard** |
| `rate.limits` | `federation.limits.federated_logins_per_minute + 5` invalid tokens within a minute produce `429` with `Retry-After` | warn |
| `time.skew` | the `Date` header is within 5 minutes | warn |

### 9.2 Client checks

Clients check what they can without probe accounts: `wk.fetch`/`wk.schema` for every node they use; key
consistency between their own fetch and their home node's view (`GET /directory/nodes/{domain}` fingerprints;
a mismatch means a split view or interception and is shown as a blocking warning for that node); and in normal
use every MLS signature, attestation, ghost member check (ENCRYPTION.md §4.6) and plaintext message signature
(§10.3). Commits the node accepted but the client finds invalid are evidence of `mls.reject`. Clients show the
node's conformance badge from the directory and MAY report findings to their home node
(`POST /api/v1/directory/reports { domain, room_id?, check, detail }`, 10 per day per user; users also report
nodes and rooms from the Discover page with a reason as `check`, and applications of any node, also of the home
node itself, with `{ subject: { kind: "application", ref: "<domain>/<id>" }, check, detail }`, listed with
`application` in the admin's reports of that domain, `APPLICATIONS.md` §4.4); reports alone never trigger
automatic blocks, they create an admin notice once 3 distinct users reported the same domain within 7 days.

### 9.3 Reputation record

Stored per peer in `known_nodes.conformance` (JSON):

```json
{
  "version": 1, "result": "pass", "checked_at": "2026-10-04T12:00:00Z", "software": "tavrn-node/0.4.0",
  "checks": [ { "id": "token.replay", "result": "pass", "detail": null } ],
  "history": [ { "checked_at": "…", "result": "warn" } ],
  "violations": [ { "kind": "issuer_mismatch", "at": "…", "count": 1 } ],
  "reports": 0,
  "blocked": null
}
```

`result` is `pass` (all checks pass), `warn` (warnings only), `fail` (at least one hard failure) or `unknown`;
`history` keeps the last 10 runs; `violations` counts live-traffic violations of the last 30 days;
`blocked` is `{ at, reason, automatic: true | false }` or null.

### 9.4 Consequences

- **Automatic block** (always, independent of configuration), with an admin notice: a hard failure in a check
  run, or a live-traffic violation: a federation token with `sub` of another domain, an inbox message with a
  `from` its sender may not use, a changed key for a known `kid`, or 3 wrong `body_sha256` within 10 minutes.
  Automatic blocks are rechecked every 24 hours and lifted after a run without hard failures; manual blocks stay.
- **Warnings** are shown to users when they join rooms or open conversations on that node ("This node does not
  pass the conformance check") and in Discover; they never block on their own.
- `TAVRN_FEDERATION_REQUIRE_CONFORMANCE=true` additionally refuses federation with peers whose latest result is
  not `pass` or `warn`, including peers not checked yet (federated logins wait for the first run:
  `503 federation.conformance_pending` with `Retry-After`).

## 10. Identity verification across nodes

### 10.1 Safety numbers

For two users with addresses `a`, `b` (`a ≠ b`) and identity public keys `ka`, `kb`, sort the pairs by address
(byte-wise UTF-8) into `(a1, k1), (a2, k2)`:

```text
digest        = SHA-256( "tavrn safety number v1" || 0x00 || str16(a1) || k1(32) || str16(a2) || k2(32) )
safety_number = decimal( big-endian unsigned integer(digest) ) mod 10^60, left-padded with "0" to 60 digits
```

Displayed as 12 groups of 5 digits (3 lines of 4 groups); both users see the same number. QR payload (UTF-8,
byte mode):

```text
tavrn:verify?v=1&a=<a1>&ka=<base64url k1>&b=<a2>&kb=<base64url k2>
```

A scanning client accepts only if one pair is its own user with its own current key and the other pair is the
contact with the key it has pinned; anything else is "numbers do not match". The comparison by reading the
digits aloud is equivalent. Test vectors go to `testvectors/federation.json`.

### 10.2 Verified contacts and key changes

- After a successful comparison the client stores, per own device in the encrypted local store,
  `{ address, identity_public_key, verified_at, method: "qr" | "numeric" }` and shows a verified badge. Syncing
  verifications between the user's own devices is not part of v1.
- **Unverified contact, key changed**: unchanged rule (ENCRYPTION.md §3.3): notice "security key changed", the
  new key is re-pinned once the notice was shown.
- **Verified contact, key changed**: the contact becomes "verification broken". In DMs and group DMs with that
  contact the client **blocks sending** until the user verifies again or explicitly accepts the new key without
  verification (which makes the contact unverified). In room channels the client shows a prominent warning on the
  member and on their messages but does not block sending.

### 10.3 Device signatures on plaintext messages

Messages with `encrypted = false` are authenticated only by the session, so the hosting node could forge them
(design note 9d). The envelope (PROTOCOL.md §7) gets the field `signature` (base64url, 80 bytes), null for
encrypted messages and for unsigned plaintext messages:

```text
signed    = "tavrn plaintext signature v1" || 0x00
            || str16(conversation id)                   # qualified: <node domain>/<conversation ULID>
            || str16(author) || str16(device_id)
            || str16(reply_to or "") || str16(thread_id or "")
            || u8(mentions_everyone) || u16(n) || str16(mention_1) || … || str16(mention_n)   # envelope order
            || u16(m) || ( str16(attachment id) || u64(size) || str16(sha256) ) for each attachment, envelope order
            || nonce(16)
            || u32(len(content)) || content
content   = RFC 8785 (JCS) serialization of the content object, UTF-8
signature = base64url( nonce(16) || Ed25519-Sign(device key, signed) )
```

- `nonce` is 16 random bytes per message; a second message with the same nonce in a conversation is a replay and
  is shown as a duplicate or hidden. Edits are signed anew by the editing device (`device_id`).
- Nodes MUST store `signature` and `mentions` exactly as received (order included) and MUST NOT modify content.
  They MAY reject a malformed `signature` (`400 message.signature_invalid`). A node that normalises the mentions
  of unsigned messages (the reference node: addresses trimmed and lowercased, role ids in canonical uppercase,
  duplicates removed) MUST NOT do so for a signed message: it refuses a signed message whose mentions are not
  already in that form with `400 message.mention_invalid` instead of changing them, so a stored signature always
  matches what the client signed. Clients therefore sign canonical mentions: lowercase addresses,
  `role:<ULID>` in uppercase, no duplicates. Not covered by the signature: `id`, `created_at`, reactions, pins
  (node-assigned metadata).
- Verifying is optional for clients: the device key comes from the author's attested devices fetched from the
  author's home node and checked against the pinned identity key. Valid → normal; missing → "unverified" marker;
  invalid → the content is hidden behind "This message could not be verified". Unsigned messages of bots and
  webhooks (`APPLICATIONS.md`: the node authenticated the application's token and marks the author as a bot) carry
  no "unverified" marker: the bot badge takes its place; a bot signature that cannot be checked is still marked.
- The first message of a thread created together with it (a forum post, `PROTOCOL.md` §7e) is signed with the
  thread id the client chose for the thread (`id` of the creation request), so one rule covers every message.
  First messages of threads created without a client-chosen id (older clients and posts) carry no signature and
  are shown unverified, not invalid.
- Signing becomes mandatory with the capability `content.signed1`: a client announcing it MUST sign every
  plaintext message, and a node MAY then refuse unsigned plaintext messages from that device
  (`400 message.signature_missing`). The reference client does not announce it yet and signs best-effort.

### 10.4 Implementation notes

- **Crate**: `tavrn_crypto::verify` (`safety_number`, `group_safety_number`, `verify_payload`,
  `parse_verify_payload`, `verify_payload_matches`) and `tavrn_crypto::plaintext` (`PlaintextFields`,
  `plaintext_signed_bytes`, `sign_plaintext`, `verify_plaintext`, `PlaintextSignature::parse`,
  `canonical_content`); WASM: `safetyNumber`, `verifyPayload`, `parseVerifyPayload`, `verifyPayloadMatches`,
  `canonicalJson`, `verifyPlaintext`, `Client.signPlaintext`. Reference values in
  `testvectors/federation.json`, checked by the Rust crate, the WASM package and the SDK.
- **One envelope field**: the nonce travels inside `signature` (first 16 of the 80 bytes) as specified in
  §10.3; there is no separate `nonce` field.
- **JCS** is `serde_json_canonicalizer` in Rust and `jcs()` in `@tavrn/sdk` (`jcs.ts`). The WASM
  functions take the canonical text from the TypeScript implementation and refuse it unless the Rust
  implementation produces the same text, so a divergence shows up as "unverified", never as a forgery.
  Numbers follow ECMAScript (integers beyond 2^53 lose precision on both sides alike); lone surrogates
  are refused.
- **QR payload parsing is strict**: exactly the parameter order of §10.1, version 1, valid addresses sorted
  by address, 32-byte keys, at most 1024 characters; surrounding whitespace from pasting is ignored. The
  web client accepts a scanned or pasted payload as text (camera scanning is left to the phone's QR
  scanner); both users see the identical payload because the pairs are sorted.
- **Verified state** is the record of §10.2, stored encrypted next to the pins
  (`verified-contacts`). "Verified" means the pinned key equals the verified key; a re-pinned key makes
  the contact "verification broken" without extra state. "Mark as verified" after a matching payload
  stores `method: "qr"`, otherwise `"numeric"`; a mismatching payload disables it. "I trust the new key"
  deletes the record and acknowledges the key change notice; verifying again stores the new key.
- **Blocking**: DMs and group DMs with a "broken" member disable the composer and show the notice with
  "Verify again" / "I trust the new key"; room channels only show the notice and the badge.
- **Node**: migration `0020_plaintext_signatures.sql` adds `messages.signature`; `message.signature_missing`
  is not used yet (no client announces `content.signed1`).
- **Device lookups after a key change**: the node does not announce newly attested devices, so a DM whose
  member has no attested device (e.g. right after an identity reset) looks the member's devices up again
  every 5 seconds while it is open.

## 11. Security and limits

### 11.1 Summary

| Topic | Rule |
|---|---|
| Transport | HTTPS with verified TLS for every S2S request (§1.3); SSRF rules; `User-Agent` |
| Authentication | Every S2S POST carries a node token (§2.3); every federated login a federation token (§2.2); keys only from the issuer's own `.well-known`, `iss` = the domain the keys were fetched from, `sub`/`from` domain bound to `iss` |
| Clock skew | ±5 minutes (`iat`); `exp` strict |
| Replay | `jti` per issuer until `exp + 5 min`; inbox ids 7 days; message ids older than 7 days refused |
| Lifetimes | federation token ≤ 10 min, node token ≤ 5 min, federated session ≤ 7 days (access 1 h), listing 48 h, `.well-known` cache 5 min – 1 h, key cache 1 h (stale ≤ 24 h only for MLS checks) |
| Sizes | inbox body 64 KiB, `.well-known` 64 KiB, profile 16 KiB, keys 256 KiB, claim 512 KiB, avatar 1 MiB, directory page 1 MiB, index 512 KiB / 2000 entries |
| Rate limits per remote domain | federated logins `TAVRN_FEDERATION_RATE_LOGINS` (60/min), inbox `TAVRN_FEDERATION_RATE_INBOX` (300/min), API requests of its users `TAVRN_FEDERATION_RATE_API` (3000/min), KeyPackage claims per requesting node `TAVRN_FEDERATION_RATE_CLAIMS` (120/min); charged after the signature check, per client address before it (§1.5); per-user limits as for local users. One remote user, and one client address, get a share only (the reference node: `TAVRN_FEDERATION_RATE_API_PER_USER`, 600/min, and a quarter of the logins), charged before the domain's budget, so attempts the share refuses do not count for the domain |
| Quotas | `TAVRN_FEDERATION_MAX_REMOTE_USERS` (10000), `…_PER_DOMAIN` (1000), `TAVRN_DIRECTORY_MAX_ROOMS` (5000), known nodes 10000 |
| Outbox | retries 1 m, 5 m, 30 m, 2 h, 12 h, then 12-hourly; give up after 3 days |

### 11.2 Error codes

`federation.disabled` (403), `federation.peer_blocked` (403), `federation.peer_unreachable` (502),
`federation.peer_invalid` (502), `federation.address_forbidden` (400/502: target resolves to a forbidden
address), `federation.domain_invalid` (400), `federation.target_self` (400), `federation.token_invalid` (401),
`federation.token_expired` (401), `federation.token_replayed` (401), `federation.issuer_mismatch` (401),
`federation.body_hash_mismatch` (401), `federation.user_banned` (403), `federation.bots_refused` (403),
`federation.remote_limit` (403), `federation.kind_mismatch` (403), `federation.peer_limit` (503), `federation.busy` (503),
`federation.local_only` (403), `federation.claim_refused` (403), `legal.forward_refused` (403),
`federation.type_forbidden` (403), `federation.recipient_unknown` (404), `federation.message_stale` (400),
`federation.payload_too_large` (413), `federation.envelope_invalid` (400: malformed inbox envelope or payload), `federation.keys_unavailable` (503), `federation.conformance_pending`
(503), `federation.already_blocked` (409), `federation.not_blocked` (409), `federation.peer_unknown` (404),
`conformance.probe_only` (403), `conformance.room_not_found` (404), `conformance.running` (409), `index.version_conflict` (412), `index.too_large` (413), `invite.wrong_user` (403),
`connect.origin_invalid` (400), `connect.code_invalid` (400), `connect.challenge_invalid` (400),
`connect.target_invalid` (400), `connect.session_invalid` (400/404), `connect.session_expired` (410), `connect.busy` (503),
`connect.purpose_invalid` (400), `connect.sealed_unlock_invalid` (400), `connect.user_mismatch` (403), `message.signature_invalid` (400),
`message.signature_missing` (400), `directory.announce_unverified` (400), `directory.cursor_invalid` (400),
`directory.node_not_found` (404), `room.discoverable_public_only` (400). Retired: `friend.remote`,
`conversation.member_remote`.

### 11.3 Logging

Logged (structured, with `request_id`): every federated login (issuer, address, device, result), every inbox
message (sender, type, id, result, latency), every outbox attempt (target, type, id, status, next attempt),
claims (requesting node, user, count), document fetches (domain, status, duration), blocks and conformance
results. Never logged: tokens, request bodies, payload contents (room names, member lists), KeyPackages.

### 11.4 Operator switches

| Variable | Default | Meaning |
|---|---|---|
| `TAVRN_FEDERATION_ENABLED` | `true` | `false`: `.well-known` stays (without `federation`/`federation.v1`), but federation tokens, federated logins, inbox, claims, outbox and announces are refused or paused (`federation.disabled`); existing remote users can no longer authenticate |
| `TAVRN_FEDERATION_BLOCKLIST` | empty | domains never federated with |
| `TAVRN_FEDERATION_ALLOWLIST` | empty | if set, federate only with these domains |
| `TAVRN_FEDERATION_ALLOW_PRIVATE` | `false` | allow peers on private/loopback addresses (dev, tests, intranets) |
| `TAVRN_FEDERATION_SRV_FALLBACK` | `true` | when a peer's identity domain serves no well-known (`404` or no HTTPS server), look up `_tavrn._tcp.<domain>` SRV before the direct `https://<domain>/api/v1` (§1.3 decision table); never after another status |
| `TAVRN_FEDERATION_DEV_PEERS` | empty | `--dev` only: `domain=http://host:port` mapping for local multi-node setups |
| `TAVRN_FEDERATION_REMOTE_BOTS` | `true` | accept bots of other nodes (only that; whether this node's bots may federate is `TAVRN_APPS_FEDERATE`) |
| `TAVRN_APPS_FEDERATE` | `true` | this node's bots may obtain federation tokens (`APPLICATIONS.md` §2.8) |
| `TAVRN_FEDERATION_RATE_LOGINS` / `_INBOX` / `_API` / `_CLAIMS` | `60` / `300` / `3000` / `120` | per remote domain per minute |
| `TAVRN_FEDERATION_MAX_REMOTE_USERS` / `_PER_DOMAIN` | `10000` / `1000` | remote user quotas |
| `TAVRN_FEDERATION_REQUIRE_CONFORMANCE` | `false` | refuse peers without a passing conformance result (§9.4) |
| `TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS` | `90` | housekeeping of remote users (§2.6); `0` keeps them |
| `TAVRN_FEDERATION_NOTIFY_BANS` | `false` | send `ban.notify` (§5.2) for room and node bans |
| `TAVRN_REFERENCE_NODES` | empty | directory starting points |
| `TAVRN_DIRECTORY_LISTING` | `true` | announce this node and allow listing |
| `TAVRN_DIRECTORY_MAX_ROOMS` | `5000` | cached remote rooms for Discover |

## 12. Capabilities and versioning

- A node lists `federation` (reserved in PROTOCOL.md §3) **and** `federation.v1` while federation is enabled;
  `federation.v1` means exactly this document. Incompatible changes (token claims, inbox envelope, signature
  formats) get `federation.v2` and run in parallel for at least 12 months.
- New inbox types, payload fields and directory fields are compatible additions; receivers ignore unknown ones.
- `content.signed1` (§10.3) is a client capability.
- `reports.v2` (`MODERATION.md` §1.6) is announced while federation is enabled: a node accepts `report.forward` and
  offers the forward route only then.
- `connect.app` (app sessions of the connect flow, §8 step 3) is announced by every node that implements them,
  independent of `TAVRN_FEDERATION_ENABLED` (the flow serves the node's own users). The session `purpose` and
  `sealed_unlock` are compatible additions to it, without a capability of their own: clients detect them by the
  `purpose` field of the `pending` answer (§8 step 3, "Sealed unlock material").
- Safety number, plaintext signature, listing and token formats carry version strings (`v1`, `typ`); a change
  requires a new label.

## 13. Implementation order

Every step is test-first (design note 9a). Federation integration tests start two in-process `TestNode`s that
listen on real loopback ports (`a.test`, `b.test`, `TAVRN_FEDERATION_ALLOW_PRIVATE=true`,
`TAVRN_FEDERATION_DEV_PEERS`, `--dev`) and talk to each other through the real federation HTTP client; Playwright
starts two nodes from its config the same way.

1. **Server foundations**: outbound client (§1.3), document cache and key rotation (§1.4), domain policy, node
   tokens, federation tokens, `POST /federation/token`, `POST /auth/federated`, remote users and profiles,
   `federation.local_only` guards, revocation. Tests: unit tests for SSRF ranges (incl. mapped IPv4, rebinding
   via the vetted address), redirect rules, size caps; integration: A issues, B accepts; every rejection of §2.5
   with its code (wrong `aud`, expired, replayed `jti`, `sub` of another domain, unknown `kid` refresh, blocked
   and non-allowlisted domains, disabled federation, quotas); profile refresh by `pv`.
2. **Inbox and outbox**: `POST /federation/inbox`, dedupe, `federation_outbox` worker with the retry schedule
   (clock injected), type authority rules. Tests: delivery, duplicates, body hash, `htu` mismatch, payload limit,
   stale ids, retries while B is down and delivery after B returns, give-up after 3 days, `type_forbidden`.
3. **Rooms, keys and MLS across nodes**: room API for remote users, domain bans removing members, direct
   invites, key cache, KeyPackage claim proxy and S2S claim, §3.6 rules, `identity.changed`/`devices.changed`.
   Tests: a user of A joins a public and an invite-only room on B, posts, is banned by domain; a member on B adds
   a user of A to a private channel with KeyPackages claimed from A; commits with unattested remote devices are
   refused; key reset on A reaches B.
4. **Friends, DMs, invite list, conversation index**: §4, §6, `room.invite`, `conversation.invite`, `notify`.
   Tests: friend request/accept/remove across nodes incl. crossing requests and blocks; DM created on A with a
   user of B under `dm_policy = friends`; group DM with members of three nodes (third `TestNode`); index
   versioning and limits.
5. **Client**: multi-node session store, federated sessions and renewal, sign-in with another node (direct and
   connect flow), conversation index sync, Home view, invite list, remote rooms in the room rail, foreign domains
   always shown. Tests: Vitest for the session store and index merge; Playwright with two nodes: sign in on
   node B's web client with an account of A (password + TOTP, then passkey through the connect flow with the
   virtual authenticator), join a room on B, encrypted chat between users of A and B, DM across nodes, a node
   going offline marks only its rooms unreachable; phone and tablet viewports.
6. **Directory and Discover**: `node.announce`, `/directory/nodes`, `/directory/rooms`, signed listings,
   `discoverable`, delisting, Discover page. Tests: announce verification, listing signature check, delisting,
   `TAVRN_DIRECTORY_LISTING=false`, limits; Playwright: discover a room on B from A and join it.
7. **Conformance**: probe account, conformance room, checks of §9.1, reputation record, automatic blocks,
   `doctor --peer`, client checks and reports. Tests: a deliberately broken test node (feature flags in the test
   harness that accept bad signatures, replayed commits or plaintext) is detected and blocked; warnings do not
   block; `REQUIRE_CONFORMANCE` behavior.
8. **Identity verification**: safety numbers and QR, verified state, key-change blocking, plaintext signatures
   and `content.signed1`. Tests: shared test vectors in `testvectors/federation.json` (Rust and
   TypeScript), JCS canonicalization, verification states in the UI; Playwright: compare safety numbers between
   two users of different nodes, key change blocks sending in a DM.

### 13.1 Implementation notes (reference node)

Decisions taken where this document leaves room; other implementations MAY differ unless a MUST says
otherwise.

- **Peer cache**: the `known_nodes` cache of §1.4 is the table `federation_peers` (document, `fetched_at`,
  `expires_at`, `status`, `kid_refresh_at`, reserved conformance/reputation columns); every `(kid, x)` ever
  seen is kept in `federation_peer_keys`. A key conflict sets `status = key_conflict`, which answers
  `403 federation.peer_blocked` until an operator resets the row. Without `Cache-Control: max-age` the TTL
  is 5 minutes. A document must announce `federation.v1`, otherwise it is `federation.peer_invalid`.
- **Outbound client**: DNS answers are vetted inside the HTTP client's resolver, and the connection uses
  exactly the vetted answer (one lookup per connection). Development peers bypass the scheme rule and the
  address check of their mapped host only. A blocklist entry also blocks its subdomains; allowlist
  entries match exactly. Any non-2xx answer, a redirect or a failed policy check is never parsed. A GET
  is retried once at once after a connection error (stale keep-alive connection); timeouts and HTTP
  errors are not retried by the client (the outbox has its own schedule).
- **Remote devices**: a remote device has a fresh local row id; `(user, home device id)` is unique and
  `home_domain` is stored. The session claim `dev` of a remote user's access token holds the local row
  id (the token never leaves this node's verification); the session response and `/auth/refresh`
  return the home device id as `device_id`, which is the identity used in MLS and messages.
- **Remote sessions**: every request of a remote user checks that its device still has a live session,
  so `session.revoke`, a disabled federation, a blocked home domain and the 7-day cap take effect at once.
  A new federated login of the same device revokes the previous refresh token (its access tokens end
  within the hour). Federated logins are also limited per client IP like password logins.
- **Profiles**: the mirror is refreshed inline during the federated login (new `pv`, or a mirror older
  than 24 hours); failures keep the mirror. `profile_version` starts at 1 and grows with every real
  display name change (there is no avatar upload route yet). Avatars are copied into the node's blob
  storage after checking `avatar_sha256` and served at `GET /api/v1/users/{address}/avatar` (the route
  takes a username for local users and `alice@other.example` for mirrors).
- **Local-only routes** for remote users also include `PATCH /users/me` (the profile is a mirror) and
  `DELETE /users/me/devices/{id}` (devices belong to the home node); the check runs in the authentication
  extractors against a route table (`federation::guard::LOCAL_ONLY`). Bots of this node get federation
  tokens only while `TAVRN_APPS_FEDERATE` is on (`federation.bots_refused`; before applications this was
  `TAVRN_FEDERATION_REMOTE_BOTS`, which now only decides whether bots of other nodes are accepted).
- **Inbox**: handlers run before the `202` (short database updates; idempotent through the dedupe).
  Malformed envelopes and payloads answer `400 federation.envelope_invalid`; a `to` that has the wrong
  shape for the type is `federation.type_forbidden`, a user address of another node
  `federation.recipient_unknown`. Unknown types are accepted without authority checks. Implemented
  handlers: `session.revoke`, `identity.changed` (mirrors the identity key, refetches the key cache,
  WS `identity.changed`, `mls.remove_needed` for all leaves of the user), `devices.changed` (refetches the
  key cache, `mls.remove_needed` for vanished devices), `profile.changed` (a known user and a newer version
  only; the refresh runs in a background task after the `202`) and those of steps 3–4 below; `node.announce` is
  checked, recorded as seen and ignored until step 6. A revoked device's WebSockets are closed with `4001`.
- **Outbox**: entries are written right after the change that causes them commits (not in the same
  database transaction); the 7-day session cap bounds a crash in between. A `401` is retried once after
  5 minutes (tracked by the last status), then given up. Giving up deletes the entry, logs
  `federation.undeliverable` and counts it (`federation_undeliverable` in `GET /admin/overview`); for
  `friend.request`, `room.invite` and `conversation.invite` the originating local user gets the WS event
  `federation.undeliverable { type, to }` (an outgoing friend request stays listed and can be withdrawn and
  sent again). Recipients of `session.revoke`, `identity.changed` and `devices.changed` are the
  `federation_targets` domains plus the home domains of the user's friends and DM/group DM co-members; device
  deletion sends `session.revoke` and `devices.changed`, device attestation `devices.changed`, an identity
  reset `identity.changed`, password change/reset, disabling (also by a node ban) and a second-factor
  reset `session.revoke` with `device: null`.
  `profile.changed` goes to the same recipients after every change of a user's public profile (the profile
  routes, `PATCH /users/me` with a public field, the profile clearing of a legal decision); it is queued with
  `next_at` 5 seconds ahead, and a newer one deletes the queued older one of the same user and target and takes
  over its `next_at`.

**Steps 3–4 (rooms, keys, friends, DMs across nodes):**

- **Key cache**: stored on the remote user's rows instead of a separate `remote_device_keys` table: the
  identity key in `users.identity_pubkey`, every attested device as a device row keyed by `(user, home
  device id)` with `public_key`, `identity_signature`, `attested_identity_key` and the share key
  (`share_public_key`, `share_key_signature`, ENCRYPTION.md §3.1), the fetch time in
  `remote_users.keys_fetched_at`. So every "attested under the current identity key" check works unchanged
  for remote devices, and device rows exist before a device's first federated login (Welcomes can be stored
  for them). A fetch verifies every attestation against the identity key of the same document and drops
  invalid devices (at most 100 per user); devices no longer published lose their attestation. Freshness:
  1 hour; a missing device identity refetches at most once per minute; `identity.changed` and
  `devices.changed` refetch at once; refetches through normal requests are limited to one per user and
  minute, and an expired cache stands in for an unreachable home node for 24 hours, then `503
  federation.keys_unavailable`. `GET /users/{address}/keys` answers only for remote users this node already
  knows (`404 user.not_found` otherwise), so anonymous callers cannot make the node fetch arbitrary addresses.
- **§3.6**: MLS identities, `mls.remove_needed`, Welcomes and the `device_id` of message envelopes use the
  home device id of a remote device; committer, added and removed identities of foreign domains are resolved
  through the key cache (refetched on a miss). Remote users this node has never seen are unknown devices.
- **Claim proxy**: the conversation's node claims only for remote users it knows (`404 user.not_found`) and
  passes through a fixed list of answers of the home node (`404 user.not_found`, `403
  federation.claim_refused` / `federation.peer_blocked` / `federation.disabled`, `429` with `Retry-After`);
  everything else is `502 federation.peer_unreachable`. The S2S claim body is at most 4 KiB;
  `federation.claim_refused` applies when `user` blocked a `requester` the home node knows.
- **Admission**: `TAVRN_FEDERATION_RATE_API` (default 3000) counts every authenticated request and WebSocket
  hello of a remote user per home domain, after the user's own share (`TAVRN_FEDERATION_RATE_API_PER_USER`, default
  600; a rate-limited hello closes with `4002 rate_limited`, not `4001`); `TAVRN_FEDERATION_RATE_CLAIMS` (default 120) every S2S claim per
  requesting node. Every request of a remote user also checks node bans of its address and domain. A node
  ban of a remote address or domain ends the federated sessions of the affected users and removes them from
  all rooms (`member.leave` with `banned: true`, `mls.remove_needed`). A room domain ban removes every member
  of the domain and every bot whose owner is there (`403 member.is_owner` if that includes the owner);
  joins of bots whose owner is banned are refused.
- **Direct invites**: `POST /rooms/{room_id}/invites/direct { user }` → `202 { invite }` with the new
  `invite.user` (the bound address); errors `400 invite.user_invalid`, `400 invite.self`, `409
  invite.already_member`, `403 room.banned`, `404 user.not_found`, `429` (20 per hour per inviter), the
  federation errors of the stub lookup. A local invitee gets the entry in the invite list directly (unless
  they blocked the inviter). `room.invite` carries `icon_url: null`: clients never load images of other nodes.
- **Invite list**: table `user_invites` (one entry per user, kind, node and room or conversation, a newer
  invitation replaces an older one; at most 200, expired entries are pruned). Conversation invitations expire
  after 7 days like room invitations. WS events `room.invite` / `conversation.invite` carry `{ invite }` in
  the shape of the list items.
- **Received invitations**: `room.node` / `conversation.node` must be the sender; a `dm` invitation must
  come from a user of the sending node (a DM lives on its initiator's home node), the inviter and the
  recipient must be members (`400 federation.envelope_invalid` otherwise). Dropped silently (`202`, nothing
  stored): a block in either direction between recipient and inviter, under this node's `dm_policy = friends`
  a conversation inviter who is not a friend of the recipient here, more than 10 invitations per hour per
  sender, recipient and type.
- **Friends**: `friend_requests.remote_request_id` keeps the other node's id of a request; `friend.remove`
  with an id matches either id. An accept for a request that no longer exists is answered with
  `friend.remove { request_id: null }`, so both sides converge. A `friend.request` creates the sender as a
  stub (quota applies). Ordering (§5.4) is tracked per pair in `friend_sync`. Blocking sends
  `friend.remove { request_id: null }` when a friendship or a request existed. `DELETE
  /users/me/friends/{user}` and `DELETE /users/me/blocks/{user}` accept addresses of known remote users.
- **DMs**: remote members are conversation members from the creation on (the invitation is a notice, not a
  precondition). The `friends` policy of a node is decided where a party is local; between two remote users
  (a remote member adding another remote user to a group DM) only the recipient's node decides. Remote
  addresses whose node cannot be reached answer `502 federation.peer_unreachable` (the retired codes
  `friend.remote` and `conversation.member_remote` are gone).
- **notify**: sent for DMs and group DMs, and for mentions (`mentions` or `@everyone`) in channels, to remote
  members without an open WebSocket on the node (counted in memory), coalesced in memory per member and
  conversation for 60 seconds. The `push_relay` setting is not implemented yet.
  Received hints are stored in `push_hints` (newest 500 per user, 7 days), forwarded as WS `notify` and, while
  the user has no connection on H, as a web push (PROTOCOL.md §6d).
- **ban.notify**: received hints are forwarded as WS `ban.notify { room, scope }`. Sending is an operator
  setting of the whole node (`TAVRN_FEDERATION_NOTIFY_BANS`, default off) instead of a room setting
  `notify_bans` (see the leftovers below).
- **Schema**: migration `0011_federation_social.sql` (`invites.bound_to`, `friend_requests.remote_request_id`,
  `friend_sync`, `user_invites`, `push_hints`).
**Step 6 (directory, Discover):**

- **Schema** (migration `0013_directory.sql`): `rooms.discoverable`; `directory_nodes` (the listed part of
  `known_nodes`, separate from the document cache `federation_peers`: name, description, software,
  capabilities and registration mode copied from the verified document, `public_rooms`, `users`, `source`
  = `announce` | `relay`, `first_seen`, `last_seen`, `last_announce`, `rooms_fetched_at`); `directory_rooms`
  (signed values plus the listing JWT and its expiry); `directory_delisted` (node, room id or `''` for the
  whole node).
- **Announcing** (§7.2): only to the reference nodes, shortly after the start, then every 6 hours (±10 minutes),
  and whenever a listing-relevant room setting changes (a room becomes discoverable or not, a discoverable room
  is renamed, re-described or deleted). A queued, undelivered announce to the same target is replaced. Nothing is
  sent with `TAVRN_DIRECTORY_LISTING=false`, with federation disabled or when the node's domain is not a node
  domain (development); development nodes have no reference nodes by default. `users` is never sent (no setting
  yet).
- **Receiving `node.announce`** (handled before the dedupe record, so a refused announce can be sent
  again): payload at most 8 KiB (`413 federation.payload_too_large`), fields capped (name 64, description
  500, software name and version 64, registration 16 characters, at most 64 capabilities of 64 characters;
  `400 federation.envelope_invalid`), `domain` must be the sender (`403 federation.type_forbidden`); a
  duplicate id is `202`; `listing: false` removes the node; a delisted node is answered `202` and ignored;
  one announce per domain per 10 minutes (`429` with `Retry-After`); then the sender's discovery document
  is fetched **fresh** (not from the cache, `502` if that fails) and name, description (capped as above),
  software, registration mode and capabilities (as a set) must equal it and it must say
  `directory_listing: true`, otherwise `400 directory.announce_unverified`. The node row is built from the
  document; only `public_rooms` and `users` come from the payload and `public_rooms` is replaced by the
  number of verified rooms after the room fetch.
- **Rooms of other nodes** are taken only from the hosting node itself:
  `GET https://<node>/api/v1/directory/rooms?local=true&limit=200` through the federation client (1 MiB),
  in the background after every accepted announce and hourly for lists older than 6 hours. Every entry
  needs a listing that verifies with the key its `kid` names in the node's own document, `iss` = the node,
  `sub` = the room id, `aud = tavrn-directory`, `typ = listing`, `exp − iat` ≤ 48 hours (+10 minutes), a
  name of 1–100 and a description of at most 1000 characters; the signed values are stored. A refresh
  replaces the node's whole list; at most 200 rooms per node and `TAVRN_DIRECTORY_MAX_ROOMS` in total
  (rooms beyond the total are not stored). A node whose document no longer says `directory_listing: true`
  is removed. Rooms are never taken from a relaying node, so this node only passes on listings it fetched
  from their own node (verbatim).
- **Reference node lists**: every 6 hours a node reads `GET /api/v1/directory/nodes` of each reference node
  (at most 10 pages of 100), and verifies the reference node itself and up to 200 domains it has not seen
  within 6 hours through their own `.well-known` (domain policy first), then fetches their rooms as above
  (`source = relay`).
- **Expiry** (§7.1): a node not seen for **48 hours** (no announce, not confirmed through a reference node list)
  is removed with its rooms; expired listings are removed hourly. At most 10 000 nodes; beyond that the least recently seen are dropped. Floods of verifiable
  subdomains are bounded only by these caps; blocking the parent domain (the blocklist covers subdomains)
  is the remedy.
- **Routes**: `GET /directory/nodes?q=&limit=&cursor=` (ordered by domain, cursor = the last domain,
  `limit` ≤ 100, `q` searches domain, name and description), `GET /directory/nodes/{domain}` (`keys` with
  `kid` and `sha256` = base64url SHA-256 of the 32 key bytes, `404 directory.node_not_found`),
  `GET /directory/rooms?q=&node=&local=&min_members=&limit=&cursor=` (most members first, `limit` ≤ 200, cursor
  `<member_count>~<node>~<room_id>`, `400 directory.cursor_invalid`, `q` at most 100 characters and
  matched literally). Public, CORS-open, 120 requests per minute and client IP. `conformance` is
  this node's latest result (step 7); `icon_url` and `icon_sha256` are null (clients never load images of other nodes).
  This node's own rooms are listed with a listing signed per response. A language filter does not exist
  (rooms have no language).
- **Listed** means: not delisted here, no node ban of the domain, no automatic block (`key_conflict`), and
  the configured block- and allowlists pass; with federation disabled only the node's own rooms are listed.
- **`discoverable`**: `PATCH /rooms/{room_id} { discoverable }` with `manage_room`; only public rooms
  (`400 room.discoverable_public_only`); switching a room to `invite` unlists it; every change of the
  listing state is audited as `room.discoverable { discoverable }`. `GET /rooms/discover` returns the
  discoverable public rooms.
- **Delisting** (node admins, instead of `POST /admin/directory/delist`): `DELETE
  /admin/directory/nodes/{domain}` and `DELETE /admin/directory/rooms/{node}/{room_id}` (`204`; `409
  directory.already_delisted`; the own domain is `400 directory.delist_self`, use
  `TAVRN_DIRECTORY_LISTING`; own rooms can be delisted), `POST /admin/directory/relist { node, room_id? }`
  (`404 directory.not_delisted`; a relisted node is verified and fetched again at once) and `GET
  /admin/directory/delisted`; audited as `admin.directory_delist` / `admin.directory_relist`.
- **Web client**: the Discover page (rail entry, `/discover`) asks only the node the client was loaded from;
  room and node tabs, search, minimum member count, "load more". Every listing is verified in the browser
  (`verifyDirectoryRooms` of the SDK, WebCrypto Ed25519) with the keys of the hosting node's own discovery
  document (this origin's document, otherwise straight from the domain or through the peer proxy, cached
  for an hour); entries that fail are hidden and counted, a browser without Ed25519 shows entries marked as
  not checked. Cards always show the hosting domain. Joining a room of another node opens a federated
  session there, joins and records the room in the conversation index. The room settings overview has the
  "Listed in the directory" toggle.

**Step 7 (conformance):**

- **Schema** (migration `0014_conformance.sql`): the reputation record lives on the peer cache row
  `federation_peers` (the `known_nodes` of §9.3): `conformance` (JSON of the latest run: `version`, `result`,
  `checked_at`, `software`, `duration_ms`, `checks`, `history` of the last 10 results),
  `conformance_checked_at`, `conformance_result` (`pass` | `warn` | `fail`, null = never checked),
  cumulative `hard_failures` (failed checks) and `soft_failures` (warnings), `violations`, `blocked_at`,
  `blocked_reason`; `status` is `ok`, `blocked` (operator), `blocked_auto` or `key_conflict`, and the domain
  policy refuses every status but `ok` (`403 federation.peer_blocked`). Live violations are rows of
  `federation_violations` (kept 30 days; the record shows those of the last 30 days, `reports` of §9.3 do
  not exist yet); `conformance_rooms` tracks the rooms this node hosts for probes.
- **Probe account**: `tavrn-conformance` is created at the first start (and before every run): no password
  (no login of any kind), not counted as a user (the first real account still becomes admin), hidden from the
  admin user list and counts; registering the name is `409 auth.username_taken` on every node. Its identity
  key and two attested devices are derived with HKDF-SHA256 from `keys/secrets.key`, so they stay the same
  across runs and restarts; before each run the second device gets one fresh KeyPackage (the only one of the
  account), whose private part lives only in that run.
- **Conformance room** (served for the probes of other nodes): `POST /api/v1/federation/conformance/room`
  only for a federated session of a user named `tavrn-conformance` (`403 conformance.probe_only`) →
  `201 { room_id, channel_id, conversation_id, plaintext_channel_id, expires_at }`: an invite-only,
  non-discoverable room owned by the probe with the usual encrypted text channel plus an **unencrypted** text
  channel (for `msg.ciphertext`), created regardless of `TAVRN_ROOM_CREATION`. A new room of the same
  checking domain deletes the previous one; at most 4 per day (1000 with `--dev`, `429`). `DELETE
  …/conformance/room/{room_id}` by the same probe (`404 conformance.room_not_found` otherwise). The worker
  deletes rooms 15 minutes after creation (checked every minute).
- **A run** (`federation::conformance::run`) has a budget of 60 seconds and talks to the peer only through
  the federation client (SSRF rules, timeouts, size caps; answers of any status are read, at most 1 MiB).
  Order: `wk.fetch`, `wk.schema`, `keys.consistent` (against every key ever seen; a conflict also sets
  `key_conflict`; and across all resolved addresses, see the leftovers below); `token.accept`; conformance
  room, `mls.sequence` (create group, claim the second probe device's KeyPackage through the peer, add,
  Welcome, external rejoin, self update, encrypted message), `mls.reject` (a commit of an older epoch, the
  replay of the accepted self update, and a commit with one byte flipped in its signed content must all be
  refused; forbidden proposal types are not exercised), `msg.plaintext` (hard), `msg.ciphertext` (ciphertext
  in the unencrypted channel, soft); `token.replay` (the `token.accept` token again), `token.bad_signature`
  (a key the checker never published under its current `kid`), `token.alg` (`none` and `HS256`), `token.aud`,
  `token.expired`, `token.issuer_mismatch` (`sub` = `tavrn-conformance@conformance.invalid`); `s2s.unsigned`,
  `s2s.body_hash`, `s2s.replay` (the same signed inbox request twice: the second must be refused; the
  messages have the type `conformance.probe`, which receivers accept and ignore); `time.skew` (the first
  `Date` header); `rate.limits` last (`federated_logins_per_minute + 5` logins with forged tokens until a
  `429` with `Retry-After`; skipped when the peer publishes more than 195 per minute). A check whose request
  the peer must refuse is `fail` only if the peer accepted it (2xx), `pass` on any other 4xx except 408/429,
  `warn` otherwise; checks that cannot run for a missing precondition are `skip` (they do not change the
  result). Soft checks never fail, they warn. `result` = `fail` if any check failed, `warn` if any warned,
  else `pass`.
- **Scheduling**: the worker (every minute) checks up to 4 peers that were never checked or not in the last
  24 hours, are `ok` or `blocked_auto`, pass the configured policy and federate with this node (remote users
  of the domain exist here or local users requested federation tokens for it). Unforced runs return the
  stored record within an hour of the last run; one run per peer at a time (`409 conformance.running`); a
  run within 70 seconds after one that sent the `rate.limits` burst is refused (`429` with `Retry-After`),
  since the peer would still answer every login with `429`. While this node blocks a peer, the peer cannot
  claim the probe's KeyPackage from this node, so a recheck of a blocked peer reports `mls.sequence` as
  `warn`.
- **Consequences**: a run with a hard failure moves `ok` to `blocked_auto` (reason: the failed check ids);
  operator blocks and key conflicts are never changed automatically. A run without hard failures lifts
  `blocked_auto`. Blocking (automatic or manual) ends the federated sessions of the peer's users at once;
  memberships stay. Live violations are counted only for evidence the peer signed (a bad signature proves
  nothing about the claimed `iss`): `issuer_mismatch` (a federation token with a valid signature and a `sub`
  of another domain; a `sub` named `tavrn-conformance` is not counted, it is the `token.issuer_mismatch`
  probe) and `type_forbidden` (a `from` the sender may not use; a misaddressed `to` is not counted) block at
  once, `body_hash` (a valid node token over another body; bodies of type `conformance.probe` are not
  counted) after 3 within 10 minutes; `key_conflict` is recorded. Automatic blocks and lifts are audited as
  `federation.block_auto` / `federation.unblock_auto` (the admin notice).
- **`TAVRN_FEDERATION_REQUIRE_CONFORMANCE`**: checked in federated logins and the inbox **after** the token
  signature was verified (only real peers can start a run): `pass`/`warn` pass, `fail` is `403
  federation.peer_blocked`, never checked is `503 federation.conformance_pending` with `Retry-After: 60`
  (the `jti` is not spent, the token can be retried) and starts a run in the background.
- **Admin routes** (audited): `GET /api/v1/admin/federation/peers?after=&limit=` (peers by domain with
  record and violations of 30 days), `POST /admin/federation/peers/{domain}/check` (forced run, `400
  federation.domain_invalid` / `federation.target_self`, `403 federation.peer_blocked` for the configured
  block- and allowlists, `409 conformance.running`, `429`; audited `admin.federation_check`), `POST
  …/block { reason }` (`blocked`, `409 federation.already_blocked`; `admin.federation_block`), `POST
  …/unblock` (from `blocked`, `blocked_auto` or `key_conflict`; a key conflict also forgets the stored keys
  of the peer so its current ones are accepted; `409 federation.not_blocked`; `admin.federation_unblock`).
  The web client's node administration has a **Federation** tab with these actions.
- **Client checks** (§9.2): `GET /api/v1/federation/peers/{domain}/state` (public, CORS-open, 120 per minute
  and client IP) → `{ domain, conformance, blocked, keys: [{ kid, sha256 }] }` as this node sees the peer.
  The web client asks its home node for every other node it shows: `blocked` replaces the node's views by a
  warning (as does `federation.peer_blocked` when a federation token is refused), `fail` shows "This node
  failed a security check" above them, and key fingerprints that differ from the client's own fetch of the
  document replace the views by a warning (only when the browser can fetch the document itself). Reports to
  the home node (`POST /directory/reports`): see the leftovers below.
- **Directory**: node cards carry the latest result (`pass`, `warn` or `unknown`); nodes whose result is
  `fail` are not listed, nor are their rooms; the Discover page shows the result on node cards.
- **`tavrn-node doctor --peer <domain>`**: a forced run with the node's configuration, keys and database
  (the node itself should be running, the peer claims the probe's KeyPackage from it); prints a table (check,
  hard/soft, result, reason) and exits with 0 (`pass`/`warn`), 1 (`fail`) or 2 (could not run). The result is
  stored with its consequences like an admin's run.
- **Deliberately broken test nodes**: `TAVRN_DEV_MISBEHAVE` (comma-separated, refused without `--dev`):
  `accept_bad_signatures` (federation and node tokens are accepted without header or signature check),
  `replay_ok` (`jti`s are never spent), `plaintext_ok` (plaintext objects are taken in encrypted channels),
  `no_rate_limit` (no per-domain and per-IP limits on federated logins).

**Leftovers of the implementation order:**

- **Self-listing**: with `TAVRN_DIRECTORY_LISTING=true` a node lists itself in its own `GET /directory/nodes`
  (sorted in by domain, paged and searched like every entry) and answers `GET /directory/nodes/{own domain}`
  with its own key fingerprints; the entry is built from its announce payload (name, description,
  software, capabilities, registration, `public_rooms` = its discoverable public rooms), `last_seen` is the
  time of the request and `conformance` is `unknown` (a node does not check itself). It is not stored in
  `directory_nodes`; announces to the own domain stay refused (a reference node never announces to itself).
  Its discoverable rooms were already part of `/directory/rooms`. Nodes that pull a reference node's list
  therefore see the reference node in it, and a client's own node shows up on its Discover page (the card
  offers no report). With listing off the node is in neither list (`404 directory.node_not_found` for its
  own domain).
- **Remote user housekeeping** (§2.6): the hourly housekeeping deletes up to 500 remote users per round that
  had no federated login for `TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS` (default 90; the creation time
  for stubs that never logged in; `0` disables it), have no live session and nothing that ties them to this
  node: no room or conversation membership, friendship, friend request or block (either direction), authored
  message, reaction, pin, upload, custom emoji, owned room, issued ban, ban of their address, owned bot or
  created invite link (messages, reactions and pins keep the row because deleting it would change what other
  members see; blocks because a local user's block must survive). The delete repeats the conditions (a login
  in between keeps the user) and cascades to devices, sessions, KeyPackages, Welcomes, the key cache and the
  mirror state; a mirrored avatar file is deleted. The user is created again by its next federated login or
  as a stub.
- **Reports** (§9.2): `POST /api/v1/directory/reports { domain, room_id?, check, detail }` (session of a
  **local** user, `federation.local_only` for remote users) → `201` with the stored report. `domain` is a
  node domain (`400 federation.domain_invalid`; the own domain `400 directory.report_self`), `room_id` an
  optional ULID, `check` 1–64 characters of `a-z 0-9 . _ -` (a §9 check id the client saw failing, or a
  reason; the web client sends `spam`, `abuse`, `illegal`, `security` or `other`; `400 validation.check`),
  `detail` at most 1000 characters of text (stored as given, shown as text). 10 per user and 24 hours
  (`429`). Table `directory_reports` (migration `0015_phase3_leftovers.sql`), kept 180 days. The report that
  makes 3 distinct reporters of a domain within 7 days writes the admin notice `directory.reports_notice`
  to the audit log (once per crossing). Admin routes: `GET /api/v1/admin/directory/reports` (per domain:
  `reports`, `reporters`, `recent` = last 7 days, `last_at`, `delisted`; most recently reported first, at
  most 200), `GET /admin/directory/reports/{domain}` (the reports with the reporter's address, newest
  first, at most 200) and `DELETE /admin/directory/reports/{domain}` (dismiss, `404
  directory.reports_not_found`, audited `admin.directory_reports_dismiss`). The Federation tab lists the
  reported nodes with their counts and reports and delists, relists or dismisses from there; the Discover page
  has a "Report" button on node and room cards of other nodes. `reports` of the reputation record (§9.3) is
  not filled; the count lives in the reports overview.
- **`keys.consistent` across addresses** (§9.1): after the comparison with the key history, the check fetches
  the discovery document once from **every** address the peer's domain resolves to (at most 8, each vetted
  like any request; one HTTP client pinned to that address per fetch) and compares the key sets
  (`kid` → `x`) of every valid answer: any difference, also an additional key on one address, is a hard
  failure ("\<ip> and \<ip> serve different keys (kid …)"). Addresses that do not answer or answer with an
  invalid document are left to `wk.fetch`. A development peer mapped to an IP literal has one address.
- **`ban.notify` sending** (§5.2): with `TAVRN_FEDERATION_NOTIFY_BANS=true` a room ban (of an address or a
  domain) sends one `ban.notify { room: { node, id, name }, scope: "room" }` per removed remote member (and
  bot) to its home domain, `to` = the member's address; a node ban of a remote address sends one with `scope:
  "node"` per room the user was removed from (the payload needs a room; a user in no room gets none). A node
  ban of a whole domain sends nothing: the domain is blocked from then on. Never the reason; queued through
  the outbox after the ban; failures never fail the ban.
- **Web client**: the message list is virtualized (only rows near the view are in the DOM, design note 9e) and
  marks the loaded count in `data-loaded`; the emoji picker is portaled out of the rows.

### 13.2 Implementation notes (reference node and web client, step 5)

- **Connect flow** (§8): `POST /auth/connect/code` takes `origin`, `code_challenge` (S256, 43 characters)
  and an optional `device_name`; local users with a full session and a reauth token only
  (`federation.local_only`, `auth.reauth_required` otherwise).
  The code (32 random bytes) is kept in memory as its SHA-256 for 2 minutes, bound to the origin, the
  challenge, the user and the confirming device. `POST /auth/connect/token` takes `code` and
  `code_verifier` without authentication; the first attempt spends the code whatever its outcome, and it
  fails with `connect.code_invalid` unless the verifier matches, the request's `Origin` header equals the
  bound origin (browsers always send it on these requests), the user is enabled and the confirming device
  still has a live session. Success is the session response of a **new device** of the home node
  (`device_name`, default "Browser (\<origin host>)") without a reauth token, audited as `user.connect`; the visiting client then
  requests federation tokens like any home client. A malformed challenge is `400 connect.challenge_invalid`.
  Limits: codes per device with the federation token limit (30/min), exchanges per client IP with the login
  limit. `http://` origins only with `--dev`.
- **Discovery for browsers**: `.well-known/tavrn` names the web client's origin in `web`. Clients fetch
  `https://<domain>/.well-known/tavrn` directly. When that is a `404` or fails, they ask the node they were
  loaded from: `GET /api/v1/federation/resolve/{domain}` answers `{domain, api, ws, web, source}` with `source`
  `well_known`, `srv` or `domain` (the node's whole resolution order of §1.3, including the SRV record browsers
  cannot read); `GET /api/v1/federation/peer/{domain}` answers the validated discovery document itself (for
  keys). Both are public, rate limited per client IP together (like logins), go through the federation client
  with its SSRF rules, domain policy and caches, and never return anything but validated endpoints or the
  validated document (no open proxy); the node's own domain is `federation.target_self`. After a direct `404`
  the client uses the node's answer, or `https://<domain>` when the node cannot help (federation off, rate
  limited, unreachable), but never after the node refused the resolution as `federation.peer_invalid`. The
  client accepts endpoints only for the requested domain (a document also needs `federation.v1`), as absolute
  `api`, `ws` and `web` URLs without credentials; since delegation (design note 4.2c) they may be on any host, the
  document being the identity domain's own statement. `http`/`ws` URLs only when the client itself was loaded
  over plain HTTP (development).
- **CORS** is exactly §8 (the preflight's request headers are mirrored); the CSP of
  `--dev` nodes adds `http: ws:` to `connect-src` for development peers.
- **Conversation index**: one row per user with the JSON array and a `BIGINT` version (migration `0012`).
  `If-Match` accepts `"7"` and `7`; `*` or no header write unconditionally; `"0"` creates the index and
  conflicts if one exists. Malformed headers are `400 validation.if_match`, duplicates
  `400 validation.duplicate`; the node's own domain is accepted as `node` even if it is not a valid peer
  domain (`localhost` in development). Writes share the read-marker limit (120/min per user).
- **Client sessions**: the home session as before (`tavrn.auth`; when the account belongs to another node
  it also stores that node's API and WebSocket URLs), federated sessions per node in `tavrn.nodes`
  (endpoints, tokens, the node-local user, the 7-day end). A 401 rotates the refresh token on that node;
  when the node refuses it, the client exchanges a fresh federation token. Sessions are renewed when less
  than 24 hours of the cap remain (checked at start and every 10 minutes). One WebSocket per node with a
  session. Reachability is learned from the requests: a network failure marks that node unreachable, any
  answer marks it reachable again; only its rooms show the banner (with a retry).
- **Client routes**: the home node's rooms keep `/rooms/<id>/…`; rooms of any other node live under
  `/n/<domain>/rooms/<id>/…` (channel view, settings). After signing in with an account of another node
  the unprefixed routes are the home node's rooms (reached cross-origin) and the rooms of the node that
  serves the client appear under its domain. Foreign domains are always shown (room rail groups, room
  header).
- **Index sync in the client**: entries are added after joining (discover list, invite link, room
  creation, invite list) and after creating a DM or group DM, and removed after leaving or deleting a room.
  At every start the client reconciles the index with each node's room and conversation lists: it opens a
  federated session for every node the index names (this is what restores rooms of other nodes on a new
  device), replaces that node's entries with what the node reports, keeps the entries of unreachable nodes
  and drops those of nodes that refuse the user for good (`federation.peer_blocked`,
  `federation.user_banned`). Conflicts are merged by re-applying the pending changes to the fresh list
  (at most three retries).
- **Invite list**: the home view lists `GET /users/me/invites` and hides the section while the node answers
  404 (before step 4); accepting joins on the hosting node, adds the index entry and dismisses the invite.
- **Encryption on a visiting web client**: unlocking uses the recovery key; the unlock page explains that
  passkeys of the home node cannot unlock on another origin, and the setup does not try to evaluate them.

**Integration (web client: encryption, DMs and invites across nodes):**

- **MLS across nodes**: the session manager (`mls.ts` in `@tavrn/e2ee`, formerly part of the web client) names
  every conversation by its qualified id `<hosting node>/<ulid>`. Group info, commits, the handshake log, Welcomes and KeyPackage
  claims (`POST /users/{address}/key-packages/claim`, the claim proxy of §3.5) go to the hosting node with
  the session there (the home client or the federated session). Identity keys and attestations of any user
  are fetched only from that user's home node: the home client for the own node, otherwise the public
  `GET /users/{address}/keys` of the address's domain, found through discovery (§13.2) and called without
  a session; the hosting node's key view is never consulted, and an address whose domain is not a valid
  node domain is not looked up. There is no proxy for this lookup: every node answers it CORS-open (§8).
  The client caches device lists for one hour (the node's cache TTL); a device it does not know triggers a
  refetch at once, `mls.remove_needed` and `identity.changed` drop the cached list. Backups stay on the home
  node under `<hosting node>/<ulid>`; per-conversation state stored by older versions with bare ids of the
  home node is qualified on load.
- **Welcomes**: fetched from the home node and every node with a session at start, whenever a node's
  WebSocket becomes ready and on `mls.welcome` of that node's socket. A Welcome is applied only if its group
  id is `<node that delivered it>/<conversation id it was delivered for>`, so no node can plant a group for a
  conversation of another node. `mls.commit`, `mls.welcome`, `mls.remove_needed`, `identity.changed` and the
  conversation events are handled on every node's socket; the ghost check uses the hosting node's member
  list.
- **DMs and group DMs**: the DM list merges the conversation lists of the home node and every node with a
  session (newest activity first); a conversation on another node lives under
  `/n/<domain>/conversations/<id>` and shows the domain. Unread counts come from each node's list and
  socket. Starting a DM first looks for a `dm` entry with that peer in the index (any node) and opens it,
  otherwise creates the DM on the home node; group DMs are always created on the home node. Members are
  compared by address (user ids are node-local); removing members, unfriending and unblocking send
  addresses.
- **Invitations**: `conversation.invite` of a **friend who is a user of the hosting node** (the
  initiator's home node; a node may name inviters of other domains for group additions, so only this case
  is trusted) is accepted without asking, like a DM of a friend on the same node simply appears: the client opens a federated session on the hosting node, reads the
  conversation there (the node's member list, not the invitation, decides the index entry and the `peer`),
  adds the index entry, dismisses the invitation and fetches the Welcomes waiting there. Pending
  invitations of friends found at start (the client was offline) are accepted the same way; all other
  invitations wait in the invite list. `room.invite` shows a notice and refreshes the invite list;
  accepting joins with the bound invite. The room's invite dialog sends direct invites by address
  (`POST /rooms/{room_id}/invites/direct`).
- **Failures**: a node that cannot be reached marks only its rooms and conversations (banner with retry,
  also for an open DM). When renewing a federated session ends in a refusal by a node (an answer, not a
  network failure), only that node's views show "sign in again", which exchanges a fresh federation token;
  a successful login clears it.
- **Room creation**: the reference node now emits `member.join` for the owner when a room is created, so
  an open WebSocket of the owner subscribes to the room at once (before, its events reached only sockets
  opened after the creation; the web client hid this by reconnecting on every route change).
- **Device changes**: the reference node does not forward `devices.changed` to clients over WebSocket (the
  client drops its cached list if a node does); the cache TTL, the refetch for unknown devices and
  `mls.remove_needed` cover new and removed devices.
- **Presence across nodes**: there is no S2S presence type. The client pushes
  its presence (chosen status, custom status, the device's idle flag and activity) to **every node it has a
  session on** — its home node and every node with a federated session — right after the session is opened,
  on every change and after reconnecting; each node computes the effective status from the user's WebSockets
  there and tells only the audience it knows itself (friends stored there, members of its rooms, members of
  its DMs; PROTOCOL.md §6a). Consequences, accepted on purpose: a node without a session of the user never
  learns anything about the user's presence, and friends of other nodes see a friend's presence only where both
  have sessions (a shared room's node, or one's home node). The web client keeps presences by address and
  merges what its nodes report.
- **Profiles**: the web client asks the node that served a user object for the profile (its mirror,
  §2.7) and loads images only from there; the full profile page takes the node in `?via=<domain>`.
- **Message requests of other nodes**: the web client lists invitations with
  `conversation.requested` under "Message requests" (not in the invite list), opens them with a federated
  session on the hosting node, accepts or declines there and dismisses the invitation on the home node; "decline
  and block" blocks on the home node with the note.
