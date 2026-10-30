# Side Tray

Private, end-to-end encrypted feed for one group. See [SPEC.md](SPEC.md).

**Status: Phase 3 (join and Key Master flow).** Devices join with their public
keys, compare safety codes with a Key Master by phone, and receive the group key
sealed to them and signed by the approving Key Master. Every device has its own
bearer token. A dev CLI (`cli/`) drives the whole flow. The desktop app, WebSocket,
pruning, removal and rate limits come in later phases.

## Layout

```
compose.yaml          api (FastAPI + SQLite) behind caddy (HTTPS)
Caddyfile             TLS via Caddy's internal CA (no domain yet)
server/app/main.py    the relay
scripts/smoke-test.sh live TLS checks + full API run on a throwaway container
crypto/               Rust crate: keys, sealing, encryption, signatures, safety codes
cli/                  Rust dev CLI (`sidetray`): init-group, join, approve, post, pull
```

## Run

Needs Docker Engine with the Compose plugin.

```sh
cp .env.example .env     # set SIDETRAY_HOST and SIDETRAY_SETUP_TOKEN
docker compose up -d --build
./scripts/smoke-test.sh  # never touches the real group
```

Data lives in the `api_data` volume (`/data/sidetray.db` and `/data/media/`).
Caddy's CA and certs live in `caddy_data`; keep that volume or clients will need the new root.

## Trusting the test certificate

There's no domain yet, so Caddy signs a cert for the IP with its own local CA.
Export the root and point curl at it:

```sh
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > sidetray-root.crt
curl --cacert sidetray-root.crt https://10.1.1.188/api/v1/health
```

When a domain exists, set `SIDETRAY_HOST` to it and remove `tls internal`
from the Caddyfile to get a Let's Encrypt cert.

## API

All under `/api/v1`. Authenticated calls send `Authorization: Bearer <device token>`;
the token comes back from `POST /join` and is stored hashed. Binary fields are
base64. The server never decrypts.

| Method | Path | Who | Body / params | Returns |
| --- | --- | --- | --- | --- |
| GET | /health | anyone | | `{ok}` |
| GET | /group | anyone | | `{exists, id?, name?}` |
| POST | /join | anyone | `{group_name, display_name, email, enc_pubkey, sign_pubkey, setup_token?}` | `{group_id, group_name, member_id, device_id, token, status, role}` |
| GET | /join/status | any device token | | `{status: pending\|active\|denied, role?, sealed_keys[]?}` |
| GET | /keys | member | | `{sealed_keys[]}` |
| GET | /joins/pending | Key Master | | `{pending[]}` with each device's public keys |
| POST | /joins/{device_id}/approve | Key Master | `{sealed_keys: [{key_version, sealed_blob, signature}]}` | `{status: active}` |
| POST | /joins/{device_id}/deny | Key Master | | `{status: denied}` |
| GET | /members | member | | `{members: [{id, display_name, role, devices: [{id, sign_pubkey}]}]}` |
| POST | /events | member | `{kind, key_version, ciphertext, signature, media_ids[]}` | `{seq}` |
| GET | /events | member | `?after=<seq>&limit=<1..500>` | `{events[], last_seq, has_more}` |
| POST | /ack | member | `{seq}` (only moves forward) | `{last_seq}` |
| POST | /media | member | raw bytes, max 10 MB | `{id, size_bytes}` |
| GET | /media/{id} | member | | the bytes |

- **Creating the group:** on a server with no group, `POST /join` with the
  operator's `SIDETRAY_SETUP_TOKEN` creates it, and that device becomes the active
  Key Master. Without the right token it's refused, so nobody else can claim an
  empty server. Once the group exists the setup token does nothing.
- **Joining:** anyone else's join is `pending`. A pending token works only for
  `/join/status`. Joining with the email of an existing member adds a device to
  that member (the pending list flags it).
- **Approving:** a Key Master uploads the group key (every version) sealed to the
  new device. Each sealed blob carries the Key Master's Ed25519 signature over
  `protocol::key_grant_message` (group, recipient device, recipient key, version,
  blob). `/join/status` returns it with the signer's public keys.

## CLI (Phase 3)

```sh
cd cli && cargo build --release      # binary: target/release/sidetray
```

Each device keeps its keys and state in `--state <dir>` (default `.sidetray`),
so several can run side by side. Pass `--ca-cert sidetray-root.crt` while there's
no real domain.

| Command | Who | What it does |
| --- | --- | --- |
| `init-group --server --group --name --email --setup-token` | first device | Creates the group, makes you Key Master, generates group key v1 |
| `join --server --group --name --email` | new device | Sends public keys, prints the safety code to read out |
| `pending` | Key Master | Lists join requests with codes computed from the relayed keys |
| `approve <device> --code <code>` | Key Master | Refuses unless the code you heard matches; seals and signs every key version; prints your Key Master code |
| `deny <device>` | Key Master | Rejects a request |
| `status` | anyone | While pending: on approval, verifies each grant's signature, unseals the keys and shows the approver's code to check |
| `members`, `post <text>`, `pull` | members | Roster; encrypt + sign a post; verify + decrypt new events and ack them |

Posts are encrypted with associated data `protocol::event_ad(group, kind)`.
Authors sign `protocol::event_message(group, author device, kind, version, ciphertext)`.
The state file holds private keys and is created with mode 0600. The desktop app
will use the OS keychain instead.

## Crypto core (Phase 2)

`crypto/` is a pure-Rust library (no system libsodium) whose formats match libsodium:

| Function | Construction | Format |
| --- | --- | --- |
| `generate_device_keys` | X25519 + Ed25519 | 32-byte public keys each |
| `generate_group_key(version)` | 32 random bytes | |
| `seal_group_key` / `unseal_group_key` | `crypto_box_seal` | seals `u32le(version) ‖ key`, 84 bytes |
| `encrypt` / `decrypt` | XChaCha20-Poly1305 IETF | `nonce[24] ‖ ct ‖ tag[16]`, AD = `u32le(key_version) ‖ ad` |
| `sign` / `verify` | Ed25519 detached, strict verify | 64 bytes |
| `safety_code` | BLAKE2b-256 over both public keys, 1024-word list | `MISS-PARCEL-EARTH-PRICE-88` |

```sh
cd crypto && cargo test
```

The tests include vectors produced by libsodium (via PyNaCl) and RFC 8032, and they
check that flipping any single byte is caught. The wordlist in `crypto/src/wordlist.rs`
is frozen: a test pins its hash, because editing it would change every safety code.
It comes from the public-domain [12dicts](http://wordlist.aspell.net/12dicts/) lists;
`crypto/tools/wordlist/` has the script and blocklist that picked it.

## Notes

- Every table carries `group_id`; the MVP has one group per server.
- Tokens are stored as SHA-256 hashes.
- Phase 3 removes the Phase 1 seed (group `g_test` and its test token) on startup.
- Footprint on the test VM: ~35 MB (api) + ~70 MB (caddy), with 256 MB / 128 MB caps.
