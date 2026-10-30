# Side Tray

Private, end-to-end encrypted feed for one group. See [SPEC.md](SPEC.md).

**Status: Phase 2 (crypto core).** The relay stores and serves events, acks and
encrypted media. Auth is a single hardcoded test token. The client crypto crate
(`crypto/`) is done; joins, WebSocket, pruning and rate limits come in later phases.

## Layout

```
compose.yaml          api (FastAPI + SQLite) behind caddy (HTTPS)
Caddyfile             TLS via Caddy's internal CA (no domain yet)
server/app/main.py    the relay
scripts/smoke-test.sh end-to-end curl checks
crypto/               Rust crate: keys, sealing, encryption, signatures, safety codes
```

## Run

Needs Docker Engine with the Compose plugin.

```sh
cp .env.example .env     # set SIDETRAY_HOST to this machine's LAN IP
docker compose up -d --build
./scripts/smoke-test.sh  # post, pull with ?after=, ack, media up/down
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

## API (Phase 1)

All under `/api/v1`, with `Authorization: Bearer $SIDETRAY_TEST_TOKEN`.
Content fields are base64 ciphertext; the server never decrypts.

| Method | Path | Body / params | Returns |
| --- | --- | --- | --- |
| POST | /events | `{kind, key_version, ciphertext, signature, media_ids[]}` | `{seq}` |
| GET | /events | `?after=<seq>&limit=<1..500>` | `{events[], last_seq, has_more}` |
| POST | /ack | `{seq}` (only moves forward) | `{last_seq}` |
| POST | /media | raw bytes, `Content-Type: application/octet-stream`, max 10 MB | `{id, size_bytes}` |
| GET | /media/{id} | | the bytes |
| GET | /health | no auth | `{ok: true}` |

`kind` is one of `post`, `comment`, `reaction`, `edit`, `delete`. `media_ids` must
reference media already uploaded to the same group.

Example:

```sh
H="Authorization: Bearer sidetray-test-token"; B=https://10.1.1.188/api/v1
curl --cacert sidetray-root.crt -H "$H" -H 'Content-Type: application/json' \
  -d '{"kind":"post","key_version":1,"ciphertext":"aGVsbG8=","signature":"c2ln"}' $B/events
curl --cacert sidetray-root.crt -H "$H" "$B/events?after=0"
```

## Crypto core (Phase 2)

`crypto/` is a pure-Rust library (no system libsodium) whose formats match libsodium:

| Function | Construction | Format |
| --- | --- | --- |
| `generate_device_keys` | X25519 + Ed25519 | 32-byte public keys each |
| `generate_group_key(version)` | 32 random bytes | |
| `seal_group_key` / `unseal_group_key` | `crypto_box_seal` | seals `u32le(version) ‖ key`, 84 bytes |
| `encrypt` / `decrypt` | XChaCha20-Poly1305 IETF | `nonce[24] ‖ ct ‖ tag[16]`, AD = `u32le(key_version) ‖ ad` |
| `sign` / `verify` | Ed25519 detached, strict verify | 64 bytes |
| `safety_code` | BLAKE2b-256 over both public keys, 256-word list | `ISLAND-HARP-JIGSAW-81` |

```sh
cd crypto && cargo test
```

The tests include vectors produced by libsodium (via PyNaCl) and RFC 8032, and they
check that flipping any single byte is caught. The wordlist in `crypto/src/wordlist.rs`
is frozen: a test pins its hash, because editing it would change every safety code.

## Notes

- Every table carries `group_id`; Phase 1 seeds one group (`g_test`), one
  Key Master member and one active device (`d_test`) bound to the test token.
- Tokens are stored as SHA-256 hashes, matching the Phase 3 design.
- Footprint on the test VM: ~35 MB (api) + ~70 MB (caddy), with 256 MB / 128 MB caps.
