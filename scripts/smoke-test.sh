#!/usr/bin/env bash
# Smoke test for the relay, run on the server host from the repo root's scripts/.
#
# 1. Live stack: TLS through Caddy, health, group lookup, and auth rejection.
#    Read-only, so it never touches the real group.
# 2. Full API on a throwaway api container (fresh database, removed afterwards):
#    group creation with the setup token, member certificates, join, pending
#    list, Key Master-only checks, approve with sealed keys + certificate +
#    anchors, deny, promotion, members, events, ack, media, and the /ws push
#    channel (who gets join_request and new_event, idle sockets dropped),
#    and Phase 6: member removal, single-device revocation, key rotation
#    (exactly the active devices, next version only, stale keys refused) and
#    the prune job (acked by every active device, and past retention).
#    Keys, signatures and ciphertext are random bytes: the relay never checks
#    them (clients do), only that certificates describe the right device.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

TMP=$(mktemp -d)
SMOKE=sidetray-smoke-$$
cleanup() { docker rm -f "$SMOKE" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 1' TERM
pass() { echo "PASS  $*"; }
# Also called from inside $(...), so stop the whole script, not just the subshell.
fail() { echo "FAIL  $*" >&2; kill -TERM $$; exit 1; }
j() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
rand32() { head -c 32 /dev/urandom | base64; }

# call METHOD URL [TOKEN] [JSON] -> prints "<status> <body>"
call() {
  local m=$1 url=$2 tok=${3:-} data=${4:-}
  local args=(-sS -X "$m" -o "$TMP/body" -w '%{http_code}')
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
  [ -n "$data" ] && args+=(-H 'Content-Type: application/json' -d "$data")
  [ -n "${CACERT:-}" ] && args+=(--cacert "$CACERT")
  local code; code=$(curl "${args[@]}" "$url")
  echo "$code $(cat "$TMP/body")"
}
# expect STATUS METHOD PATH [TOKEN] [JSON] -> prints body, fails on other status
expect() {
  local want=$1; shift
  local out; out=$(call "$1" "$B$2" "${3:-}" "${4:-}")
  [ "${out%% *}" = "$want" ] || fail "$1 $2 -> ${out%% *}, wanted $want: ${out#* }"
  echo "${out#* }"
}

echo "== live stack (https://$SIDETRAY_HOST)"
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$TMP/root.crt"
CACERT=$TMP/root.crt B="https://$SIDETRAY_HOST/api/v1"
[ "$(expect 200 GET /health | j '["ok"]')" = True ] && pass "health over TLS with Caddy's root" || fail "health over TLS with Caddy's root"
EXISTS=$(expect 200 GET /group | j '["exists"]'); pass "GET /group (exists=$EXISTS)"
expect 401 GET /events >/dev/null && pass "no token -> 401" || fail "no token -> 401"
expect 401 GET /events bogus-token >/dev/null && pass "unknown token -> 401" || fail "unknown token -> 401"
expect 401 GET /join/status bogus-token >/dev/null && pass "unknown token on /join/status -> 401" || fail "unknown token on /join/status -> 401"
probe() { python3 scripts/ws_probe.py "$@"; }
[ "$(probe "wss://$SIDETRAY_HOST/api/v1/ws" --cacert "$CACERT" || true)" = "rejected 403" ]   && pass "/ws through Caddy without a token -> 403" || fail "/ws through Caddy without a token -> 403"
[ "$(probe "wss://$SIDETRAY_HOST/api/v1/ws" --cacert "$CACERT" --token=bogus-token || true)" = "rejected 403" ]   && pass "/ws through Caddy with an unknown token -> 403" || fail "/ws through Caddy with an unknown token -> 403"
unset CACERT

echo "== full API on a throwaway container"
docker compose run -d --rm --no-deps --name "$SMOKE" -p 127.0.0.1::8000 \
  -e SIDETRAY_DATA=/tmp/smoke -e SIDETRAY_SETUP_TOKEN=smoke-setup -e SIDETRAY_WS_IDLE_SECONDS=6 -e SIDETRAY_PRUNE_EVERY_SECONDS=2 api >/dev/null
PORT=$(docker port "$SMOKE" 8000/tcp | head -1 | sed 's/.*://')
B="http://127.0.0.1:$PORT/api/v1"
for _ in $(seq 50); do curl -sf "$B/health" >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(expect 200 GET /group | j '["exists"]')" = False ] && pass "fresh server has no group" || fail "fresh server has no group"

KM_SIGN=$(rand32)
join_body() {  # name email [setup_token] [group] [sign_pubkey]
  local extra=""; [ -n "${3:-}" ] && extra=",\"setup_token\":\"$3\""
  echo "{\"group_name\":\"${4:-Smoke Family}\",\"display_name\":\"$1\",\"email\":\"$2\",\"enc_pubkey\":\"$(rand32)\",\"sign_pubkey\":\"${5:-$(rand32)}\"$extra}"
}
sig64() { head -c 64 /dev/urandom | base64 -w0; }
cert() {  # device role display_name
  echo "{\"device_id\":\"$1\",\"role\":\"$2\",\"display_name\":\"$3\",\"signature\":\"$(sig64)\"}"
}

expect 403 POST /join "" "$(join_body Eve e@x.test)" >/dev/null && pass "join with no group and no setup token -> 403" || fail "join with no group and no setup token -> 403"
expect 403 POST /join "" "$(join_body Eve e@x.test wrong)" >/dev/null && pass "wrong setup token -> 403" || fail "wrong setup token -> 403"
expect 422 POST /join "" '{"group_name":"G","display_name":"A","email":"a@x.test","enc_pubkey":"c2hvcnQ=","sign_pubkey":"c2hvcnQ="}' >/dev/null \
  && pass "short public keys -> 422" || fail "short public keys -> 422"

KM=$(expect 201 POST /join "" "$(join_body Kim kim@x.test smoke-setup "" "$KM_SIGN")")
KM_TOK=$(echo "$KM" | j '["token"]'); KM_DEV=$(echo "$KM" | j '["device_id"]'); KM_MEM=$(echo "$KM" | j '["member_id"]')
[ "$(echo "$KM" | j '["role"]')" = keymaster ] && [ "$(echo "$KM" | j '["status"]')" = active ] \
  && pass "setup token creates the group; first device is an active Key Master ($KM_DEV)" || fail "setup token creates the group; first device is an active Key Master ($KM_DEV)"
[ "$(expect 200 GET /group | j '["name"]')" = "Smoke Family" ] && pass "GET /group names it" || fail "GET /group names it"
expect 422 POST /certs "$KM_TOK" "{\"certs\":[$(cert "$KM_DEV" member Kim)]}" >/dev/null \
  && pass "self-certificate with the wrong role -> 422" || fail "self-certificate with the wrong role -> 422"
expect 422 POST /certs "$KM_TOK" "{\"certs\":[$(cert "$KM_DEV" keymaster Kimberly)]}" >/dev/null \
  && pass "certificate with the wrong display name -> 422" || fail "certificate with the wrong display name -> 422"
expect 200 POST /certs "$KM_TOK" "{\"certs\":[$(cert "$KM_DEV" keymaster Kim)]}" >/dev/null \
  && pass "founder stores a self-signed Key Master certificate" || fail "founder stores a self-signed Key Master certificate"
expect 409 POST /join "" "$(join_body Eve e@x.test smoke-setup)" >/dev/null && pass "second create -> 409" || fail "second create -> 409"
expect 404 POST /join "" "$(join_body Eve e@x.test "" "Other Group")" >/dev/null && pass "wrong group name -> 404" || fail "wrong group name -> 404"

AL=$(expect 201 POST /join "" "$(join_body Al al@x.test "" "smoke family")")
AL_TOK=$(echo "$AL" | j '["token"]'); AL_DEV=$(echo "$AL" | j '["device_id"]'); AL_MEM=$(echo "$AL" | j '["member_id"]')
[ "$(echo "$AL" | j '["status"]')" = pending ] && pass "member join is pending ($AL_DEV)" || fail "member join is pending ($AL_DEV)"
[ "$(expect 200 GET /join/status "$AL_TOK" | j '["status"]')" = pending ] && pass "/join/status -> pending" || fail "/join/status -> pending"
expect 401 GET /events "$AL_TOK" >/dev/null && pass "pending token can't read events" || fail "pending token can't read events"
expect 401 POST /events "$AL_TOK" '{"kind":"post","key_version":1,"ciphertext":"eA==","signature":"eA=="}' >/dev/null \
  && pass "pending token can't post" || fail "pending token can't post"

PEND=$(expect 200 GET /joins/pending "$KM_TOK")
[ "$(echo "$PEND" | j '["pending"][0]["device_id"]')" = "$AL_DEV" ] && pass "Key Master sees the pending device with its keys" || fail "Key Master sees the pending device with its keys"
SEALED=$(head -c 84 /dev/urandom | base64 -w0); SIG=$(head -c 64 /dev/urandom | base64 -w0)
approve_body() {  # device display_name [role]
  echo "{\"sealed_keys\":[{\"key_version\":1,\"sealed_blob\":\"$SEALED\",\"signature\":\"$SIG\"}],
    \"cert\":$(cert "$1" "${3:-member}" "$2"),
    \"anchors\":[{\"device_id\":\"$KM_DEV\",\"sign_pubkey\":\"$KM_SIGN\"}],\"anchors_signature\":\"$(sig64)\"}"
}
APPROVE=$(approve_body "$AL_DEV" Al)
expect 422 POST "/joins/$AL_DEV/approve" "$KM_TOK" '{"sealed_keys":[]}' >/dev/null && pass "approve without sealed keys -> 422" || fail "approve without sealed keys -> 422"
expect 422 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$(echo "$APPROVE" | python3 -c "import sys,json; b=json.load(sys.stdin); del b['cert']; print(json.dumps(b))")" >/dev/null \
  && pass "approve without a member certificate -> 422" || fail "approve without a member certificate -> 422"
expect 422 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$(approve_body "$KM_DEV" Al)" >/dev/null \
  && pass "approve with a certificate for another device -> 422" || fail "approve with a certificate for another device -> 422"
expect 422 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$(approve_body "$AL_DEV" Al keymaster)" >/dev/null \
  && pass "approve with a Key Master certificate for a member -> 422" || fail "approve with a Key Master certificate for a member -> 422"
expect 200 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$APPROVE" >/dev/null && pass "Key Master approves with a sealed, signed key" || fail "Key Master approves with a sealed, signed key"
expect 409 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$APPROVE" >/dev/null && pass "approving twice -> 409" || fail "approving twice -> 409"

ST=$(expect 200 GET /join/status "$AL_TOK")
python3 - "$ST" "$SEALED" "$SIG" "$KM_DEV" <<'PY'
import json, sys
s, sealed, sig, km = json.loads(sys.argv[1]), *sys.argv[2:]
k = s["sealed_keys"][0]
assert s["status"] == "active" and s["role"] == "member", s
assert (k["key_version"], k["sealed_blob"], k["signature"], k["signer_device_id"]) == (1, sealed, sig, km), k
assert len(k["signer_sign_pubkey"]) == 44 and len(k["signer_enc_pubkey"]) == 44 and k["signer_name"] == "Kim", k
assert s["approved_by"] == km and s["anchors"][0]["device_id"] == km and len(s["anchors_signature"]) == 88, s
PY
pass "/join/status returns the sealed key, signature, approver keys and handed-over anchors"
[ "$(expect 200 GET /keys "$AL_TOK" | j '["sealed_keys"][0]["key_version"]')" = 1 ] && pass "GET /keys" || fail "GET /keys"
expect 403 GET /joins/pending "$AL_TOK" >/dev/null && pass "member can't list pending joins (403)" || fail "member can't list pending joins (403)"

MAL=$(expect 201 POST /join "" "$(join_body Mal mal@x.test)")
MAL_TOK=$(echo "$MAL" | j '["token"]'); MAL_DEV=$(echo "$MAL" | j '["device_id"]')
expect 403 POST /certs "$AL_TOK" "{\"certs\":[$(cert "$AL_DEV" member Al)]}" >/dev/null \
  && pass "member can't store certificates (403)" || fail "member can't store certificates (403)"
expect 403 POST "/members/$AL_MEM/role" "$AL_TOK" "{\"role\":\"keymaster\",\"certs\":[$(cert "$AL_DEV" keymaster Al)]}" >/dev/null \
  && pass "member can't promote themselves (403)" || fail "member can't promote themselves (403)"
expect 403 POST "/joins/$MAL_DEV/approve" "$AL_TOK" "$(approve_body "$MAL_DEV" Mal)" >/dev/null && pass "member can't approve (403)" || fail "member can't approve (403)"
expect 200 POST "/joins/$MAL_DEV/deny" "$KM_TOK" >/dev/null && pass "Key Master denies a join" || fail "Key Master denies a join"
[ "$(expect 200 GET /join/status "$MAL_TOK" | j '["status"]')" = denied ] && pass "/join/status -> denied" || fail "/join/status -> denied"
expect 401 GET /events "$MAL_TOK" >/dev/null && pass "denied token can't read events" || fail "denied token can't read events"
expect 404 POST /joins/d_nope/deny "$KM_TOK" >/dev/null && pass "unknown device -> 404" || fail "unknown device -> 404"

ROSTER=$(expect 200 GET /members "$AL_TOK")
python3 - "$ROSTER" "$KM_DEV" "$AL_DEV" <<'PY'
import json, sys
r, km, al = json.loads(sys.argv[1]), *sys.argv[2:]
assert [m["display_name"] for m in r["members"]] == ["Kim", "Al"], r
devs = {d["id"]: d for m in r["members"] for d in m["devices"]}
assert set(devs) == {km, al}, devs
for d in devs.values():
    assert len(d["enc_pubkey"]) == 44 and len(d["sign_pubkey"]) == 44, d
assert [(c["issuer_device_id"], c["role"]) for c in devs[km]["certs"]] == [(km, "keymaster")], devs[km]
assert [(c["issuer_device_id"], c["role"], c["display_name"]) for c in devs[al]["certs"]] == [(km, "member", "Al")], devs[al]
PY
pass "GET /members lists Kim and Al only, each device with its keys and certificates"

expect 422 POST "/members/$AL_MEM/role" "$KM_TOK" "{\"role\":\"keymaster\",\"certs\":[$(cert "$KM_DEV" keymaster Kim)]}" >/dev/null \
  && pass "promotion without a certificate for each of the member's devices -> 422" || fail "promotion without a certificate for each of the member's devices -> 422"
expect 422 POST "/members/$AL_MEM/role" "$KM_TOK" "{\"role\":\"member\",\"certs\":[$(cert "$AL_DEV" member Al)]}" >/dev/null \
  && pass "demotion isn't supported yet -> 422" || fail "demotion isn't supported yet -> 422"
expect 200 POST "/members/$AL_MEM/role" "$KM_TOK" "{\"role\":\"keymaster\",\"certs\":[$(cert "$AL_DEV" keymaster Al)]}" >/dev/null \
  && pass "Key Master promotes Al with a signed Key Master certificate" || fail "Key Master promotes Al with a signed Key Master certificate"
expect 409 POST "/members/$AL_MEM/role" "$KM_TOK" "{\"role\":\"keymaster\",\"certs\":[$(cert "$AL_DEV" keymaster Al)]}" >/dev/null \
  && pass "promoting twice -> 409" || fail "promoting twice -> 409"
[ "$(expect 200 GET /join/status "$AL_TOK" | j '["role"]')" = keymaster ] && pass "Al's /join/status now says keymaster" || fail "Al's /join/status now says keymaster"
[ "$(expect 200 GET /members "$AL_TOK" | python3 -c "import sys,json; r=json.load(sys.stdin); print(sorted(c['role'] for m in r['members'] for d in m['devices'] if m['display_name']=='Al' for c in d['certs']))")" = "['keymaster', 'member']" ] \
  && pass "Al's device carries both certificates" || fail "Al's device carries both certificates"
expect 200 GET /joins/pending "$AL_TOK" >/dev/null && pass "promoted Al can list pending joins" || fail "promoted Al can list pending joins"

head -c 200000 /dev/urandom > "$TMP/blob"
MID=$(curl -sS --fail-with-body -H "Authorization: Bearer $AL_TOK" -H 'Content-Type: application/octet-stream' \
  --data-binary @"$TMP/blob" "$B/media" | j '["id"]')
curl -sS --fail-with-body -H "Authorization: Bearer $KM_TOK" -o "$TMP/blob.out" "$B/media/$MID"
cmp -s "$TMP/blob" "$TMP/blob.out" && pass "media round trip between devices ($MID)" || fail "media round trip between devices ($MID)"
CT=$(head -c 100 /dev/urandom | base64 -w0)
SEQ=$(expect 201 POST /events "$AL_TOK" "{\"kind\":\"post\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\",\"media_ids\":[\"$MID\"]}" | j '["seq"]')
pass "member posted event seq=$SEQ"
GOT=$(expect 200 GET "/events?after=0" "$KM_TOK")
python3 -c "import sys,json; e=json.loads(sys.argv[1])['events'][-1]; assert (e['seq'],e['ciphertext'],e['author_device_id'],e['media_ids'])==($SEQ,'$CT','$AL_DEV',['$MID']), e" "$GOT"
pass "Key Master pulled it, attributed to the member's device"
[ "$(expect 200 GET "/events?after=$SEQ" "$KM_TOK" | j '["events"]')" = "[]" ] && pass "?after=$SEQ is empty" || fail "?after=$SEQ is empty"
[ "$(expect 200 POST /ack "$KM_TOK" "{\"seq\":$SEQ}" | j '["last_seq"]')" = "$SEQ" ] && pass "acked seq=$SEQ" || fail "acked seq=$SEQ"

echo "== push channel (/ws)"
W="ws://127.0.0.1:$PORT/api/v1/ws"
[ "$(probe "$W" || true)" = "rejected 403" ] && pass "/ws without a token -> 403" || fail "/ws without a token -> 403"
[ "$(probe "$W" --token=bogus-token || true)" = "rejected 403" ] && pass "/ws with an unknown token -> 403" || fail "/ws with an unknown token -> 403"
ZED=$(expect 201 POST /join "" "$(join_body Zed zed@x.test)")
ZED_TOK=$(echo "$ZED" | j '["token"]'); ZED_DEV=$(echo "$ZED" | j '["device_id"]'); ZED_MEM=$(echo "$ZED" | j '["member_id"]')
[ "$(probe "$W" --token="$ZED_TOK" || true)" = "rejected 403" ] && pass "/ws with a pending token -> 403" || fail "/ws with a pending token -> 403"
[ "$(probe "$W" --token="$MAL_TOK" || true)" = "rejected 403" ] && pass "/ws with a denied token -> 403" || fail "/ws with a denied token -> 403"
expect 200 POST "/joins/$ZED_DEV/approve" "$KM_TOK" "$(approve_body "$ZED_DEV" Zed)" >/dev/null && pass "Zed approved as a member" || fail "Zed approved as a member"

# Kim (Key Master) and Zed (member) listen; then Yan asks to join, Zed posts, Kim posts.
probe "$W" --token="$KM_TOK" --count 2 --timeout 15 --ready "$TMP/km.ready" > "$TMP/km.ws" & KM_WS=$!
probe "$W" --token="$ZED_TOK" --count 1 --timeout 15 --ready "$TMP/zed.ready" > "$TMP/zed.ws" & ZED_WS=$!
for _ in $(seq 50); do [ -e "$TMP/km.ready" ] && [ -e "$TMP/zed.ready" ] && break; sleep 0.1; done
[ -e "$TMP/km.ready" ] && [ -e "$TMP/zed.ready" ] && pass "two devices connected, each got hello and a pong" || fail "two devices connected, each got hello and a pong"
YAN=$(expect 201 POST /join "" "$(join_body Yan yan@x.test)")
YAN_DEV=$(echo "$YAN" | j '["device_id"]'); YAN_TOK=$(echo "$YAN" | j '["token"]')
ZSEQ=$(expect 201 POST /events "$ZED_TOK" "{\"kind\":\"post\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" | j '["seq"]')
KSEQ=$(expect 201 POST /events "$KM_TOK" "{\"kind\":\"comment\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" | j '["seq"]')
wait "$KM_WS" || fail "Kim's socket didn't get its two messages"
wait "$ZED_WS" || fail "Zed's socket didn't get its message"
python3 - "$TMP/km.ws" "$TMP/zed.ws" "$YAN_DEV" "$ZSEQ" "$KSEQ" <<'PY'
import json, sys
km = [json.loads(l) for l in open(sys.argv[1])]
zed = [json.loads(l) for l in open(sys.argv[2])]
yan, zseq, kseq = sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
assert km == [{"type": "join_request", "device_id": yan, "display_name": "Yan", "existing_member": False},
              {"type": "new_event", "seq": zseq, "kind": "post"}], km
assert zed == [{"type": "new_event", "seq": kseq, "kind": "comment"}], zed
PY
pass "Key Master got join_request + Zed's new_event; member Zed got only Kim's new_event, not its own or the join"
[ "$(probe "$W" --token="$KM_TOK" --count 1 --timeout 12)" = '{"type": "_closed"}' ]   && pass "a socket that stops pinging is closed after the idle timeout" || fail "a socket that stops pinging is closed after the idle timeout"

echo "== removal, revocation and key rotation"
expect 200 POST "/joins/$YAN_DEV/approve" "$KM_TOK" "$(approve_body "$YAN_DEV" Yan)" >/dev/null && pass "Yan approved as a member" || fail "Yan approved as a member"
expect 403 POST "/members/$KM_MEM/remove" "$YAN_TOK" >/dev/null && pass "member can't remove anyone (403)" || fail "member can't remove anyone (403)"
expect 409 POST "/members/$KM_MEM/remove" "$KM_TOK" >/dev/null && pass "Key Master can't remove themselves (409)" || fail "Key Master can't remove themselves (409)"
expect 404 POST /members/m_nope/remove "$KM_TOK" >/dev/null && pass "unknown member -> 404" || fail "unknown member -> 404"

probe "$W" --token="$ZED_TOK" --count 2 --timeout 15 --ready "$TMP/zed2.ready" > "$TMP/zed2.ws" & ZED_WS=$!
for _ in $(seq 50); do [ -e "$TMP/zed2.ready" ] && break; sleep 0.1; done
REM=$(expect 200 POST "/members/$ZED_MEM/remove" "$KM_TOK")
[ "$(echo "$REM" | j '["revoked_devices"]')" = "['$ZED_DEV']" ] && [ "$(echo "$REM" | j '["rotation_pending"]')" = True ] \
  && pass "Key Master removes Zed: his device is revoked, rotation pending" || fail "Key Master removes Zed: his device is revoked, rotation pending"
wait "$ZED_WS" || fail "Zed's socket didn't get removed + close"
[ "$(cat "$TMP/zed2.ws")" = "$(printf '%s\n%s' '{"type": "removed", "scope": "member"}' '{"type": "_closed"}')" ] \
  && pass "Zed's open socket got {type: removed, scope: member} and was closed" || fail "Zed's open socket got removed + close: $(cat "$TMP/zed2.ws")"
expect 401 GET /events "$ZED_TOK" >/dev/null && pass "removed member's token can't read events" || fail "removed member's token can't read events"
expect 401 GET /keys "$ZED_TOK" >/dev/null && pass "removed member's token can't fetch keys" || fail "removed member's token can't fetch keys"
[ "$(expect 200 GET /join/status "$ZED_TOK" | j '["status"]')" = removed ] && pass "/join/status tells Zed's app it was removed" || fail "/join/status tells Zed's app it was removed"
[ "$(probe "$W" --token="$ZED_TOK" || true)" = "rejected 403" ] && pass "/ws with a removed member's token -> 403" || fail "/ws with a removed member's token -> 403"
expect 409 POST "/members/$ZED_MEM/remove" "$KM_TOK" >/dev/null && pass "removing twice -> 409" || fail "removing twice -> 409"
[ "$(expect 200 GET /members "$KM_TOK" | python3 -c "import sys,json; print(sorted(m['display_name'] for m in json.load(sys.stdin)['members']))")" = "['Al', 'Kim', 'Yan']" ] \
  && pass "roster no longer lists Zed" || fail "roster no longer lists Zed"
KEYS=$(expect 200 GET /keys "$KM_TOK")
[ "$(echo "$KEYS" | j '["rotation_pending"]')" = True ] && [ "$(echo "$KEYS" | j '["key_version"]')" = 1 ] \
  && pass "GET /keys: key version 1, rotation pending" || fail "GET /keys: key version 1, rotation pending"

# rotate_body VERSION DEVICE... -> a v-VERSION key "sealed" to each device
rotate_body() {
  local v=$1; shift
  python3 - "$v" "$@" <<'PY'
import base64, json, os, sys
v, devs = int(sys.argv[1]), sys.argv[2:]
b = lambda n: base64.b64encode(os.urandom(n)).decode()
print(json.dumps({"key_version": v, "sealed_keys": [{"device_id": d, "sealed_blob": b(84), "signature": b(64)} for d in devs]}))
PY
}
expect 403 POST /keys/rotate "$YAN_TOK" "$(rotate_body 2 "$KM_DEV" "$AL_DEV" "$YAN_DEV")" >/dev/null && pass "member can't rotate the key (403)" || fail "member can't rotate the key (403)"
expect 409 POST /keys/rotate "$KM_TOK" "$(rotate_body 3 "$KM_DEV" "$AL_DEV" "$YAN_DEV")" >/dev/null && pass "skipping a version -> 409" || fail "skipping a version -> 409"
expect 422 POST /keys/rotate "$KM_TOK" "$(rotate_body 2 "$KM_DEV" "$AL_DEV")" >/dev/null && pass "leaving an active device out -> 422" || fail "leaving an active device out -> 422"
expect 422 POST /keys/rotate "$KM_TOK" "$(rotate_body 2 "$KM_DEV" "$AL_DEV" "$YAN_DEV" "$ZED_DEV")" >/dev/null && pass "sealing to the removed device -> 422" || fail "sealing to the removed device -> 422"
expect 422 POST /keys/rotate "$KM_TOK" "$(rotate_body 2 "$KM_DEV" "$AL_DEV" "$YAN_DEV" "$YAN_DEV")" >/dev/null && pass "two keys for one device -> 422" || fail "two keys for one device -> 422"
probe "$W" --token="$YAN_TOK" --count 1 --timeout 15 --ready "$TMP/yan.ready" > "$TMP/yan.ws" & YAN_WS=$!
for _ in $(seq 50); do [ -e "$TMP/yan.ready" ] && break; sleep 0.1; done
ROT=$(rotate_body 2 "$KM_DEV" "$AL_DEV" "$YAN_DEV")
expect 200 POST /keys/rotate "$KM_TOK" "$ROT" >/dev/null && pass "Key Master rotates to v2, sealed to exactly Kim, Al and Yan" || fail "Key Master rotates to v2"
wait "$YAN_WS" || fail "Yan's socket didn't get key_rotated"
[ "$(cat "$TMP/yan.ws")" = '{"type": "key_rotated", "key_version": 2}' ] && pass "Yan's socket got key_rotated v2" || fail "Yan's socket got key_rotated v2: $(cat "$TMP/yan.ws")"
expect 409 POST /keys/rotate "$KM_TOK" "$ROT" >/dev/null && pass "rotating to v2 twice -> 409" || fail "rotating to v2 twice -> 409"
python3 - "$(expect 200 GET /keys "$YAN_TOK")" "$ROT" "$YAN_DEV" "$KM_DEV" <<'PY'
import json, sys
k, rot, yan, km = json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3], sys.argv[4]
assert k["key_version"] == 2 and k["rotation_pending"] is False, k
v2 = [s for s in k["sealed_keys"] if s["key_version"] == 2]
mine = next(s for s in rot["sealed_keys"] if s["device_id"] == yan)
assert [s["key_version"] for s in k["sealed_keys"]] == [1, 2], k
assert (v2[0]["sealed_blob"], v2[0]["signature"], v2[0]["signer_device_id"]) == (mine["sealed_blob"], mine["signature"], km), v2
PY
pass "Yan's GET /keys has v1 and v2 (its own blob, signed by Kim); rotation no longer pending"
expect 409 POST /events "$YAN_TOK" "{\"kind\":\"post\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" >/dev/null && pass "posting with the old key v1 -> 409" || fail "posting with the old key v1 -> 409"
expect 422 POST /events "$YAN_TOK" "{\"kind\":\"post\",\"key_version\":3,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" >/dev/null && pass "posting with a key that doesn't exist yet -> 422" || fail "posting with key v3 -> 422"
V2SEQ=$(expect 201 POST /events "$YAN_TOK" "{\"kind\":\"post\",\"key_version\":2,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" | j '["seq"]')
pass "posting with v2 works (seq=$V2SEQ)"
[ "$(expect 200 GET "/events?after=0" "$KM_TOK" | j '["key_version"]')" = 2 ] && pass "GET /events reports the current key version" || fail "GET /events reports the current key version"

v12() {  # approve body sealing versions 1 and 2: device display_name [role]
  echo "$(approve_body "$@")" | python3 -c "import sys,json; b=json.load(sys.stdin); k=dict(b['sealed_keys'][0]); k['key_version']=2; b['sealed_keys'].append(k); print(json.dumps(b))"
}
WES=$(expect 201 POST /join "" "$(join_body Wes wes@x.test)")
WES_DEV=$(echo "$WES" | j '["device_id"]'); WES_TOK=$(echo "$WES" | j '["token"]')
expect 409 POST "/joins/$WES_DEV/approve" "$KM_TOK" "$(approve_body "$WES_DEV" Wes)" >/dev/null && pass "approving with only the old key -> 409" || fail "approving with only the old key -> 409"
expect 200 POST "/joins/$WES_DEV/approve" "$KM_TOK" "$(v12 "$WES_DEV" Wes)" >/dev/null && pass "approving with v1 and v2 works" || fail "approving with v1 and v2 works"

AL2=$(expect 201 POST /join "" "$(join_body Al al@x.test)")
AL2_DEV=$(echo "$AL2" | j '["device_id"]'); AL2_TOK=$(echo "$AL2" | j '["token"]')
expect 409 POST "/devices/$AL2_DEV/revoke" "$KM_TOK" >/dev/null && pass "revoking a pending device -> 409 (deny it)" || fail "revoking a pending device -> 409"
expect 200 POST "/joins/$AL2_DEV/approve" "$KM_TOK" "$(v12 "$AL2_DEV" Al keymaster)" >/dev/null && pass "Al's second device approved" || fail "Al's second device approved"
expect 403 POST "/devices/$AL2_DEV/revoke" "$YAN_TOK" >/dev/null && pass "member can't revoke a device (403)" || fail "member can't revoke a device (403)"
expect 409 POST "/devices/$KM_DEV/revoke" "$KM_TOK" >/dev/null && pass "Key Master can't revoke the device they're using (409)" || fail "can't revoke own device (409)"
probe "$W" --token="$AL2_TOK" --count 2 --timeout 15 --ready "$TMP/al2.ready" > "$TMP/al2.ws" & AL2_WS=$!
for _ in $(seq 50); do [ -e "$TMP/al2.ready" ] && break; sleep 0.1; done
expect 200 POST "/devices/$AL2_DEV/revoke" "$KM_TOK" >/dev/null && pass "Key Master revokes Al's second (lost) device" || fail "Key Master revokes Al's second device"
wait "$AL2_WS" || fail "the lost device's socket didn't get removed + close"
[ "$(head -1 "$TMP/al2.ws")" = '{"type": "removed", "scope": "device"}' ] && pass "its socket got {type: removed, scope: device}" || fail "lost device socket: $(cat "$TMP/al2.ws")"
expect 401 GET /events "$AL2_TOK" >/dev/null && pass "revoked device's token can't read events" || fail "revoked device's token can't read events"
[ "$(expect 200 GET /join/status "$AL2_TOK" | j '["status"]')" = revoked ] && pass "/join/status says revoked (not removed)" || fail "/join/status says revoked"
expect 200 GET /events "$AL_TOK" >/dev/null && pass "Al's other device still works" || fail "Al's other device still works"
[ "$(expect 200 GET /keys "$KM_TOK" | j '["rotation_pending"]')" = True ] && pass "revoking a device makes rotation pending" || fail "revoking a device makes rotation pending"
expect 200 POST /keys/rotate "$KM_TOK" "$(rotate_body 3 "$KM_DEV" "$AL_DEV" "$YAN_DEV" "$WES_DEV")" >/dev/null && pass "rotate to v3 without the lost device" || fail "rotate to v3 without the lost device"

echo "== pruning"
LAST=$(expect 201 POST /events "$KM_TOK" "{\"kind\":\"post\",\"key_version\":3,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\",\"media_ids\":[\"$MID\"]}" | j '["seq"]')
for t in "$KM_TOK" "$AL_TOK" "$YAN_TOK"; do expect 200 POST /ack "$t" "{\"seq\":$LAST}" >/dev/null; done
sleep 4
[ "$(expect 200 GET "/events?after=0" "$KM_TOK" | j '["events"][0]["seq"]')" -le "$LAST" ] && pass "nothing pruned while Wes (active) hasn't acked" || fail "nothing pruned while Wes hasn't acked"
expect 200 POST /ack "$WES_TOK" "{\"seq\":$LAST}" >/dev/null
for _ in $(seq 40); do [ "$(expect 200 GET "/events?after=0" "$KM_TOK" | j '["events"]')" = "[]" ] && break; sleep 0.25; done
GOT=$(expect 200 GET "/events?after=0" "$KM_TOK")
[ "$(echo "$GOT" | j '["events"]')" = "[]" ] && [ "$(echo "$GOT" | j '["pruned_through"]')" = "$LAST" ] \
  && pass "hourly job (every 2 s here) pruned everything once every active device acked; removed Zed and revoked devices didn't count" \
  || fail "prune job after everyone acked: $GOT"
expect 404 GET "/media/$MID" "$KM_TOK" >/dev/null && pass "the pruned post's media is gone" || fail "the pruned post's media is gone"
OLD=$(expect 201 POST /events "$KM_TOK" "{\"kind\":\"post\",\"key_version\":3,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\"}" | j '["seq"]')
expect 200 POST /ack "$KM_TOK" "{\"seq\":$OLD}" >/dev/null
docker exec "$SMOKE" python -c "import sqlite3; c = sqlite3.connect('/tmp/smoke/sidetray.db'); c.execute('UPDATE events SET created_at = created_at - 91 * 86400 WHERE seq = ?', ($OLD,)); c.commit()"
PRUNED=$(docker exec "$SMOKE" python -m app.admin prune)
[ "$(echo "$PRUNED" | j '["events"]')" -le 1 ] || fail "admin prune: $PRUNED"
GOT=$(expect 200 GET "/events?after=$LAST" "$YAN_TOK")
[ "$(echo "$GOT" | j '["events"]')" = "[]" ] && [ "$(echo "$GOT" | j '["pruned_through"]')" = "$OLD" ] \
  && pass "an event past the 90-day window is pruned though Yan never got it; pruned_through ($OLD) > Yan's cursor ($LAST) tells Yan it missed posts" \
  || fail "retention prune: $GOT"
echo "All smoke checks passed."
