#!/usr/bin/env bash
# Smoke test for the relay, run on the server host from the repo root's scripts/.
#
# 1. Live stack: TLS through Caddy, health, group lookup, and auth rejection.
#    Read-only, so it never touches the real group.
# 2. Full API on a throwaway api container (fresh database, removed afterwards):
#    group creation with the setup token, join, pending list, Key Master-only
#    checks, approve with sealed keys, deny, members, events, ack, media.
#    Keys and ciphertext are random bytes: the relay never looks inside them.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

TMP=$(mktemp -d)
SMOKE=sidetray-smoke-$$
cleanup() { docker rm -f "$SMOKE" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; exit 1; }
j() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
rand32() { head -c 32 /dev/urandom | base64; }

# call METHOD URL [TOKEN] [JSON] -> prints "<status> <body>"
call() {
  local m=$1 url=$2 tok=${3:-} data=${4:-} args=(-sS -X "$m" -o "$TMP/body" -w '%{http_code}')
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
[ "$(expect 200 GET /health | j '["ok"]')" = True ] && pass "health over TLS with Caddy's root"
EXISTS=$(expect 200 GET /group | j '["exists"]'); pass "GET /group (exists=$EXISTS)"
expect 401 GET /events >/dev/null && pass "no token -> 401"
expect 401 GET /events bogus-token >/dev/null && pass "unknown token -> 401"
expect 401 GET /join/status bogus-token >/dev/null && pass "unknown token on /join/status -> 401"
unset CACERT

echo "== full API on a throwaway container"
docker compose run -d --rm --no-deps --name "$SMOKE" -p 127.0.0.1::8000 \
  -e SIDETRAY_DATA=/tmp/smoke -e SIDETRAY_SETUP_TOKEN=smoke-setup api >/dev/null
PORT=$(docker port "$SMOKE" 8000/tcp | head -1 | sed 's/.*://')
B="http://127.0.0.1:$PORT/api/v1"
for _ in $(seq 50); do curl -sf "$B/health" >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(expect 200 GET /group | j '["exists"]')" = False ] && pass "fresh server has no group"

join_body() {  # name email [setup_token] [group]
  local extra=""; [ -n "${3:-}" ] && extra=",\"setup_token\":\"$3\""
  echo "{\"group_name\":\"${4:-Smoke Family}\",\"display_name\":\"$1\",\"email\":\"$2\",\"enc_pubkey\":\"$(rand32)\",\"sign_pubkey\":\"$(rand32)\"$extra}"
}

expect 403 POST /join "" "$(join_body Eve e@x.test)" >/dev/null && pass "join with no group and no setup token -> 403"
expect 403 POST /join "" "$(join_body Eve e@x.test wrong)" >/dev/null && pass "wrong setup token -> 403"
expect 422 POST /join "" '{"group_name":"G","display_name":"A","email":"a@x.test","enc_pubkey":"c2hvcnQ=","sign_pubkey":"c2hvcnQ="}' >/dev/null \
  && pass "short public keys -> 422"

KM=$(expect 201 POST /join "" "$(join_body Kim kim@x.test smoke-setup)")
KM_TOK=$(echo "$KM" | j '["token"]'); KM_DEV=$(echo "$KM" | j '["device_id"]')
[ "$(echo "$KM" | j '["role"]')" = keymaster ] && [ "$(echo "$KM" | j '["status"]')" = active ] \
  && pass "setup token creates the group; first device is an active Key Master ($KM_DEV)"
[ "$(expect 200 GET /group | j '["name"]')" = "Smoke Family" ] && pass "GET /group names it"
expect 409 POST /join "" "$(join_body Eve e@x.test smoke-setup)" >/dev/null && pass "second create -> 409"
expect 404 POST /join "" "$(join_body Eve e@x.test "" "Other Group")" >/dev/null && pass "wrong group name -> 404"

AL=$(expect 201 POST /join "" "$(join_body Al al@x.test "" "smoke family")")
AL_TOK=$(echo "$AL" | j '["token"]'); AL_DEV=$(echo "$AL" | j '["device_id"]')
[ "$(echo "$AL" | j '["status"]')" = pending ] && pass "member join is pending ($AL_DEV)"
[ "$(expect 200 GET /join/status "$AL_TOK" | j '["status"]')" = pending ] && pass "/join/status -> pending"
expect 401 GET /events "$AL_TOK" >/dev/null && pass "pending token can't read events"
expect 401 POST /events "$AL_TOK" '{"kind":"post","key_version":1,"ciphertext":"eA==","signature":"eA=="}' >/dev/null \
  && pass "pending token can't post"

PEND=$(expect 200 GET /joins/pending "$KM_TOK")
[ "$(echo "$PEND" | j '["pending"][0]["device_id"]')" = "$AL_DEV" ] && pass "Key Master sees the pending device with its keys"
SEALED=$(head -c 84 /dev/urandom | base64 -w0); SIG=$(head -c 64 /dev/urandom | base64 -w0)
APPROVE="{\"sealed_keys\":[{\"key_version\":1,\"sealed_blob\":\"$SEALED\",\"signature\":\"$SIG\"}]}"
expect 422 POST "/joins/$AL_DEV/approve" "$KM_TOK" '{"sealed_keys":[]}' >/dev/null && pass "approve without sealed keys -> 422"
expect 200 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$APPROVE" >/dev/null && pass "Key Master approves with a sealed, signed key"
expect 409 POST "/joins/$AL_DEV/approve" "$KM_TOK" "$APPROVE" >/dev/null && pass "approving twice -> 409"

ST=$(expect 200 GET /join/status "$AL_TOK")
python3 - "$ST" "$SEALED" "$SIG" "$KM_DEV" <<'PY'
import json, sys
s, sealed, sig, km = json.loads(sys.argv[1]), *sys.argv[2:]
k = s["sealed_keys"][0]
assert s["status"] == "active" and s["role"] == "member", s
assert (k["key_version"], k["sealed_blob"], k["signature"], k["signer_device_id"]) == (1, sealed, sig, km), k
assert len(k["signer_sign_pubkey"]) == 44 and len(k["signer_enc_pubkey"]) == 44 and k["signer_name"] == "Kim", k
PY
pass "/join/status returns the sealed key, signature and the approver's public keys"
[ "$(expect 200 GET /keys "$AL_TOK" | j '["sealed_keys"][0]["key_version"]')" = 1 ] && pass "GET /keys"
expect 403 GET /joins/pending "$AL_TOK" >/dev/null && pass "member can't list pending joins (403)"

MAL=$(expect 201 POST /join "" "$(join_body Mal mal@x.test)")
MAL_TOK=$(echo "$MAL" | j '["token"]'); MAL_DEV=$(echo "$MAL" | j '["device_id"]')
expect 403 POST "/joins/$MAL_DEV/approve" "$AL_TOK" "$APPROVE" >/dev/null && pass "member can't approve (403)"
expect 200 POST "/joins/$MAL_DEV/deny" "$KM_TOK" >/dev/null && pass "Key Master denies a join"
[ "$(expect 200 GET /join/status "$MAL_TOK" | j '["status"]')" = denied ] && pass "/join/status -> denied"
expect 401 GET /events "$MAL_TOK" >/dev/null && pass "denied token can't read events"
expect 404 POST /joins/d_nope/deny "$KM_TOK" >/dev/null && pass "unknown device -> 404"

ROSTER=$(expect 200 GET /members "$AL_TOK")
[ "$(echo "$ROSTER" | j '["members"].__len__()')" = 2 ] && pass "GET /members lists Kim and Al only"

head -c 200000 /dev/urandom > "$TMP/blob"
MID=$(curl -sS --fail-with-body -H "Authorization: Bearer $AL_TOK" -H 'Content-Type: application/octet-stream' \
  --data-binary @"$TMP/blob" "$B/media" | j '["id"]')
curl -sS --fail-with-body -H "Authorization: Bearer $KM_TOK" -o "$TMP/blob.out" "$B/media/$MID"
cmp -s "$TMP/blob" "$TMP/blob.out" && pass "media round trip between devices ($MID)"
CT=$(head -c 100 /dev/urandom | base64 -w0)
SEQ=$(expect 201 POST /events "$AL_TOK" "{\"kind\":\"post\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"$SIG\",\"media_ids\":[\"$MID\"]}" | j '["seq"]')
pass "member posted event seq=$SEQ"
GOT=$(expect 200 GET "/events?after=0" "$KM_TOK")
python3 -c "import sys,json; e=json.loads(sys.argv[1])['events'][-1]; assert (e['seq'],e['ciphertext'],e['author_device_id'],e['media_ids'])==($SEQ,'$CT','$AL_DEV',['$MID']), e" "$GOT"
pass "Key Master pulled it, attributed to the member's device"
[ "$(expect 200 GET "/events?after=$SEQ" "$KM_TOK" | j '["events"]')" = "[]" ] && pass "?after=$SEQ is empty"
[ "$(expect 200 POST /ack "$KM_TOK" "{\"seq\":$SEQ}" | j '["last_seq"]')" = "$SEQ" ] && pass "acked seq=$SEQ"
echo "All smoke checks passed."
