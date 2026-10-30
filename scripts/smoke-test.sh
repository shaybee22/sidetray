#!/usr/bin/env bash
# Phase 1 smoke test: post an event, pull it back with ?after=, ack it,
# upload and download a media blob. Runs against the live Caddy HTTPS endpoint.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$TMP/root.crt"
B="https://$SIDETRAY_HOST/api/v1"
AUTH="Authorization: Bearer $SIDETRAY_TEST_TOKEN"
c() { curl -sS --fail-with-body --cacert "$TMP/root.crt" -H "$AUTH" "$@"; }
j() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
ok() { echo "PASS  $*"; }

code=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$TMP/root.crt" "$B/events")
[ "$code" = 401 ] && ok "no token -> 401" || { echo "FAIL no token -> $code"; exit 1; }

head -c 200000 /dev/urandom > "$TMP/blob"
MID=$(c -H 'Content-Type: application/octet-stream' --data-binary @"$TMP/blob" "$B/media" | j '["id"]')
c -o "$TMP/blob.out" "$B/media/$MID"
cmp -s "$TMP/blob" "$TMP/blob.out" && ok "media round-trip ($MID)"

START=$(c "$B/events?after=0&limit=500" | j '["last_seq"]')
while [ "$(c "$B/events?after=$START" | j '["has_more"]')" = True ]; do
  START=$(c "$B/events?after=$START" | j '["last_seq"]')
done
CT=$(printf 'smoke %s' "$(date +%s)" | base64)
SEQ=$(c -H 'Content-Type: application/json' \
  -d "{\"kind\":\"post\",\"key_version\":1,\"ciphertext\":\"$CT\",\"signature\":\"c2ln\",\"media_ids\":[\"$MID\"]}" \
  "$B/events" | j '["seq"]')
ok "posted event seq=$SEQ"

GOT=$(c "$B/events?after=$START" | j "['events'][-1]")
python3 -c "import sys,ast; e=ast.literal_eval(sys.argv[1]); assert e['seq']==$SEQ and e['ciphertext']=='$CT' and e['media_ids']==['$MID'], e" "$GOT"
ok "pulled seq=$SEQ back with ?after=$START"

[ "$(c "$B/events?after=$SEQ" | j '["events"]')" = "[]" ] && ok "?after=$SEQ is empty"

ACK=$(c -H 'Content-Type: application/json' -d "{\"seq\":$SEQ}" "$B/ack" | j '["last_seq"]')
[ "$ACK" = "$SEQ" ] && ok "acked seq=$SEQ"
echo "All Phase 1 checks passed."
