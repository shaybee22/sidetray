#!/usr/bin/env bash
# Side Tray relay installer, for a fresh Debian or Ubuntu server. Run as root:
#
#   sudo ./install.sh                     # from a checkout or release folder
#   curl -fsSL <release url>/install.sh | sudo SIDETRAY_SOURCE_URL=<release tarball> bash
#
# It asks how people will reach the server: a domain name (production: a
# Let's Encrypt certificate) or a LAN IP address (test mode: Caddy's own CA,
# which the app has to be given). Then it installs Docker Engine and the
# Compose plugin from Docker's apt repository if they're missing, writes
# /opt/sidetray (compose.yaml, Caddyfile, .env, server/), starts the stack,
# waits for it to answer over HTTPS and prints a setup token for the first
# group.
#
# It can also run a push server (ntfy) next to the relay, so the Android app
# gets instant notifications: asked during install (off unless you say yes),
# and asked again on a re-run of a server that hasn't decided yet.
#
# Safe to re-run: it updates the code and restarts the stack, keeps the data
# volumes and .env (only the settings you change are rewritten), keeps a .bak
# of any file it replaces, and issues a new setup token only when the server
# has no way to create a group yet, or when you pass --new-group.
#
# Options (each skips its question):
#   --domain NAME --email ADDRESS   production mode
#   --ip ADDRESS                    test mode
#   --retention DAYS                how long the relay keeps undelivered posts (default 90)
#   --push / --no-push              run the push server for Android notifications, or not
#   --new-group                     also issue a fresh setup token for another group
#   --yes                           don't ask; keep existing settings, take defaults
set -euo pipefail

DIR=${SIDETRAY_DIR:-/opt/sidetray}
ADMIN_BIN=/usr/local/bin/sidetray-admin

say()  { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }

DOMAIN="" EMAIL="" IP="" RETENTION="" NEW_GROUP=0 YES=0 MODE="" PUSH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=${2:?--domain needs a name}; MODE=production; shift 2 ;;
    --email) EMAIL=${2:?--email needs an address}; shift 2 ;;
    --ip) IP=${2:?--ip needs an address}; MODE=test; shift 2 ;;
    --retention) RETENTION=${2:?--retention needs a number of days}; shift 2 ;;
    --new-group) NEW_GROUP=1; shift ;;
    --push) PUSH=yes; shift ;;
    --no-push) PUSH=no; shift ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'Unknown option: %s\n\n' "$1" >&2; usage 2 ;;
  esac
done
[ -n "$DOMAIN" ] && [ -n "$IP" ] && die "pass either --domain or --ip, not both"

# --- prompts (from the terminal, so this also works piped from curl) ----------

if [ "$YES" = 0 ] && { exec 3</dev/tty; } 2>/dev/null; then TTY=1; else TTY=0; fi

# ask VAR "question" [default]
ask() {
  local __var=$1 q=$2 def=${3:-} ans
  if [ "$TTY" = 0 ]; then
    [ -n "$def" ] || die "no answer for \"$q\" (no terminal to ask on; see --help for options)"
    printf -v "$__var" '%s' "$def"; return
  fi
  if [ -n "$def" ]; then printf '%s [%s]: ' "$q" "$def"; else printf '%s: ' "$q"; fi
  IFS= read -r ans <&3 || die "no answer"
  ans=$(printf '%s' "$ans" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  printf -v "$__var" '%s' "${ans:-$def}"
}

# yes_no "question" default(y|n)
yes_no() {
  local a
  ask a "$1 (y/n)" "$2"
  case "$a" in [yY]*) return 0 ;; [nN]*) return 1 ;; *) yes_no "$1" "$2" ;; esac
}

valid_ipv4() {
  local IFS=. o; local -a p
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  read -ra p <<<"$1"
  for o in "${p[@]}"; do [ "$o" -le 255 ] || return 1; done
}
valid_domain() { [[ $1 =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$ ]]; }
valid_email() { [[ $1 =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
valid_days() { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 3650 ]; }

DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')
[ -z "$DOMAIN" ] || valid_domain "$DOMAIN" || die "--domain: \"$DOMAIN\" isn't a domain name (like tray.example.org)"
[ -z "$EMAIL" ] || valid_email "$EMAIL" || die "--email: \"$EMAIL\" doesn't look like an email address"
[ -z "$IP" ] || valid_ipv4 "$IP" || die "--ip: \"$IP\" isn't an IPv4 address"
[ -z "$RETENTION" ] || valid_days "$RETENTION" || die "--retention must be a whole number of days from 1 to 3650"

# env_get KEY: the value in $DIR/.env, or empty.
env_get() {
  [ -f "$DIR/.env" ] || return 0
  sed -n "s/^$1=//p" "$DIR/.env" | tail -1 | sed 's/^"\(.*\)"$/\1/'
}

# --- checks -------------------------------------------------------------------

[ "$(id -u)" = 0 ] || die "run this as root (sudo $0)"
command -v apt-get >/dev/null || die "this installer is for Debian or Ubuntu (apt-get not found)"
. /etc/os-release
case "$ID ${ID_LIKE:-}" in
  *ubuntu*) DOCKER_DIST=ubuntu; DOCKER_FALLBACK=noble ;;
  *debian*) DOCKER_DIST=debian; DOCKER_FALLBACK=bookworm ;;
  *) die "this installer is for Debian or Ubuntu (found $PRETTY_NAME)" ;;
esac

# Where the relay's code comes from: next to this script, or a release tarball.
SRC=""
HERE=$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || true)
if [ -n "$HERE" ] && [ -f "$HERE/compose.yaml" ] && [ -f "$HERE/server/Dockerfile" ]; then
  SRC=$HERE
elif [ -n "${SIDETRAY_SOURCE_URL:-}" ]; then
  command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; }
  FETCH=$(mktemp -d)
  trap 'rm -rf "$FETCH"' EXIT
  step "Downloading $SIDETRAY_SOURCE_URL"
  curl -fsSL "$SIDETRAY_SOURCE_URL" | tar -xz -C "$FETCH" || die "couldn't download or unpack $SIDETRAY_SOURCE_URL"
  SRC=$(dirname "$(find "$FETCH" -path '*/server/Dockerfile' | head -1)")
  SRC=$(dirname "$SRC")
  [ -f "$SRC/compose.yaml" ] || die "$SIDETRAY_SOURCE_URL doesn't look like a Side Tray release (no compose.yaml)"
else
  die "run this from a Side Tray checkout or release folder (it needs compose.yaml and server/ next to it), or set SIDETRAY_SOURCE_URL to a release tarball"
fi

# --- settings -----------------------------------------------------------------

OLD_HOST=$(env_get SIDETRAY_HOST)
OLD_MODE=$(env_get SIDETRAY_MODE)
OLD_EMAIL=$(env_get SIDETRAY_ACME_EMAIL)
OLD_RETENTION=$(env_get SIDETRAY_RETENTION_DAYS)
OLD_PUSH=$(env_get SIDETRAY_PUSH)
NTFY_PORT=$(env_get SIDETRAY_NTFY_PORT); NTFY_PORT=${NTFY_PORT:-8443}
if [ -n "$OLD_HOST" ] && [ -z "$OLD_MODE" ]; then
  if valid_ipv4 "$OLD_HOST"; then OLD_MODE=test; else OLD_MODE=production; fi
fi

say "Side Tray relay installer ($PRETTY_NAME)"
KEEP=0
if [ -n "$OLD_HOST" ] && [ -z "$MODE" ]; then
  say ""
  say "Found an existing install in $DIR:"
  say "  address:   https://$OLD_HOST ($OLD_MODE mode)"
  [ "$OLD_MODE" = production ] && say "  email:     ${OLD_EMAIL:-none}"
  say "  retention: ${OLD_RETENTION:-90} days"
  say "  push:      ${OLD_PUSH:-not set up} (Android notifications through ntfy)"
  if yes_no "Keep these settings?" y; then KEEP=1; fi
fi

if [ "$KEEP" = 1 ]; then
  MODE=$OLD_MODE
  if [ "$MODE" = production ]; then DOMAIN=$OLD_HOST; EMAIL=${EMAIL:-$OLD_EMAIL}; else IP=$OLD_HOST; fi
  RETENTION=${RETENTION:-${OLD_RETENTION:-90}}
else
  if [ -z "$MODE" ]; then
    say ""
    say "How will people reach this server?"
    say "  1) A domain name, e.g. tray.example.org (production: a free Let's Encrypt certificate)"
    say "  2) A LAN IP address (test mode: Caddy's own certificate authority; each app needs its root)"
    def=1; [ "$OLD_MODE" = test ] && def=2
    [ "$TTY" = 0 ] && [ -z "$OLD_MODE" ] && die "pass --domain NAME --email ADDRESS, or --ip ADDRESS (no terminal to ask on)"
    while :; do
      ask choice "Choose 1 or 2" "$def"
      case "$choice" in 1) MODE=production; break ;; 2) MODE=test; break ;; esac
    done
  fi
  if [ "$MODE" = production ]; then
    [ "$OLD_MODE" = production ] && def=$OLD_HOST || def=""
    while [ -z "$DOMAIN" ] || ! valid_domain "$DOMAIN"; do
      [ -n "$DOMAIN" ] && say "\"$DOMAIN\" isn't a domain name (lowercase, like tray.example.org)."
      ask DOMAIN "Domain name" "$def"
      DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')
    done
    while [ -z "$EMAIL" ] || ! valid_email "$EMAIL"; do
      [ -n "$EMAIL" ] && say "\"$EMAIL\" doesn't look like an email address."
      ask EMAIL "Email for Let's Encrypt (certificate expiry notices)" "$OLD_EMAIL"
    done
  else
    def=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1 || true)
    [ "$OLD_MODE" = test ] && def=$OLD_HOST
    while [ -z "$IP" ] || ! valid_ipv4 "$IP"; do
      [ -n "$IP" ] && say "\"$IP\" isn't an IPv4 address."
      ask IP "This server's LAN IP address" "$def"
    done
  fi
  while [ -z "$RETENTION" ] || ! valid_days "$RETENTION"; do
    [ -n "$RETENTION" ] && say "Enter a whole number of days from 1 to 3650."
    ask RETENTION "Days to keep posts that not every device has fetched yet" "${OLD_RETENTION:-90}"
  done
fi
# Push server: a flag decides; otherwise keep what .env says; otherwise ask
# (default no). With --yes and nothing decided yet, it stays off.
if [ -z "$PUSH" ]; then
  if [ -n "$OLD_PUSH" ]; then
    PUSH=$OLD_PUSH
  elif [ "$TTY" = 1 ]; then
    say ""
    say "Side Tray's Android app can get instant notifications through a small push"
    say "server (ntfy) running next to the relay, on port $NTFY_PORT. It only carries empty"
    say "wake-ups; phones then fetch the encrypted posts themselves. Without it, phones"
    say "check for new posts about every 15 minutes."
    if yes_no "Run the push server?" n; then PUSH=yes; else PUSH=no; fi
  else
    PUSH=no
  fi
fi
case "$PUSH" in yes|no) ;; *) PUSH=no ;; esac

valid_days "$RETENTION" || die "--retention must be a whole number of days from 1 to 3650"
if [ "$MODE" = production ]; then
  valid_domain "$DOMAIN" || die "\"$DOMAIN\" isn't a domain name"
  valid_email "$EMAIL" || die "production mode needs an email address for Let's Encrypt (--email)"
  HOST=$DOMAIN
else
  valid_ipv4 "$IP" || die "\"$IP\" isn't an IPv4 address"
  HOST=$IP
fi

compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yaml" "$@"; }
stack_running() {
  command -v docker >/dev/null && [ -f "$DIR/compose.yaml" ] \
    && [ -n "$(compose ps -q --status running caddy 2>/dev/null)" ]
}

# --- network checks -----------------------------------------------------------

step "Checking the network"
if stack_running; then
  say "Ports 80 and 443: in use by this Side Tray install (it will be restarted)."
else
  busy=$(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null || true)
  if [ -n "$busy" ]; then
    say "$busy"
    die "ports 80 and 443 must be free for Caddy, but something is listening (above). Stop it (for example: systemctl disable --now apache2 nginx) and run this again."
  fi
  say "Ports 80 and 443: free."
fi

my_ips=$(ip -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|veth)/ {print $4}' | cut -d/ -f1 | sort -u)
if [ "$MODE" = production ]; then
  resolved=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u || true)
  [ -n "$resolved" ] || die "$DOMAIN doesn't resolve. At your DNS provider, add an A record (and AAAA for IPv6) for $DOMAIN pointing at this server's public address, wait a few minutes, and run this again."
  public=$( { curl -4 -fsS -m 5 https://api.ipify.org 2>/dev/null; echo; curl -6 -fsS -m 5 https://api6.ipify.org 2>/dev/null; echo; } | grep . || true)
  mine=$(printf '%s\n%s\n' "$my_ips" "$public" | grep . | sort -u)
  if printf '%s\n' "$resolved" | grep -qxF -f <(printf '%s\n' "$mine"); then
    say "DNS: $DOMAIN -> $(echo $resolved) (this server)."
  else
    warn "$DOMAIN points at $(echo $resolved), but this server's addresses are: $(echo $mine)."
    say "Let's Encrypt checks the domain by connecting to it on ports 80 and 443, so the A/AAAA"
    say "records must point here (or at a router forwarding those ports here)."
    [ "$TTY" = 1 ] || die "fix the DNS record for $DOMAIN and run this again"
    yes_no "Continue anyway?" n || die "fix the DNS record for $DOMAIN and run this again"
  fi
else
  if printf '%s\n' "$my_ips" | grep -qxF "$IP"; then
    say "Address: $IP is on this server."
  else
    warn "$IP isn't one of this server's addresses ($(echo $my_ips)). Clients must still reach it there."
  fi
fi

# --- Docker -------------------------------------------------------------------

step "Docker"
if command -v docker >/dev/null; then
  docker compose version >/dev/null 2>&1 \
    || die "Docker is installed but the Compose plugin isn't. Install docker-compose-plugin (https://docs.docker.com/compose/install/linux/) and run this again."
  say "Already installed: $(docker --version)"
else
  say "Installing Docker Engine and the Compose plugin from Docker's apt repository..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$DOCKER_DIST/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  suite=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
  if [ "$DOCKER_DIST" = debian ]; then suite=${VERSION_CODENAME:-}; fi
  if [ -z "$suite" ] || ! curl -fsI "https://download.docker.com/linux/$DOCKER_DIST/dists/$suite/Release" >/dev/null 2>&1; then
    warn "Docker has no packages for '${suite:-this release}' yet; using $DOCKER_FALLBACK's."
    suite=$DOCKER_FALLBACK
  fi
  cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$DOCKER_DIST
Suites: $suite
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  systemctl enable --now docker >/dev/null 2>&1 || true
  say "Installed: $(docker --version)"
fi

# --- files --------------------------------------------------------------------

step "Writing $DIR"
install -d -m 755 "$DIR"

# put FILE < content: replace FILE, keeping the old one as FILE.bak if it changes.
put() {
  local f=$1 new; new=$(mktemp)
  cat >"$new"
  if [ -f "$f" ] && cmp -s "$f" "$new"; then rm -f "$new"; return; fi
  if [ -f "$f" ]; then
    local bak="$f.bak"; [ -e "$bak" ] && bak="$f.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "$f" "$bak"; say "  kept the previous $(basename "$f") as $(basename "$bak")"
  fi
  chmod 644 "$new"; mv "$new" "$f"
}

if [ "$SRC" != "$DIR" ]; then
  put "$DIR/compose.yaml" <"$SRC/compose.yaml"
  rm -rf "$DIR/server.new"
  cp -R "$SRC/server" "$DIR/server.new"
  rm -rf "$DIR/server"
  mv "$DIR/server.new" "$DIR/server"
  [ -f "$SRC/install.sh" ] && put "$DIR/install.sh" <"$SRC/install.sh" && chmod 755 "$DIR/install.sh"
fi

caddy_site() {
  cat <<'EOF'
	request_body {
		max_size 12MB
	}

	handle /api/* {
		reverse_proxy api:8000
	}

	handle {
		respond "Side Tray relay" 200
	}
}
EOF
}
# The push server's site, on its own port of the same address. In test mode it
# has its own long-lived self-signed certificate: the ntfy app pins the exact
# certificate it was shown, and Caddy's own test certificates change every
# few hours.
ntfy_site() {
  [ "$PUSH" = yes ] || return 0
  printf '\n# Push server for the Android app (ntfy), when install.sh was told to run it.\n'
  printf '{$SIDETRAY_HOST}:{$SIDETRAY_NTFY_PORT} {\n'
  if [ "$MODE" = test ]; then
    printf '\ttls /etc/caddy/ntfy-tls/cert.pem /etc/caddy/ntfy-tls/key.pem\n'
  fi
  printf '\treverse_proxy ntfy:80\n}\n'
}
caddyfile_before=""
[ -f "$DIR/Caddyfile" ] && caddyfile_before=$(sha256sum <"$DIR/Caddyfile")
if [ "$MODE" = production ]; then
  { cat <<'EOF'
# Written by install.sh (production mode). Re-running it rewrites this file and keeps a .bak.
{
	# Let's Encrypt account: certificate expiry notices go here.
	email {$SIDETRAY_ACME_EMAIL}
}

{$SIDETRAY_HOST} {
EOF
    caddy_site; ntfy_site; } | put "$DIR/Caddyfile"
else
  { cat <<'EOF'
# Written by install.sh (test mode). Re-running it rewrites this file and keeps a .bak.
{
	# Clients connecting by bare IP send no SNI; serve this host's cert to them.
	default_sni {$SIDETRAY_HOST}
}

{$SIDETRAY_HOST} {
	# No domain: Caddy's own local CA. Apps pin its root certificate after the
	# person confirms its fingerprint (the one printed at the end of install.sh).
	tls internal

	# Test mode: Caddy's root certificate (public; never the key), so the app can
	# show its fingerprint for the person to compare with what install.sh printed.
	handle /sidetray-root.crt {
		root * /data/caddy/pki/authorities/local
		rewrite * /root.crt
		file_server
	}

EOF
    caddy_site; ntfy_site; } | put "$DIR/Caddyfile"
fi

# Test mode with push: the ntfy port's certificate, made once (10 years) and
# remade only if the server's address changed.
install -d -m 755 "$DIR/ntfy-tls"
if [ "$PUSH" = yes ] && [ "$MODE" = test ]; then
  cert="$DIR/ntfy-tls/cert.pem"
  if [ ! -s "$cert" ] || ! openssl x509 -noout -checkip "$IP" -in "$cert" 2>/dev/null | grep -q 'does match'; then
    (umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj "/CN=Side Tray push $IP" -addext "subjectAltName=IP:$IP" \
      -keyout "$DIR/ntfy-tls/key.pem" -out "$cert" 2>/dev/null) || die "couldn't make the push server's certificate (is openssl installed?)"
    chmod 644 "$cert"
    say "  made a certificate for the push server ($IP, valid 10 years)"
  fi
fi

# Push settings in .env: the compose profile that starts ntfy, and where the
# relay sends wake-ups.
push_env() {
  env_set SIDETRAY_PUSH "$PUSH"
  if [ "$PUSH" = yes ]; then
    env_set COMPOSE_PROFILES push
    env_set SIDETRAY_NTFY_PORT "$NTFY_PORT"
    env_set SIDETRAY_NTFY_URL "https://$HOST:$NTFY_PORT"
    env_set SIDETRAY_NTFY_INTERNAL "http://ntfy"
  else
    env_set COMPOSE_PROFILES ""
    env_set SIDETRAY_NTFY_URL ""
    env_set SIDETRAY_NTFY_INTERNAL ""
  fi
}

# .env: a new one, or only the settings that changed. The setup token and
# anything else in an existing .env are left alone.
env_set() {
  local k=$1 v=$2
  [ "$(env_get "$k")" = "$v" ] && grep -q "^$k=" "$DIR/.env" && return
  [ -n "${NEW_ENV:-}" ] || [ -e "$DIR/.env.bak" ] || cp -p "$DIR/.env" "$DIR/.env.bak"
  if grep -q "^$k=" "$DIR/.env"; then
    local tmp; tmp=$(mktemp)
    awk -v k="$k" -v v="$v" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$DIR/.env" >"$tmp"
    cat "$tmp" >"$DIR/.env"; rm -f "$tmp"
  else
    printf '%s=%s\n' "$k" "$v" >>"$DIR/.env"
  fi
  [ -n "${NEW_ENV:-}" ] || say "  .env: $k=$v"
}
if [ ! -f "$DIR/.env" ]; then
  (umask 077; cat >"$DIR/.env" <<EOF
# Side Tray relay settings, written by install.sh. Re-running it keeps this file.
# production (a domain, Let's Encrypt) or test (a LAN IP, Caddy's own CA).
SIDETRAY_MODE=$MODE
# Address clients use to reach the relay.
SIDETRAY_HOST=$HOST
# Let's Encrypt account email (production mode).
SIDETRAY_ACME_EMAIL=$EMAIL
# Days to keep events and photos that not every device has fetched yet.
# Anything every active device has acked is deleted sooner, by the hourly prune job.
SIDETRAY_RETENTION_DAYS=$RETENTION
# Optional: a secret that lets the first device create the server's first group.
# install.sh leaves it empty and issues a one-time token instead
# (sudo sidetray-admin new-group).
SIDETRAY_SETUP_TOKEN=
EOF
  )
  NEW_ENV=1 push_env
  say "  wrote .env"
else
  env_set SIDETRAY_MODE "$MODE"
  env_set SIDETRAY_HOST "$HOST"
  env_set SIDETRAY_ACME_EMAIL "$EMAIL"
  env_set SIDETRAY_RETENTION_DAYS "$RETENTION"
  push_env
  chmod 600 "$DIR/.env"
  say "  kept .env (setup token and other settings untouched)"
fi

cat >"$ADMIN_BIN" <<EOF
#!/bin/sh
# Installed by Side Tray's install.sh: operator commands, run in the relay's container.
# sidetray-admin new-group | list-groups | prune   (sidetray-admin -h for details)
exec docker compose --project-directory "$DIR" -f "$DIR/compose.yaml" exec -T api sidetray-admin "\$@"
EOF
chmod 755 "$ADMIN_BIN"

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null && say "  ufw: allowed ports 80 and 443"
  if [ "$PUSH" = yes ]; then
    ufw allow "$NTFY_PORT/tcp" >/dev/null && say "  ufw: allowed port $NTFY_PORT (push server)"
  fi
fi

# --- start --------------------------------------------------------------------

step "Building and starting the relay (the first build takes a minute or two)"
compose up -d --build --remove-orphans
if [ "$PUSH" = no ] && [ -n "$(docker ps -aq --filter label=com.docker.compose.project=sidetray --filter label=com.docker.compose.service=ntfy)" ]; then
  say "  push is off: removing the push server's container (its volumes are kept)"
  docker rm -f $(docker ps -aq --filter label=com.docker.compose.project=sidetray --filter label=com.docker.compose.service=ntfy) >/dev/null
fi
# The Caddyfile is bind-mounted as a single file, and put() replaces it, so a
# running Caddy still sees the old one: restart it when the file changed.
if [ -n "$caddyfile_before" ] && [ "$caddyfile_before" != "$(sha256sum <"$DIR/Caddyfile")" ]; then
  say "  the Caddyfile changed: restarting Caddy"
  compose restart caddy >/dev/null
fi

step "Waiting for https://$HOST/api/v1/health"
ok=0
if [ "$MODE" = test ]; then
  for _ in $(seq 60); do
    if compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$DIR/sidetray-root.crt.new" 2>/dev/null \
       && [ -s "$DIR/sidetray-root.crt.new" ] \
       && curl -fsS -m 5 --cacert "$DIR/sidetray-root.crt.new" "https://$HOST/api/v1/health" >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 2
  done
  if [ -s "$DIR/sidetray-root.crt.new" ]; then mv "$DIR/sidetray-root.crt.new" "$DIR/sidetray-root.crt"; else rm -f "$DIR/sidetray-root.crt.new"; fi
else
  for _ in $(seq 90); do
    curl -fsS -m 5 "https://$HOST/api/v1/health" >/dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
fi
if [ "$ok" = 0 ]; then
  compose ps
  compose logs --tail 30 caddy api || true
  if [ "$MODE" = production ]; then
    die "the relay didn't answer over a trusted certificate within 3 minutes. Caddy's log is above. Usually: the domain's A/AAAA record doesn't point here yet, or ports 80/443 aren't reachable from the internet (a cloud firewall or router). Fix that and run this again; your settings are kept."
  fi
  die "the relay didn't answer on https://$HOST within 2 minutes; the logs are above."
fi
say "The relay is answering over HTTPS."

if [ "$PUSH" = yes ]; then
  step "Waiting for the push server at https://$HOST:$NTFY_PORT"
  pok=0
  for _ in $(seq 30); do
    if [ "$MODE" = test ]; then
      curl -fsS -m 5 --cacert "$DIR/ntfy-tls/cert.pem" "https://$HOST:$NTFY_PORT/v1/health" >/dev/null 2>&1 && { pok=1; break; }
    else
      curl -fsS -m 5 "https://$HOST:$NTFY_PORT/v1/health" >/dev/null 2>&1 && { pok=1; break; }
    fi
    sleep 2
  done
  if [ "$pok" = 1 ]; then
    say "The push server is answering."
  else
    compose logs --tail 20 ntfy || true
    warn "the push server didn't answer on https://$HOST:$NTFY_PORT within a minute (logs above). Phones fall back to checking every 15 minutes. If a firewall in front of this server blocks port $NTFY_PORT, open it."
  fi
fi

# --- setup token --------------------------------------------------------------

status=$("$ADMIN_BIN" setup-status)
groups=$(printf '%s' "$status" | sed -n 's/.*groups=\([0-9]*\).*/\1/p')
tokens=$(printf '%s' "$status" | sed -n 's/.*tokens=\([0-9]*\).*/\1/p')
env_token=$(printf '%s' "$status" | sed -n 's/.*env_token=\([a-z]*\).*/\1/p')
TOKEN_OUT=""
if [ "$NEW_GROUP" = 1 ] || { [ "$groups" = 0 ] && [ "$tokens" = 0 ] && [ "$env_token" = no ]; }; then
  TOKEN_OUT=$("$ADMIN_BIN" new-group)
fi

# --- summary ------------------------------------------------------------------

step "Done"
say "Side Tray relay: https://$HOST"
if [ "$MODE" = production ]; then
  say "Certificate:     Let's Encrypt (renewed automatically; notices to $EMAIL)"
else
  say "Mode:            TEST (Caddy's own certificate authority)"
  say "Root certificate: $DIR/sidetray-root.crt"
  command -v openssl >/dev/null && say "                 $(openssl x509 -noout -fingerprint -sha256 -in "$DIR/sidetray-root.crt" | sed 's/^.*Fingerprint=/SHA-256 /')"
  say "                 The app shows this fingerprint when someone first connects; it must match."
fi
say "Retention:       $RETENTION days"
if [ "$PUSH" = yes ]; then
  say "Push server:     https://$HOST:$NTFY_PORT (ntfy; Android phones set it as ntfy's default server)"
  if [ "$MODE" = test ] && command -v openssl >/dev/null; then
    say "                 its certificate: $(openssl x509 -noout -fingerprint -sha256 -in "$DIR/ntfy-tls/cert.pem" | sed 's/^.*Fingerprint=/SHA-256 /')"
    say "                 The ntfy app shows this when it first connects; it must match."
  fi
else
  say "Push server:     off (Android phones check every 15 minutes; re-run with --push to turn it on)"
fi
say "Settings:        $DIR/.env, $DIR/Caddyfile; data in Docker volumes sidetray_api_data and sidetray_caddy_data"
say "Admin:           sudo sidetray-admin new-group | list-groups | prune"
say ""
if [ -n "$TOKEN_OUT" ]; then
  say "$TOKEN_OUT"
  say ""
  say "In the Side Tray app's first-run wizard: server https://$HOST, the group's name,"
  say "your name and email, and this token. You become the group's first Key Master."
elif [ "$groups" != 0 ]; then
  say "This server has $groups group(s). For another one: sudo sidetray-admin new-group"
else
  say "No group yet, and a way to create one already exists (an unused setup token issued"
  say "earlier, or SIDETRAY_SETUP_TOKEN in .env). Lost it? sudo sidetray-admin new-group"
fi
