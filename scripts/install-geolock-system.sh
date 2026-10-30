#!/usr/bin/env bash
# Move the boot-time geolock out of the user's home and make its failure visible.
#
# Today vaultos-country-block.service runs the geolock from a user-owned
# checkout with ExecStartPost=-...: anything that can write that checkout runs
# as root at boot, and a failed geolock is silently ignored. This installs a
# root-owned copy and points the unit at it with a drop-in:
#
#   /usr/local/lib/home-dns/{geolock,scripts/,lib/,go/bin/}  root:root 0755
#   /etc/home-dns/geolock.env           settings (copied unchanged from the live ones)
#   /etc/home-dns/geolock.service.env   cache path, Tailscale underlay, app cgroup
#   /var/lib/home-dns/geolock/          list cache (seeded from the live cache)
#   /etc/systemd/system/vaultos-country-block.service.d/10-home-dns-geolock.conf
#       ExecStartPost=                                  (clears the old "-" entry)
#       ExecStartPost=/usr/local/lib/home-dns/geolock   (failure now fails the unit)
#
# Nothing is installed unless the new copy renders a ruleset byte-identical to
# the live geolock.nft (same countries, mode, ports, IPv4/IPv6 and directions).
# It only runs `systemctl daemon-reload`: no restart, no firewall change, and
# the geolock table loaded now is left alone. The next boot uses the new copy.
#
#   scripts/install-geolock-system.sh --dry-run      show the plan and run the identity check (no root)
#   pkexec /path/to/scripts/install-geolock-system.sh          install (backs up first)
#   pkexec /path/to/scripts/install-geolock-system.sh --rollback [BACKUP_DIR]
#
# Needs go/bin/geolock-apply built in this checkout:
#   (cd go && go build -trimpath -o bin/geolock-apply ./cmd/geolock-apply)
#
# INSTALL_SYSROOT=/tmp/x runs against a fake root for testing (no chown, no systemctl).
set -Eeuo pipefail
umask 022

UNIT=vaultos-country-block.service
SYSROOT="${INSTALL_SYSROOT:-}"
SYSROOT="${SYSROOT%/}"
DEST=/usr/local/lib/home-dns
ETC=/etc/home-dns
STATE=/var/lib/home-dns/geolock
UNIT_FILE=/etc/systemd/system/$UNIT
DROPIN_DIR=/etc/systemd/system/$UNIT.d
DROPIN=$DROPIN_DIR/10-home-dns-geolock.conf
BACKUPS=/var/backups
WRAPPER=$DEST/geolock
MANAGED=("$DEST" "$ETC" "$STATE" "$DROPIN")

REPO="$(cd "$(dirname "$0")/.." && pwd)"
MODE=install
ROLLBACK_DIR=
case "${1:-}" in
  "") ;;
  --dry-run|-n) MODE=dry ;;
  --rollback) MODE=rollback; ROLLBACK_DIR="${2:-}" ;;
  -h|--help) sed -n '2,/^set -E/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
  *) echo "usage: $0 [--dry-run | --rollback [BACKUP_DIR]]" >&2; exit 2 ;;
esac

say() { echo "install-geolock: $*"; }
die() { echo "install-geolock: ERROR $*" >&2; exit 1; }
p() { printf '%s%s' "$SYSROOT" "$1"; }   # path on the (possibly fake) root
run() {
  if [[ "$MODE" == dry ]]; then
    printf 'would run:'; printf ' %q' "$@"; echo
  else
    "$@"
  fi
}
own() { [[ -z "$SYSROOT" && "$MODE" != dry ]] && chown -R root:root "$@"; return 0; }

if [[ "$MODE" != dry && -z "$SYSROOT" && "$(id -u)" -ne 0 ]]; then
  die "needs root (use --dry-run to preview without root)"
fi

# Effective ExecStartPost list of the unit from its files: the unit, then
# drop-ins in name order; an empty assignment clears the list.
exec_start_post() {
  local f line
  local -a out=()
  for f in "$(p "$UNIT_FILE")" "$(p "$DROPIN_DIR")"/*.conf; do
    [[ -f "$f" ]] || continue
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ "$line" =~ ^[[:space:]]*ExecStartPost=(.*)$ ]] || continue
      if [[ -z "${BASH_REMATCH[1]}" ]]; then out=(); else out+=("${BASH_REMATCH[1]}"); fi
    done < "$f"
  done
  printf '%s\n' "${out[@]}"
}

# ---------------------------------------------------------------- rollback
if [[ "$MODE" == rollback ]]; then
  if [[ -z "$ROLLBACK_DIR" ]]; then
    ROLLBACK_DIR="$(find "$(p "$BACKUPS")" -maxdepth 1 -type d -name 'home-dns-geolock-*' 2>/dev/null | sort | tail -n1)"
    [[ -n "$ROLLBACK_DIR" ]] || die "no backups in $(p "$BACKUPS")/home-dns-geolock-*"
  fi
  [[ -f "$ROLLBACK_DIR/manifest" ]] || die "$ROLLBACK_DIR/manifest not found"
  say "rolling back from $ROLLBACK_DIR"
  while read -r state path; do
    case "$state" in present|absent) ;; *) continue ;; esac
    ok=0; for m in "${MANAGED[@]}"; do [[ "$path" == "$m" ]] && ok=1; done
    [[ $ok -eq 1 ]] || die "manifest names a path this script does not manage: $path"
    rm -rf -- "$(p "$path")"
    say "removed $path"
  done < "$ROLLBACK_DIR/manifest"
  if [[ -s "$ROLLBACK_DIR/files.tar" ]]; then
    tar -C "$(p /)" -xpf "$ROLLBACK_DIR/files.tar"
    say "restored: $(tar -tf "$ROLLBACK_DIR/files.tar" | grep -c .) entries"
  fi
  rmdir "$(p "$DROPIN_DIR")" "$(p /var/lib/home-dns)" 2>/dev/null || true
  [[ -z "$SYSROOT" ]] && systemctl daemon-reload
  want="$(sed -n 's/^execstartpost //p' "$ROLLBACK_DIR/manifest")"
  got="$(exec_start_post | paste -sd '|')"
  [[ "$got" == "$want" ]] || die "after rollback ExecStartPost is '$got', expected '$want'"
  say "rollback done; ExecStartPost=$got (no restart; next boot uses it)"
  exit 0
fi

# ---------------------------------------------------------------- checks
[[ -f "$(p "$UNIT_FILE")" ]] || die "$UNIT_FILE not found"
mapfile -t posts < <(exec_start_post)
geo=()
for e in "${posts[@]}"; do [[ "$e" == *geolock* ]] && geo+=("$e"); done
[[ ${#geo[@]} -eq 1 ]] || die "expected one geolock ExecStartPost in $UNIT, found ${#geo[@]}"
cur="${geo[0]}"
cur_path="$(sed -E 's/^[-@:+!]+//; s/[[:space:]].*//' <<<"$cur")"
say "current: ExecStartPost=$cur"

if [[ "$cur_path" == "$WRAPPER" ]]; then
  say "already installed; checking the update against the installed settings"
  LIVE_SETTINGS="$(p "$ETC")/geolock.env"
  LIVE_CACHE="$(p "$STATE")"
else
  [[ "$cur_path" == */scripts/geolock-apply.sh ]] || die "unexpected geolock command: $cur_path"
  live_root="$(dirname "$(dirname "$cur_path")")"
  LIVE_SETTINGS="$live_root/geolock/settings.env"
  LIVE_CACHE="$live_root/geolock/cache"
fi
LIVE_NFT="$LIVE_CACHE/geolock.nft"
[[ -r "$LIVE_SETTINGS" ]] || die "cannot read live settings $LIVE_SETTINGS"
[[ -r "$LIVE_NFT" ]] || die "cannot read live ruleset $LIVE_NFT"
for f in scripts/geolock-apply.sh lib/cidr.sh go/bin/geolock-apply; do
  [[ -f "$REPO/$f" ]] || die "$REPO/$f missing (build: cd go && go build -trimpath -o bin/geolock-apply ./cmd/geolock-apply)"
done

# Boot-time inputs the live file was built with.
underlay=0
grep -q 'comment "tailscale underlay"' "$LIVE_NFT" && underlay=1
mapfile -t cgs < <(grep -o 'socket cgroupv2 level [0-9]* "[^"]*"' "$LIVE_NFT" \
  | sed 's/.*"\(.*\)"/\1/' | grep -vx 'system.slice/tailscaled.service' | sort -u)
[[ ${#cgs[@]} -le 1 ]] || die "more than one app cgroup in $LIVE_NFT"
appcg="${cgs[0]:-}"
say "live ruleset: $LIVE_NFT ($(sha256sum < "$LIVE_NFT" | cut -c1-12)…)"
say "derived: GEOLOCK_TAILSCALE_UNDERLAY=$underlay GEOLOCK_APP_CGROUP=${appcg:-<none>}"

# ---------------------------------------------------------------- stage + identity gate
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/tree/scripts" "$stage/tree/lib" "$stage/tree/go/bin" "$stage/cache"
cp "$REPO/scripts/geolock-apply.sh" "$stage/tree/scripts/"
cp "$REPO/lib/cidr.sh" "$stage/tree/lib/"
cp "$REPO/go/bin/geolock-apply" "$stage/tree/go/bin/"
cat > "$stage/tree/geolock" <<'EOF'
#!/usr/bin/env bash
# Boot/manual entry point for the root-owned geolock (installed by
# scripts/install-geolock-system.sh). Reads KEY=value pairs from the service
# env file (nothing in it is executed), then runs the geolock.
set -euo pipefail
envf="${HOME_DNS_GEOLOCK_ENV:-/etc/home-dns/geolock.service.env}"
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^(GEOLOCK_(SETTINGS|CACHE|TAILSCALE_UNDERLAY|APP_CGROUP))=([A-Za-z0-9@._/:-]*)$ ]] \
    && export "${BASH_REMATCH[1]}=${BASH_REMATCH[3]}"
done < "$envf"
exec "$(dirname "$(readlink -f "$0")")/scripts/geolock-apply.sh" "$@"
EOF
chmod 0755 "$stage/tree/geolock" "$stage/tree/scripts/geolock-apply.sh" "$stage/tree/go/bin/geolock-apply"
chmod 0644 "$stage/tree/lib/cidr.sh"
# Cache: per-country lists only (old upper-case files are not used).
find "$LIVE_CACHE" -maxdepth 1 -type f -regextype posix-extended -regex '.*/[a-z]{2}\.v[46]' \
  -exec cp -p {} "$stage/cache/" \;
cp "$LIVE_SETTINGS" "$stage/settings.env"
{
  echo "GEOLOCK_SETTINGS=$ETC/geolock.env"
  echo "GEOLOCK_CACHE=$STATE"
  echo "GEOLOCK_TAILSCALE_UNDERLAY=$underlay"
  [[ -n "$appcg" ]] && echo "GEOLOCK_APP_CGROUP=$appcg"
} > "$stage/service.env"

# Render with the staged copy exactly as boot would, but from the cached lists
# only (no downloads) and with nft -c instead of a load.
gate() {
  local label="$1"; shift
  local c="$stage/gate-$label"
  rm -rf "$c"; cp -a "$stage/cache" "$c"
  { cat "$stage/settings.env"; echo; echo "GEOLOCK_MAX_AGE_DAYS=36500"; } > "$stage/gate.env"
  sed -e "s#^GEOLOCK_SETTINGS=.*#GEOLOCK_SETTINGS=$stage/gate.env#" \
      -e "s#^GEOLOCK_CACHE=.*#GEOLOCK_CACHE=$c#" "$stage/service.env" > "$stage/gate-service.env"
  env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    HOME_DNS_GEOLOCK_ENV="$stage/gate-service.env" GEOLOCK_DRY_RUN=1 \
    GEOLOCK_URL_BASE=file:///nonexistent "$@" "$stage/tree/geolock" > "$stage/gate-$label.log" 2>&1 \
    || { cat "$stage/gate-$label.log" >&2; die "$label render failed; nothing changed"; }
  if ! cmp -s "$c/geolock.nft" "$LIVE_NFT"; then
    diff "$LIVE_NFT" "$c/geolock.nft" | head -20 >&2 || true
    die "$label render differs from the live $LIVE_NFT; nothing changed"
  fi
  say "identity check ($label): byte-identical to the live ruleset ($(sha256sum < "$c/geolock.nft" | cut -c1-12)…)"
}
gate go
gate bash PIHOLE_NO_GO=1

# ---------------------------------------------------------------- backup
ts="$(date +%Y%m%d-%H%M%S)"
bdir="$(p "$BACKUPS")/home-dns-geolock-$ts"
say "backup: $bdir"
if [[ "$MODE" == dry ]]; then
  for m in "${MANAGED[@]}"; do
    if [[ -e "$(p "$m")" ]]; then say "  would save $m"; else say "  would record $m as absent"; fi
  done
else
  mkdir -p "$(p "$BACKUPS")"
  mkdir -m 0700 "$bdir"
  : > "$bdir/manifest"
  present=()
  for m in "${MANAGED[@]}"; do
    if [[ -e "$(p "$m")" ]]; then echo "present $m" >> "$bdir/manifest"; present+=("${m#/}")
    else echo "absent $m" >> "$bdir/manifest"; fi
  done
  echo "execstartpost $(exec_start_post | paste -sd '|')" >> "$bdir/manifest"
  if [[ ${#present[@]} -gt 0 ]]; then
    tar -C "$(p /)" -cpf "$bdir/files.tar" "${present[@]}"
  fi
fi

# ---------------------------------------------------------------- install
rollback_now() {
  echo "install-geolock: install failed; rolling back from $bdir" >&2
  INSTALL_SYSROOT="$SYSROOT" "$REPO/scripts/install-geolock-system.sh" --rollback "$bdir" >&2 || true
  exit 1
}
[[ "$MODE" == dry ]] || trap 'rollback_now' ERR

run install -d -m 0755 "$(p "$DEST")" "$(p "$DEST/scripts")" "$(p "$DEST/lib")" "$(p "$DEST/go")" "$(p "$DEST/go/bin")"
run install -m 0755 "$stage/tree/geolock" "$(p "$WRAPPER")"
run install -m 0755 "$stage/tree/scripts/geolock-apply.sh" "$(p "$DEST/scripts/geolock-apply.sh")"
run install -m 0755 "$stage/tree/lib/cidr.sh" "$(p "$DEST/lib/cidr.sh")"
run install -m 0755 "$stage/tree/go/bin/geolock-apply" "$(p "$DEST/go/bin/geolock-apply")"
run install -d -m 0755 "$(p "$ETC")"
if [[ "$LIVE_SETTINGS" != "$(p "$ETC")/geolock.env" ]]; then
  run install -m 0644 "$stage/settings.env" "$(p "$ETC/geolock.env")"
fi
run install -m 0644 "$stage/service.env" "$(p "$ETC/geolock.service.env")"
run install -d -m 0755 "$(p "$STATE")"
if [[ "$LIVE_CACHE" != "$(p "$STATE")" ]]; then
  for f in "$stage/cache"/*; do
    [[ -e "$f" ]] && run install -m 0644 "$f" "$(p "$STATE")/"
  done
  run install -m 0644 "$LIVE_NFT" "$(p "$STATE/geolock.nft")"
fi
[[ "$MODE" == dry ]] || own "$(p "$DEST")" "$(p "$ETC")" "$(p "$STATE")"
cat > "$stage/dropin.conf" <<EOF
# Installed by home-dns scripts/install-geolock-system.sh. Remove this file
# (or run it with --rollback) to go back to the unit's own ExecStartPost.
[Service]
ExecStartPost=
ExecStartPost=$WRAPPER
EOF
run install -d -m 0755 "$(p "$DROPIN_DIR")"
run install -m 0644 "$stage/dropin.conf" "$(p "$DROPIN")"
if [[ "$MODE" == dry ]]; then
  echo "--- $DROPIN"; cat "$stage/dropin.conf"
  echo "--- $ETC/geolock.service.env"; cat "$stage/service.env"
  echo "---"
fi
[[ -z "$SYSROOT" ]] && run systemctl daemon-reload

# ---------------------------------------------------------------- verify
if [[ "$MODE" == dry ]]; then
  say "dry run: nothing changed. Would leave ExecStartPost=$WRAPPER (no '-'); no restart."
  exit 0
fi
for f in geolock scripts/geolock-apply.sh lib/cidr.sh go/bin/geolock-apply; do
  cmp -s "$stage/tree/$f" "$(p "$DEST/$f")" || { echo "install-geolock: $DEST/$f differs from the checked copy" >&2; false; }
done
got="$(exec_start_post | paste -sd '|')"
[[ "$got" == "$WRAPPER" ]] || { echo "install-geolock: ExecStartPost is '$got'" >&2; false; }
if [[ -z "$SYSROOT" ]]; then
  show="$(systemctl show -p ExecStartPost --value "$UNIT")"
  [[ "$show" == *"path=$WRAPPER "* && "$show" == *"ignore_errors=no"* ]] \
    || { echo "install-geolock: systemd reports: $show" >&2; false; }
fi
trap - ERR
say "installed. ExecStartPost=$WRAPPER (failures now fail the unit). Not restarted; next boot uses it."
say "run it now (optional, reloads the same ruleset atomically): sudo $WRAPPER"
say "undo: pkexec $REPO/scripts/install-geolock-system.sh --rollback $bdir"
