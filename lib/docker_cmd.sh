# shellcheck shell=bash
# Sourced by Pi-hole automation. The user manager can start before this
# login has the docker group, so `docker` fails and bare `sudo` would
# prompt for a password. Prefer newgrp(1); never prompt.
docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
    return
  fi

  local user members runner st
  user=$(id -un)
  members=$(getent group docker 2>/dev/null | awk -F: '{print $4}')
  if [[ -x /usr/bin/newgrp && ",${members}," == *",${user},"* ]]; then
    runner=$(mktemp)
    {
      printf '#!/bin/bash\n'
      printf 'exec docker '
      printf '%q ' "$@"
      printf '\n'
    } >"${runner}"
    chmod 700 "${runner}"
    st=0
    # Unquoted heredoc so ${runner} expands in this shell before newgrp reads it.
    /usr/bin/newgrp docker <<NG || st=$?
exec /bin/bash --norc --noprofile "${runner}"
NG
    rm -f "${runner}"
    return "${st}"
  fi

  # Passwordless sudo only. Never call sudo if it would ask for a password
  # (that prints "sudo: a password is required" into cron/systemd logs).
  if sudo -n true >/dev/null 2>&1; then
    sudo -n docker "$@"
    return
  fi

  echo "docker_cmd: docker unavailable (no active docker group, no passwordless sudo)" >&2
  return 1
}
