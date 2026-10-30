# Geolock at boot: root-owned copy

`vaultos-country-block.service` loads the country and malice tables, then runs
the geolock. On the original host it ran it straight from a user-owned checkout:

    ExecStartPost=-<home>/pihole/scripts/geolock-apply.sh

That has two problems. Root runs a script and a `go/bin` binary that the user
account can rewrite. And the leading `-` means a failed geolock is ignored, so
the unit reports success with no geolock table.

`scripts/install-geolock-system.sh` fixes both without touching the firewall.

## What it does

1. It reads the unit and finds the current geolock command, and from that the
   live settings and `geolock/cache/geolock.nft`.
2. It works out the boot-only inputs (`GEOLOCK_TAILSCALE_UNDERLAY`,
   `GEOLOCK_APP_CGROUP`) from the live ruleset.
3. It builds the new copy in a temp dir. It renders the ruleset from the cached
   lists only, with Go and with Bash, and runs `nft -c` on it. **If either render
   is not byte-identical to the live `geolock.nft`, it stops and changes nothing.**
4. It backs up everything it will touch to `/var/backups/home-dns-geolock-<time>/`.
5. It installs these files, all `root:root`:

   | Path | Contents |
   |---|---|
   | `/usr/local/lib/home-dns/geolock` | entry point (0755) |
   | `/usr/local/lib/home-dns/scripts/geolock-apply.sh`, `lib/cidr.sh`, `go/bin/geolock-apply` | the geolock (0755) |
   | `/etc/home-dns/geolock.env` | your settings, copied unchanged |
   | `/etc/home-dns/geolock.service.env` | cache path, underlay, app cgroup |
   | `/var/lib/home-dns/geolock/` | list cache, seeded from the live one |
   | `/etc/systemd/system/vaultos-country-block.service.d/10-home-dns-geolock.conf` | the drop-in below |

   The drop-in:

   ```ini
   [Service]
   ExecStartPost=
   ExecStartPost=/usr/local/lib/home-dns/geolock
   ```

6. It runs `systemctl daemon-reload` and checks that systemd now reports that
   path with `ignore_errors=no`. If any step fails, it rolls back on its own.

It does **not** restart the unit or reload any table. The table loaded now stays
as it is, and the next boot uses the new copy. The unit file itself is not
edited. `systemd/system/` has the drop-in and the resulting unit as examples.

## Run it

Build the Go binary in the checkout first. The script refuses to run without it.

```bash
cd go && nice go build -trimpath -o bin/geolock-apply ./cmd/geolock-apply && cd ..
scripts/install-geolock-system.sh --dry-run        # no root: plan + identity check
pkexec "$PWD/scripts/install-geolock-system.sh"    # install (one password prompt)
```

To undo, run `pkexec <checkout>/scripts/install-geolock-system.sh --rollback`.
That restores the latest backup. You can also pass a backup dir.

## After installing

* Change countries or settings in `/etc/home-dns/geolock.env` (root). The old
  checkout's `geolock/settings.env` no longer affects boot.
* Apply now (optional, swaps in the same table atomically, with rollback):
  `sudo /usr/local/lib/home-dns/geolock`. Use `--refresh` to download the lists again.
* A failing geolock now shows as a failed unit:
  `systemctl status vaultos-country-block` and
  `journalctl -u vaultos-country-block`.
* After updating the checkout, run the installer again. It checks the new
  version against the installed ruleset the same way.

## Testing

`tests/install-geolock-system-test.sh` runs the installer against a fake root
(`INSTALL_SYSROOT`). It covers the dry run, refusing a changed render, install,
reinstall, a failure partway through (automatic rollback) and `--rollback`.
CI runs it too.
