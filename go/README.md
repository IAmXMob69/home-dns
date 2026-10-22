# go/

Go builds of the stack's scripts. Each `.sh` runs `go/bin/<tool>` when it
exists, else its own shell body. The Python tools stay as fallback the same way.

- `bin/pihole-install`: `install.sh`
- `bin/geolock-apply`: `scripts/geolock-apply.sh`
- `bin/malice-ip-apply`: `scripts/malice-ip-apply.sh`
- `bin/refresh-dot-cert`: `scripts/refresh-dot-cert.sh`
- `bin/pihole-groups`: `scripts/lib/pihole_groups.py`
- `bin/pihole-exporter`: `monitoring/pihole-exporter.py` (image via `make image`)
- Host tools, same name as their script: `harden`, `expose-lan`,
  `setup-tailscale-privileged`, `join-tailnet`, `publish-tailscale-dns`, `fix-pihole`,
  `apply-stack`, `rollback-dns`, `backup`, `cleanup`, `watchdog` (`watchdog.py`),
  `dns-probe` (`dns-probe.py`), and under `automation/`: `healthcheck`, `status`,
  `update-gravity`, `update-pihole`, `import-lists`, `import-webpwnized-lists`,
  `install-privacy-shield`, `debug-window-off`

Build: `make` (vet + test + build, niced, 2 cores). Needs Go 1.26+.
Rollback: `PIHOLE_NO_GO=1 ./install.sh` for one run, or `make clean`.
