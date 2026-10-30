# systemd examples

User timers assume the checkout is at `~/home-dns` (`%h/home-dns`). Change the path if yours differs.

```bash
cp -r systemd/user/* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pihole-watchdog.timer pihole-healthcheck.timer pihole-gravity.timer \
  pihole-cleanup.timer pihole-backup.timer pihole-image-update.timer pihole-dot-cert.timer pihole-indic-idn-guard.timer
```

`system/pihole-tailscale-dns.service` runs as root's systemd: set `YOUR_USER` and the path first.
