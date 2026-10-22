#!/usr/bin/env python3
"""Fail over this PC to Cloudflare if Pi-hole stops answering; fail back when it recovers.

Also self-heals once per incident via `docker restart pihole` after 2 consecutive
loopback failures, and logs structured events + desktop notifications.
"""
from __future__ import annotations

import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(os.environ.get("PIHOLE_ROOT") or Path(__file__).resolve().parent)
STATE_PATH = ROOT / "state" / "watchdog.json"
LOG_PATH = ROOT / "logs" / "watchdog.log"
PIHOLE = "127.0.0.1"
# Filled by load_settings() from the env or <checkout>/.env (see .env.example).
WIFI_CON = ""
WIFI_DEV = ""
LAN_DNS = ""
PIHOLE_DNS = ""
HINTS = {
    "WIFI_CON": "It is the NetworkManager connection name (nmcli -t -f NAME connection show --active).",
    "WIFI_DEV": "It is the network device name (nmcli -t -f DEVICE connection show --active).",
    "DOT_AUTH_NAME": "It is the TLS name Pi-hole's DoT certificate answers to, e.g. your-host.your-tailnet.ts.net.",
}
CLOUDFLARE = ["1.1.1.1#cloudflare-dns.com", "8.8.8.8#dns.google"]
STRIKES = 3
HEAL_AFTER = 2
HEAL_WAIT_SEC = 8
HEAL_COOLDOWN_SEC = 600


def is_placeholder(v: str) -> bool:
    v = v.strip()
    return not v or any(t in v for t in ("your-", "your_", "change-me", "x.x")) or v.endswith(".x")


def read_env_file() -> dict[str, str]:
    path = Path(os.environ.get("PIHOLE_ENV_FILE") or ROOT / ".env")
    out: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            key, sep, val = line.strip().partition("=")
            key = key.removeprefix("export ").strip()
            if sep and key and not key.startswith("#"):
                out[key] = val.strip().strip("'\"")
    return out


def setting(key: str, file_vals: dict[str, str], default: str = "") -> str:
    v = os.environ.get(key) or file_vals.get(key, "")
    return default if is_placeholder(v) else v


def need(key: str, file_vals: dict[str, str]) -> str:
    v = setting(key, file_vals)
    if not v:
        sys.exit(
            f"watchdog: {key} is not set. {HINTS[key]}\n"
            f"Add {key}=... to .env (see .env.example) or export it, then run this again."
        )
    return v


def load_settings() -> None:
    global WIFI_CON, WIFI_DEV, LAN_DNS, PIHOLE_DNS
    vals = read_env_file()
    WIFI_CON = need("WIFI_CON", vals)
    WIFI_DEV = need("WIFI_DEV", vals)
    PIHOLE_DNS = setting("PIHOLE_DNS", vals) or "127.0.0.1#" + need("DOT_AUTH_NAME", vals)
    LAN_DNS = setting("PIHOLE_WATCHDOG_LAN", vals) or setting("LAN_IPV4", vals)


def iso_now() -> str:
    return datetime.now(UTC).astimezone().isoformat(timespec="seconds")


def dns_ok(server: str, host: str = "example.com", timeout: float = 4.0) -> bool:
    def enc(name: str) -> bytes:
        out = b""
        for label in name.rstrip(".").split("."):
            part = label.encode("idna")
            out += bytes([len(part)]) + part
        return out + b"\x00"

    tid = random.randint(0, 65535)
    msg = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    msg += enc(host) + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (server, 53))
        data, _ = sock.recvfrom(4096)
        return len(data) >= 12 and (data[3] & 0x0F) in (0, 3)
    except OSError:
        return False
    finally:
        sock.close()


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            data = json.loads(STATE_PATH.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "mode": "pihole",
        "fail": 0,
        "ok": 0,
        "last_heal": None,
        "last_notify": None,
        "heal_tried": False,
    }


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "mode": state.get("mode", "pihole"),
        "fail": int(state.get("fail", 0)),
        "ok": int(state.get("ok", 0)),
        "last_heal": state.get("last_heal"),
        "last_notify": state.get("last_notify"),
        "heal_tried": bool(state.get("heal_tried", False)),
    }
    STATE_PATH.write_text(json.dumps(out))


def log_line(event: str, **fields) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts": iso_now(), "event": event, **fields}
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, separators=(",", ":")) + "\n")


def notify(title: str, body: str, state: dict) -> None:
    env = os.environ.copy()
    env["DISPLAY"] = ":0.0"
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{os.getuid()}/bus")
    try:
        subprocess.run(
            ["notify-send", "-a", "Pi-hole", title, body],
            env=env,
            check=False,
            capture_output=True,
            timeout=10,
        )
        state["last_notify"] = iso_now()
        log_line("notify", title=title, body=body)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log_line("notify_error", error=str(exc), title=title)


def nmcli(*args: str) -> None:
    subprocess.run(["nmcli", *args], check=False, capture_output=True)


def use_pihole() -> None:
    nmcli(
        "connection",
        "modify",
        WIFI_CON,
        "ipv4.dns",
        PIHOLE_DNS,
        "ipv6.dns",
        "",
        "connection.dns-over-tls",
        "yes",
    )
    if subprocess.run(["nmcli", "device", "reapply", WIFI_DEV], capture_output=True, check=False).returncode != 0:
        subprocess.run(["resolvectl", "dns", WIFI_DEV, PIHOLE_DNS], check=False)
        subprocess.run(["resolvectl", "dnsovertls", WIFI_DEV, "yes"], check=False)


def use_cloudflare() -> None:
    nmcli(
        "connection",
        "modify",
        WIFI_CON,
        "ipv4.dns",
        ",".join(CLOUDFLARE),
        "connection.dns-over-tls",
        "yes",
    )
    if subprocess.run(["nmcli", "device", "reapply", WIFI_DEV], capture_output=True, check=False).returncode != 0:
        subprocess.run(["resolvectl", "dns", WIFI_DEV, *CLOUDFLARE], check=False)
        subprocess.run(["resolvectl", "dnsovertls", WIFI_DEV, "yes"], check=False)


def docker_restart_pihole() -> int:
    """Restart pihole container; mirror lib/docker_cmd.sh (direct docker, then newgrp)."""
    try:
        if subprocess.run(["docker", "info"], capture_output=True, timeout=15, check=False).returncode == 0:
            return subprocess.run(
                ["docker", "restart", "pihole"],
                check=False,
                capture_output=True,
                timeout=60,
            ).returncode
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        user = subprocess.check_output(["id", "-un"], text=True).strip()
        members = subprocess.check_output(
            ["getent", "group", "docker"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        member_list = members.split(":")[-1].split(",") if members else []
        if user in member_list and Path("/usr/bin/newgrp").is_file():
            runner = Path(f"/tmp/pihole-watchdog-docker-{os.getpid()}.sh")
            runner.write_text("#!/bin/bash\nexec docker restart pihole\n")
            runner.chmod(0o700)
            try:
                proc = subprocess.run(
                    ["/usr/bin/newgrp", "docker"],
                    check=False,
                    input=f'exec /bin/bash --norc --noprofile "{runner}"\n',
                    text=True,
                    capture_output=True,
                    timeout=90,
                )
                return proc.returncode
            finally:
                runner.unlink(missing_ok=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    try:
        return subprocess.run(
            ["sudo", "-n", "docker", "restart", "pihole"],
            check=False,
            capture_output=True,
            timeout=60,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _heal_cooldown_ok(state: dict) -> bool:
    last = state.get("last_heal")
    if not last:
        return True
    try:
        then = datetime.fromisoformat(str(last))
        if then.tzinfo is None:
            then = then.replace(tzinfo=UTC)
        return (datetime.now(UTC) - then.astimezone(UTC)).total_seconds() >= HEAL_COOLDOWN_SEC
    except (TypeError, ValueError):
        return True


def try_self_heal(state: dict) -> bool:
    """Attempt one docker restart per incident. Returns True if loopback recovers."""
    if not _heal_cooldown_ok(state):
        log_line("heal_skipped_cooldown", fail=state.get("fail"), last_heal=state.get("last_heal"))
        state["heal_tried"] = True
        return False
    log_line("heal_attempt", fail=state.get("fail"), mode=state.get("mode"))
    rc = docker_restart_pihole()
    state["last_heal"] = iso_now()
    state["heal_tried"] = True
    time.sleep(HEAL_WAIT_SEC)
    recovered = dns_ok(PIHOLE)
    log_line("heal_result", docker_rc=rc, recovered=recovered)
    return recovered


def main() -> int:
    load_settings()
    state = load_state()
    loopback_ok = dns_ok(PIHOLE)
    lan_ok = dns_ok(LAN_DNS) if LAN_DNS else False
    # Host uses loopback DNS; failover decisions require 127.0.0.1.
    # LAN probe is logged for diagnostics (either answering means LAN path alive).
    healthy = loopback_ok
    lan_alive = loopback_ok or lan_ok

    log_line(
        "check",
        mode=state.get("mode"),
        loopback=loopback_ok,
        lan=lan_ok,
        lan_alive=lan_alive,
        fail=int(state.get("fail", 0)),
        ok=int(state.get("ok", 0)),
    )

    if healthy:
        state["fail"] = 0
        state["heal_tried"] = False
        state["ok"] = int(state.get("ok", 0)) + 1
        if state.get("mode") != "pihole" and state["ok"] >= STRIKES:
            use_pihole()
            state["mode"] = "pihole"
            msg = "Pi-hole recovered; DNS restored to 127.0.0.1"
            print(msg)
            log_line("recovery", fail=0, ok=state["ok"])
            notify("Pi-hole recovered", msg, state)
    else:
        state["ok"] = 0
        state["fail"] = int(state.get("fail", 0)) + 1
        fail = state["fail"]

        # Self-heal once per incident after 2 consecutive loopback failures
        # while still pointing at Pi-hole.
        if (
            state.get("mode") == "pihole"
            and fail >= HEAL_AFTER
            and not state.get("heal_tried")
        ):
            if try_self_heal(state):
                state["fail"] = 0
                state["ok"] = 1
                state["heal_tried"] = False
                log_line("heal_success", fail=fail)
                save_state(state)
                return 0
            # Still failing after heal; continue toward failover if fail>=STRIKES
            # Re-read fail after increment; heal does not reset fail on failure.
            fail = state["fail"]

        if state.get("mode") != "cloudflare" and fail >= STRIKES:
            use_cloudflare()
            state["mode"] = "cloudflare"
            msg = "Pi-hole down; failed over to 1.1.1.1+8.8.8.8"
            print(msg, file=sys.stderr)
            log_line("failover", fail=fail, lan_ok=lan_ok)
            notify("Pi-hole failover", msg, state)

    save_state(state)
    # Always succeed: this is a probe/failover actor, not a healthcheck.
    # Returning 1 during the strike window made systemd log
    # "Failed to start Fail over DNS..." every 30s without changing policy.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
