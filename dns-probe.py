#!/usr/bin/env python3
"""Send one DNS A/AAAA query. Exit 0 if a nameserver actually answers.

Pi-hole block responses (0.0.0.0 / ::) are labeled BLOCKED but still count
as a successful connectivity probe (exit 0).
"""
import ipaddress
import os
import random
import socket
import struct
import sys
from pathlib import Path


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        part = label.encode("idna")
        if len(part) > 63:
            raise ValueError(f"label too long: {label}")
        out += bytes([len(part)]) + part
    return out + b"\x00"


def skip_name(data: bytes, offset: int) -> int:
    """Advance past a DNS name (labels or compression pointer)."""
    while True:
        if offset >= len(data):
            raise RuntimeError("truncated DNS name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise RuntimeError("truncated compression pointer")
            return offset + 2
        offset += 1 + length


def parse_answers(data: bytes) -> list[str]:
    """Return A/AAAA address strings from the answer section."""
    if len(data) < 12:
        raise RuntimeError("short DNS response")
    ancount = struct.unpack(">H", data[6:8])[0]
    offset = 12
    # question
    offset = skip_name(data, offset)
    offset += 4  # qtype + qclass
    addrs: list[str] = []
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            raise RuntimeError("truncated RR header")
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:  # A
            addrs.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == 28 and rdlength == 16:  # AAAA
            addrs.append(str(ipaddress.IPv6Address(rdata)))
    return addrs


def build_query(host: str, qtype: int = 1) -> bytes:
    tid = random.randint(0, 65535)
    msg = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    msg += encode_name(host) + struct.pack(">HH", qtype, 1)
    return msg


def parse_header(data: bytes) -> tuple[int, int]:
    if len(data) < 12:
        raise RuntimeError("short DNS response")
    rcode = data[3] & 0x0F
    ancount = struct.unpack(">H", data[6:8])[0]
    return rcode, ancount


def recvall(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        buf = sock.recv(n - len(chunks))
        if not buf:
            raise RuntimeError("connection closed")
        chunks.extend(buf)
    return bytes(chunks)


def query(host: str, server: str, qtype: int = 1, timeout: float = 3.0) -> tuple[int, int, int, bytes]:
    msg = build_query(host, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    rcode, ancount = parse_header(data)
    return rcode, ancount, len(data), data


def query_dot(
    host: str,
    server: str,
    server_name: str,
    qtype: int = 1,
    timeout: float = 5.0,
) -> tuple[int, int, int, bytes]:
    import ssl

    msg = build_query(host, qtype)
    wire = struct.pack(">H", len(msg)) + msg
    ctx = ssl.create_default_context()
    with (
        socket.create_connection((server, 853), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=server_name) as tls,
    ):
        tls.sendall(wire)
        hdr = recvall(tls, 2)
        (n,) = struct.unpack(">H", hdr)
        data = recvall(tls, n)
    rcode, ancount = parse_header(data)
    return rcode, ancount, len(data), data


def query_doh(
    host: str,
    server: str,
    server_name: str,
    qtype: int = 1,
    timeout: float = 5.0,
) -> tuple[int, int, int, bytes]:
    import subprocess
    import tempfile

    # dnsdist DoH is HTTP/2; stdlib http.client is HTTP/1.1.
    msg = build_query(host, qtype)
    with tempfile.NamedTemporaryFile(suffix=".dns") as fh:
        fh.write(msg)
        fh.flush()
        proc = subprocess.run(
            [
                "curl",
                "-sS",
                "--http2",
                "--max-time",
                str(int(timeout)),
                "--resolve",
                f"{server_name}:8443:{server}",
                "-H",
                "Content-Type: application/dns-message",
                "-H",
                "Accept: application/dns-message",
                "--data-binary",
                f"@{fh.name}",
                f"https://{server_name}:8443/dns-query",
            ],
            check=False,
            capture_output=True,
        )
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip() or f"curl exit {proc.returncode}"
        raise RuntimeError(err)
    data = proc.stdout
    rcode, ancount = parse_header(data)
    return rcode, ancount, len(data), data


def is_block_addr(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip == ipaddress.ip_address("0.0.0.0") or ip == ipaddress.ip_address("::")


def default_server_name() -> str:
    """DoT/DoH TLS name: DOT_AUTH_NAME from the env or .env, else pihole.lan."""
    name = os.environ.get("DOT_AUTH_NAME", "")
    env = Path(os.environ.get("PIHOLE_ENV_FILE") or Path(__file__).resolve().parent / ".env")
    if not name and env.is_file():
        for line in env.read_text().splitlines():
            key, sep, val = line.strip().partition("=")
            if sep and key.removeprefix("export ").strip() == "DOT_AUTH_NAME":
                name = val.strip().strip("'\"")
    if not name or "your-" in name or "your_" in name:
        return "pihole.lan"
    return name


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--"]
    mode = "plain"
    if args and args[0] in ("--dot", "--doh"):
        mode = args.pop(0)[2:]
    host = args[0] if args else "example.com"
    server = args[1] if len(args) > 1 else "127.0.0.1"
    server_name = args[2] if len(args) > 2 else default_server_name()
    if mode == "dot":
        rcode, ancount, size, data = query_dot(host, server, server_name)
    elif mode == "doh":
        rcode, ancount, size, data = query_doh(host, server, server_name)
    else:
        rcode, ancount, size, data = query(host, server)
    addrs = parse_answers(data) if ancount else []
    blocked = any(is_block_addr(a) for a in addrs)
    addr_s = ",".join(addrs) if addrs else "-"
    status = "BLOCKED" if blocked else ("ok" if rcode in (0, 3) else "fail")
    print(
        f"mode={mode} server={server} host={host} rcode={rcode} answers={ancount} "
        f"addrs={addr_s} status={status} bytes={size}"
    )
    if blocked:
        print("BLOCKED")
    # NOERROR or NXDOMAIN both mean the server is alive; block pages are not failures.
    return 0 if rcode in (0, 3) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - any failure is a failed probe
        print(f"DNS probe failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
