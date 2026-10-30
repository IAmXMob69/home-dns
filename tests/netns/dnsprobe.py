#!/usr/bin/env python3
"""Tiny DNS responder and prober for the geolock netns harness (tests only).

  dnsprobe.py serve                       answer every query on :53 (UDP+TCP, v4+v6)
  dnsprobe.py query SRC DST [--tcp]       exit 0 if DST answered a query sent from SRC
"""

import argparse
import os
import socket
import struct
import sys
import threading

QUERY_BODY = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"


def reply(q):
    # Same ID, QR + RD + RA, NOERROR, question echoed, no answers.
    return q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x00\x00\x00\x00\x00" + q[12:]


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve_udp(fam, addr):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, 53))
    while True:
        q, peer = s.recvfrom(4096)
        if len(q) >= 12:
            s.sendto(reply(q), peer)


def serve_tcp(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, 53))
    s.listen(16)
    while True:
        c, _ = s.accept()
        with c:
            c.settimeout(2)
            try:
                n = struct.unpack("!H", c.recv(2))[0]
                q = c.recv(n)
                r = reply(q)
                c.sendall(struct.pack("!H", len(r)) + r)
            except (OSError, struct.error):
                pass


def serve():
    for fam, addr in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        for fn in (serve_udp, serve_tcp):
            threading.Thread(target=fn, args=(fam, addr), daemon=True).start()
    threading.Event().wait()


def query(src, dst, tcp, timeout):
    qid = os.urandom(2)
    q = qid + QUERY_BODY
    fam = family(dst)
    s = socket.socket(fam, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind((src, 0))
        if tcp:
            s.connect((dst, 53))
            s.sendall(struct.pack("!H", len(q)) + q)
            n = struct.unpack("!H", s.recv(2))[0]
            r = s.recv(n)
        else:
            s.sendto(q, (dst, 53))
            r, _ = s.recvfrom(4096)
    except (OSError, struct.error):
        return 1
    finally:
        s.close()
    return 0 if r[:2] == qid and r[2] & 0x80 else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    qp = sub.add_parser("query")
    qp.add_argument("src")
    qp.add_argument("dst")
    qp.add_argument("--tcp", action="store_true")
    qp.add_argument("--timeout", type=float, default=1.0)
    a = ap.parse_args()
    if a.cmd == "serve":
        serve()
        return 0
    return query(a.src, a.dst, a.tcp, a.timeout)


if __name__ == "__main__":
    sys.exit(main())
