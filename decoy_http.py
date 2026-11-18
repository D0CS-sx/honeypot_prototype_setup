#!/usr/bin/env python3
"""Minimal fake admin portal. Logs each request as one JSON line."""
import asyncio, json, time, uuid
from urllib.parse import parse_qs

LOG = "/var/log/decoy/decoy_http.json"
PORT = 8081
PAGE = (b"<html><head><title>Router Admin</title></head><body>"
        b"<form method='POST' action='/login'>User: <input name='username'> "
        b"Pass: <input name='password' type='password'>"
        b"<input type='submit'></form></body></html>")


def log(event, **fields):
    rec = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "eventid": event, **fields}
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


async def handle(reader, writer):
    src_ip, src_port = writer.get_extra_info("peername")[:2]
    sid = uuid.uuid4().hex[:12]
    log("decoy.http.connect", session=sid, src_ip=src_ip, src_port=src_port, dst_port=PORT)
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        lines = head.decode("latin-1").split("\r\n")
        method, path = (lines[0].split(" ") + ["", ""])[:2]
        headers = {k.lower(): v for k, v in
                   (ln.split(": ", 1) for ln in lines[1:] if ": " in ln)}
        body = b""
        length = min(int(headers.get("content-length", "0") or 0), 4096)
        if length:
            body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
        log("decoy.http.request", session=sid, src_ip=src_ip, dst_port=PORT,
            method=method, path=path, user_agent=headers.get("user-agent", ""))
        if method == "POST" and path == "/login":
            form = parse_qs(body.decode("latin-1"))
            log("decoy.http.login", session=sid, src_ip=src_ip, dst_port=PORT,
                username=form.get("username", [""])[0],
                password=form.get("password", [""])[0])
            resp = (b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 14\r\n"
                    b"Connection: close\r\n\r\nLogin failed.\n")
        else:
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(PAGE)) + PAGE
        writer.write(resp)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
