#!/usr/bin/env python3
"""Tail the honeypot JSON logs, normalise them and insert into PostgreSQL."""
import json, os, time
import psycopg2
from psycopg2.extras import Json

DSN = "host=192.168.56.30 dbname=honeydb user=honey password=change-me"
STATE = "/var/lib/honey-ingest/offsets.json"
SOURCES = {
    "cowrie": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
    "opencanary": "/var/log/opencanary/opencanary.log",
    "decoy_http": "/var/log/decoy/decoy_http.json",
}

INSERT = """INSERT INTO events
 (ts, source, eventid, session, src_ip, dst_port, username, password,
  command, url, sha256, raw)
 VALUES (%(ts)s, %(source)s, %(eventid)s, %(session)s, %(src_ip)s, %(dst_port)s,
  %(username)s, %(password)s, %(command)s, %(url)s, %(sha256)s, %(raw)s)"""


def normalise(source, rec):
    if source == "opencanary":
        data = rec.get("logdata") or {}
        return {"ts": rec["utc_time"].replace(" ", "T") + "Z",
                "eventid": "opencanary.%s" % rec.get("logtype"),
                "session": None, "src_ip": rec.get("src_host"),
                "dst_port": rec.get("dst_port"),
                "username": data.get("USERNAME"), "password": data.get("PASSWORD"),
                "command": None, "url": data.get("PATH"), "sha256": None}
    # cowrie and decoy_http already use the cowrie-style field names
    return {"ts": rec["timestamp"], "eventid": rec["eventid"],
            "session": rec.get("session"), "src_ip": rec.get("src_ip"),
            "dst_port": rec.get("dst_port"),
            "username": rec.get("username"), "password": rec.get("password"),
            "command": rec.get("input"), "url": rec.get("url"),
            "sha256": rec.get("shasum")}


def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    try:
        with open(STATE) as f:
            offsets = json.load(f)
    except (FileNotFoundError, ValueError):
        offsets = {}
    conn = psycopg2.connect(DSN)
    conn.autocommit = True
    cur = conn.cursor()
    while True:
        for source, path in SOURCES.items():
            if not os.path.exists(path):
                continue
            pos = offsets.get(path, 0)
            if os.path.getsize(path) < pos:   # file was rotated
                pos = 0
            with open(path, "rb") as f:
                f.seek(pos)
                for raw in iter(f.readline, b""):
                    if not raw.endswith(b"\n"):
                        break                  # half-written line, retry later
                    pos += len(raw)
                    try:
                        rec = json.loads(raw)
                        ev = normalise(source, rec)
                    except (ValueError, KeyError):
                        continue
                    if not ev.get("src_ip"):
                        continue
                    cur.execute(INSERT, {**ev, "source": source, "raw": Json(rec)})
            offsets[path] = pos
        with open(STATE, "w") as f:
            json.dump(offsets, f)
        time.sleep(2)


if __name__ == "__main__":
    main()
