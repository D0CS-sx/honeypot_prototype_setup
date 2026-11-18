-- 1. Tag events with a technique (rule-based on purpose: simple, explainable)
UPDATE events SET technique = CASE
  WHEN eventid = 'cowrie.session.file_download'
    THEN 'T1105 Ingress Tool Transfer'
  WHEN eventid = 'cowrie.command.input'
    THEN 'T1059 Command and Scripting Interpreter'
  WHEN eventid IN ('cowrie.login.failed', 'cowrie.login.success', 'decoy.http.login')
    OR (eventid LIKE 'opencanary.%' AND username IS NOT NULL)
    THEN 'T1110 Brute Force'
  WHEN eventid IN ('cowrie.session.connect', 'decoy.http.connect')
    THEN 'T1595 Active Scanning'
  ELSE NULL END
WHERE technique IS NULL;

-- 2. Extract IoCs (recomputed from events, so re-running is safe)
INSERT INTO iocs (ioc_type, value, first_seen, last_seen, hits)
SELECT 'ip', src_ip, min(ts), max(ts), count(*) FROM events GROUP BY src_ip
ON CONFLICT (ioc_type, value) DO UPDATE SET
  first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
  last_seen = EXCLUDED.last_seen, hits = EXCLUDED.hits;

INSERT INTO iocs (ioc_type, value, first_seen, last_seen, hits)
SELECT 'url', url, min(ts), max(ts), count(*) FROM events
WHERE eventid = 'cowrie.session.file_download' AND url LIKE 'http%' GROUP BY url
ON CONFLICT (ioc_type, value) DO UPDATE SET
  first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
  last_seen = EXCLUDED.last_seen, hits = EXCLUDED.hits;

INSERT INTO iocs (ioc_type, value, first_seen, last_seen, hits)
SELECT 'sha256', sha256, min(ts), max(ts), count(*) FROM events
WHERE sha256 IS NOT NULL GROUP BY sha256
ON CONFLICT (ioc_type, value) DO UPDATE SET
  first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
  last_seen = EXCLUDED.last_seen, hits = EXCLUDED.hits;

INSERT INTO iocs (ioc_type, value, first_seen, last_seen, hits)
SELECT 'credential', username || ':' || password, min(ts), max(ts), count(*) FROM events
WHERE username IS NOT NULL AND password IS NOT NULL GROUP BY username, password
ON CONFLICT (ioc_type, value) DO UPDATE SET
  first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
  last_seen = EXCLUDED.last_seen, hits = EXCLUDED.hits;
