# SSH Brute Force Detection - SPL Query & Investigation Guide

> **Detection Engineering** | Splunk Enterprise Security | MITRE ATT&CK: T1110 — Brute Force

---

## Overview

This query detects SSH brute force and password spray attacks by parsing raw sshd log messages, extracting attacker fields, geo-enriching source IPs, and aggregating attack patterns for SOC triage.

---

## Raw Log Format

What Splunk ingests from `index=ssh_logs`:

```
Aug 18 03:42:11 server sshd[3291]: Failed password for root from 185.220.101.47 port 52341 ssh2
Aug 18 03:42:14 server sshd[3292]: Failed password for admin from 185.220.101.47 port 52345 ssh2
Aug 18 03:42:17 server sshd[3293]: Failed password for ubuntu from 45.83.64.12 port 44211 ssh2
```

---

## Message Field Index Map

After `split(Message, " ")`, each word maps to a position:

| Index | Value | Extracted As |
|-------|-------|-------------|
| 0 | `Failed` | — |
| 1 | `password` | — |
| 2 | `for` | — |
| 3 | `root` | → `user` |
| 4 | `from` | — |
| 5 | `185.220.101.47` | → `src_ip` |
| 6 | `port` | — |
| 7 | `52341` | → `port` |
| 8 | `ssh2` | — |

---

## SPL Query Evolution

### Step 1 - Basic Search
```spl
index=ssh_logs "Failed password"
```

### Step 2 - Add Table View
```spl
index=ssh_logs "Failed password"
| table _time user src_ip Message
```

### Step 3 - Parse Message with split()
```spl
index=ssh_logs "Failed password"
| table _time user src_ip Message
| eval temp = split(Message, " ")
```

### Step 4 - Extract Fields with mvindex()
```spl
index=ssh_logs "Failed password"
| eval temp = split(_raw, " ")
| eval user   = mvindex(temp, 3),
       src_ip = mvindex(temp, 5),
       port   = mvindex(temp, 7)
| fields - temp Message
```

### Step 5 - Final Investigation Query (Full)
```spl
index=ssh_logs "Failed password"
| eval temp = split(_raw, " ")
| eval user   = mvindex(temp, 3),
       src_ip = mvindex(temp, 5),
       port   = mvindex(temp, 7)
| fields - temp Message
| iplocation src_ip
| stats count
        min(_time) as first_seen
        max(_time) as last_seen
        dc(user)   as unique_users
        by src_ip port City Country
| sort - count
| head 10
```

---

## What Each Command Does

| Command | Purpose |
|---------|---------|
| `index=ssh_logs "Failed password"` | Filter only failed SSH login events |
| `eval temp = split(_raw, " ")` | Break raw message into list by spaces |
| `mvindex(temp, N)` | Extract word at position N from the list |
| `fields - temp Message` | Remove raw/temp fields, keep output clean |
| `iplocation src_ip` | Geo-enrich IP with Country, City, lat/lon |
| `stats count ... by src_ip` | Aggregate attack counts per source IP |
| `dc(user)` | Count distinct usernames targeted (spray indicator) |
| `min/max(_time)` | Show when attacks started and last seen |
| `sort - count` | Highest attack count first |
| `head 10` | Top 10 attacking IPs only |

---

## Sample Output

| src_ip | count | unique_users | Country | City | first_seen | last_seen |
|--------|-------|-------------|---------|------|------------|-----------|
| 185.220.101.47 | 2,847 | 38 | Germany | Frankfurt | Aug 18 00:01 | Aug 18 03:47 |
| 45.83.64.12 | 1,203 | 22 | Netherlands | Amsterdam | Aug 18 01:12 | Aug 18 03:44 |
| 194.165.16.18 | 487 | 11 | Russia | Moscow | Aug 18 02:33 | Aug 18 03:41 |
| 103.99.0.122 | 231 | 7 | China | Beijing | Aug 18 03:01 | Aug 18 03:38 |
| 91.121.87.243 | 98 | 3 | France | Paris | Aug 18 03:21 | Aug 18 03:35 |

---

## SOC Triage Logic

### Brute Force vs Password Spray
| Indicator | Brute Force | Password Spray |
|-----------|------------|----------------|
| `unique_users` | Low (1–2) | High (10+) |
| `count` | Very high per user | Spread across users |
| Pattern | One target, many passwords | Many targets, few passwords each |

### Severity Decision
- `count > 1000` + `unique_users > 10` → **Critical** — likely automated spray tool
- `count > 200` + `unique_users > 5` → **High** — investigate and consider block
- `count < 200` → **Medium** — monitor, check if IP is known bad

### Investigation Steps
1. Check if `src_ip` is a known Tor exit node or VPN provider
2. Check if any login **succeeded** from same IP — pivot to `Accepted password`
3. Check `unique_users` - high count = spray attack targeting common usernames
4. Look at `first_seen` vs `last_seen` - ongoing or historical?
5. Cross-reference IP with threat intel (VirusTotal, AbuseIPDB)
6. Block at firewall if Critical, create Splunk ES notable event

---

## Related Queries

### Check if any login Succeeded from same attacker IP
```spl
index=ssh_logs "Accepted password"
| eval temp = split(_raw, " ")
| eval user   = mvindex(temp, 3),
       src_ip = mvindex(temp, 5)
| where src_ip="185.220.101.47"
| table _time user src_ip
```

### Detect Password Spray (many users, distributed attempts)
```spl
index=ssh_logs "Failed password"
| eval temp = split(_raw, " ")
| eval user   = mvindex(temp, 3),
       src_ip = mvindex(temp, 5)
| stats dc(user) as unique_users count by src_ip
| where unique_users > 10
| sort - unique_users
```

### Time-based Attack Pattern (is it ongoing?)
```spl
index=ssh_logs "Failed password"
| eval temp = split(_raw, " ")
| eval src_ip = mvindex(temp, 5)
| timechart span=5m count by src_ip limit=5
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|-----|--------|
| Brute Force | T1110 | Credential Access |
| Password Spraying | T1110.003 | Credential Access |
| Valid Accounts (if successful) | T1078 | Initial Access / Persistence |

---

## Notes

- `_raw` is used instead of `Message` for reliability across different log formats
- `mvindex` positions depend on exact sshd log format — verify against your environment
- Add `| where count > 50` before `sort` to filter low-noise IPs
- For production, consider extracting fields at index time using transforms.conf

---

*Part of the [Splunk ES Detection Engineering Repo](https://github.com/smitbhatt20/Splunk-Enterprise-Security-ESS---SPL-Query-and-Detection-Engineering)*
