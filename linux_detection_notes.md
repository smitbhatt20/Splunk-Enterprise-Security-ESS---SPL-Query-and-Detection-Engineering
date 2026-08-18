# Notable Event: Successful Root Login After SSH Authentication

## Alert Details

Severity: High

Host: ubuntu-prod-01

User: root

Source IP: 185.100.87.12

Failed Logins: 25

Successful Login: Yes

Time: 03:12 AM IST

## Investigation Objective

Investigate whether the successful root login was legitimate or the result of brute-force activity, privilege escalation, or unauthorized access.

## SPL Query 1

```spl
index=linux source="/var/log/auth.log" user="root" action IN ("failed","success")
| table _time user host src_ip action eventName
| sort -_time