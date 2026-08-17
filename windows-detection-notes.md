# Windows Detection Notes

Splunk SPL queries and triage logic for Windows notable events.

---

## 1. Unusual PowerShell Execution

### Step 1 — Command line audit
Pull raw PowerShell command-line activity per host/user and scan for suspicious patterns: `Invoke-Expression`, `IEX`, `DownloadString`, `-ExecutionPolicy Bypass`, `-NoLogo`/`-NoProfile` combined with encoded commands.

```spl
index=windows EventCode=4104
| table _time host user process commandline
| sort -_time
```

### Step 2 — Parent/child process relationship
Look for what spawned PowerShell, and what PowerShell spawned. Include process hashes to verify integrity.

```spl
index=processes process="powershell.exe"
| table _time host user parent_process parent_process_hash parent_commandline child_process child_process_hash child_commandline
| sort -_time
```

### Step 3 — Risk-score by parent process

```spl
index=processes process="powershell.exe"
| eval risk_score=if(parent_process IN ("winword.exe","outlook.exe","cmd.exe"),90,30)
| table _time host user parent_process process risk_score
| sort -_time
```

| Parent → PowerShell | Assessment |
|---|---|
| `schtasks.exe` → `powershell.exe` | Requires investigation |
| `outlook.exe` → `powershell.exe` | Suspicious |
| `winword.exe` → `powershell.exe` | Highly suspicious |
| `svchost.exe` → `powershell.exe` | Likely benign |

### Step 4 — Child processes spawned by PowerShell

```spl
index=processes parent_process="powershell.exe"
| table _time host user process commandline process_hash
| sort -_time
```

---

## 2. New Local Administrator Account Created

**Example alert:**

| Field | Value |
|---|---|
| Severity | High |
| Host | FINANCE-LT-245 |
| User performing action | j.smith |
| New account created | backup_admin |
| Added to group | Administrators |
| Time | 02:13 AM (Bengaluru office) |

### Step 1 — Baseline the actor's history (30-day lookback)
Check how often `j.smith` creates accounts and adds them to admin groups, to establish whether this is routine or anomalous for this user.

```spl
index=windows sourcetype=windows:securitylogs EventCode IN ("4720","4728","4732") earliest=-30d latest=now
| search SubjectUserName="j.smith"
| table _time Source_Host SubjectUserName SubjectUserSID src_ip src_geolocation TargetUserName TargetUserSID EventCode EventName Action Process_PID
```

### Step 2 — Check what the new account did next

```spl
index=windows sourcetype=windows:securitylogs user_name="backup_admin"
| table _time host user_name SubjectUserName EventCode Event_Action Result
| sort -_time
```

### Step 3 — Frequency baseline

```spl
index=windows sourcetype=windows:securitylogs EventCode IN ("4624","4728","4732")
| search SubjectUserName="j.smith"
| stats count by SubjectUserName
```

### Step 4 — Add an after-hours risk flag

```spl
index=windows sourcetype=windows:securitylogs EventCode IN ("4720","4728","4732") SubjectUserName="j.smith"
| eval business_hours=if(date_hour>=19 OR date_hour<=6,100,30)
| table _time host SubjectUserName SubjectUserSID EventName action business_hours
| sort -_time
```

> **Fix applied:** original condition was `date_hour>=19 AND date_hour<=6`, which can never be true — no hour is both ≥19 and ≤6. That always scored 30 regardless of time, so a 2 AM alert like the example above would incorrectly read as low risk. Because the after-hours window spans midnight, it needs `OR`, not `AND`.

**Escalation logic:** if this is the first time `j.smith` has performed this action, and it happened outside business hours, escalate. If it's a frequent, routine action for this user, treat as lower priority.
