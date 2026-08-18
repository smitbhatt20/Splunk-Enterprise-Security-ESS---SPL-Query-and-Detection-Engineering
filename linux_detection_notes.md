# Notable Event: Successful Root Login After SSH Authentication

## Alert Details

**Severity:** High

**Host:** ubuntu-prod-01

**User:** root

**Source IP:** 185.100.87.12

**Failed Logins:** 25

**Successful Login:** Yes

**Time:** 03:12 AM IST

---

# Description

This alert indicates a successful root login following SSH authentication activity.

The primary objective is to determine whether the access was legitimate administrative activity or the result of:

- Brute Force Attack
- Privilege Escalation
- Unauthorized SSH Access
- Persistence Establishment
- Malicious User Activity

---

# Investigation Workflow

```text
SSH Authentication Activity
          ↓
Successful Root Login
          ↓
Identify Original User
          ↓
Review User Activity
          ↓
Review Root Activity
          ↓
30-Day Baselining
          ↓
Risk Assessment
          ↓
Escalation
```

---

# I. Review Authentication Activity

### SPL Query

```spl
index=linux source="/var/log/auth.log" sourcetype=.log user="root" action IN ("failed","success")
| table _time user host src_ip action eventName
| sort -_time
```

### Purpose

Review successful and failed SSH authentication events.

### Investigation Questions

1. Were multiple failures seen before success?
2. Was the same IP used?
3. Was brute force observed?
4. Was the source IP expected?

---

# II. Identify Original User Before Root Access

### SPL Query

```spl
index=linux sourcetype=linux:syslog user="root" host="ubuntu-prod-01" source_ip="185.100.87.12"
| search command_line="sudo su"
| table _time host source_ip source_geolocation user original_user eventName action
| sort -_time
```

### Purpose

Determine whether root access was obtained through privilege escalation.

### Investigation Questions

1. Was it a direct root login?
2. Was sudo used?
3. Who was the original user?
4. Is the original user authorized?

---

# III. Review Original User Activity

### SPL Query

```spl
index=linux sourcetype=linux:syslog original_user="<identified_user>" host="ubuntu-prod-01"
| table _time host source_ip source_geolocation original_user user eventName action command_line
| sort -_time
```

### Purpose

Review activities executed before the user obtained root privileges.

### Investigation Questions

1. What was the user doing before becoming root?
2. Were suspicious commands executed?
3. Was software downloaded?
4. Was privilege escalation anticipated?

### Examples

```text
wget
curl
chmod
scp
nc
sudo su
```

---

# IV. Establish Historical Baseline

### SPL Query

```spl
index=linux sourcetype=linux:syslog user="root" original_user="<identified_user>" host="ubuntu-prod-01" earliest=-30d latest=now
| search command_line IN ("sudo su","usermod -aG sudo <username>")
| stats count as Number_of_Times_logged_as_root by command_line
| eval risk_score=if(Number_of_Times_logged_as_root<3,85,0)
| table command_line Number_of_Times_logged_as_root risk_score
```

### Purpose

Determine whether root access is normal behavior for the identified user.

### Investigation Questions

1. Has the user performed root actions before?
2. How frequently is root used?
3. Is this the first occurrence in 30 days?
4. Is the behavior consistent with historical activity?

### Risk Logic

```text
Root Activity Occurrences < 3
           ↓
Rare Behavior
           ↓
Risk Score = 85

Root Activity Frequently Observed
           ↓
Expected Behavior
           ↓
Risk Score = 0
```

---

# V. Build Event Timeline

After identifying the successful root login timestamp, investigate activities before and after the event.

### SPL Query

```spl
index=linux host="ubuntu-prod-01" earliest="root_login_time" latest=now
| table _time user command_line action eventName
| sort _time
```

### Purpose

Reconstruct the attack timeline.

### Look For

```text
useradd
passwd
usermod
crontab
systemctl
authorized_keys modification
wget
curl
chmod
```

---

# Escalation Criteria

Escalate the incident if any of the following are observed:

- Multiple failed SSH logins followed by success
- Successful root login from an unusual IP
- Privilege escalation via sudo
- First-time root activity within 30 days
- New user creation
- SSH authorized_keys modification
- Scheduled task or cron creation
- Download and execution of external payloads
- Persistence mechanisms established

---

# Benign Scenario

```text
Known Administrator
Known Source IP
Expected Maintenance Window
Previously Observed Root Activity
```

---

# Suspicious Scenario

```text
Multiple Failed SSH Attempts
Unusual Source IP
First-Time Root Activity
Privilege Escalation
Persistence Creation
Payload Download
Lateral Movement
```

---

# Analyst Notes

A successful root login should never be considered suspicious solely because root access occurred.

The investigation should focus on:

1. Authentication history
2. Source IP reputation
3. User behavior
4. Privilege escalation path
5. Activities executed after root access
6. Historical usage patterns

Proper baselining over a 30-day period helps distinguish legitimate administrative activity from unauthorized access.