# AWS Detection Notes

Splunk SPL queries and triage logic for AWS notable events.

---

## 1. AWS Console Login Without MFA

### Step 1 — Triage for brute force pattern
Check for multiple failed login attempts before a successful login, and confirm whether the same source IP was used.

```spl
index=aws sourcetype=aws:cloudtrail user="smit" action IN ("failure", "success")
| table _time src_ip src_geolocation user eventName action MFAUsed
| sort -_time
```

> **Fix applied:** original query had `action IN ("failure", "sucess")` — the misspelled "sucess" meant successful logins were silently excluded from results.

### Step 2 — Risk-score successful logins by MFA status

```spl
index=aws sourcetype=aws:cloudtrail action="success"
| eval risk_score = case(MFAUsed="No", "High", MFAUsed="Yes", "Low", true(), "Unknown")
| table _time user arn src_ip src_geo eventName MFAUsed risk_score
| sort -_time
```

> **Fix applied:** added a third bucket for missing/null `MFAUsed` values (`case()` instead of `if()`) — some CloudTrail events don't populate this field, and those were silently falling into "Low" risk before.

### Step 3 — Pivot to post-login activity
Once a no-MFA success login is confirmed, check what the user did afterward — this surfaces abnormal API calls (e.g. `ListS3Buckets`, `GetAccountInformation`).

```spl
index=aws user="smit" earliest="<login_time>"
| table _time src_ip src_geolocation user eventName action MFAUsed
| sort -_time
```

> AWS console login without MFA is not a security best practice — treat as a high-severity event regardless of downstream activity.

---

## 2. Multiple Failed Logins Followed by Success (Brute Force)

```spl
index=authentication user="smit" action IN ("success","failure")
| table _time user src_ip src_geolocation host action
| sort -_time
```

### Cross-reference against IAM status
Flag logins from terminated/inactive accounts.

```spl
(index=vpn OR index=authentication) action="success"
| lookup IAM_Inventory_Status_lookup user OUTPUT status
| search status IN ("terminated","inactive","resigned")
| eval risk_score=if(status IN ("terminated","inactive","resigned"),100,50)
| table _time user status src_ip src_geolocation action risk_score
| sort -_time
```

A lookup table (`user`, `status`, `action`) makes it possible to flag unauthorized access from accounts that should no longer be active — e.g. a "terminated" user with a "success" login.

---

## 3. Stale Authentication Credentials

Stale credentials are active credentials that haven't been used for an extended period. Query pending — typically built as a lookup of last-auth timestamps against an inactivity threshold (e.g. 90 days).

---

## 4. AWS GuardDuty Finding

### Step 1 — Pull the finding

```spl
index=aws sourcetype=aws:guardduty arn="<arn>"
| table _time aws_account_id aws_region arn username src_ip src_geolocation type severity title
| sort -_time
```

Common GuardDuty finding types:
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`
- `Recon:EC2/PortProbeUnprotectedPort`
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- `Discovery:IAMUser/AnomalousBehavior`

### Step 2 — Pivot to CloudTrail for context
Once the user, ARN, and account ID are known, pivot to CloudTrail around the finding's timeframe for full activity context.

```spl
index=aws sourcetype=aws:cloudtrail arn="<arn>" earliest="<guardduty_finding_time>" latest=now
| table _time aws_account_id aws_region user src_ip src_geolocation eventName
| sort _time
```
