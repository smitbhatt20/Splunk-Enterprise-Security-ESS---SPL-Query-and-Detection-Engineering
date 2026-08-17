# Azure Detection Notes

Splunk SPL queries and triage logic for Azure / Microsoft Entra ID notable events.

---

## 1. Microsoft Entra ID (Azure AD) High-Risk Sign-In

A high-risk sign-in can be triggered by:
- Sign-in from an unfamiliar location
- Anonymous IP / TOR usage
- Impossible travel
- Malware-linked IP
- Device not compliant or not Entra-joined
- Conditional Access policy failure
- Risky user account
- Suspicious token activity

### Step 1 — Pull sign-in context

```spl
index=azure sourcetype=azure:signinlogs user="smit"
| table _time user.account src_ip src_geolocation azure.signin.activity action application_accessed device_name device_detail compliance_status risk_level
| sort -_time
```

This query identifies:
1. User account
2. Source IP address
3. Geolocation
4. Device involved
5. Risk level assigned by Microsoft
6. Sign-in status
7. Conditional Access result

### Step 2 — Isolate high-risk sign-ins, last 7 days

```spl
index=azure sourcetype=azure:signinlogs user.account="smit" earliest=-7d latest=now risk_level="High"
| table _time src_ip src_geolocation device_name device_detail compliance_status risk_level application_accessed action
| sort -_time
```

Review and determine:
- Is the same device being used repeatedly?
- Is the same IP being used repeatedly?
- Is the same location being used repeatedly?
- Is the device consistently non-compliant?
- Is the user consistently generating high-risk sign-ins?

If this pattern repeats across multiple users, consider a dashboard to track and enforce Conditional Access policy compliance.
