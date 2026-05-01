# CrowdStrike — Workstation Business Hours Silence Detection

Detects workstations that were active during the current business day but have gone silent for 2+ hours.
Scoped to Mon–Fri 9am–5pm to avoid noise from overnight/weekend shutdowns.

---

## Falcon Next-Gen SIEM (LogScale)

```logscale
// Workstations silent 2+ hours during business hours (Mon-Fri, 9am-5pm)
// ProductType 1 = Workstation only
#event_simpleName = /^(AgentConnect|SensorHeartbeat|AgentOnline)$/
| ProductType = "1"
// Exclude non-prod workstations by naming convention — adjust to your environment
| not regex("(?i)(dev|test|uat|qa|lab|sandbox)", field=ComputerName)
| groupBy([aid, ComputerName, LocalAddressIP4], function=[
    max(@timestamp, as=last_seen),
    count(as=total_events)
  ])
| silence_ms := now() - last_seen
| silence_hours := silence_ms / 3600000
// 2–10 hour window: active today but went silent
// Upper bound of 10h excludes hosts that simply never came online this morning
| silence_hours >= 2
| silence_hours <= 10
// Business hours gate — only surface results Mon–Fri 9am–5pm
// Adjust timezone to match your environment
| now_ts := now()
| current_hour := formatTime("%H", field=now_ts, timezone="America/Chicago")
| current_dow  := formatTime("%a", field=now_ts, timezone="America/Chicago")
| not regex("Sat|Sun", field=current_dow)
| current_hour >= "09"
| current_hour < "17"
| sort(silence_hours, order=desc)
| select([ComputerName, aid, LocalAddressIP4, last_seen, silence_hours, total_events])
```

---

## How the Business Hours Gate Works

| Field | Logic | Purpose |
|---|---|---|
| `not regex("Sat\|Sun", field=current_dow)` | `%a` gives abbreviated day name (Mon…Sun) | Drops Saturday and Sunday entirely |
| `current_hour >= "09"` | `%H` is zero-padded 2-digit 24h string | No alerts before 9am |
| `current_hour < "17"` | String comparison works correctly on zero-padded values | No alerts after 5pm |
| `silence_hours <= 10` | Upper bound | Excludes hosts that never came online today (off since yesterday evening) |

The business hours gate acts as a global pass/fail on the result set — if the query runs outside business hours, it returns zero results and the correlation rule fires no alert.

---

## Correlation Rule Setup

| Setting | Value |
|---|---|
| Rule Type | Scheduled Search |
| Schedule | Every 30–60 minutes |
| Lookback Window | `earliest=-12h` |
| Alert Threshold | Result count >= 1 |

Run the schedule continuously — the in-query time filter handles suppression outside business hours. No need to configure a time-restricted schedule in the rule itself.

---

## Severity Guidance

Unlike servers, workstation silence during business hours is often lower severity unless:
- The workstation belongs to a privileged user (admin, executive, service account owner)
- The silence coincided with a known incident or active threat campaign
- Multiple workstations go silent in the same subnet simultaneously (lateral movement / wiper indicator)

| Condition | Suggested Severity |
|---|---|
| Single workstation, no context | Low |
| Privileged user workstation | Medium |
| 3+ workstations silent in same subnet | High |
| During active incident | Critical |

---

## Notes

- Adjust `timezone` to match your org's primary location (`America/New_York`, `America/Chicago`, `America/Los_Angeles`, etc.)
- If your org spans multiple time zones, consider running separate rules per region with different timezone values
- Pair with the server silence rule ([crowdstrike_host_silence_detection.md](crowdstrike_host_silence_detection.md)) for full endpoint coverage
