# CrowdStrike — Host Silence Detection (2+ Hours)

Detects servers that have stopped sending sensor events to the Falcon cloud for more than 2 hours.
Can indicate legitimate downtime, patching, or sensor tampering/evasion.

---

## Falcon Event Search (SPL — Classic)

### Base Query

```spl
index=main sourcetype=crowdstrike* earliest=-24h
| stats max(_time) as last_seen by aid, ComputerName, aip
| eval hours_silent = round((now() - last_seen) / 3600, 2)
| where hours_silent >= 2
| eval last_seen_readable = strftime(last_seen, "%Y-%m-%d %H:%M:%S UTC")
| sort -hours_silent
| table ComputerName, aid, aip, last_seen_readable, hours_silent
```

### Scoped to Servers Only (adjust naming pattern to your environment)

```spl
index=main sourcetype=crowdstrike* earliest=-24h event_platform=Win
| search ComputerName IN ("SRV*", "DC*", "*-PROD-*")
| stats max(_time) as last_seen by aid, ComputerName, aip
| eval hours_silent = round((now() - last_seen) / 3600, 2)
| where hours_silent >= 2
| eval last_seen_readable = strftime(last_seen, "%Y-%m-%d %H:%M:%S UTC")
| sort -hours_silent
| table ComputerName, aid, aip, last_seen_readable, hours_silent
```

### With Severity Tiering

```spl
index=main sourcetype=crowdstrike* earliest=-24h
| stats max(_time) as last_seen by aid, ComputerName, aip
| eval hours_silent = round((now() - last_seen) / 3600, 2)
| where hours_silent >= 2
| eval severity = case(
    hours_silent >= 8,  "Critical",
    hours_silent >= 4,  "High",
    hours_silent >= 2,  "Medium"
  )
| eval last_seen_readable = strftime(last_seen, "%Y-%m-%d %H:%M:%S UTC")
| sort -hours_silent
| table ComputerName, aid, aip, last_seen_readable, hours_silent, severity
```

---

## Falcon Next-Gen SIEM (LogScale Query Language)

```logscale
// Find servers whose sensor has stopped communicating for more than 2 hours
// Uses connectivity/heartbeat events only — not security events — to avoid false positives
// on quiet-but-online servers that simply aren't generating security telemetry
// HostType = "Server" covers Windows, Linux, and macOS servers cross-platform
#event_simpleName = /^(AgentConnect|SensorHeartbeat|AgentOnline)$/
| HostType = "Server"
| groupBy([aid, ComputerName, LocalAddressIP4, HostType], function=[
    max(@timestamp, as=last_seen),
    count(as=total_events)
  ])
| silence_ms := now() - last_seen
| silence_hours := silence_ms / 3600000
// Lower bound: 2 hours = newly went silent
// Upper bound: 48 hours = likely decommissioned or already-known long-term outage
| silence_hours >= 2
| silence_hours <= 48
| sort(silence_hours, order=desc)
| select([ComputerName, aid, LocalAddressIP4, HostType, last_seen, silence_hours, total_events])
```

**Tuning Notes:**

| Tuning | Mechanism | Adjust If... |
|---|---|---|
| Decommissioned host exclusion | `silence_hours <= 48` upper bound | You want a wider window before assuming decommissioned |

---

## Correlation Rule Setup

| Setting | Value |
|---|---|
| Rule Type | Scheduled Search |
| Schedule | Every 30–60 minutes |
| Lookback Window | `earliest=-3h` |
| Alert Threshold | Result count >= 1 |

### Severity Thresholds

| Hours Silent | Severity |
|---|---|
| 2–4 hours | Medium |
| 4–8 hours | High |
| 8+ hours | Critical |

### Key Fields to Surface in Alert

| Field | Purpose |
|---|---|
| `ComputerName` | Host identifier |
| `aid` | CrowdStrike agent ID |
| `hours_silent` | Duration offline |
| `aip` | Last known IP |

---

## Notes

- Suppress alerts during known maintenance windows using a lookup table or CrowdStrike Host Groups
- Alert fires for both legitimate downtime AND potential sensor tampering — triage accordingly
- Adjust the `ComputerName` filter pattern to match your environment's server naming convention
