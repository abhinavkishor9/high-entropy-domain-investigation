# Investigation Timeline

## Lab 96 — High-Entropy Domain Investigation

**Host:** `DESKTOP-9MMM37V`  
**Date:** `04 October 2026`  
**Workspace:** `C:\HighEntropyDomainLab\Evidence`

---

## Timeline

| Time | Event | Source | Assessment |
|---|---|---|---|
| 06:48 | High-Entropy Domain lab workspace created | PowerShell | Investigation setup |
| 06:48 | Host, OS, user, and investigation-time baselines collected | PowerShell | Baseline evidence |
| 06:xx | `microsoft.com` selected as test domain | PowerShell | Controlled test input |
| 06:xx | `microsoft` extracted as domain label | PowerShell | Entropy-analysis preparation |
| 06:xx | Shannon entropy calculated for `microsoft` | PowerShell | Entropy = `2.95` |
| 06:xx | `google.com` and `example.com` analyzed | PowerShell | Comparison baseline |
| 06:xx | Entropy results exported | PowerShell | Evidence preserved |
| 06:xx | `microsoft.com` resolved successfully | DNS / PowerShell | `150.171.109.132` observed |
| 06:xx | Ten controlled DNS resolutions performed | PowerShell | Test DNS activity generated |
| 06:17:23 | Sysmon Event ID 22 observed for test domain | Sysmon | DNS telemetry |
| 06:45:02.174 | Wazuh registry-integrity event observed | Wazuh | Unrelated FIM event |
| 06:49:48 | Sysmon Event ID 22 observed for test domain | Sysmon | DNS telemetry |
| 06:54:19 | Sysmon Event ID 22 observed for test domain | Sysmon | DNS telemetry |
| 06:59:26 | Sysmon Event ID 22 observed for test domain | Sysmon | DNS telemetry |
| 07:00:46–07:03:04 | Multiple Sysmon Event ID 1 events observed | Sysmon | Process telemetry; details incomplete |
| 07:xx | NXDOMAIN search performed | Sysmon | No matching text returned |
| 07:xx | Evidence inventory generated | PowerShell | Evidence preservation |

---

## Entropy Results

| Domain | Label | Length | Unique Characters | Entropy |
|---|---|---:|---:|---:|
| `microsoft.com` | `microsoft` | 9 | 8 | 2.95 |
| `google.com` | `google` | 6 | 4 | 1.92 |
| `example.com` | `example` | 7 | 6 | 2.52 |

---

## DNS Telemetry

The following Sysmon Event ID 22 timestamps contained the test domain in the captured results:

```text
04-10-2026 06:17:23
04-10-2026 06:49:48
04-10-2026 06:54:19
04-10-2026 06:59:26
```

These timestamps demonstrate DNS telemetry visibility.

They should not automatically be interpreted as proof that every event represents one of the ten PowerShell resolution attempts because DNS caching and resolver behavior can affect endpoint telemetry.

---

## Wazuh Event

At:

```text
04-10-2026 06:45:02.174
```

Wazuh reported a registry integrity change involving:

```text
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOffEndTimePerfCounter
```

The event reported changes to:

```text
MD5
SHA-1
SHA-256
```

No evidence established a relationship between this event and the DNS investigation.

Therefore it remains a separate FIM event.

---

## Process Telemetry

Sysmon Event ID 1 events were observed approximately from:

```text
04-10-2026 07:00:46
```

through:

```text
04-10-2026 07:03:04
```

The captured output contained only:

```text
Process Create:...
```

The available evidence did not provide enough detail to associate a specific process with the observed DNS queries.

---

## NXDOMAIN Assessment

The search for:

```text
NXDOMAIN
```

within the available Sysmon Event ID 22 message output returned no results.

Because the captured event representation may not expose DNS response status, the final assessment is:

```text
NXDOMAIN behavior: Unknown
```

---

## Final Timeline Assessment

The investigation established three primary evidence streams:

```text
DNS Resolution
       |
       +----> Sysmon Event ID 22
       |
       +----> Entropy Analysis

Process Telemetry
       |
       +----> Sysmon Event ID 1

Integrity Telemetry
       |
       +----> Wazuh FIM
```

The available evidence did not establish a causal relationship between all three streams.

In particular:

- The entropy values were not sufficient to establish DGA.
- DNS telemetry confirmed query visibility but did not establish malicious intent.
- Process telemetry was incomplete.
- NXDOMAIN behavior remained unknown.
- The Wazuh registry event was not correlated to the DNS activity.
- No malicious DNS command-and-control behavior was established.

---

## Final Classification

```text
Entropy analysis: Completed
DNS activity: Confirmed
Sysmon DNS telemetry: Confirmed
Process attribution: Not established
NXDOMAIN behavior: Unknown
DGA behavior: Not established
DNS C2: Not established
Wazuh DNS correlation: Not established
Overall finding: No malicious DNS activity established
```

> **The timeline supports DNS telemetry visibility and entropy analysis, but not a conclusion of malicious high-entropy or DGA activity.**
