# High-Entropy Domain Investigation

## Overview

This lab investigates the use of **domain-name entropy as a DNS threat-hunting signal**. High-entropy or random-looking domain labels can sometimes be associated with Domain Generation Algorithms (DGA), malware command-and-control infrastructure, or dynamically generated DNS infrastructure.

The investigation uses a Windows endpoint to calculate Shannon entropy for domain labels, perform controlled DNS resolution, review Sysmon DNS Query events, examine process creation telemetry, and correlate available Wazuh data.

The investigation follows an evidence-first approach. A high entropy value is treated as an investigative signal rather than proof of malicious activity.

> **Follow the evidence, not the assumption.**

---

## Environment

| Item | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| Build | `10.0.26200` |
| PowerShell | 7.6.6 |
| Sysmon | Event ID 22 and Event ID 1 reviewed |
| Wazuh Agent | `001` |
| Lab Workspace | `C:\HighEntropyDomainLab\Evidence` |
| Investigation Date | 04 October 2026 |

---

## Investigation Objective

The objective was to determine whether unusual domain characteristics could be identified and whether DNS behavior could be correlated with endpoint telemetry.

The investigation focused on:

- Calculating Shannon entropy for domain labels.
- Comparing entropy across multiple domains.
- Performing controlled DNS resolution.
- Recording repeated DNS resolution activity.
- Reviewing Sysmon Event ID 22 DNS telemetry.
- Searching for NXDOMAIN-related telemetry.
- Reviewing Sysmon Event ID 1 process creation activity.
- Reviewing Wazuh endpoint telemetry.
- Separating relevant DNS evidence from unrelated integrity-monitoring events.
- Determining whether the evidence supports suspicious or malicious DNS behavior.

---

## Investigation Workflow

```text
Domain Selection
      |
      v
Domain Label Extraction
      |
      v
Shannon Entropy Calculation
      |
      v
Entropy Comparison
      |
      v
Controlled DNS Resolution
      |
      v
Sysmon Event ID 22
      |
      +------> NXDOMAIN Analysis
      |
      v
Sysmon Event ID 1
      |
      v
Wazuh Correlation
      |
      v
Timeline Analysis
      |
      v
Evidence-Based Assessment
```

---

## Domain Entropy Analysis

The initial test domain was:

```text
microsoft.com
```

The analyzed label was:

```text
microsoft
```

The calculated Shannon entropy was:

```text
2.95
```

Additional comparison:

| Domain | Label | Length | Unique Characters | Entropy |
|---|---|---:|---:|---:|
| `microsoft.com` | `microsoft` | 9 | 8 | 2.95 |
| `google.com` | `google` | 6 | 4 | 1.92 |
| `example.com` | `example` | 7 | 6 | 2.52 |

These values demonstrate the entropy-calculation methodology but do not establish that any of the domains are malicious.

---

## DNS Investigation

The controlled DNS resolution of `microsoft.com` returned:

```text
150.171.109.132
```

Repeated DNS resolution was performed ten times with a five-second delay between attempts.

The results were saved to:

```text
C:\HighEntropyDomainLab\Evidence\DNS-Resolution-History.csv
```

A DNS resolution record was also saved to:

```text
C:\HighEntropyDomainLab\Evidence\DNS-Resolution.txt
```

---

## Sysmon DNS Telemetry

Sysmon Event ID `22` was available on the endpoint.

DNS events were collected from:

```text
Microsoft-Windows-Sysmon/Operational
```

The controlled domain appeared in multiple Event ID 22 results, including:

```text
04-10-2026 06:17:23
04-10-2026 06:49:48
04-10-2026 06:54:19
04-10-2026 06:59:26
```

The presence of these events confirms that DNS query telemetry was available and that `microsoft.com` appeared in the collected Sysmon DNS data.

The events were saved to:

```text
C:\HighEntropyDomainLab\Evidence\Sysmon-DNS-Events.txt
```

The available output displayed only abbreviated `Dns query:...` messages, so detailed process and DNS response fields were not available from the captured console output.

---

## NXDOMAIN Analysis

A search for `NXDOMAIN` within the available Sysmon Event ID 22 messages returned no results.

This does **not** prove that no NXDOMAIN responses occurred.

The result is documented as a telemetry limitation because the captured Sysmon message output did not expose enough DNS response information to make a definitive determination.

---

## Process Telemetry

Sysmon Event ID `1` Process Create events were observed repeatedly between approximately:

```text
04-10-2026 07:00:46
04-10-2026 07:03:04
```

The captured output displayed abbreviated:

```text
Process Create:...
```

messages without complete process image, command-line, parent-process, or user fields.

Therefore, a specific process could not be reliably associated with the DNS activity using the captured evidence.

---

## Wazuh Correlation

A Wazuh registry-integrity event was observed at:

```text
04-10-2026 06:45:02.174
```

The event concerned:

```text
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOffEndTimePerfCounter
```

The event reported changes to MD5, SHA-1, and SHA-256 values.

Although the event occurred during the broader investigation period, there is no evidence connecting this registry modification to the DNS activity.

It is therefore treated as **unrelated Wazuh integrity telemetry**, not as evidence of malicious DNS behavior.

---

## Evidence Assessment

### Confirmed

- Shannon entropy calculation was successfully performed.
- `microsoft.com`, `google.com`, and `example.com` were compared.
- Controlled DNS resolution succeeded.
- Sysmon Event ID 22 DNS telemetry was available.
- The controlled domain appeared in Sysmon DNS telemetry.
- Sysmon Event ID 1 process creation telemetry was available.
- Wazuh registry-integrity telemetry was available.

### Not Established

- Malicious high-entropy domain activity.
- Domain Generation Algorithm (DGA) behavior.
- DNS-based command and control.
- NXDOMAIN-based beaconing.
- A suspicious process responsible for the observed DNS queries.
- Malicious network infrastructure.
- A relationship between the Wazuh registry event and DNS activity.

---

## Conclusion

The investigation demonstrated how domain entropy can be used as an initial DNS threat-hunting signal and confirmed that DNS activity was observable through Sysmon Event ID 22. The tested domains did not provide sufficient evidence to classify the activity as malicious, and the available telemetry did not establish DGA behavior, DNS command and control, or a suspicious process responsible for the queries.

The Wazuh registry-integrity event was documented separately because its registry path and available evidence did not establish a relationship with the DNS investigation.

The key lesson is that **entropy alone is insufficient for detection**. Stronger conclusions require correlation between domain characteristics, DNS frequency, timing, response behavior, process context, network destinations, and additional endpoint telemetry.

---

## Evidence Files

```text
Evidence/
├── Host-Baseline.txt
├── OS-Baseline.txt
├── Investigation-Time.txt
├── User-Context.txt
├── Domain-Entropy-Analysis.csv
├── DNS-Resolution.txt
├── DNS-Resolution-History.csv
├── Sysmon-DNS-Events.txt
└── Evidence-Inventory.txt
```

---

## Key Takeaway

> **High entropy is a signal, not a verdict.**

A domain should only become a stronger threat-hunting candidate when entropy is supported by additional evidence such as repeated randomized queries, unusual timing, NXDOMAIN patterns, suspicious process context, abnormal infrastructure, or other endpoint indicators.
