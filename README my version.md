# high-entropy-domain-investigation
## Overview
A high-entropy domain is a domain containing a relatively random-looking sequence of characters. Such domains can appear in Domain Generation Algorithms (DGA) used by malware to generate large numbers of possible command-and-control domains.

For example, a normal domain might look like:

updates.example.com

A suspicious-looking generated label might resemble:

x7k2m9q4v8p1.example.com

The important point is that high entropy alone does not prove malicious activity. Legitimate applications, CDNs, cloud services, tracking systems, and dynamically generated hostnames can also produce unusual-looking domains.


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

## Lab Objectives

- Establish a documented baseline for the Windows endpoint, operating system, user context, and investigation environment.
- Select a controlled DNS domain and extract the relevant domain label for entropy analysis.
- Implement Shannon entropy calculation in PowerShell to measure the character randomness of domain labels.
- Compare entropy values across multiple legitimate domains to understand normal variation in domain-name characteristics.
- Record the length and unique-character count of each analyzed domain label as additional context for entropy analysis.
- Perform controlled DNS resolution and preserve the resulting DNS information as investigation evidence.
- Generate repeated DNS resolution activity to create observable endpoint DNS telemetry.
- Identify and review Sysmon Event ID 22 DNS Query events associated with the investigation.
- Determine whether the controlled domain is visible within the available Sysmon DNS telemetry.
- Investigate whether available DNS telemetry provides useful response information such as NXDOMAIN status.
- Review Sysmon Event ID 1 Process Create events around the DNS investigation window.
- Assess whether the available process telemetry is sufficient to associate DNS activity with a specific process.
- Review endpoint-specific Wazuh telemetry for events occurring during the investigation period.
- Distinguish DNS-related evidence from unrelated Wazuh events, such as registry integrity monitoring alerts.
- Correlate domain characteristics, DNS activity, timestamps, process telemetry, and Wazuh events without assuming that temporally adjacent events are related.
- Identify telemetry limitations that prevent stronger conclusions, including incomplete event fields or unavailable DNS response information.
- Determine whether the observed evidence supports normal DNS activity, suspicious DNS behavior, DGA activity, or an inconclusive finding.
- Document the investigation using an evidence-based classification of confirmed, plausible, and unknown findings.
- Preserve the collected artifacts and maintain a clear investigation timeline for future analysis.
  
---

## Lab Scenario

A Windows endpoint is being investigated for potentially unusual DNS activity involving domain names with high character entropy. High-entropy domains can sometimes appear in Domain Generation Algorithm (DGA) activity, malware command-and-control infrastructure, or other dynamically generated DNS patterns. However, legitimate services can also use domains or hostnames that appear random, so entropy alone cannot be treated as evidence of compromise.

The investigation begins by establishing the endpoint and user baseline, followed by controlled DNS resolution and calculation of Shannon entropy for several domain labels. The analyst will compare the results to understand whether the observed entropy is unusual in context.

The investigation will examine:

- Domain length, character diversity, and Shannon entropy.
- Entropy differences between multiple legitimate domains.
- Controlled and repeated DNS resolution activity.
- Sysmon Event ID 22 DNS Query telemetry.
- Sysmon Event ID 1 Process Create telemetry around the investigation window.
- Available DNS response information, including potential NXDOMAIN indicators.
- Wazuh endpoint telemetry occurring during the same period.
- Whether seemingly related events can actually be correlated using timestamps and available context.

The analyst will specifically avoid treating a high entropy value as proof of DGA or malicious activity. DNS behavior must be evaluated together with frequency, timing, process context, response behavior, and other available endpoint evidence.

The controlled DNS activity provides a known reference point for examining endpoint telemetry. Sysmon DNS events are reviewed to determine whether the test domain is visible, while process creation events are examined for potentially relevant execution context.

Wazuh telemetry is also reviewed, but unrelated events are kept separate from the DNS investigation unless evidence establishes a meaningful relationship. In this lab, a registry-integrity event is treated independently because its available details do not establish a connection to the DNS activity.

The investigation must also document telemetry limitations. Incomplete Sysmon event fields or unavailable DNS response information should be recorded as limitations rather than interpreted as proof that an event did not occur.

The investigation should determine whether the observed domain characteristics and DNS behavior provide sufficient evidence of suspicious activity. The final assessment should distinguish between normal or explainable DNS behavior, activity that warrants additional investigation, evidence consistent with DGA or DNS-based command and control, and insufficient telemetry to make a stronger determination.

> **High entropy is an investigative signal, not a verdict.**


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

