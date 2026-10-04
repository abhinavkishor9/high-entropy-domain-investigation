# Troubleshooting Notes

## Lab 96 — High-Entropy Domain Investigation

---

## 1. Sysmon Event ID 22 Returned Abbreviated Messages

### Observation

The PowerShell output displayed:

```text
Dns query:...
```

rather than the complete DNS event contents.

### Impact

The investigation could confirm that Event ID 22 telemetry existed, but the captured output did not expose all useful fields such as:

- Query name
- Process image
- Process ID
- User
- Response status

### Resolution

The investigation continued using Event ID 22 as evidence of DNS telemetry availability.

A stronger future collection method should extract the complete XML/event properties instead of relying only on the formatted `Message` field.

### Lesson

Do not infer missing process or DNS response information from an abbreviated event message.

---

## 2. NXDOMAIN Search Returned No Results

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "NXDOMAIN"
} |
Select-Object TimeCreated, Message
```

### Result

No output was returned.

### Interpretation

This does not prove that the endpoint had no NXDOMAIN responses.

The available Sysmon message representation may not expose the DNS response status.

### Correct Assessment

```text
NXDOMAIN behavior: Unknown
```

not:

```text
NXDOMAIN behavior: None
```

---

## 3. Test Domain Was a Normal Domain

### Observation

The test domain was:

```text
microsoft.com
```

The calculated entropy of the `microsoft` label was:

```text
2.95
```

### Issue

The domain was intentionally used as a legitimate comparison point, but it does not represent a high-confidence malicious or DGA-style domain.

### Resolution

The result was treated as a baseline rather than as malicious evidence.

The investigation focused on demonstrating the methodology:

```text
Entropy calculation
        +
DNS behavior
        +
Endpoint telemetry
        =
Stronger assessment
```

### Lesson

A normal domain can have relatively high entropy compared with another normal domain. Entropy must not be treated as a binary malicious/benign threshold.

---

## 4. Entropy Alone Was Not Used as a Detection Threshold

### Observation

The comparison produced:

```text
microsoft.com → 2.95
google.com    → 1.92
example.com   → 2.52
```

### Issue

There is no universal Shannon entropy value that independently proves DGA activity.

### Resolution

No fixed threshold was used to label a domain malicious.

The investigation instead considered:

- Entropy
- Length
- Character diversity
- Query frequency
- Timing
- DNS response behavior
- Process context
- Network context

---

## 5. Repeated DNS Resolution Did Not Automatically Mean Beaconing

### Observation

Ten DNS resolution attempts were generated with a five-second delay.

### Issue

Repeated DNS queries can occur for many legitimate reasons.

### Resolution

The activity was treated as controlled test traffic.

Repeated DNS activity would become more interesting when combined with:

- Randomized domains
- Regular intervals
- NXDOMAIN responses
- Multiple generated domains
- Suspicious processes
- Unusual destination infrastructure

### Lesson

A repeated query pattern alone is not sufficient evidence of DNS command and control.

---

## 6. DNS Results May Be Affected by Caching

### Observation

Repeated `Resolve-DnsName` operations were performed against the same domain.

### Consideration

DNS caching and resolver behavior can affect how frequently a DNS request reaches the network.

### Impact

The ten PowerShell resolution attempts should not automatically be interpreted as ten independent external DNS transactions.

### Lesson

When investigating DNS behavior, distinguish:

```text
Application-level DNS resolution
```

from:

```text
Observed DNS network activity
```

Endpoint telemetry should be used to establish what actually occurred.

---

## 7. Sysmon Event ID 1 Output Was Incomplete

### Observation

Process creation results were displayed as:

```text
Process Create:...
```

### Impact

The available evidence did not expose:

- Process image
- Command line
- Parent process
- Process ID
- User

### Resolution

Process telemetry was retained as evidence that Event ID 1 was available, but no specific process was attributed to the DNS activity.

### Lesson

Do not assign process responsibility without a reliable process identifier, timestamp, or other correlation evidence.

---

## 8. Wazuh Registry Event Was Not Automatically Correlated

### Observation

Wazuh reported:

```text
Winlogon\LastLogOffEndTimePerfCounter
```

with changed MD5, SHA-1, and SHA-256 values.

### Issue

The event occurred during the broader investigation period, but no evidence connected the registry change to DNS activity.

### Resolution

The event was documented separately as Wazuh FIM telemetry.

### Correct Interpretation

```text
Wazuh FIM event = confirmed
Relationship to DNS investigation = not established
```

### Lesson

An alert occurring near another event does not automatically make the two events part of the same attack chain.

---

## 9. Wazuh Agent Identity

For endpoint-specific investigation, use:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Avoid using Wazuh manager events as endpoint evidence.

The investigation should remain scoped to the Windows endpoint before interpreting DNS or Sysmon-related Wazuh data.

---

## 10. Evidence Inventory

The evidence directory was created at:

```text
C:\HighEntropyDomainLab\Evidence
```

The final inventory was generated with:

```powershell
Get-ChildItem $EvidencePath |
Select-Object Name, Length, LastWriteTime |
Out-File "$EvidencePath\Evidence-Inventory.txt"
```

This provides a basic record of the collected investigation artifacts.

---

## 11. General Investigation Lesson

The main troubleshooting lesson from this lab is:

```text
Missing telemetry ≠ no activity
```

and:

```text
Unusual telemetry ≠ malicious activity
```

Both situations require additional validation before reaching a conclusion.

The investigation therefore records:

- What was observed
- What was not observed
- What could not be determined
- Why the evidence was insufficient
- What additional telemetry would improve confidence

This prevents unsupported conclusions from being introduced into the investigation.
