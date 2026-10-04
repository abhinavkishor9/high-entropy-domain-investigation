# Investigation Notes

## 1. Investigation Purpose

The investigation examines whether domain-name entropy can provide useful evidence for DNS threat hunting.

High-entropy domain labels may occur in DGA-generated domains or other suspicious DNS infrastructure, but entropy by itself cannot establish malicious intent.

The investigation therefore combines entropy analysis with DNS resolution, Sysmon telemetry, process telemetry, and Wazuh correlation.

---

## 2. Host Baseline

The lab evidence was collected from:

```text
DESKTOP-9MMM37V
```

The endpoint baseline and user context were saved before the DNS investigation.

Evidence files:

```text
Host-Baseline.txt
OS-Baseline.txt
Investigation-Time.txt
User-Context.txt
```

---

## 3. Test Domain

The initial test domain was:

```text
microsoft.com
```

The first DNS label was extracted using:

```powershell
$DomainLabel = ($TestDomain -split "\.")[0]
```

Result:

```text
microsoft
```

---

## 4. Shannon Entropy

A PowerShell function was used to calculate Shannon entropy:

```powershell
function Get-ShannonEntropy {
    param(
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return 0
    }

    $Length = $Text.Length

    $Groups = $Text.ToCharArray() |
        Group-Object

    $Entropy = 0

    foreach ($Group in $Groups) {
        $Probability = $Group.Count / $Length
        $Entropy -= $Probability * [Math]::Log($Probability, 2)
    }

    return [Math]::Round($Entropy, 4)
}
```

The test result for `microsoft` was:

```text
Length: 9
Unique Characters: 8
Entropy: 2.95
```

---

## 5. Comparison Domains

Three domains were compared:

| Domain | Length | Unique Characters | Entropy |
|---|---:|---:|---:|
| `microsoft.com` | 9 | 8 | 2.95 |
| `google.com` | 6 | 4 | 1.92 |
| `example.com` | 7 | 6 | 2.52 |

The results demonstrate that entropy varies naturally between ordinary domain labels.

No threshold was used to declare a domain malicious because there is no universal entropy value that independently establishes DGA activity.

---

## 6. DNS Resolution

The test domain resolved successfully:

```text
microsoft.com
```

Observed IPv4 address:

```text
150.171.109.132
```

The resolution output was saved to:

```text
DNS-Resolution.txt
```

---

## 7. Repeated DNS Resolution

Ten controlled DNS resolutions were performed with a five-second delay:

```powershell
$DNSResults = 1..10 | ForEach-Object {

    $Time = Get-Date

    $Result = Resolve-DnsName $TestDomain -Type A -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        Time = $Time
        Domain = $TestDomain
        IPAddresses = (
            $Result |
            Where-Object Type -eq "A" |
            Select-Object -ExpandProperty IPAddress
        ) -join ", "
    }

    Start-Sleep -Seconds 5
}
```

The results were saved to:

```text
DNS-Resolution-History.csv
```

Repeated resolution was used to generate observable DNS activity for endpoint telemetry.

---

## 8. Sysmon DNS Telemetry

Sysmon Event ID `22` was available.

The query:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 22
} -MaxEvents 20 |
Select-Object TimeCreated, Id, Message
```

returned multiple DNS query events.

The controlled domain was observed in the available Event ID 22 results at several timestamps:

```text
04-10-2026 06:17:23
04-10-2026 06:49:48
04-10-2026 06:54:19
04-10-2026 06:59:26
```

The events were saved to:

```text
Sysmon-DNS-Events.txt
```

---

## 9. DNS Telemetry Interpretation

The presence of Event ID 22 records confirms that DNS query telemetry was being collected.

However, the captured console output showed:

```text
Dns query:...
```

rather than complete event fields.

Therefore, the investigation cannot reliably determine the complete:

- Query process
- Query process ID
- User
- DNS response status
- Detailed query metadata

from the captured output alone.

This limitation is important because process correlation is required to determine whether unusual DNS activity originated from a suspicious executable or a legitimate application.

---

## 10. NXDOMAIN Investigation

A search was performed for NXDOMAIN within the available Sysmon Event ID 22 messages.

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

No results were returned.

### Assessment

The investigation does not establish that NXDOMAIN responses were absent.

The available event representation may simply not expose the DNS response status in the captured message.

Therefore:

```text
NXDOMAIN behavior = Unknown
```

rather than:

```text
NXDOMAIN behavior = None
```

---

## 11. Process Creation Telemetry

Sysmon Event ID `1` was reviewed.

Process creation events were observed between approximately:

```text
04-10-2026 07:00:46
04-10-2026 07:03:04
```

The available output contained abbreviated messages:

```text
Process Create:...
```

No complete image path, command line, parent process, or user context was available in the captured evidence.

Consequently, no specific process was attributed to the DNS activity.

---

## 12. Wazuh Investigation

The relevant Wazuh endpoint was:

```text
agent.id: 001
agent.name: DESKTOP-9MMM37V
```

A Wazuh registry-integrity event was observed at:

```text
04-10-2026 06:45:02.174
```

The event involved:

```text
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\LastLogOffEndTimePerfCounter
```

Changed attributes included:

```text
md5
sha1
sha256
```

### Correlation Assessment

The event does not contain evidence linking it to:

- `microsoft.com`
- Sysmon Event ID 22
- DNS resolution
- A suspicious process
- DGA activity

It is therefore treated as an independent Wazuh FIM event.

---

## 13. Timeline Correlation

The investigation produced several separate telemetry streams:

| Time | Evidence | Assessment |
|---|---|---|
| 06:17:23 | Sysmon EID 22 for test domain | DNS telemetry |
| 06:45:02 | Wazuh registry integrity event | Unrelated FIM event |
| 06:49:48 | Sysmon EID 22 for test domain | DNS telemetry |
| 06:54:19 | Sysmon EID 22 for test domain | DNS telemetry |
| 06:59:26 | Sysmon EID 22 for test domain | DNS telemetry |
| 07:00:46–07:03:04 | Sysmon EID 1 | Process telemetry |

Temporal proximity alone was not used to establish relationships between these events.

---

## 14. Evidence Classification

### Confirmed

- DNS resolution was successfully performed.
- Domain entropy was calculated.
- Multiple domains were compared.
- Sysmon Event ID 22 DNS telemetry was available.
- The test domain appeared in DNS telemetry.
- Sysmon Event ID 1 telemetry was available.
- Wazuh FIM telemetry was available.

### Plausible

The methodology is suitable for identifying domains that warrant additional investigation when higher entropy is combined with other suspicious DNS characteristics.

### Not Established

- DGA activity
- Malware-generated domain activity
- DNS command and control
- NXDOMAIN beaconing
- Malicious process attribution
- Malicious infrastructure
- A relationship between the Wazuh FIM event and DNS activity

---

