# Investigation Timeline

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

