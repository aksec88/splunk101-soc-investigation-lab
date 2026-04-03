## Password Spray to Endpoint Compromise and C2 (Sliver)

### Project Description
This project documents a SOC investigation into a successful password spraying attack that led to endpoint compromise, command-and-control (C2) communication, and the establishment of persistence on a Windows host.

### Objective
- Identify how the attacker gained initial access  
- Reconstruct attacker activity on the compromised endpoint  
- Determine whether persistence mechanisms were deployed  
- Assess whether the intrusion extended beyond the initial system  

### Skills Learned
- Log analysis using Splunk (Windows Event Logs and Sysmon)  
- Correlating authentication, process creation, and network activity  
- Identifying attacker behavior across multiple attack stages  
- Validating incident scope and containment  
- Applying threat intelligence to confirm malicious infrastructure  
- Mapping attacker actions to detection opportunities  

### Tools & Technologies (Purpose)
- **Splunk (SIEM):** Log aggregation, querying, and event correlation  
- **Sysmon:** Visibility into process execution and network connections  
- **Windows Event Logs:** Authentication and privilege-related activity  
- **Zeek:** Network connection and protocol analysis  
- **Suricata:** Detection of suspicious or malicious network traffic  

### Scenario
A user (Ryan Adams) reported unauthorized mouse movement on **FRONTDESK-PC1**, suggesting potential remote access.  
The investigation focused on identifying the source of compromise, reconstructing attacker activity, and determining whether additional systems were affected.

## Attack Chain

```
Password Spray → Account Compromise → Privilege Escalation → Defender Disabled → Payload Download → Execution → C2 Established → Lateral Movement Attempt → Persistence
```

## Investigation Methodology

### Step 1 — Establish Scope
Identified 7,013 events across 8 log sources and 53 event codes to determine available visibility.

### Step 2 — Authentication Analysis
Identified password spray attack from 172[.]16[.]0[.]184 targeting 4 accounts with 157 failed attempts in 73 seconds. Ryan.Adams compromised via NTLM at 12:52:12.

![Password Spray and Successful Logon](screenshots/01_Password_Spray_and_Successful_Logon.png)

Confirmed 6 privileged sessions with full administrative privileges assigned immediately after authentication.

![Privilege Escalation](screenshots/02_Privilege_Escalation.png)

### Step 3 — Process Execution & Persistence
Traced attacker activity from payload execution through PowerShell interaction to scheduled task creation.

![Payload Execution](screenshots/05_Payload_Execution.png)

Identified persistence mechanism: scheduled task "PythonUpdate" configured to run as SYSTEM on startup.

![Persistence Scheduled Task](screenshots/08_Persistence_Scheduled_Task.png)

### Step 4 — Payload Delivery & File Activity
Confirmed payload (python.exe) was downloaded via Chrome and written to a non-standard user-writable directory.

![Payload Delivery](screenshots/04_Payload_Delivery.png)

### Step 5 — Network Activity
Identified C2 communication to 157[.]245[.]46[.]190:8888 and internal RPC connections to 172[.]16[.]0[.]7.

![C2 Communication](screenshots/06_C2_Communication.png)

### Step 6 — Credential Access
Checked for LSASS access and credential dumping tools. No evidence found. The attacker relied on valid credentials from password spray.

### Step 7 — Defense Evasion
Confirmed Windows Defender Real-Time Protection was disabled at 12:55:50 under SYSTEM context, before payload delivery.

![Defender Disabled](screenshots/03_Defender_Disabled.png)

Investigated sethc.exe T1546.008 alert — ruled out as legitimate Windows accessibility initialization through IFEO registry checks and baseline comparison.

### Step 8 — IDS Detection
Suricata confirmed malicious traffic: executable download from dotted-quad host, malformed TLS, activity across ports 8888 and 9999.

![Suricata IDS Alerts](screenshots/07_Suricata_IDS_Alerts.png)

### Step 9 — Lateral Movement Validation
Confirmed all attacker activity confined to FRONTDESK-PC1. No credential reuse, malware spread, or C2 from other hosts.

![Lateral Movement Validation](screenshots/09_Lateral_Movement_Validation.png)

### Step 10 — Threat Intelligence (OSINT)
Validated C2 IP through multiple sources confirming Sliver C2 infrastructure.

![AbuseIPDB](screenshots/10_OSINT_AbuseIPDB.png)
![VirusTotal Detection Ratio](screenshots/11_OSINT_VirusTotal_DetectionRatio.png)
![VirusTotal Domain](screenshots/10_OSINT_VirusTotal_Domain.png)
![VirusTotal Sliver Association](screenshots/11_OSINT_VirusTotal_Sliver.png)

## Key Findings

- **Timeframe:** 2025-10-15 12:51:44–13:04:59 UTC  
- **Host:** FRONTDESK-PC1 (172.16.0.110)  
- **Compromised Account:** KCD\Ryan.Adams — Local Administrator  
- **Attacker Source:** 172.16.0.184 (DESKTOP-924H12)  
- **C2:** 157.245.46.190:8888, 9999 (AS14061 — DigitalOcean, London, UK)  
- **C2 Domain:** kajsdiqwe[.]icu  
- **C2 Framework:** Sliver  
- **Threat Type:** botnet_cc  
- **Confidence Level:** 46%  
- **Payload:** python.exe  
- **Payload Path:** C:\Users\Ryan.Adams\Music\python.exe  
- **Payload SHA256:** CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044  
- **Persistence:** Scheduled Task “PythonUpdate” (onstart /ru SYSTEM)  
- **Lateral Movement Target:** 172.16.0.7 (Ports 135, 49669)

## Scope & Impact

- Compromise contained to FRONTDESK-PC1
- No lateral movement to additional hosts
- No credential reuse on other systems
- No malware execution outside the affected endpoint
- No evidence of patient data access, modification, or exfiltration

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Password Spraying | T1110.003 | 157 failed authentication attempts from 172[.]16[.]0[.]184 across multiple accounts within 73 seconds |
| Initial Access | Valid Accounts | T1078.002 | Successful NTLM logon (Type 3) using compromised account Ryan.Adams from 172[.]16[.]0[.]184 |
| Execution | User Execution | T1204 | Malicious binary python.exe executed from user-writable directory |
| Execution | Command and Scripting Interpreter (PowerShell) | T1059.001 | Interactive PowerShell sessions observed post-compromise |
| Persistence | Scheduled Task | T1053.005 | Scheduled task PythonUpdate created to execute payload as SYSTEM at startup |
| Defense Evasion | Impair Defenses | T1562.001 | Microsoft Defender Real-Time Protection disabled under SYSTEM context (EventCode 5001) |
| Defense Evasion | Masquerading | T1036 | Payload named python.exe stored in non-standard path: C:\Users\Ryan.Adams\Music\ |
| Command and Control | Ingress Tool Transfer | T1105 | Payload downloaded via Chrome from external IP 157[.]245[.]46[.]190 |
| Command and Control | Application Layer Protocol | T1071 | C2 communication over TCP ports 8888 and 9999 using direct IP (no DNS) |
| Discovery | Remote System Discovery | T1018 | Internal RPC probing to 172[.]16[.]0[.]7 (port 135) |
| Lateral Movement | Remote Services | T1021 | RPC connections to 172[.]16[.]0[.]7 (ports 135, 49669); no successful movement observed |

8 tactics, 11 techniques observed.

## MITRE D3FEND Countermeasures

| D3FEND Tactic | Technique | Application to This Incident |
|---|---|---|
| Harden | Multi-factor Authentication | Prevents credential-only access even if the password is compromised |
| Harden | Strong Password Policy | Reduces password spray success rate |
| Harden | System Configuration Permissions | Prevents unauthorized modification of Defender settings |
| Harden | Credential Rotation | Limits window of compromised credential validity |
| Detect | Authentication Event Thresholding | Alerts on high-volume failed logons from a single source |
| Detect | Domain Account Monitoring | Identifies anomalous logon patterns for compromised accounts |
| Detect | Scheduled Job Analysis | Detects creation of suspicious scheduled tasks |
| Detect | Script Execution Analysis | Monitors interactive PowerShell activity post-compromise |
| Detect | Process Spawn Analysis | Flags execution from non-standard directories |
| Detect | Network Traffic Signature Analysis | IDS detection of executable download from dotted-quad host |
| Detect | RPC Traffic Analysis | Identifies internal RPC probing activity |
| Detect | System Daemon Monitoring | Detects unauthorized disabling of security services |
| Detect | File Hashing | Identifies known-bad binaries by SHA256 comparison |
| Detect | IP Reputation Analysis | Flags C2 infrastructure as malicious |
| Isolate | Executable Allowlisting | Blocks execution from user-writable directories |
| Isolate | Outbound Traffic Filtering | Blocks connections to known malicious infrastructure |
| Isolate | Broadcast Domain Isolation | Network segmentation limits lateral movement paths |
| Isolate | User Account Permissions | Enforces least-privilege for administrative accounts |
| Evict | Account Locking | Locks accounts after failed authentication threshold |
| Evict | Credential Revocation | Revokes compromised sessions |
| Evict | Process Termination | Terminates malicious processes |
| Evict | File Eviction | Removes malicious payload from disk |
| Restore | Restore Configuration | Re-enables Defender Real-Time Protection |
| Restore | Reissue Credential | Issues new credentials for compromised account |
| Restore | Restore Software | Reinstalls or validates endpoint security tools |

7 tactics, 25 techniques.

## Detection Opportunities

- **EventCode 4625** — High-volume failed logons from a single source (password spray indicator)
- **EventCode 5001** — Defender Real-Time Protection disabled (defense evasion)
- **Sysmon EventCode 1** — Execution from user-writable directory (C:\Users\*\Music\)
- **Sysmon EventCode 3** — Outbound connection to known malicious IP on non-standard port
- **Suricata** — Executable download from dotted-quad host (no DNS resolution)
- **Sysmon EventCode 1** — schtasks.exe creating SYSTEM-level scheduled task

## Recommendations

**Immediate (0–24 hours)**
- Isolate FRONTDESK-PC1 from the network
- Reset credentials for Ryan.Adams and revoke all active sessions
- Remove persistence: delete the scheduled task PythonUpdate and the malicious file
- Block 157[.]245[.]46[.]190, 172[.]16[.]0[.]184, and kajsdiqwe[.]icu
- Re-enable Microsoft Defender Real-Time Protection
- Investigate 172[.]16[.]0[.]7 for compromise indicators

**Short-term (1–7 days)**
- Implement account lockout policies
- Enforce application control (AppLocker / WDAC)
- Reduce NTLM usage, enforce Kerberos
- IOC sweep across the environment
- Verify audit policy for EventCode 4698

**Long-term (30–90 days)**
- Enforce MFA for all administrative accounts
- Deploy EDR with tamper protection
- Enhance centralized logging and monitoring
- Security architecture review: privileged access management, network segmentation, endpoint hardening

## Lessons Learned

- **Evidence drives the investigation, not checklists.** Early iterations included redundant queries that repeated findings from earlier steps. Restructuring the investigation to let each finding drive the next question eliminated duplication and improved clarity.

- **Validate every IOC before it goes in a report.** The initial payload hash was incorrect — it belonged to sethc.exe, not python.exe. A verification query caught the mistake before submission. In a production environment, a wrong hash in an IOC list could misdirect an entire response effort.

- **Negative findings have value when investigated properly.** The sethc.exe T1546.008 alert required a full investigation (process execution, IFEO registry, baseline comparison) before it could be ruled out. Documenting why something is benign is as important as documenting what is malicious.

- **Log gaps are findings too.** EventCode 4698 (scheduled task creation) was missing from Security logs. Persistence was identified through Sysmon instead. This gap became a recommendation — not just a note.

- **Understanding attacker methodology matters more than memorizing queries.** Knowing that Defender was disabled before the payload was delivered (not after) changed the investigation direction and led to the root cause analysis of how it was disabled remotely.

## Author

**Abdul Kuyateh** — SOC Analyst

---

*This project was completed as part of the MyDFIR Splunk 101 Capstone. All analysis was performed on simulated lab data.*
