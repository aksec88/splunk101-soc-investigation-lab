# Password Spray → C2 Compromise Investigation
End‑to‑end SOC investigation of a simulated compromise at Kerning City Dental (KCD).

---

## Project Overview
Analyzed a full intrusion chain on FRONTDESK-PC1 after a user reported suspicious activity. Using Splunk, Windows Event Logs, Sysmon, Zeek, and Suricata, I traced the attack from a password spray to NTLM compromise, privilege escalation, Defender tampering, payload execution, and Sliver C2 communication. I confirmed attempted lateral movement, identified persistence via a scheduled task, validated IOCs with OSINT, and mapped all activity to MITRE ATT&CK. The investigation produced a complete timeline, detection opportunities, and remediation recommendations.

---

## Tools & Technologies
- Splunk SIEM (log aggregation, correlation, timeline analysis)
- Sysmon (process, file, and network telemetry)
- Windows Event Logs (authentication and security events)
- Zeek (network protocol visibility)
- Suricata (IDS alerts and C2 validation)
- MITRE ATT&CK (technique mapping)
- Threat Intelligence: VirusTotal, AbuseIPDB, ThreatFox

---

## Key Findings
- 157 failed password‑spray attempts led to a successful NTLM logon for Ryan.Adams.
- The attacker gained immediate administrative privileges after authentication.
- Microsoft Defender Real‑Time Protection was disabled under SYSTEM.
- A malicious `python.exe` payload was downloaded via Chrome and executed from a user directory.
- The host established Sliver C2 connections to **157[.]245[.]46[.]190** on ports **8888** and **9999**.
- Persistence was created through a scheduled task named **PythonUpdate**.
- RPC activity showed attempted lateral movement, but none succeeded.

---

## Investigation Highlights
- Correlated authentication, process, file, and network telemetry across all log sources.
- Reconstructed the full attack timeline from password spray to persistence.
- Identified key IOCs (IP, domain, file hash, payload path).
- Mapped activity to MITRE ATT&CK (11 techniques across 8 tactics).
- Built detection logic for brute‑force activity, payload execution, and C2 traffic.

---

## Investigation Evidence

### 1. Initial Access — Password Spray & NTLM Logon
![Password Spray](screenshots/01_Password_Spray_and_Successful_Logon.png)

---

### 2. Privilege Escalation
![Privilege Escalation](screenshots/02_Privilege_Escalation.png)

---

### 3. Defense Evasion — Defender Disabled
![Defender Disabled](screenshots/03_Defender_Disabled.png)

---

### 4. Payload Delivery
![Payload Delivery](screenshots/04_Payload_Delivery.png)

---

### 5. Payload Execution
![Payload Execution](screenshots/05_Payload_Execution.png)

---

### 6. Command & Control (C2) Traffic
![C2](screenshots/06_C2_Communication.png)

---

### 7. Suricata IDS Alerts
![Suricata Alerts](screenshots/07_Suricata_IDS_Alerts.png)

---

### 8. Persistence — Scheduled Task
![Persistence](screenshots/08_Persistence_Scheduled_Task.png)

---

### 9. Lateral Movement Attempt
![Lateral Movement](screenshots/09_Lateral_Movement_Validation.png)

---

### 10. Threat Intelligence — AbuseIPDB
![AbuseIPDB](screenshots/10_OSINT_AbuseIPDB.png)

---

### 11. Threat Intelligence — VirusTotal (Domain)
![VT Domain](screenshots/10_OSINT_VirusTotal_Domain.png)

---

### 12. Threat Intelligence — VirusTotal Detection Ratio
![VT Detection Ratio](screenshots/11_OSINT_VirusTotal_DetectionRatio.png)

---

### 13. Threat Intelligence — Sliver C2 Association
![VT Sliver](screenshots/11_OSINT_VirusTotal_Sliver.png)

---

## Lessons Learned
- Correlating Windows, Sysmon, Zeek, and Suricata logs made the attack path clear end‑to‑end.
- The password spray showed how weak lockout policies quickly lead to real compromise.
- Privileged access immediately after login stood out and requires closer monitoring.
- Defender being disabled (5001) was the key pivot point in the intrusion.
- Payload delivery via Chrome and execution from a user folder highlighted risky paths.
- RPC, authentication, and process correlation confirmed that lateral movement was attempted but failed.
- OSINT validation confirmed the external infrastructure was tied to Sliver C2.
- ATT&CK mapping made the detection and alerting gaps obvious.

---

## Detection Logic

| Detection Category                 | EventCodes / Sysmon IDs        | Evidence Activity |
|-----------------------------------|--------------------------------|-------------------|
| Password spraying                 | 4625                           | 157 failed logons from 172.16.0.184 across multiple accounts |
| Successful NTLM authentication    | 4624 (Logon Type 3)            | NTLM network logon for Ryan.Adams at 12:52:12 |
| Privilege escalation              | 4672                           | Special privileges assigned immediately after logon |
| Defender tampering                | 5001, 5007                     | Defender Real-Time Protection disabled under SYSTEM |
| Payload delivery (file creation)  | Sysmon 11                      | chrome.exe wrote python.exe to C:\Users\Ryan.Adams\Music |
| Payload execution                 | Sysmon 1                       | python.exe executed from user-writable directory |
| C2 communication                  | Sysmon 3, Zeek, Suricata       | Connections to 157.245.46.190 on ports 8888/9999 |
| Persistence via scheduled task    | Sysmon 1 (schtasks.exe)        | Task “PythonUpdate” created to run payload at startup |
| Lateral movement attempt (RPC)    | Sysmon 3                       | Connections to 172.16.0.7 on ports 135 and 49669 |
| OSINT infrastructure validation   | VT / AbuseIPDB                 | IP linked to Sliver C2, malicious detections and abuse reports |

Full SPL query set is provided in **spl_queries.txt**.

---

## Artifacts
- [**FRONTDESK‑PC1 Compromise_Report.pdf**](https://github.com/aksec88/splunk-soc-investigation-lab/blob/main/FRONTDESK%E2%80%91PC1%20Compromise_Report.pdf) — Full SOC investigation report  
- **spl_queries.txt** — Complete SPL query set  

*All analysis performed on simulated lab data as part of the MyDFIR Splunk-101 Capstone.*

---

**Kerning City Dental — FRONTDESK‑PC1 Compromise**  
**splunk101 SOC Investigation Capstone**  
**Analyst:** Abdul Kuyateh  

