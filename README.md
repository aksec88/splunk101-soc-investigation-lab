# Splunk 101 Capstone — FRONTDESK-PC1 Compromise Investigation

## Objective

Investigate a suspected endpoint compromise on FRONTDESK-PC1 reported by local administrator Ryan Adams after observing suspicious mouse movement on October 15, 2025 at approximately 13:00 UTC. Using Splunk and Sysmon telemetry, identify the infection vector, attacker behavior, command-and-control activity, persistence mechanisms, and produce a formal SOC investigation report.

---

## Skills Learned

- SIEM log analysis and threat hunting using Splunk (SPL)
- Process execution analysis using Sysmon EventCode 1
- Network connection correlation using Sysmon EventCode 3
- File creation tracking using Sysmon EventCode 11
- Parent-child process tree reconstruction
- Logon session correlation across multiple interactive sessions
- Hands-on-keyboard attacker activity identification
- Infection vector determination
- Persistence mechanism detection
- IOC extraction and documentation
- MITRE ATT&CK technique mapping
- SOC investigation report writing

---

## Tools Used

| Tool | Purpose |
|---|---|
| Splunk | SIEM platform for log ingestion, search, and analysis |
| Sysmon | Endpoint telemetry (process creation, network connections, file creation) |
| Windows Event Logs | Authentication and system activity |
| MITRE ATT&CK | Framework for mapping attacker techniques |

---

## Steps

### Step 1: Establish Scope

Defined the investigation boundaries based on the reported suspicious activity.

- Reported suspicious time: ~13:00 UTC
- Investigation window: 12:55–13:10 UTC
- Host: FRONTDESK-PC1
- User: KCD\Ryan.Adams

*Ref 1 — Splunk time picker set to investigation window (12:55–13:10 UTC on 10/15/2025)*

![Ref 1 — Splunk Time Range](screenshots/s1-time-range.png)

---

### Step 2: Identify Suspicious Process Execution

Performed a broad process creation sweep to identify all processes executed during the investigation window.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=1
| table _time Image CommandLine User ProcessGuid ParentImage ParentProcessGuid LogonId
| sort +_time
```

*Ref 2 — Broad process timeline showing normal activity (Chrome, OneDrive, rundll32) followed by python.exe at 13:00:33*

![Ref 2 — Broad Process Timeline](screenshots/s9-Broad-process-timeline.png)

Focused on high-risk binaries after identifying the initial anomaly.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=1
| search Image="C:\\Users\\Ryan.Adams\\Music\\python.exe"
        OR Image="*powershell.exe"
        OR Image="*schtasks.exe"
        OR (Image="*mmc.exe" AND CommandLine="*taskschd.msc*")
| eval CommandLineShort = substr(CommandLine, 1, 40) . "..."
| table _time Image ParentImage CommandLineShort User LogonId
| sort +_time
```

*Ref 3 — Focused malicious process timeline showing the full attack chain: python.exe → PowerShell → mmc.exe → schtasks.exe across two LogonIds*

![Ref 3 — Malicious Process Timeline](screenshots/s3.png)

---

### Step 3: Build the Process Tree

Pivoted on the malicious ProcessGuid to reconstruct the execution chain.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" ProcessGuid="{650091ea-9af1-68ef-8e0a-000000001500}"
| table _time Image CommandLine User LogonId ParentImage ParentProcessGuid
| sort +_time
```

*Ref 4 — python.exe process tree showing execution from C:\Users\Ryan.Adams\Music, launched by explorer.exe under LogonId 0xac65b1*

![Ref 4 — python.exe Process Tree](screenshots/s3-python-process-tree.png)

Confirmed python.exe session attribution.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=1
| search Image="C:\\Users\\Ryan.Adams\\Music\\python.exe"
| table _time Image User LogonId TerminalSessionId ParentImage
| sort +_time
```

*Ref 5 — python.exe execution details showing User KCD\Ryan.Adams, LogonId 0xac65b1, TerminalSessionId 2, Parent explorer.exe*

![Ref 5 — python.exe Execution Details](screenshots/s2-python-execution1.png)

---

### Step 4: Analyze PowerShell Activity

Identified all PowerShell sessions launched during the attack.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" Image="*powershell.exe" EventCode=1
| eval CommandLineShort = substr(CommandLine, 1, 40) . "..."
| table _time Image ParentImage CommandLineShort User LogonId
| sort +_time
```

*Ref 6 — PowerShell timeline showing four sessions: three launched by explorer.exe under LogonId 0xac65b1, one launched by RuntimeBroker.exe under LogonId 0xac64d7*

![Ref 6 — PowerShell Activity](screenshots/s4-powershell-activity.png)

---

### Step 5: Detect Persistence Mechanism

Identified Task Scheduler GUI and scheduled task creation.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" (Image="*schtasks.exe" OR Image="*mmc.exe") EventCode=1
| eval CommandLineShort = substr(CommandLine, 1, 40) . "..."
| table _time Image ParentImage CommandLineShort User LogonId
| sort +_time
```

*Ref 7 — Task Scheduler GUI (mmc.exe) opened under LogonId 0xac65b1 at 13:02:14, followed by schtasks.exe creating persistence*

![Ref 7 — mmc.exe Session 1](screenshots/s5-mmc-session1.png)

*Ref 8 — Second LogonId (0xac64d7) showing mmc.exe, PowerShell via RuntimeBroker.exe, and schtasks.exe creating the "PythonUpdate" task*

![Ref 8 — mmc.exe Session 2](screenshots/s6-mmc-session2.png)

Confirmed the scheduled task details.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" Image="*schtasks.exe" EventCode=1
| eval CommandLineShort = substr(CommandLine, 1, 40) . "..."
| table _time Image ParentImage CommandLineShort User LogonId
| sort +_time
```

*Ref 9 — schtasks.exe creating scheduled task "PythonUpdate" with /create /tn PythonUpdate /tr C:\Users\Ryan.Adams\Music\python.exe at SYSTEM level under LogonId 0xac64d7*

![Ref 9 — Scheduled Task Creation](screenshots/s7-schtasks-persistence.png)

---

### Step 6: Correlate Network Activity

Identified all network connections during the investigation window.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=3
| table _time Image SourceIp SourcePort dest_ip dest_port Protocol ProcessGuid User
| sort +_time
```

*Ref 10 — Full network timeline showing normal Defender/Chrome activity followed by python.exe connecting to C2 (157.245.46.190:8888) and internal recon (172.16.0.7:135, :49669)*

![Ref 10 — Network Activity](screenshots/s10-network-activity.png)

Pivoted on browser activity to trace the infection vector.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=3
| search Image="*chrome.exe" OR Image="*msedge.exe" OR Image="*iexplore.exe"
| table _time Image dest_ip dest_port ProcessGuid User
| sort +_time
```

*Ref 11 — Chrome network activity immediately before python.exe download, confirming browser-based delivery*

![Ref 11 — Browser Network Activity](screenshots/s8-malicious-processtimeline.png)

---

### Step 7: Identify Infection Vector

Confirmed how python.exe entered the system using file creation events.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=11
| search TargetFilename="*python.exe"
| table _time Image TargetFilename User ProcessGuid
| sort +_time
```

*Ref 12 — Chrome.exe created python.exe at 12:57:00 in C:\Users\Ryan.Adams\Music, confirming browser download as the infection vector*

![Ref 12 — File Creation Event](screenshots/s12-file-creation.png)

---

### Step 8: Logon Session Correlation

Correlated all malicious activity across two interactive logon sessions.

```spl
index="mydfir-lab1" host="FRONTDESK-PC1" EventCode=1
| search Image="*python.exe" OR Image="*powershell.exe" OR Image="*schtasks.exe" OR Image="*mmc.exe"
| table _time Image User LogonId TerminalSessionId ParentImage ProcessGuid
| sort +_time
```

*Ref 13 — All malicious processes mapped across two LogonIds: 0xac65b1 (initial execution, PowerShell, first mmc.exe) and 0xac64d7 (second mmc.exe, RuntimeBroker PowerShell, schtasks persistence)*

![Ref 13 — LogonId Correlation](screenshots/s13-logonid-correlation.png)

---

## Findings

- Timeframe: 2025-10-15 12:57:00–13:04:59 UTC
- Host: FRONTDESK-PC1
- User: KCD\Ryan.Adams
- Filename: python.exe
- File Path: C:\Users\Ryan.Adams\Music\python.exe
- SHA256: CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044
- SHA1: F83E0EA8A2350CEFDC686FC9EDFC06290AB79191
- MD5: DE070C106BD0EB0E092F31A2C4285020
- Execution Time: 2025-10-15 13:00:33 UTC
- Parent Process: C:\Windows\explorer.exe
- LogonId: 0xac65b1
- External C2 IP: 157[.]245[.]46[.]190:8888
- Internal Recon Target: 172[.]16[.]0[.]7 (ports 135, 49669)
- Persistence: Scheduled Task "PythonUpdate" (SYSTEM)
- Persistence LogonId: 0xac64d7
- Possible Malware Type: Python-based C2 Implant (Sliver associated)
- Hands-On Keyboard: Confirmed
- Lateral Movement: None observed

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 12:57:00 | python.exe downloaded via Chrome to C:\Users\Ryan.Adams\Music\ |
| 13:00:33 | python.exe executed by explorer.exe under LogonId 0xac65b1 |
| 13:00:34 | Outbound C2 connection established to 157.245.46.190:8888 |
| 13:00:34 | Internal RPC reconnaissance to 172.16.0.7 on ports 135 and 49669 |
| 13:00:44 | PowerShell launched, manual navigation into Music directory |
| 13:02:14 | Task Scheduler GUI (mmc.exe) opened under LogonId 0xac65b1 |
| 13:02:15 | Task Scheduler GUI opened again under LogonId 0xac64d7 |
| 13:03:57 | Additional PowerShell session launched |
| 13:04:08 | PowerShell launched with Set-Location into Music directory |
| 13:04:53 | PowerShell launched by RuntimeBroker.exe under LogonId 0xac64d7 |
| 13:04:59 | Scheduled task "PythonUpdate" created with SYSTEM privileges |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1204.002 | User Execution: Malicious File | python.exe downloaded via Chrome and executed by user |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Multiple interactive PowerShell sessions |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | "PythonUpdate" task created with SYSTEM privileges |
| Discovery | T1018 | Remote System Discovery | Internal RPC connections to 172.16.0.7 |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Outbound connection to 157.245.46.190:8888 |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | python.exe named to appear legitimate |

---

## Recommendations

1. Immediately isolate FRONTDESK-PC1 from the network
2. Remove the scheduled task "PythonUpdate" and delete python.exe from Music directory
3. Reset credentials for KCD\Ryan.Adams and perform full forensic review
4. Block IOC IP 157[.]245[.]46[.]190 at firewall, proxy, and endpoint layers
5. Sweep environment for python.exe in user-writable directories and scheduled task "PythonUpdate"
6. Implement monitoring for execution from user-writable directories, schtasks.exe with /ru SYSTEM, outbound traffic to uncommon high ports, and PowerShell launched from unusual parent processes
7. Implement application allowlisting and restrict local administrator privileges
8. Provide user awareness training regarding suspicious downloads
