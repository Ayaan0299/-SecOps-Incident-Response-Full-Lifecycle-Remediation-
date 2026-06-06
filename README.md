# [![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=800&size=28&duration=1500&pause=1000&color=B44FFF&width=1000&lines=MICROSOFT+SENTINEL+%7C+BRUTE+FORCE+DETECTION;KQL+ALERT+ENGINEERING+%7C+INCIDENT+RESPONSE;NIST+800-61+%7C+SOC+INVESTIGATION+WORKFLOW)](https://git.io/typing-svg)

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure">
  <img src="https://img.shields.io/badge/KQL-Detection%20Engineering-9B30FF?style=for-the-badge">
  <img src="https://img.shields.io/badge/NIST%20800--61-Incident%20Response-purple?style=for-the-badge">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20Brute%20Force-red?style=for-the-badge">
</p>

# Microsoft Sentinel: Brute Force Detection & Incident Response

> Deployed a scheduled KQL alert rule in Microsoft Sentinel to detect RDP brute force attempts against an Azure VM, triggered the detection, and worked the generated incident to closure following the NIST 800-61 Incident Response Lifecycle.

**Environment:** Microsoft Azure VM · Microsoft Sentinel · Log Analytics Workspace  
**Detection:** Scheduled Query Rule firing on 10 or more failed logons from the same remote IP within 5 hours  
**Data Source:** `DeviceLogonEvents` via Microsoft Defender for Endpoint  
**Framework:** NIST 800-61 Incident Response Lifecycle · MITRE ATT&CK T1110

---

## Table of Contents

- [Lab Architecture](#lab-architecture)
- [Part 1: Create Alert Rule](#part-1-create-alert-rule)
- [Part 2: Trigger Alert](#part-2-trigger-alert)
- [Part 3: Work Incident](#part-3-work-incident)
  - [Preparation](#preparation)
  - [Detection and Analysis](#detection-and-analysis)
  - [Containment, Eradication and Recovery](#containment-eradication-and-recovery)
  - [Post-Incident Activities](#post-incident-activities)
  - [Closure](#closure)
- [Skills Demonstrated](#skills-demonstrated)

---

## Lab Architecture

<!-- Add architecture diagram here -->

---
<img width="728" height="389" alt="image" src="https://github.com/user-attachments/assets/0763399b-7c26-46f9-922f-faf1edeff87a" />

## Part 1: Create Alert Rule

When entities attempt to log into a virtual machine, a log is created on the local machine and forwarded to Microsoft Defender for Endpoint under the `DeviceLogonEvents` table. These logs are then forwarded to the Log Analytics Workspace used by Microsoft Sentinel. A Scheduled Query Rule was built within Sentinel to trigger when the same remote IP address fails to log in to the same VM 10 or more times within a 5 hour period.

### KQL Query

```kql
DeviceLogonEvents
| where DeviceName == 'ayaan-vm-soc'
| where TimeGenerated >= ago(5h)
| where ActionType == 'LogonFailed'
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

The rule was created in **Sentinel → Analytics → Scheduled Query Rule** with the following settings:

- Rule enabled
- MITRE ATT&CK categories configured based on query behaviour
- Query runs every 4 hours
- Lookback window of 5 hours
- Entity mappings configured for RemoteIP and DeviceName
- Incident automatically created on trigger
- All alerts grouped into a single incident per 24 hours
- Query stops running after alert is generated

<!-- Add screenshot of rule configuration here -->

---

## Part 2: Trigger Alert

The rule was triggered by generating enough failed RDP logon attempts against `ayaan-vm-soc` to meet the detection threshold. Once 10 or more failures from the same remote IP were recorded within the 5 hour window, Sentinel fired the alert and automatically created an incident, visible under **Threat Management → Incidents**.

<!-- Add screenshot of triggered alert in Sentinel Incidents view here -->

<!-- Add screenshot of alert details and entity mappings here -->

---

## Part 3: Work Incident

The incident was worked to closure following the NIST 800-61 Incident Response Lifecycle.

---

### Preparation

- Roles, responsibilities, and procedures documented prior to investigation
- Microsoft Sentinel, MDE, and Log Analytics confirmed operational
- Tooling and access verified before beginning analysis

---

### Detection and Analysis

- Incident assigned to Ayaan Latif, status set to Active
- Investigated via **Actions → Investigate** and observed entity mappings
- Noted which remote IP addresses triggered the failures and which hosts were targeted
- Checked whether any of the brute force attempts resulted in a successful logon using the query below

```kql
let TargetDevice = "ayaan-vm-soc";
let SuspectIP = "<suspect-ip>";

DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

**Findings:** Brute force was not successful. No successful logons from any of the identified source IPs were recorded against `ayaan-vm-soc`.

<!-- Add screenshot of incident investigation and entity mappings here -->

---

### Containment, Eradication and Recovery

- In a real incident where the threat was serious, the VM would be isolated directly from Microsoft Defender for Endpoint, immediately cutting off all network communication whilst preserving access to the Defender management plane
- For this lab, the Network Security Group attached to `ayaan-vm-soc` was updated to restrict inbound RDP to my local IP only, blocking all public internet access to port 3389
- NSG was locked down to prevent further RDP attempts from the public internet
- No active threat to eradicate as the brute force did not result in a successful logon
- VM restored to normal operation with hardened NSG in place

<!-- Add screenshot of NSG rule update here -->

---

### Post-Incident Activities

- Findings documented within the incident record in Sentinel
- Lessons learned recorded noting that open NSGs significantly increase the attack surface for brute force campaigns
- Corporate policy proposed to enforce NSG hardening across all VMs using Azure Policy to prevent recurrence

---

### Closure

- Incident notes reviewed and resolution confirmed
- Incident closed within Sentinel as a **True Positive**

<!-- Add screenshot of closed incident here -->

---

## Skills Demonstrated

| Area | Detail |
|---|---|
| **Detection Engineering** | Scheduled Query Rule in Sentinel targeting repeated logon failures across a rolling time window |
| **KQL** | `summarize`, `count()`, `ago()`, `where`, `order by`, entity correlation across `DeviceLogonEvents` |
| **Incident Response** | Worked incident end to end following all five phases of the NIST 800-61 lifecycle |
| **SIEM** | Microsoft Sentinel alert configuration, entity mapping, incident management |
| **Cloud Security** | Azure VM, NSG hardening, Log Analytics Workspace, Defender for Endpoint telemetry |
| **MITRE ATT&CK** | Detection mapped to T1110 Brute Force and T1078 Valid Accounts |
