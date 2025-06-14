# SOC-Automation-Lab
# Introduction
The SOC Automation Lab project is a self-contained cybersecurity home lab designed to simulate real-world attack and defense scenarios using open-source tools. It focuses on building hands-on skills in threat detection, log analysis, and automated alerting—key components of a Security Operations Center (SOC).

This lab setup demonstrates how a simulated attacker (Kali Linux) launches various attacks such as Nmap scans and reverse shells against a victim machine (Windows), which in turn forwards logs to a centralized Wazuh SIEM (Security Information and Event Management) server. The Wazuh platform is configured to monitor, detect, and alert on suspicious behavior using custom rules and log-based detections.

# Setup Requirements
| Category                 | Requirements                                       |
|--------------------------|---------------------------------------------------|
| **Operating Systems**    | - Ubuntu VM (22 version) <br> - Windows 10 VM <br> - Kali Linux VM |
| **System Requirements**  | - RAM: 8GB or 16GB  <br> - Internet Connection: Required for downloads and updates |
| **Logging & Monitoring Tools** | - Wazuh (Open-Source SIEM) <br> - Sysmon (System monitoring & event logging) |

# Lab Architecture & Topology
### Diagram:
![lab architecture   Topology of Soc Automation Lab - visual selection](https://github.com/user-attachments/assets/2574c29f-f885-45b7-902e-054ccf57d02f)



### Description:
Kali Linux acts as the attacker machine to simulate real-world exploits and scans.
Windows 10 serves as the victim, forwarding security logs for monitoring.
Ubuntu hosts the Wazuh SIEM to collect, analyze, and alert on suspicious activities.

## Getting Started
### Step 1. Lab Setup

### 1.1. Network Configuration for VMs  
**Assign NAT/Host-Only Networks**  
For **all VMs (Ubuntu, Kali, Windows)**:  
- Open VM Settings → **Network**  
- **Adapter 1**:  
  - Attached to: **NAT Network**  
  - Name: `SOC_NAT`   
- **Adapter 2** (Optional):  
  - Attached to: **Host-Only Network**  
  - Purpose: Internal VM-to-VM communication  

---

### 1.2. Ubuntu SIEM Server Setup  
**Requirements**: Ubuntu LTS ISO  
**Steps**:  
1. **Create VM**:  
   - RAM: 2GB (4GB recommended)  
   - Storage: 20GB+  
   - Network: Bridged/Host-Only 
2. **Install Ubuntu**:  
   - Attach ISO → Start VM → Choose **Normal Installation**  
   - Enable updates during setup  
   - Create user account with strong password  
3. **Post-Installation**:  
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

---

### 1.3. Kali Linux Attacker VM  
**Requirements**: Kali Linux  
**Setup**:   
1. **Resource Allocation**:  
   - RAM: 2GB (4GB recommended)  
   - Storage: 20GB+  
2. **Update System**:  
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

---

### 1.4. Windows 10 Victim Machine  
**Requirements**: Windows 10 
**Configuration**:  
1. **Create VM**:  
   - RAM: 4GB (8GB recommended)  
   - Storage: 40GB+  
   - Network: Bridged/Host-Only  
2. **Install Windows**:  
   - Complete regional/language settings  
   - Create user account  
3. **Optimize for Lab**:  
   - Disable automatic updates (for stability)  
   - Install tools like Sysmon, Wazuh agent  
---
### 1.5 Configuration for Windows VM
1️⃣ Configure Local Security Policy (Enable Auditing)
To ensure that important system events (like logins, file access, and process creation) are logged and can be forwarded to Wazuh:

Steps:

Press Win + R to open the Run dialog.

Type "secpol.msc" and press Enter.

In the Local Security Policy window, navigate to:
Security Settings → Local Policies → Audit Policy

Security Settings → Local Policies → Audit Policy
Double-click and enable auditing for the following categories:

Audit logon events → Success and Failure

Audit object access → Success and Failure

Audit process tracking → Success and Failure

Click Apply and OK after configuring each one.

Restart the system to ensure all policy changes take effect.

2️⃣ Disable Windows Defender (for Payload Execution)
Disabling antivirus and firewall is important for allowing reverse shell payloads to execute without being blocked.

Steps to Disable Real-Time Protection:

Go to Start → Settings → Update & Security → Windows Security.

Click Virus & threat protection.

Under Virus & threat protection settings, click Manage settings.

Turn Real-time protection to Off.

3️⃣ Disable Windows Firewall
To prevent blocking of incoming reverse shell connections from Kali (Attacker):

Steps:

Open Control Panel → System and Security → Windows Defender Firewall.

On the left sidebar, click Turn Windows Defender Firewall on or off.

Under both Private and Public network settings:

Select Turn off Windows Defender Firewall.

---

### 1.6. Snapshots (Highly Recommended)  
Take clean-state snapshots after setup:  
- **VirtualBox**: Machine → Take Snapshot  
- **VMware**: VM → Snapshot → Take Snapshot  
---
### Step 2. Installing Sysmon on Windows 
Sysmon (System Monitor) is a Windows system service and device driver that logs detailed information about process creations, network connections, file changes, and more. Integrating Sysmon with Wazuh enhances visibility into endpoint activity for advanced threat detection.
 Installation Steps:
1. Download Sysmon
Download Sysinternals Suite or just Sysmon.exe and Sysmon64.exe from the official Microsoft website:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

2. Choose a Sysmon Configuration File
Use a community-configured file 

3. Install Sysmon with Configuration
Run Command Prompt or PowerShell as Administrator and use:
 ```bash
   sysmon64.exe -accepteula -i sysmonconfig.xml
  ```
<div align="center">
<h1></h1> 
    <img src="https://github.com/user-attachments/assets/0137e58a-a7a7-44cf-aa60-52d213528a14" >
    <p><em>Figure.2: Verification of Sysmon installation</em></p>
</div>

Replace sysmonconfig.xml with the name of your config file.

4. Verify Installation
```bash
  Sysmon64 --version
   ```
Or by checking the Windows Event Viewer under:
> Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/cff6035d-fc64-428e-b57d-e9052422a484">
    <p><em>Figure.3: Verification of Sysmon Running in Event Viewer</em></p>
</div>

### Step 3. Wazuh Installation on Ubuntu (SIEM Server)
1. Update Your System Packages by following Command
```bash
  Sudo apt-get update && Sudo apt upgrade -y
   ```
2. Install Required Dependencies
```bash
 sudo apt install curl apt-transport-https lsb-release gnupg -y
   ```
3. Add the Wazuh Repository
```bash
 curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
 sudo bash wazuh-install.sh -a
   ```
4. Verify Wazuh Manager Status
```bash
sudo systemctl status wazuh-manager
   ```
After the Installation Wazuh Manager is running on your web server address on Port 443 

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/b8a07e94-dad4-402e-8740-5db215851f6d">
    <p><em>Figure.4: Installation of Wazuh Manager </em></p>
</div>

---
# Step 4. Install Wazuh Agent on Windows
1. Download the Agent

Download the .msi installer to your Windows machine.

2. Install the Agent

Double-click the .msi file and follow the wizard.

During setup:

Enter the Wazuh Manager IP (your Ubuntu server’s IP).

Keep the default port (1514/UDP).

Name the agent (e.g., Windows-Victim).

3. Register the Agent with the Wazuh Manager

On Ubuntu (Wazuh server), run:
```bash
sudo /var/ossec/bin/manage_agents
   ```
Choose A to add a new agent.

Enter the name, IP, and OS type.

After adding, choose E to extract the key.

Copy the key and paste it into the Windows agent

You can find the Configuration file named "Win32" in a ossec folder directory it will prompt you to enter the wazuh manager IP address and Key 

4. Start the Agent

From PowerShell (as Administrator):
```bash
sc start WazuhSvc
   ```
# Step 5. Configure Wazuh to ingest Sysmon logs

Edit the Wazuh agent configuration file:

#### Path: `C:\Program Files (x86)\ossec-agent\ossec.conf`
```xml
<localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
```











