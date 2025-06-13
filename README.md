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

### 2. Network Configuration for VMs  
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

### 3. Ubuntu SIEM Server Setup  
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

### 4. Kali Linux Attacker VM  
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

### 5. Windows 10 Victim Machine  
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

### 6. Snapshots (Highly Recommended)  
Take clean-state snapshots after setup:  
- **VirtualBox**: Machine → Take Snapshot  
- **VMware**: VM → Snapshot → Take Snapshot  
**Naming Convention**:  
- `Base Setup - Clean`  
- `Pre-Attack Configuration`  

---


