
---

🟦 3. Intrusion Detection System (IDS)  

```markdown
Intrusion Detection System (IDS)

A Python-based IDS that monitors ARP traffic to detect spoofing attacks in a LAN. Suspicious activity is flagged instantly and logged into a CSV file for future analysis.

 🚀 Features
- Monitors ARP packets using Scapy  
- Detects IP-MAC mismatches (ARP spoofing)  
- Console alerts for real-time warnings  
- Unique Feature: Logs alerts into `alerts.csv` with timestamp for forensic analysis  

⚙️ How It Works
- Input: Live ARP traffic from the network  
- Process: Sniffs ARP packets → Validates IP-MAC mapping → Detects spoof → Logs  
- Output:  
<img width="1593" height="964" alt="image" src="https://github.com/user-attachments/assets/d5cf9808-4534-4b66-96c8-0bcf31246f17" />

<img width="1593" height="964" alt="image" src="https://github.com/user-attachments/assets/0beaeb84-90d6-46db-8835-c51c6909eb1f" />


  - Console alert: `[ALERT] ARP Spoofing Detected! IP 192.168.1.1 is being spoofed by xx:xx:xx:xx`  
  - CSV log entry: `2025-08-25 19:30, ARP Spoofing Detected! IP 192.168.1.1 ...`  

 ▶️ Run Instructions
```bash
pip install scapy
python ids.py
