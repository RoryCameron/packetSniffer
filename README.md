![image](https://github.com/user-attachments/assets/26886615-d7c0-4e0a-b48b-ad65fec4e8d6)


![image](https://github.com/user-attachments/assets/5ce03ec0-bd34-4eca-9d8c-c1fe07ee5068)


**Overview**

This project is an in-progress home network threat detection system, built with Python, Utilizing Scapy for packet sniffing and Flask for a live web dashboard. Its goal is to serve as a lightweight IDS that can be run on a Raspberry PI, offering automated responses and alerting the user to suspicious activity through multiple channels.

**Current Features:**

-	Packet Sniffer: Live packet capture via Scapy.
-	Web Dashboard: Flash based dashboard displaying live alerts to suspicious IPs, and a list of all known flagged suspicious Ips.
-	AbsuelPDB API. Ips are checked using the AbsuelPDB API for flagged  user flagged malicious Ips.
  
**Upcoming Features:**

-	IP Blocking/Unblocking: Ability to block/unblock flagged Ips on the firewall, through the dashboard.
-	DNS Blacklist
-	Anomaly Detection
-	Machine Learning
-	User Alert System: Alert user of suspicious activity on various devices via email, SMS etc
-	Raspberry Pi Deployment
