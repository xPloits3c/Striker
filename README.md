<img width="1024" height="1536" alt="image" src="https://github.com/user-attachments/assets/8e898b8a-3d1e-4743-ab76-3378794333f7" />




<h1 align="center">🛡️ Striker</h1>
<p align="center">
  <strong>Advanced Vulnerability Scanner</strong><br>
  Lightweight | Modular | Reverse IP | SQLi, XSS, LFI & more
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" />
  <img src="https://img.shields.io/github/license/xPloits3c/GPTScanner?style=flat-square" />
  <img src="https://img.shields.io/github/stars/xPloits3c/GPTScanner?style=social" />
  <img src="https://img.shields.io/github/release/xPloits3c/GPTScanner" />
  
</p>

---
 ![Repo View Counter](https://profile-counter.glitch.me/GPTScanner/count.svg)

**Striker is an advanced tool written in Python to identify any vulnerability.**

**Includes intelligent scanning, custom payloads, advanced terminal interface and results export.**
+ SQL Injection (SQLi)
+ Cross Site Scripting (XSS)
+ Local File Inclusion (LFI)

![image](https://github.com/user-attachments/assets/a0b14da1-29be-48b7-83bf-53a323d61347)


**✨ Key Features**
--------------------------
✔️ Crawler Test vuln.

✔️ SQLi-XSS-LFI testing with custom or default payloads.

✔️ Web Application Firewall (WAF)

✔️ Reverse IP

✔️ Real-time highlighting:

✔️ Progress bar (tqdm)

✔️ Automatic results export to .CSV

✔️ Multi-threading for speed

**⚙️ Requirements**
------------
- Python 3.7+
- Required modules:
- `requests`
- `beautifulsoup4`
- `tqdm`
- `colorama`

## ⚙️ Installation
+ git clone https://github.com/xPloits3c/Striker.git
+ cd Striker
+ pip install -r requirements.txt
+ python3 striker.py

**▶️ Example of use**
----------------
- `1) python3 striker.py`
- `2) Custom scan.`
- `3) Payloads file (optional, default send): sqli.payloads.txt`
- `4) Number of threads (default 5): 5`

![image](https://github.com/user-attachments/assets/3488993c-b0c2-4d6f-b8f9-80a87e8783e8)

**📝 CSV Output**
-------------
Each query is automatically saved in Format:`.csv`

![image](https://github.com/user-attachments/assets/684bfd39-45a5-4662-9505-682718c13699)

**🧠 Logic**
---------
The tool compares the normal response with the modified one. If:
- It contains suspicious keywords (e.g. "sql error", "syntax").
- Or is significantly different in content.
- Then the link is flagged as **vulnerable**.

**👨‍💻 Author**
-----------
Developed with passion by: **`xPloits3c`** with: **`Open-Ai`**

License: MIT
Contact: whitehat.report@onionmail.org
