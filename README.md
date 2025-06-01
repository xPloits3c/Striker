![image](https://github.com/user-attachments/assets/c5423940-3a46-4301-80c5-b15704a85d70)



<h1 align="center">🛡️ Striker</h1>
<p align="center">
  <strong>Advanced Vulnerability Scanner powered by xPloits3c</strong><br>
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

![icon_SQL](https://github.com/user-attachments/assets/922b63de-9adf-44cd-9027-fd1aee6b22a2)

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

**💻 Screenshots**
--------------------------
![photo_1_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a8dd9565-c6e9-4420-87c3-fde6af8b4be8)
![photo_5_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1b5b5b7e-fe19-4d24-8fd0-d0c914cdb28e)
![photo_4_2025-05-03_15-29-31](https: //github.com/user-attachments/assets/6d7c394a-50b9-43f6-91cb-20e38411edd5)
![photo_2_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a2994e83-ca21-4925-bb1e-6bfaa868266e)
![photo_3_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1957b754-32ae-4384-bb64-68d1d038a328)

**📝 CSV Output**
-------------
Each query is automatically saved in Format:`.csv`

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
