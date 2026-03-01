![image](https://github.com/user-attachments/assets/c30cefbb-f246-4b0a-8226-cf0832351a9b)





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

**Striker is an advanced tool written in Python to identify any vulnerability.**

**Includes intelligent scanning, custom payloads, advanced terminal interface and results export.**
<img width="1127" height="722" alt="striker_menu" src="https://github.com/user-attachments/assets/17fb0f1e-d1d9-4d78-8c36-06f3830d72fe" />

**⚙️ Requirements**
------------
- Python 3.7+
- `requests`
- `beautifulsoup4`
- `tqdm`
- `colorama`

## ⚙️ Installation
+ `git clone https://github.com/xPloits3c/Striker.git`
+ `cd Striker`
+ `python -m venv striker_env`
+ `source striker_env/bin/activate`
+ `pip install -r requirements.txt`
+ `python striker.py`

**▶️ Example of use**
----------------
-  `python3 striker.py`
-  `Custom scan.`
-  Payloads file (optional, default send): `sqli.payloads.txt`
-  Number of threads (default 5): `5`

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
Developed by: **`xPloits3c`**

License: MIT
Contact: **`whitehat.report@onionmail.org`**
