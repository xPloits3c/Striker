![image](https://github.com/user-attachments/assets/c5423940-3a46-4301-80c5-b15704a85d70)



<h1 align="center">🛡️ Striker</h1>
<p align="center">
  <strong>Advanced Vulnerability Scanner powered by xPloits3c</strong><br>
  Lightweight | Modular | Reverse Ip | SQLi, XSS, LFI & more
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" />
  <img src="https://img.shields.io/github/license/xPloits3c/GPTScanner?style=flat-square" />
  <img src="https://img.shields.io/github/stars/xPloits3c/GPTScanner?style=social" />
  <img src="https://img.shields.io/github/release/xPloits3c/GPTScanner" />
  
</p>

---
 ![Repo View Counter](https://profile-counter.glitch.me/GPTScanner/count.svg)

**Striker è uno strumento avanzato scritto in Python per identificare eventuali vulnerabilità.**

**Include scansione intelligente, payload personalizzati, interfaccia terminale avanzata ed esportazione dei risultati.**
  + SQL Injection (SQLi)
  + Cross Site Scripting (XSS)
  + Local File Inclusion (LFI)
    
![icon_SQL](https://github.com/user-attachments/assets/922b63de-9adf-44cd-9027-fd1aee6b22a2)

**✨ Funzionalità principali**
--------------------------
  ✔️ Crawler Test vuln.

  ✔️ Testing SQLi-XSS-LFI con payload personalizzati o di default.

  ✔️ Web Application Firewall (WAF)

  ✔️ Reverse IP 

  ✔️ Evidenziazione in tempo reale:

  ✔️ Barra di avanzamento (tqdm)

  ✔️ Esportazione risultati automatica in .CSV

  ✔️ Multi-threading per velocità

**⚙️ Requisiti**
-------------
  - Python 3.7+
  - Moduli richiesti:
    - `requests`
    - `beautifulsoup4`
    - `tqdm`
    - `colorama`

## ⚙️ Installazione
  +     git clone https://github.com/xPloits3c/Striker.git
  +     cd Striker
  +     pip install -r requirements.txt
  +     python3 striker.py

**▶️ Esempio d’uso**
----------------
- `1) python3 striker.py`
- `2) Scansione personalizzata.`
- `3) File payloads (opzionale, invio per default): sqli.payloads.txt`
- `4) Numero di threads (default 5): 5`

**💻 Screenshots**
--------------------------
![photo_1_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a8dd9565-c6e9-4420-87c3-fde6af8b4be8)
![photo_5_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1b5b5b7e-fe19-4d24-8fd0-d0c914cdb28e)
![photo_4_2025-05-03_15-29-31](https://github.com/user-attachments/assets/6d7c394a-50b9-43f6-91cb-20e38411edd5)
![photo_2_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a2994e83-ca21-4925-bb1e-6bfaa868266e)
![photo_3_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1957b754-32ae-4384-bb64-68d1d038a328)

**📝 Output CSV**
--------------
Ogni ricerca viene salvata automaticamente in Formato:`.csv`

**🧠 Logica**
----------
Il tool confronta la risposta normale con quella modificata. Se:
  - Contiene parole chiave sospette (es. "sql error", "syntax").
  - O è significativamente diversa in contenuto.
  - Allora il link è segnalato come **vulnerabile**.

**👨‍💻 Autore**
-----------
Sviluppato con passione da: **`xPloits3c`** con: **`Open-Ai`**

Licenza: MIT
Contatto: whitehat.report@onionmail.org

