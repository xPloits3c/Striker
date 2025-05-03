<h1 align="center">🛡️ GPTScanner</h1>
<p align="center">
  <strong>Advanced Vulnerability Scanner powered by OPEN-AI</strong><br>
  Lightweight | Modular | Updated 2025 | SQLi, XSS, LFI & more
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" />
  <img src="https://img.shields.io/github/license/xPloits3c/GPTScanner?style=flat-square" />
  <img src="https://img.shields.io/github/stars/xPloits3c/GPTScanner?style=social" />
</p>

---
 

🔍 GPTScanner — Advanced SQLi Vulnerability Scanner
===================================================

GPTScanner è uno strumento avanzato scritto in Python per identificare vulnerabilità **SQL Injection (SQLi)** nei siti web.
Include scansione intelligente, payload personalizzati, interfaccia terminale avanzata e esportazione dei risultati.

**✨ Funzionalità principali**
--------------------------
✔️ Scansione automatica di tutte le pagine e link

✔️ Testing SQLi con payload personalizzati o di default

✔️ Evidenziazione in tempo reale:

    ✅ Verde: VULNERABILE
    ❌ Rosso: NON vulnerabile

✔️ Barra di avanzamento (tqdm)

✔️ Esportazione risultati in CSV

✔️ Multi-threading per velocità

![photo_1_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a8dd9565-c6e9-4420-87c3-fde6af8b4be8)
![photo_5_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1b5b5b7e-fe19-4d24-8fd0-d0c914cdb28e)
![photo_4_2025-05-03_15-29-31](https://github.com/user-attachments/assets/6d7c394a-50b9-43f6-91cb-20e38411edd5)
![photo_2_2025-05-03_15-29-31](https://github.com/user-attachments/assets/a2994e83-ca21-4925-bb1e-6bfaa868266e)
![photo_3_2025-05-03_15-29-31](https://github.com/user-attachments/assets/1957b754-32ae-4384-bb64-68d1d038a328)

**⚙️ Requisiti**
-------------
- Python 3.7+
- Moduli richiesti:
  - requests
  - beautifulsoup4
  - tqdm
  - colorama

Installa tutto con:
> pip install -r requirements.txt

**▶️ Esempio d’uso**
----------------
>     python3 gptscanner.py

> Opzioni future: python3 gptscanner.py -u http://vulnerabile.it -p payloads.txt -o risultati.csv
- `-u` : URL target
- `-p` : (opzionale) File con payload personalizzati
- `-o` : (opzionale) Esporta risultati in formato CSV

**📝 Output CSV**
--------------
Formato:
Status, URL
VULNERABILE, http://...
OK, http://...

**🧠 Logica**
----------
Il tool confronta la risposta normale con quella modificata. Se:
- Contiene parole chiave sospette (es. "sql error", "syntax")
- O è significativamente diversa in contenuto

Allora il link è segnalato come **vulnerabile**.

**🛡️ Prossime funzioni**
---------------------
- Rilevamento XSS e LFI
- Report in formato HTML
- GUI web interattiva

**👨‍💻 Autore**
-----------
Sviluppato con passione da: **xPloits3c**

Licenza: MIT

## ⚙️ Installazione

```bash
git clone https://github.com/tuonome/GPTScanner.git
cd GPTScanner
pip install -r requirements.txt
python3 gptscanner.py
