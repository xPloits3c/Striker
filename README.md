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

## 🚀 Panoramica

**GPTScanner** è uno strumento avanzato di *web vulnerability scanning* creato da xPloits3c e potenziato da logica automatizzata e moduli personalizzabili.  
Supporta l'individuazione di vulnerabilità comuni come **SQL Injection**, **XSS**, **LFI**, e include un **crawler intelligente**, **dumper database**, supporto per **payload personalizzati**, ed esportazione CSV.

---

## 🧰 Caratteristiche

- [x] Crawler intelligente e profondo (fino a 5 livelli)
- [x] Rilevamento SQLi, XSS, LFI aggiornato al 2025
- [x] Dump automatico database (opzionale)
- [x] Interfaccia web con evidenziazione vulnerabilità
- [x] Supporto per payload personalizzati
- [x] Esportazione risultati in CSV
- [x] Modalità headless + opzione `-h` per help avanzato

---

## 📸 Screenshot

<p align="center">
  <em>[+] Interfaccia di scansione con evidenziazione vulnerabilità in tempo reale.</em>
</p>
![photo_1_2025-05-03_15-29-31](https://github.com/user-attachments/assets/08b11c3d-7ff5-41fb-894f-5038bbe4f94c)
<p align="center">
  <em>[+] Il menù principale ti aiuta a scegliere il tipo di attacco che vuoi fare.</em>
</p>
![photo_5_2025-05-03_15-29-31](https://github.com/user-attachments/assets/79938a98-32ea-409e-861f-9777ae735de9)
<p align="center">
  <em>[+] Trovate vulnerabilità, GPTScanner effetuerà una scansione approfondita.</em>
</p>
![photo_4_2025-05-03_15-29-31](https://github.com/user-attachments/assets/ecb4996a-5110-458d-80c0-bde8af471f15)
<p align="center">
  <em>[+] Una volta finito, visualizza il file output con i link vulnerabili. EX: cat output.csv</em>
</p>
![photo_3_2025-05-03_15-29-31](https://github.com/user-attachments/assets/8169214e-d61a-442b-a308-2cc435f7b4e8)
<p align="center">
  <em>[+] IL GIOCO E' FATTO!</em>
</p>
---

## ⚙️ Installazione

```bash
git clone https://github.com/tuonome/GPTScanner.git
cd GPTScanner
pip install -r requirements.txt
python3 gptscanner.py
