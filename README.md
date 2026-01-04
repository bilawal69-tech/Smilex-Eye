# 👁️ Smilex-Eye v20.0

**Developed by:** `0x0smilex`

Smilex-Eye is a **high-speed Shodan reconnaissance and deception-detection tool**.  
It features a **dynamic filter engine** that automatically adapts to your **Shodan API subscription tier**.

---

## ⚠️ WARNING

> **THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY.**  
>  
> The developer is not responsible for any misuse or illegal activity.  
> Always ensure you have **explicit authorization** before scanning any systems.

---

## ✨ Features

- Master Filter Library with **67+ specialized Shodan filters** (Web, SSL, Cloud, ICS, and more)
- Dynamic Tier Awareness (unsupported filters are automatically hidden)
- Honeypot Detection using official Shodan tags and banner heuristics
- Export clean IP lists for tools such as **Nmap** and **Masscan**

---

## 📥 Quick Setup, Installation & Global Execution

```bash
git clone https://github.com/0x0smilex/smilex-eye.git && cd smilex-eye && pip install -r requirements.txt --break-system-packages && mv smilex-eye.py smilex-eye && chmod +x smilex-eye && sudo mv smilex-eye /usr/local/bin/
The --break-system-packages flag is used to bypass environment restrictions on modern Linux systems.
