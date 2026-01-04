👁️ Smilex-Eye v20.0
Developed by: 0x0smilex

Smilex-Eye is a high-speed Shodan reconnaissance and deception-detection tool. It features a dynamic filter engine that automatically adjusts based on your Shodan API subscription tier.

✨ Features
Master Filter Library: Access to 67+ specialized Shodan filters (Web, SSL, Cloud, ICS, and more).

Dynamic Tier-Awareness: Automatically hides filters your API plan doesn't support.

Honeypot Logic: Identifies deceptive systems using official Shodan tags and banner heuristics.

Exporting: Save clean IP lists for further scanning with tools like Nmap or Masscan.

📥 Quick Setup & Installation
To get started, clone the repository using git clone https://github.com/0x0smilex/smilex-eye.git && cd smilex-eye, then install the dependencies using pip install -r requirements.txt --break-system-packages to bypass environment restrictions on modern Linux systems. To run the tool globally as a command, execute mv smilex-eye.py smilex-eye && chmod +x smilex-eye && sudo mv smilex-eye /usr/local/bin/, ensuring you do not remove the Shebang line (#!/usr/bin/env python3) at the very top of the script as it is required for the system to execute the file without the .py extension.
