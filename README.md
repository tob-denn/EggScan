EggScan

![Latest release](https://img.shields.io/github/v/release/MRsnoken/EggScan?label=version)

Self-hosted LAN device monitor. Shows IP, MAC, vendor and online status via a simple web dashboard.

EggScan is a lightweight Flask-based web application that scans your local network, shows connected devices, and provides details such as IP, MAC, vendor, ping status, and discovery events.
It is designed for private LAN environments only and installs through a simple one-command installer script.

EGGSCAN IS A HOBBY PROJECT. NOT INTENDED FOR ENTERPRISE OR SECURITY-CRITICAL USE.
DO NOT EXPOSE EGGSCAN TO THE PUBLIC INTERNET.
NO HARDENING, NO HTTPS, NO PRODUCTION-GRADE AUTH.


Features

- Fast local network scanning (ARP + Nmap)
- Web interface (Flask)
- Device list with IP, MAC, vendor lookup
- IPv4 and IPv6 address discovery (via neighbor scans)
- Alias naming for devices
- Online/offline/new indicators
- SQLite database storage
- Runs as a systemd service
- Versioning via version.json
- No cloud backend – all scan data stays on your LAN




Installation (Debian/Ubuntu)

Supported Debian-based systems:
Ubuntu
Raspberry Pi OS
Debian
Linux Mint
Other Debian derivatives

Run:

chmod +x install_eggscan.sh
sudo ./install_eggscan.sh

The installer will:

Check system requirements
Install required system packages
Create a Python virtual environment
Install Python dependencies inside the venv
Copy eggscan.py to /opt/eggscan
Copy version.json
Create a systemd service
Start EggScan automatically

After installation, open:

http://<your_local_ip>:5000

Python dependencies

Listed in requirements.txt:
Flask
Flask-SQLAlchemy
Flask-Login
Flask-Bcrypt
python-nmap

Manual install:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Installation on other Linux systems (Arch, Fedora, etc.)

No automatic installer is provided.

You must manually install:

Python 3
python3-venv (or equivalent)
pip
nmap
iproute2 / net-tools
Python dependencies from requirements.txt

You must also manually create:

a virtual environment
a systemd service file
a directory structure under /opt/eggscan

For advanced users only.



Uninstallation

To remove EggScan manually, delete:

/opt/eggscan/
/lib/systemd/system/eggscan.service (or /etc/systemd/system/)
/opt/eggscan/secret_key.txt
eggscan.db (if present)

Then run:

sudo systemctl stop eggscan.service
sudo systemctl disable eggscan.service
sudo systemctl daemon-reload

Security Notes

EggScan is intended for home LAN usage only.

It does not include:

CSRF protection
Hardened authentication
Multi-user model
HTTPS/TLS

For remote access, you must place it behind:

a reverse proxy (Nginx, Caddy, Traefik, etc)
proper authentication
HTTPS/TLS

Do not expose EggScan directly to the internet.



License

EggScan is released under the GNU General Public License version 3 (GPL-3.0).

This means:

You may use, study, modify and share the project
Modified versions must remain under GPL-3.0
You must keep copyright and attribution
You may not close the source and sell it as proprietary software



Disclaimer

EggScan is provided as is, without warranty.
Use at your own risk.



Credits

Created by MRsnoken.
Network discovery powered by Nmap and public OUI data.

