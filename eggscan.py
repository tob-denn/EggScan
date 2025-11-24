import threading
import time
import ipaddress
import uuid
import datetime
import subprocess
import os
import json
import secrets

from flask import (
    Flask, render_template_string, redirect, url_for, request, flash,
    jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from flask_bcrypt import Bcrypt
import nmap

# ---------------------------
#   PATHS, VERSION, SECRET
# ---------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(BASE_DIR, "version.json")
SECRET_FILE = os.path.join(BASE_DIR, "secret_key.txt")
DB_FILE = os.path.join(BASE_DIR, "eggscan.db")


def load_version():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("version", "unknown")
    except Exception:
        return "unknown"


def load_or_create_secret_key():
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass

    key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(key)
        try:
            os.chmod(SECRET_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass
    return key


APP_VERSION = load_version()

app = Flask(__name__)
app.config["SECRET_KEY"] = load_or_create_secret_key()
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------------------
#         MODELLER
# ---------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=True)


class Device(db.Model):
    """
    is_new: True om enheten är helt nyupptäckt och ej "bekräftad".
            När du sätter alias eller klickar på "Markera känd"
            sätts is_new=False.
    """
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(200))
    mac_address = db.Column(db.String(40), unique=True)
    alias = db.Column(db.String(100), nullable=True)
    manufacturer = db.Column(db.String(100), nullable=True)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    last_seen_scan = db.Column(db.String(36), nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)  # <-- NY
    is_new = db.Column(db.Boolean, default=False)


class SubNetwork(db.Model):
    """
    Lagrar flera subnät (CIDR), t.ex. 192.168.0.0/24, 192.168.1.0/24 osv.
    """
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(50), unique=True, nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------
#     Language / Translation
# ---------------------------

TRANSLATIONS = {
    "sv": {
        # Generellt
        "LANG_SV": "Svenska",
        "LANG_EN": "English",
        "LANGUAGE_LABEL": "Språk",
        "SAVE": "Spara",
        "BACK": "Tillbaka",
        "LOGOUT": "Logga ut",
        "CHANGE_PASSWORD": "Byt lösenord",
        "MANAGE_USERS": "Hantera användare",
        "SETTINGS": "Inställningar",
        "CONFIRM_DELETE": "Är du säker?",
        "YES": "Ja",
        "NO": "Nej",
        "VERSION_LABEL": "Version",

        # Index / Dashboard
        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Inloggad som:",
        "MANUAL_PING_PLACEHOLDER": "Ange IP att testa",
        "MANUAL_PING_BUTTON": "Testa adress",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Båda",
        "FILTER_ONLINE": "Endast online",
        "FILTER_OFFLINE": "Endast offline",
        "SEARCH_PLACEHOLDER": "Sök IP/MAC/Alias",
        "SEARCH_FILTER_BUTTON": "Sök/Filtrera",
        "SORT_LABEL": "Sortera:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Tillverkare",
        "SORT_UPDATED": "Uppdaterad",
        "SCAN_NOW": "Skanna nu",
        "SCAN_RUNNING": "Skanning pågår…",
        "TABLE_IP": "IP",
        "TABLE_MAC": "MAC",
        "TABLE_ALIAS": "Alias",
        "TABLE_PING": "Ping",
        "TABLE_MANUFACTURER": "Tillverkare",
        "TABLE_STATUS": "Status",
        "TABLE_STATUS": "Status",
        "TABLE_ACTIONS": "Åtgärder",
        "ALIAS_NONE": "Inget alias",
        "MANUFACTURER_UNKNOWN": "Okänd",
        "MARK_KNOWN": "Markera känd",
        "DELETE": "Ta bort",
        "ALIAS_MODAL_TITLE": "Uppdatera Alias",
        "ALIAS_LABEL": "Alias",
        "CANCEL": "Avbryt",
        "ALIAS_SAVE": "Spara",

        # Setup
        "SETUP_TITLE": "Setup Admin",
        "SETUP_USERNAME": "Användarnamn",
        "SETUP_PASSWORD": "Lösenord",
        "SETUP_CREATE_ADMIN": "Skapa Admin",

        # Login
        "LOGIN_TITLE": "Logga in",
        "LOGIN_BUTTON": "Logga in",
        "LOGIN_USERNAME": "Användarnamn",
        "LOGIN_PASSWORD": "Lösenord",

        # Change password
        "CHANGE_PASSWORD_TITLE": "Byt lösenord",
        "CHANGE_PASSWORD_NEW": "Nytt lösenord",
        "CHANGE_PASSWORD_UPDATE": "Uppdatera lösenord",

        # Manage users
        "MANAGE_USERS_TITLE": "Hantera användare",
        "MANAGE_USERS_ADD_TITLE": "Lägg till användare",
        "MANAGE_USERS_USERNAME": "Användarnamn",
        "MANAGE_USERS_PASSWORD": "Lösenord",
        "MANAGE_USERS_ADD_BUTTON": "Lägg till",
        "MANAGE_USERS_EXISTING": "Befintliga användare",
        "MANAGE_USERS_ID": "ID",
        "MANAGE_USERS_IS_ADMIN": "Admin?",
        "MANAGE_USERS_ACTION": "Åtgärd",
        "MANAGE_USERS_DELETE_BUTTON": "Radera",
        "MANAGE_USERS_ADMIN_LABEL": "Ja",
        "MANAGE_USERS_NOT_ADMIN_LABEL": "Nej",
        "MANAGE_USERS_ADMIN_TAG": "(Admin)",

        # Config / Inställningar
        "CONFIG_TITLE": "Nätverksinställningar",
        "CONFIG_ADD_SUBNET_LABEL": "Lägg till subnät (t.ex. 192.168.0.0/24):",
        "CONFIG_ADD_SUBNET_BUTTON": "Lägg till",
        "CONFIG_SUBNET_COL": "Subnät",
        "CONFIG_SUBNET_DELETE_COL": "Ta bort",
        "CONFIG_SUBNET_DELETE_BUTTON": "Radera",
        "CONFIG_GUESS_BUTTON": "Gissa mitt IPv4-spann",
        "CONFIG_OTHER_SETTINGS": "Övriga inställningar",
        "CONFIG_IPV6_ENABLE": "Aktivera IPv6-upptäckt",
        "CONFIG_SCAN_INTERVAL": "Skanningsintervall (minuter):",
        "CONFIG_HIGHLIGHT_NEW": "Nya/okända enheter blinkar",
        "CONFIG_IPV6_UTILS": "IPv6-interface (t.ex. eth0):",
        "CONFIG_SAVE_BUTTON": "Spara",

        # Flash-meddelanden
        "FLASH_SETUP_USER_PASS_REQUIRED": "Användarnamn och lösenord krävs.",
        "FLASH_SETUP_ADMIN_CREATED": "Admin-konto skapat! Logga in.",
        "FLASH_LOGIN_OK": "Du har loggat in!",
        "FLASH_LOGIN_FAIL": "Felaktigt användarnamn eller lösenord.",
        "FLASH_LOGOUT": "Du har loggat ut.",
        "FLASH_PASSWORD_REQUIRED": "Nytt lösenord krävs.",
        "FLASH_PASSWORD_UPDATED": "Lösenordet har uppdaterats!",
        "FLASH_ALIAS_ADMIN_ONLY": "Endast admin kan ändra alias!",
        "FLASH_ALIAS_UPDATED": "Alias uppdaterat!",
        "FLASH_STATUS_ADMIN_ONLY": "Endast admin kan ändra status!",
        "FLASH_DEVICE_MARKED_KNOWN": "Enhet markerad som känd.",
        "FLASH_CANNOT_PING_OFFLINE": "Kan inte pinga en offline-enhet.",
        "FLASH_PING_OK": "Ping OK: {ip}",
        "FLASH_PING_FAIL": "Ping misslyckades: {ip}",
        "FLASH_PING_ERROR": "Fel vid ping: {error}",
        "FLASH_MANUAL_PING_IP_REQUIRED": "Ingen IP angiven.",
        "FLASH_MANUAL_PING_ERROR": "Fel vid ping av {ip}: {error}",
        "FLASH_DELETE_ADMIN_ONLY": "Endast admin kan ta bort enheter!",
        "FLASH_DEVICE_DELETED": "Enhet raderad!",
        "FLASH_DEVICE_NOT_FOUND": "Enheten kunde inte hittas.",
        "FLASH_USER_ADDED": "Användare tillagd!",
        "FLASH_USER_DELETED": "Användare raderad!",
        "FLASH_USER_DELETE_FAIL": "Kunde inte radera (user ej funnen eller är admin).",
        "FLASH_SUBNET_ADDED": "Subnät {cidr} tillagt!",
        "FLASH_SUBNET_EXISTS": "Subnät {cidr} finns redan!",
        "FLASH_SUBNET_NOT_FOUND": "Subnätet kunde inte hittas.",
        "FLASH_SUBNET_ID_INVALID": "Ogiltigt subnät-ID.",
        "FLASH_GUESSED_SUBNET_ADDED": "Gissat subnät {cidr} tillagt!",
        "FLASH_GUESSED_SUBNET_EXISTS": "Subnät {cidr} finns redan!",
        "FLASH_SUBNET_DELETED": "Subnät {cidr} raderat!",
        "FLASH_SCAN_INTERVAL_INVALID": "Skanningsintervall måste vara ett positivt heltal.",
        "FLASH_SETTINGS_UPDATED": "Inställningar uppdaterade!",
    },
    "en": {
        # General
        "LANG_SV": "Swedish",
        "LANG_EN": "English",
        "LANGUAGE_LABEL": "Language",
        "SAVE": "Save",
        "BACK": "Back",
        "LOGOUT": "Log out",
        "CHANGE_PASSWORD": "Change password",
        "MANAGE_USERS": "Manage users",
        "SETTINGS": "Settings",
        "CONFIRM_DELETE": "Are you sure?",
        "YES": "Yes",
        "NO": "No",
        "VERSION_LABEL": "Version",

        # Index / Dashboard
        "INDEX_TITLE": "EggScan",
        "LOGGED_IN_AS": "Logged in as:",
        "MANUAL_PING_PLACEHOLDER": "Enter IP to test",
        "MANUAL_PING_BUTTON": "Test address",
        "FILTER_LABEL": "Filter:",
        "FILTER_BOTH": "Both",
        "FILTER_ONLINE": "Online only",
        "FILTER_OFFLINE": "Offline only",
        "SEARCH_PLACEHOLDER": "Search IP/MAC/Alias",
        "SEARCH_FILTER_BUTTON": "Search/Filter",
        "SORT_LABEL": "Sort:",
        "SORT_IP": "IP",
        "SORT_MAC": "MAC",
        "SORT_ALIAS": "Alias",
        "SORT_MANUFACTURER": "Manufacturer",
        "SORT_UPDATED": "Updated",
        "SCAN_NOW": "Scan now",
        "SCAN_RUNNING": "Scanning in progress…",
        "TABLE_IP": "IP",
        "TABLE_MAC": "MAC",
        "TABLE_ALIAS": "Alias",
        "TABLE_PING": "Ping",
        "TABLE_MANUFACTURER": "Manufacturer",
        "TABLE_LAST_SEEN": "Last seen",
        "TABLE_STATUS": "Status",
        "TABLE_ACTIONS": "Actions",
        "ALIAS_NONE": "No alias",
        "MANUFACTURER_UNKNOWN": "Unknown",
        "MARK_KNOWN": "Mark as known",
        "DELETE": "Delete",
        "ALIAS_MODAL_TITLE": "Update Alias",
        "ALIAS_LABEL": "Alias",
        "CANCEL": "Cancel",
        "ALIAS_SAVE": "Save",

        # Setup
        "SETUP_TITLE": "Setup Admin",
        "SETUP_USERNAME": "Username",
        "SETUP_PASSWORD": "Password",
        "SETUP_CREATE_ADMIN": "Create Admin",

        # Login
        "LOGIN_TITLE": "Log in",
        "LOGIN_BUTTON": "Log in",
        "LOGIN_USERNAME": "Username",
        "LOGIN_PASSWORD": "Password",

        # Change password
        "CHANGE_PASSWORD_TITLE": "Change password",
        "CHANGE_PASSWORD_NEW": "New password",
        "CHANGE_PASSWORD_UPDATE": "Update password",

        # Manage users
        "MANAGE_USERS_TITLE": "Manage Users",
        "MANAGE_USERS_ADD_TITLE": "Add user",
        "MANAGE_USERS_USERNAME": "Username",
        "MANAGE_USERS_PASSWORD": "Password",
        "MANAGE_USERS_ADD_BUTTON": "Add",
        "MANAGE_USERS_EXISTING": "Existing users",
        "MANAGE_USERS_ID": "ID",
        "MANAGE_USERS_IS_ADMIN": "Admin?",
        "MANAGE_USERS_ACTION": "Action",
        "MANAGE_USERS_DELETE_BUTTON": "Delete",
        "MANAGE_USERS_ADMIN_LABEL": "Yes",
        "MANAGE_USERS_NOT_ADMIN_LABEL": "No",
        "MANAGE_USERS_ADMIN_TAG": "(Admin)",

        # Config / Settings
        "CONFIG_TITLE": "Network settings",
        "CONFIG_ADD_SUBNET_LABEL": "Add subnet (e.g. 192.168.0.0/24):",
        "CONFIG_ADD_SUBNET_BUTTON": "Add",
        "CONFIG_SUBNET_COL": "Subnet",
        "CONFIG_SUBNET_DELETE_COL": "Delete",
        "CONFIG_SUBNET_DELETE_BUTTON": "Delete",
        "CONFIG_GUESS_BUTTON": "Guess my IPv4 range",
        "CONFIG_OTHER_SETTINGS": "Other settings",
        "CONFIG_IPV6_ENABLE": "Enable IPv6 discovery",
        "CONFIG_SCAN_INTERVAL": "Scan interval (minutes):",
        "CONFIG_HIGHLIGHT_NEW": "New/unknown devices blink",
        "CONFIG_IPV6_UTILS": "IPv6 interface (e.g. eth0):",
        "CONFIG_SAVE_BUTTON": "Save",

        # Flash messages
        "FLASH_SETUP_USER_PASS_REQUIRED": "Username and password are required.",
        "FLASH_SETUP_ADMIN_CREATED": "Admin account created! Please log in.",
        "FLASH_LOGIN_OK": "You have logged in!",
        "FLASH_LOGIN_FAIL": "Incorrect username or password.",
        "FLASH_LOGOUT": "You have logged out.",
        "FLASH_PASSWORD_REQUIRED": "New password is required.",
        "FLASH_PASSWORD_UPDATED": "Password has been updated!",
        "FLASH_ALIAS_ADMIN_ONLY": "Only admin can change aliases!",
        "FLASH_ALIAS_UPDATED": "Alias updated!",
        "FLASH_STATUS_ADMIN_ONLY": "Only admin can change status!",
        "FLASH_DEVICE_MARKED_KNOWN": "Device marked as known.",
        "FLASH_CANNOT_PING_OFFLINE": "Cannot ping an offline device.",
        "FLASH_PING_OK": "Ping OK: {ip}",
        "FLASH_PING_FAIL": "Ping failed: {ip}",
        "FLASH_PING_ERROR": "Error while pinging: {error}",
        "FLASH_MANUAL_PING_IP_REQUIRED": "No IP address provided.",
        "FLASH_MANUAL_PING_ERROR": "Error while pinging {ip}: {error}",
        "FLASH_DELETE_ADMIN_ONLY": "Only admin can delete devices!",
        "FLASH_DEVICE_DELETED": "Device deleted!",
        "FLASH_DEVICE_NOT_FOUND": "Device could not be found.",
        "FLASH_USER_ADDED": "User added!",
        "FLASH_USER_DELETED": "User deleted!",
        "FLASH_USER_DELETE_FAIL": "Could not delete user (not found or is admin).",
        "FLASH_SUBNET_ADDED": "Subnet {cidr} added!",
        "FLASH_SUBNET_EXISTS": "Subnet {cidr} already exists!",
        "FLASH_SUBNET_DELETED": "Subnet {cidr} deleted!",
        "FLASH_SUBNET_NOT_FOUND": "Subnet could not be found.",
        "FLASH_SUBNET_ID_INVALID": "Invalid subnet ID.",
        "FLASH_GUESSED_SUBNET_ADDED": "Guessed subnet {cidr} added!",
        "FLASH_GUESSED_SUBNET_EXISTS": "Subnet {cidr} already exists!",
        "FLASH_SCAN_INTERVAL_INVALID": "Scan interval must be a positive integer.",
        "FLASH_SETTINGS_UPDATED": "Settings updated!",
    },
}


def get_setting(key, default_value=None):
    s = Settings.query.filter_by(key=key).first()
    return s.value if s else default_value


def set_setting(key, value):
    s = Settings.query.filter_by(key=key).first()
    if not s:
        s = Settings(key=key, value=value)
        db.session.add(s)
    else:
        s.value = value
    db.session.commit()


def get_language():
    lang = get_setting("language", "sv")
    if lang not in ("sv", "en"):
        lang = "sv"
    return lang


def t(key):
    lang = get_language()
    return TRANSLATIONS.get(lang, TRANSLATIONS["sv"]).get(key, key)


def tf(key, **kwargs):
    text = t(key)
    try:
        return text.format(**kwargs)
    except Exception:
        return text


# ---------------------------
#   HJÄLPFUNKTIONER
# ---------------------------

def guess_network_range():
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Kunde inte hämta standardrout")
        default_line = result.stdout.strip().splitlines()[0]
        parts = default_line.split()
        default_if = parts[parts.index("dev") + 1]

        result = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", "dev", default_if],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Kunde inte hämta IP-adress")
        line = result.stdout.strip().splitlines()[0]
        ip_with_prefix = line.split()[3]
        net = ipaddress.ip_network(ip_with_prefix, strict=False)
        return str(net)
    except Exception as e:
        print("Error in guess_network_range:", e)
        return "192.168.0.0/24"


def discover_ipv6_neighbors():
    mac_to_v6 = {}
    ipv6_utils = get_setting("ipv6_utils", "").strip()

    if ipv6_utils:
        ping_cmd = ["ping", "-6", "-I", ipv6_utils, "ff02::1", "-c", "3"]
    else:
        ping_cmd = ["ping", "-6", "ff02::1", "-c", "3"]

    try:
        subprocess.run(ping_cmd, timeout=5, check=False)
    except Exception as e:
        print("Fel vid ping6 ff02::1:", e)

    try:
        result = subprocess.run(["ip", "-6", "neighbor", "show"],
                                capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and parts[1] == 'dev' and parts[3] == 'lladdr':
                ipv6_addr = parts[0].lower()
                mac_addr = parts[4].lower()
                if mac_addr not in mac_to_v6:
                    mac_to_v6[mac_addr] = []
                if ipv6_addr not in mac_to_v6[mac_addr]:
                    mac_to_v6[mac_addr].append(ipv6_addr)
    except Exception as e:
        print("Fel vid ip -6 neighbor show:", e)

    return mac_to_v6


def nmap_scan_and_save():
    subnets = SubNetwork.query.all()
    if not subnets:
        set_setting("scan_status", "done")
        return

    set_setting("scan_status", "running")
    current_scan_id = str(uuid.uuid4())
    set_setting("last_scan_id", current_scan_id)

    nm = nmap.PortScanner()

    existing_devices = {d.mac_address.lower(): d for d in Device.query.all()}
    ipv6_enabled = (get_setting("ipv6_enabled", "false") == "true")

    # Här samlar vi *endast* IP:na som hittas i den här skanningen
    scan_ips_per_mac = {}

    # ---- IPv4-skanning (nmap) ----
    for sn in subnets:
        cidr = sn.cidr.strip()
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version == 4:
                scan_output = nm.scan(hosts=cidr, arguments="-sn")
                for host, info in scan_output.get("scan", {}).items():
                    mac = info.get("addresses", {}).get("mac", None)
                    if not mac:
                        continue
                    mac_lower = mac.lower()
                    manufacturer = info.get("vendor", {}).get(mac, None)

                    # Lägg till IPv4-adressen i "denna skanning"-listan
                    if mac_lower not in scan_ips_per_mac:
                        scan_ips_per_mac[mac_lower] = set()
                    scan_ips_per_mac[mac_lower].add(host)

                    if mac_lower in existing_devices:
                        dev = existing_devices[mac_lower]
                        if manufacturer:
                            dev.manufacturer = manufacturer
                        dev.last_seen_scan = current_scan_id
                        dev.last_seen_at = datetime.datetime.now()
                    else:
                        new_dev = Device(
                            ip_address=host,
                            mac_address=mac,
                            manufacturer=manufacturer,
                            last_seen_scan=current_scan_id,
                            last_seen_at=datetime.datetime.now(),
                            is_new=True
                        )
                        db.session.add(new_dev)
                        existing_devices[mac_lower] = new_dev
            else:
                # IPv6-nät i SubNetwork ignoreras avsiktligt här (hanteras via neighbor discovery)
                pass
        except Exception as e:
            print(f"Fel vid scanning av subnät {cidr}: {e}")

    db.session.commit()

    # ---- IPv6-skanning (neighbor discovery) ----
    if ipv6_enabled:
        v6_map = discover_ipv6_neighbors()

        for mac_lower, ipv6_list in v6_map.items():
            if not ipv6_list:
                continue

            # Lägg IPv6-adresser i "denna skanning"-listan
            if mac_lower not in scan_ips_per_mac:
                scan_ips_per_mac[mac_lower] = set()
            for ip6 in ipv6_list:
                scan_ips_per_mac[mac_lower].add(ip6)

            if mac_lower in existing_devices:
                dev = existing_devices[mac_lower]
                dev.last_seen_scan = current_scan_id
                dev.last_seen_at = datetime.datetime.now()
            else:
                new_dev = Device(
                    ip_address=",".join(ipv6_list),
                    mac_address=mac_lower,
                    manufacturer=None,
                    last_seen_scan=current_scan_id,
                    last_seen_at=datetime.datetime.now(),
                    is_new=True
                )
                db.session.add(new_dev)
                existing_devices[mac_lower] = new_dev

        db.session.commit()

    # ---- Sätt ip_address baserat *bara* på denna skanning ----
    for mac_lower, dev in existing_devices.items():
        if dev.last_seen_scan == current_scan_id:
            addr_set = scan_ips_per_mac.get(mac_lower, set())
            if addr_set:
                dev.ip_address = ",".join(sorted(addr_set))
            else:
                dev.ip_address = "-"
    db.session.commit()

    # ---- Markera offline-enheter (inte hittade i denna skanning) ----
    offline_devs = Device.query.filter(Device.last_seen_scan != current_scan_id).all()
    for d in offline_devs:
        d.ip_address = "-"
    db.session.commit()

    # ---- Om IPv6 är avstängt: ta bort ev. IPv6-adresser (samma som din originalkod) ----
    if not ipv6_enabled:
        all_devs = Device.query.all()
        for d in all_devs:
            if d.ip_address and d.ip_address != "-":
                addresses = [x.strip() for x in d.ip_address.split(",")]
                keep_only_v4 = []
                for addr in addresses:
                    try:
                        ip_obj = ipaddress.ip_address(addr)
                        if ip_obj.version == 4:
                            keep_only_v4.append(addr)
                    except Exception:
                        pass
                if keep_only_v4:
                    d.ip_address = ",".join(keep_only_v4)
                else:
                    d.ip_address = "-"
        db.session.commit()

    set_setting("scan_status", "done")


def run_periodic_scan():
    while True:
        with app.app_context():
            interval_str = get_setting("scan_interval", "5")
            try:
                interval_minutes = int(interval_str)
            except Exception:
                interval_minutes = 5
            nmap_scan_and_save()
        time.sleep(interval_minutes * 60)


# ---------------------------
#          ROUTES
# ---------------------------

from flask import session


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if User.query.first():
        return redirect(url_for("login"))

    if request.method == "POST":
        language = request.form.get("language", "").strip()
        if language in ("sv", "en"):
            set_setting("language", language)

        username = request.form["username"]
        password = request.form["password"]
        if not username or not password:
            flash(t("FLASH_SETUP_USER_PASS_REQUIRED"), "danger")
            return redirect(url_for("setup"))
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        admin_user = User(username=username, password=hashed_pw, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        flash(t("FLASH_SETUP_ADMIN_CREATED"), "success")
        return redirect(url_for("login"))

    lang = get_language()
    return render_template_string(SETUP_TEMPLATE, t=t, lang=lang, version=APP_VERSION)


@app.route("/login", methods=["GET", "POST"])
def login():
    if User.query.count() == 0:
        return redirect(url_for("setup"))

    if request.method == "POST":
        language = request.form.get("language", "").strip()
        if language in ("sv", "en"):
            set_setting("language", language)

        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(t("FLASH_LOGIN_OK"), "success")
            return redirect(url_for("index"))
        flash(t("FLASH_LOGIN_FAIL"), "danger")

    lang = get_language()
    return render_template_string(LOGIN_TEMPLATE, t=t, lang=lang, version=APP_VERSION)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash(t("FLASH_LOGOUT"), "info")
    return redirect(url_for("login"))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form["password"]
        if not new_password:
            flash(t("FLASH_PASSWORD_REQUIRED"), "danger")
            return redirect(url_for("change_password"))
        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        current_user.password = hashed_pw
        db.session.commit()
        flash(t("FLASH_PASSWORD_UPDATED"), "success")
        return redirect(url_for("index"))

    lang = get_language()
    return render_template_string(CHANGE_PASSWORD_TEMPLATE, t=t, lang=lang, version=APP_VERSION)


@app.route("/")
@login_required
def index():
    scan_status = get_setting("scan_status", "done")
    last_scan_id = get_setting("last_scan_id", "")
    highlight_new = (get_setting("highlight_new", "false") == "true")

    filter_mode = request.args.get("filter", "both")
    search_q = request.args.get("search", "").strip()
    sort_field = request.args.get("sort", "ip")
    sort_dir = request.args.get("dir", "asc")

    q = Device.query

    if search_q:
        pattern = f"%{search_q}%"
        q = q.filter(
            db.or_(
                Device.ip_address.ilike(pattern),
                Device.mac_address.ilike(pattern),
                Device.alias.ilike(pattern),
                Device.manufacturer.ilike(pattern)
            )
        )

    if filter_mode in ["online", "offline"] and last_scan_id:
        if filter_mode == "online":
            q = q.filter(Device.last_seen_scan == last_scan_id)
        else:
            q = q.filter(
                db.or_(
                    Device.last_seen_scan != last_scan_id,
                    Device.last_seen_scan.is_(None)
                )
            )

    devices = q.all()

    def none_str(x):
        return x if x else ""

    if sort_field == "ip":
        def ip_key(dev):
            if dev.ip_address == "-" or not dev.ip_address:
                return (999, ipaddress.ip_address("255.255.255.255"))
            first_ip = dev.ip_address.split(",")[0].strip()
            try:
                ip_obj = ipaddress.ip_address(first_ip)
                return (ip_obj.version, ip_obj)
            except Exception:
                return (999, ipaddress.ip_address("255.255.255.255"))
        devices.sort(key=ip_key, reverse=(sort_dir == "desc"))

    elif sort_field == "mac":
        devices.sort(key=lambda d: none_str(d.mac_address).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "alias":
        devices.sort(key=lambda d: none_str(d.alias).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "manufacturer":
        devices.sort(key=lambda d: none_str(d.manufacturer).lower(), reverse=(sort_dir == "desc"))
    elif sort_field == "updated":
        def updated_key(d):
            return d.updated_at if d.updated_at else datetime.datetime(1970, 1, 1)
        devices.sort(key=updated_key, reverse=(sort_dir == "desc"))

    lang = get_language()
    return render_template_string(
        INDEX_TEMPLATE,
        devices=devices,
        current_user=current_user,
        scan_status=scan_status,
        last_scan_id=last_scan_id,
        filter_mode=filter_mode,
        search_q=search_q,
        sort_field=sort_field,
        sort_dir=sort_dir,
        highlight_new=highlight_new,
        t=t,
        lang=lang,
        version=APP_VERSION
    )


@app.route("/scan_status", methods=["GET"])
def get_scan_status():
    status = get_setting("scan_status", "done")
    return jsonify({"status": status})


@app.route("/force_scan", methods=["POST"])
@login_required
def force_scan():
    def do_scan_now():
        with app.app_context():
            nmap_scan_and_save()

    t_thread = threading.Thread(target=do_scan_now, daemon=True)
    t_thread.start()
    return redirect(url_for("index"))


@app.route("/update_alias", methods=["POST"])
@login_required
def update_alias():
    if not current_user.is_admin:
        flash(t("FLASH_ALIAS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))
    mac = request.form.get("mac")
    alias = request.form.get("alias", "").strip()
    if mac:
        dev = Device.query.filter_by(mac_address=mac).first()
        if dev:
            dev.alias = alias
            if dev.is_new:
                dev.is_new = False
            db.session.commit()
            flash(t("FLASH_ALIAS_UPDATED"), "success")
    return redirect(url_for("index"))


@app.route("/mark_known/<int:device_id>", methods=["POST"])
@login_required
def mark_known(device_id):
    if not current_user.is_admin:
        flash(t("FLASH_STATUS_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))
    dev = Device.query.get(device_id)
    if dev and dev.is_new:
        dev.is_new = False
        db.session.commit()
        flash(t("FLASH_DEVICE_MARKED_KNOWN"), "success")
    return redirect(url_for("index"))


@app.route("/ping_device/<int:device_id>", methods=["POST"])
@login_required
def ping_device(device_id):
    dev = Device.query.get(device_id)
    if not dev or dev.ip_address == "-":
        flash(t("FLASH_CANNOT_PING_OFFLINE"), "warning")
        return redirect(url_for("index"))

    ip = dev.ip_address
    ip_to_ping = ip.split(",")[0].strip()

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip_to_ping],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            flash(tf("FLASH_PING_OK", ip=ip_to_ping), "success")
        else:
            flash(tf("FLASH_PING_FAIL", ip=ip_to_ping), "danger")
    except Exception as e:
        flash(tf("FLASH_PING_ERROR", error=e), "danger")

    return redirect(url_for("index"))


@app.route("/manual_ping", methods=["POST"])
@login_required
def manual_ping():
    ip = request.form.get("ip", "").strip()
    is_ipv6 = ("ipv6" in request.form)

    if not ip:
        flash(t("FLASH_MANUAL_PING_IP_REQUIRED"), "warning")
        return redirect(url_for("index"))

    cmd = ["ping", "-c", "1", "-W", "2", ip]
    if is_ipv6:
        cmd = ["ping", "-6", "-c", "1", "-W", "2", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            flash(tf("FLASH_PING_OK", ip=ip), "success")
        else:
            flash(tf("FLASH_PING_FAIL", ip=ip), "danger")
    except Exception as e:
        flash(tf("FLASH_MANUAL_PING_ERROR", ip=ip, error=e), "danger")

    return redirect(url_for("index"))


@app.route("/delete_device/<int:device_id>", methods=["POST"])
@login_required
def delete_device(device_id):
    if not current_user.is_admin:
        flash(t("FLASH_DELETE_ADMIN_ONLY"), "danger")
        return redirect(url_for("index"))
    dev = Device.query.get(device_id)
    if dev:
        db.session.delete(dev)
        db.session.commit()
        flash(t("FLASH_DEVICE_DELETED"), "success")
    else:
        flash(t("FLASH_DEVICE_NOT_FOUND"), "warning")
    return redirect(url_for("index"))


@app.route("/manage_users", methods=["GET", "POST"])
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")
        password = request.form.get("password")
        user_id = request.form.get("user_id")

        if action == "add" and username and password:
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash(t("FLASH_USER_ADDED"), "success")

        elif action == "delete" and user_id:
            usr = User.query.get(int(user_id))
            if usr and not usr.is_admin:
                db.session.delete(usr)
                db.session.commit()
                flash(t("FLASH_USER_DELETED"), "success")
            else:
                flash(t("FLASH_USER_DELETE_FAIL"), "warning")

    users = User.query.all()
    lang = get_language()
    return render_template_string(MANAGE_USERS_TEMPLATE, users=users, t=t, lang=lang, version=APP_VERSION)


@app.route("/config_eggscan", methods=["GET", "POST"])
@login_required
def config_eggscan():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_subnet":
            cidr = request.form.get("cidr", "").strip()
            if cidr:
                ex = SubNetwork.query.filter_by(cidr=cidr).first()
                if not ex:
                    sn = SubNetwork(cidr=cidr)
                    db.session.add(sn)
                    db.session.commit()
                    flash(tf("FLASH_SUBNET_ADDED", cidr=cidr), "success")
                else:
                    flash(tf("FLASH_SUBNET_EXISTS", cidr=cidr), "warning")

        elif action == "delete_subnet":
            subnet_id = request.form.get("subnet_id")
            if subnet_id and subnet_id.isdigit():
                sn = SubNetwork.query.get(int(subnet_id))
                if sn:
                    cidr = sn.cidr
                    db.session.delete(sn)
                    db.session.commit()
                    flash(tf("FLASH_SUBNET_DELETED", cidr=cidr), "success")
                else:
                    flash(t("FLASH_SUBNET_NOT_FOUND"), "warning")
            else:
                flash(t("FLASH_SUBNET_ID_INVALID"), "danger")

        elif action == "guess":
            guessed = guess_network_range()
            if guessed:
                ex = SubNetwork.query.filter_by(cidr=guessed).first()
                if not ex:
                    new_sn = SubNetwork(cidr=guessed)
                    db.session.add(new_sn)
                    db.session.commit()
                    flash(tf("FLASH_GUESSED_SUBNET_ADDED", cidr=guessed), "success")
                else:
                    flash(tf("FLASH_GUESSED_SUBNET_EXISTS", cidr=guessed), "warning")

        elif action == "update_settings":
            ipv6 = (request.form.get("ipv6") == "on")
            scan_interval = request.form.get("scan_interval", "5").strip()
            highlight_new = (request.form.get("highlight_new") == "on")
            ipv6_utils = request.form.get("ipv6_utils", "").strip()
            language = request.form.get("language", "").strip()

            if not scan_interval.isdigit() or int(scan_interval) <= 0:
                flash(t("FLASH_SCAN_INTERVAL_INVALID"), "danger")
                return redirect(url_for("config_eggscan"))

            set_setting("ipv6_enabled", "true" if ipv6 else "false")
            set_setting("scan_interval", scan_interval)
            set_setting("highlight_new", "true" if highlight_new else "false")
            set_setting("ipv6_utils", ipv6_utils)
            if language in ("sv", "en"):
                set_setting("language", language)

            flash(t("FLASH_SETTINGS_UPDATED"), "success")

        return redirect(url_for("config_eggscan"))

    subnets = SubNetwork.query.all()
    ipv6_enable = (get_setting("ipv6_enabled", "false") == "true")
    scan_interval = get_setting("scan_interval", "5")
    highlight_new = (get_setting("highlight_new", "false") == "true")
    ipv6_utils = get_setting("ipv6_utils", "")
    lang = get_language()

    return render_template_string(
        CONFIG_TEMPLATE,
        subnets=subnets,
        ipv6=ipv6_enable,
        scan_interval=scan_interval,
        highlight_new=highlight_new,
        ipv6_utils=ipv6_utils,
        t=t,
        lang=lang,
        version=APP_VERSION
    )


# ---------------------------
#       TEMPLATES
# ---------------------------

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 40%, #111827 100%);
        color: #e5e7eb;
        min-height: 100vh;
    }
    .main-card {
        margin-top: 30px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .blink-new {
        animation: blink-bg 1s linear infinite;
    }
    @keyframes blink-bg {
        0% { background-color: #e11d48; }
        50% { background-color: #f97316; }
        100% { background-color: #e11d48; }
    }
    .version-pill {
        font-size: 0.8rem;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        background-color: #111827;
        color: #9ca3af;
        border: 1px solid #374151;
        margin-left: 0.5rem;
    }
    .status-badge-online {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        background-color: #16a34a;
        color: #ecfdf5;
        font-size: 0.8rem;
    }

    .status-badge-offline {
        display: inline-block;
        padding: 0.2rem 0.6rem;
        border-radius: 999px;
        background-color: #374151;
        color: #e5e7eb;
        font-size: 0.8rem;
    }

    .table-dark-header {
        background-color: #111827;
    }

    .table-dark-header th {
        background-color: #111827;
        border-color: #1f2933;
        color: #ffffff !important;
    }

    .table-dark-body tbody tr {
        background-color: #020617;
        color: #e5e7eb;
    }
    .table-dark-body tbody tr:nth-child(even) {
        background-color: #030712;
    }
    .table-dark-body tbody tr:hover {
        background-color: #0f172a;
    }
    .navbar-eggscan {
        background-color: #020617;
        border-bottom: 1px solid #1f2937;
    }
    .navbar-eggscan a, .navbar-eggscan span {
        color: #e5e7eb !important;
    }
    .badge-role {
        font-size: 0.75rem;
        background-color: #4b5563;
    }
    footer {
        margin-top: 20px;
        padding-top: 10px;
        border-top: 1px solid #1f2937;
        font-size: 0.8rem;
        color: #9ca3af;
    }
    .btn-outline-secondary {
        border-color: #4b5563;
        color: #e5e7eb;
    }
    .btn-outline-secondary:hover {
        background-color: #4b5563;
        color: #f9fafb;
    }
    .card-header {
        background-color: #020617;
        border-bottom: 1px solid #1f2937;
    }
    .card-body {
        background-color: #020617;
    }

    .ip-modal-list-item {
        background-color: #ffffff;
        color: #000000;
        border-color: #e5e7eb;
        font-weight: 500;
    }

    /* Toggle switches */
    .toggle-switch {
        position: relative;
        display: inline-block;
        width: 44px;
        height: 24px;
    }

    .toggle-switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .toggle-slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #4b5563;
        transition: 0.3s;
        border-radius: 9999px;
    }

    .toggle-slider::before {
        position: absolute;
        content: "";
        height: 18px;
        width: 18px;
        left: 3px;
        bottom: 3px;
        background-color: #f9fafb;
        transition: 0.3s;
        border-radius: 9999px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.5);
    }

    .toggle-switch input:checked + .toggle-slider {
        background-color: #22c55e;
    }

    .toggle-switch input:checked + .toggle-slider::before {
        transform: translateX(20px);
    }

    .toggle-switch input:focus + .toggle-slider {
        box-shadow: 0 0 0 3px rgba(34,197,94,0.4);
    }

    </style>
</head>
<body>
<nav class="navbar navbar-expand navbar-eggscan">
  <div class="container">
    <a class="navbar-brand font-weight-bold" href="#">
      {{ t("INDEX_TITLE") }}
      <span class="version-pill">{{ t("VERSION_LABEL") }} {{ version }}</span>
    </a>
    <div class="ml-auto d-flex align-items-center">
      <span class="mr-3">
        {{ t("LOGGED_IN_AS") }} {{ current_user.username }}
        {% if current_user.is_admin %}
          <span class="badge badge-role ml-1">admin</span>
        {% endif %}
      </span>
      <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-danger mr-2">{{ t("LOGOUT") }}</a>
      <a href="{{ url_for('change_password') }}" class="btn btn-sm btn-outline-warning mr-2">{{ t("CHANGE_PASSWORD") }}</a>
      {% if current_user.is_admin %}
      <a href="{{ url_for('manage_users') }}" class="btn btn-sm btn-outline-info mr-2">{{ t("MANAGE_USERS") }}</a>
      <a href="{{ url_for('config_eggscan') }}" class="btn btn-sm btn-outline-light">{{ t("SETTINGS") }}</a>
      {% endif %}
    </div>
  </div>
</nav>

<div class="container">
  <div class="card main-card">
    <div class="card-header d-flex justify-content-between align-items-center">
      <div>
        <h4 class="mb-0">{{ t("INDEX_TITLE") }}</h4>
        <small class="text-muted">{{ t("VERSION_LABEL") }} {{ version }}</small>
      </div>
      <form method="POST" action="{{ url_for('manual_ping') }}" class="form-inline">
        <div class="form-group mr-2 mb-0">
          <input type="text" name="ip" id="ipInput" class="form-control form-control-sm"
                 placeholder="{{ t('MANUAL_PING_PLACEHOLDER') }}" required>
        </div>
        <div class="d-flex align-items-center mr-2 mb-0">
          <label class="toggle-switch mb-0">
            <input type="checkbox" name="ipv6" id="ipv6Check">
            <span class="toggle-slider"></span>
          </label>
          <label for="ipv6Check" class="mb-0 ml-2 text-light">IPv6</label>
        </div>
        <button type="submit" class="btn btn-outline-secondary btn-sm">{{ t("MANUAL_PING_BUTTON") }}</button>
      </form>
    </div>
    <div class="card-body">

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="mb-3">
          {% for category, msg in messages %}
            <div class="alert alert-{{ 'danger' if category=='danger' else category }} mb-1" role="alert">
              {{ msg }}
            </div>
          {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <form method="GET" class="form-inline mb-3">
        <input type="text" name="search" class="form-control form-control-sm mr-2"
               value="{{ search_q }}" placeholder="{{ t('SEARCH_PLACEHOLDER') }}">
        <label class="mr-2 text-light">{{ t("FILTER_LABEL") }}</label>
        <select name="filter" class="form-control form-control-sm mr-2">
            <option value="both" {% if filter_mode=='both' %}selected{% endif %}>{{ t("FILTER_BOTH") }}</option>
            <option value="online" {% if filter_mode=='online' %}selected{% endif %}>{{ t("FILTER_ONLINE") }}</option>
            <option value="offline" {% if filter_mode=='offline' %}selected{% endif %}>{{ t("FILTER_OFFLINE") }}</option>
        </select>
        <button type="submit" class="btn btn-outline-primary btn-sm">{{ t("SEARCH_FILTER_BUTTON") }}</button>
      </form>

      <div class="d-flex justify-content-between align-items-center mb-3">
        <div class="text-light">
          {{ t("SORT_LABEL") }}
          <a class="text-info" href="?sort=ip&dir={% if sort_field=='ip' and sort_dir=='asc' %}desc{% else %}asc{% endif %}&filter={{filter_mode}}&search={{search_q}}">{{ t("SORT_IP") }}</a> |
          <a class="text-info" href="?sort=mac&dir={% if sort_field=='mac' and sort_dir=='asc' %}desc{% else %}asc{% endif %}&filter={{filter_mode}}&search={{search_q}}">{{ t("SORT_MAC") }}</a> |
          <a class="text-info" href="?sort=alias&dir={% if sort_field=='alias' and sort_dir=='asc' %}desc{% else %}asc{% endif %}&filter={{filter_mode}}&search={{search_q}}">{{ t("SORT_ALIAS") }}</a> |
          <a class="text-info" href="?sort=manufacturer&dir={% if sort_field=='manufacturer' and sort_dir=='asc' %}desc{% else %}asc{% endif %}&filter={{filter_mode}}&search={{search_q}}">{{ t("SORT_MANUFACTURER") }}</a> |
          <a class="text-info" href="?sort=updated&dir={% if sort_field=='updated' and sort_dir=='asc' %}desc{% else %}asc{% endif %}&filter={{filter_mode}}&search={{search_q}}">{{ t("SORT_UPDATED") }}</a>
        </div>
        <form method="POST" action="{{ url_for('force_scan') }}" class="mb-0">
          <button type="submit" class="btn btn-sm btn-primary">{{ t("SCAN_NOW") }}</button>
        </form>
      </div>

      {% if scan_status == "running" %}
      <div class="alert alert-info d-flex align-items-center" id="scan-info">
          <strong>{{ t("SCAN_RUNNING") }}</strong>
          <div class="spinner-border text-primary ml-auto" role="status" aria-hidden="true"></div>
      </div>
      {% endif %}

      <div class="table-responsive table-dark-body">
        <table class="table table-sm mb-0">
          <thead class="table-dark-header text-white">
            <tr>
                <th>{{ t("TABLE_IP") }}</th>
                <th>{{ t("TABLE_MAC") }}</th>
                <th>{{ t("TABLE_ALIAS") }}</th>
                <th>{{ t("TABLE_PING") }}</th>
                <th>{{ t("TABLE_MANUFACTURER") }}</th>
                <th>{{ t("TABLE_LAST_SEEN") }}</th>
                <th>{{ t("TABLE_STATUS") }}</th>
                <th>{{ t("TABLE_ACTIONS") }}</th>
            </tr>
          </thead>
          <tbody>
          {% for dev in devices %}
            {% if dev.last_seen_scan == last_scan_id %}
                {% set status_text = "Online" %}
                {% set status_class = "status-badge-online" %}
            {% else %}
                {% set status_text = "Offline" %}
                {% set status_class = "status-badge-offline" %}
            {% endif %}

            {% if highlight_new and dev.is_new %}
                {% set row_class = "blink-new" %}
            {% else %}
                {% set row_class = "" %}
            {% endif %}

            <tr class="{{ row_class }}">
                <td class="align-middle">
                    {% if dev.ip_address and dev.ip_address != "-" %}
                        {% set ip_list = dev.ip_address.split(",") %}
                        {{ ip_list[0] | trim }}
                        {% if ip_list|length > 1 %}
                            <button type="button"
                                    class="btn btn-link btn-sm p-0 ml-1"
                                    data-toggle="modal"
                                    data-target="#ipModal{{ dev.id }}">
                                (+{{ ip_list|length - 1 }} more)
                            </button>
                        {% endif %}
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td class="align-middle"><code class="text-light">{{ dev.mac_address or "N/A" }}</code></td>
                <td class="align-middle">
                    {% if dev.alias %}
                        <a href="#" data-toggle="modal" data-target="#aliasModal{{ dev.id }}">{{ dev.alias }}</a>
                    {% else %}
                        <a href="#" data-toggle="modal" data-target="#aliasModal{{ dev.id }}">{{ t("ALIAS_NONE") }}</a>
                    {% endif %}
                </td>
                <td class="align-middle">
                    {% if dev.ip_address != "-" %}
                        <form method="POST" action="{{ url_for('ping_device', device_id=dev.id) }}" class="d-inline">
                            <button type="submit" class="btn btn-info btn-sm">{{ t("TABLE_PING") }}</button>
                        </form>
                    {% else %}
                        -
                    {% endif %}
                </td>
                 <td class="align-middle">{{ dev.manufacturer or t("MANUFACTURER_UNKNOWN") }}</td>
                 <td class="align-middle">
                 {% if dev.last_seen_at %}
                 {{ dev.last_seen_at.strftime("%Y-%m-%d %H:%M:%S") }}
                 {% else %}
                     -
                  {% endif %}
                 </td>
                  <td class="align-middle">
                   <span class="{{ status_class }}">{{ status_text }}</span>
                   {% if dev.is_new %}
                    <span class="badge badge-warning ml-1">new</span>
                   {% endif %}
                     </td>

                <td class="align-middle">
                    {% if current_user.is_admin %}
                        <div class="d-flex">
                            {% if dev.is_new %}
                                <form method="POST" action="{{ url_for('mark_known', device_id=dev.id) }}" class="mr-1">
                                    <button type="submit" class="btn btn-warning btn-sm">{{ t("MARK_KNOWN") }}</button>
                                </form>
                            {% endif %}
                            <form method="POST" action="{{ url_for('delete_device', device_id=dev.id) }}">
                                <button type="submit" onclick="return confirm('{{ t("CONFIRM_DELETE") }}')" class="btn btn-danger btn-sm">{{ t("DELETE") }}</button>
                            </form>
                        </div>
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>

            <div class="modal fade" id="aliasModal{{ dev.id }}" tabindex="-1" role="dialog" aria-labelledby="aliasModalLabel{{ dev.id }}" aria-hidden="true">
              <div class="modal-dialog" role="document">
                <form method="POST" action="{{ url_for('update_alias') }}">
                    <div class="modal-content">
                      <div class="modal-header">
                        <h5 class="modal-title text-dark" id="aliasModalLabel{{ dev.id }}">{{ t("ALIAS_MODAL_TITLE") }}</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Stäng">
                          <span aria-hidden="true">&times;</span>
                        </button>
                      </div>
                      <div class="modal-body">
                            <input type="hidden" name="mac" value="{{ dev.mac_address }}">
                            <div class="form-group">
                                <label for="aliasInput{{ dev.id }}">{{ t("ALIAS_LABEL") }}</label>
                                <input type="text" class="form-control text-dark" id="aliasInput{{ dev.id }}" name="alias"
                                       value="{{ dev.alias or '' }}" placeholder="{{ t('ALIAS_LABEL') }}">
                            </div>
                      </div>
                      <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ t("CANCEL") }}</button>
                        <button type="submit" class="btn btn-primary">{{ t("ALIAS_SAVE") }}</button>
                      </div>
                    </div>
                </form>
              </div>
            </div>

            {% if dev.ip_address and dev.ip_address != "-" %}
            <div class="modal fade" id="ipModal{{ dev.id }}" tabindex="-1" role="dialog" aria-labelledby="ipModalLabel{{ dev.id }}" aria-hidden="true">
              <div class="modal-dialog" role="document">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title text-dark" id="ipModalLabel{{ dev.id }}">
                      IP addresses for {{ dev.alias or dev.mac_address }}
                    </h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                      <span aria-hidden="true">&times;</span>
                    </button>
                  </div>
                  <div class="modal-body">
                    {% set all_ips = dev.ip_address.split(",") %}
                    <ul class="list-group">
                      {% for addr in all_ips %}
<li class="list-group-item ip-modal-list-item">
  {{ addr | trim }}
</li>
                      {% endfor %}
                    </ul>
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                  </div>
                </div>
              </div>
            </div>
            {% endif %}

          {% endfor %}
          </tbody>
        </table>
      </div>

      <footer class="text-right">
        {{ t("INDEX_TITLE") }} - {{ t("VERSION_LABEL") }} {{ version }}
      </footer>
    </div>
  </div>
</div>

<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
<script>
  setInterval(function(){
    fetch("{{ url_for('get_scan_status') }}")
    .then(res => res.json())
    .then(data => {
      if(data.status === "running"){
        let scanInfo = document.getElementById("scan-info");
        if(!scanInfo){
          let scanDiv = document.createElement("div");
          scanDiv.className = "alert alert-info d-flex align-items-center mb-3";
          scanDiv.id = "scan-info";
          scanDiv.innerHTML = '<strong>{{ t("SCAN_RUNNING") }}</strong><div class="spinner-border text-primary ml-auto" role="status" aria-hidden="true"></div>';
          let cardBody = document.querySelector(".card-body");
          if(cardBody){
            cardBody.insertBefore(scanDiv, cardBody.firstChild.nextSibling);
          }
        }
      } else if(data.status === "done"){
        let scanInfo = document.getElementById("scan-info");
        if(scanInfo){
          scanInfo.remove();
          setTimeout(function(){
            window.location.reload();
          }, 2000);
        }
      }
    })
    .catch(error => {
      console.error('Error fetching scan status:', error);
    });
  }, 2000);
</script>
</body>
</html>
"""

SETUP_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("SETUP_TITLE") }} - {{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background: radial-gradient(circle at top, #1d4ed8 0, #020617 55%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .card-setup {
        border-radius: 12px;
        box-shadow: 0 15px 35px rgba(15,23,42,0.7);
        width: 100%;
        max-width: 450px;
    }
    .app-title {
        font-weight: 700;
    }
    .version-pill {
        font-size: 0.8rem;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        background-color: #eff6ff;
        color: #1d4ed8;
        border: 1px solid #bfdbfe;
        margin-left: 0.5rem;
    }
    </style>
</head>
<body>
<div class="card card-setup">
  <div class="card-header bg-white border-0">
    <h4 class="mb-0 app-title">
      {{ t("INDEX_TITLE") }}
      <span class="version-pill">{{ t("VERSION_LABEL") }} {{ version }}</span>
    </h4>
    <small class="text-muted">{{ t("SETUP_TITLE") }}</small>
  </div>
  <div class="card-body">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="mb-3">
        {% for category, msg in messages %}
          <div class="alert alert-{{ 'danger' if category=='danger' else category }}" role="alert">
            {{ msg }}
          </div>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <form method="POST" class="mt-2">
        <div class="form-group">
            <label for="language">{{ t("LANGUAGE_LABEL") }}</label>
            <select name="language" id="language" class="form-control">
                <option value="sv" {% if lang == 'sv' %}selected{% endif %}>{{ t("LANG_SV") }}</option>
                <option value="en" {% if lang == 'en' %}selected{% endif %}>{{ t("LANG_EN") }}</option>
            </select>
        </div>

        <div class="form-group">
            <label>{{ t("SETUP_USERNAME") }}</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="form-group">
            <label>{{ t("SETUP_PASSWORD") }}</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">{{ t("SETUP_CREATE_ADMIN") }}</button>
    </form>
  </div>
</div>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("LOGIN_TITLE") }} - {{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background: radial-gradient(circle at top, #22c55e 0, #020617 55%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .card-login {
        border-radius: 12px;
        box-shadow: 0 15px 35px rgba(15,23,42,0.7);
        width: 100%;
        max-width: 420px;
    }
    .app-title {
        font-weight: 700;
    }
    .version-pill {
        font-size: 0.8rem;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        background-color: #ecfdf5;
        color: #15803d;
        border: 1px solid #bbf7d0;
        margin-left: 0.5rem;
    }
    </style>
</head>
<body>
<div class="card card-login">
  <div class="card-header bg-white border-0">
    <h4 class="mb-0 app-title">
      {{ t("INDEX_TITLE") }}
      <span class="version-pill">{{ t("VERSION_LABEL") }} {{ version }}</span>
    </h4>
    <small class="text-muted">{{ t("LOGIN_TITLE") }}</small>
  </div>
  <div class="card-body">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="mb-3">
        {% for category, msg in messages %}
          <div class="alert alert-{{ 'danger' if category=='danger' else category }}" role="alert">
            {{ msg }}
          </div>
        {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    <form method="POST" class="mt-2">
        <div class="form-group">
            <label for="language">{{ t("LANGUAGE_LABEL") }}</label>
            <select name="language" id="language" class="form-control">
                <option value="sv" {% if lang == 'sv' %}selected{% endif %}>{{ t("LANG_SV") }}</option>
                <option value="en" {% if lang == 'en' %}selected{% endif %}>{{ t("LANG_EN") }}</option>
            </select>
        </div>

        <div class="form-group">
            <label>{{ t("LOGIN_USERNAME") }}</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="form-group">
            <label>{{ t("LOGIN_PASSWORD") }}</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-success btn-block">{{ t("LOGIN_BUTTON") }}</button>
    </form>
  </div>
</div>
</body>
</html>
"""

CHANGE_PASSWORD_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("CHANGE_PASSWORD_TITLE") }} - {{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background-color: #020617;
        color: #e5e7eb;
        min-height: 100vh;
    }
    .card-main {
        margin-top: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.6);
    }
    </style>
</head>
<body>
<div class="container">
  <div class="card card-main">
    <div class="card-header bg-dark text-light d-flex justify-content-between align-items-center">
      <div>
        <h5 class="mb-0">{{ t("CHANGE_PASSWORD_TITLE") }}</h5>
        <small class="text-muted">{{ t("VERSION_LABEL") }} {{ version }}</small>
      </div>
      <div>
        <a href="{{ url_for('index') }}" class="btn btn-secondary btn-sm">{{ t("BACK") }}</a>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">{{ t("LOGOUT") }}</a>
      </div>
    </div>
    <div class="card-body bg-dark text-light">

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="mb-3">
          {% for category, msg in messages %}
            <div class="alert alert-{{ 'danger' if category=='danger' else category }}" role="alert">
              {{ msg }}
            </div>
          {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <form method="POST">
        <div class="form-group">
            <label>{{ t("CHANGE_PASSWORD_NEW") }}</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary">{{ t("CHANGE_PASSWORD_UPDATE") }}</button>
      </form>
    </div>
  </div>
</div>
</body>
</html>
"""

MANAGE_USERS_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("MANAGE_USERS_TITLE") }} - {{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background-color: #020617;
        color: #e5e7eb;
        min-height: 100vh;
    }
    .card-main {
        margin-top: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.6);
    }
    </style>
</head>
<body>
<div class="container">
  <div class="card card-main">
    <div class="card-header bg-dark text-light d-flex justify-content-between align-items-center">
      <div>
        <h5 class="mb-0">{{ t("MANAGE_USERS_TITLE") }}</h5>
        <small class="text-muted">{{ t("VERSION_LABEL") }} {{ version }}</small>
      </div>
      <div>
        <a href="{{ url_for('index') }}" class="btn btn-secondary btn-sm">{{ t("BACK") }}</a>
        <a href="{{ url_for('change_password') }}" class="btn btn-warning btn-sm">{{ t("CHANGE_PASSWORD") }}</a>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">{{ t("LOGOUT") }}</a>
      </div>
    </div>
    <div class="card-body bg-dark text-light">

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="mb-3">
          {% for category, msg in messages %}
            <div class="alert alert-{{ 'danger' if category=='danger' else category }}" role="alert">
              {{ msg }}
            </div>
          {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <h5>{{ t("MANAGE_USERS_ADD_TITLE") }}</h5>
      <form method="POST" class="form-inline mb-4">
          <input type="hidden" name="action" value="add">
          <input name="username" class="form-control mr-2 mb-2" placeholder="{{ t('MANAGE_USERS_USERNAME') }}" required>
          <input name="password" class="form-control mr-2 mb-2" placeholder="{{ t('MANAGE_USERS_PASSWORD') }}" type="password" required>
          <button type="submit" class="btn btn-primary mb-2">{{ t("MANAGE_USERS_ADD_BUTTON") }}</button>
      </form>

      <h5>{{ t("MANAGE_USERS_EXISTING") }}</h5>
      <div class="table-responsive">
        <table class="table table-dark table-striped table-sm">
            <thead>
                <tr>
                    <th>{{ t("MANAGE_USERS_ID") }}</th>
                    <th>{{ t("MANAGE_USERS_USERNAME") }}</th>
                    <th>{{ t("MANAGE_USERS_IS_ADMIN") }}</th>
                    <th>{{ t("MANAGE_USERS_ACTION") }}</th>
                </tr>
            </thead>
            <tbody>
            {% for u in users %}
            <tr>
                <td>{{ u.id }}</td>
                <td>{{ u.username }}</td>
                <td>{{ t("MANAGE_USERS_ADMIN_LABEL") if u.is_admin else t("MANAGE_USERS_NOT_ADMIN_LABEL") }}</td>
                <td>
                    {% if not u.is_admin %}
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="user_id" value="{{ u.id }}">
                        <button type="submit" class="btn btn-danger btn-sm">{{ t("MANAGE_USERS_DELETE_BUTTON") }}</button>
                    </form>
                    {% else %}
                    {{ t("MANAGE_USERS_ADMIN_TAG") }}
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""

CONFIG_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ 'sv' if lang == 'sv' else 'en' }}">
<head>
    <meta charset="UTF-8">
    <title>{{ t("CONFIG_TITLE") }} - {{ t("INDEX_TITLE") }} v{{ version }}</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
    body {
        background-color: #020617;
        color: #e5e7eb;
        min-height: 100vh;
    }
    .card-main {
        margin-top: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.6);
    }

    /* Toggle switches */
    .toggle-switch {
        position: relative;
        display: inline-block;
        width: 44px;
        height: 24px;
    }

    .toggle-switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .toggle-slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #4b5563;
        transition: 0.3s;
        border-radius: 9999px;
    }

    .toggle-slider::before {
        position: absolute;
        content: "";
        height: 18px;
        width: 18px;
        left: 3px;
        bottom: 3px;
        background-color: #f9fafb;
        transition: 0.3s;
        border-radius: 9999px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.5);
    }

    .toggle-switch input:checked + .toggle-slider {
        background-color: #22c55e;
    }

    .toggle-switch input:checked + .toggle-slider::before {
        transform: translateX(20px);
    }

    .toggle-switch input:focus + .toggle-slider {
        box-shadow: 0 0 0 3px rgba(34,197,94,0.4);
    }

    </style>
</head>
<body>
<div class="container">
  <div class="card card-main">
    <div class="card-header bg-dark text-light d-flex justify-content-between align-items-center">
      <div>
        <h5 class="mb-0">{{ t("CONFIG_TITLE") }}</h5>
        <small class="text-muted">{{ t("VERSION_LABEL") }} {{ version }}</small>
      </div>
      <div>
        <a href="{{ url_for('index') }}" class="btn btn-secondary btn-sm">{{ t("BACK") }}</a>
        <a href="{{ url_for('change_password') }}" class="btn btn-warning btn-sm">{{ t("CHANGE_PASSWORD") }}</a>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">{{ t("LOGOUT") }}</a>
      </div>
    </div>
    <div class="card-body bg-dark text-light">

      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="mb-3">
          {% for category, msg in messages %}
            <div class="alert alert-{{ 'danger' if category=='danger' else category }}" role="alert">
              {{ msg }}
            </div>
          {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <form method="POST" class="form-inline mb-3">
          <input type="hidden" name="action" value="add_subnet">
          <label class="mr-2">{{ t("CONFIG_ADD_SUBNET_LABEL") }}</label>
          <input type="text" name="cidr" class="form-control mr-2" required>
          <button type="submit" class="btn btn-primary">{{ t("CONFIG_ADD_SUBNET_BUTTON") }}</button>
      </form>

      <div class="table-responsive mb-3">
        <table class="table table-dark table-striped table-sm">
            <thead>
                <tr>
                    <th>{{ t("CONFIG_SUBNET_COL") }}</th>
                    <th>{{ t("CONFIG_SUBNET_DELETE_COL") }}</th>
                </tr>
            </thead>
            <tbody>
            {% for sn in subnets %}
            <tr>
                <td>{{ sn.cidr }}</td>
                <td>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="delete_subnet">
                        <input type="hidden" name="subnet_id" value="{{ sn.id }}">
                        <button type="submit" class="btn btn-danger btn-sm">{{ t("CONFIG_SUBNET_DELETE_BUTTON") }}</button>
                    </form>
                </td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
      </div>

      <form method="POST" class="mb-4">
          <input type="hidden" name="action" value="guess">
          <button type="submit" class="btn btn-info">{{ t("CONFIG_GUESS_BUTTON") }}</button>
      </form>

      <hr class="border-secondary">
      <h5 class="mb-3">{{ t("CONFIG_OTHER_SETTINGS") }}</h5>
      <form method="POST">
        <input type="hidden" name="action" value="update_settings">

        <div class="form-group mb-2">
            <label for="language">{{ t("LANGUAGE_LABEL") }}</label>
            <select name="language" id="language" class="form-control">
                <option value="sv" {% if lang == 'sv' %}selected{% endif %}>{{ t("LANG_SV") }}</option>
                <option value="en" {% if lang == 'en' %}selected{% endif %}>{{ t("LANG_EN") }}</option>
            </select>
        </div>

        <div class="d-flex align-items-center mb-2">
            <span class="mr-2">{{ t("CONFIG_IPV6_ENABLE") }}</span>
            <label class="toggle-switch mb-0">
                <input type="checkbox" name="ipv6" id="ipv6check" {% if ipv6 %}checked{% endif %}>
                <span class="toggle-slider"></span>
            </label>
        </div>

        <div class="form-group mb-2">
            <label>{{ t("CONFIG_SCAN_INTERVAL") }}</label>
            <input type="number" name="scan_interval" class="form-control" value="{{ scan_interval }}" min="1" required>
        </div>

        <div class="d-flex align-items-center mb-2">
            <span class="mr-2">{{ t("CONFIG_HIGHLIGHT_NEW") }}</span>
            <label class="toggle-switch mb-0">
                <input type="checkbox" name="highlight_new" id="highlightCheck" {% if highlight_new %}checked{% endif %}>
                <span class="toggle-slider"></span>
            </label>
        </div>

        <div class="form-group mb-3">
            <label for="ipv6_utils">{{ t("CONFIG_IPV6_UTILS") }}</label>
            <input type="text" id="ipv6_utils" name="ipv6_utils" class="form-control" placeholder="eth0 / enp0s3 / wlan0"
                   value="{{ ipv6_utils }}">
        </div>

        <button type="submit" class="btn btn-success">{{ t("CONFIG_SAVE_BUTTON") }}</button>
      </form>

      <div class="mt-4 text-muted">
        <small>{{ t("INDEX_TITLE") }} - {{ t("VERSION_LABEL") }} {{ version }}</small>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""

# ---------------------------
#       STARTUP
# ---------------------------

if __name__ == "__main__":
    t_thread = threading.Thread(target=run_periodic_scan, daemon=True)
    t_thread.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
