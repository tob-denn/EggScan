#!/usr/bin/env bash
set -euo pipefail

echo "=== EggScan installer ==="

# ------------------------------------------------------------------------------
# 1. Basic checks
# ------------------------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use: sudo ./install_eggscan.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/eggscan"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_FILE="/lib/systemd/system/eggscan.service"
DB_PATH="$INSTALL_DIR/eggscan.db"

echo "Installing from directory: $SCRIPT_DIR"
echo "Install directory: $INSTALL_DIR"
echo "Virtualenv: $VENV_DIR"
echo

check_dpkg_lock() {
    echo "Checking if apt/dpkg is busy (locks on /var/lib/dpkg/lock* )..."
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        echo "  dpkg/apt is locked by another process. Waiting 5 seconds..."
        sleep 5
    done
    echo "dpkg/apt is free, continuing."
}

# ------------------------------------------------------------------------------
# 2. Install system packages (only base tools, no Python libs)
# ------------------------------------------------------------------------------

echo "Updating package index..."
check_dpkg_lock
apt-get update -y

echo "Installing system packages (python3, pip, venv, nmap, iproute2, sqlite3)..."
check_dpkg_lock
apt-get install -y python3 python3-pip python3-venv nmap iproute2 sqlite3

echo
echo "System packages done."
echo

# ------------------------------------------------------------------------------
# 3. Create virtualenv for EggScan
# ------------------------------------------------------------------------------

echo "Creating install directory and virtualenv..."

mkdir -p "$INSTALL_DIR"

if [ -d "$VENV_DIR" ]; then
    echo "Virtualenv already exists at $VENV_DIR"
else
    python3 -m venv "$VENV_DIR"
    echo "Created virtualenv at $VENV_DIR"
fi

PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"

if [ ! -x "$PYTHON_BIN" ]; then
    echo "ERROR: $PYTHON_BIN not found or not executable."
    exit 1
fi

echo
echo "Upgrading pip inside the virtualenv..."
"$PYTHON_BIN" -m pip install --upgrade pip

# ------------------------------------------------------------------------------
# 4. Install Python dependencies *inside* the virtualenv
# ------------------------------------------------------------------------------

echo
echo "Installing Python packages via pip inside venv (Flask, SQLAlchemy, Login, Bcrypt, python-nmap)..."

"$PIP_BIN" install \
    Flask \
    flask_sqlalchemy \
    Flask-Login \
    Flask-Bcrypt \
    python-nmap

echo
echo "Verifying that Python dependencies can be imported from the venv..."
"$PYTHON_BIN" - << 'EOF'
import flask
import flask_sqlalchemy
import flask_login
import flask_bcrypt
import nmap
print(" Python dependencies inside venv look OK.")
EOF

# ------------------------------------------------------------------------------
# 5. Copy application files (eggscan.py + version.json) to /opt/eggscan
# ------------------------------------------------------------------------------

echo
echo "Copying eggscan.py and version.json to $INSTALL_DIR ..."

if [ ! -f "$SCRIPT_DIR/eggscan.py" ]; then
    echo "ERROR: eggscan.py not found in $SCRIPT_DIR"
    exit 1
fi

cp "$SCRIPT_DIR/eggscan.py" "$INSTALL_DIR/eggscan.py"
chmod 755 "$INSTALL_DIR/eggscan.py"

if [ -f "$SCRIPT_DIR/version.json" ]; then
    cp "$SCRIPT_DIR/version.json" "$INSTALL_DIR/version.json"
else
    echo "WARNING: version.json not found in $SCRIPT_DIR – continuing without it."
fi

echo "Application files copied."

# ------------------------------------------------------------------------------
# 6. Database migration (ensure last_seen_at column exists)
# ------------------------------------------------------------------------------

echo
echo "Checking for existing EggScan database for migration..."

if [ -f "$DB_PATH" ]; then
    echo "Existing database found at $DB_PATH"

    DEVICE_TABLE_EXISTS=$(sqlite3 "$DB_PATH" ".tables device" | grep -c '^device$' || true)

    if [ "$DEVICE_TABLE_EXISTS" -eq 1 ]; then
        echo "device table exists, checking for last_seen_at column..."

        HAS_LAST_SEEN_COL=$(sqlite3 "$DB_PATH" "PRAGMA table_info(device);" | awk -F'|' '{print $2}' | grep -c '^last_seen_at$' || true)

        if [ "$HAS_LAST_SEEN_COL" -eq 0 ]; then
            echo "last_seen_at column is missing, applying migration..."
            sqlite3 "$DB_PATH" "ALTER TABLE device ADD COLUMN last_seen_at DATETIME;"
            echo "Migration done: last_seen_at column added to device table."
        else
            echo "Migration skipped: last_seen_at column already exists."
        fi
    else
        echo "device table does not exist yet in $DB_PATH, skipping migration."
    fi
else
    echo "No existing database found at $DB_PATH (fresh install), skipping DB migration."
fi

# ------------------------------------------------------------------------------
# 7. Create systemd unit that uses the virtualenv Python
# ------------------------------------------------------------------------------

echo
echo "Creating systemd unit at $SERVICE_FILE ..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EggScan - Network Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_BIN $INSTALL_DIR/eggscan.py
Restart=always
RestartSec=5

# Run as root by default (no User= line). If you want a dedicated user,
# create one and add: User=eggscan Group=eggscan
# and ensure permissions on $INSTALL_DIR and any data dirs.

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling EggScan service at boot..."
systemctl enable eggscan.service

echo "Restarting EggScan service..."
systemctl restart eggscan.service || systemctl start eggscan.service

echo
echo "=== Status for eggscan.service ==="
systemctl status eggscan.service --no-pager || true

echo
echo " EggScan installation finished."
echo "If everything looks good above, you can open the web UI on port 5000 of this machine."
echo "The service runs with its own virtualenv at: $VENV_DIR"