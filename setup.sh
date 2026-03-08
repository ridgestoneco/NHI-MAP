#!/bin/bash
set -e

echo "=== NHI Map Setup ==="
echo ""

# --- PostgreSQL ---
echo "[1/4] Setting up PostgreSQL..."

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "  Installing PostgreSQL..."
    sudo apt update -qq
    sudo apt install -y postgresql postgresql-contrib
fi

# Start PostgreSQL if not running
if ! sudo pg_isready -q 2>/dev/null; then
    echo "  Starting PostgreSQL..."
    sudo service postgresql start
fi

# Create user and database (idempotent)
echo "  Creating database user 'nhi_user' and database 'nhi_map'..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='nhi_user'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER nhi_user WITH PASSWORD 'changeme';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_catalog.pg_database WHERE datname='nhi_map'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE nhi_map OWNER nhi_user;"

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE nhi_map TO nhi_user;" 2>/dev/null || true

echo "  PostgreSQL ready."
echo ""

# --- Python venv ---
echo "[2/4] Setting up Python virtual environment..."

cd "$(dirname "$0")/backend"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "  Created venv."
fi

source venv/bin/activate

echo "[3/4] Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "  Dependencies installed."
echo ""

# --- .env ---
echo "[4/4] Checking .env..."

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "  Created .env from .env.example."
    echo "  >>> IMPORTANT: Edit backend/.env to change default passwords before production use."
else
    echo "  .env already exists, skipping."
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Default credentials (CHANGE THESE):"
echo "  DB User:     nhi_user"
echo "  DB Password: changeme"
echo "  API Key:     disabled (default key skips auth)"
echo ""
echo "To start:"
echo "  cd backend && source venv/bin/activate"
echo "  uvicorn main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Then open http://localhost:8000"
