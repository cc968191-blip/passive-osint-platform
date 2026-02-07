#!/bin/bash
# Deployment script for Passive OSINT Platform

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     PASSIVE OSINT PLATFORM - DEPLOYMENT SCRIPT                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"

# Check Python version
echo ""
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[✓] Python version: $python_version"

# Create virtual environment
echo ""
echo "[*] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[✓] Virtual environment created"
else
    echo "[✓] Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "[*] Activating virtual environment..."
source venv/bin/activate || . venv/Scripts/activate
echo "[✓] Virtual environment activated"

# Upgrade pip
echo ""
echo "[*] Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo "[✓] pip upgraded"

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip install -r requirements.txt
echo "[✓] Dependencies installed"

# Create .env file if it doesn't exist
echo ""
echo "[*] Checking configuration..."
if [ ! -f ".env" ]; then
    echo "[*] Creating .env from template..."
    cp .env.example .env
    echo "[!] Please edit .env with your API keys"
else
    echo "[✓] .env file exists"
fi

# Run tests
echo ""
echo "[*] Running installation tests..."
python test_example.py
echo "[✓] Tests passed"

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  DEPLOYMENT COMPLETE                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys (optional)"
echo "  2. Run: python app.py"
echo "  3. Open: http://localhost:5000"
echo ""
echo "For production deployment:"
echo "  gunicorn wsgi:app --workers 4 --bind 0.0.0.0:5000"
echo ""
