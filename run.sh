#!/usr/bin/env bash
# Run the backend using the project venv.
# Creates .venv and installs deps if needed.

set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

echo "Installing dependencies..."
venv/bin/pip install -q -r requirements.txt

echo "Starting Flask..."
venv/bin/flask run --port 5000
