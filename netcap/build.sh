#!/bin/bash

# Create a virtual environment
python3 -m venv netcap_venv

# Activate the virtual environment
source netcap_venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate the virtual environment
deactivate

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ln -sf "$SCRIPT_DIR/run.sh" /usr/local/bin/netcap
chmod +x "$SCRIPT_DIR/run.sh"
mkdir /etc/netcap
cp -r $SCRIPT_DIR/* /etc/netcap/
