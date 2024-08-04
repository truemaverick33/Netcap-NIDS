#!/bin/bash

# Activate the virtual environment
source /etc/netcap/netcap_venv/bin/activate

# Run your Python project
sudo -E /etc/netcap/netcap_venv/bin/python3 /etc/netcap/netcap9m5.py

# Deactivate the virtual environment (optional if your project terminates)
deactivate

