#!/usr/bin/env python3

import json
import logging
import os
import subprocess
import tomllib

# Configure logging
log_file = "/var/log/messages"
logging.basicConfig(filename=log_file, level=logging.INFO, format='[%(filename)s] %(message)s')

debug_mode = os.environ.get("DEBUG")

if not debug_mode:
    logging.info("DEBUG MODE OFF")
else:
    logging.info("DEBUG MODE ON")
    try:
        with open("pyproject.toml", "rb") as f:
            toml = tomllib.load(f)["tool"]
            poetry = toml["poetry"]

            desc = poetry["description"]
            name = poetry["name"]
            version = poetry["version"]

            logging.info(f"Integration Module: {desc}")
            logging.info(f"{' ' * 11}Version: {version}")
    except FileNotFoundError:
        logging.warning("container_settings.json not found.")
    except json.JSONDecodeError:
        logging.error("Error decoding container_settings.json.")
    logging.info("Starting supervisord ...")

# Execute supervisord
try:
    subprocess.run(["/usr/bin/supervisord", "-c", "/supervisord.ini"], check=True)
except subprocess.CalledProcessError as e:
    logging.error(f"supervisord failed to start with error: {e}")
    exit(1)
except FileNotFoundError:
    logging.error("supervisord not found at /usr/bin/supervisord")
    exit(1)
