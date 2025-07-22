#!/usr/bin/env python3.12

import os
import sys

if alpine_python := os.environ.get("ALPINEPYTHON"):
    new_paths = ":".join([f"/usr/local/lib/{alpine_python}/site-packages", f"/usr/lib/{alpine_python}/site-packages"])
    if python_path := os.environ.get("PYTHONPATH", ""):
        python_path = f"{python_path}:{new_paths}"
    else:
        python_path = new_paths
    os.environ["PYTHONPATH"] = python_path

if len(sys.argv) > 1:
    command = sys.argv[1:]
    os.execvp(command[0], command)
else:
    print("No command provided to execute.")
