#!/usr/bin/env python3.12
import sys
import tomllib

if __name__ == "__main__":
    with open("pyproject.toml", "rb") as f:
        toml = tomllib.load(f)

    val = toml["tool"]
    for key in sys.argv[1:]:
        val = val.get(key, {})
    print(val)
