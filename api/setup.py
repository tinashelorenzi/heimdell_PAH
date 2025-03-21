#!/usr/bin/env python3
import requests
import json
import sys
from pathlib import Path

from ..core.config import load_keys

def athena_keyexchange():
    local_keys = load_keys()
    print(local_keys)

if __name__ == "__main__":
    athena_keyexchange()
	