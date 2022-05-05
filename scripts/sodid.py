#!/bin/bash
# Script generates EF.SOD ID from EF.SOD file or hex
import sys
from pathlib import Path
from port.proto import SodId
from pymrtd import ef

def fatal_error(msg: str):
    print(msg, file=sys.stderr)
    exit(1)

if __name__ == "__main__":
    if len(sys.argv[1:]) == 0:
        fatal_error("Usage:  sodid.py <path_to_ef.sod_file|ef.sod_hex>")
    try:
        raw_sod = None
        sod_file = Path(sys.argv[1])
        if sod_file.exists() and sod_file.is_file():
            with sod_file.open('rb') as f:
                raw_sod = f.read()
        else: # Try to load hex sting
            raw_sod = bytes.fromhex(sys.argv[1])

        sodId = SodId.fromSOD(ef.SOD.load(raw_sod))
        print("EF.SOD ID: ", sodId.hex())
    except Exception as e:
        fatal_error(f"And error has occurred: {str(e)}")
