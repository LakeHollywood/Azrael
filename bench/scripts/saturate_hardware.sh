#!/usr/bin/env bash
# TC2 hardware-grade saturation: stress-ng CPU+GPU thermal loading.
# Run in a second terminal while `python -m bench.run_benchmark` executes.
set -euo pipefail
DUR="${DUR:-120}"
command -v stress-ng >/dev/null 2>&1 || { echo "install stress-ng on the rig first"; exit 1; }
stress-ng --cpu "$(nproc)" --cpu-method matrixprod --gpu 4 \
          --thermal-zone 0 --timeout "$DUR" --metrics-brief
