#!/usr/bin/env python3
from pathlib import Path
import re
print(re.search(r"project\(SentinelSIEM VERSION ([0-9.]+)", (Path(__file__).resolve().parents[1] / "CMakeLists.txt").read_text()).group(1))
