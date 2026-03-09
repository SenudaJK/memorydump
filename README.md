# Memory Forensics — WinDump.mem Analysis

Repository containing a memory image and Volatility analysis outputs for a Windows 10 host.

## Overview

This repository stores a raw physical memory image (`WinDump.mem`), an automated analysis script (`memoryforensics.sh`), the generated Volatility output files (`output/`), and a formal investigation report (`forensic_report.md`). The analysis was performed with Volatility (Volatility 3 CLI) against a Windows 10 (build 15063) memory capture.

## Contents

- `WinDump.mem` — raw physical memory image (case evidence)
- `memoryforensics.sh` — Bash wrapper that runs a sequence of Volatility plugins and saves outputs to `output/`
- `forensic_report.md` — Analyst report summarizing findings, IOCs, and methodology
- `output/` — Directory with analysis results (multiple `.txt` files, dumped files and processes)

Common output files (examples):
- `output/system_info.txt`
- `output/pslist.txt`
- `output/pstree.txt`
- `output/psscan.txt`
- `output/netscan.txt`
- `output/malfind.txt`
- `output/dlllist_all.txt`
- `output/handles.txt`
- `output/filescan.txt`
- `output/WinDump.mem.sha256` and `output/WinDump.mem.md5` — image hash values

## Prerequisites

- Linux (analysis host)
- Python 3 (used by Volatility 3)
- Volatility 3 CLI (the script invokes `vol`) — recommended: the same version used during analysis (see `forensic_report.md`)
- Shell utilities: `bash`, `sha256sum`, `md5sum`

Notes:
- The included `memoryforensics.sh` script is written to call `vol -f WinDump.mem <plugin>` and therefore expects the `vol` CLI to be available in `PATH`.

## Quick Start — Reproduce Analysis

1. Ensure prerequisites are installed (Volatility 3 and Python 3).
2. Make the script executable (if needed) and run it from the repository root where `WinDump.mem` is located:

```bash
chmod +x memoryforensics.sh
./memoryforensics.sh
```

3. After the script completes, review the generated files in `output/`.

If you prefer to run Volatility plugins manually use the `vol` CLI directly, for example:

```bash
vol -f WinDump.mem windows.pslist > output/pslist.txt
vol -f WinDump.mem windows.netscan > output/netscan.txt
```

To verify image integrity (hashes):

```bash
sha256sum WinDump.mem > output/WinDump.mem.sha256
md5sum WinDump.mem > output/WinDump.mem.md5
```

## Attribution & License

This repository contains case materials for investigative purposes. No license is specified — treat the contents as case evidence and handle accordingly.

---
