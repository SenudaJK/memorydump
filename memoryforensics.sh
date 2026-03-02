#!/bin/bash

# Create output directories
mkdir -p output/dumped_processes
mkdir -p output/dumped_files

echo "=============================================="
echo "   VOLATILITY FORENSIC ANALYSIS"
echo "=============================================="
echo "Memory File: WinDump.mem"
echo "OS: Windows 10 Build 15063"
echo "Date: $(date)"
echo "=============================================="
echo ""

echo "[1/15] System Information..."
vol -f WinDump.mem windows.info > output/system_info.txt

echo "[2/15] Process List..."
vol -f WinDump.mem windows.pslist > output/pslist.txt

echo "[3/15] Process Tree..."
vol -f WinDump.mem windows.pstree > output/pstree.txt

echo "[4/15] Process Scan (hidden processes)..."
vol -f WinDump.mem windows.psscan > output/psscan.txt

echo "[5/15] Network Connections..."
vol -f WinDump.mem windows.netscan > output/netscan.txt

echo "[6/15] DLL List (all processes)..."
vol -f WinDump.mem windows.dlllist > output/dlllist_all.txt

echo "[7/15] File Handles..."
vol -f WinDump.mem windows.handles > output/handles.txt

echo "[8/15] File Scan..."
vol -f WinDump.mem windows.filescan > output/filescan.txt

echo "[9/15] Malware Detection (malfind)..."
vol -f WinDump.mem windows.malfind > output/malfind.txt

echo "[10/15] Loaded Modules (ldrmodules)..."
vol -f WinDump.mem windows.ldmodules > output/ldmodules.txt

echo "[11/15] Command History..."
vol -f WinDump.mem windows.cmdscan > output/cmdscan.txt 2>&1

echo "[12/15] Console Output..."
vol -f WinDump.mem windows.console > output/console.txt 2>&1

echo "[13/15] Environment Variables..."
vol -f WinDump.mem windows.envars > output/envars.txt

echo "[14/15] User SIDs..."
vol -f WinDump.mem windows.getsids > output/getsids.txt

echo "[15/15] Drivers & Mutexes..."
vol -f WinDump.mem windows.driverscan > output/driverscan.txt
vol -f WinDump.mem windows.mutantscan > output/mutantscan.txt

echo ""
echo "=============================================="
echo "   ANALYSIS COMPLETE"
echo "=============================================="
echo ""
echo "Output files:"
ls -lh output/*.txt
echo ""
echo "Dumped files:"
ls -lh output/dumped_processes/ 2>/dev/null
ls -lh output/dumped_files/ 2>/dev/null
echo ""
echo "Next: Review output files for suspicious activity"

