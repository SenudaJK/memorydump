#!/bin/bash

#================================================================================
# MEMORY FORENSICS ANALYSIS SCRIPT
# Mid-Term Assignment: Memory Dump Analysis & Reporting
#================================================================================
# Purpose: Automate Volatility 3 analysis of WinDump.mem to satisfy all
#          assignment requirements (sections 3.1-3.6)
# Author:  [Your Name]
# Date:    $(date +%Y-%m-%d)
#================================================================================

# Configuration
IMAGE="WinDump.mem"
OUTDIR="output"

# Auto-detect Volatility command (tries multiple common paths/commands)
if command -v /home/senjlk/volatility/volatility3/venv/bin/vol &> /dev/null; then
    VOL="/home/senjlk/volatility/volatility3/venv/bin/vol"
elif command -v vol3 &> /dev/null; then
    VOL="vol3"
elif command -v vol &> /dev/null; then
    VOL="vol"
elif python3 -c "import volatility3.cli" 2>/dev/null; then
    VOL="python3 -m volatility3.cli"
else
    VOL="vol"  # fallback (will error if not found)
fi

# Suspicious PIDs identified from initial analysis (update these after first run)
SUSPICIOUS_PIDS="9932 2688"  # remsh.exe, MsMpEng.exe (injected)

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

#================================================================================
# HELPER FUNCTIONS
#================================================================================

print_section() {
    echo -e "\n${GREEN}=============================================="
    echo -e "  $1"
    echo -e "==============================================${NC}\n"
}

print_step() {
    echo -e "${YELLOW}[$1] $2${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

#================================================================================
# START ANALYSIS
#================================================================================

print_section "VOLATILITY FORENSIC ANALYSIS"
echo "Memory Image: $IMAGE"
echo "OS Profile: Windows 10 Build 15063 (Creators Update)"
echo "Analysis Date: $(date)"
echo "Volatility Version: $($VOL --version 2>&1 | head -1)"
echo ""

# Check if image exists
if [ ! -f "$IMAGE" ]; then
    print_error "Memory image '$IMAGE' not found!"
    exit 1
fi

# Create output directories
mkdir -p "$OUTDIR/dumped_processes" "$OUTDIR/dumped_files" "$OUTDIR/charts"

#================================================================================
# 3.1 PREPARE THE ENVIRONMENT
#================================================================================

print_section "3.1 PREPARE ENVIRONMENT & VERIFY IMAGE"

print_step "1a" "Computing SHA256 hash (chain of custody)..."
sha256sum "$IMAGE" > "$OUTDIR/WinDump.mem.sha256"
cat "$OUTDIR/WinDump.mem.sha256"

print_step "1b" "Computing MD5 hash (legacy compatibility)..."
md5sum "$IMAGE" > "$OUTDIR/WinDump.mem.md5"
cat "$OUTDIR/WinDump.mem.md5"

print_step "1c" "Determining OS profile (windows.info)..."
$VOL -f "$IMAGE" windows.info > "$OUTDIR/system_info.txt"
echo "Profile/symbol information saved to $OUTDIR/system_info.txt"
head -20 "$OUTDIR/system_info.txt"

#================================================================================
# 3.2 PROCESS ENUMERATION
#================================================================================

print_section "3.2 PROCESS ENUMERATION"

print_step "2a" "Listing running processes (pslist)..."
$VOL -f "$IMAGE" windows.pslist > "$OUTDIR/pslist.txt"
echo "Saved to $OUTDIR/pslist.txt"

print_step "2b" "Process tree with parent-child relationships (pstree)..."
$VOL -f "$IMAGE" windows.pstree > "$OUTDIR/pstree.txt"
echo "Saved to $OUTDIR/pstree.txt"

print_step "2c" "Scanning for hidden/terminated processes (psscan)..."
$VOL -f "$IMAGE" windows.psscan > "$OUTDIR/psscan.txt"
echo "Saved to $OUTDIR/psscan.txt"

#================================================================================
# 3.3 NETWORK ANALYSIS
#================================================================================

print_section "3.3 NETWORK ANALYSIS"

print_step "3a" "Enumerating network connections (netscan)..."
$VOL -f "$IMAGE" windows.netscan > "$OUTDIR/netscan.txt"
echo "Saved to $OUTDIR/netscan.txt"
echo ""
echo "Top 10 remote endpoints by connection count:"
grep -E "ESTABLISHED|CLOSED" "$OUTDIR/netscan.txt" | awk '{print $6}' | sort | uniq -c | sort -rn | head -10

#================================================================================
# 3.4 DLL AND HANDLE INSPECTION
#================================================================================

print_section "3.4 DLL & HANDLE INSPECTION"

print_step "4a" "Listing loaded DLLs for all processes (dlllist)..."
$VOL -f "$IMAGE" windows.dlllist > "$OUTDIR/dlllist_all.txt"
echo "Saved to $OUTDIR/dlllist_all.txt"

print_step "4b" "Checking module load inconsistencies (ldrmodules)..."
$VOL -f "$IMAGE" windows.ldrmodules > "$OUTDIR/ldmodules.txt"
echo "Saved to $OUTDIR/ldmodules.txt"

print_step "4c" "Listing file handles (handles)..."
$VOL -f "$IMAGE" windows.handles > "$OUTDIR/handles.txt"
echo "Saved to $OUTDIR/handles.txt"

print_step "4d" "Scanning file objects (filescan)..."
$VOL -f "$IMAGE" windows.filescan > "$OUTDIR/filescan.txt"
echo "Saved to $OUTDIR/filescan.txt"

#================================================================================
# 3.5 DETECT INJECTED CODE
#================================================================================

print_section "3.5 DETECT INJECTED CODE"

print_step "5a" "Detecting code injection (malfind)..."
$VOL -f "$IMAGE" windows.malfind > "$OUTDIR/malfind.txt"
echo "Saved to $OUTDIR/malfind.txt"
echo ""
echo "Processes with RWX regions:"
grep -E "^[0-9]+" "$OUTDIR/malfind.txt" | awk '{print $2}' | sort | uniq -c | sort -rn

print_step "5b" "Dumping suspicious processes (procdump)..."
for PID in $SUSPICIOUS_PIDS; do
    echo "  - Dumping PID $PID..."
    $VOL -f "$IMAGE" -o "$OUTDIR/dumped_processes" windows.procdump --pid "$PID" >> "$OUTDIR/procdump_${PID}.txt" 2>&1
done
ls -lh "$OUTDIR/dumped_processes/" 2>/dev/null || echo "  (No dumps produced; check procdump_*.txt for errors)"

print_step "5c" "Extracting injected memory regions (dumpfiles)..."
for PID in $SUSPICIOUS_PIDS; do
    echo "  - Extracting memory for PID $PID..."
    $VOL -f "$IMAGE" -o "$OUTDIR/dumped_files" windows.dumpfiles --pid "$PID" >> "$OUTDIR/dumpfiles_${PID}.txt" 2>&1
done
ls -lh "$OUTDIR/dumped_files/" 2>/dev/null || echo "  (No dumps produced; check dumpfiles_*.txt for errors)"

#================================================================================
# 3.6 ADDITIONAL ANALYSIS
#================================================================================

print_section "3.6 ADDITIONAL ANALYSIS"

print_step "6a" "Command history (cmdscan)..."
$VOL -f "$IMAGE" windows.cmdscan > "$OUTDIR/cmdscan.txt" 2>&1
echo "Saved to $OUTDIR/cmdscan.txt (may fail on this build)"

print_step "6b" "Console buffers (consoles)..."
$VOL -f "$IMAGE" windows.consoles > "$OUTDIR/console.txt" 2>&1
echo "Saved to $OUTDIR/console.txt (may fail on this build)"

print_step "6a2" "Process command lines (cmdline) — more compatible alternative..."
$VOL -f "$IMAGE" windows.cmdline > "$OUTDIR/cmdline.txt" 2>&1
echo "Saved to $OUTDIR/cmdline.txt"

print_step "6c" "Environment variables (envars)..."
$VOL -f "$IMAGE" windows.envars > "$OUTDIR/envars.txt"
echo "Saved to $OUTDIR/envars.txt"

print_step "6d" "User SIDs (getsids)..."
$VOL -f "$IMAGE" windows.getsids > "$OUTDIR/getsids.txt"
echo "Saved to $OUTDIR/getsids.txt"

print_step "6e" "Kernel drivers (driverscan)..."
$VOL -f "$IMAGE" windows.driverscan > "$OUTDIR/driverscan.txt"
echo "Saved to $OUTDIR/driverscan.txt"

print_step "6f" "Mutex objects (mutantscan)..."
$VOL -f "$IMAGE" windows.mutantscan > "$OUTDIR/mutantscan.txt"
echo "Saved to $OUTDIR/mutantscan.txt"

#================================================================================
# GENERATE CHARTS & VISUALIZATIONS
#================================================================================

print_section "GENERATE VISUALIZATIONS"

print_step "7a" "Creating netscan top-10 chart (requires matplotlib)..."

python3 - <<'PYEOF' 2>"$OUTDIR/nets_chart_error.txt"
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

ips = {}
try:
    with open('output/netscan.txt', 'r', errors='ignore') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 6 and ':' in parts[5]:
                remote = parts[5]
                ips[remote] = ips.get(remote, 0) + 1
    
    items = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]
    if items:
        labels = [i[0] for i in items]
        vals = [i[1] for i in items]
        
        plt.figure(figsize=(10, 6))
        plt.barh(range(len(vals)), vals, color='steelblue')
        plt.yticks(range(len(vals)), labels)
        plt.gca().invert_yaxis()
        plt.xlabel('Connection Count')
        plt.title('Top 10 Remote Endpoints by Connection Count')
        plt.tight_layout()
        plt.savefig('output/charts/nets_top10.png', dpi=150)
        print('Chart saved to output/charts/nets_top10.png')
    else:
        print('No remote IPs found in netscan.txt')
except Exception as e:
    print(f'Error: {e}')
    import sys
    sys.exit(1)
PYEOF

if [ $? -eq 0 ]; then
    echo "✓ Chart generated successfully"
else
    print_error "Chart generation failed (check $OUTDIR/nets_chart_error.txt)"
    echo "  Tip: Install matplotlib with: python3 -m pip install matplotlib"
fi

#================================================================================
# PACKAGE ARTIFACTS
#================================================================================

print_section "PACKAGE ARTIFACTS FOR SUBMISSION"

print_step "8a" "Creating artifacts archive..."

ARTIFACT_ZIP="scantestwin4_artifacts.zip"

# Check if zip is available; use tar.gz as fallback
if command -v zip &> /dev/null; then
    cd "$OUTDIR"
    zip -r "../$ARTIFACT_ZIP" \
        *.txt \
        *.sha256 \
        *.md5 \
        dumped_processes/ \
        dumped_files/ \
        charts/ \
        2>/dev/null
    cd ..
    echo "✓ Artifacts packaged to $ARTIFACT_ZIP"
    ls -lh "$ARTIFACT_ZIP"
else
    tar -czf "${ARTIFACT_ZIP%.zip}.tar.gz" "$OUTDIR"
    echo "✓ Artifacts packaged to ${ARTIFACT_ZIP%.zip}.tar.gz (zip not available)"
    ls -lh "${ARTIFACT_ZIP%.zip}.tar.gz"
fi

#================================================================================
# SUMMARY
#================================================================================

print_section "ANALYSIS COMPLETE"

echo "Output Directory: $OUTDIR/"
echo ""
echo "Generated Files:"
echo "  - system_info.txt         (3.1 OS profile)"
echo "  - WinDump.mem.sha256      (3.1 hash verification)"
echo "  - WinDump.mem.md5         (3.1 hash verification)"
echo "  - pslist.txt              (3.2 process list)"
echo "  - pstree.txt              (3.2 process tree)"
echo "  - psscan.txt              (3.2 hidden processes)"
echo "  - netscan.txt             (3.3 network connections)"
echo "  - dlllist_all.txt         (3.4 loaded DLLs)"
echo "  - ldmodules.txt           (3.4 module inconsistencies)"
echo "  - handles.txt             (3.4 file handles)"
echo "  - filescan.txt            (3.4 file objects)"
echo "  - malfind.txt             (3.5 injected code)"
echo "  - procdump_*.txt          (3.5 process dumps)"
echo "  - dumpfiles_*.txt         (3.5 memory dumps)"
echo "  - cmdscan.txt             (3.6 command history)"
echo "  - envars.txt              (3.6 environment variables)"
echo "  - getsids.txt             (3.6 user SIDs)"
echo "  - driverscan.txt          (3.6 kernel drivers)"
echo "  - mutantscan.txt          (3.6 mutex objects)"
echo "  - charts/nets_top10.png   (visualization)"
echo ""
echo "Dumped Binaries:"
ls -lh "$OUTDIR/dumped_processes/" 2>/dev/null | tail -n +2 | wc -l | xargs echo "  - Process dumps:"
ls -lh "$OUTDIR/dumped_files/" 2>/dev/null | tail -n +2 | wc -l | xargs echo "  - Memory regions:"
echo ""
echo "Next Steps:"
echo "  1. Review forensic_report.md"
echo "  2. Analyze suspicious processes/IPs in the outputs"
echo "  3. Submit: forensic_report.pdf + $ARTIFACT_ZIP"
echo ""
echo "For questions or issues, review the assignment requirements (sections 3.1-3.6)"
echo ""

