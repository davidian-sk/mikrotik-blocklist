#!/usr/bin/env bash
#
# Threat Feed Aggregator (Local Version)
# Purpose: Downloads multiple threat feeds, dedupes, removes private ranges,
#          compresses to minimal CIDR ranges, generates a RouterOS .rsc script.
#          Designed for cron execution; DOES NOT interact with Git.
#
# Fix Notes: Uses 'ipaddress.ip_network(..., strict=False)' for robustly handling
#            mixed IP/CIDR inputs and ensures the script is runnable via cron.

# --- Configuration ---
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
RSC_OUTPUT="blocklist.rsc"
SOURCES_FILE="sources.txt"
LIST_NAME="davidian-sk-blocklist"

# --- Function to clean up on exit ---
cleanup() {
    rm -f temp_raw.txt temp_clean.txt
    echo -e "\nCleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

# --- CRON JOB SAFETY (Crucial for cron) ---
# Ensure the script executes from its own directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit

# --- 1. Download and Extract IPs/Ranges from Sources ---
echo "Starting IP aggregation and cleanup... 🚀"

# Check if sources.txt exists
if [[ ! -f "$SOURCES_FILE" ]]; then
    echo -e "\n❌ ERROR: $SOURCES_FILE not found. Cannot proceed."
    exit 1
fi

# Clear the raw file before starting
> temp_raw.txt

while IFS= read -r url; do
    if [[ -z "$url" ]]; then
        continue # Skip empty lines
    fi

    echo "Processing $url..."

    # Use curl to download and pipe directly to processing.
    # The regex is now highly permissive to catch:
    # 1. IPv4 addresses (e.g., 1.2.3.4)
    # 2. IPv4 ranges (e.g., 1.2.3.0/24)
    # It also strips surrounding garbage from MikroTik commands or JSON data.
    curl -sL "$url" | \
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\d{1,2})?' | \
    sed -E 's/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/\//\1/g' | \
    sed -E 's/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/([0-9]+).*/\1\/\2/g' >> temp_raw.txt

done < "$SOURCES_FILE"

TOTAL_RAW_LINES=$(wc -l < temp_raw.txt 2>/dev/null || echo 0)
echo -e "\nExtraction complete. Total raw lines collected: $TOTAL_RAW_LINES"

# --- 2. Deduplication and Initial Cleanup ---
echo "Deduplicating and filtering IPs/Ranges..."

# 1. Sort and uniq to remove duplicates (pre-Python optimization)
# 2. Fix leading zeros (e.g., 1.2.3.004 -> 1.2.3.4) for Python compatibility
sort -h temp_raw.txt | uniq | sed -E 's/\.0+([0-9]+)/\.\1/g' > "$FINAL_IP_LIST"

# 3. Filter out common private/reserved ranges
grep -vE '^10\.' "$FINAL_IP_LIST" | \
grep -vE '^172\.(1[6-9]|2[0-9]|3[0-1])\.' | \
grep -vE '^192\.168\.' | \
grep -vE '^127\.' | \
grep -vE '^0\.' > temp_clean.txt
mv temp_clean.txt "$FINAL_IP_LIST"

TOTAL_CLEAN_LINES=$(wc -l < "$FINAL_IP_LIST" 2>/dev/null || echo 0)
echo "Final unique and cleaned IP/Ranges: $TOTAL_CLEAN_LINES written to **$FINAL_IP_LIST**"

# --- 3. Range Aggregation (Using Python) ---
echo -e "\nStarting CIDR range aggregation for minimal clutter..."

if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."

    python3 -c "
import ipaddress
import sys
import os

networks = set()
invalid_lines = 0

with open('$FINAL_IP_LIST', 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            networks.add(ipaddress.ip_network(line, strict=False))
        except ValueError:
            invalid_lines += 1

minimized_networks = ipaddress.collapse_addresses(networks)

with open('$RANGED_IP_LIST', 'w') as f:
    for net in minimized_networks:
        if not net.is_private and not net.is_loopback and not net.is_reserved:
            f.write(str(net) + '\n')

print(f\"Successfully created minimal CIDR ranges: **$RANGED_IP_LIST**\")
print(f\"Total invalid lines skipped: {invalid_lines}\")
"
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation."
    exit 1
fi

RANGES_CREATED=$(wc -l < "$RANGED_IP_LIST" 2>/dev/null || echo 0)
echo "Ranges created: $RANGES_CREATED"

# --- 4. Format Output for MikroTik RouterOS ---
echo "Formatting output for MikroTik RouterOS..."
{
    echo "/ip firewall address-list"
    # Use awk to prepend the MikroTik command to every line in the minimized list
    awk -v list="$LIST_NAME" '{print "add list=" list " address=" $1}' "$RANGED_IP_LIST"
} > "$RSC_OUTPUT"

FINAL_RSC_ENTRIES=$(wc -l < "$RSC_OUTPUT" 2>/dev/null || echo 0)
echo "✅ MikroTik script generated: **$RSC_OUTPUT** (Entries: $FINAL_RSC_ENTRIES)"

