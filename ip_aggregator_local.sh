#!/bin/bash

# --- CONFIGURATION ---
SOURCES_FILE="sources.txt"
LIST_NAME="davidian-sk-blocklist"
# Define the output files
TEMP_IP_LIST="temp_ips.txt"
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
RSC_OUTPUT="blacklist.rsc"

# --- Function to clean up on exit ---
cleanup() {
    # We leave the local output files (rsc, txt) for MikroTik to download/use,
    # but remove the temporary raw list.
    rm -f "$TEMP_IP_LIST"
    echo "Cleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

# Clear the temporary file before starting
> "$TEMP_IP_LIST"

echo "Starting IP aggregation and cleanup (LOCAL RUN)... 🚀"

# --- 1. Download and Extract IPs from Sources ---
while IFS= read -r url; do
    if [[ -z "$url" ]]; then
        continue # Skip empty lines
    fi

    echo "Processing $url..."

    # Use curl to download and pipe directly to processing.
    # Extracts all valid IPv4 addresses.
    curl -sL "$url" | \
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' >> "$TEMP_IP_LIST"

done < "$SOURCES_FILE"

# --- 2. Deduplication and Initial Cleanup ---
echo -e "\nExtraction complete. Raw IPs collected: $(wc -l < "$TEMP_IP_LIST")"
echo "Deduplicating and filtering private IPs..."

# Sort and unique to remove duplicates
sort -h "$TEMP_IP_LIST" | uniq > "$FINAL_IP_LIST"

# Filter out common private/reserved ranges (10/8, 172.16/12, 192.168/16, 127/8, 0/8)
grep -vE '^10\.' "$FINAL_IP_LIST" | \
grep -vE '^172\.(1[6-9]|2[0-9]|3[0-1])\.' | \
grep -vE '^192\.168\.' | \
grep -vE '^127\.' | \
grep -vE '^0\.' > temp_clean.txt
mv temp_clean.txt "$FINAL_IP_LIST"

echo "Final unique and cleaned IPs: $(wc -l < "$FINAL_IP_LIST")"

# --- 2.5. Fix Leading Zeros (CRITICAL FIX for Python) ---
echo "Removing problematic leading zeros for Python compatibility..."
# Use sed to remove leading zeros from each octet (e.g., .001 becomes .1)
sed -i -E 's/\.0+([0-9]+)/\.\1/g' "$FINAL_IP_LIST"

# --- 3. Range Aggregation (Using Python) ---
echo -e "\nStarting CIDR range aggregation for better clutter avoidance..."

if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."
    
    # Python script to read IPs and output minimal CIDR ranges
    python3 -c "
import ipaddress
import os
import sys

# Read all IPs from the cleaned file
with open('$FINAL_IP_LIST', 'r') as f:
    # Convert each line to an IPv4Address object, skipping empty lines
    ips = [ipaddress.IPv4Address(line.strip()) for line in f if line.strip()]

# Aggregate them into the smallest possible list of CIDR networks
networks = ipaddress.collapse_addresses(ips)

# Write the resulting CIDR networks (ranges) to the final file
with open('$RANGED_IP_LIST', 'w') as f:
    for net in networks:
        f.write(str(net) + '\n')

# Count the resulting lines for the output message
RANGES_COUNT = 0
if os.path.exists('$RANGED_IP_LIST'):
    with open('$RANGED_IP_LIST', 'r') as f:
        RANGES_COUNT = len(f.readlines())

print(f\"Successfully created minimal CIDR ranges: **$RANGED_IP_LIST**\")
print(f\"Ranges created: {RANGES_COUNT}\")
"
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation. **$FINAL_IP_LIST** is the final output."
fi

# Recount the ranges in BASH after Python execution to ensure accuracy for output
if [ -f "$RANGED_IP_LIST" ]; then
    RANGES_COUNT=$(wc -l < "$RANGED_IP_LIST")
else
    RANGES_COUNT=0
fi

# --- 4. Format Output for MikroTik (.rsc) ---
echo -e "\nFormatting output for MikroTik RouterOS..."

# Start the .rsc file with the command context
echo "/ip firewall address-list" > "$RSC_OUTPUT"

# Read the compressed CIDR ranges and format them for the RouterOS script
while IFS= read -r cidr_range; do
    if [[ -n "$cidr_range" ]]; then
        echo "add list=$LIST_NAME address=$cidr_range" >> "$RSC_OUTPUT"
    fi
done < "$RANGED_IP_LIST"

echo "✅ MikroTik script generated: **$RSC_OUTPUT** (Entries: $RANGES_COUNT)"

# No Git pushing in this version!

# The 'cleanup' trap will execute automatically now.

