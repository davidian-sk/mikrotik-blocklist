#!/bin/bash

# --- Configuration ---
SOURCES_FILE="sources.txt"
TEMP_IP_LIST="temp_ips.txt"
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
RSC_OUTPUT="blocklist.rsc"
ADDRESS_LIST_NAME="davidian-sk-blocklist"

# --- Function to clean up on exit ---
cleanup() {
    rm -f "$TEMP_IP_LIST" temp_source.txt
    echo -e "\nCleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

# Clear the temporary file before starting
> "$TEMP_IP_LIST"

echo "Starting IP aggregation and cleanup... 🚀"
current_time=$(date +"%Y-%m-%d %H:%M:%S")

# --- 1. Download and Extract IPs/Ranges from Sources ---
while IFS= read -r url; do
    if [ -z "$url" ]; then # Checks if the URL is empty (using compatible syntax)
        continue # Skip empty lines
    fi

    echo "Processing $url..."
    
    # Download content to a temporary file
    curl -sL "$url" > temp_source.txt
    
    # ROBUST EXTRACTION: Captures both raw IPs (1.1.1.1) and full CIDR ranges (1.1.1.0/24)
    # The new regex ensures that large ranges from .rsc files are preserved for optimization.
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\d{1,2})?' temp_source.txt >> "$TEMP_IP_LIST"

done < "$SOURCES_FILE"

# --- 2. Deduplication and Initial Cleanup ---
raw_ip_count=$(wc -l < "$TEMP_IP_LIST" 2>/dev/null || echo 0)
echo -e "\nExtraction complete. Total raw IP/Ranges collected: $raw_ip_count"

echo "Deduplicating and filtering IPs/Ranges..."
# Sort and unique the temporary file to remove duplicates
sort -h "$TEMP_IP_LIST" | uniq > "$FINAL_IP_LIST"

# Optionally, remove common private/reserved ranges (recommended)
grep -vE '^10\.' "$FINAL_IP_LIST" | \
grep -vE '^172\.(1[6-9]|2[0-9]|3[0-1])\.' | \
grep -vE '^192\.168\.' | \
grep -vE '^127\.' | \
grep -vE '^0\.' > temp_clean.txt
mv temp_clean.txt "$FINAL_IP_LIST"

cleaned_ip_count=$(wc -l < "$FINAL_IP_LIST" 2>/dev/null || echo 0)
echo "Final unique and cleaned IPs/Ranges: $cleaned_ip_count written to **$FINAL_IP_LIST**"

# --- 2.5. Fix Leading Zeros (CRITICAL FIX for Python) ---
echo "Removing problematic leading zeros for Python compatibility..."
# This converts 1.1.1.007 to 1.1.1.7, which is required by Python's ipaddress module.
sed -i -E 's/\.0+([0-9]+)/\.\1/g' "$FINAL_IP_LIST"
echo "Leading zero fix applied."

# --- 3. Range Aggregation (Using Python) ---
echo -e "\nStarting CIDR range aggregation for better clutter avoidance..."

if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."
    
    # The Python script reads all IPs/ranges and outputs the minimal set of CIDR blocks.
    # We pipe stderr (Python's error output) to /dev/null to keep the console clean.
    python3 -c "
import ipaddress
import sys
import os

# 1. Read all IPs/Ranges from the cleaned file
input_list = []
with open('$FINAL_IP_LIST', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        
        try:
            # ip_network handles both single addresses and CIDR notation (1.1.1.0/24).
            ip_obj = ipaddress.ip_network(line, strict=False)
        except ValueError as e:
            # Handle any remaining invalid formats and skip them
            print(f\"Skipping invalid IP/Range: {line} ({e})\", file=sys.stderr)
            continue
        
        input_list.append(ip_obj)

# 2. Aggregate them into the smallest possible list of CIDR networks
networks = ipaddress.collapse_addresses(input_list)

# 3. Write the resulting CIDR networks (ranges) to the final file
with open('$RANGED_IP_LIST', 'w') as f:
    for net in networks:
        f.write(str(net) + '\n')

print(f\"Successfully created minimal CIDR ranges: **$RANGED_IP_LIST**\", file=sys.stderr)
" 2> /dev/null
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation. **$FINAL_IP_LIST** is the final output."
    cp "$FINAL_IP_LIST" "$RANGED_IP_LIST"
fi

# Get the count of ranges generated
range_count=$(wc -l < "$RANGED_IP_LIST" 2>/dev/null || echo 0)

# --- 4. Format Output for MikroTik RouterOS ---
echo -e "\nFormatting output for MikroTik RouterOS..."

echo "/ip firewall address-list" > "$RSC_OUTPUT"

while IFS= read -r range; do
    echo "add list=$ADDRESS_LIST_NAME address=$range" >> "$RSC_OUTPUT"
done < "$RANGED_IP_LIST"

echo "✅ MikroTik script generated: **$RSC_OUTPUT** (Entries: $range_count)"

# Note: Step 5 (Git Push) is omitted in this local version.

