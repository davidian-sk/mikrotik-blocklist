#!/usr/bin/env bash
#
# Threat Feed Aggregator (Git Version)
# Purpose: Downloads multiple threat feeds, dedupes, removes private ranges,
#          compresses to minimal CIDR ranges, generates a RouterOS .rsc script,
#          and commits/pushes the results to a Git repository.
#
# Fix Notes: Uses 'ipaddress.ip_network(..., strict=False)' for robustly handling
#            both individual IPs and full CIDR ranges (like /22) from all sources.

# --- Configuration ---
# Define the output files
TEMP_IP_LIST="temp_ips.txt"
TEMP_SOURCE_FILE="temp_source.txt"
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
RSC_OUTPUT="blocklist.rsc"
SOURCES_FILE="sources.txt"
ROUTEROS_LIST_NAME="davidian-sk-blocklist" # The name of the address-list on your MikroTik

# --- Function to clean up on exit ---
cleanup() {
    rm -f "$TEMP_IP_LIST" "$TEMP_SOURCE_FILE"
    echo -e "\nCleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

# Clear temporary and output files before starting
> "$TEMP_IP_LIST"
> "$TEMP_SOURCE_FILE"

echo "Starting IP aggregation and cleanup... 🚀"

# --- 1. Download and Extract IPs/Ranges from Sources ---
while IFS= read -r url; do
    if [[ -z "$url" ]]; then
        continue # Skip empty lines
    fi

    echo "Processing $url..."

    # Use curl to download content into a temp file
    if ! curl -sL "$url" > "$TEMP_SOURCE_FILE"; then
        echo "⚠️ Warning: Failed to download $url. Skipping."
        continue
    fi

    # Use a single, robust regex to extract ANY IPv4 address or CIDR range (IP/CIDR)
    # This handles raw lists, JSON, and structured Mikrotik .rsc files by grabbing
    # everything that looks like an address or address/mask.
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\d{1,2})?' "$TEMP_SOURCE_FILE" >> "$TEMP_IP_LIST"

done < "$SOURCES_FILE"

# Clean up the temporary source file
rm -f "$TEMP_SOURCE_FILE"

echo -e "\nExtraction complete. Total raw lines collected: $(wc -l < "$TEMP_IP_LIST")"

# --- 2. Deduplication, Sanitization, and Initial Cleanup ---
echo "Deduplicating and filtering IPs..."

# 2.1 Sort, unique, and move to final IPs list
sort -h "$TEMP_IP_LIST" | uniq > "$FINAL_IP_LIST"

# 2.2 Fix problematic leading zeros (e.g., .001) for Python compatibility
# Sed handles both dot and slash delimiters for IP/CIDR strings
sed -i -E 's/\.0+([0-9]+)/\.\1/g' "$FINAL_IP_LIST"

# 2.3 Filter out common private/reserved ranges (optional but recommended)
grep -vE '^10\.' "$FINAL_IP_LIST" | \
grep -vE '^172\.(1[6-9]|2[0-9]|3[0-1])\.' | \
grep -vE '^192\.168\.' | \
grep -vE '^127\.' | \
grep -vE '^0\.' > temp_clean_filtered.txt

mv temp_clean_filtered.txt "$FINAL_IP_LIST"

echo "Final unique and cleaned IP/Ranges: $(wc -l < "$FINAL_IP_LIST") written to **$FINAL_IP_LIST**"

# --- 3. Range Aggregation (Using Python) ---
echo -e "\nStarting CIDR range aggregation for minimal clutter..."

# Check if Python is available (required for range aggregation)
if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."

    # Python script to read IPs/Ranges and output minimal CIDR networks
    python3 -c "
import ipaddress
import sys
import os

# Set to store all network objects (ranges or /32 individuals)
networks_set = set()
invalid_lines = 0

# Read all IPs and Ranges from the cleaned file
with open('$FINAL_IP_LIST', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            # Use ip_network to handle both 1.1.1.1 (as /32) and 1.1.1.0/24
            # strict=False allows bare IPs to be treated as /32 hosts
            net = ipaddress.ip_network(line, strict=False)
            networks_set.add(net)
        except ValueError:
            invalid_lines += 1
            # print(f'Skipping invalid address or network: {line}', file=sys.stderr)

# Collapse them into the smallest possible list of CIDR networks
networks = sorted(ipaddress.collapse_addresses(networks_set))

# Write the resulting minimal CIDR networks (ranges) to the final file
with open('$RANGED_IP_LIST', 'w') as f:
    for net in networks:
        f.write(str(net) + '\n')

print(f\"Successfully created minimal CIDR ranges: **$RANGED_IP_LIST**\")
print(f\"Total invalid lines skipped: {invalid_lines}\")
"
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation."
    cp "$FINAL_IP_LIST" "$RANGED_IP_LIST"
fi

RANGES_COUNT=$(wc -l < "$RANGED_IP_LIST")
echo "Ranges created: $RANGES_COUNT"

# --- 4. Format Output for MikroTik RouterOS ---
echo "Formatting output for MikroTik RouterOS..."

# Add header
echo "/ip firewall address-list" > "$RSC_OUTPUT"

# Add all aggregated CIDR ranges to the specified address list
while IFS= read -r line; do
    echo "add list=$ROUTEROS_LIST_NAME address=$line" >> "$RSC_OUTPUT"
done < "$RANGED_IP_LIST"

echo "✅ MikroTik script generated: **$RSC_OUTPUT** (Entries: $RANGES_COUNT)"

# --- 5. AUTOMATIC GIT PUSH ---
echo -e "\nAttempting to push files to Git repository..."

# Check if the output files are different from the last commit
# Check the script file, sources, and all three output files
if ! git diff --quiet "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0"; then

    CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

    # Stage the output files and the script itself
    git add "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0"

    # Commit the changes
    if git commit -m "Auto-update: Threat feeds aggregated. CIDR Ranges: $RANGES_COUNT. Run at $CURRENT_TIME."; then

        # Push the commit
        if git push origin main; then
            echo "✅ Successfully pushed new feeds to GitHub."
        else
            echo "❌ ERROR: Git push failed. Ensure your SSH key is authorized and your branch is in sync (try 'git pull --rebase')."
        fi
    else
        echo "ℹ️ Failed to create commit. Check for pending conflicts."
    fi
else
    echo "ℹ️ No changes to commit. Feeds were identical to the last run."
fi

