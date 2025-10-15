#!/usr/bin/env bash
#
# Threat Feed Aggregator (Git Version)
# Purpose: Downloads multiple threat feeds, dedupes, removes private ranges,
#          compresses to minimal CIDR ranges, generates a RouterOS .rsc script,
#          and commits/pushes the results to a Git repository.
#
# Fix Notes: Uses 'ipaddress.ip_network(..., strict=False)' for robustly handling
#            mixed IP/CIDR inputs and ensures the script is runnable via cron.

# --- Configuration ---
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
RSC_OUTPUT="blacklist.rsc"
SOURCES_FILE="sources.txt"
LIST_NAME="davidian-sk-blocklist"

# Get current time for commit message
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

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
    # 3. Clean up leading/trailing junk from MikroTik commands or JSON data
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

# 3. Filter out common private/reserved ranges (optional but recommended for public feeds)
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

# Requires the 'ipaddress' module (standard since Python 3.3)
if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."

    # Simple Python script to read IPs/Ranges and output minimal CIDR ranges
    python3 -c "
import ipaddress
import sys
import os

# Set of all network objects (ranges or IPs)
networks = set()
invalid_lines = 0

# Read all IP/CIDR strings from the cleaned file
with open('$FINAL_IP_LIST', 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            # ip_network handles both 1.2.3.4 (as /32) and 1.2.3.0/24 correctly
            networks.add(ipaddress.ip_network(line, strict=False))
        except ValueError:
            invalid_lines += 1
            # print(f'Skipping invalid IP/range: {line}', file=sys.stderr)

# Collapse them into the smallest possible list of CIDR networks
minimized_networks = ipaddress.collapse_addresses(networks)

# Write the resulting CIDR networks (ranges) to the final file
with open('$RANGED_IP_LIST', 'w') as f:
    for net in minimized_networks:
        # Filter out any lingering private ranges or loopbacks that slip past the grep
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

# --- 5. AUTOMATIC GIT PUSH ---
echo -e "\nAttempting to push files to Git repository..."

# Check if the generated output files (and sources.txt) differ from the last commit.
# If nothing has changed, we skip the commit to keep history clean.
if ! git diff --quiet --exit-code "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0" &>/dev/null; then

    # Files have changed. Stage all relevant files.
    git add "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0"

    # Commit the changes (using the number of final ranges in the message)
    if git commit -m "Auto-update: Threat feeds aggregated. CIDR Ranges: $RANGES_CREATED. Run at $CURRENT_TIME."; then

        # Push to the remote repository
        if git push origin main; then
            echo "✅ Successfully pushed new feeds to GitHub."
        else
            echo "❌ ERROR: Git push failed. Ensure your SSH key or credentials are set up for GitHub."
        fi
    else
        echo "ℹ️ Failed to create commit. Check for pending conflicts."
    fi
else
    echo "ℹ️ No changes to commit. Feeds were identical to the last run."
fi

