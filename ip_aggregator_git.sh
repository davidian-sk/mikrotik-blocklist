#!/usr/bin/env bash
#
# Threat Feed Aggregator (Git Version) by davidian-sk
# Purpose: Downloads multiple threat feeds, dedupes, removes private ranges,
#          compresses to minimal CIDR ranges, generates three RouterOS .rsc files,
#          and commits/pushes the results to a Git repository.
#
# Fix Notes: Uses 'ipaddress.ip_network(..., strict=False)' for robust CIDR parsing.

# --- Configuration ---
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"

# Output files and their corresponding MikroTik list names
RSC_OUTPUT_ACTIVE="blocklist.rsc"
LIST_NAME_ACTIVE="davidian-sk-active-blocklist"

RSC_OUTPUT_A="blocklist_a.rsc"
LIST_NAME_A="davidian-sk-blocklist_a"

RSC_OUTPUT_B="blocklist_b.rsc"
LIST_NAME_B="davidian-sk-blocklist_b"

SOURCES_FILE="sources.txt"

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

    # Robust regex to capture full IPv4 address AND optional CIDR range (/XX)
    curl -sL "$url" | \
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\d{1,2})?' >> temp_raw.txt

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

# Check if Python is available (required for range aggregation)
if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."

    # Python script to read IPs/Ranges and output minimal CIDR networks
    python3 -c "
import ipaddress
import sys
import os

networks = set()
invalid_lines = 0

# Read all IP/CIDR strings from the cleaned file
with open('$FINAL_IP_LIST', 'r') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            # ip_network handles both single addresses and CIDR notation (1.1.1.0/24).
            networks.add(ipaddress.ip_network(line, strict=False))
        except ValueError:
            invalid_lines += 1

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
    cp "$FINAL_IP_LIST" "$RANGED_IP_LIST"
fi

RANGES_CREATED=$(wc -l < "$RANGED_IP_LIST" 2>/dev/null || echo 0)
echo "Ranges created: $RANGES_CREATED"

# --- 4. Format Output for MikroTik RouterOS (Triple Output) ---
echo "Formatting output for MikroTik RouterOS..."

# Function to generate the RSC file
generate_rsc() {
    local output_file=$1
    local list_name=$2
    {
        echo "/ip firewall address-list"
        # Use awk to prepend the MikroTik command to every line in the minimized list
        awk -v list="$list_name" '{print "add list=" list " address=" $1}' "$RANGED_IP_LIST"
    } > "$output_file"
    local entries=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo "✅ MikroTik script generated: **$output_file** (List: $list_name, Entries: $entries)"
}

# 4a. Generate the main ACTIVE blocklist
generate_rsc "$RSC_OUTPUT_ACTIVE" "$LIST_NAME_ACTIVE"

# 4b. Generate Blocklist A
generate_rsc "$RSC_OUTPUT_A" "$LIST_NAME_A"

# 4c. Generate Blocklist B
generate_rsc "$RSC_OUTPUT_B" "$LIST_NAME_B"

# --- 5. AUTOMATIC GIT PUSH ---
echo -e "\nAttempting to push files to Git repository..."

# Array of files to check and push
FILES_TO_PUSH=("$RSC_OUTPUT_ACTIVE" "$RSC_OUTPUT_A" "$RSC_OUTPUT_B" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0")

# Check if the output files are different from the last commit
if ! git diff --quiet --exit-code "${FILES_TO_PUSH[@]}"; then

    CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

    # Stage the output files and the script itself
    git add "${FILES_TO_PUSH[@]}"

    # Commit the changes
    if git commit -m "Auto-update: Threat feeds aggregated. CIDR Ranges: $RANGES_CREATED. Run at $CURRENT_TIME."; then

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

# The 'cleanup' trap will execute automatically now.
