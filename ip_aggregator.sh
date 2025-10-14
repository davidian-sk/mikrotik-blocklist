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
    rm -f "$TEMP_IP_LIST"
    echo "Cleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

# Get current timestamp for commit message
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# Clear the temporary file before starting
> "$TEMP_IP_LIST"

echo "Starting IP aggregation and cleanup... 🚀"

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
import sys
# Read all IPs from the cleaned file
with open('$FINAL_IP_LIST', 'r') as f:
    # Convert each line to an IPv4Address object
    ips = [ipaddress.IPv4Address(line.strip()) for line in f if line.strip()]

# Aggregate them into the smallest possible list of CIDR networks
networks = ipaddress.collapse_addresses(ips)

# Write the resulting CIDR networks (ranges) to the final file
with open('$RANGED_IP_LIST', 'w') as f:
    for net in networks:
        f.write(str(net) + '\n')

RANGES_COUNT = 0
if os.path.exists('$RANGED_IP_LIST'):
    with open('$RANGED_IP_LIST', 'r') as f:
        RANGES_COUNT = sum(1 for line in f)

print(f\"Successfully created minimal CIDR ranges: **$RANGED_IP_LIST**\")
print(f\"Ranges created: {RANGES_COUNT}\")
"
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation. **$FINAL_IP_LIST** is the final output."
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

RANGES_COUNT=$(wc -l < "$RANGED_IP_LIST")

echo "✅ MikroTik script generated: **$RSC_OUTPUT** (Entries: $RANGES_COUNT)"

# --- 5. AUTOMATIC GIT PUSH ---
echo -e "\nAttempting to push files to Git repository..."

# Git config needs to be set globally or locally for this to work
# git config --global user.name "Your Name"
# git config --global user.email "your@email.com"

# Stage the script, sources, and all output files
git add "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE" "$0"

# Commit the changes (using the count of ranges in the message)
COMMIT_MSG="Auto-update: Threat feeds aggregated. CIDR Ranges: ${RANGES_COUNT}. Run at ${TIMESTAMP}."

if git commit -m "$COMMIT_MSG"; then
    # Push to the remote repository
    if git push origin main; then
        echo "✅ Successfully pushed new feeds to GitHub."
    else
        echo "❌ ERROR: Git push failed. Ensure your SSH key or credentials are set up for GitHub."
        echo "Hint: Did you run 'git pull --rebase' after making changes on the web?"
    fi
else
    # This happens if there were no changes to the tracked files (e.g., feed was identical)
    echo "ℹ️ No changes to commit. Feeds were identical to the last run."
fi

# The 'cleanup' trap will execute automatically now.
