#!/bin/bash

# Define the output files
TEMP_IP_LIST="temp_ips.txt"
FINAL_IP_LIST="aggregated_ips.txt"
RANGED_IP_LIST="aggregated_cidr_ranges.txt"
SOURCES_FILE="sources.txt"
RSC_OUTPUT="blacklist.rsc" # <-- NEW: MikroTik RouterOS script output

# --- Function to clean up on exit ---
cleanup() {
    # Remove the temporary raw IP file
    rm -f "$TEMP_IP_LIST"
    # Note: FINAL_IP_LIST, RANGED_IP_LIST, and RSC_OUTPUT are kept as the final output.
    echo -e "\nCleanup complete. Temporary files removed. 👋"
}

# Trap signals for proper cleanup
trap cleanup EXIT

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
    # The grep -oP command extracts all valid IPv4 addresses.
    curl -sL "$url" | \
    grep -oP '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' >> "$TEMP_IP_LIST"

done < "$SOURCES_FILE"

echo -e "\nExtraction complete. Total raw IPs collected: $(wc -l < "$TEMP_IP_LIST")"

# --- 2. Deduplication and Initial Cleanup ---
echo "Deduplicating and filtering IPs..."

# Sort, unique, and filter out common private/reserved ranges (optional but recommended for threat feeds)
# 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0/8
sort -h "$TEMP_IP_LIST" | uniq | \
grep -vE '^10\.' | \
grep -vE '^172\.(1[6-9]|2[0-9]|3[0-1])\.' | \
grep -vE '^192\.168\.' | \
grep -vE '^127\.' | \
grep -vE '^0\.' > "$FINAL_IP_LIST"

echo "Final unique and cleaned IPs: $(wc -l < "$FINAL_IP_LIST") written to **$FINAL_IP_LIST**"

# --- 2.5. Fix Leading Zeros (CRITICAL FIX for Python) ---
echo "Removing problematic leading zeros (e.g., '001') for Python compatibility..."
# Use sed to find octets starting with a dot followed by one or more zeros, and capture the non-zero digits.
# It replaces the whole matched pattern (e.g., .001) with a dot and the captured digit(s) (.1).
sed -i -E 's/\.0+([0-9]+)/\.\1/g' "$FINAL_IP_LIST"
# Also handle IPs that start with a leading zero octet (e.g., 001.2.3.4), although less common for public IPs.
sed -i -E 's/^0+([0-9]+)/\1/' "$FINAL_IP_LIST"

echo "Leading zero fix applied. Ready for aggregation."

# --- 3. Range Aggregation (Using Python) ---
echo -e "\nStarting CIDR range aggregation for better clutter avoidance..."

# Check if Python is available (required for range aggregation)
if command -v python3 &> /dev/null
then
    echo "Python 3 found. Running range aggregation..."
    
    # Simple Python script to read IPs and output minimal CIDR ranges
    # This leverages the 'ipaddress.collapse_addresses' function for maximum efficiency.
    python3 -c "
import ipaddress
import sys
# Define file names for internal Python use
final_ip_list = '$FINAL_IP_LIST'
ranged_ip_list = '$RANGED_IP_LIST'

try:
    # Read all IPs from the cleaned file
    with open(final_ip_list, 'r') as f:
        # Convert each line to an IPv4Address object
        # The sed command above ensures this line will now execute without AddressValueError
        ips = [ipaddress.IPv4Address(line.strip()) for line in f if line.strip()]

    # Aggregate them into the smallest possible list of CIDR networks
    networks = ipaddress.collapse_addresses(ips)

    # Write the resulting CIDR networks (ranges) to the final file
    with open(ranged_ip_list, 'w') as f:
        for net in networks:
            f.write(str(net) + '\n')

    print(f\"Successfully created minimal CIDR ranges: **{ranged_ip_list}**\")
    # Use wc -l in Python to count lines and confirm output size
    import subprocess
    range_count = subprocess.check_output(['wc', '-l', ranged_ip_list]).decode().split()[0]
    print(f\"Total CIDR ranges created: {range_count}\")

except Exception as e:
    print(f\"An error occurred during Python aggregation: {e}\", file=sys.stderr)
    print(\"Aggregation failed. Check your Python environment and the FINAL_IP_LIST for issues.\", file=sys.stderr)
    
"
else
    echo "⚠️ Python 3 not found. Skipping CIDR range aggregation. **$FINAL_IP_LIST** is the final output."
fi

# --- 4. Generate MikroTik .rsc File from CIDR Ranges ---
if [ -f "$RANGED_IP_LIST" ]; then
    echo -e "\nGenerating MikroTik RouterOS script: **$RSC_OUTPUT**"
    
    # 1. Start with the required header command to set the context
    echo "/ip firewall address-list" > "$RSC_OUTPUT"
    
    # 2. Use awk to iterate over the CIDR ranges and format them for RouterOS import.
    # We use the list name 'pwlgrzs-blacklist' as provided in your example.
    awk -v list_name="pwlgrzs-blacklist" '{print "add list=" list_name " address=" $1 " comment=\"Threat Intel Feed\""}' "$RANGED_IP_LIST" >> "$RSC_OUTPUT"

    echo "MikroTik script generated successfully. Ready to import into your RB5009!"
fi

# --- 5. AUTOMATIC GIT PUSH ---
echo -e "\nAttempting to push files to Git repository..."

# Check if the current directory is a Git repository
if [ -d .git ]; then
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 1. Add the output files and the source list, but EXCLUDE the script itself.
    git add "$RSC_OUTPUT" "$RANGED_IP_LIST" "$FINAL_IP_LIST" "$SOURCES_FILE"
    
    # 2. Commit the changes
    git commit -m "Auto-update: Threat feeds aggregated. CIDR Ranges: $(wc -l < "$RANGED_IP_LIST" | awk '{print $1}'). Run at $TIMESTAMP."
    
    # 3. Push to the remote repository
    if git push origin main; then
        echo "✅ Successfully pushed new feeds to GitHub."
    else
        echo "❌ ERROR: Git push failed. Ensure your SSH key or credentials are set up for GitHub."
    fi
else
    echo "⚠️ Skipping Git push: .git directory not found. Please run 'git init' first."
fi

# The 'cleanup' trap will execute automatically now.
