# **🛡️ Automated MikroTik Threat Intelligence Blocklist**

This repository provides an automated, high-performance solution for maintaining an up-to-date IPv4 threat intelligence blocklist. The resulting RouterOS script is optimized for use with **MikroTik RouterOS** devices (like the RB5009 or hAP AX3), providing enhanced firewall security with minimal resource impact.

The core script, ip\_aggregator\_git.sh, is designed to run on a dedicated Linux host (e.g., a server, virtual machine, or container) and automatically updates this repository with fresh data.

## **✨ Features**

* **Source Aggregation:** Pulls IP data from a customizable list of public threat feed URLs (sources.txt).  
* **Cleanup & Filtering:** Automatically removes duplicate IP entries and filters out all common private/reserved IP ranges (192.168.x.x, 10.x.x.x, 172.16.x.x, etc.) before processing.  
* **CIDR Compression (High Efficiency):** Uses Python's ipaddress.collapse\_addresses to convert long lists of individual IPs into the smallest possible set of CIDR ranges (e.g., condensing hundreds of entries into a few /24 or /22 networks). This is critical for improving firewall rule processing speed.  
* **MikroTik Ready Output:** Generates a complete RouterOS script (blacklist.rsc) ready for immediate import.  
* **Automation & Tracking:** The entire process is automated via a Bash script that commits the generated files to this repository via Git/SSH after every execution.

## **📦 Output Files**

| File Name | Description | Format | Usage |
| :---- | :---- | :---- | :---- |
| **blacklist.rsc** | The final script containing all aggregated CIDR ranges formatted as /ip firewall address-list commands. **Ready for MikroTik import.** | RouterOS Script (.rsc) | Imported directly into the MikroTik Files list. |
| **aggregated\_cidr\_ranges.txt** | A pure text file containing the final, unique, and compressed CIDR ranges (one per line). | Plain Text | For reference or use in other firewall/router systems. |
| aggregated\_ips.txt | The list of unique, non-ranged IPv4 addresses *before* CIDR compression. | Plain Text | For troubleshooting or auditing. |
| sources.txt | The list of public URLs the script uses for data collection. | Plain Text | Defines the input sources. |
| ip\_aggregator\_git.sh | The Linux shell script responsible for the entire automation process. | Bash Script | Runs on the automation host. |

## **⚙️ MikroTik Usage Guide**

To deploy the generated threat list to your MikroTik router:

### **1\. Transfer the Script**

Copy the blacklist.rsc file from this repository to the root directory of the MikroTik router's storage.

* **Via WinBox/WebFig:** Drag and drop blacklist.rsc into the **Files** menu.  
* **Via SCP (Linux/macOS):**  
  \# Replace 'user' and '192.168.88.1' with the router's credentials/IP  
  scp blacklist.rsc user@192.168.88.1:/

### **2\. Import and Load the Address List**

Use the MikroTik Terminal to import the file.

\# WARNING: This command first removes the old list completely to prevent stale entries.  
/ip firewall address-list remove \[find list=pwlgrzs-blacklist\]

\# This command imports the new list of CIDR ranges.  
/import file=blacklist.rsc

The new, optimized list will be available under /ip firewall address-list with the name pwlgrzs-blacklist.

### **3\. Apply the List to Firewall Rules (Performance Critical)**

For managing large, external blocklists, it is **highly recommended** to use the **raw** firewall table. This table processes traffic *before* connection tracking, preventing known malicious connections from consuming valuable router CPU and memory.

#### **Option A: High-Performance Raw Rule (Recommended for Large Lists)**

This rule drops incoming connections destined for devices behind the router using the most efficient table.

/ip firewall raw  
add action=drop chain=prerouting comment="DROP Automated Threat List (RAW)" src-address-list=pwlgrzs-blacklist

#### **Option B: Standard Filter Rule**

If the standard filter chain is preferred:

/ip firewall filter  
add action=drop chain=forward comment="DROP Automated Threat List (FILTER)" src-address-list=pwlgrzs-blacklist

## **💻 Automation Setup (Linux Host)**

The script is designed for hands-off operation on a Linux host using a scheduled job:

1. **Git Setup:** Ensure the Git author information (git config \--global user.name and user.email) is set and that a secure **SSH key** is configured and linked to the GitHub account for automatic pushes.  
2. **Cron Job:** Schedule the script to run periodically (e.g., every 6 hours) using cron or a similar scheduling tool:  
   \# Example: Run every 6 hours and log output  
   0 \*/6 \* \* \* /path/to/ip\_aggregator\_git.sh \> /var/log/threatfeed.log 2\>&1

This version is ready to be the face of your public GitHub repository\!