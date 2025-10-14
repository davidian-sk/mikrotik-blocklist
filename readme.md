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

## **⚙️ MikroTik Usage Guide: Full Automation (Recommended)**

This method sets up the MikroTik router to automatically download the latest **blacklist.rsc** file from your GitHub repository on a repeating schedule, ensuring your firewall is always current.

### **1\. Apply the Automated Scheduler Script**

Copy and paste this entire block into your MikroTik terminal. This creates two scripts (download and import) and two schedulers to run them **every 7 days (weekly)**.

\# 1\. Define the Download Script  
/system script  
add name="davidian-sk-dl" source={  
  :log info "Starting download of davidian-sk-blocklist from GitHub..."  
  /tool fetch url="\[https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blacklist.rsc\](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blacklist.rsc)" mode=https dst-path=blacklist.rsc;  
}

\# 2\. Define the Import/Replace Script  
add name="davidian-sk-replace" source={  
  :log info "Starting import and replacement of davidian-sk-blocklist..."  
  \# Remove old list entries before importing new ones  
  /ip firewall address-list remove \[find list=davidian-sk-blocklist\];  
  \# Import the new script  
  /import file-name=blacklist.rsc;  
  \# Clean up the downloaded file  
  /file remove blacklist.rsc;  
  :log info "davidian-sk-blocklist successfully updated."  
}

\# 3\. Schedule the Run (Every 7 days)  
/system scheduler  
\# Download script runs at 00:05:00 every 7 days  
add name="dl-sk-blacklist" interval=7d start-date=jan/01/1970 start-time=00:05:00 on-event=davidian-sk-dl  
\# Import script runs 5 minutes later to ensure download is complete  
add name="ins-sk-blacklist" interval=7d start-date=jan/01/1970 start-time=00:10:00 on-event=davidian-sk-replace

The new, optimized list will be available under /ip firewall address-list with the name **davidian-sk-blocklist**.

### **2\. Apply the List to Firewall Rules (Performance Critical)**

For managing large, external blocklists, it is **highly recommended** to use the **raw** firewall table. This table processes traffic *before* connection tracking, preventing known malicious connections from consuming valuable router CPU and memory.

#### **Option A: High-Performance Raw Rule (Recommended for Large Lists)**

This rule drops incoming connections destined for devices behind the router using the most efficient table.

/ip firewall raw  
add action=drop chain=prerouting comment="DROP Automated Threat List (RAW)" src-address-list=davidian-sk-blocklist

#### **Option B: Standard Filter Rule**

If the standard filter chain is preferred:

/ip firewall filter  
add action=drop chain=forward comment="DROP Automated Threat List (FILTER)" src-address-list=davidian-sk-blocklist

## **💻 Automation Setup (Linux Host)**

The script is designed for hands-off operation on a Linux host (like a Raspberry Pi or Proxmox VM) using a scheduled job:

1. **Git Setup:** Ensure the Git author information (git config \--global user.name and user.email) is set and that a secure **SSH key** is configured and linked to the GitHub account for automatic pushes.  
2. **Cron Job:** Schedule the script to run **daily** using cron or a similar scheduling tool:  
   \# Example: Run daily at 1:00 AM (01:00) and log output  
   0 1 \* \* \* /path/to/ip\_aggregator\_git.sh \> /var/log/threatfeed.log 2\>&1  
