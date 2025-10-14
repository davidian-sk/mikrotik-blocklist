# **🛡️ Automated MikroTik Threat Intelligence Blocklist**

This repository contains aggregated, optimized, and automatically updated IPv4 threat intelligence feeds designed specifically for use with **MikroTik RouterOS** devices (like the RB5009 or hAP AX3 in your homelab).

The core script, ip\_aggregator\_git.sh (running on **Garuda Linux** or another system), executes daily/hourly to maintain a current, clutter-free blocklist for your firewall.

## **✨ Features**

* **Source Aggregation:** Pulls data from multiple public threat feed URLs (sources.txt).  
* **Deduplication & Cleanup:** Automatically removes duplicate IP entries and filters out private/reserved IP ranges (192.168.x.x, 10.x.x.x, etc.).  
* **CIDR Compression (Clutter Reduction):** Uses Python's ipaddress.collapse\_addresses to convert massive lists of individual IPs into the smallest possible set of CIDR ranges (e.g., condensing 256 individual IPs into a single /24 network). This dramatically improves MikroTik's firewall performance.  
* **MikroTik Ready:** Outputs a complete RouterOS script (blacklist.rsc) ready for immediate import.  
* **Version Control:** Automatically commits and pushes all changes to this repository via Git/SSH after every execution.

## **📦 Output Files**

| File Name | Description | Format | Usage |
| :---- | :---- | :---- | :---- |
| **blacklist.rsc** | The final script containing all aggregated CIDR ranges formatted as /ip firewall address-list commands. **Ready for MikroTik import.** | RouterOS Script (.rsc) | Imported directly into the MikroTik Files list. |
| **aggregated\_cidr\_ranges.txt** | A pure text file containing the final, unique, and compressed CIDR ranges (one per line). | Plain Text | For reference or use in other firewall/router systems. |
| aggregated\_ips.txt | The list of unique, non-ranged IPv4 addresses *before* CIDR compression. | Plain Text | For troubleshooting or auditing. |
| sources.txt | The list of URLs the script uses for data collection. | Plain Text | Defines the input sources. |
| ip\_aggregator\_git.sh | The Linux shell script responsible for the entire automation process. | Bash Script | Runs on the homelab system (e.g., Proxmox or a Docker container). |

## **⚙️ MikroTik Usage Guide (RB5009 Example)**

To deploy the generated threat list to your MikroTik router, follow these steps:

### **1\. Transfer the Script**

Copy the blacklist.rsc file from this repository to your MikroTik router.

* **Via WinBox/WebFig:** Drag and drop blacklist.rsc into the **Files** menu.  
* **Via SCP (Linux/macOS):**  
  \# Replace 'user' and '192.168.88.1' with your router credentials/IP  
  scp blacklist.rsc user@192.168.88.1:/

### **2\. Import and Load the Address List**

Use the MikroTik Terminal to import the file.

\# This command first removes the old list completely to prevent stale entries.  
/ip firewall address-list remove \[find list=pwlgrzs-blacklist\]

\# This command imports the new list of CIDR ranges.  
/import file=blacklist.rsc

The new, optimized list will now be available under /ip firewall address-list with the name pwlgrzs-blacklist.

### **3\. Apply the List to Firewall Rules**

For large lists, it's highly recommended to use the **raw** firewall table, which processes traffic *before* connection tracking. This prevents known bad traffic from consuming router resources and provides the highest performance.

#### **Option A: High-Performance Raw Rule (Recommended)**

This drops incoming traffic destined for devices behind your router and uses the most efficient table.

/ip firewall raw  
add action=drop chain=prerouting comment="DROP Automated Threat List (RAW)" src-address-list=pwlgrzs-blacklist

#### **Option B: Standard Filter Rule**

If you prefer the standard filter chain, use this rule:

/ip firewall filter  
add action=drop chain=forward comment="DROP Automated Threat List (FILTER)" src-address-list=pwlgrzs-blacklist

## **💻 Automation Setup (Homelab)**

The aggregation script runs on a dedicated Linux host (like your **Intel NUC** running **Garuda Linux**) using a scheduled job.

1. **Git Setup:** Ensure your SSH key is set up and configured for this repo (git remote set-url origin git@github.com:davidian-sk/mikrotik-blocklist.git).  
2. **Cron Job:** The script should be scheduled to run periodically (e.g., every 6 hours) using cron or a similar scheduling tool:  
   \# Example: Run every 6 hours and log output  
   0 \*/6 \* \* \* /path/to/ip\_aggregator\_git.sh \> /var/log/threatfeed.log 2\>&1

