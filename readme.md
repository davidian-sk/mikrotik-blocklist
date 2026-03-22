# **🛡️ Davidian-SK MikroTik Blocklist Aggregator**

This repository provides a self-updating MikroTik address list built by aggregating multiple public threat intelligence feeds. Its main goal is to generate the most compact practical set of CIDR ranges possible, reducing address-list size and improving firewall efficiency on MikroTik devices such as the RB5009.

## **🚀 Features**


- **Source aggregation:** Pulls IP data from multiple public threat feeds listed in `sources.txt`.
- **CIDR compression:** Uses Python's `ipaddress` library to aggregate individual IPs and ranges into a compact list of CIDR blocks.
- **RouterOS output:** Generates RouterOS import scripts for use with MikroTik address lists.

Sources:

```
# === CORE (HIGH CONFIDENCE – KEEP THESE) ===

# Spamhaus DROP (known bad networks)
https://www.spamhaus.org/drop/drop.txt

# Spamhaus EDROP (extended bad networks)
https://www.spamhaus.org/drop/edrop.txt

# Feodo Tracker (botnet C2)
https://feodotracker.abuse.ch/downloads/ipblocklist.txt

# EmergingThreats compromised IPs
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
```
  
## **📝 Output Files**

The generator creates the following files:

| File Name | Content | Purpose |
|---|---|---|
| `blocklist.rsc` | RouterOS import script | Single-list import file. Suitable for simple replace workflows, but not ideal if you want near-zero downtime. |
| `blocklist_a.rsc` | RouterOS import script | First half of the dual-list rotation method. |
| `blocklist_b.rsc` | RouterOS import script | Second half of the dual-list rotation method. |
| `aggregated_cidr_ranges.txt` | Final optimized CIDR ranges | Useful for auditing or reuse in other tools. |
| `aggregated_ips.txt` | Aggregated plain IP/range output | Useful for inspection or downstream processing. |

## 2. MikroTik RouterOS Setup

This method uses a custom RouterOS script that downloads the next blocklist file to `usb2/blocklist/`, verifies that the file exists and is not empty, imports it into the inactive address list, and then atomically switches the firewall rules to the new list.

The dual-list method is recommended because it avoids replacing the active list in place.


### Prerequisites

Before using the rotation script:

1. Create the address list `davidian-sk-blocklist_a` and add a dummy entry such as `10.0.0.1`.
2. Create the address list `davidian-sk-blocklist_b` and add a dummy entry such as `10.0.0.2`.
3. Create two RAW firewall rules:
   - one that drops traffic from source IPs in the active blocklist on the WAN side
   - one that drops LAN traffic destined for IPs in the active blocklist
4. Ensure your router can write to `usb2/blocklist/`.
5. Ensure the script name matches the scheduler entry exactly.
## 

## How the Dual-List Rotation Works

The rotation method uses two MikroTik address lists:

- `davidian-sk-blocklist_a`
- `davidian-sk-blocklist_b`

At any given time, one list is active in the RAW firewall rules, while the other is inactive and can be refreshed safely. After a successful download and import, the script switches the firewall rules to the updated list and purges the old one.

### I. SCRIPT DEFINITIONS (Atomic Switch)

#### Blocklist Rotate

let's name it

"Blocklist-Rotate"

The following version adds additional safeguards

- lock/guard so it won’t run twice at the same time

- download/import sanity check

- minimum imported entry threshold

- do not switch rules if the new list looks suspiciously small

- do not purge old list unless the switch really happened

- cleanup lock on failure

```routeros
# Final hardened Blocklist-Rotate deployment
# Single-script version based on the verified working backup logic, with:
# - lock file protection
# - minimum entry threshold
# - suspicious-size guard
# - silent bulk operations
# - Discord success/failure notifications

/system script remove [find name="Blocklist-Rotate"]
/system scheduler remove [find name="Blocklist-Rotate-Schedule"]

/system script add name="Blocklist-Rotate" owner="david" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    dont-require-permissions=no \
    source=":local scriptName \"BLOCKLIST-ROTATE\"; \
:local webhook \"https://discord.com/api/webhooks/REDACTED/redacted\"; \
:local lockFile \"usb2/blocklist/rotate.lock\"; \
:local minEntries 1000; \
:local activeList \"\"; \
:local nextList \"\"; \
:local nextFile \"\"; \
:local removeList \"\"; \
:local dstPath \"\"; \
:local sizeKb 0; \
:local importedCount 0; \
:local removeCount 0; \
:local errorText \"\"; \
:log info (\$scriptName . \": === Starting rotation ===\"); \
:if ([:len [/file find name=\$lockFile]] > 0) do={ \
    :set errorText \"Rotation locked\"; \
    :log warning (\$scriptName . \": Lock file exists, another rotation may already be running. Aborting.\"); \
    :error \$errorText; \
}; \
/file print file=\$lockFile; \
:do { \
    :local hs [/ip firewall raw find where chain=prerouting and action=drop and src-address-list~\"^davidian-sk-blocklist_\"]; \
    :local ph [/ip firewall raw find where chain=prerouting and action=drop and dst-address-list~\"^davidian-sk-blocklist_\"]; \
    :if (([:len \$hs] = 0) or ([:len \$ph] = 0)) do={ \
        :set errorText \"Required raw rules not found\"; \
        :log error (\$scriptName . \": Required blocklist raw rules not found. Aborting.\"); \
        :error \$errorText; \
    }; \
    :set activeList [/ip firewall raw get \$hs src-address-list]; \
    :if (\$activeList = \"davidian-sk-blocklist_a\") do={ \
        :set nextList \"davidian-sk-blocklist_b\"; \
        :set nextFile \"blocklist_b.rsc\"; \
        :set removeList \"davidian-sk-blocklist_a\"; \
    } else={ \
        :if (\$activeList = \"davidian-sk-blocklist_b\") do={ \
            :set nextList \"davidian-sk-blocklist_a\"; \
            :set nextFile \"blocklist_a.rsc\"; \
            :set removeList \"davidian-sk-blocklist_b\"; \
        } else={ \
            :set errorText (\"Unexpected active list: \" . \$activeList); \
            :log error (\$scriptName . \": Unexpected active list: \" . \$activeList . \". Aborting.\"); \
            :error \$errorText; \
        }; \
    }; \
    :log info (\$scriptName . \": Active=\" . \$activeList . \" | Rotating to=\" . \$nextList); \
    :set dstPath (\"usb2/blocklist/\" . \$nextFile); \
    :local url (\"https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/\" . \$nextFile); \
    :if ([:len [/file find name=\$dstPath]] > 0) do={ /file remove \$dstPath; }; \
    :log info (\$scriptName . \": [1/6] Downloading \" . \$nextFile . \"...\"); \
    /tool fetch url=\$url mode=https dst-path=\$dstPath; \
    :local f [/file find name=\$dstPath]; \
    :if ([:len \$f] = 0) do={ \
        :set errorText \"Download failed\"; \
        :log error (\$scriptName . \": [1/6] FAILED - Download failed. Keeping current protection.\"); \
        :error \$errorText; \
    }; \
    :local size [/file get \$f size]; \
    :if (\$size = 0) do={ \
        :set errorText \"Downloaded file is empty\"; \
        :log error (\$scriptName . \": [1/6] FAILED - Downloaded file is empty. Keeping current protection.\"); \
        :error \$errorText; \
    }; \
    :set sizeKb (\$size / 1024); \
    :log info (\$scriptName . \": [1/6] OK - Downloaded \" . \$sizeKb . \" KB.\"); \
    :local staleCount [:len [/ip firewall address-list find where list=\$nextList]]; \
    :if (\$staleCount > 0) do={ \
        :log info (\$scriptName . \": [2/6] Found \" . \$staleCount . \" stale entries in \" . \$nextList . \" - clearing...\"); \
        /system logging disable 0; \
        /ip firewall address-list remove [find where list=\$nextList]; \
        /system logging enable 0; \
        :log info (\$scriptName . \": [2/6] OK - Cleared \" . \$staleCount . \" stale entries.\"); \
    } else={ \
        :log info (\$scriptName . \": [2/6] OK - No stale entries in \" . \$nextList . \".\"); \
    }; \
    :log info (\$scriptName . \": [3/6] Importing \" . \$nextList . \"...\"); \
    :local importOk true; \
    /system logging disable 0; \
    :do { /import file-name=\$dstPath; } on-error={ :set importOk false; }; \
    /system logging enable 0; \
    :if (\$importOk = false) do={ \
        :set errorText \"Import failed\"; \
        :log error (\$scriptName . \": [3/6] FAILED - Import failed. Keeping \" . \$activeList . \" active.\"); \
        :error \$errorText; \
    }; \
    :set importedCount [:len [/ip firewall address-list find where list=\$nextList]]; \
    :log info (\$scriptName . \": [3/6] OK - Imported \" . \$importedCount . \" entries into \" . \$nextList . \".\"); \
    :if (\$importedCount < \$minEntries) do={ \
        :set errorText (\"Imported only \" . \$importedCount . \" entries, below threshold of \" . \$minEntries); \
        :log error (\$scriptName . \": [4/6] FAILED - Imported count \" . \$importedCount . \" is below minimum threshold \" . \$minEntries . \". Keeping \" . \$activeList . \" active.\"); \
        :error \$errorText; \
    }; \
    :local activeCount [:len [/ip firewall address-list find where list=\$activeList]]; \
    :if ((\$activeCount > 0) and (\$importedCount < (\$activeCount / 2))) do={ \
        :set errorText (\"New list suspiciously small: \" . \$importedCount . \" vs active \" . \$activeCount); \
        :log warning (\$scriptName . \": [4/6] Imported list is much smaller than active list (\" . \$importedCount . \" vs \" . \$activeCount . \"). Aborting switch.\"); \
        :error \$errorText; \
    }; \
    :log info (\$scriptName . \": [4/6] OK - Sanity checks passed.\"); \
    :log info (\$scriptName . \": [5/6] Switching raw rules to \" . \$nextList . \"...\"); \
    /ip firewall raw set \$hs src-address-list=\$nextList; \
    /ip firewall raw set \$ph dst-address-list=\$nextList; \
    :log info (\$scriptName . \": [5/6] OK - Blocklist raw rules now -> \" . \$nextList . \".\"); \
    :set removeCount [:len [/ip firewall address-list find where list=\$removeList]]; \
    :log info (\$scriptName . \": [6/6] Purging \" . \$removeCount . \" entries from old list \" . \$removeList . \"...\"); \
    /system logging disable 0; \
    /ip firewall address-list remove [find where list=\$removeList]; \
    /system logging enable 0; \
    :if ([:len [/file find name=\$dstPath]] > 0) do={ /file remove \$dstPath; }; \
    :log info (\$scriptName . \": [6/6] OK - Purged \" . \$removeCount . \" entries from \" . \$removeList . \".\"); \
    :log info (\$scriptName . \": === Complete: \" . \$activeList . \" -> \" . \$nextList . \" ===\"); \
    :local successJson (\"{\\\"embeds\\\": [{\\\"title\\\": \\\"Blocklist Rotation Complete\\\",\\\"color\\\": 5763719,\\\"fields\\\": [{\\\"name\\\": \\\"Rotation\\\",\\\"value\\\": \\\"\" . \$activeList . \" -> \" . \$nextList . \"\\\",\\\"inline\\\": false},{\\\"name\\\": \\\"Downloaded\\\",\\\"value\\\": \\\"\" . \$sizeKb . \" KB\\\",\\\"inline\\\": true},{\\\"name\\\": \\\"Imported\\\",\\\"value\\\": \\\"\" . \$importedCount . \" entries\\\",\\\"inline\\\": true},{\\\"name\\\": \\\"Purged old\\\",\\\"value\\\": \\\"\" . \$removeCount . \" entries\\\",\\\"inline\\\": true}]}]}\"); \
    /tool fetch url=\$webhook http-method=post http-header-field=\"content-type: application/json\" http-data=\$successJson output=none; \
} on-error={ \
    :if ([:len \$errorText] = 0) do={ :set errorText \"Rotation aborted\"; }; \
    :log error (\$scriptName . \": Rotation aborted due to error. Current active rules were left unchanged unless already switched.\"); \
    :local failRotation \"unknown\"; \
    :if (([:len \$activeList] > 0) and ([:len \$nextList] > 0)) do={ :set failRotation (\$activeList . \" -> \" . \$nextList); }; \
    :local failJson (\"{\\\"embeds\\\": [{\\\"title\\\": \\\"Blocklist Rotation Failed\\\",\\\"color\\\": 15548997,\\\"fields\\\": [{\\\"name\\\": \\\"Reason\\\",\\\"value\\\": \\\"\" . \$errorText . \"\\\",\\\"inline\\\": false},{\\\"name\\\": \\\"Rotation\\\",\\\"value\\\": \\\"\" . \$failRotation . \"\\\",\\\"inline\\\": false},{\\\"name\\\": \\\"Downloaded\\\",\\\"value\\\": \\\"\" . \$sizeKb . \" KB\\\",\\\"inline\\\": true},{\\\"name\\\": \\\"Imported\\\",\\\"value\\\": \\\"\" . \$importedCount . \" entries\\\",\\\"inline\\\": true}]}]}\"); \
    :do { /tool fetch url=\$webhook http-method=post http-header-field=\"content-type: application/json\" http-data=\$failJson output=none; } on-error={}; \
}; \
:if ([:len [/file find name=\$lockFile]] > 0) do={ /file remove \$lockFile; }; \
:if (([:len \$dstPath] > 0) and ([:len [/file find name=\$dstPath]] > 0)) do={ /file remove \$dstPath; };"

/system scheduler add name="Blocklist-Rotate-Schedule" start-date=2026-03-16 start-time=00:02:00 interval=6h \
    on-event="/system script run Blocklist-Rotate" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    disabled=no \
    comment="Every 6 hours at :02 using Blocklist-Rotate"
```

### Rotation Script - NO DISCORD VERSION


routeros
```
# Final hardened Blocklist-Rotate no-Discord deployment
# Single-script version matching the live hardened logic, without Discord and without scheduler changes.

/system script remove [find name="Blocklist-Rotate-No-Discord"]

/system script add name="Blocklist-Rotate-No-Discord" owner="david" \
    policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
    dont-require-permissions=no \
    source=":local scriptName \"BLOCKLIST-ROTATE\"; \
:local lockFile \"usb2/blocklist/rotate.lock\"; \
:local minEntries 1000; \
:local activeList \"\"; \
:local nextList \"\"; \
:local nextFile \"\"; \
:local removeList \"\"; \
:local dstPath \"\"; \
:local sizeKb 0; \
:local importedCount 0; \
:local removeCount 0; \
:local errorText \"\"; \
:log info (\$scriptName . \": === Starting rotation ===\"); \
:if ([:len [/file find name=\$lockFile]] > 0) do={ \
    :set errorText \"Rotation locked\"; \
    :log warning (\$scriptName . \": Lock file exists, another rotation may already be running. Aborting.\"); \
    :error \$errorText; \
}; \
/file print file=\$lockFile; \
:do { \
    :local hs [/ip firewall raw find where chain=prerouting and action=drop and src-address-list~\"^davidian-sk-blocklist_\"]; \
    :local ph [/ip firewall raw find where chain=prerouting and action=drop and dst-address-list~\"^davidian-sk-blocklist_\"]; \
    :if (([:len \$hs] = 0) or ([:len \$ph] = 0)) do={ \
        :set errorText \"Required raw rules not found\"; \
        :log error (\$scriptName . \": Required blocklist raw rules not found. Aborting.\"); \
        :error \$errorText; \
    }; \
    :set activeList [/ip firewall raw get \$hs src-address-list]; \
    :if (\$activeList = \"davidian-sk-blocklist_a\") do={ \
        :set nextList \"davidian-sk-blocklist_b\"; \
        :set nextFile \"blocklist_b.rsc\"; \
        :set removeList \"davidian-sk-blocklist_a\"; \
    } else={ \
        :if (\$activeList = \"davidian-sk-blocklist_b\") do={ \
            :set nextList \"davidian-sk-blocklist_a\"; \
            :set nextFile \"blocklist_a.rsc\"; \
            :set removeList \"davidian-sk-blocklist_b\"; \
        } else={ \
            :set errorText (\"Unexpected active list: \" . \$activeList); \
            :log error (\$scriptName . \": Unexpected active list: \" . \$activeList . \". Aborting.\"); \
            :error \$errorText; \
        }; \
    }; \
    :log info (\$scriptName . \": Active=\" . \$activeList . \" | Rotating to=\" . \$nextList); \
    :set dstPath (\"usb2/blocklist/\" . \$nextFile); \
    :local url (\"https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/\" . \$nextFile); \
    :if ([:len [/file find name=\$dstPath]] > 0) do={ /file remove \$dstPath; }; \
    :log info (\$scriptName . \": [1/6] Downloading \" . \$nextFile . \"...\"); \
    /tool fetch url=\$url mode=https dst-path=\$dstPath; \
    :local f [/file find name=\$dstPath]; \
    :if ([:len \$f] = 0) do={ \
        :set errorText \"Download failed\"; \
        :log error (\$scriptName . \": [1/6] FAILED - Download failed. Keeping current protection.\"); \
        :error \$errorText; \
    }; \
    :local size [/file get \$f size]; \
    :if (\$size = 0) do={ \
        :set errorText \"Downloaded file is empty\"; \
        :log error (\$scriptName . \": [1/6] FAILED - Downloaded file is empty. Keeping current protection.\"); \
        :error \$errorText; \
    }; \
    :set sizeKb (\$size / 1024); \
    :log info (\$scriptName . \": [1/6] OK - Downloaded \" . \$sizeKb . \" KB.\"); \
    :local staleCount [:len [/ip firewall address-list find where list=\$nextList]]; \
    :if (\$staleCount > 0) do={ \
        :log info (\$scriptName . \": [2/6] Found \" . \$staleCount . \" stale entries in \" . \$nextList . \" - clearing...\"); \
        /system logging disable 0; \
        /ip firewall address-list remove [find where list=\$nextList]; \
        /system logging enable 0; \
        :log info (\$scriptName . \": [2/6] OK - Cleared \" . \$staleCount . \" stale entries.\"); \
    } else={ \
        :log info (\$scriptName . \": [2/6] OK - No stale entries in \" . \$nextList . \".\"); \
    }; \
    :log info (\$scriptName . \": [3/6] Importing \" . \$nextList . \"...\"); \
    :local importOk true; \
    /system logging disable 0; \
    :do { /import file-name=\$dstPath; } on-error={ :set importOk false; }; \
    /system logging enable 0; \
    :if (\$importOk = false) do={ \
        :set errorText \"Import failed\"; \
        :log error (\$scriptName . \": [3/6] FAILED - Import failed. Keeping \" . \$activeList . \" active.\"); \
        :error \$errorText; \
    }; \
    :set importedCount [:len [/ip firewall address-list find where list=\$nextList]]; \
    :log info (\$scriptName . \": [3/6] OK - Imported \" . \$importedCount . \" entries into \" . \$nextList . \".\"); \
    :if (\$importedCount < \$minEntries) do={ \
        :set errorText (\"Imported only \" . \$importedCount . \" entries, below threshold of \" . \$minEntries); \
        :log error (\$scriptName . \": [4/6] FAILED - Imported count \" . \$importedCount . \" is below minimum threshold \" . \$minEntries . \". Keeping \" . \$activeList . \" active.\"); \
        :error \$errorText; \
    }; \
    :local activeCount [:len [/ip firewall address-list find where list=\$activeList]]; \
    :if ((\$activeCount > 0) and (\$importedCount < (\$activeCount / 2))) do={ \
        :set errorText (\"New list suspiciously small: \" . \$importedCount . \" vs active \" . \$activeCount); \
        :log warning (\$scriptName . \": [4/6] Imported list is much smaller than active list (\" . \$importedCount . \" vs \" . \$activeCount . \"). Aborting switch.\"); \
        :error \$errorText; \
    }; \
    :log info (\$scriptName . \": [4/6] OK - Sanity checks passed.\"); \
    :log info (\$scriptName . \": [5/6] Switching raw rules to \" . \$nextList . \"...\"); \
    /ip firewall raw set \$hs src-address-list=\$nextList; \
    /ip firewall raw set \$ph dst-address-list=\$nextList; \
    :log info (\$scriptName . \": [5/6] OK - Blocklist raw rules now -> \" . \$nextList . \".\"); \
    :set removeCount [:len [/ip firewall address-list find where list=\$removeList]]; \
    :log info (\$scriptName . \": [6/6] Purging \" . \$removeCount . \" entries from old list \" . \$removeList . \"...\"); \
    /system logging disable 0; \
    /ip firewall address-list remove [find where list=\$removeList]; \
    /system logging enable 0; \
    :if ([:len [/file find name=\$dstPath]] > 0) do={ /file remove \$dstPath; }; \
    :log info (\$scriptName . \": [6/6] OK - Purged \" . \$removeCount . \" entries from \" . \$removeList . \".\"); \
    :log info (\$scriptName . \": === Complete: \" . \$activeList . \" -> \" . \$nextList . \" ===\"); \
} on-error={ \
    :if ([:len \$errorText] = 0) do={ :set errorText \"Rotation aborted\"; }; \
    :log error (\$scriptName . \": Rotation aborted due to error. Current active rules were left unchanged unless already switched.\"); \
}; \
:if ([:len [/file find name=\$lockFile]] > 0) do={ /file remove \$lockFile; }; \
:if (([:len \$dstPath] > 0) and ([:len [/file find name=\$dstPath]] > 0)) do={ /file remove \$dstPath; };"
```

You can also use `blocklist.rsc` if you prefer a single-list workflow that downloads the file, removes the current entries, and imports the new list. This method is simpler, but it does not provide the same continuity as the dual-list rotation approach.

### III. SCHEDULER SETUP (Daily Run)

### Scheduler Setup

Run the rotation script at your preferred interval. The example below runs it every 6 hours:

routeros

```
/system scheduler
add name="Blocklist-Rotate" \
    comment="[6h] Automatically detects active blocklist and rotates to the other" \
    interval=6h \
    start-date=2026-03-12 \
    start-time=18:02:00 \
    on-event="/system script run davidian-sk-blocklist-rotate" \
    policy=read,write,policy,test
```

# **3\. Add Firewall Rule (Router OS)**


### **High-Performance Raw Rule (for Large Lists)**

These RAW rules drop unwanted traffic before connection tracking. This reduces processing overhead compared with filtering the same traffic later in the firewall pipeline.

This is the most efficient method. This rule runs before connection tracking, which is highly efficient and saves CPU cycles on your router.
Add the firewall rule to your raw table to drop all incoming traffic from sources in your new address list. 
The first rule drops inbound traffic from known malicious source IPs on the WAN side.  
The second rule blocks LAN devices from connecting to known malicious destination IPs.

```routeros
/ip firewall raw
add chain=prerouting in-interface-list=WAN src-address-list=davidian-sk-blocklist_a action=drop comment="RAW-SEC: Drop known malicious WAN source IPs early"
add chain=prerouting in-interface-list=LAN dst-address-list=davidian-sk-blocklist_a action=drop comment="RAW-SEC: Drop LAN traffic to malicious destinations"
```
