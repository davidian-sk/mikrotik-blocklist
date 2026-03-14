# **🛡️ Davidian-SK MikroTik Blocklist Aggregator**

This repository provides a self-updating MikroTik address list built by aggregating multiple public threat intelligence feeds. Its main goal is to generate the most compact practical set of CIDR ranges possible, reducing address-list size and improving firewall efficiency on MikroTik devices such as the RB5009.

## **🚀 Features**


- **Source aggregation:** Pulls IP data from multiple public threat feeds listed in `sources.txt`.
- **CIDR compression:** Uses Python's `ipaddress` library to aggregate individual IPs and ranges into a compact list of CIDR blocks.
- **RouterOS output:** Generates RouterOS import scripts for use with MikroTik address lists.
- **Dual deployment options:** Supports both local generation and GitHub-based delivery workflows.
  
## **📝 Output Files**

The Linux script generates the following files:

## 📝 Output Files

The generator creates the following files:

| File Name | Content | Purpose |
|---|---|---|
| `blocklist.rsc` | RouterOS import script | Single-list import file. Suitable for simple replace workflows, but not ideal if you want near-zero downtime. |
| `blocklist_a.rsc` | RouterOS import script | First half of the dual-list rotation method. |
| `blocklist_b.rsc` | RouterOS import script | Second half of the dual-list rotation method. |
| `aggregated_cidr_ranges.txt` | Final optimized CIDR ranges | Useful for auditing or reuse in other tools. |
| `aggregated_ips.txt` | Aggregated plain IP/range output | Useful for inspection or downstream processing. |
| `sources.txt` | Source feed list | Defines the public feeds used as input. |

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

"davidian-sk-blocklist-rotate"

```routeros
:log info "BLOCKLIST-ROTATE: === Starting rotation ===";

:local hs [/ip firewall raw find where comment~"Hacker Shield"];
:local ph [/ip firewall raw find where comment~"Phone-Home Shield"];

:if (([:len $hs] = 0) or ([:len $ph] = 0)) do={
    :log error "BLOCKLIST-ROTATE: Required raw rules not found. Aborting.";
    :error "Missing raw rules";
};

:local activeList [/ip firewall raw get $hs src-address-list];
:local nextList;
:local nextFile;
:local removeList;

:if ($activeList = "davidian-sk-blocklist_a") do={
    :set nextList "davidian-sk-blocklist_b";
    :set nextFile "blocklist_b.rsc";
    :set removeList "davidian-sk-blocklist_a";
} else={
    :if ($activeList = "davidian-sk-blocklist_b") do={
        :set nextList "davidian-sk-blocklist_a";
        :set nextFile "blocklist_a.rsc";
        :set removeList "davidian-sk-blocklist_b";
    } else={
        :log error ("BLOCKLIST-ROTATE: Unexpected active list: " . $activeList . ". Aborting.");
        :error "Unexpected active list";
    };
};

:log info ("BLOCKLIST-ROTATE: Active=" . $activeList . " | Rotating to=" . $nextList);

:local dstPath ("usb2/blocklist/" . $nextFile);
:local url ("https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/" . $nextFile);

:log info ("BLOCKLIST-ROTATE: [1/5] Downloading " . $nextFile . "...");
/tool fetch url=$url mode=https dst-path=$dstPath;

:local f [/file find name=$dstPath];

:if ([:len $f] = 0) do={
    :log error "BLOCKLIST-ROTATE: [1/5] FAILED - Download failed. Keeping current protection.";
    :error "Download failed";
};

:local size [/file get $f size];

:if ($size = 0) do={
    :log error "BLOCKLIST-ROTATE: [1/5] FAILED - Downloaded file is empty. Keeping current protection.";
    :error "Empty download";
};

:local sizeKb ($size / 1024);
:log info ("BLOCKLIST-ROTATE: [1/5] OK - Downloaded " . $sizeKb . " KB.");

:local staleCount [:len [/ip firewall address-list find where list=$nextList]];

:if ($staleCount > 0) do={
    :log info ("BLOCKLIST-ROTATE: [2/5] Found " . $staleCount . " stale entries in " . $nextList . " - clearing...");
    /system logging disable 0
    :foreach i in=[/ip firewall address-list find where list=$nextList] do={
        /ip firewall address-list remove $i
    }
    /system logging enable 0
    :log info ("BLOCKLIST-ROTATE: [2/5] OK - Cleared " . $staleCount . " stale entries.");
} else={
    :log info ("BLOCKLIST-ROTATE: [2/5] OK - No stale entries in " . $nextList . ".");
};

:log info ("BLOCKLIST-ROTATE: [3/5] Importing " . $nextList . "...");

:local importOk true;

/system logging disable 0
:do {
    /import file-name=$dstPath
} on-error={
    :set importOk false
}
/system logging enable 0

:if ($importOk = false) do={
    :log error ("BLOCKLIST-ROTATE: [3/5] FAILED - Import failed. Keeping " . $activeList . " active.");
    :error "Import failed";
};

:local importedCount [:len [/ip firewall address-list find where list=$nextList]];

:log info ("BLOCKLIST-ROTATE: [3/5] OK - Imported " . $importedCount . " entries into " . $nextList . ".");

:log info ("BLOCKLIST-ROTATE: [4/5] Switching raw rules to " . $nextList . "...");

/ip firewall raw set $hs src-address-list=$nextList
/ip firewall raw set $ph dst-address-list=$nextList

:log info ("BLOCKLIST-ROTATE: [4/5] OK - Hacker Shield + Phone-Home Shield now -> " . $nextList . ".");

:local removeCount [:len [/ip firewall address-list find where list=$removeList]];

:log info ("BLOCKLIST-ROTATE: [5/5] Purging " . $removeCount . " entries from old list " . $removeList . "...");

/system logging disable 0
:foreach i in=[/ip firewall address-list find where list=$removeList] do={
    /ip firewall address-list remove $i
}
/system logging enable 0

/file remove $dstPath

:log info ("BLOCKLIST-ROTATE: [5/5] OK - Purged " . $removeCount . " entries from " . $removeList . ".");
:log info ("BLOCKLIST-ROTATE: === Complete: " . $activeList . " -> " . $nextList . " ===");
```

### Safer Rotation Script (Untested)

The following version adds additional safeguards, but has not yet been validated in production:

- lock/guard so it won’t run twice at the same time

- download/import sanity check

- minimum imported entry threshold

- do not switch rules if the new list looks suspiciously small

- do not purge old list unless the switch really happened

- cleanup lock on failure

routeros
```
:local scriptName "BLOCKLIST-ROTATE";
:local lockFile "usb2/blocklist/.rotate.lock";
:local minEntries 1000;

:log info ($scriptName . ": === Starting rotation ===");

# Guard against concurrent runs
:if ([:len [/file find name=$lockFile]] > 0) do={
    :log warning ($scriptName . ": Lock file exists, another rotation may already be running. Aborting.");
    :error "Rotation locked";
}

/file print file="usb2/blocklist/.rotate.lock";

:do {

    :local hs [/ip firewall raw find where comment~"Hacker Shield"];
    :local ph [/ip firewall raw find where comment~"Phone-Home Shield"];

    :if (([:len $hs] = 0) or ([:len $ph] = 0)) do={
        :log error ($scriptName . ": Required raw rules not found. Aborting.");
        :error "Missing raw rules";
    };

    :local activeList [/ip firewall raw get $hs src-address-list];
    :local nextList;
    :local nextFile;
    :local removeList;

    :if ($activeList = "davidian-sk-blocklist_a") do={
        :set nextList "davidian-sk-blocklist_b";
        :set nextFile "blocklist_b.rsc";
        :set removeList "davidian-sk-blocklist_a";
    } else={
        :if ($activeList = "davidian-sk-blocklist_b") do={
            :set nextList "davidian-sk-blocklist_a";
            :set nextFile "blocklist_a.rsc";
            :set removeList "davidian-sk-blocklist_b";
        } else={
            :log error ($scriptName . ": Unexpected active list: " . $activeList . ". Aborting.");
            :error "Unexpected active list";
        };
    };

    :log info ($scriptName . ": Active=" . $activeList . " | Rotating to=" . $nextList);

    :local dstPath ("usb2/blocklist/" . $nextFile);
    :local url ("https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/" . $nextFile);

    # Remove any leftover file first
    :if ([:len [/file find name=$dstPath]] > 0) do={
        /file remove $dstPath;
    };

    :log info ($scriptName . ": [1/6] Downloading " . $nextFile . "...");
    /tool fetch url=$url mode=https dst-path=$dstPath;

    :local f [/file find name=$dstPath];
    :if ([:len $f] = 0) do={
        :log error ($scriptName . ": [1/6] FAILED - Download failed. Keeping current protection.");
        :error "Download failed";
    };

    :local size [/file get $f size];
    :if ($size = 0) do={
        :log error ($scriptName . ": [1/6] FAILED - Downloaded file is empty. Keeping current protection.");
        :error "Empty download";
    };

    :local sizeKb ($size / 1024);
    :log info ($scriptName . ": [1/6] OK - Downloaded " . $sizeKb . " KB.");

    # Clear target list only
    :local staleCount [:len [/ip firewall address-list find where list=$nextList]];
    :if ($staleCount > 0) do={
        :log info ($scriptName . ": [2/6] Found " . $staleCount . " stale entries in " . $nextList . " - clearing...");
        :foreach i in=[/ip firewall address-list find where list=$nextList] do={
            /ip firewall address-list remove $i;
        };
        :log info ($scriptName . ": [2/6] OK - Cleared " . $staleCount . " stale entries.");
    } else={
        :log info ($scriptName . ": [2/6] OK - No stale entries in " . $nextList . ".");
    };

    :log info ($scriptName . ": [3/6] Importing " . $nextList . "...");
    :local importOk true;

    :do {
        /import file-name=$dstPath;
    } on-error={
        :set importOk false;
    };

    :if ($importOk = false) do={
        :log error ($scriptName . ": [3/6] FAILED - Import failed. Keeping " . $activeList . " active.");
        :error "Import failed";
    };

    :local importedCount [:len [/ip firewall address-list find where list=$nextList]];
    :log info ($scriptName . ": [3/6] OK - Imported " . $importedCount . " entries into " . $nextList . ".");

    # Sanity threshold check
    :if ($importedCount < $minEntries) do={
        :log error ($scriptName . ": [4/6] FAILED - Imported count " . $importedCount . " is below minimum threshold " . $minEntries . ". Keeping " . $activeList . " active.");
        :error "Imported list below threshold";
    };

    # Optional comparison against old active list size
    :local activeCount [:len [/ip firewall address-list find where list=$activeList]];
    :if (($activeCount > 0) and ($importedCount < ($activeCount / 2))) do={
        :log warning ($scriptName . ": [4/6] Imported list is much smaller than active list (" . $importedCount . " vs " . $activeCount . "). Aborting switch.");
        :error "Imported list suspiciously small";
    };

    :log info ($scriptName . ": [4/6] OK - Sanity checks passed.");

    :log info ($scriptName . ": [5/6] Switching raw rules to " . $nextList . "...");
    /ip firewall raw set $hs src-address-list=$nextList;
    /ip firewall raw set $ph dst-address-list=$nextList;
    :log info ($scriptName . ": [5/6] OK - Hacker Shield + Phone-Home Shield now -> " . $nextList . ".");

    :local removeCount [:len [/ip firewall address-list find where list=$removeList]];
    :log info ($scriptName . ": [6/6] Purging " . $removeCount . " entries from old list " . $removeList . "...");
    :foreach i in=[/ip firewall address-list find where list=$removeList] do={
        /ip firewall address-list remove $i;
    };
    :log info ($scriptName . ": [6/6] OK - Purged " . $removeCount . " entries from " . $removeList . ".");

    # Cleanup downloaded file
    :if ([:len [/file find name=$dstPath]] > 0) do={
        /file remove $dstPath;
    };

    :log info ($scriptName . ": === Complete: " . $activeList . " -> " . $nextList . " ===");

} on-error={

    :log error ($scriptName . ": Rotation aborted due to error. Current active rules were left unchanged unless already switched.");

} 

# Always try to remove lock at the end
:if ([:len [/file find name=$lockFile]] > 0) do={
    /file remove $lockFile;
}
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


### **Option A: *(Recommended Method)* High-Performance Raw Rule (for Large Lists)**

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
