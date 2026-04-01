# **🛡️ Davidian-SK MikroTik Blocklist Aggregator**

This repository provides a self-updating MikroTik address list built by aggregating multiple public threat intelligence feeds. Its main goal is to generate the most compact practical set of CIDR ranges possible, reducing address-list size and improving firewall efficiency on MikroTik devices such as the RB5009.

## **🚀 Features**


- **Source aggregation:** Pulls IP data from multiple public threat feeds listed in `sources.txt`.
- **CIDR compression:** Uses Python's `ipaddress` library to aggregate individual IPs and ranges into a compact list of CIDR blocks.
- **RouterOS output:** Generates RouterOS import scripts for use with MikroTik address lists.

Sources:

```
# === CORE (HIGH CONFIDENCE – LOW MAINTENANCE) ===

🌐 [IN] https://www.spamhaus.org/drop/drop.txt
🌐 [IN] https://www.spamhaus.org/drop/edrop.txt
🌐 [IN] https://feodotracker.abuse.ch/downloads/ipblocklist.txt
🌐 [IN] https://rules.emergingthreats.net/blockrules/compromised-ips.txt
🌐 [IN] https://check.torproject.org/torbulkexitlist
🌐 [IN] https://www.dshield.org/block.txt

🌐 [OUT] https://feodotracker.abuse.ch/downloads/ipblocklist.txt
🌐 [OUT] https://rules.emergingthreats.net/blockrules/compromised-ips.txt



## **📝 Output Files**

The generator creates the following files:

📦 blocklist.rsc
📦 blocklist_a.rsc
📦 blocklist_b.rsc
📦 blocklist_out.rsc
📦 blocklist_out_a.rsc
📦 blocklist_out_b.rsc

## 2. MikroTik RouterOS Setup

This method uses a custom RouterOS script that downloads the next blocklist file to `usb2/blocklist/`, verifies that the file exists and is not empty, imports it into the inactive address list, and then atomically switches the firewall rules to the new list.

The dual-list method is recommended because it avoids replacing the active list in place.


### Prerequisites

Before using the rotation script:

1. Create the address list `davidian-sk-blocklist_a/davidian-sk-blocklist-out_a` and add a dummy entry such as `10.0.0.1`.
2. Create the address list `davidian-sk-blocklist_b/davidian-sk-blocklist-out_b` and add a dummy entry such as `10.0.0.2`.
3. Create two RAW firewall rules:
   - one that drops traffic from source IPs in the active blocklist on the WAN side
   - one that drops LAN traffic destined for IPs in the active blocklist
4. Ensure your router can write to `usb2/blocklist/`.
5. Ensure the script name matches the scheduler entry exactly.
## 

## How the Dual-List Rotation Works

The rotation method uses two sdets of MikroTik address lists:

- `davidian-sk-blocklist_a`
- `davidian-sk-blocklist_b`
- `davidian-sk-blocklist-out_a`
- `davidian-sk-blocklist-out_b`

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
# ==========================================
# BLOCKLIST-ROTATE-FINAL-DISCORD
# 7-stage, low-noise, verified rotation
# ==========================================

:local scriptName "BLOCKLIST-ROTATE-FINAL-DISCORD"
:local webhook "https://discord.com/api/webhooks/redacted/redacted"
:local lockFile "usb2/Tools-Scripts/blocklist_rotate.lock"
:local baseUrl "https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/"

:local tsDate [/system clock get date]
:local tsTime [/system clock get time]
:local ts ($tsDate . " " . $tsTime)

:local activeIn ""
:local nextIn ""
:local activeOut ""
:local nextOut ""

:local fileIn ""
:local fileOut ""

:local ruleIn
:local ruleOut

:local verifyIn ""
:local verifyOut ""

:local importedIn 0
:local importedOut 0
:local purgedIn 0
:local purgedOut 0
:local deltaIn 0
:local deltaOut 0

:local fetchIn
:local fetchOut

:local errMsg ""
:local failDate ""
:local failTime ""
:local failTs ""
:local payload ""

:log info ($scriptName . ": START at " . $ts)

# ==========================================
# Stage 1/7 - Lock guard
# ==========================================
:log info ($scriptName . ": [1/7] Initializing guard and checking lock.")

:if ([:len [/file find where name=$lockFile]] > 0) do={
    :log warning ($scriptName . ": Lock file exists, aborting.")
    :error "Locked"
}

/file print file=$lockFile

:do {

    # ==========================================
    # Stage 2/7 - Detect current active targets
    # ==========================================
    :log info ($scriptName . ": [2/7] Detecting active RAW targets.")

    :set ruleIn [/ip firewall raw find where comment~"WAN source IPs early"]
    :set ruleOut [/ip firewall raw find where comment~"outbound traffic to malicious"]

    :if ([:len $ruleIn] = 0) do={
        :set errMsg "Inbound RAW rule not found"
        :error $errMsg
    }
    :if ([:len $ruleOut] = 0) do={
        :set errMsg "Outbound RAW rule not found"
        :error $errMsg
    }

    :set activeIn [/ip firewall raw get $ruleIn src-address-list]
    :set activeOut [/ip firewall raw get $ruleOut dst-address-list]

    :if ($activeIn = "davidian-sk-blocklist_a") do={
        :set nextIn "davidian-sk-blocklist_b"
        :set fileIn "blocklist_b.rsc"
        :set nextOut "davidian-sk-blocklist-out_b"
        :set fileOut "blocklist_out_b.rsc"
    } else={
        :set nextIn "davidian-sk-blocklist_a"
        :set fileIn "blocklist_a.rsc"
        :set nextOut "davidian-sk-blocklist-out_a"
        :set fileOut "blocklist_out_a.rsc"
    }

    :log info ($scriptName . ": Active IN=" . $activeIn . " -> Next IN=" . $nextIn)
    :log info ($scriptName . ": Active OUT=" . $activeOut . " -> Next OUT=" . $nextOut)

    # ==========================================
    # Stage 3/7 - Fetch next files
    # ==========================================
    :log info ($scriptName . ": [3/7] Fetching next blocklist files.")

    :set fetchIn [/tool fetch url=($baseUrl . $fileIn) dst-path=("usb2/blocklist/" . $fileIn) as-value]
    :set fetchOut [/tool fetch url=($baseUrl . $fileOut) dst-path=("usb2/blocklist/" . $fileOut) as-value]

    :if (($fetchIn->"status") != "finished") do={
        :set errMsg ("Fetch failed for inbound file " . $fileIn . ": " . ($fetchIn->"status"))
        :error $errMsg
    }
    :if (($fetchOut->"status") != "finished") do={
        :set errMsg ("Fetch failed for outbound file " . $fileOut . ": " . ($fetchOut->"status"))
        :error $errMsg
    }

    :if ([:len [/file find where name=("usb2/blocklist/" . $fileIn)]] = 0) do={
        :set errMsg ("Downloaded inbound file missing: " . $fileIn)
        :error $errMsg
    }
    :if ([:len [/file find where name=("usb2/blocklist/" . $fileOut)]] = 0) do={
        :set errMsg ("Downloaded outbound file missing: " . $fileOut)
        :error $errMsg
    }

    # ==========================================
    # Stage 4/7 - Import into staging lists
    # ==========================================
    :log info ($scriptName . ": [4/7] Purging staging lists and importing fresh entries.")

    /system logging disable 0

    /ip firewall address-list remove [find where list=$nextIn]
    /ip firewall address-list remove [find where list=$nextOut]

    /import file-name=("usb2/blocklist/" . $fileIn)
    /import file-name=("usb2/blocklist/" . $fileOut)

    :set importedIn [:len [/ip firewall address-list find where list=$nextIn]]
    :set importedOut [:len [/ip firewall address-list find where list=$nextOut]]

    /system logging enable 0

    :if ($importedIn = 0) do={
        :set errMsg ("Inbound import is empty for list " . $nextIn)
        :error $errMsg
    }
    :if ($importedOut = 0) do={
        :set errMsg ("Outbound import is empty for list " . $nextOut)
        :error $errMsg
    }

    :log info ($scriptName . ": Imported staging counts: IN=" . $importedIn . ", OUT=" . $importedOut)

    # ==========================================
    # Stage 5/7 - Swap live RAW rules
    # ==========================================
    :log info ($scriptName . ": [5/7] Swapping RAW rules to next blocklists.")

    /ip firewall raw set $ruleIn src-address-list=$nextIn
    /ip firewall raw set $ruleOut dst-address-list=$nextOut

    :set verifyIn [/ip firewall raw get $ruleIn src-address-list]
    :set verifyOut [/ip firewall raw get $ruleOut dst-address-list]

    :if (($verifyIn != $nextIn) || ($verifyOut != $nextOut)) do={
        :log error ($scriptName . ": Swap verification failed. Rolling back.")
        /ip firewall raw set $ruleIn src-address-list=$activeIn
        /ip firewall raw set $ruleOut dst-address-list=$activeOut
        :set errMsg ("Swap verification failed. Restored previous lists: " . $activeIn . " / " . $activeOut)
        :error $errMsg
    }

    :log info ($scriptName . ": Swap verified: IN=" . $verifyIn . ", OUT=" . $verifyOut)

    # ==========================================
    # Stage 6/7 - Cleanup old live lists and temp files
    # ==========================================
    :log info ($scriptName . ": [6/7] Cleaning old active lists and temporary files.")

    /system logging disable 0

    :set purgedIn [:len [/ip firewall address-list find where list=$activeIn]]
    :set purgedOut [:len [/ip firewall address-list find where list=$activeOut]]

    /ip firewall address-list remove [find where list=$activeIn]
    /ip firewall address-list remove [find where list=$activeOut]

    /file remove [find where name=("usb2/blocklist/" . $fileIn)]
    /file remove [find where name=("usb2/blocklist/" . $fileOut)]

    /system logging enable 0

    :set deltaIn ($importedIn - $purgedIn)
    :set deltaOut ($importedOut - $purgedOut)

    :log info ($scriptName . ": Cleanup stats: IN imported=" . $importedIn . ", purged=" . $purgedIn . ", delta=" . $deltaIn)
    :log info ($scriptName . ": Cleanup stats: OUT imported=" . $importedOut . ", purged=" . $purgedOut . ", delta=" . $deltaOut)

    # ==========================================
    # Stage 7/7 - Notify and unlock
    # ==========================================
    :log info ($scriptName . ": [7/7] Sending success notification and cleaning lock.")

    :set payload ("{\"embeds\":[{\"title\":\"\F0\9F\9B\A1\EF\B8\8F Blocklist Dual-Guard Refreshed\",\"color\":5763719,\"fields\":[{\"name\":\"Inbound Guard (" . $activeIn . " -> " . $nextIn . ")\",\"value\":\"" . $importedIn . " Imported\\n" . $purgedIn . " Purged\\nDelta: " . $deltaIn . "\",\"inline\":true},{\"name\":\"Outbound Guard (" . $activeOut . " -> " . $nextOut . ")\",\"value\":\"" . $importedOut . " Imported\\n" . $purgedOut . " Purged\\nDelta: " . $deltaOut . "\",\"inline\":true}],\"footer\":{\"text\":\"" . $scriptName . " | " . [/system clock get date] . " " . [/system clock get time] . "\"}}]}")

    /tool fetch url=$webhook http-method=post http-header-field="content-type: application/json" http-data=$payload output=none

    :if ([:len [/file find where name=$lockFile]] > 0) do={
        /file remove [find where name=$lockFile]
    }

    :log info ($scriptName . ": SUCCESS at " . [/system clock get time] . ". Imported " . $importedIn . " IN / " . $importedOut . " OUT, purged " . $purgedIn . " IN / " . $purgedOut . " OUT, delta " . $deltaIn . " IN / " . $deltaOut . " OUT.")

} on-error={

    :set failDate [/system clock get date]
    :set failTime [/system clock get time]
    :set failTs ($failDate . " " . $failTime)

    :if ($errMsg = "") do={
        :set errMsg "Unknown error"
    }

    :if ([:len [/file find where name=$lockFile]] > 0) do={
        /file remove [find where name=$lockFile]
    }

    :log error ($scriptName . ": FAILED at " . $failTs . " | " . $errMsg)

    :set payload ("{\"embeds\":[{\"title\":\"\E2\9D\8C Blocklist Rotation FAILED\",\"color\":15158332,\"fields\":[{\"name\":\"Script\",\"value\":\"" . $scriptName . "\",\"inline\":true},{\"name\":\"Time\",\"value\":\"" . $failTs . "\",\"inline\":true},{\"name\":\"Reason\",\"value\":\"" . $errMsg . "\",\"inline\":false}],\"footer\":{\"text\":\"Rollback attempted where applicable\"}}]}")

    /tool fetch url=$webhook http-method=post http-header-field="content-type: application/json" http-data=$payload output=none
}
```

### Rotation Script - NO DISCORD VERSION


routeros
```
# ==========================================
# BLOCKLIST-ROTATE-FINAL-NODISCORD
# 7-stage, low-noise, verified rotation
# ==========================================

:local scriptName "BLOCKLIST-ROTATE-FINAL-NODISCORD"
:local lockFile "usb2/Tools-Scripts/blocklist_rotate.lock"
:local baseUrl "https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/"

:local tsDate [/system clock get date]
:local tsTime [/system clock get time]
:local ts ($tsDate . " " . $tsTime)

:local activeIn ""
:local nextIn ""
:local activeOut ""
:local nextOut ""

:local fileIn ""
:local fileOut ""

:local ruleIn
:local ruleOut

:local verifyIn ""
:local verifyOut ""

:local importedIn 0
:local importedOut 0
:local purgedIn 0
:local purgedOut 0
:local deltaIn 0
:local deltaOut 0

:local fetchIn
:local fetchOut

:local errMsg ""
:local failDate ""
:local failTime ""
:local failTs ""

:log info ($scriptName . ": START at " . $ts)

# ==========================================
# Stage 1/7 - Lock guard
# ==========================================
:log info ($scriptName . ": [1/7] Initializing guard and checking lock.")

:if ([:len [/file find where name=$lockFile]] > 0) do={
    :log warning ($scriptName . ": Lock file exists, aborting.")
    :error "Locked"
}

/file print file=$lockFile

:do {

    # ==========================================
    # Stage 2/7 - Detect current active targets
    # ==========================================
    :log info ($scriptName . ": [2/7] Detecting active RAW targets.")

    :set ruleIn [/ip firewall raw find where comment~"WAN source IPs early"]
    :set ruleOut [/ip firewall raw find where comment~"outbound traffic to malicious"]

    :if ([:len $ruleIn] = 0) do={
        :set errMsg "Inbound RAW rule not found"
        :error $errMsg
    }
    :if ([:len $ruleOut] = 0) do={
        :set errMsg "Outbound RAW rule not found"
        :error $errMsg
    }

    :set activeIn [/ip firewall raw get $ruleIn src-address-list]
    :set activeOut [/ip firewall raw get $ruleOut dst-address-list]

    :if ($activeIn = "davidian-sk-blocklist_a") do={
        :set nextIn "davidian-sk-blocklist_b"
        :set fileIn "blocklist_b.rsc"
        :set nextOut "davidian-sk-blocklist-out_b"
        :set fileOut "blocklist_out_b.rsc"
    } else={
        :set nextIn "davidian-sk-blocklist_a"
        :set fileIn "blocklist_a.rsc"
        :set nextOut "davidian-sk-blocklist-out_a"
        :set fileOut "blocklist_out_a.rsc"
    }

    :log info ($scriptName . ": Active IN=" . $activeIn . " -> Next IN=" . $nextIn)
    :log info ($scriptName . ": Active OUT=" . $activeOut . " -> Next OUT=" . $nextOut)

    # ==========================================
    # Stage 3/7 - Fetch next files
    # ==========================================
    :log info ($scriptName . ": [3/7] Fetching next blocklist files.")

    :set fetchIn [/tool fetch url=($baseUrl . $fileIn) dst-path=("usb2/blocklist/" . $fileIn) as-value]
    :set fetchOut [/tool fetch url=($baseUrl . $fileOut) dst-path=("usb2/blocklist/" . $fileOut) as-value]

    :if (($fetchIn->"status") != "finished") do={
        :set errMsg ("Fetch failed for inbound file " . $fileIn . ": " . ($fetchIn->"status"))
        :error $errMsg
    }
    :if (($fetchOut->"status") != "finished") do={
        :set errMsg ("Fetch failed for outbound file " . $fileOut . ": " . ($fetchOut->"status"))
        :error $errMsg
    }

    :if ([:len [/file find where name=("usb2/blocklist/" . $fileIn)]] = 0) do={
        :set errMsg ("Downloaded inbound file missing: " . $fileIn)
        :error $errMsg
    }
    :if ([:len [/file find where name=("usb2/blocklist/" . $fileOut)]] = 0) do={
        :set errMsg ("Downloaded outbound file missing: " . $fileOut)
        :error $errMsg
    }

    # ==========================================
    # Stage 4/7 - Import into staging lists
    # ==========================================
    :log info ($scriptName . ": [4/7] Purging staging lists and importing fresh entries.")

    /system logging disable 0

    /ip firewall address-list remove [find where list=$nextIn]
    /ip firewall address-list remove [find where list=$nextOut]

    /import file-name=("usb2/blocklist/" . $fileIn)
    /import file-name=("usb2/blocklist/" . $fileOut)

    :set importedIn [:len [/ip firewall address-list find where list=$nextIn]]
    :set importedOut [:len [/ip firewall address-list find where list=$nextOut]]

    /system logging enable 0

    :if ($importedIn = 0) do={
        :set errMsg ("Inbound import is empty for list " . $nextIn)
        :error $errMsg
    }
    :if ($importedOut = 0) do={
        :set errMsg ("Outbound import is empty for list " . $nextOut)
        :error $errMsg
    }

    :log info ($scriptName . ": Imported staging counts: IN=" . $importedIn . ", OUT=" . $importedOut)

    # ==========================================
    # Stage 5/7 - Swap live RAW rules
    # ==========================================
    :log info ($scriptName . ": [5/7] Swapping RAW rules to next blocklists.")

    /ip firewall raw set $ruleIn src-address-list=$nextIn
    /ip firewall raw set $ruleOut dst-address-list=$nextOut

    :set verifyIn [/ip firewall raw get $ruleIn src-address-list]
    :set verifyOut [/ip firewall raw get $ruleOut dst-address-list]

    :if (($verifyIn != $nextIn) || ($verifyOut != $nextOut)) do={
        :log error ($scriptName . ": Swap verification failed. Rolling back.")
        /ip firewall raw set $ruleIn src-address-list=$activeIn
        /ip firewall raw set $ruleOut dst-address-list=$activeOut
        :set errMsg ("Swap verification failed. Restored previous lists: " . $activeIn . " / " . $activeOut)
        :error $errMsg
    }

    :log info ($scriptName . ": Swap verified: IN=" . $verifyIn . ", OUT=" . $verifyOut)

    # ==========================================
    # Stage 6/7 - Cleanup old live lists and temp files
    # ==========================================
    :log info ($scriptName . ": [6/7] Cleaning old active lists and temporary files.")

    /system logging disable 0

    :set purgedIn [:len [/ip firewall address-list find where list=$activeIn]]
    :set purgedOut [:len [/ip firewall address-list find where list=$activeOut]]

    /ip firewall address-list remove [find where list=$activeIn]
    /ip firewall address-list remove [find where list=$activeOut]

    /file remove [find where name=("usb2/blocklist/" . $fileIn)]
    /file remove [find where name=("usb2/blocklist/" . $fileOut)]

    /system logging enable 0

    :set deltaIn ($importedIn - $purgedIn)
    :set deltaOut ($importedOut - $purgedOut)

    :log info ($scriptName . ": Cleanup stats: IN imported=" . $importedIn . ", purged=" . $purgedIn . ", delta=" . $deltaIn)
    :log info ($scriptName . ": Cleanup stats: OUT imported=" . $importedOut . ", purged=" . $purgedOut . ", delta=" . $deltaOut)

    # ==========================================
    # Stage 7/7 - Unlock and finish
    # ==========================================
    :log info ($scriptName . ": [7/7] Cleaning lock and finishing.")

    :if ([:len [/file find where name=$lockFile]] > 0) do={
        /file remove [find where name=$lockFile]
    }

    :log info ($scriptName . ": SUCCESS at " . [/system clock get time] . ". Imported " . $importedIn . " IN / " . $importedOut . " OUT, purged " . $purgedIn . " IN / " . $purgedOut . " OUT, delta " . $deltaIn . " IN / " . $deltaOut . " OUT.")

} on-error={

    :set failDate [/system clock get date]
    :set failTime [/system clock get time]
    :set failTs ($failDate . " " . $failTime)

    :if ($errMsg = "") do={
        :set errMsg "Unknown error"
    }

    :if ([:len [/file find where name=$lockFile]] > 0) do={
        /file remove [find where name=$lockFile]
    }

    :log error ($scriptName . ": FAILED at " . $failTs . " | " . $errMsg)
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


### **High-Performance Raw Rule (for Large Lists)**

These RAW rules drop unwanted traffic before connection tracking. This reduces processing overhead compared with filtering the same traffic later in the firewall pipeline.

This is the most efficient method. This rule runs before connection tracking, which is highly efficient and saves CPU cycles on your router.
Add the firewall rule to your raw table to drop all incoming traffic from sources in your new address list. 
The first rule drops inbound traffic from known malicious source IPs on the WAN side.  
The second rule blocks LAN devices from connecting to known malicious destination IPs.

```routeros
/ip firewall raw

add action=drop chain=prerouting in-interface-list=WAN src-address-list=davidian-sk-blocklist_a comment="RAW-SEC: Drop known malicious WAN source IPs early"
add action=drop chain=prerouting dst-address-list=davidian-sk-blocklist-out_a dst-address=!224.0.0.0/4 dst-address-type=!broadcast src-address-list=!DNS-Servers comment="RAW-SEC: Drop outbound traffic to malicious blocklist"
```
