# MikroTik Blocklist

Two self-updating firewall address lists for **MikroTik RouterOS**, rebuilt four times a day from public threat-intelligence feeds and published here as ready-to-import `.rsc` files:

- an **inbound list**: addresses that should never reach your WAN interface (known attackers, hijacked networks, compromised hosts);
- an **outbound list**: destinations your network and your router should never talk to (botnet command servers, compromised hosts).

The lists are compressed into compact CIDR ranges, so even a small router handles them easily, and each list is published twice (`_a` and `_b`) so you can swap to a fresh copy without ever having an empty list.

> **Read [Staying safe](#staying-safe) before you switch the drop rules on.** Any blocklist can block something you need.

## Choose what you need

| I want to... | Go to |
|---|---|
| just **download the lists** and use them my own way | [Download the lists](#download-the-lists) |
| only **set up the firewall rules** (and load the lists myself) | [Firewall rules only](#firewall-rules-only) |
| have it **fully automatic** on my MikroTik (recommended) | [Quick start](#quick-start) |
| one list without rotation, as simple as possible | [Simple mode](#simple-mode-one-list-no-rotation) |

## Contents

- [Published files](#published-files)
- [Quick start](#quick-start)
- [Firewall rules only](#firewall-rules-only)
- [Download the lists](#download-the-lists)
- [Staying safe](#staying-safe)
- [Simple mode: one list, no rotation](#simple-mode-one-list-no-rotation)
- [How the lists are built](#how-the-lists-are-built)
- [Using the lists on other firewalls](#using-the-lists-on-other-firewalls)
- [Troubleshooting](#troubleshooting)
- [Undo / uninstall](#undo--uninstall)
- [Disclaimer](#disclaimer)

## Published files

| File | Content | Address-list name inside the file |
|---|---|---|
| `blocklist_a.rsc`, `blocklist_b.rsc` | inbound list, two identical copies for rotation | `davidian-sk-blocklist_a` / `davidian-sk-blocklist_b` |
| `blocklist_out_a.rsc`, `blocklist_out_b.rsc` | outbound list, two identical copies for rotation | `davidian-sk-blocklist-out_a` / `davidian-sk-blocklist-out_b` |
| `blocklist.rsc` | inbound list for [simple mode](#simple-mode-one-list-no-rotation) | `davidian-sk-active-blocklist` |
| `blocklist_out.rsc` | outbound list for simple mode | `davidian-sk-blocklist-out` |
| `aggregated_cidr_ranges.txt`, `aggregated_cidr_ranges_out.txt` | the same lists as plain text, one CIDR per line | - |
| `aggregated_ips.txt`, `aggregated_ips_out.txt` | the individual addresses before compression | - |
| `build_stats.txt`, `build_stats_out.txt` | numbers from the last build (sources processed, ranges created, ...) | - |
| `too_broad_cidrs.txt`, `too_broad_cidrs_out.txt` | very broad ranges that were split into smaller pieces | - |

Roughly 14,000 inbound ranges (about 0.9 MB) and a few hundred to a few thousand outbound ranges. All files are rebuilt four times a day (shortly before 00:00, 06:00, 12:00 and 18:00 Central European Time); there is no point in fetching them more often than that.

## Quick start

You need RouterOS 7, a firewall with a `WAN` interface list, and about 2 MB of free storage for the temporary download. About 15 minutes.

### 1. Create the address lists

The rotation script needs both copies of each list to exist. Placeholder entries (from the documentation range `192.0.2.0/24`, which is never routed) are replaced on the first run:

```routeros
/ip firewall address-list
add list=davidian-sk-blocklist_a     address=192.0.2.1 comment="placeholder"
add list=davidian-sk-blocklist_b     address=192.0.2.2 comment="placeholder"
add list=davidian-sk-blocklist-out_a address=192.0.2.3 comment="placeholder"
add list=davidian-sk-blocklist-out_b address=192.0.2.4 comment="placeholder"
```

### 2. Add the three RAW firewall rules

(Only want the rules, without the rotation? See [Firewall rules only](#firewall-rules-only).)

RAW rules run before connection tracking, so dropped packets cost almost no CPU. **The comments must stay exactly as written**: the rotation script finds the rules by their comments.

```routeros
/ip firewall raw
add chain=prerouting action=drop in-interface-list=WAN src-address-list=davidian-sk-blocklist_a \
    comment="RAW-SEC: Drop known malicious WAN source IPs early"
add chain=prerouting action=drop dst-address-list=davidian-sk-blocklist-out_a \
    dst-address=!224.0.0.0/4 dst-address-type=!broadcast \
    comment="RAW-SEC: Drop outbound traffic to malicious blocklist"
add chain=output action=drop dst-address-list=davidian-sk-blocklist-out_a \
    comment="RAW-SEC: Drop router-originated traffic to malicious destinations"
```

- Rule 1 drops packets arriving on the WAN from listed addresses.
- Rule 2 drops traffic from your LAN towards listed destinations.
- Rule 3 does the same for traffic the router itself creates.

**Recommended for the first day:** change `action=drop` to `action=passthrough log=yes log-prefix=BLOCKLIST` on all three rules. Nothing is blocked, but the counters and the log show what *would* have been dropped. Switch to `drop` once you are happy (see [Staying safe](#staying-safe)).

### 3. Install the rotation script

In WinBox or WebFig: **System > Scripts > Add**, name it `Blocklist-Rotate`, tick the policies **read, write, policy, test, ftp**, and paste the script below. It was checked to compile on RouterOS 7.

What it does, in seven stages: take a lock (it expires by itself after 15 minutes) -> find which copy is active -> download the other copy of both lists -> clear and import the inactive lists -> point the three RAW rules at the fresh lists -> verify (and roll back on any mismatch) -> purge the old lists and temporary files. If anything fails, the old lists stay active.

```routeros
# ==========================================
# BLOCKLIST-ROTATE
# 7-stage, low-noise, verified A/B rotation
# Swaps three RAW rules (inbound, outbound, router-originated)
# ==========================================

:local scriptName "BLOCKLIST-ROTATE"
:local lockList "blocklist_rotate_lock"
:local baseUrl "https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/"
# Folder on the router storage for the downloaded files. Use e.g. "usb1/blocklist/" for external storage.
:local dir "blocklist/"

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
:local ruleRouter

:local verifyIn ""
:local verifyOut ""
:local verifyRouter ""

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

:if ([:len [/ip firewall address-list find list=$lockList]] > 0) do={
    :log warning ($scriptName . ": Lock exists, aborting.")
    :error "Locked"
}

/ip firewall address-list add list=$lockList address="127.0.0.1" timeout=15m

:do {

    # ==========================================
    # Stage 2/7 - Detect current active targets
    # ==========================================
    :log info ($scriptName . ": [2/7] Detecting active RAW targets.")

    :set ruleIn [/ip firewall raw find where comment~"WAN source IPs early"]
    :set ruleOut [/ip firewall raw find where comment~"outbound traffic to malicious"]
    :set ruleRouter [/ip firewall raw find where comment~"Drop router-originated traffic to malicious destinations"]

    :if ([:len $ruleIn] = 0) do={ :set errMsg "Inbound RAW rule not found"; :error $errMsg }
    :if ([:len $ruleOut] = 0) do={ :set errMsg "Outbound RAW rule not found"; :error $errMsg }
    :if ([:len $ruleRouter] = 0) do={ :set errMsg "Router-Protection RAW rule not found"; :error $errMsg }

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

    :set fetchIn [/tool fetch url=($baseUrl . $fileIn) dst-path=($dir . $fileIn) as-value]
    :set fetchOut [/tool fetch url=($baseUrl . $fileOut) dst-path=($dir . $fileOut) as-value]

    :if (($fetchIn->"status") != "finished") do={ :set errMsg ("Fetch failed for inbound file " . $fileIn); :error $errMsg }
    :if (($fetchOut->"status") != "finished") do={ :set errMsg ("Fetch failed for outbound file " . $fileOut); :error $errMsg }

    # ==========================================
    # Stage 4/7 - Import into staging lists
    # ==========================================
    :log info ($scriptName . ": [4/7] Purging staging lists and importing fresh entries.")

    /ip firewall address-list remove [find where list=$nextIn]
    /ip firewall address-list remove [find where list=$nextOut]

    /import file-name=($dir . $fileIn)
    /import file-name=($dir . $fileOut)

    :set importedIn [:len [/ip firewall address-list find where list=$nextIn]]
    :set importedOut [:len [/ip firewall address-list find where list=$nextOut]]


    :if ($importedIn = 0) do={ :set errMsg ("Inbound import empty: " . $nextIn); :error $errMsg }
    :if ($importedOut = 0) do={ :set errMsg ("Outbound import empty: " . $nextOut); :error $errMsg }

    # ==========================================
    # Stage 5/7 - Swap live RAW rules (Atomic)
    # ==========================================
    :log info ($scriptName . ": [5/7] Swapping RAW rules to next blocklists.")

    /ip firewall raw set $ruleIn src-address-list=$nextIn
    /ip firewall raw set $ruleOut dst-address-list=$nextOut
    /ip firewall raw set $ruleRouter dst-address-list=$nextOut

    :set verifyIn [/ip firewall raw get $ruleIn src-address-list]
    :set verifyOut [/ip firewall raw get $ruleOut dst-address-list]
    :set verifyRouter [/ip firewall raw get $ruleRouter dst-address-list]

    :if (($verifyIn != $nextIn) || ( $verifyOut != $nextOut) || ($verifyRouter != $nextOut)) do={
        :log error ($scriptName . ": Swap verification failed. Rolling back.")
        /ip firewall raw set $ruleIn src-address-list=$activeIn
        /ip firewall raw set $ruleOut dst-address-list=$activeOut
        /ip firewall raw set $ruleRouter dst-address-list=$activeOut
        :set errMsg "Swap verification failed"
        :error $errMsg
    }

    # ==========================================
    # Stage 6/7 - Cleanup old live lists and temp files
    # ==========================================
    :log info ($scriptName . ": [6/7] Cleaning old active lists and temporary files.")

    :set purgedIn [:len [/ip firewall address-list find where list=$activeIn]]
    :set purgedOut [:len [/ip firewall address-list find where list=$activeOut]]
    /ip firewall address-list remove [find where list=$activeIn]
    /ip firewall address-list remove [find where list=$activeOut]
    /file remove [find where name=($dir . $fileIn)]
    /file remove [find where name=($dir . $fileOut)]

    :set deltaIn ($importedIn - $purgedIn)
    :set deltaOut ($importedOut - $purgedOut)

    # ==========================================
    # Stage 7/7 - Unlock and finish
    # ==========================================
    :log info ($scriptName . ": [7/7] Cleaning lock and finishing.")

    :if ([:len [/ip firewall address-list find list=$lockList]] > 0) do={ /ip firewall address-list remove [find list=$lockList] }
    :log info ($scriptName . ": SUCCESS at " . [/system clock get time] . ". Delta IN: " . $deltaIn . " / OUT: " . $deltaOut)

} on-error={
    :if ([:len [/ip firewall address-list find list=$lockList]] > 0) do={ /ip firewall address-list remove [find list=$lockList] }
    :log error ($scriptName . ": FAILED | " . $errMsg)
}
```

Set `dir` at the top if you want the temporary files on other storage (for example `usb1/blocklist/`). If your RouterOS version does not create the folder by itself, create it first with `/file add name=blocklist type=directory`.

### 4. Run it once and check

```routeros
/system script run Blocklist-Rotate
/log print where message~"BLOCKLIST-ROTATE"
/ip firewall address-list print count-only where list~"davidian-sk-blocklist"
/ip firewall raw print stats where comment~"RAW-SEC"
```

You should see `SUCCESS` with the number of imported entries. The first run takes a few minutes on a small router. The packet counters of the RAW rules start to grow as traffic is matched.

### 5. Schedule it

Every 6 hours is the natural rhythm: the lists are rebuilt four times a day, so rotating more often only downloads the same data again:

```routeros
/system scheduler
add name=Blocklist-Rotate interval=6h start-time=00:02:00 \
    on-event="/system script run Blocklist-Rotate" \
    policy=read,write,policy,test,ftp \
    comment="Rotate to the fresh blocklists"
```

## Firewall rules only

Use this if you load the address lists yourself (by hand, with your own script, or from another tool) or if you want to prepare the firewall first. Empty or missing lists are harmless: the rules simply match nothing until a list is loaded.

### Recommended: RAW rules

```routeros
/ip firewall raw
add chain=prerouting action=drop in-interface-list=WAN src-address-list=davidian-sk-active-blocklist \
    comment="RAW-SEC: Drop known malicious WAN source IPs early"
add chain=prerouting action=drop dst-address-list=davidian-sk-blocklist-out \
    dst-address=!224.0.0.0/4 dst-address-type=!broadcast \
    comment="RAW-SEC: Drop outbound traffic to malicious blocklist"
add chain=output action=drop dst-address-list=davidian-sk-blocklist-out \
    comment="RAW-SEC: Drop router-originated traffic to malicious destinations"
```

| Rule | What it stops |
|---|---|
| 1 | packets arriving from the internet from listed addresses |
| 2 | traffic from your network towards listed destinations |
| 3 | traffic created by the router itself towards listed destinations |

These use the list names of the [single files](#published-files) (`blocklist.rsc` and `blocklist_out.rsc`). RAW rules run before connection tracking, so dropped packets cost almost no CPU. If you switch to the [rotation setup](#quick-start) later, the rotation script takes over these same rules and repoints them by itself; only keep the comments unchanged.

**Try it without blocking anything first:** change `action=drop` to `action=passthrough log=yes log-prefix=BLOCKLIST`. The rule counters and the log then show what would have been dropped. Change it back to `drop` when you are happy.

### Alternative: filter rules

If you do not use the RAW table, the same protection works in the filter table. Place these **above** any fasttrack and "accept established" rules (the `place-before=0` puts them at the top):

```routeros
/ip firewall filter
add chain=input   action=drop in-interface-list=WAN  src-address-list=davidian-sk-active-blocklist place-before=0 \
    comment="BLOCKLIST: drop known malicious sources reaching the router"
add chain=forward action=drop in-interface-list=WAN  src-address-list=davidian-sk-active-blocklist place-before=0 \
    comment="BLOCKLIST: drop known malicious sources reaching the network"
add chain=forward action=drop out-interface-list=WAN dst-address-list=davidian-sk-blocklist-out    place-before=0 \
    comment="BLOCKLIST: drop traffic to known malicious destinations"
add chain=output  action=drop dst-address-list=davidian-sk-blocklist-out                            place-before=0 \
    comment="BLOCKLIST: drop router traffic to known malicious destinations"
```

This costs more CPU than RAW because the packets are tracked first, but it works on every setup. Whichever you choose, do not forget the [exemptions](#staying-safe) for the services you depend on.

## Download the lists

Every list is a normal file in this repository, so you can fetch it with any tool. The base address is:

```text
https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/<file>
```

| What | Direct links |
|---|---|
| Inbound list for RouterOS | [`blocklist.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist.rsc) (single list), [`blocklist_a.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_a.rsc) / [`blocklist_b.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_b.rsc) (rotation copies) |
| Outbound list for RouterOS | [`blocklist_out.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_out.rsc) (single list), [`blocklist_out_a.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_out_a.rsc) / [`blocklist_out_b.rsc`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_out_b.rsc) (rotation copies) |
| Plain text, one CIDR per line (any firewall) | [`aggregated_cidr_ranges.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_cidr_ranges.txt) (inbound), [`aggregated_cidr_ranges_out.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_cidr_ranges_out.txt) (outbound) |
| Plain text, individual addresses | [`aggregated_ips.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_ips.txt), [`aggregated_ips_out.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_ips_out.txt) |
| Statistics of the last build | [`build_stats.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/build_stats.txt), [`build_stats_out.txt`](https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/build_stats_out.txt) |

**On a MikroTik** (download, replace the old entries, import):

```routeros
/tool fetch url="https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist.rsc" dst-path=blocklist.rsc
/tool fetch url="https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist_out.rsc" dst-path=blocklist_out.rsc

/ip firewall address-list remove [find where list="davidian-sk-active-blocklist"]
/ip firewall address-list remove [find where list="davidian-sk-blocklist-out"]
/import file-name=blocklist.rsc
/import file-name=blocklist_out.rsc

/file remove [find where name="blocklist.rsc" or name="blocklist_out.rsc"]
```

Check the result with `/ip firewall address-list print count-only where list="davidian-sk-active-blocklist"`. You should see thousands of entries for the inbound list. For continuous operation without a gap, use the [rotation setup](#quick-start) instead.

**On Linux or macOS:**

```sh
curl -fsSLO https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_cidr_ranges.txt
# or
wget https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_cidr_ranges.txt
```

**Good manners:**

- The files change four times a day. Downloading every 6 hours is plenty; please do not poll more often than that.
- GitHub caches raw files for a few minutes, so a file can be a little behind the newest commit.
- To see how fresh the lists are, look at the latest commit time (the commits are named `Auto-update: ...`) or at `build_stats.txt`.
- The repository history is squashed into a single commit about once a week to keep it small, so old commit links stop working. Always download from `main`, and use `git clone --depth 1` if you clone.

## Staying safe

Blocklists are a trade-off: they stop a lot of noise and some real attacks, and now and then they block an address you actually need (shared hosting, a cloud server that changed owner, a friend's network). A few habits keep this harmless:

**1. Never block what you depend on.** Put accept rules *before* the drop rules for your DNS servers, your VPN endpoints, and anything your setup needs to reach (including `raw.githubusercontent.com`, where this repository is downloaded from):

```routeros
/ip firewall address-list
add list=blocklist-allow address=1.1.1.1 comment="DNS resolver"
add list=blocklist-allow address=9.9.9.9 comment="DNS resolver"

/ip firewall raw
add chain=prerouting action=accept dst-address-list=blocklist-allow \
    comment="RAW-INF: Never block these destinations" \
    place-before=[find comment~"Drop outbound traffic to malicious"]
add chain=prerouting action=accept in-interface-list=WAN src-address-list=blocklist-allow \
    comment="RAW-INF: Never block these sources" \
    place-before=[find comment~"WAN source IPs early"]
```

If a server of yours must always reach a whole provider network (for example a tunnel to a CDN), scope the exemption to that device: `src-address=<device> dst-address-list=<provider list>`.

**2. Do not edit the lists by hand.** They are replaced on every rotation. Add exceptions to `blocklist-allow` instead.

**3. See what is being blocked.** Turn on logging for a while, read it, switch it off:

```routeros
/ip firewall raw set [find comment~"Drop outbound traffic to malicious"] log=yes log-prefix="BLOCKLIST-OUT"
/log print where message~"BLOCKLIST-OUT"
/ip firewall raw set [find comment~"Drop outbound traffic to malicious"] log=no
```

**4. Found a false positive?** Add the address to `blocklist-allow` right away and open an issue here with the address and the time. Include which direction (inbound or outbound) blocked it.

## Simple mode: one list, no rotation

The easiest setup, at the price of a short moment with an empty list while it reloads. Use `blocklist.rsc` (inbound) and/or `blocklist_out.rsc` (outbound):

```routeros
/tool fetch url="https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/blocklist.rsc" dst-path=blocklist.rsc
/ip firewall address-list remove [find where list="davidian-sk-active-blocklist"]
/import file-name=blocklist.rsc
/file remove blocklist.rsc

/ip firewall raw
add chain=prerouting action=drop in-interface-list=WAN src-address-list=davidian-sk-active-blocklist \
    comment="Drop known malicious WAN source IPs"
```

Repeat with `blocklist_out.rsc` and `dst-address-list=davidian-sk-blocklist-out` for the outbound list, and run the commands from a scheduler.

## How the lists are built

Four times a day a script on a server:

1. downloads the configured feeds (separate source lists for inbound and outbound);
2. extracts valid IPv4 addresses and ranges and discards everything else;
3. removes duplicates and merges neighbours into the fewest possible CIDR ranges;
4. splits any range broader than a `/16` into `/16` pieces (a single bad feed line can never block a huge part of the internet by accident);
5. runs sanity checks: a minimum number of ranges, and a refusal to publish a list that suddenly shrank by more than half (a broken feed must not empty your blocklist);
6. generates the RouterOS files and publishes them here only if everything passed.

**Public feeds in use:**

| Direction | Feed | What it contains |
|---|---|---|
| inbound, outbound | [Spamhaus DROP](https://www.spamhaus.org/drop/) | hijacked and criminal network blocks |
| inbound, outbound | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | active botnet command servers |
| inbound, outbound | [Emerging Threats compromised IPs](https://rules.emergingthreats.net/blockrules/) | hosts seen compromised or attacking |
| inbound | [DShield block list](https://www.dshield.org/block.txt) | the most active attacking networks |

The published lists can also include addresses from additional feeds curated by the maintainer. The inbound list is intentionally broader than the outbound list: attackers on the way in are not the same as servers your devices would connect to.

Every feed has its own terms of use. Please read them before you copy or reuse the data outside of this repository.

## Using the lists on other firewalls

`aggregated_cidr_ranges.txt` and `aggregated_cidr_ranges_out.txt` are plain text with one CIDR per line, so they work with anything that takes a list of networks. For example with `ipset` on Linux:

```sh
ipset create blocklist hash:net
curl -s https://raw.githubusercontent.com/davidian-sk/mikrotik-blocklist/main/aggregated_cidr_ranges.txt | while read n; do ipset add blocklist "$n" -exist; done
iptables -I INPUT -m set --match-set blocklist src -j DROP
```

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Log says `Locked` | A previous run is still going, or it died. The lock expires by itself after 15 minutes; to clear it now: `/ip firewall address-list remove [find list=blocklist_rotate_lock]` |
| `Inbound RAW rule not found` (or outbound / router) | A RAW rule comment was changed. Restore the exact comments from step 2. |
| `Fetch failed` | The router cannot reach `raw.githubusercontent.com`: check DNS, the router's clock and that no rule blocks it (see [Staying safe](#staying-safe)). |
| `import empty` | The download was empty or failed to import. The old lists stay active; check `/file print` in your `dir` folder and run again. |
| Drops stay at zero | Check the rule order (an earlier `accept` may match first) and that `in-interface-list=WAN` matches your WAN interface. |
| A site or service stopped working | See [Staying safe](#staying-safe): log the blocklist rules, find the address, add it to `blocklist-allow`. |

## Undo / uninstall

```routeros
/system scheduler remove [find name=Blocklist-Rotate]
/system script remove [find name=Blocklist-Rotate]
/ip firewall raw remove [find comment~"RAW-SEC: Drop"]
/ip firewall address-list remove [find where list~"davidian-sk"]
```

## Disclaimer

Provided as is, without any warranty. Blocking lists can block legitimate traffic, and no list catches everything. Test before you rely on it, keep your own exemptions, and use it at your own risk. The data comes from third-party feeds that are subject to their own terms.

