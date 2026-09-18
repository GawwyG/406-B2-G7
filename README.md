# 406-B2-G7 — TCP Reset Attack on Video Streaming

CSE406 (CSE406: Cyber Security Sessional) project — assigned tool **#15: TCP
reset attack on video streaming**. Roll 2105094 & 2105104, Section B2,
Group 7.

## What this is

An on-path attacker, sharing a switched LAN with a video-streaming
client, forges a TCP `RST` segment that appears to originate from the
legitimate streaming server. The forged RST kills the client's
connection immediately, interrupting playback — without guessing any
sequence number, by reading the exact value the client itself reveals
in its own outgoing traffic.

## Plan

1. **Topology** — Mininet + Open vSwitch: client and attacker on one LAN
   switch, server behind a router on a separate, bandwidth/delay-shaped
   WAN link.
2. **Streaming** — an HTTP/1.1 server with Range-request support, and a
   synthetic test video, so there's a real, live TCP connection to
   attack.
3. **Attacker visibility** — since a switched LAN doesn't hand the
   attacker the client's traffic for free, emulate the data-plane result
   of an ARP-spoof precondition (ARP spoofing itself is a separately
   assigned tool) with a switch port mirror.
4. **The attack** — sniff the client's outgoing ACKs and fire a forged
   RST, spoofed as the server, using the sniffed value as the exact
   sequence number.
5. **Defense** — a switch-side countermeasure that drops the forged
   packets before they reach the client (bonus marks).
6. **Evaluation** — measured success rate, before/after the defense, to
   back up the final report's claims with real numbers rather than a
   single anecdotal demo run.

## Design report summary

The full design report (submitted separately) covers this in detail;
this is the short version.

**Threat model.** Attacker is on-path, on the same subnet/switch as the
client. ARP spoofing (a separately assigned tool) is assumed already
achieved — out of scope here. The attacker does not suppress or delay
legitimate traffic; only the RST-specific mechanics are being
demonstrated. Target is the TCP layer, independent of HTTP version
(HTTP/3/QUIC is out of scope — no TCP 4-tuple/sequence to spoof).

**The attack.** Spoof the server, send a forged `RST` to the client.
This kills the client's socket immediately (a visible player error),
which is the strongest demo outcome compared to resetting the
server-side socket instead.

**Why the topology favors the attacker.** Client and attacker share a
switch — one hop. The real server is remote, reached only via a router
— multiple hops, plus WAN latency. A forged packet from attacker to
client never touches the router at all, giving the attacker a
structural head start in the race against the real server's next
segment.

**The key trick: learning the sequence number without guessing.** A
client's outgoing TCP `ACK` field already equals the server's
next-expected sequence number (its `RCV.NXT`). So the attacker doesn't
need to see a server→client packet at all — sniffing a client→server
packet (which travels the attacker's own short path first) is enough to
read off the exact value needed, and to react before that packet has
even reached the real server.

**The race.** Forged RST (attacker → client, one hop) races the real
next data segment (server → router → client, multi-hop, WAN-shaped).
Failure is clean, not messy: a late RST simply falls outside the
client's already-advanced receive window and is silently discarded — no
side effects, no signal. Since a stream carries many packets, and each
one is an independent, equally-valid attempt, firing on every sniffed
ACK rather than a single timed shot compounds the odds of success.

**Forged packet fields.**

| Layer | Field | Value |
|---|---|---|
| Ethernet | Src / Dst MAC | Attacker MAC / Client MAC |
| IP | Src IP | Server IP (spoofed) |
| IP | Dst IP | Client IP |
| TCP | Src port | Server's real listening port |
| TCP | Dst port | Client's ephemeral port (from the sniffed packet) |
| TCP | Sequence number | The sniffed client ACK value |
| TCP | Flags | `RST` only |
| TCP | Payload | none |

**Why RFC 5961 doesn't stop this.** Modern TCP stacks require an
*exact* sequence match to accept a RST immediately; an in-window but
inexact value only triggers a challenge ACK, and an out-of-window value
is silently discarded. Because the sequence number here is sniffed
directly off the wire rather than guessed, it's always an exact match —
so RFC 5961's headline protection, aimed at blind/guessing attackers,
does not apply to this attacker.

Full slide deck: `../406-Project/Design_Report_B2_G7.pdf`.

## Prerequisites (one-time setup)

Tested on **Ubuntu 22.04** (works the same under WSL2 on Windows, or a
native/VM install). Root (`sudo`) is needed for the Mininet/OVS/`tcpdump`
steps throughout.

Install everything via `apt` — **not** `pip`. Mininet hosts (and this
project's scripts) run as root, and a `pip install` without `sudo`
installs to your own user's site-packages, which root's Python can't
see (a real, previously-hit failure mode: `ModuleNotFoundError` for a
package that "is definitely installed").

```bash
sudo apt update
sudo apt install -y \
  mininet openvswitch-switch openvswitch-common \
  python3-flask python3-scapy \
  ffmpeg fonts-dejavu-core \
  xterm curl tcpdump \
  texlive-latex-extra texlive-pictures texlive-latex-recommended
```

- `mininet`, `openvswitch-*` — the emulated topology (Section: Topology).
- `python3-flask` — the streaming server; `python3-scapy` — used only by
  `attack/sniffer.py` (the passive visibility-check demo script; the
  actual attack tool, `attacker.py`, uses no packet-crafting library at
  all, only raw sockets and hand-rolled `struct` code, per the project's
  "craft your own frame" requirement).
- `ffmpeg` + `fonts-dejavu-core` — generating the synthetic test video
  (`streaming/generate_video.sh` burns in a running timestamp using a
  DejaVu Sans Mono font file).
- `xterm`, `curl`, `tcpdump` — per-host terminals, the scripted-trial
  client, and the packet captures `experiments/diagnose_race.py` uses.
- `texlive-*` — compiling `report/final_report.tex` (plain `article`
  class with `tikz`, `booktabs`, `listings`, `xcolor`, `hyperref`,
  `caption`/`subcaption`, `graphicx`, `amsmath`/`amssymb`, `enumitem`,
  `parskip` — all standard packages covered by the three `texlive-*`
  packages above; if a package still can't be found, `texlive-full` is
  the always-safe fallback, just much larger).

`streaming/video.mp4` is already included in this repo (checked in), so
`generate_video.sh` only needs to be re-run if you want to regenerate it.

## How to run

Everything below assumes the prerequisites above are already installed.

### 1. Bring up the topology

```bash
cd topology
sudo python3 topo.py
```
Lands at a `mininet>` prompt. Sanity check: `pingall` should show `0%
dropped`. Open a terminal per host: `xterm h1 h2 h3` (these inherit
`topology/` as their working directory, since that's where `topo.py`
was launched from — the paths below account for that).

### 2. Start the stream

In **h3**'s terminal:
```bash
cd ../streaming
python3 server.py
```
(If `streaming/video.mp4` doesn't exist yet: `./generate_video.sh` first.)

In **h1**'s terminal:
```bash
ffplay http://10.0.2.10:8000/video.mp4
```

### 3. Give the attacker visibility

From a **normal terminal** at the repo root (not inside a Mininet
xterm), with the topology still up:
```bash
cd attack
./mirror_enable.sh
```
This must be re-run every time the topology is restarted.

### 4. Run the attack

In **h2**'s terminal:
```bash
python3 ../attack/attacker.py
```
Watch it fire forged RSTs and watch `h1`'s playback die mid-stream.

To just confirm visibility without attacking: `python3 ../attack/sniffer.py`.

### 5. Defense on/off

From a normal terminal at the repo root, topology still up:
```bash
cd topology
./defense_enable.sh    # turn the countermeasure on
./defense_disable.sh   # turn it back off
```
Re-run the attack with the defense on to confirm it now fails (full
download survives). `sudo ovs-ofctl dump-flows s1` shows the drop rule's
packet counter climbing as the attacker fires.

### 6. Automated experiments

These build and tear down their own topology — don't run them while
`topo.py` is already up separately. Run from the repo root:

```bash
cd experiments
sudo python3 run_experiments.py --trials 20
```
Runs both defense-off and defense-on scenarios, writes `results.csv`,
prints a success-rate summary. Useful flags: `--wan-bw`, `--scenarios
off|on|both`, `--out <path>` (see `--help` for the rest).

For a packet-level look at one specific trial (why a shot won or lost):
```bash
sudo python3 diagnose_race.py --trials 6
```

The `results*.csv` files and `logs/` directory in this folder are the
actual data behind the final report's tables.

### 7. Compile the final report

```bash
cd report
pdflatex final_report.tex
pdflatex final_report.tex   # twice, for the table of contents
```
A plain `article`-class paper (see the Prerequisites section above for
the exact `texlive-*` packages needed). The topology diagram is inline
TikZ, but the evidence figures are real screenshots in `report/Images/`
— keep that folder alongside the `.tex` file. Search the `.tex` for
`\fillin{...}` for anything still needing a name, date, or per-member
contribution description filled in by hand.
