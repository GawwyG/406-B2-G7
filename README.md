# 406-B2-G7 — TCP Reset Attack on Video Streaming

CSE406 (Computer Networks Security) project — assigned tool **#15: TCP
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
