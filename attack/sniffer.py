#!/usr/bin/env python3
"""
Sanity check: just prove h2 can see h1's traffic. Run with
mirror_enable.sh already applied and a stream active between h1 and h3.

Only sniffs client -> server segments. Their ACK field is the server's
next-expected sequence number -- exactly what attacker.py needs to
forge a valid RST later. Doesn't send anything, just observes.
"""

from scapy.all import sniff, TCP, IP

# h2's monitor interface, not its primary one -- mirroring onto the
# primary broke its own outgoing traffic.
IFACE = "h2-eth1"
CLIENT_IP = "10.0.1.10"
SERVER_IP = "10.0.2.10"
SERVER_PORT = 8000

BPF_FILTER = f"tcp and src host {CLIENT_IP} and dst host {SERVER_IP} and dst port {SERVER_PORT}"


def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    ip, tcp = pkt[IP], pkt[TCP]
    payload_len = len(tcp.payload)
    print(
        f"[sniff] {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} "
        f"flags={tcp.flags!s:5} seq={tcp.seq:<12} ack={tcp.ack:<12} len={payload_len}"
    )


if __name__ == "__main__":
    print(f"[sniffer] listening on {IFACE}, filter: '{BPF_FILTER}'")
    print("[sniffer] start/continue the h1<->h3 stream now if it isn't already running")
    sniff(iface=IFACE, filter=BPF_FILTER, prn=handle, store=False, promisc=True)
