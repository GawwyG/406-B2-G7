#!/usr/bin/env python3
"""
Step 1 of the attacker: just prove we can see h1's traffic.

Run on h2 (attacker), with mirror_enable.sh already applied on s1 and a
stream in progress between h1 and h3 (see streaming/README.md).

Captures only client (h1) -> server (h3) segments -- i.e. h1's HTTP
request and its ongoing ACKs while downloading. Per the design report,
the ACK field of these packets equals the server's next-expected
sequence number (h1's RCV.NXT for the server's byte stream), which is
everything the attacker needs later to forge a valid RST "from the
server". This script does not craft or send any packets yet -- it only
observes.
"""

from scapy.all import sniff, TCP, IP

# h2's dedicated monitor interface -- the OVS mirror's output-port (see
# NOTES_SNIFFING.md). Deliberately NOT h2-eth0: mirroring onto h2's
# primary, actively-transmitting interface broke its own outgoing
# traffic entirely, confirmed empirically while debugging attacker.py.
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
