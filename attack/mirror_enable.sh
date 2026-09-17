#!/bin/bash
# Emulates the data-plane consequence of a successful ARP-spoof MITM:
# mirrors all traffic to/from h1's switch port onto h2's (attacker's)
# switch port on s1, using Open vSwitch's built-in port mirroring (SPAN).
# See NOTES_SNIFFING.md for why this is the right modeling choice.
#
# Run with the topology already up (topo.py):
#   ./mirror_enable.sh

set -euo pipefail

# NOTE: these are the switch-side (OVS port) names, not the host-side
# names -- OVS only knows about its own ports. Verify with:
#   sudo ovs-vsctl list-ports s1
#
# ATTACKER_IFACE points at h2's SECOND, dedicated interface (h2-eth1 /
# s1-eth4), not its primary one (s1-eth2). Mirroring onto h2's primary,
# actively-transmitting port broke h2's own outgoing traffic entirely
# (confirmed empirically -- see NOTES_SNIFFING.md) -- a port can't be
# both a normal two-way port and a mirror output-port at once here.
SWITCH=s1
VICTIM_IFACE=s1-eth1    # switch-side end of the link to h1
ATTACKER_IFACE=s1-eth4  # switch-side end of h2's dedicated monitor interface (h2-eth1)

# select-src-port/select-dst-port/output-port on the Mirror table are
# references to rows in the *Port* table (not raw ofport integers), so we
# resolve them with the "--id=@ref get Port <name>" idiom in one
# transaction, as documented in `man ovs-vsctl`.
sudo ovs-vsctl \
    -- --id=@vp get Port "$VICTIM_IFACE" \
    -- --id=@ap get Port "$ATTACKER_IFACE" \
    -- --id=@m create Mirror name=attacker-mirror \
        select-dst-port=@vp select-src-port=@vp output-port=@ap \
    -- set Bridge "$SWITCH" mirrors=@m

echo "Mirroring ${SWITCH} port ${VICTIM_IFACE} -> port ${ATTACKER_IFACE}"
sudo ovs-vsctl list Mirror attacker-mirror
