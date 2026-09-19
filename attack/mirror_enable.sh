#!/bin/bash
# Emulates the data-plane result of a successful ARP-spoof MITM: mirrors
# h1's switch port onto h2's (attacker's) port, using OVS port mirroring.
#
# Run with the topology already up (topo.py):
#   ./mirror_enable.sh

set -euo pipefail

# Switch-side (OVS port) names, not host-side -- check with
# `sudo ovs-vsctl list-ports s1` if these ever drift.
#
# ATTACKER_IFACE is h2's second, dedicated interface (h2-eth1 / s1-eth4),
# not its primary one -- mirroring onto the primary broke h2's own
# outgoing traffic (a port can't be both two-way and a mirror output at once).
SWITCH=s1
VICTIM_IFACE=s1-eth1    # switch-side end of the link to h1
ATTACKER_IFACE=s1-eth4  # switch-side end of h2's monitor interface (h2-eth1)

# select-*-port/output-port want Port table UUIDs, not ofport integers,
# hence the "--id=@ref get Port <name>" idiom (see `man ovs-vsctl`).
sudo ovs-vsctl \
    -- --id=@vp get Port "$VICTIM_IFACE" \
    -- --id=@ap get Port "$ATTACKER_IFACE" \
    -- --id=@m create Mirror name=attacker-mirror \
        select-dst-port=@vp select-src-port=@vp output-port=@ap \
    -- set Bridge "$SWITCH" mirrors=@m

echo "Mirroring ${SWITCH} port ${VICTIM_IFACE} -> port ${ATTACKER_IFACE}"
sudo ovs-vsctl list Mirror attacker-mirror
