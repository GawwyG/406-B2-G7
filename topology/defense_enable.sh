#!/bin/bash
# Switch-side IP Source Guard on s1: real switches bind each port to the
# IP/MAC learned via DHCP snooping and drop ingress frames that don't
# match. We approximate it with one OVS flow: any frame entering on
# h2's port claiming to be the server (10.0.2.10, the forged RST's
# spoofed src) gets dropped before it can reach h1.
#
# Run with topo.py's network still up:
#   ./defense_enable.sh

set -euo pipefail

# Switch-side (OVS port) name, not host-side -- check with
# `sudo ovs-vsctl list-ports s1` if this ever drifts.
SWITCH=s1
ATTACKER_IFACE=s1-eth2  # switch-side end of the link to h2
SERVER_IP=10.0.2.10
PRIORITY=100

PORT=$(sudo ovs-vsctl get Interface "$ATTACKER_IFACE" ofport)

sudo ovs-ofctl add-flow "$SWITCH" \
  "priority=${PRIORITY},in_port=${PORT},ip,nw_src=${SERVER_IP},actions=drop"

echo "IP Source Guard enabled: ${SWITCH} port ${PORT} (${ATTACKER_IFACE}) now drops frames claiming src=${SERVER_IP}"
sudo ovs-ofctl dump-flows "$SWITCH"
