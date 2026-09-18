#!/bin/bash
# Enable a switch-side IP Source Guard rule on s1 (the LAN switch).
#
# Real switches implement IP Source Guard by binding each port to the
# IP/MAC learned via DHCP snooping, then dropping any ingress frame on
# that port whose source IP doesn't match the binding. We approximate
# the same effect with an OVS flow rule: h2 (attacker) is only ever
# allowed to send frames with src IP = its own address (10.0.1.20).
# Any frame entering on h2's port claiming to be the server
# (10.0.2.10, used by the forged RST) is dropped before it can reach h1.
#
# Run this from inside the Mininet CLI's underlying shell (or a second
# WSL terminal) while topo.py's network is still up:
#   ./defense_enable.sh

set -euo pipefail

# NOTE: this is the switch-side (OVS port) name, not the host-side name
# -- OVS only knows about its own ports. Verify with:
#   sudo ovs-vsctl list-ports s1
SWITCH=s1
ATTACKER_IFACE=s1-eth2  # switch-side end of the link to h2
SERVER_IP=10.0.2.10
PRIORITY=100

PORT=$(sudo ovs-vsctl get Interface "$ATTACKER_IFACE" ofport)

sudo ovs-ofctl add-flow "$SWITCH" \
  "priority=${PRIORITY},in_port=${PORT},ip,nw_src=${SERVER_IP},actions=drop"

echo "IP Source Guard enabled: ${SWITCH} port ${PORT} (${ATTACKER_IFACE}) now drops frames claiming src=${SERVER_IP}"
sudo ovs-ofctl dump-flows "$SWITCH"
