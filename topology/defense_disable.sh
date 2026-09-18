#!/bin/bash
# Remove the IP Source Guard rule installed by defense_enable.sh,
# restoring the "before defense" (vulnerable) state for the demo.

set -euo pipefail

SWITCH=s1
ATTACKER_IFACE=s1-eth2  # switch-side end of the link to h2
SERVER_IP=10.0.2.10

PORT=$(sudo ovs-vsctl get Interface "$ATTACKER_IFACE" ofport)

sudo ovs-ofctl del-flows "$SWITCH" "in_port=${PORT},ip,nw_src=${SERVER_IP}"

echo "IP Source Guard disabled on ${SWITCH} port ${PORT} (${ATTACKER_IFACE})"
sudo ovs-ofctl dump-flows "$SWITCH"
