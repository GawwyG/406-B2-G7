#!/bin/bash
# Removes the port mirror set up by mirror_enable.sh, restoring normal
# switch behavior (h2 no longer sees h1's traffic).

set -euo pipefail

SWITCH=s1

sudo ovs-vsctl clear Bridge "$SWITCH" mirrors
sudo ovs-vsctl --if-exists destroy Mirror attacker-mirror

echo "Mirroring removed from ${SWITCH}"
