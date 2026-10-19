#!/usr/bin/env bash
# TC4 hardware-grade network adversary: tc/netem 50% loss + 500ms spikes +
# partition windows on the rig's uplink while agents run.
set -euo pipefail
IFACE="${IFACE:-eth0}"
ACTION="${1:-apply}"   # apply | partition | clear
case "$ACTION" in
  apply)
    tc qdisc replace dev "$IFACE" root netem loss 50% delay 500ms 100ms distribution normal ;;
  partition)
    tc qdisc replace dev "$IFACE" root netem loss 100% ; sleep 15; "$0" apply ;;
  clear)
    tc qdisc del dev "$IFACE" root 2>/dev/null || true ;;
  *) echo "usage: packet_storm.sh [apply|partition|clear]"; exit 2 ;;
esac
echo "[netem] $ACTION applied on $IFACE"
