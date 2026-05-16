#!/bin/bash

# Run this as sudo, after running:
# cargo run -- run tunnels.yaml
# cargo run -- run test/tunnels2.yaml -P 4223

set -v

ip netns delete ns1
ip netns delete ns2

ip netns add ns1
ip netns add ns2

ip link add wg1 type wireguard
ip link add wg2 type wireguard

wg setconf wg1 test/wg1.conf
wg setconf wg2 test/wg2.conf

ip link set wg1 netns ns1
ip link set wg2 netns ns2

ip -n ns1 addr add 10.0.0.1/24 dev wg1
ip -n ns2 addr add 10.0.0.2/24 dev wg2

ip -n ns1 link set wg1 up
ip -n ns2 link set wg2 up

ip -n ns1 route add 10.0.0.2/24 via 10.0.0.1 dev wg1
ip -n ns2 route add 10.0.0.1/24 via 10.0.0.2 dev wg2

ip netns exec ns1 wg show
ip netns exec ns1 ping 10.0.0.2
