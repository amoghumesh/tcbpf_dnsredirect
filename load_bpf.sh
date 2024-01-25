#!/bin/bash
make
tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf direct-action obj dns_redirect.o sec tc_loopback
tc filter show dev lo ingress
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf direct-action obj dns_redirect.o sec tc_eth0
tc filter show dev eth0 ingress
