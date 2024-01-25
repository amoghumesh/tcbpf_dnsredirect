#!/bin/bash
tc qdisc del dev lo clsact
tc qdisc del dev eth0 clsact
