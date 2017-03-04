#!/bin/bash
ip add flush dev eth0
ip add flush dev eth1
brctl addbr br0
brctl addif br0 eth0 eth1
ip link set dev br0 up
dhclient br0

