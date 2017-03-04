#!/bin/bash
ifconfig br0 down
ifconfig eth0 0.0.0.0 down
ifconfig eth1 0.0.0.0 down
brctl delif br0 eth0 eth1
brctl delbr br0
ifconfig eth0 up
ifconfig eth1 up
dhclient eth0
