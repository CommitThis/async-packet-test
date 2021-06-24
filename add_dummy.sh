#! /usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    sudo $0
    exit
fi

modprobe -v dummy
ip link add dummy0 type dummy
ip link set dummy0 address 00:00:00:11:11:11
ip link set dummy0 up
ip addr add 192.168.1.150/24 dev dummy0