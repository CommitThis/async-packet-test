#! /usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    python3 -m venv .venv
    source .venv/bin/activate

    pip install .

    sudo $0
else

    modprobe -v dummy
    ip link add dummy0 type dummy
    sudo systemd-resolve --set-mdns=no --interface=dummy0
    ip link set dummy0 address 00:00:00:11:11:11
    ip link set dummy0 up
    ip addr add 192.168.1.150/24 dev dummy0

    .venv/bin/python -m pytest .

    ip link del dummy0 type dummy

fi