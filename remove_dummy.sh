#! /usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    sudo $0
    exit
fi

ip link del dummy0 type dummy