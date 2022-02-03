#! /usr/bin/env bash

function setup_dummy() {
    echo "Setting up dummy interface"
    modprobe -v dummy
    ip link add dummy0 type dummy
    sudo systemd-resolve --set-mdns=no --interface=dummy0
    ip link set dummy0 address 00:00:00:11:11:11
    ip link set dummy0 up
    ip addr add 192.168.1.150/24 dev dummy0
}

function teardown_dummy() {
    echo "Tearing down dummy interface"
    ip link del dummy0 type dummy
}

SETUP_DUMMY=$(declare -f setup_dummy)
TEARDOWN_DUMMY=$(declare -f teardown_dummy)

poetry install
sudo bash -c "$SETUP_DUMMY; setup_dummy"
sudo -E PYTHONDONTWRITEBYTECODE=1 $(which poetry) run pytest -p no:cacheprovider --cov=async_packet_test --cov-report html
sudo bash -c "$TEARDOWN_DUMMY; teardown_dummy"
sudo chown $USER:$USER htmlcov .coverage -R
