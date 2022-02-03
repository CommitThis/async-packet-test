import pytest

from scapy.all import Ether, Dot1Q, TCP, IP
from scapy.all import sendp, get_if_hwaddr

from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import saw_vlan_tag
from async_packet_test.predicates import Predicate

iface = 'lo'
src_mac = get_if_hwaddr(iface)
dst_mac = 'ff:ff:ff:ff:ff:ff'
context = make_pytest_context()

test_packet = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=102) / \
	IP(src='221.221.221.221', dst='17.17.17.17') / TCP(sport=3456, dport=43)

class saw_ip_address(Predicate):
    def __init__(self, address):
        self._address = address
    
    def stop_condition(self, pkt):
        return pkt.haslayer(IP) and \
            (pkt[IP].src == self._address or pkt[IP].dst == self._address)

    def on_finish(self, timed_out):
        return not timed_out


def test_saw_vlan_102(context):
    result = context.expect(iface, saw_vlan_tag(102))
    sendp(test_packet, iface=iface)
    assert result

def test_did_not_see_vlan_103(context):
    result = context.expect(iface, saw_vlan_tag(103), timeout=0.5)
    sendp(test_packet, iface=iface)
    assert not result

def test_saw_expected_ip(context):
    result = context.expect(iface, saw_ip_address('17.17.17.17'))
    sendp(test_packet, iface=iface)
    assert result

def test_did_not_see_unexpected_ip(context):
    result = context.expect(iface, saw_ip_address('42.42.42.42'), timeout=0.5)
    sendp(test_packet, iface=iface)
    assert not result



