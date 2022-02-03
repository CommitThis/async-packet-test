import pytest

from scapy.all import Ether, Dot1Q, TCP, IP, sendp

from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import saw_vlan_tag

iface = 'lo'
context = make_pytest_context()
test_packet = Ether() / Dot1Q(vlan=102) / IP() / TCP()

def test_saw_vlan_102(context):
    result = context.expect(iface, saw_vlan_tag(102))
    sendp(test_packet, iface=iface)
    assert result

# You could use the `did_not_see_vlan_tag` predicate, however, this demonstrates
# a negated assertion. It also demonstrates the usage of a timeout. Otherwise
# the test would be sat waiting for a packet it will never see (until the
# default timeout is reached)
def test_did_not_see_vlan_103(context):
    result = context.expect(iface, saw_vlan_tag(103), timeout=0.5)
    sendp(test_packet, iface=iface)
    assert not result