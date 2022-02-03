import pytest
import time

from scapy.all import Ether, IP, ICMP, sendp, Dot1Q, ARP
from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import Predicate


class saw_protocol(Predicate):
    def __init__(self, proto):
        self._proto = proto

    def stop_condition(self, packet):
        return packet.haslayer(self._proto)

    def on_finish(self, timed_out):
        return not timed_out


packet = Ether() / IP() / ICMP()

context = make_pytest_context()

def test_saw_icmp_packet(context):
    result = context.expect('lo', saw_protocol(ICMP))
    sendp(packet, iface='lo')
    result.assert_true()


def test_did_not_see_vlan(context):
    result = context.expect('lo', saw_protocol(Dot1Q))
    sendp(packet, iface='lo')
    result.assert_false()


def test_saw_ICMP_naked_assert(context):
    result = context.expect('lo', saw_protocol(ICMP))
    sendp(packet, iface='lo')
    assert result


def test_did_not_see_ARP_naked_assert(context):
    result = context.expect('lo', saw_protocol(ARP))
    sendp(packet, iface='lo')
    assert not result