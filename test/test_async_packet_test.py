import pytest
import time

from scapy.all import Ether, IP, TCP, Dot1Q, get_if_hwaddr, sendp, ICMP, ARP
from async_packet_test.context import make_pytest_context
from async_packet_test.predicates import Predicate
from async_packet_test.predicates import received_packet
from async_packet_test.predicates import timed_out
from async_packet_test.predicates import saw_src_mac
from async_packet_test.predicates import saw_dst_mac
from async_packet_test.predicates import did_not_see_src_mac
from async_packet_test.predicates import did_not_see_dst_mac
from async_packet_test.predicates import saw_vlan_tag
from async_packet_test.predicates import did_not_see_vlan
from async_packet_test.predicates import did_not_see_vlan_tag
from async_packet_test.predicates import saw_packet_equaling
from async_packet_test.predicates import packet_count_was
from async_packet_test.predicates import packet_count
from async_packet_test.sniff_future import NotNakedAssertable



iface = 'dummy0'

src_mac = get_if_hwaddr(iface)
dst_mac = 'ff:ff:ff:ff:ff:ff'
tcp_pkt = Ether(src=src_mac, dst=dst_mac) / \
	IP(src='221.221.221.221', dst='17.17.17.17') / TCP(sport=3456, dport=43)

vlan_102_pkt = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=102) / \
	IP(src='221.221.221.221', dst='17.17.17.17') / TCP(sport=3456, dport=43)

vlan_202_pkt = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=202) / \
	IP(src='221.221.221.221', dst='17.17.17.17') / TCP(sport=3456, dport=43)

icmp_packet = Ether() / IP() / ICMP()


context = make_pytest_context()



def test_received_packet_returns_true_when_packet_sent(context):
	future = context.expect(iface, received_packet)
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


''' This may fail -- packets may be flying around the interface for any number
	of reasons '''
@pytest.mark.skip
def test_received_packet_returns_false_when_packet_not_sent(context):
	future = context.expect(iface, received_packet)
	future.assert_false()


''' This may fail -- packets may be flying around the interface for any number
	of reasons '''
@pytest.mark.skip
def test_timed_out_returns_true_when_no_packet_sent(context):
	future = context.expect(iface, timed_out)
	future.assert_true()


def test_timed_out_returns_false_when_packet_sent(context):
	future = context.expect(iface, timed_out, timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_naked_assert_true(context):
    result = context.expect(iface, saw_protocol(ICMP))
    sendp(icmp_packet, iface=iface)
    assert result


def test_naked_assert_false(context):
    result = context.expect(iface, saw_protocol(ARP), timeout=1.0)
    sendp(icmp_packet, iface=iface)
    assert not result


def test_should_saw_src_mac_returns_true_when_mac_present(context):
	future = context.expect(iface, saw_src_mac(src_mac))
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_should_saw_src_mac_returns_false_when_mac_not_present(context):
	future = context.expect(iface, saw_src_mac('ab:ab:ab:ab:ab:ab'), timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_did_not_see_src_mac_returns_true_when_mac_not_present(context):
	future = context.expect(iface, did_not_see_src_mac('ab:ab:ab:ab:ab:ab'))
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_did_not_see_src_mac_returns_false_when_mac_present(context):
	future = context.expect(iface, did_not_see_src_mac(src_mac), timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_should_saw_dst_mac_returns_true_when_mac_present(context):
	future = context.expect(iface, saw_dst_mac(dst_mac))
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_should_saw_dst_mac_returns_false_when_mac_not_present(context):
	future = context.expect(iface, saw_dst_mac('ab:ab:ab:ab:ab:ab'), timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_did_not_see_dst_mac_returns_true_when_mac_not_present(context):
	future = context.expect(iface, did_not_see_dst_mac('ab:ab:ab:ab:ab:ab'))
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_did_not_see_dst_mac_returns_false_when_mac_present(context):
	future = context.expect(iface, did_not_see_dst_mac(dst_mac), timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_saw_vlan_tag_returns_true_when_tag_sent(context):
	future = context.expect(iface, saw_vlan_tag(102))
	sendp(vlan_102_pkt, iface=iface)
	future.assert_true()


def test_saw_vlan_tag_returns_false_when_tag_not_sent(context):
	future = context.expect(iface, saw_vlan_tag(202), timeout=1.0)
	sendp(vlan_102_pkt, iface=iface)
	future.assert_false()


def test_saw_vlan_tag_returns_false_when_vlan_not_sent(context):
	future = context.expect(iface, saw_vlan_tag(102), timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


def test_did_not_see_vlan_returns_true_when_vlan_not_present(context):
	future = context.expect(iface, did_not_see_vlan)
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_did_not_see_vlan_returns_false_when_vlan_present(context):
	future = context.expect(iface, did_not_see_vlan, timeout=1.0)
	sendp(vlan_102_pkt, iface=iface)
	future.assert_false()


def test_received_packet_equals_sent_returns_true(context):
	tmp = tcp_pkt.__class__(bytes(tcp_pkt)) # Calculates checksum
	future = context.expect(iface, saw_packet_equaling(tmp))
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


def test_received_packet_equals_sent_returns_false(context):
	future = context.expect(iface, saw_packet_equaling(tcp_pkt), timeout=1.0)
	sendp(vlan_102_pkt, iface=iface)
	future.assert_false()


''' This may fail -- packets may be flying around the interface for any number
	of reasons '''
@pytest.mark.skip
def test_packet_count_was_returns_true_when_correct_count_received(context):
	''' If sending on loopback, sniffer will see packet twice '''
	future = context.expect(iface, packet_count_was(3))
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	future.assert_true()


''' This may fail -- packets may be flying around the interface for any number
	of reasons '''
@pytest.mark.skip
def test_packet_count_was_returns_false_when_correct_count_not_received(context):
	future = context.expect(iface, packet_count_was(5))
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	future.assert_false()


''' This may fail -- packets may be flying around the interface for any number
	of reasons '''
@pytest.mark.skip
def test_packet_count_returns_correct_number_of_packets(context):
	count = context.expect(iface, packet_count)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	count.assert_value(3)


'''
Testing timeouts
'''

def test_packet_count_with_timeout(context):
	count = context.expect(iface, packet_count, timeout=1.0)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	time.sleep(3)
	# Should have joined by this point
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	sendp(tcp_pkt, iface=iface)
	count.assert_value(3)



def test_did_not_see_vlan_tag_is_true_when_not_sent(context):
	result = context.expect(iface, did_not_see_vlan_tag(103), timeout=1.0)
	sendp(vlan_102_pkt, iface=iface)
	assert result

def test_did_not_see_vlan_tag_is_false_when_sent(context):
	result = context.expect(iface, did_not_see_vlan_tag(102), timeout=1.0)
	sendp(vlan_102_pkt, iface=iface)
	assert not result




class saw_protocol(Predicate):
    def __init__(self, proto):
        self._proto = proto

    def stop_condition(self, packet):
        return packet.haslayer(self._proto)

    def on_finish(self, timed_out):
        return not timed_out


def test_custom_predicate_true(context):
    result = context.expect(iface, saw_protocol(ICMP))
    sendp(icmp_packet, iface=iface)
    result.assert_true()


def test_custom_predicate_false(context):
    result = context.expect(iface, saw_protocol(Dot1Q), timeout=1.0)
    sendp(icmp_packet, iface=iface)
    result.assert_false()





class DummyValuePredicate(Predicate):
    def stop_condition(self, pkt) -> bool:
        return True

    def on_finish(self, timed_out) -> bool:
        return 42


def test_value_predicate(context):
    result = context.expect(iface, DummyValuePredicate)
    sendp(icmp_packet, iface=iface)
    assert result.result() == 42


def test_non_bool_value_raises_NotNakedAssertable(context):
    result = context.expect(iface, DummyValuePredicate)
    sendp(icmp_packet, iface=iface)

    with pytest.raises(NotNakedAssertable):
        assert result    



'''The functions under test below are not yet implemented. The motivation here
would be to stop/halt the underlying sniffer without cancelling, such that the
future should at least have some valid result.
'''

# def test_packet_count_with_notify(context):
# 	count = context.expect(iface, packet_count, timeout=10.0)
# 	start_time = time.time()
# 	count.notify()
# 	count.result()
# 	duration = time.time() - start_time
# 	assert(duration < 2)


# def test_packet_count_without_notify(context):
# 	count = context.expect(iface, packet_count, timeout=5.0)
# 	start_time = time.time()
# 	time.sleep(1)
# 	count.result()
# 	duration = time.time() - start_time
# 	assert(duration >= 5)