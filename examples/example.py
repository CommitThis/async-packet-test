from scapy.all import Ether, IP, TCP, Dot1Q, get_if_hwaddr, sendp


from async_packet_test.context import TestContext
from async_packet_test.predicates import received_packet


iface = 'dummy0'

src_mac = get_if_hwaddr(iface)
dst_mac = 'ff:ff:ff:ff:ff:ff'

context = TestContext()

tcp_pkt = Ether(src=src_mac, dst=dst_mac) / \
	IP(src='221.221.221.221', dst='17.17.17.17') / \
	TCP(sport=3456, dport=43)

future = context.expect(iface, received_packet)
sendp(tcp_pkt, iface=iface)
future.assert_result()