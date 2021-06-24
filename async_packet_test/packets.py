from scapy.all import Ether, TCP, IP, get_if_hwaddr, get_if_addr


def make_packet(src_iface, dst_iface, payload):
	src_mac = get_if_hwaddr(src_iface)
	dst_mac = get_if_hwaddr(dst_iface)
	src_ip = get_if_addr(src_iface)
	dst_ip = get_if_addr(dst_iface)
	return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / payload