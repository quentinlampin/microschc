from microschc.protocol.registry import Stack, factory
from microschc.parser import PacketParser
from microschc.rfc8724 import PacketDescriptor


def test_stack_ipv6_udp_coap():
    """
    test the IPv6/UDP/CoAP stack parser import
    """
    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)
    assert len(packet_parser.parsers) == 3