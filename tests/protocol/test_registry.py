from microschc.protocol.registry import Stack, factory
from microschc.parser import PacketParser
from microschc.rfc8724 import PacketDescriptor

def test_manager_factory_stack_id():
    """
    test the import of the parsers using the stack string
    """
    stack_id = 'IPv6-UDP-CoAP'
    assert factory(stack_id=stack_id) != None

def test_stack_ipv6_udp_coap():
    """
    test the IPv6/UDP/CoAP stack parser import
    """
    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)
    assert len(packet_parser.parsers) == 3