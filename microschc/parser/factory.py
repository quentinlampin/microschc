"""
CoAP stack parser

Parser for the CoAP[1] over UDP[2] over IPv6[3] stack.


[1] "RFC7252: The Constrained Application Protocol (CoAP)", Z. Shelby et al.
[2] "RFC768: User Datagram Protocol", J. Postel.
[3] "RFC8200: Internet Protocol, Version 6 (IPv6) Specification", S. Deering et al.
"""

from microschc.parser import PacketParser
from microschc.parser.parser import HeaderParser
from microschc.rfc8724extras import StacksImplementation

from microschc.parser.protocol.coap import CoAPParser
from microschc.parser.protocol.udp import UDPParser
from microschc.parser.protocol.ipv6 import IPv6Parser



def factory(stack_implementation: StacksImplementation) -> PacketParser:
    if stack_implementation == StacksImplementation.IPV6_UDP_COAP:
        ipv6_parser: HeaderParser = IPv6Parser()
        udp_parser: HeaderParser = UDPParser()
        coap_parser: HeaderParser = CoAPParser()
        packet_parser: PacketParser = PacketParser(stack_implementation, [ipv6_parser, udp_parser, coap_parser])
        return packet_parser
