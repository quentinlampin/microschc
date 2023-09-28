from microschc.protocol.ipv4 import IPV4_HEADER_ID, IPv4Parser
from microschc.protocol.ipv6 import IPv6_HEADER_ID, IPv6Parser
from microschc.protocol.udp import UDP_HEADER_ID, UDPParser
from microschc.protocol.coap import COAP_HEADER_ID, CoAPParser

from microschc.parser import PacketParser

from enum import Enum

PROTOCOLS = {
    IPV4_HEADER_ID: IPv4Parser,
    IPv6_HEADER_ID: IPv6Parser,
    UDP_HEADER_ID: UDPParser,
    COAP_HEADER_ID: CoAPParser
}

class Stack(str, Enum):
    IPV6_UDP_COAP = 'IPv6-UDP-CoAP'
    IPV4_UDP_COAP = 'IPv4-UDP-CoAP'

STACKS = {
    Stack.IPV6_UDP_COAP: [IPv6Parser, UDPParser, CoAPParser],
    Stack.IPV4_UDP_COAP: [IPv4Parser, UDPParser, CoAPParser],
}

def factory(stack_id: str) -> PacketParser:
    protocol_parsers = STACKS[stack_id]
    packet_parser: PacketParser = PacketParser(stack_id, [parser_class() for parser_class in protocol_parsers])
    return packet_parser
    