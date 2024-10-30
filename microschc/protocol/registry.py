from microschc.protocol.ipv4 import IPV4_HEADER_ID, IPv4Parser
from microschc.protocol.ipv6 import IPv6_HEADER_ID, IPv6Parser
from microschc.protocol.udp import UDP_HEADER_ID, UDPParser
from microschc.protocol.coap import COAP_HEADER_ID, CoAPParser

from microschc.parser import PacketParser,PdmlLayerParser

from enum import Enum

PDML_SPECIFIC_PARSER = {
    'ip' : PdmlLayerParser(listFieldToNotParse=['flags']),
    'tcp' : PdmlLayerParser(listFieldToNotParse=['len','hdr_len','window_size_value','window_size_scalefactor']),
    'lwm2mtlv' : PdmlLayerParser(depth=3,listFieldToNotParse=['value.integer','value.integer','value.double','value.timestamp','value.unsigned_integer']),
    'sctp' : PdmlLayerParser(depth=2,listFieldToNotParse=['data_tsn_raw'])
}

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
    