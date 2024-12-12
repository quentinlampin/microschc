from typing import List, Type
# from microschc.protocol.ipv4 import IPV4_HEADER_ID, IPv4Parser
# from microschc.protocol.ipv6 import IPV6_HEADER_ID, IPv6Parser
# from microschc.protocol.udp import UDP_HEADER_ID, UDPParser
# from microschc.protocol.sctp import SCTP_HEADER_ID, SCTPParser
# from microschc.protocol.coap import COAP_HEADER_ID, CoAPParser


from microschc.parser import PacketParser

from enum import Enum

from microschc.parser.parser import HeaderParser

class ProtocolsIDs(int, Enum):
    IPV4 =    4
    IPV6 =    6
    UDP  =   17
    SCTP =  132
    COAP = 5683

PARSERS = {
    # dynamically filled by individual parser modules
    # ProtocolsIDs.IPV4: IPv4Parser,
    # ProtocolsIDs.IPV6: IPv6Parser,
    # ProtocolsIDs.UDP:  UDPParser,
    # ProtocolsIDs.COAP: CoAPParser,
    # ProtocolsIDs.SCTP: SCTPParser
}

def REGISTER_PARSER(protocol_id: int, parser_class: Type[HeaderParser]):
    PARSERS[protocol_id] = parser_class



class Stack(str, Enum):
    IPV6_UDP_COAP = 'IPv6-UDP-CoAP'
    IPV4_UDP_COAP = 'IPv4-UDP-CoAP'

STACKS = {
    Stack.IPV6_UDP_COAP: [ProtocolsIDs.IPV6, ProtocolsIDs.UDP, ProtocolsIDs.COAP],
    Stack.IPV4_UDP_COAP: [ProtocolsIDs.IPV4, ProtocolsIDs.UDP, ProtocolsIDs.COAP],
}


def factory(stack_id: str) -> PacketParser:
    protocol_ids: List[ProtocolsIDs] = STACKS[stack_id]
    packet_parser: PacketParser = PacketParser(stack_id, [PARSERS[protocol_id]() for protocol_id in protocol_ids])
    return packet_parser
    