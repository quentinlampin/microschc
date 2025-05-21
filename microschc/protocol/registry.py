from typing import Dict, List, Tuple, Type
from microschc.parser import PacketParser

from enum import IntEnum
from microschc.compat import StrEnum

from microschc.parser.parser import HeaderParser
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType

class ProtocolsIDs(IntEnum):
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

COMPUTE_FUNCTIONS = {
    # dynamically filled by individual protocol modules
}

def REGISTER_PARSER(protocol_id: int, parser_class: Type[HeaderParser]):
    PARSERS[protocol_id] = parser_class

def REGISTER_COMPUTE_FUNCTIONS(compute_functions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]]):
    for field_id, compute_function in compute_functions.items():
        COMPUTE_FUNCTIONS[field_id] = compute_function


class Stack(StrEnum):
    IPV6_UDP_COAP = 'IPv6-UDP-CoAP'
    IPV4_UDP_COAP = 'IPv4-UDP-CoAP'

STACKS = {
    Stack.IPV6_UDP_COAP: [ProtocolsIDs.IPV6, ProtocolsIDs.UDP, ProtocolsIDs.COAP],
    Stack.IPV4_UDP_COAP: [ProtocolsIDs.IPV4, ProtocolsIDs.UDP, ProtocolsIDs.COAP],
}

PROTOCOLS = {
    'IPv4': ProtocolsIDs.IPV4,
    'IPv6': ProtocolsIDs.IPV6,
    'UDP':  ProtocolsIDs.UDP,
    'CoAP': ProtocolsIDs.COAP,
    'SCTP': ProtocolsIDs.SCTP,
}

def factory(stack_id: str) -> PacketParser:
    try:
        protocol_ids: List[ProtocolsIDs] = STACKS[stack_id]
        parsers_instances: List[HeaderParser] = [PARSERS[protocol_id]() for protocol_id in protocol_ids]
    except KeyError:
        protocol_ids: List[ProtocolsIDs] = [PROTOCOLS[stack_id]]
        parsers_instances: List[HeaderParser] = [PARSERS[protocol_id](predict_next=True) for protocol_id in protocol_ids]
    packet_parser: PacketParser = PacketParser(stack_id, parsers_instances)
    return packet_parser
    