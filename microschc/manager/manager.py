from typing import Union
from dataclasses import dataclass
from microschc.binary import Buffer
from microschc.compressor.compressor import compress
from microschc.decompressor.decompressor import decompress
from microschc.parser.parser import PacketParser
from microschc.parser.protocol.registry import factory
from microschc.rfc8724 import DirectionIndicator, PacketDescriptor, RuleDescriptor

from microschc.rfc8724extras import Context
from microschc.ruler.ruler import Ruler


@dataclass
class ContextManager:
    context: Context
    parser: PacketParser
    ruler: Ruler

    def __init__(self, context: Context, parser: Union[PacketParser, str, None]=None) -> None:
        self.context = context
        if isinstance(parser, PacketParser):
            self.parser = parser
        elif isinstance(parser, str):
            self.parser = factory(stack_id=parser)
        else:
            self.parser = factory(stack_id=context.parser_id)

        self.ruler = Ruler(rules_descriptors=self.context.ruleset)

    def compress(self, packet: Buffer, direction=DirectionIndicator.UP):
        packet_descriptor: PacketDescriptor = self.parser.parse(packet)
        packet_descriptor.direction = direction
        rule_descriptor: RuleDescriptor = self.ruler.match_packet_descriptor(packet_descriptor=packet_descriptor)    
        schc_packet: Buffer = compress(packet_descriptor=packet_descriptor, rule_descriptor=rule_descriptor)
        return schc_packet
    
    def decompress(self, schc_packet: Buffer):
        rule_descriptor: RuleDescriptor = self.ruler.match_schc_packet(schc_packet=schc_packet)
        packet: Buffer = decompress(schc_packet=schc_packet, rule_descriptor=rule_descriptor)
        return packet

