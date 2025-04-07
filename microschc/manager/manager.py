from microschc.compat import StrEnum
from typing import Union
from dataclasses import dataclass
from microschc.binary import Buffer
from microschc.compressor.compressor import compress
from microschc.decompressor.decompressor import decompress
from microschc.parser.parser import PacketParser
from microschc.protocol.registry import factory
from microschc.rfc8724 import DirectionIndicator, PacketDescriptor, RuleDescriptor

from microschc.rfc8724extras import Context
from microschc.ruler.ruler import Ruler

class MatchStrategy(StrEnum):
    FIRST = f'first'
    BEST  = f'best'

@dataclass
class ContextManager:
    context: Context
    parser: PacketParser
    ruler: Ruler

    def __init__(self, context: Union[Context, str], parser: Union[PacketParser, str, None]=None) -> None:
        if isinstance(context, Context):
            self.context = context
        elif isinstance(context, str):
            self.context = Context.from_json(context)
        else:
            raise AttributeError(f'Wrong type of argument passed for context: {context}')
        
        if isinstance(parser, PacketParser):
            self.parser = parser
        elif isinstance(parser, str):
            self.parser = factory(stack_id=parser)
        else:
            self.parser = factory(stack_id=context.parser_id)

        self.ruler = Ruler(rules_descriptors=self.context.ruleset)

    def compress(self, packet: Buffer, direction=DirectionIndicator.UP, match_strategy:MatchStrategy=MatchStrategy.FIRST):
        packet_descriptor: PacketDescriptor = self.parser.parse(packet)
        packet_descriptor.direction = direction
        if match_strategy == MatchStrategy.FIRST:
            rule_descriptor: RuleDescriptor = next(self.ruler.match_packet_descriptor(packet_descriptor=packet_descriptor))
            schc_packet: Buffer = compress(packet_descriptor=packet_descriptor, rule_descriptor=rule_descriptor)

        elif match_strategy == MatchStrategy.BEST:
            schc_packet: Buffer = None
            for rule_descriptor in self.ruler.match_packet_descriptor(packet_descriptor=packet_descriptor):
                compressed: Buffer = compress(packet_descriptor=packet_descriptor, rule_descriptor=rule_descriptor)
                if schc_packet is None or compressed.length < schc_packet.length:
                    schc_packet = compressed 
        
        return schc_packet
    
    def decompress(self, schc_packet: Buffer):
        rule_descriptor: RuleDescriptor = self.ruler.match_schc_packet(schc_packet=schc_packet)
        packet: Buffer = decompress(schc_packet=schc_packet, rule_descriptor=rule_descriptor)
        return packet

