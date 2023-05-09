from dataclasses import dataclass
from typing import List, Union, Dict

from microschc.binary.buffer import Buffer
from microschc.compressor import compress
from microschc.decompressor import decompress
from microschc.manager import ContextManager
from microschc.parser import PacketParser, ParserError
from microschc.parser.protocol.registry import STACKS, factory
from microschc.rfc8724 import PacketDescriptor, RuleDescriptor
from microschc.rfc8724extras import Context
from microschc.ruler import Ruler, RuleDescriptorMatchError, RuleIDMatchError



@dataclass
class SCHC:
    context_managers: Dict[str, List[ContextManager]]

    def __init__(self, contexts: List[Context]) -> None:
        self.context_managers = {}
        for context in contexts:
            if context.interface_id not in self.context_managers.keys():
                self.context_managers[context.interface_id] = []
            self.context_managers[context.interface_id].append(ContextManager(context=context))
    
    def compress(self, packet: Buffer, interface_id: str):
        eligible_context_managers: List[ContextManager] = self.context_managers[interface_id]
        for context_manager in eligible_context_managers:
            try:
                schc_packet: Buffer = context_manager.compress(packet)
                return schc_packet
            except ParserError: 
                pass
            except RuleDescriptorMatchError:
                pass
        
        # no compression rule found, use the no compression rule
        # TODO: no compression rule
        return packet
        

    def decompress(self, packet: Buffer, interface_id: str):
        eligible_context_managers: List[ContextManager] = self.context_managers[interface_id]
        for context_manager in eligible_context_managers:
            try:
                packet: Buffer = context_manager.decompress(packet)
                return packet
            except RuleIDMatchError:
                pass
        # no rule matching, return packet as is.
        return packet


