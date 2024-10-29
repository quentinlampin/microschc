#!/usr/bin/env python3

from microschc.parser.pdmlParser import PdmlParser,PdmlLayerParser
from microschc.protocol.registry import PDML_SPECIFIC_PARSER
from microschc.rfc8724 import PacketDescriptor

# set the debug mode
debug:bool = True
# file to test
pdmlFileName='testpdml.pdml'
# pdmlFileName='ngcap_short.pdml'

# set debug mode to the parser
for la in list(PDML_SPECIFIC_PARSER.values()):
    la.debug=debug

parser = PdmlParser(pdmlFileName,dictLayerParser=PDML_SPECIFIC_PARSER,debug=debug)
listOfPacketDeciptor:list[PacketDescriptor] = parser.parse()

print(f'*** number of PacketDescriptor parsed={len(listOfPacketDeciptor)} ***')
