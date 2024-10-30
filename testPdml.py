#!/usr/bin/env python3

from microschc.parser.pdmlParser import PdmlParser,PdmlLayerParser
from microschc.protocol.registry import PDML_SPECIFIC_PARSER
from microschc.rfc8724 import PacketDescriptor

# set the debug mode
debug:bool = True
# file to test
# pdmlFileName='testpdml.pdml'
# pdmlFileName='ngcap_short.pdml'
pdmlFileName='ngcap_empty.pdml'
pdmlFileName='cubic.pdml'
# pdmlFileName='https://wiki.wireshark.org/uploads/__moin_import__/attachments/PDML/cubic.pdml'

# set debug mode to the parser
for la in list(PDML_SPECIFIC_PARSER.values()):
    la.debug=debug

parser = PdmlParser(dictLayerParser=PDML_SPECIFIC_PARSER,debug=debug)
listOfPacketDeciptor:list[PacketDescriptor] = parser.parseFromFile(pdmlFileName)

print(f'-> number of PacketDescriptor parsed={len(listOfPacketDeciptor)}')
# pos:int = 3
# print(f' listOfPacketDeciptor[{pos} = {listOfPacketDeciptor[pos]}]')

pdmlTxt:str ="""
<pdml version="0" creator="wireshark/4.4.1" time="Wed Oct 23 18:55:25 2024" capture_file="/Users/upse6650/dev/microschc-main/NGAP_capture.pcap">
<packet>
  <proto name="eth" showname="Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)" size="14" pos="0">
    <field name="eth.dst" showname="Destination: 00:00:00_00:00:00 (00:00:00:00:00:00)" size="6" pos="0" show="00:00:00:00:00:00" value="000000000000">
    </field>
    <field name="eth.src" showname="Source: 00:00:00_00:00:00 (00:00:00:00:00:00)" size="6" pos="6" show="00:00:00:00:00:00" value="000000000000">
    </field>
    <field name="eth.type" showname="Type: IPv4 (0x0800)" size="2" pos="12" show="0x0800" value="0800"/>
    <field name="eth.stream" showname="Stream index: 0" size="0" pos="0" show="0"/>
  </proto>
</packet>
</pdml>
"""
listOfPacketDeciptor:list[PacketDescriptor] = parser.parseFromString(xmlStr=pdmlTxt)
