from microschc.parser.parser import PacketParser
from microschc.parser.protocol.registry import Stack, factory
from microschc.parser.protocol.coap import CoAPFields
from microschc.parser.protocol.ipv6 import IPv6Fields
from microschc.parser.protocol.udp import UDPFields
from microschc.rfc8724 import DirectionIndicator, PacketDescriptor
from microschc.binary.buffer import Buffer

def test_parser_ipv6_udp_coap():
    """
    The packet is made of:

    - an IPv6 header with following fields:
        - id='Version'              length=4    position=0  value=b'\x06'
        - id='Traffic Class'        length=8    position=0  value=b'\x00'
        - id='Flow Label'           length=20   position=0  value=b'\x00\xef\x2d'
        - id='Payload Length'       length=16   position=0  value=b'\x00\x68'
        - id='Next Header'          length=8    position=0  value=b'\x11'
        - id='Hop Limit'            length=8    position=0  value=b'\x40'
        - id='Source Address'       length=128  position=0  value=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
        - id='Destination Address'  length=128  position=0  value=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20"

    - a UDP header with following fields:
        - id='Source Port'          length=16    position=0  value=b'\xd1\x00'
        - id='Destination Port'     length=16    position=0  value=b'\x16\x33'
        - id='Length'               length=16    position=0  value=b'\x00\x68'
        - id='Checksum'             length=16    position=0  value=b'\x5c\x21'

    - a CoAP header with following fields:
        - id='Version'                length=2    position=0  value=b'\x01'
        - id='Type'                   length=2    position=0  value=b'\x02'
        - id='Token Length'           length=4    position=0  value=b'\x08'
        - id='Code'                   length=8    position=0  value=b'\x45'
        - id='message ID'             length=16   position=0  value=b\x22\xf6'
        - id='Token'                  length=32   position=0  value=b"\xb8\x30\x0e\xfe\xe6\x62\x91\x22"

        - id='Option Delta'           length=4    position=0  value=b'\x0c'
        - id='Option Length'          length=4    position=0  value=b'\x01'
        - id='Option Value'           length=16   position=0  value=b'\x6e'
        - id='Payload Marker'         length=8    position=0  value=b'\xff'
    - a Payload:
        - id='Payload'                length=648  position=0  value=b"\x5b\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22" \
                                                                    b"\x3a\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d" \
                                                                    b"\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a" \
                                                                    b"\x34\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22" \
                                                                    b"\x2c\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"


    """
    # leshan-0 frame 24
    valid_stack_packet:bytes = bytes(
        b"\x60\x00\xef\x2d\x00\x68\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x20\xd1\x00\x16\x33\x00\x68\x5c\x21" \
        b"\x68\x45\x22\xf6\xb8\x30\x0e\xfe\xe6\x62\x91\x22\xc1\x6e\xff\x5b" \
        b"\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22\x3a" \
        b"\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d\x2c" \
        b"\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a\x34" \
        b"\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22\x2c" \
        b"\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"
    )
    packet_buffer = Buffer(content=valid_stack_packet, length=len(valid_stack_packet)*8)

    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)

    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=packet_buffer)

    assert packet_descriptor.fields[0].id == IPv6Fields.VERSION
    assert packet_descriptor.fields[0].value == Buffer(content=b'\x06', length=4)
    assert packet_descriptor.fields[1].id == IPv6Fields.TRAFFIC_CLASS
    assert packet_descriptor.fields[1].value == Buffer(content=b'\x00', length=8)
    assert packet_descriptor.fields[2].id == IPv6Fields.FLOW_LABEL
    assert packet_descriptor.fields[2].value == Buffer(content=b'\x00\xef\x2d', length=20)
    assert packet_descriptor.fields[3].id == IPv6Fields.PAYLOAD_LENGTH
    assert packet_descriptor.fields[3].value == Buffer(content=b'\x00\x68', length=16)
    assert packet_descriptor.fields[4].id == IPv6Fields.NEXT_HEADER
    assert packet_descriptor.fields[4].value == Buffer(content=b'\x11', length=8)
    assert packet_descriptor.fields[5].id == IPv6Fields.HOP_LIMIT
    assert packet_descriptor.fields[5].value == Buffer(content=b'\x40', length=8)
    assert packet_descriptor.fields[6].id == IPv6Fields.SRC_ADDRESS
    assert packet_descriptor.fields[6].value == Buffer(content=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", length=128)
    assert packet_descriptor.fields[7].id == IPv6Fields.DST_ADDRESS
    assert packet_descriptor.fields[7].value == Buffer(content=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20", length=128)

    assert packet_descriptor.fields[8].id == UDPFields.SOURCE_PORT
    assert packet_descriptor.fields[8].value == Buffer(content=b'\xd1\x00', length=16)
    assert packet_descriptor.fields[9].id == UDPFields.DESTINATION_PORT
    assert packet_descriptor.fields[9].value == Buffer(content=b'\x16\x33', length=16)
    assert packet_descriptor.fields[10].id == UDPFields.LENGTH
    assert packet_descriptor.fields[10].value == Buffer(content=b'\x00\x68', length=16)
    assert packet_descriptor.fields[11].id == UDPFields.CHECKSUM
    assert packet_descriptor.fields[11].value == Buffer(content=b'\x5c\x21', length=16)

    assert packet_descriptor.fields[12].id == CoAPFields.VERSION
    assert packet_descriptor.fields[12].value == Buffer(content=b'\x01', length=2)
    assert packet_descriptor.fields[13].id == CoAPFields.TYPE
    assert packet_descriptor.fields[13].value == Buffer(content=b'\x02', length=2)
    assert packet_descriptor.fields[14].id == CoAPFields.TOKEN_LENGTH
    assert packet_descriptor.fields[14].value == Buffer(content=b'\x08', length=4)
    assert packet_descriptor.fields[15].id == CoAPFields.CODE 
    assert packet_descriptor.fields[15].value == Buffer(content=b'\x45', length=8)
    assert packet_descriptor.fields[16].id == CoAPFields.MESSAGE_ID 
    assert packet_descriptor.fields[16].value == Buffer(content=b'\x22\xf6', length=16)
    assert packet_descriptor.fields[17].id == CoAPFields.TOKEN 
    assert packet_descriptor.fields[17].value == Buffer(content=b"\xb8\x30\x0e\xfe\xe6\x62\x91\x22", length=64)
    assert packet_descriptor.fields[18].id == CoAPFields.OPTION_DELTA 
    assert packet_descriptor.fields[18].value == Buffer(content=b'\x0c', length=4)
    assert packet_descriptor.fields[19].id == CoAPFields.OPTION_LENGTH 
    assert packet_descriptor.fields[19].value == Buffer(content=b'\x01', length=4)
    assert packet_descriptor.fields[20].id == CoAPFields.OPTION_VALUE 
    assert packet_descriptor.fields[20].value == Buffer(content=b'\x6e', length=8)
    assert packet_descriptor.fields[21].id == CoAPFields.PAYLOAD_MARKER 
    assert packet_descriptor.fields[21].value == Buffer(content=b'\xff', length=8)

    payload_content: bytes =    b"\x5b\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22" \
                                b"\x3a\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d" \
                                b"\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a" \
                                b"\x34\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22" \
                                b"\x2c\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"
    assert packet_descriptor.payload == Buffer(content=payload_content, length=8*len(payload_content))


    # leshan 0 - 2to20 frame 6
    valid_stack_packet: bytes = b"\x60\x00\xef\x2d\x00\x14\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x20\xd1\x00\x16\x33\x00\x14\x5b\xcd" \
                                b"\x68\x44\x22\xf8\x0c\x68\xa4\xf0\xaf\xe7\xa8\x17"
    packet_buffer = Buffer(content=valid_stack_packet, length=len(valid_stack_packet)*8)

    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)
    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=packet_buffer)
    assert True # no raised exception for zero option CoAP packet

    # leshan 0 - 2to20 frame 15
    valid_stack_packet: bytes = b"\x60\x00\xef\x2d\x00\x22\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x20\xd1\x00\x16\x33\x00\x22\x5b\xdb" \
                                b"\x48\x02\xc7\x0b\x48\xa0\x8a\x71\x59\xb7\x94\x83\xb2\x72\x64\x0a" \
                                b"\x61\x30\x6e\x72\x6a\x76\x45\x46\x37\x47"
    packet_buffer = Buffer(content=valid_stack_packet, length=len(valid_stack_packet)*8)

    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)
    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=packet_buffer)
    assert True # no raised exception for no payload CoAP packet

