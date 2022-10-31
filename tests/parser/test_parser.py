from microschc.parser.factory import factory
from microschc.parser.parser import PacketParser
from microschc.parser.protocol.coap import CoAPHeaderFields
from microschc.parser.protocol.ipv6 import IPv6Fields
from microschc.parser.protocol.udp import UDPFields
from microschc.rfc8724 import DirectionIndicator, HeaderDescriptor, PacketDescriptor
from microschc.rfc8724extras import ParserDefinitions, StacksImplementation

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
        - id='Length'               length=16    position=0  value=b'\x68'
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

    packet_parser: PacketParser = factory(stack_implementation=StacksImplementation.IPV6_UDP_COAP)
    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=valid_stack_packet, direction=DirectionIndicator.DOWN)

    ipv6_header: HeaderDescriptor = packet_descriptor.headers[0]
    udp_header: HeaderDescriptor = packet_descriptor.headers[1]
    coap_header: HeaderDescriptor = packet_descriptor.headers[2]
    
    payload: HeaderDescriptor = packet_descriptor.headers[3]

    assert ipv6_header.fields[0].id == IPv6Fields.VERSION
    assert ipv6_header.fields[0].value == b'\x06'
    assert ipv6_header.fields[1].id == IPv6Fields.TRAFFIC_CLASS
    assert ipv6_header.fields[1].value == b'\x00'
    assert ipv6_header.fields[2].id == IPv6Fields.FLOW_LABEL
    assert ipv6_header.fields[2].value == b'\x00\xef\x2d'
    assert ipv6_header.fields[3].id == IPv6Fields.PAYLOAD_LENGTH
    assert ipv6_header.fields[3].value == b'\x00\x68'
    assert ipv6_header.fields[4].id == IPv6Fields.NEXT_HEADER
    assert ipv6_header.fields[4].value == b'\x11'
    assert ipv6_header.fields[5].id == IPv6Fields.HOP_LIMIT
    assert ipv6_header.fields[5].value == b'\x40'
    assert ipv6_header.fields[6].id == IPv6Fields.SRC_ADDRESS
    assert ipv6_header.fields[6].value == b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
    assert ipv6_header.fields[7].id == IPv6Fields.DST_ADDRESS
    assert ipv6_header.fields[7].value == b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20"

    assert udp_header.fields[0].id == UDPFields.SOURCE_PORT
    assert udp_header.fields[0].value == b'\xd1\x00'
    assert udp_header.fields[1].id == UDPFields.DESTINATION_PORT
    assert udp_header.fields[1].value == b'\x16\x33'
    assert udp_header.fields[2].id == UDPFields.LENGTH
    assert udp_header.fields[2].value == b'\x00\x68'
    assert udp_header.fields[3].id == UDPFields.CHECKSUM
    assert udp_header.fields[3].value == b'\x5c\x21'

    assert coap_header.fields[0].id == CoAPHeaderFields.VERSION
    assert coap_header.fields[0].value == b'\x01'
    assert coap_header.fields[1].id == CoAPHeaderFields.TYPE
    assert coap_header.fields[1].value == b'\x02'
    assert coap_header.fields[2].id == CoAPHeaderFields.TOKEN_LENGTH
    assert coap_header.fields[2].value == b'\x08'
    assert coap_header.fields[3].id == CoAPHeaderFields.CODE 
    assert coap_header.fields[3].value == b'\x45'
    assert coap_header.fields[4].id == CoAPHeaderFields.MESSAGE_ID 
    assert coap_header.fields[4].value == b'\x22\xf6'
    assert coap_header.fields[5].id == CoAPHeaderFields.TOKEN 
    assert coap_header.fields[5].value == b"\xb8\x30\x0e\xfe\xe6\x62\x91\x22"
    assert coap_header.fields[6].id == CoAPHeaderFields.OPTION_DELTA 
    assert coap_header.fields[6].value == b'\x0c'
    assert coap_header.fields[7].id == CoAPHeaderFields.OPTION_LENGTH 
    assert coap_header.fields[7].value == b'\x01'
    assert coap_header.fields[8].id == CoAPHeaderFields.OPTION_VALUE 
    assert coap_header.fields[8].value == b'\x6e'
    assert coap_header.fields[9].id == CoAPHeaderFields.PAYLOAD_MARKER 
    assert coap_header.fields[9].value == b'\xff'

    assert payload.fields[0].id == ParserDefinitions.PAYLOAD
    assert payload.fields[0].length == 648
    assert payload.fields[0].position == 0
    assert payload.fields[0].value == b"\x5b\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22" \
                                      b"\x3a\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d" \
                                      b"\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a" \
                                      b"\x34\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22" \
                                      b"\x2c\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"