from typing import Dict, List, Tuple
from microschc.protocol.ipv6 import IPv6ComputeFunctions, IPv6Parser, IPv6Fields
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import FieldDescriptor
from microschc.binary.buffer import Buffer
from microschc.rfc8724extras import ParserDefinitions

def test_ipv6_parser_import():
    """test: IPv6 header parser import and instanciation
    The test instanciate an IPv6 parser and checks for import errors
    """
    parser = IPv6Parser()
    assert( isinstance(parser, IPv6Parser) )

def test_ipv6_parser_parse():
    """test: IPv6 header parser parses IPv6 packet

    The packet is made of an IPv6 header with following fields:
        - id='Version'              length=4    position=0  value=6
        - id='Traffic Class'        length=8    position=0  value=0
        - id='Flow Label'           length=20   position=0  value=b'\x00\x00\x00'
        - id='Payload Length'       length=16   position=0  value=16
        - id='Next Header'          length=8    position=0  value=17
        - id='Hop Limit'            length=8    position=0  value=64
        - id='Source Address'       length=128  position=0  value=b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1'
        - id='Destination Address'  length=128  position=0  value=b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa2'

    """

    valid_ipv6_packet:bytes = bytes(b"\x60\x00\x00\x00\x00\x10\x11\x40\xfe\x80\x00\x00\x00\x00\x00\x00"
                                    b"\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x80\x00\x00\x00\x00\x00\x00"
                                    b"\x00\x00\x00\x00\x00\x00\x00\xa2\x23\x29\x23\x2a\x00\x10\x2d\xa1"
                                    b"\x64\x65\x61\x64\x62\x65\x65\x66"
    )
    valid_ipv6_packet_buffer: Buffer = Buffer(content=valid_ipv6_packet, length=len(valid_ipv6_packet)*8)
    parser:IPv6Parser = IPv6Parser()
    
    ipv6_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_ipv6_packet_buffer)

    # test ipv6_header_descriptor type
    assert isinstance(ipv6_header_descriptor, HeaderDescriptor)

    # test for ipv6_header_descriptor.fields length
    assert len(ipv6_header_descriptor.fields) == 8

    # test for ipv6_header_descriptor.fields types
    for field in ipv6_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match IPv6 header content
    version_fd:FieldDescriptor = ipv6_header_descriptor.fields[0]
    assert version_fd.id == IPv6Fields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x06', length=4)

    traffic_class_fd:FieldDescriptor = ipv6_header_descriptor.fields[1]
    assert traffic_class_fd.id == IPv6Fields.TRAFFIC_CLASS
    assert traffic_class_fd.position == 0
    assert traffic_class_fd.value == Buffer(content=b'\x00', length=8)

    flow_label_fd:FieldDescriptor = ipv6_header_descriptor.fields[2]
    assert flow_label_fd.id == IPv6Fields.FLOW_LABEL
    assert flow_label_fd.position == 0
    assert flow_label_fd.value == Buffer(content=b'\x00\x00\x00', length=20)

    payload_length_fd:FieldDescriptor = ipv6_header_descriptor.fields[3]
    assert payload_length_fd.id == IPv6Fields.PAYLOAD_LENGTH
    assert payload_length_fd.position == 0
    assert payload_length_fd.value == Buffer(content=b'\x00\x10', length=16)

    next_header_fd:FieldDescriptor = ipv6_header_descriptor.fields[4]
    assert next_header_fd.id == IPv6Fields.NEXT_HEADER
    assert next_header_fd.position == 0
    assert next_header_fd.value == Buffer(content=b'\x11', length=8)

    hop_limit_fd:FieldDescriptor = ipv6_header_descriptor.fields[5]
    assert hop_limit_fd.id == IPv6Fields.HOP_LIMIT
    assert hop_limit_fd.position == 0
    assert hop_limit_fd.value == Buffer(content=b'\x40', length=8)

    source_address_fd:FieldDescriptor = ipv6_header_descriptor.fields[6]
    assert source_address_fd.id == IPv6Fields.SRC_ADDRESS
    assert source_address_fd.position == 0
    assert source_address_fd.value == Buffer(content=b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1', length=128)

    destination_address_fd:FieldDescriptor = ipv6_header_descriptor.fields[7]
    assert destination_address_fd.id == IPv6Fields.DST_ADDRESS
    assert destination_address_fd.position == 0
    assert destination_address_fd.value == Buffer(content=b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa2', length=128)

    
def test_ipv6_compute_length():

    parser:IPv6Parser = IPv6Parser()
    partially_reconstructed_ipv6_content:bytes = bytes(
        b"\x60\x00\x00\x00\x00\x00\x11\x40\xfe\x80\x00\x00\x00\x00\x00\x00" # payload length is \x00\x00, should be \x00\x10
        b"\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x80\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\xa2\x23\x29\x23\x2a\x00\x10\x2d\xa1"
        b"\x64\x65\x61\x64\x62\x65\x65\x66"
    )
    partially_reconstructed_ipv6_packet_buffer: Buffer = Buffer(content=partially_reconstructed_ipv6_content, length=len(partially_reconstructed_ipv6_content)*8)
    ipv6_header_descriptor: HeaderDescriptor = parser.parse(buffer=partially_reconstructed_ipv6_packet_buffer)
    decompressed_fields: List[Tuple[str, Buffer]] = [ (field.id,field.value) for field in ipv6_header_descriptor.fields]
    decompressed_fields.append((ParserDefinitions.PAYLOAD, Buffer(content=b"\x23\x29\x23\x2a\x00\x10\x2d\xa1\x64\x65\x61\x64\x62\x65\x65\x66", length=128)))
   

    payload_length_buffer: Buffer = IPv6ComputeFunctions[IPv6Fields.PAYLOAD_LENGTH][0](decompressed_fields, 3)
    assert payload_length_buffer == Buffer(content=b'\x00\x10', length=16)