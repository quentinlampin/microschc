from typing import Dict, List, Tuple
from microschc.protocol.ipv6 import IPv6ComputeFunctions, IPv6Parser, IPv6Fields, ipv6_base_header_template
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import CDA, DI, MO, FieldDescriptor
from microschc.binary.buffer import Buffer
from microschc.rfc8724extras import ParserDefinitions
from microschc.tools.targetvalue import create_target_value

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

def test_ipv6_base_header_template():
    """Test the IPv6 field descriptors template generation."""
    # Test with all fields provided
    field_descriptors = ipv6_base_header_template(
        src_address=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
        dst_address=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20",
        traffic_class=0,
        flow_label=0xef2d,
        next_header=17,
        hop_limit=64
    )

    # Verify the number of fields
    assert len(field_descriptors) == 8

    # Verify each field's properties
    for field in field_descriptors:
        assert field.direction == DI.BIDIRECTIONAL
        assert field.position == 0

        if field.id == IPv6Fields.VERSION:
            assert field.length == 4
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(6, length=4)  # IPv6 version 6

        elif field.id == IPv6Fields.TRAFFIC_CLASS:
            assert field.length == 8
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(0, length=8)

        elif field.id == IPv6Fields.FLOW_LABEL:
            assert field.length == 20
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(0xef2d, length=20)

        elif field.id == IPv6Fields.PAYLOAD_LENGTH:
            assert field.length == 16
            assert field.matching_operator == MO.IGNORE
            assert field.compression_decompression_action == CDA.COMPUTE
            assert field.target_value is None

        elif field.id == IPv6Fields.NEXT_HEADER:
            assert field.length == 8
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(17, length=8)

        elif field.id == IPv6Fields.HOP_LIMIT:
            assert field.length == 8
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(64, length=8)

        elif field.id == IPv6Fields.SRC_ADDRESS:
            assert field.length == 128
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", length=128)

        elif field.id == IPv6Fields.DST_ADDRESS:
            assert field.length == 128
            assert field.matching_operator == MO.EQUAL
            assert field.compression_decompression_action == CDA.NOT_SENT
            assert field.target_value == create_target_value(b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20", length=128)