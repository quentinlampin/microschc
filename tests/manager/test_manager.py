from typing import List
from microschc.binary import Buffer
from microschc.protocol.coap import CoAPFields, CoAPOptionMode, CoAPParser, coap_option_template
from microschc.protocol.registry import Stack, factory
from microschc.manager import ContextManager
from microschc.parser import PacketParser
from microschc.protocol.ipv6 import IPv6Fields, IPv6Parser
from microschc.protocol.udp import UDPFields, UDPParser
from microschc.rfc8724 import FieldDescriptor, MatchMapping, PacketDescriptor, DirectionIndicator, RuleFieldDescriptor, RuleDescriptor
from microschc.rfc8724 import CompressionDecompressionAction as CDA
from microschc.rfc8724 import MatchingOperator as MO

from microschc.rfc8724extras import Context, ParserDefinitions

from microschc.protocol.ipv6 import ipv6_base_header_template
from microschc.protocol.udp import udp_header_template
from microschc.protocol.coap import coap_base_header_template, coap_semantic_option_template
from microschc.tools.targetvalue import create_target_value

def test_manager():

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

    field_descriptors_1: List[RuleFieldDescriptor] = [
        RuleFieldDescriptor(
            id=IPv6Fields.VERSION, length=4, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\x06', length=4), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.TRAFFIC_CLASS, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\x00', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.FLOW_LABEL, length=20, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x00\xef\x2d', length=20), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.PAYLOAD_LENGTH, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'', length=16), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.NEXT_HEADER, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x11', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.HOP_LIMIT, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x40', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.SRC_ADDRESS, length=128, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00', length=120), 
            matching_operator=MO.MSB, compression_decompression_action=CDA.LSB),
        RuleFieldDescriptor(id=IPv6Fields.DST_ADDRESS, length=128, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=MatchMapping(forward_mapping={
                Buffer(content=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20", length=128):Buffer(content=b'\x00', length=2)
            }), 
            matching_operator=MO.MATCH_MAPPING, compression_decompression_action=CDA.MAPPING_SENT),

        RuleFieldDescriptor(id=UDPFields.SOURCE_PORT, length=16, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\xd1\x00', length=16), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=UDPFields.DESTINATION_PORT, length=16, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x16\x33', length=16), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=UDPFields.LENGTH, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=UDPFields.CHECKSUM, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),

        RuleFieldDescriptor(id=CoAPFields.VERSION, length=2, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x01', length=2), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.TYPE, length=2, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x02', length=2), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.TOKEN_LENGTH, length=4, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.CODE, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.MESSAGE_ID, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.TOKEN, length=0, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_DELTA, length=4, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x0c', length=4), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_LENGTH, length=4, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_VALUE, length=0, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.PAYLOAD_MARKER, length=8, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\xff', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT)
    ]
    rule_descriptor_1: RuleDescriptor = RuleDescriptor(id=Buffer(content=b'\x03', length=2), field_descriptors=field_descriptors_1)

    context: Context = Context(id='default', description='IPv6 UDP CoAP', interface_id='wlan0', parser_id=Stack.IPV6_UDP_COAP, ruleset=[rule_descriptor_1])

    context_manager: ContextManager = ContextManager(context=context)

    compressed_packet = context_manager.compress(packet=packet_buffer, direction=DirectionIndicator.UP)
    decompressed_packet = context_manager.decompress(schc_packet=compressed_packet)
    assert decompressed_packet == packet_buffer

def test_manager_unparse():
    
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

    semantic_parser: PacketParser = PacketParser('semantic', parsers=[
        IPv6Parser(),
        UDPParser(),
        CoAPParser(interpret_options=CoAPOptionMode.SEMANTIC)
    ])

    packet_descriptor: PacketDescriptor = semantic_parser.parse(packet_buffer)


    ipv6_field_descriptors = ipv6_base_header_template(
        flow_label=b'\x00\xef\x2d',
        src_address=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02',
        dst_address=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20',
        next_header=17,
        hop_limit=64
    )

    udp_field_descriptors = udp_header_template(
        source_port=b'\xd1\x00',
        destination_port=b'\x16\x33'
    )

    coap_base_header_field_descriptors = coap_base_header_template(
        type=b'\x02',
        code=None,
        message_id=None,
        token_length=8,
        token=None
    )
    coap_option_content_format = RuleFieldDescriptor(
        id=CoAPFields.OPTION_CONTENT_FORMAT, 
        length=0,
        position=0, 
        target_value=None
    )

    coap_payload_marker_field_descriptor = RuleFieldDescriptor(
        id=CoAPFields.PAYLOAD_MARKER,
        length=8,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(value=b'\xff', length=8)
    )

    rule_descriptor: RuleDescriptor = RuleDescriptor(
        id=Buffer(content=b'\x01', length=2),
        field_descriptors= ipv6_field_descriptors +
                            udp_field_descriptors +
                            coap_base_header_field_descriptors +
                            [coap_option_content_format,
                             coap_payload_marker_field_descriptor]
    )

    context = Context(
        id='IPv6-UDP-CoAP-semantic',
        description='test context',
        interface_id='',
        parser_id='IPv6-UDP-CoAP-Semantic',
        ruleset=[rule_descriptor]
    )

    context_manager = ContextManager(context=context, parser=semantic_parser)
    compressed:Buffer = context_manager.compress(packet=packet_buffer)


    



