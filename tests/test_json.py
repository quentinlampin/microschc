from microschc.binary.buffer import Buffer
from microschc.parser.protocol.registry import Stack
from microschc.parser.protocol.ipv6 import IPv6Fields
from microschc.rfc8724 import Context, DirectionIndicator, FieldDescriptor, HeaderDescriptor, MatchMapping, PacketDescriptor, RuleDescriptor, RuleFieldDescriptor
from microschc.rfc8724 import CompressionDecompressionAction as CDA
from microschc.rfc8724 import MatchingOperator as MO

from typing import List

def test_match_mapping_to_json():
    """
    test JSON serialization of MatchMapping objects
    """
    match_mapping: MatchMapping = MatchMapping(forward_mapping={
        Buffer(content=b"\x20\x01\x0d", length=24):Buffer(content=b'\x01', length=2),
        Buffer(content=b"\x20\x01\x0e", length=24):Buffer(content=b'\x02', length=2)
    })

    json_str: str = match_mapping.json()
    print(json_str)
    assert json_str == '[{"index": {"content": "01", "length": 2, "padding": "left"}, "value": {"content": "20010d", "length": 24, "padding": "left"}}, {"index": {"content": "02", "length": 2, "padding": "left"}, "value": {"content": "20010e", "length": 24, "padding": "left"}}]'

def test_match_mapping_from_json():
    """
    test JSON deserialization of MatchMapping objects
    """
    json_str = '[{"index": {"content": "01", "length": 2, "padding": "left"}, "value": {"content": "20010d", "length": 24, "padding": "left"}}, {"index": {"content": "02", "length": 2, "padding": "left"}, "value": {"content": "20010e", "length": 24, "padding": "left"}}]'
    match_mapping: MatchMapping = MatchMapping.from_json(json_str=json_str)
    assert match_mapping.forward[Buffer(content=b"\x20\x01\x0d", length=24)] == Buffer(content=b'\x01', length=2)
    assert match_mapping.forward[Buffer(content=b"\x20\x01\x0e", length=24)] == Buffer(content=b'\x02', length=2)

def test_field_descriptor_to_json():
    """
    test JSON serialization of FieldDescriptor objects
    """
    field_descriptor: FieldDescriptor = FieldDescriptor(
        id='field descriptor',
        value=Buffer(content=b'\x00\x11', length=16),
        position=0
    )
    json_str = field_descriptor.json()
    assert json_str == '{"id": "field descriptor", "value": {"content": "0011", "length": 16, "padding": "left"}, "position": 0}'

def test_field_descriptor_from_json():
    """
    test JSON deserialization of FieldDescriptor objects
    """
    json_str = '{"id": "field descriptor", "value": {"content": "0011", "length": 16, "padding": "left"}, "position": 0}'

    field_descriptor: FieldDescriptor = FieldDescriptor.from_json(json_str=json_str)
    assert field_descriptor.id == 'field descriptor'
    assert field_descriptor.value == Buffer(content=b'\x00\x11', length=16)
    assert field_descriptor.position == 0


def test_header_descriptor_to_json():
    """
    test JSON serialization of HeaderDescriptor objects
    """
    header_descriptor: HeaderDescriptor = HeaderDescriptor(
        id='header descriptor',
        length=100,
        fields=[
            FieldDescriptor(id='fd1', value=Buffer(content=b'\x00\x01', length=16), position=0),
            FieldDescriptor(id='fd2', value=Buffer(content=b'\x00\x02', length=16), position=0)
        ]
    )
    json_str = header_descriptor.json()
    assert json_str == '{"id": "header descriptor", "length": 100, "fields": [{"id": "fd1", "value": {"content": "0001", "length": 16, "padding": "left"}, "position": 0}, {"id": "fd2", "value": {"content": "0002", "length": 16, "padding": "left"}, "position": 0}]}'

def test_header_descriptor_from_json():
    """
    test JSON deserialization of HeaderDescriptor objects
    """
    json_str = '{"id": "header descriptor", "length": 100, "fields": [{"id": "fd1", "value": {"content": "0001", "length": 16, "padding": "left"}, "position": 0}, {"id": "fd2", "value": {"content": "0002", "length": 16, "padding": "left"}, "position": 0}]}'
    header_descriptor: HeaderDescriptor = HeaderDescriptor.from_json(json_str=json_str)
    assert header_descriptor.id == 'header descriptor'
    assert header_descriptor.length == 100
    assert header_descriptor.fields == [
            FieldDescriptor(id='fd1', value=Buffer(content=b'\x00\x01', length=16), position=0),
            FieldDescriptor(id='fd2', value=Buffer(content=b'\x00\x02', length=16), position=0)
    ]

def test_packet_descriptor_to_json():
    """
    test JSON serialization of PacketDescriptor objects
    """
    packet_descriptor: PacketDescriptor = PacketDescriptor(
        direction=DirectionIndicator.UP,
        fields=[
            FieldDescriptor(id='fd1', value=Buffer(content=b'\x00\x01', length=16), position=0),
            FieldDescriptor(id='fd2', value=Buffer(content=b'\x00\x02', length=16), position=0)
        ],
        payload=Buffer(content=b'\x00\x01\x02', length=24),
        length=100
    )
    json_str = packet_descriptor.json()
    assert json_str == '{"direction": "Up", "fields": [{"id": "fd1", "value": {"content": "0001", "length": 16, "padding": "left"}, "position": 0}, {"id": "fd2", "value": {"content": "0002", "length": 16, "padding": "left"}, "position": 0}], "payload": {"content": "000102", "length": 24, "padding": "left"}, "length": 100}'

def test_packet_descriptor_from_json():
    """
    test JSON deserialization of PacketDescriptor objects
    """
    json_str = '{"direction": "Up", "fields": [{"id": "fd1", "value": {"content": "0001", "length": 16, "padding": "left"}, "position": 0}, {"id": "fd2", "value": {"content": "0002", "length": 16, "padding": "left"}, "position": 0}], "payload": {"content": "000102", "length": 24, "padding": "left"}, "length": 100}'
    packet_descriptor: PacketDescriptor = PacketDescriptor.from_json(json_str=json_str)
    assert packet_descriptor.direction == DirectionIndicator.UP
    assert packet_descriptor.fields == [
            FieldDescriptor(id='fd1', value=Buffer(content=b'\x00\x01', length=16), position=0),
            FieldDescriptor(id='fd2', value=Buffer(content=b'\x00\x02', length=16), position=0)
    ]
    assert packet_descriptor.payload == Buffer(content=b'\x00\x01\x02', length=24)
    assert packet_descriptor.length == 100

def test_rule_field_descriptor_to_json():
    """
    test JSON serialization of RuleFieldDescriptor objects
    """
    rule_field_descriptor: RuleFieldDescriptor = RuleFieldDescriptor(
            id=IPv6Fields.PAYLOAD_LENGTH, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'', length=16), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT)

    json_str = rule_field_descriptor.json()
    assert json_str == '{"id": "IPv6:Payload Length", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 16, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}'

def test_rule_field_descriptor_from_json():
    """
    test JSON deserialization of RuleFieldDescriptor objects
    """
    json_str = '{"id": "IPv6:Payload Length", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 16, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}'

    rule_field_descriptor: RuleFieldDescriptor = RuleFieldDescriptor.from_json(json_str=json_str)
    assert rule_field_descriptor.id == IPv6Fields.PAYLOAD_LENGTH
    assert rule_field_descriptor.length == 16
    assert rule_field_descriptor.position == 0
    assert rule_field_descriptor.direction == DirectionIndicator.BIDIRECTIONAL
    assert rule_field_descriptor.target_value == Buffer(content=b'', length=16)
    assert rule_field_descriptor.matching_operator == MO.IGNORE
    assert rule_field_descriptor.compression_decompression_action == CDA.VALUE_SENT

def test_rule_descriptor_to_json():
    """
    test JSON serialization of RuleDescriptor objects
    """

    rule_field_descriptors: List[RuleFieldDescriptor] = [
        RuleFieldDescriptor(
            id='field1', length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT
        ),
        RuleFieldDescriptor(
            id='field2', length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\xef', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT
        )
    ]
    rule_descriptor: RuleDescriptor = RuleDescriptor(id=Buffer(content=b'\x00', length=2), field_descriptors=rule_field_descriptors)

    json_str = rule_descriptor.json()
    assert json_str == '{"id": {"content": "00", "length": 2, "padding": "left"}, "field_descriptors": [{"id": "field1", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 0, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}, {"id": "field2", "length": 8, "position": 0, "direction": "Bi", "target_value": {"content": "ef", "length": 8, "padding": "left"}, "matching_operator": "equal", "compression_decompression_action": "not-sent"}]}'

def test_rule_descriptor_from_json():
    """
    test JSON deserialization of RuleDescriptor objects
    """
    json_str = '{"id": {"content": "00", "length": 2, "padding": "left"}, "field_descriptors": [{"id": "field1", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 0, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}, {"id": "field2", "length": 8, "position": 0, "direction": "Bi", "target_value": {"content": "ef", "length": 8, "padding": "left"}, "matching_operator": "equal", "compression_decompression_action": "not-sent"}]}'

    rule_descriptor: RuleDescriptor = RuleDescriptor.from_json(json_str=json_str)
    assert rule_descriptor.id == Buffer(content=b'\x00', length=2)
    assert len(rule_descriptor.field_descriptors) == 2

    assert rule_descriptor.field_descriptors[0].id == 'field1'
    assert rule_descriptor.field_descriptors[0].length == 16
    assert rule_descriptor.field_descriptors[0].position == 0
    assert rule_descriptor.field_descriptors[0].direction == DirectionIndicator.BIDIRECTIONAL
    assert rule_descriptor.field_descriptors[0].target_value == Buffer(content=b'', length=0)
    assert rule_descriptor.field_descriptors[0].matching_operator == MO.IGNORE
    assert rule_descriptor.field_descriptors[0].compression_decompression_action == CDA.VALUE_SENT

    assert rule_descriptor.field_descriptors[1].id == 'field2'
    assert rule_descriptor.field_descriptors[1].length == 8
    assert rule_descriptor.field_descriptors[1].position == 0
    assert rule_descriptor.field_descriptors[1].direction == DirectionIndicator.BIDIRECTIONAL
    assert rule_descriptor.field_descriptors[1].target_value == Buffer(content=b'\xef', length=8)
    assert rule_descriptor.field_descriptors[1].matching_operator == MO.EQUAL
    assert rule_descriptor.field_descriptors[1].compression_decompression_action == CDA.NOT_SENT


def test_context_to_json():
    """
    test JSON serialization of RuleDescriptor objects
    """

    rule_field_descriptors: List[RuleFieldDescriptor] = [
        RuleFieldDescriptor(
            id='field1', length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'', length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT
        ),
        RuleFieldDescriptor(
            id='field2', length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\xef', length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT
        )
    ]
    rule_descriptor: RuleDescriptor = RuleDescriptor(id=Buffer(content=b'\x00', length=2), field_descriptors=rule_field_descriptors)

    context: Context = Context(id='test_context', description='this is a test context', interface_id='eth0', parser_id=Stack.IPV6_UDP_COAP, ruleset=[rule_descriptor])

    json_str = context.json()
    assert json_str == '{"id": "test_context", "description": "this is a test context", "interface_id": "eth0", "parser_id": "IPv6-UDP-CoAP", "ruleset": [{"id": {"content": "00", "length": 2, "padding": "left"}, "field_descriptors": [{"id": "field1", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 0, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}, {"id": "field2", "length": 8, "position": 0, "direction": "Bi", "target_value": {"content": "ef", "length": 8, "padding": "left"}, "matching_operator": "equal", "compression_decompression_action": "not-sent"}]}]}'

def test_context_from_json():
    """
    test JSON deserialization of Context objects
    """
    json_str = '{"id": "test_context", "description": "this is a test context", "interface_id": "eth0", "parser_id": "IPv6-UDP-CoAP", "ruleset": [{"id": {"content": "00", "length": 2, "padding": "left"}, "field_descriptors": [{"id": "field1", "length": 16, "position": 0, "direction": "Bi", "target_value": {"content": "", "length": 0, "padding": "left"}, "matching_operator": "ignore", "compression_decompression_action": "value-sent"}, {"id": "field2", "length": 8, "position": 0, "direction": "Bi", "target_value": {"content": "ef", "length": 8, "padding": "left"}, "matching_operator": "equal", "compression_decompression_action": "not-sent"}]}]}'

    context: Context = Context.from_json(json_str=json_str)
    assert context.id == 'test_context'
    assert context.description == 'this is a test context'
    assert context.interface_id == 'eth0'
    assert context.parser_id == Stack.IPV6_UDP_COAP

    assert context.ruleset[0].field_descriptors[0].id == 'field1'
    assert context.ruleset[0].field_descriptors[0].length == 16
    assert context.ruleset[0].field_descriptors[0].position == 0
    assert context.ruleset[0].field_descriptors[0].direction == DirectionIndicator.BIDIRECTIONAL
    assert context.ruleset[0].field_descriptors[0].target_value == Buffer(content=b'', length=0)
    assert context.ruleset[0].field_descriptors[0].matching_operator == MO.IGNORE
    assert context.ruleset[0].field_descriptors[0].compression_decompression_action == CDA.VALUE_SENT

    assert context.ruleset[0].field_descriptors[1].id == 'field2'
    assert context.ruleset[0].field_descriptors[1].length == 8
    assert context.ruleset[0].field_descriptors[1].position == 0
    assert context.ruleset[0].field_descriptors[1].direction == DirectionIndicator.BIDIRECTIONAL
    assert context.ruleset[0].field_descriptors[1].target_value == Buffer(content=b'\xef', length=8)
    assert context.ruleset[0].field_descriptors[1].matching_operator == MO.EQUAL
    assert context.ruleset[0].field_descriptors[1].compression_decompression_action == CDA.NOT_SENT