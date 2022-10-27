from microschc.rfc8724 import CompressionDecompressionAction, DirectionIndicator, FieldDescriptor, MatchingOperator, RuleFieldDescriptor
from microschc.ruler.ruler import _field_match

def test_ruler_field_match():

    # test the `ignore` matching-operator on a matching field with same ID and same length
    packet_field: FieldDescriptor = FieldDescriptor(id='field-1', length=16, position=0, value=b'\xff\xff')

    rule_field_ignore: RuleFieldDescriptor = RuleFieldDescriptor(
        id='field-1',
        length=16,
        position=0,
        direction=DirectionIndicator.UP,
        target_value=b'',
        matching_operator=MatchingOperator.IGNORE,
        compression_decompression_action=CompressionDecompressionAction.NOT_SENT
    )
    assert _field_match(packet_field=packet_field, rule_field=rule_field_ignore) == True

    # test the `equal` matching-operator on a matching field with same ID and same length
    rule_field_equal: RuleFieldDescriptor = RuleFieldDescriptor(
        id='field-1',
        length=16,
        position=0,
        direction=DirectionIndicator.UP,
        target_value=b'\xff\xff',
        matching_operator=MatchingOperator.EQUAL,
        compression_decompression_action=CompressionDecompressionAction.NOT_SENT
    )
    assert _field_match(packet_field=packet_field, rule_field=rule_field_equal) == True

    # test the `equal` matching-operator on a matching field with Same ID, same value representation but
    # different length
    packet_field: FieldDescriptor = FieldDescriptor(id='field-1', length=15, position=0, value=b'\x7f\xff')
    rule_field_equal: RuleFieldDescriptor = RuleFieldDescriptor(
        id='field-1',
        length=16,
        position=0,
        direction=DirectionIndicator.UP,
        target_value=b'\7f\xff',
        matching_operator=MatchingOperator.EQUAL,
        compression_decompression_action=CompressionDecompressionAction.NOT_SENT
    )
    assert _field_match(packet_field=packet_field, rule_field=rule_field_equal) == False

