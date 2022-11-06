from microschc.matching.operators import equal, ignore, most_significant_bits, match_mapping
from microschc.rfc8724 import FieldDescriptor, MatchMapping


SOME_ID = 'ID'

def test_equal():
    """test: equal matching operator
    Test against different target values of different lengths
    """
    
    # test on bytes values
    bytes_target_value = b'\x13\xff'
    other_bytes_value_of_same_length = b'\x14\xff'
    same_bytes_value_of_different_length = b'\x00\x13\xff'
    different_bytes_value_of_different_length = b'\x00\x14\xff'
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=bytes_target_value)
    assert equal(bytes_field, target_value=bytes_target_value) == True
    assert equal(bytes_field, target_value=other_bytes_value_of_same_length) == False
    assert equal(bytes_field, target_value=same_bytes_value_of_different_length) == False
    assert equal(bytes_field, target_value=different_bytes_value_of_different_length) == False

def test_ignore():
    """test: ignore matching operator
    Test that matching operator always returns True
    """
    any_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=0)
    assert ignore(any_field) == True

def test_most_significant_bits():
    """test: MSB(x) matching operator
    
    """
    pattern: bytes = b'\x01\x9f\xf9'
    pattern_length = 17

    # test on:
    # - value matching the pattern
    # - value is not byte-aligned
    # - residue is not byte-aligned
    # - pattern is not byte-aligned
    pattern: bytes = b'\x01\x9f\xf9'
    pattern_length = 17
    field_value: bytes = b'\x33\xff\x23\xdb\xda'
    field_length: int = 38

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=field_length, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern_length=pattern_length, pattern=pattern) == True

    # test on:
    # - value matching the pattern
    # - value is byte-aligned
    # - pattern is not byte-aligned
    pattern: bytes = b'\x33\xff\x23'
    pattern_length = 24
    field_value: bytes = b'\x33\xff\x23\xdb\xda'
    field_length: int = 40

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=field_length, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern_length=pattern_length, pattern=pattern) == True

    # test on:
    # - value not matching the pattern
    # - value is not byte-aligned
    # - pattern is not byte-aligned
    pattern: bytes = b'\x01\x9f\xf9'
    pattern_length = 17
    field_value: bytes = b'\x34\xff\x23\xdb\xda'
    field_length: int = 38

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=field_length, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern_length=pattern_length, pattern=pattern) == False

    # test on:
    # - value not matching the pattern
    # - value is not byte-aligned
    # - pattern is not byte-aligned
    pattern: bytes = b'\x01\x9f\xf9'
    pattern_length = 17
    field_value: bytes = b'\xf4\xff\x23\xdb\xda'
    field_length: int = 38

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=field_length, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern_length=pattern_length, pattern=pattern) == False

def test_match_mapping():
    """test: match-mapping operator
    test the match-mapping operator on different value types
    
    """

    integer_mapping: MatchMapping = MatchMapping(index_length=2, forward_mapping={14: 1, 21: 2, 34: 3})
    bytes_mapping: MatchMapping = MatchMapping(index_length=2, forward_mapping={b'\xff\x13':1 , b'\xff\xff\x00':2, b'\x00':3, b'\x0e':4})

    # testing on integer type fields
    matching_integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=14)
    assert match_mapping(matching_integer_field, target_values=integer_mapping) == True
    non_matching_integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=15)
    assert match_mapping(non_matching_integer_field, target_values=integer_mapping) == False

    # testing on bytes fields
    matching_bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=b'\xff\x13')
    assert match_mapping(matching_bytes_field, target_values=bytes_mapping) == True
    non_matching_bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=b'\xff\x15')
    assert match_mapping(non_matching_bytes_field, target_values=bytes_mapping) == False

    # testing on fields of wrong type
    integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value= 14)
    assert match_mapping(integer_field, target_values=bytes_mapping) == False
    

