from dataclasses import Field
from microschc.matching.operators import equal, ignore, most_significant_bits, match_mapping
from microschc.rfc8724 import FieldDescriptor


SOME_ID = 'ID'

def test_equal():
    """test: equal matching operator
    Test against different target values of different lengths
    """
    
    # test on integer values
    integer_target_value = 13
    integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=integer_target_value)
    assert equal(integer_field, target_value=integer_target_value) == True
    assert equal(integer_field, target_value=integer_target_value+1) == False

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

    # test on string values
    target_value: str = 'some string'
    other_value: str = 'another string'
    string_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=len(target_value), position=0, value=target_value)
    assert equal(string_field, target_value=target_value) == True
    assert equal(string_field, target_value=other_value) == False

def test_ignore():
    """test: ignore matching operator
    Test that matching operator always returns True
    """
    any_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=None)
    assert ignore(any_field) == True

def test_most_significant_bits():
    """test: MSB(x) matching operator
    
    """
    # test on pattern of length 29
    pattern: bytes = b'\x13\xff\x23\xd8'
    pattern_length = 29

    first_value = b'\x13\xff\x23\xdb' # same length as pattern, should match
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=len(first_value), position=0, value=first_value)
    assert most_significant_bits(bytes_field, pattern_length=pattern_length, pattern=pattern) == True
