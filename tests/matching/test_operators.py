from microschc.matching.operators import equal, ignore, most_significant_bits, match_mapping
from microschc.rfc8724 import FieldDescriptor, MatchMapping
from microschc.binary.buffer import Buffer


SOME_ID = 'ID'

def test_equal():
    """test: equal matching operator
    Test against different target values of different lengths
    """
    
    # test on bytes values
    bytes_target_value = Buffer(content=b'\x13\xff', bit_length=16)
    other_bytes_value_of_same_length = Buffer(content=b'\x14\xff', bit_length=16)
    same_bytes_value_of_different_length = Buffer(content=b'\x00\x13\xff', bit_length=24)
    different_bytes_value_of_different_length = Buffer(content=b'\x00\x14\xff', bit_length=24)
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=bytes_target_value)
    assert equal(bytes_field, target_value=bytes_target_value) == True
    assert equal(bytes_field, target_value=other_bytes_value_of_same_length) == False
    assert equal(bytes_field, target_value=same_bytes_value_of_different_length) == False
    assert equal(bytes_field, target_value=different_bytes_value_of_different_length) == False

def test_ignore():
    """test: ignore matching operator
    Test that matching operator always returns True
    """
    any_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=Buffer(content=b'', bit_length=16))
    assert ignore(any_field) == True

def test_most_significant_bits():
    """test: MSB(x) matching operator
    
    """
    # test on:
    # - value matching the pattern
    # - value is not byte-aligned
    # - residue is not byte-aligned
    # - pattern is not byte-aligned
    pattern: Buffer = Buffer(content=b'\x01\x9f\xf9', bit_length=17)
    field_value: Buffer = Buffer(content=b'\x33\xff\x23\xdb\xda', bit_length=38)

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern=pattern) == True

    # test on:
    # - value matching the pattern
    # - value is byte-aligned
    # - pattern is not byte-aligned
    pattern: Buffer = Buffer(content=b'\x33\xff\x23', bit_length=24)
    field_value: Buffer = Buffer(content=b'\x33\xff\x23\xdb\xda', bit_length=40)

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern=pattern) == True

    # test on:
    # - value not matching the pattern
    # - value is not byte-aligned
    # - pattern is not byte-aligned
    pattern: Buffer = Buffer(content=b'\x01\x9f\xf9', bit_length=17)
    field_value: Buffer = Buffer(content=b'\x34\xff\x23\xdb\xda', bit_length=38)
    

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern=pattern) == False

    # test on:
    # - value not matching the pattern
    # - value is not byte-aligned
    # - pattern is not byte-aligned
    pattern: Buffer = Buffer(content=b'\x01\x9f\xf9', bit_length=17)
    field_value: Buffer = Buffer(content=b'\xf4\xff\x23\xdb\xda', bit_length=38)

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=field_value)
    assert most_significant_bits(bytes_field, pattern=pattern) == False

def test_match_mapping():
    """test: match-mapping operator
    test the match-mapping operator on different values (matching and non-matching)
    
    """

    bytes_mapping: MatchMapping = MatchMapping(forward_mapping={
        Buffer(content=b'\xff\x13', bit_length=16): Buffer(content=b'\x01', bit_length=2),
        Buffer(content=b'\xff\xff\x00', bit_length=24): Buffer(content=b'\x02', bit_length=2), 
        Buffer(content=b'\x00', bit_length=8): Buffer(content=b'\x03', bit_length=2), 
        Buffer(content=b'\x0e', bit_length=8): Buffer(content=b'\x04', bit_length=2)
    })

    # testing on bytes fields
    matching_bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=Buffer(content=b'\xff\x13', bit_length=16))
    assert match_mapping(matching_bytes_field, target_values=bytes_mapping) == True
    non_matching_bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=Buffer(content=b'\xff\x15', bit_length=16))
    assert match_mapping(non_matching_bytes_field, target_values=bytes_mapping) == False


