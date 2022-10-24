from math import ceil
from microschc.actions.compression import not_sent, value_sent, mapping_sent, least_significant_bits
from microschc.rfc8724 import FieldDescriptor, FieldResidue, Mapping, MatchMapping


SOME_ID = 'ID'

def test_not_sent():
    """test: `not-sent` compression action
    Test that residue is of size 0 and empty
    """
    
    # test on integer values
    integer_target_value = 13
    integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=integer_target_value)
    
    field_residue: FieldResidue = not_sent(integer_field)

    assert field_residue.length == 0
    assert field_residue.residue == b''

def test_value_sent():
    """test: `value-sent` compression action
    Test that residue is identical the the field descriptor value
    """
    
    # test on integer values
    integer_value = 13
    integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=integer_value)
    field_residue: FieldResidue = value_sent(field_descriptor=integer_field)
    assert int.from_bytes(field_residue.residue, 'big') == integer_value
    assert field_residue.length == integer_field.length

    # test on bytes value
    bytes_value = b'\x13\xff'
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=bytes_value)
    field_residue: FieldResidue = value_sent(field_descriptor=bytes_field)
    assert field_residue.residue == bytes_value
    assert field_residue.length == bytes_field.length

def test_mapping_sent():
    """test: `mapping-sent` compression action
    Test that residue is equal to the value stored in the forward mapping at the key of the field value
    """
    
    # test on integer values
    integer_value = 13
    integer_forward_mapping: Mapping = {13: 1, 14:2}
    index_length: int = 2

    integer_match_mapping : MatchMapping = MatchMapping(index_length=index_length, forward_mapping=integer_forward_mapping)
    integer_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=integer_value)
    field_residue: FieldResidue = mapping_sent(field_descriptor=integer_field, mapping=integer_match_mapping)
    assert int.from_bytes(field_residue.residue, 'big') == integer_forward_mapping[integer_value]
    assert field_residue.length == index_length

    # test on bytes value
    bytes_value = b'\x13\xff'
    bytes_forward_mapping: Mapping = {b'\xff': 1, b'\x13\xff':2}
    index_length: int = 3

    bytes_match_mapping : MatchMapping = MatchMapping(index_length=index_length, forward_mapping=bytes_forward_mapping)
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=16, position=0, value=bytes_value)
    field_residue: FieldResidue = mapping_sent(field_descriptor=bytes_field, mapping=bytes_match_mapping)
    assert int.from_bytes(field_residue.residue, 'big') == 2
    assert field_residue.length == index_length

def test_least_significant_bits():
    """test: `LSB` compression action
    Test that residue is equal to bits not included in the pattern matched by the `MSB(x)` Matching Operator.

    Suppose the following field value: b'\x33\xff\x23\xdb\xda' of length 38 bits, pattern: b'\x01\x9f\xf9' of length 17 bits
                                    field value
        |---------------------------------------------------------------------------|
          0x33             0xff            0x23           0xdb           0xda
     0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
    |     byte0     |   byte1       |     byte2     |     byte3     |    byte4      |
        |--------------pattern------------|-----------------residue-----------------|
  | [...] |     byte1     |     byte2     |
     0x01       0x9f            0xf9

    The expected residue is:  
                            0x3              0xdb           0xda
                       0 0 0 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
                      |     byte2     |     byte3     |    byte4      |
                      |  0s |                                         | 
    
    """

    pattern: bytes = b'\x01\x9f\xf9'
    pattern_length: int = 17 # in bits

    field_value: bytes = b'\x33\xff\x23\xdb\xda'
    field_length: int = 38 # in bits
    

    expected_residue_length: int = field_length - pattern_length
    expected_residue: bytes = b'\x03\xdb\xda'

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, length=field_length, position=0, value=field_value)

    field_residue: FieldResidue = least_significant_bits(field_descriptor=bytes_field, match_pattern_length=pattern_length)
    assert field_residue.length == expected_residue_length
    assert field_residue.residue == expected_residue
