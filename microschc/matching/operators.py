"""
Matching Operators

Matching Operators (MOs) as defined in section 7.3 of RFC 8724 [1], i.e.:

    - `equal`: returns True if the field value is equal to the target value else False
    - `ignore`: returns True
    - `MSB(x)`: returns True if the x leftmost bits of the field value equal that of the target value
    - `match_mapping`: returns True if the field value is in the target mapping values 

[1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from microschc.rfc8724 import FieldDescriptor, Mapping, MatchMapping


def equal(field_descriptor: FieldDescriptor, target_value: bytes) -> bool:
    """
    `equal` matching operator: 
    the match result is True if the field value in the packet matches the target value
    """
    return (field_descriptor.value == target_value)

def ignore(field_descriptor: FieldDescriptor) -> bool:
    """
    `ignore` matching operator: 
    the match result is always True
    """
    return True

def most_significant_bits(field_descriptor: FieldDescriptor, pattern: bytes, pattern_length: int) -> bool:
    """
    `MSB(x)` matching operator:
    the match result is True if the `pattern_length` most significant (leftmost) bits of the field value equal 
    the `pattern` of length `pattern_length`.

    *Important note*: we assume that the parser provides the field value represented as bytes,
    this means that for fields lengths differents than a multiple of 8, the byte representation
    contains padding bits. We further assume that the field is left-padded, i.e. all padding bits
    are on the first byte of the representation. Colloquially speaking, the raw field is packed on 
    the right when parsed.

    we also assume that the pattern is provided as bytes and that it is left-padded, if necessary.

        Suppose the following field value: b'\x33\xff\x23\xdb\xda' of length 38 bits, pattern: b'\x01\x9f\xf9' of length 17 bits
                                    field value
            |---------------------------------------------------------------------------|
            0x33             0xff            0x23           0xdb           0xda
        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
       |     byte0     |   byte1       |     byte2     |     byte3     |    byte4      |
           |--------------pattern------------|-----------------residue-----------------|
    | [...] 1|     byte1     |     byte2     |
        0x01        0x9f            0xf9

        The expected residue is:  
                                0x3              0xdb           0xda
                        0 0 0 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
                        |     byte2     |     byte3     |    byte4      |
                        |  0s |                                         | 
    """

    field_value: bytes = field_descriptor.value
    field_length: int = field_descriptor.length

    residue_length: int = field_length - pattern_length
    residue_fullbytes: int = residue_length // 8

    most_significant_bits: bytes = field_value[:-residue_fullbytes] # bytes 0-2
    residue_alignment: int = residue_length % 8
    if residue_alignment > 0:
        left_shift: int = 8 - residue_alignment
        region_of_interest: bytes = most_significant_bits
        region_of_interest_length = len(region_of_interest)
        #                  region of interest
        #  |-------------------------------------|
        #   0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0 0 1 1 
        #  |     byte0     |   byte1       |     byte2     |

        #                       pattern
        #   0 0 0 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1
        #|      byte0      |     byte1     |     byte2     |
        #       0x01             0x9f            0xf9


        most_significant_bits: bytes = b''
        bitmask: int = 0xff >> left_shift
        for i in range(region_of_interest_length-1, 0,-1):
            right_part: int = region_of_interest[i] >> residue_alignment
            left_part: int =  (region_of_interest[i-1] & bitmask) << left_shift
            byte_realigned = left_part + right_part
            most_significant_bits = byte_realigned.to_bytes(1, 'big') + most_significant_bits
        
        # leading bits of region of interest
        leading_bits = region_of_interest[0] >> residue_alignment
        most_significant_bits = leading_bits.to_bytes(1, 'big') + most_significant_bits

    return most_significant_bits == pattern

def match_mapping(field_descriptor: FieldDescriptor, target_values: MatchMapping) -> bool:
    """
    `match_mapping` matching operator:
    the match result is True if the field value is in the values of the target values
    """

    return (field_descriptor.value in target_values.forward.keys())
