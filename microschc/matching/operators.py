"""
Matching Operators

Matching Operators (MOs) as defined in section 7.3 of RFC 8724 [1], i.e.:

    - `equal`: returns True if the field value is equal to the target value else False
    - `ignore`: returns True
    - `MSB(x)`: returns True if the x leftmost bits of the field value equal that of the target value
    - `match_mapping`: returns True if the field value is in the target mapping values 

[1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from typing import Any, Dict
from microschc.rfc8724 import FieldDescriptor


def equal(field_descriptor: FieldDescriptor, target_value: Any):
    """
    `equal` matching operator: 
    the match result is True if the field value in the packet matches the target value
    """
    return (field_descriptor.value == target_value)

def ignore(field_descriptor: FieldDescriptor):
    """
    `ignore` matching operator: 
    the match result is always True
    """
    return True

def most_significant_bits(field_descriptor: FieldDescriptor, pattern: bytes, pattern_length: int):
    """
    `MSB(x)` matching operator:
    the match result is True if the `pattern_length` most significant (leftmost) bits of the field value equal 
    the `pattern_length` most significant (leftmost) bits of the pattern.
    """

    pattern_bytes = pattern_length // 8 # number of "full" bytes in the pattern to match
    bits_residue = pattern_length % 8 # number of bits in the pattern to match excluding "full" bytes to match

    if pattern_bytes > 0 and field_descriptor.value[0:pattern_bytes] != pattern[0:pattern_bytes]:
        return False
    
    if bits_residue > 0:
        bitmask = 0xff << (8-bits_residue) & 0xff
        return (field_descriptor.value[pattern_bytes] == pattern[pattern_bytes])

    return True

def match_mapping(field_descriptor: FieldDescriptor, target_values: Dict[int, Any]):
    """
    `match_mapping` matching operator:
    the match result is True if the field value is in the values of the target values
    """

    return (field_descriptor.value in target_values.values())
