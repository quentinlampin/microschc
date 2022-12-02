"""
Matching Operators

Matching Operators (MOs) as defined in section 7.3 of RFC 8724 [1], i.e.:

    - `equal`: returns True if the field value is equal to the target value else False
    - `ignore`: returns True
    - `MSB(x)`: returns True if the x leftmost bits of the field value equal that of the target value
    - `match_mapping`: returns True if the field value is in the target mapping values 

[1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from microschc.binary.buffer import Buffer
from microschc.rfc8724 import FieldDescriptor, Mapping, MatchMapping


def equal(field_descriptor: FieldDescriptor, target_value: Buffer) -> bool:
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

def most_significant_bits(field_descriptor: FieldDescriptor, pattern: Buffer) -> bool:
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
    """
    field_value: Buffer = field_descriptor.value
    most_significant_bits = field_value.shift(shift=(field_value.length-pattern.length), inplace=False)
    return most_significant_bits == pattern

def match_mapping(field_descriptor: FieldDescriptor, target_values: MatchMapping) -> bool:
    """
    `match_mapping` matching operator:
    the match result is True if the field value is in the values of the target values
    """
    # TODO zero-padding, alignment issue?
    return (field_descriptor.value in target_values.forward.keys())
