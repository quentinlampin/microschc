"""
Compression Actions (CAs)

Compression Actions (CAs) as defined in section 7.4 of RFC 8724 [1], i.e.:

    - `not-sent`: do not send the field value, at decompression the target value of the `equal` Matching Operator is used.
    - `value-sent`: send the field value, at decompression the field value is used.
    - `mapping-sent`: send the index in the mapping, at decompression the target value stored in the mapping at the index is used.
    - `LSB`: send bits not included in the pattern matched by the `MSB(x)` Matching Operator.
    - `compute-*`: not implemented yet, those include hard-coded expert logic on fields, e.g. compute UDP checksum based on UDP payload, etc
    - `devIID`: not implemented yet, same as compute-*, it's a hard-coded expert logic.
    - `appIID`: not implemented yet, same as compute-*, it's a hard-coded expert logic.

*** Important note: ***
    If the residue length (in bits) is not a multiple of 8, the residue has leading zeros (0s) in their bytes representation.
    The `compaction` of the residues, i.e. removal of leading zeros (0s), is done
    at the SCHC compression residue step (see Section 7.2 of [1]) after all fields residues are computed, when
    the SCHC Compression Residue payload is assembled (see Figure 7 of [1]).


[1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.


"""
from microschc.binary.buffer import Buffer
from microschc.rfc8724 import FieldDescriptor, MatchMapping


def not_sent(_: FieldDescriptor) -> Buffer:
    """
    `not-sent` compression action (CA): do not send the field value as it's supposed known by the receiver

    """
    field_residue: Buffer = Buffer(content=b'', bit_length=0)
    return field_residue


def value_sent(field_descriptor: FieldDescriptor) -> Buffer:
    """
    `value-sent` compression action (CA): send the original value
        ! important note in file header about integer residues: !
        for integer field lengths (in bits) that are not a multiple
        of 8, the residue has leading zeros (0s) in their bytes representation.
        The `compaction` of the residues, i.e. removal of leading zeros (0s), is done
        at the SCHC compression residue step (see Section 7.2 of [1]), when all fields residues are computed.

    """

    field_residue: Buffer = field_descriptor.value
    return field_residue

def mapping_sent(field_descriptor: FieldDescriptor, mapping: MatchMapping) -> Buffer:
    """
    `mapping-sent`: send the index in the mapping, at decompression the target value stored 
    in the reverse mapping at the index is used.
    """
    field_value: Buffer = field_descriptor.value
    index: Buffer = mapping.forward[field_value]

    field_residue: Buffer = index
    return field_residue

def least_significant_bits(field_descriptor: FieldDescriptor, bit_length: int) -> Buffer:
    """
    `LSB`: send bits not included in the pattern matched by the `MSB(x)` Matching Operator.

    *Important note*: we assume that the parser provides the field value represented as bytes,
    this means that for fields lengths differents than a multiple of 8, the byte representation
    contains padding bits. We further assume that the field is left-padded, i.e. all padding bits
    are on the first byte of the representation. Colloquially speaking, the raw field is packed on 
    the right when parsed.

    For example , consider the following header:
    fields |    #1    |  #2  |        #3       |    #4     |
    bytes  |        1      |               |               |
    bits    . . . . . . . . . 1 0 1 1 0 1 1 1 0 . . . . . .
                              =================
                                  field of
                                  interest
    
    The field of interest #3 is of size 9 bits and the parser 
    yields 2 bytes:
        byte #0           byte #1
    |               |               |
     0 0 0 0 0 0 0 1 0 1 1 0 1 1 1 0
    |             |                 |
     zero padding        field
        7 bits           9 bits 
        

    Suppose now that the matching pattern is: 1 0 1 1 0, it is represented
    as : 
    |    pattern    | 
     0 0 0 1 0 1 1 0
    |zeros| actual  |
    |     | pattern |

    The expected bits residue is therefore:  1 1 1 0
    and the byte-padded residue is :  0 0 0 0 1 1 1 0

    """
    field_value: Buffer = field_descriptor.value

    # assume pattern is matched, we retrieve the residue_length last bits.
    residue: bytes = b''
    residue_length: int = bit_length
    residue_full_bytes: int = residue_length // 8
    if residue_full_bytes > 0:
        residue = field_value.content[-(residue_length // 8):]

    residue_leading_bits: int = residue_length % 8
    if residue_leading_bits > 0:
        residue_partial_byte: int = field_value.content[-(residue_length // 8 + 1)]
        bitmask = (0xff >> (8-residue_leading_bits))
        leading_bits_residue: int = residue_partial_byte & bitmask
        residue = leading_bits_residue.to_bytes(1, 'big') + residue
    
    field_residue: Buffer = Buffer(content=residue, bit_length=residue_length)
    return field_residue






