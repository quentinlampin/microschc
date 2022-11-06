'''
Implementation SCHC packet compression as described in section 7.2 of [1].

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
'''

from typing import List, Tuple
from microschc.actions.compression import least_significant_bits, mapping_sent, value_sent
from microschc.rfc8724 import FieldDescriptor, FieldResidue, MatchMapping, PacketDescriptor, Pattern, RuleDescriptor
from microschc.rfc8724 import CompressionDecompressionAction as CDA


def compress(packet_descriptor: PacketDescriptor, rule_descriptor: RuleDescriptor) -> Tuple[bytes, int]:
    """
        Compress the packet fields following the rule's compression actions.
        See section 7.2 of [1].
    """
    schc_packet: bytes = b''
    schc_packet_length: int = 0

    rule_id: bytes = rule_descriptor.id
    rule_id_length: int = rule_descriptor.id_length

    schc_packet = _compact_left(buffer=schc_packet, buffer_length=schc_packet_length, bytefield=rule_id, bytefield_length=rule_id_length)
    schc_packet_length += rule_id_length

    packet_fields: List[FieldDescriptor] = []
    
    for header_descriptor in packet_descriptor.headers:
        header_fields: List[FieldDescriptor] = [FieldDescriptor(id=f.id, length=f.length, position=f.position, value=f.value )  for f in header_descriptor.fields]
        packet_fields += header_fields

    for pf, rf in zip(packet_fields, rule_descriptor.field_descriptors):
        field_residue: FieldResidue
        if rf.compression_decompression_action == CDA.NOT_SENT:
            continue
        elif rf.compression_decompression_action == CDA.LSB:
            assert isinstance(rf.target_value, Pattern)
            field_residue = least_significant_bits(field_descriptor=pf, match_pattern_length=rf.target_value.length)
        elif rf.compression_decompression_action == CDA.MAPPING_SENT:
            assert isinstance(rf.target_value, MatchMapping)
            field_residue = mapping_sent(field_descriptor=pf, mapping=rf.target_value)
        elif rf.compression_decompression_action == CDA.VALUE_SENT:
            field_residue = value_sent(field_descriptor=pf)

        if rf.compression_decompression_action in {CDA.LSB, CDA.VALUE_SENT} and rf.length == 0:
            encoded_length, encoded_length_length = _encode_length(field_residue.length)
            schc_packet = _compact_left(buffer=schc_packet, buffer_length=schc_packet_length, bytefield=encoded_length, bytefield_length=encoded_length_length)
            schc_packet_length += encoded_length_length

        schc_packet = _compact_left(buffer=schc_packet, buffer_length=schc_packet_length, bytefield=field_residue.residue, bytefield_length=field_residue.length)
        schc_packet_length += field_residue.length
    
    return schc_packet, schc_packet_length

def _encode_length(length:int) -> Tuple[bytes, int]:
    '''
    Encode the length value following instructions in section 7.4.2 of [1].
    '''
    encoded_length_value: bytes
    encoded_length_length: int
    assert length < 2**16
    if length < 15:
        encoded_length_value = length.to_bytes(1, 'big')
        encoded_length_length = 4
    elif length < 255:
        encoded_length_value = b'\x0f' + length.to_bytes(1, 'big')
        encoded_length_length = 12
    else:
        encoded_length_value = b'\x0f\xff' + length.to_bytes(2, 'big')
        encoded_length_length = 28
    return (encoded_length_value, encoded_length_length)

def _compact_left(buffer: bytes, buffer_length:int, bytefield: bytes, bytefield_length: int) -> bytes:
    '''
    concatenate buffer and bytefield after removing leading zero-padding
    '''
    buffer_offset: int = buffer_length % 8
    bytefield_offset: int = - bytefield_length % 8

    last_byte: int = buffer[-1] if len(buffer) > 0 else 0
    
    bytefield_aligned: bytes = b''

    # need realignment of bytefield
    if bytefield_offset != buffer_offset:
        # need realignment of bytefield
        if buffer_offset > bytefield_offset:
            # bytefield is shifted right
            shift: int = buffer_offset - bytefield_offset
            shift_complement: int = 8 - shift 
            bytefield_aligned = ((bytefield[-1] << shift_complement) & 0xff).to_bytes(1, 'big')

            # note: bytefields provided by the parser are zero-padded on the left (right-packed)
            bitmask: int = 0xff >> shift_complement

            for i in range(len(bytefield)-1, 0, -1):
                right_part:int = bytefield[i] >> shift
                left_part:int = (bytefield[i-1] << shift_complement)& 0xff
                bytefield_aligned = (left_part + right_part).to_bytes(1, 'big') + bytefield_aligned
            bytefield_aligned = (bytefield[0] >> shift).to_bytes(1, 'big') + bytefield_aligned
        else:
            # bytefield is shifted left
            shift: int = bytefield_offset - buffer_offset
            shift_complement: int = 8 - shift
            #bitmask: int = (0xff << shift_complement)
            for i in range(len(bytefield)-1):
                bytefield_aligned += (((bytefield[i] << shift) & 0xff) + (bytefield[i+1] >> shift_complement)).to_bytes(1, 'big')
            bytefield_aligned += ((bytefield[-1] << shift) & 0xff).to_bytes(1, 'big')
    else:
        # no need for realignment
        bytefield_aligned = bytefield

    if buffer_offset == 0:
        buffer += bytefield_aligned
    else:
        buffer = buffer[0:-1] + (last_byte + bytefield_aligned[0]).to_bytes(1, 'big') + bytefield_aligned[1:]

    return buffer