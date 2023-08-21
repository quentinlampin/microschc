'''
Implementation SCHC packet compression as described in section 7.2 of [1].

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
'''

from typing import List, Tuple
from microschc.actions.compression import least_significant_bits, mapping_sent, value_sent
from microschc.binary.buffer import Buffer, Padding
from microschc.rfc8724 import FieldDescriptor, MatchMapping, PacketDescriptor, RuleDescriptor, RuleNature
from microschc.rfc8724 import CompressionDecompressionAction as CDA


def compress(packet_descriptor: PacketDescriptor, rule_descriptor: RuleDescriptor) -> Buffer:
    """
        Compress the packet fields following the rule's compression actions.
        See section 7.2 of [1].
    """
    schc_packet: Buffer = Buffer(content=b'', length=0, padding=Padding.RIGHT)

    rule_id: Buffer = rule_descriptor.id

    schc_packet += rule_id

    packet_fields: List[FieldDescriptor] = packet_descriptor.fields

    if rule_descriptor.nature is RuleNature.COMPRESSION:

        for pf, rf in zip(packet_fields, rule_descriptor.field_descriptors):
            field_residue: Buffer
            if rf.compression_decompression_action == CDA.NOT_SENT:
                continue
            elif rf.compression_decompression_action == CDA.LSB:
                assert isinstance(rf.target_value, Buffer)
                field_residue = least_significant_bits(field_descriptor=pf, bit_length=pf.value.length - rf.target_value.length)
            elif rf.compression_decompression_action == CDA.MAPPING_SENT:
                assert isinstance(rf.target_value, MatchMapping)
                field_residue = mapping_sent(field_descriptor=pf, mapping=rf.target_value)
            elif rf.compression_decompression_action == CDA.VALUE_SENT:
                field_residue = value_sent(field_descriptor=pf)

            if rf.compression_decompression_action in {CDA.LSB, CDA.VALUE_SENT} and rf.length == 0:
                encoded_length: Buffer = _encode_length(field_residue.length)
                schc_packet += encoded_length

            schc_packet += field_residue
        
        schc_packet += packet_descriptor.payload

    elif rule_descriptor.nature is RuleNature.NO_COMPRESSION:
        for pf in packet_fields:
            schc_packet += value_sent(field_descriptor=pf)

        schc_packet += packet_descriptor.payload

    return schc_packet

def _encode_length(length:int) -> Buffer:
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
    return Buffer(content=encoded_length_value, length=encoded_length_length)