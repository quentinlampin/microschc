'''
Implementation SCHC packet compression as described in section 7.2 of [1].

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
'''

from typing import List
from microschc.actions.compression import least_significant_bits, mapping_sent, value_sent
from microschc.binary.buffer import Buffer, Padding
from microschc.rfc8724 import FieldDescriptor, MatchMapping, PacketDescriptor, RuleDescriptor, RuleFieldDescriptor, RuleNature
from microschc.rfc8724 import CompressionDecompressionAction as CDA
from microschc.rfc8724 import DirectionIndicator as DI


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
        # Filter rule fields by direction
        matching_fields: List[RuleFieldDescriptor] = [
            rf for rf in rule_descriptor.field_descriptors
            if rf.direction == packet_descriptor.direction or rf.direction == DI.BIDIRECTIONAL
        ]

        for pf, rf in zip(packet_fields, matching_fields):
            field_residue: Buffer
            if rf.compression_decompression_action in {CDA.NOT_SENT, CDA.COMPUTE}:
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
        schc_packet += packet_descriptor.raw

    return schc_packet

def _encode_length(length_bits:int) -> Buffer:
    '''
    Encode the length value following instructions in section 7.4.2 of [1], in bytes.
    '''
    encoded_length_value: bytes
    encoded_length_bit_length: int
    assert length_bits < 2**16
    assert length_bits % 8 == 0
    length_bytes = length_bits // 8
    if length_bytes < 15:
        encoded_length_value = length_bytes.to_bytes(1, 'big')
        encoded_length_bit_length = 4
    elif length_bytes < 255:
        encoded_length_value = b'\x0f' + length_bytes.to_bytes(1, 'big')
        encoded_length_bit_length = 12
    else:
        encoded_length_value = b'\x0f\xff' + length_bytes.to_bytes(2, 'big')
        encoded_length_bit_length = 28
    return Buffer(content=encoded_length_value, length=encoded_length_bit_length)