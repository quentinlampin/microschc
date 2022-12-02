'''
Implementation SCHC packet decompression as described in section 7.2 of [1].

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
'''

from microschc.binary.buffer import Buffer, Padding
from microschc.rfc8724 import DirectionIndicator, MatchMapping, RuleDescriptor
from microschc.rfc8724 import CompressionDecompressionAction as CDA



def decompress(schc_packet: Buffer, direction: DirectionIndicator, rule: RuleDescriptor) -> Buffer:
    """
        Decompress the packet fields following the rule's compression actions.
        See section 7.2 of [1].
    """
    decompressed: Buffer = Buffer(content=b'', length=0,padding=Padding.RIGHT)

    # remove rule ID
    schc_packet = schc_packet[rule.id.length:]

    # decompress all fields
    field_residue: Buffer
    residue_bitlength: int
    decompressed_field: Buffer
    for rf in rule.field_descriptors:
        residue_bitlength = 0
        decompressed_field = Buffer(content=b'', length=0, padding=Padding.RIGHT)
        if rf.compression_decompression_action == CDA.NOT_SENT:
            decompressed_field += rf.target_value
        elif rf.compression_decompression_action == CDA.LSB:
            assert isinstance(rf.target_value, Buffer)
            lsb_bitlength: int = rf.length-rf.target_value.length
            field_residue = schc_packet[:lsb_bitlength]
            decompressed_field += rf.target_value
            decompressed_field += field_residue
            residue_bitlength = lsb_bitlength
        elif rf.compression_decompression_action == CDA.MAPPING_SENT:
            assert isinstance(rf.target_value, MatchMapping)
            for key, value in rf.target_value.reverse.items():
                if key == schc_packet[0:key.length]:
                    field_residue = key
                    decompressed_field += value
                    residue_bitlength = key.length
                    break
        elif rf.compression_decompression_action == CDA.VALUE_SENT:
            assert isinstance(rf.target_value, Buffer)
            if rf.length != 0:
                field_residue = schc_packet[0:rf.length]
                decompressed_field += field_residue
                residue_bitlength = rf.length
            else:
                # variable field encoded length
                length_buffer: Buffer = schc_packet[0:4]
                length_buffer.pad(padding=Padding.LEFT, inplace=True)
                encoded_length_value: int = int.from_bytes(length_buffer.content, 'big')
                if encoded_length_value < 15:
                    decompressed_field += schc_packet[4:4+encoded_length_value]
                    residue_bitlength = 4 + encoded_length_value
                else:
                    length_buffer = schc_packet[4:12]
                    length_buffer.pad(padding=Padding.LEFT, inplace=True)
                    encoded_length_value: int = int.from_bytes(length_buffer.content, 'big')
                    if encoded_length_value < 255:
                        decompressed_field += schc_packet[12:12+encoded_length_value]
                        residue_bitlength = 12 + encoded_length_value
                    else:
                        length_buffer = schc_packet[12:28]
                        length_buffer.pad(padding=Padding.LEFT, inplace=True)
                        encoded_length_value: int = int.from_bytes(length_buffer.content, 'big')
                        decompressed_field += schc_packet[28:28+encoded_length_value]
                        residue_bitlength = 28 + encoded_length_value
        
        decompressed += decompressed_field

        schc_packet = schc_packet[residue_bitlength:]

    # concatenate the rest of the SCHC payload
    decompressed += schc_packet


    return decompressed



    

    # encoded_length_value: bytes
    # encoded_length_length: int
    # assert length < 2**16
    # if length < 15:
    #     encoded_length_value = length.to_bytes(1, 'big')
    #     encoded_length_length = 4
    # elif length < 255:
    #     encoded_length_value = b'\x0f' + length.to_bytes(1, 'big')
    #     encoded_length_length = 12
    # else:
    #     encoded_length_value = b'\x0f\xff' + length.to_bytes(2, 'big')
    #     encoded_length_length = 28
    # return Buffer(content=encoded_length_value, bit_length=encoded_length_length)