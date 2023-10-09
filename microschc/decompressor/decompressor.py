'''
Implementation SCHC packet decompression as described in section 7.2 of [1].

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
'''

from functools import cmp_to_key, reduce
from typing import Dict, List, Set, Tuple
from microschc.binary.buffer import Buffer, Padding
from microschc.protocol import ComputeFunctions
from microschc.protocol.compute import ComputeFunctionType
from microschc.rfc8724 import RuleFieldDescriptor, MatchMapping, RuleDescriptor
from microschc.rfc8724 import CompressionDecompressionAction as CDA

class ComputeEntry:
    field_position: int
    field_id: str
    function: ComputeFunctionType
    dependencies: Set[str]

    def __init__(self, field_position: int, field_id: str, function:ComputeFunctionType, dependencies: Set[str]) -> None:
        self.field_position = field_position
        self.field_id = field_id
        self.function = function
        self.dependencies = dependencies

def compute_function_sort(entry_1: ComputeEntry, entry_2: ComputeEntry) -> int:
    if entry_1.field_id in entry_2.dependencies:
        return -1
    if entry_2.field_id in entry_1.dependencies:
        return 1
    return entry_1.field_position - entry_2.field_position



def decompress(schc_packet: Buffer, rule_descriptor: RuleDescriptor) -> Buffer:
    """
        Decompress the packet fields following the rule's compression actions.
        See section 7.2 of [1].
    """
    compute_entries: List[ComputeEntry] = []

    decompressed_fields: List[Tuple(str, Buffer)] = []

    # remove rule ID
    schc_packet = schc_packet[rule_descriptor.id.length:]

    # decompress all fields
    field_residue: Buffer
    residue_bitlength: int
    decompressed_field: Buffer
    for rf_position, rf in enumerate(rule_descriptor.field_descriptors):
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
        elif rf.compression_decompression_action == CDA.COMPUTE:
            # add a placeholder for the decompressed field and add the decompression action to the LIFO queue
            field_length: int = rf.length
            decompressed_field: Buffer = Buffer(content=bytes(1+field_length//8), length=field_length)

            # retrieve compute dependencies
            compute_function, compute_dependencies = ComputeFunctions[field_id]
            compute_entry: ComputeEntry = ComputeEntry(
                field_position=rf_position,
                field_id=rf.id,
                function=compute_function,
                dependencies_set=compute_dependencies
            )
            compute_entries.append(compute_entry)
        
        decompressed_fields.append((rf.id, decompressed_field))
        
        schc_packet = schc_packet[residue_bitlength:]

    # sort compute CDA entries according 
    compute_entries.sort(key=cmp_to_key(compute_function_sort))

    # execute compute function in the reverse order of their position in the packet
    for compute_entry in compute_entries:
        field_id: str = compute_entry.field_id
        field_position: int = compute_entry.field_position
        compute_function: ComputeFunctionType = compute_entry.function        
        decompressed_fields[field_position] = compute_function(decompressed_fields, field_position)

    # concatenate decompressed fields
    decompressed_field_values = [field_value for field_id, field_value in decompressed_fields]
    decompressed: Buffer = reduce(lambda x, y: x+y, decompressed_field_values, Buffer(content=b'', length=0))
    # concatenate the rest of the SCHC payload
    decompressed += schc_packet

    return decompressed