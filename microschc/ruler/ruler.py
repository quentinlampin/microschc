"""
The Ruler

The ruler implements the logic around rules as defined in RFC 8724 [1], i.e.:
    - rule storing: manages a collection of rules.
    - rule matching: determine if a rule applies to a packet descriptor.
    - packet compression: compress packets according to matching rules.
    - packet decompression: decompress packets according to rules IDs.

**Important note**: the field descriptors of a rule are supposed to be in the same order than that of targeted packets.
The objective is that compression residues appear in the same order as corresponding headers in the source packets such that
the order of decompressed fields at the recompression is unambiguous.

[1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from typing import List
from microschc.binary.buffer import Buffer
from microschc.matching.operators import equal, ignore, match_mapping, most_significant_bits

from microschc.rfc8724 import DirectionIndicator, FieldDescriptor, MatchMapping, MatchingOperator, PacketDescriptor, RuleDescriptor, RuleFieldDescriptor, TargetValue


class Ruler:

    def __init__(self, rules_descriptors: List[RuleDescriptor]) -> None:
        self.rules: List[RuleDescriptor] = rules_descriptors

    def match_packet_descriptor(self, packet_descriptor: PacketDescriptor) -> RuleDescriptor:
        """
        Find a rule matching the packet descriptor
        """
        packet_fields: List[FieldDescriptor] = packet_descriptor.fields
        packet_direction: DirectionIndicator = packet_descriptor.direction

        for rule in self.rules[0:-1]:
            
            # rules field descriptors and IDs that apply to packet direction
            rule_fields: List[RuleFieldDescriptor] = [f for f in filter(lambda f: f.direction in {packet_direction, DirectionIndicator.BIDIRECTIONAL}, rule.field_descriptors)]
            # TODO: implement alternative algorithm for mandatory/optional fields

            # sanity check: both lists are of the same size
            if len(packet_fields) != len(rule_fields):
                break

            # assert that the list of packet fields matches that of rule fields
            if any(_field_match(packet_field=pf, rule_field=rf) == False for (pf, rf) in zip(packet_fields, rule_fields)):
                break

            # rule matches, return it
            return rule
        # if no rule matches, use the default
        return self.rules[-1]
    
    def match_schc_packet(self, schc_packet: Buffer) -> RuleDescriptor:
        '''
        find a rule matching the rule ID of a SCHC packet
        '''
        matching_rule: RuleFieldDescriptor
        # iterate though rules and try matching the rule ID with SCHC packet beginning
        for rule in self.rules:
            rule_id: Buffer = rule.id
            if rule_id.length > schc_packet.length:
                continue
            if rule_id == schc_packet[0:rule_id.length]:
                return rule
        
        # if no rule matched, return default
        return self.rules[-1]


def _field_match(packet_field: FieldDescriptor, rule_field: RuleFieldDescriptor):
    # basic test: field IDs and length match
    # note: with the assumption of the ordering of field descriptors in rules, the position test is unnecessary
    if packet_field.id != rule_field.id :
        return False
    # check with the Matching Operator (MO) of the rule field
    if rule_field.matching_operator == MatchingOperator.IGNORE:
        return ignore(packet_field)

    elif rule_field.matching_operator == MatchingOperator.EQUAL:
        assert isinstance(rule_field.target_value, Buffer)
        return packet_field.value == rule_field.target_value

    elif rule_field.matching_operator == MatchingOperator.MSB:
        pattern: TargetValue = rule_field.target_value
        if (rule_field.length != packet_field.value.length):
            return False
        assert isinstance(pattern, Buffer)
        return most_significant_bits(packet_field, pattern=pattern)

    elif rule_field.matching_operator == MatchingOperator.MATCH_MAPPING:
        mapping: TargetValue = rule_field.target_value
        assert isinstance(mapping, MatchMapping)
        return match_mapping(packet_field, target_values=mapping)
