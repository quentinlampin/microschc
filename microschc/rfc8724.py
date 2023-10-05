"""
definitions from RFC 8724 [1] and corresponding data models.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from enum import Enum
from dataclasses import dataclass
import json
from typing import  Dict, List, Union

from microschc.binary.buffer import Buffer

ReverseMapping = Dict[Buffer, Buffer]
Mapping = Dict[Buffer, Buffer]


class MatchMapping:
    def __init__(self, forward_mapping: Mapping):
        self.forward: Mapping = forward_mapping
        self.reverse: ReverseMapping = {v: k for k, v in self.forward.items()}

    def __json__(self) -> list:
        json_object: list = [{'index': k.__json__(), 'value': v.__json__()} for k, v in self.reverse.items()]
        return json_object
    
    def __repr__(self) -> str:
        repr: str = "{" + ",".join([f"{k}:{v}" for k,v in self.reverse.items()]) + "}"
        return repr
    
    def json(self, indent=None, separators=None):
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        forward: Mapping = {}
        for entry in json_object:
            index: Buffer = Buffer.__from_json_object__(entry['index'])
            value: Buffer = Buffer.__from_json_object__(entry['value'])
            forward[value] = index
        return MatchMapping(forward_mapping=forward)

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        match_mapping: MatchMapping = MatchMapping.__from_json_object__(json_object=json_object)
        return match_mapping


TargetValue = Union[Buffer, MatchMapping]

class DirectionIndicator(str, Enum):
    UP = 'Up'
    DOWN = 'Dw'
    BIDIRECTIONAL = 'Bi'


class MatchingOperator(str, Enum):
    EQUAL = 'equal'
    IGNORE = 'ignore'
    MSB = 'MSB'
    MATCH_MAPPING = 'match-mapping'


class CompressionDecompressionAction(str, Enum):
    NOT_SENT = 'not-sent'
    LSB = 'least-significant-bits'
    MAPPING_SENT = 'mapping-sent'
    VALUE_SENT = 'value-sent'
    COMPUTE = 'compute'

class RuleNature(str, Enum):
    COMPRESSION = 'compression'
    NO_COMPRESSION = 'no-compression'
    FRAGMENTATION = 'fragmentation'

DI = DirectionIndicator
MO = MatchingOperator
CDA = CompressionDecompressionAction

@dataclass
class FieldDescriptor:
    id: str
    value: Buffer
    position: int

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id,
            'value': self.value.__json__(),
            'position': self.position
        }
        return jsonisable
    
    def __repr__(self) -> str:
        return f"[{self.id}|{self.value}]"

    def json(self, indent=None, separators=None):
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        return FieldDescriptor(
            id=json_object['id'],
            value=Buffer.__from_json_object__(json_object=json_object['value']),
            position=json_object['position']
        )


    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return FieldDescriptor.__from_json_object__(json_object=json_object)

@dataclass
class HeaderDescriptor:
    id: str
    length: int
    fields: List[FieldDescriptor]

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id,
            'length': self.length,
            'fields': [ field.__json__() for field in self.fields]
        }
        return jsonisable
    
    def json(self, indent=None, separators=None):
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        return HeaderDescriptor(
            id=json_object['id'],
            length=json_object['length'],
            fields=[FieldDescriptor.__from_json_object__(fd_json) for fd_json in json_object['fields']]
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return HeaderDescriptor.__from_json_object__(json_object=json_object)

@dataclass
class PacketDescriptor:
    direction: DirectionIndicator
    fields: List[FieldDescriptor]
    payload: Buffer
    length: int

    def __repr__(self):
        fields_str: str = ','.join([str(field) for field in self.fields])
        repr: str = f"[{self.direction}|{fields_str}]"
        return repr

    def __json__(self) -> dict:
        jsonisable: dict = {
            'direction': self.direction,
            'fields': [ field.__json__() for field in self.fields],
            'payload': self.payload.__json__(),
            'length': self.length
        }
        return jsonisable

    def json(self, indent=None, separators=None):
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        return PacketDescriptor(
            direction=json_object['direction'],
            fields=[FieldDescriptor.__from_json_object__(fd_json) for fd_json in json_object['fields']],
            payload=Buffer.__from_json_object__(json_object['payload']),
            length=json_object['length']
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return PacketDescriptor.__from_json_object__(json_object=json_object)


@dataclass
class RuleFieldDescriptor:
    id: str
    length: int
    position: int
    direction: DirectionIndicator
    target_value: TargetValue
    matching_operator: MatchingOperator
    compression_decompression_action: CompressionDecompressionAction

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RuleFieldDescriptor):
            return False
        if other.id != self.id or \
            other.length != self.length or \
            other.position != self.position or \
            other.direction != self.direction or \
            other.target_value != self.target_value or \
            other.matching_operator != self.matching_operator or \
            other.compression_decompression_action != self.compression_decompression_action:
            return False
        return True


    def __repr__(self) -> str:
        mo_to_short_str: Dict[str,str] = {MO.EQUAL:'eq', MO.IGNORE:'ig', MO.MATCH_MAPPING:'ma', MO.MSB:'ms'}
        cda_to_short_str: Dict[str,str] = {CDA.NOT_SENT:'ns', CDA.VALUE_SENT:'vs', CDA.MAPPING_SENT:'ma', CDA.LSB:'ls'}
        repr: str = "{"+f"{self.id}({self.length}):{mo_to_short_str[self.matching_operator]}/{cda_to_short_str[self.compression_decompression_action]}|{self.target_value}"+"}"
        return repr

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id,
            'length': self.length,
            'position': self.position,
            'direction': self.direction,
            'target_value': self.target_value.__json__(),
            'matching_operator': self.matching_operator,
            'compression_decompression_action': self.compression_decompression_action
        }
        return jsonisable

    def json(self, indent=None, separators=None):
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        target_value: TargetValue
        if json_object['compression_decompression_action'] == CompressionDecompressionAction.MAPPING_SENT:
            target_value = MatchMapping.__from_json_object__(json_object=json_object['target_value'])
        else:
            target_value = Buffer.__from_json_object__(json_object=json_object['target_value'])

        return RuleFieldDescriptor(
            id=json_object['id'],
            length=json_object['length'],
            position=json_object['position'],
            direction=json_object['direction'],
            target_value=target_value,
            matching_operator=json_object['matching_operator'],
            compression_decompression_action=json_object['compression_decompression_action']
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return RuleFieldDescriptor.__from_json_object__(json_object=json_object)
    

@dataclass
class RuleDescriptor:
    id: Buffer
    nature: RuleNature
    field_descriptors: List[RuleFieldDescriptor]

    def __init__(self, id:Buffer, nature:RuleNature=RuleNature.COMPRESSION, field_descriptors:List[RuleFieldDescriptor]=[]):
        self.id = id
        self.nature = nature
        self.field_descriptors=field_descriptors

    def __repr__(self) -> str:
        if self.nature is RuleNature.COMPRESSION:
            repr: str = f"[{self.id}]({len(self.field_descriptors)}) {'|'.join(str(rfd) for rfd in self.field_descriptors)}"
        elif self.nature is RuleNature.NO_COMPRESSION:
            repr: str = f"[{self.id}] no_compression"
        elif self.nature is RuleNature.FRAGMENTATION:
            raise NotImplementedError('Fragmentation/Reassembly is not implemented')
        return repr

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id.__json__(),
            'nature': self.nature.value,
        }
        if self.nature is RuleNature.COMPRESSION:
            jsonisable['field_descriptors'] = [ field_descriptor.__json__() for field_descriptor in self.field_descriptors]

        elif self.nature is RuleNature.NO_COMPRESSION:
            pass

        elif self.nature is RuleNature.FRAGMENTATION:
            raise NotImplementedError('Fragmentation/Reassembly is not implemented')
        
        return jsonisable

    def json(self, indent=None, separators=None) -> str:
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        if json_object['nature'] == RuleNature.COMPRESSION.value:
            field_descriptors = [RuleFieldDescriptor.__from_json_object__(rfd_json) for rfd_json in json_object['field_descriptors']]
            return RuleDescriptor(
                id=Buffer.__from_json_object__(json_object['id']),
                nature=RuleNature.COMPRESSION,
                field_descriptors=field_descriptors,
            )
        elif json_object['nature'] == RuleNature.NO_COMPRESSION.value:
            return RuleDescriptor(
                id=Buffer.__from_json_object__(json_object['id']),
                nature=RuleNature.NO_COMPRESSION,
            )
        else:
            raise NotImplementedError('Fragmentation/Reassembly is not implemented')
        

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return RuleDescriptor.__from_json_object__(json_object=json_object)
