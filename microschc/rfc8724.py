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
    field_descriptors: List[RuleFieldDescriptor]

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id.__json__(),
            'field_descriptors': [ field_descriptor.__json__() for field_descriptor in self.field_descriptors]
        }
        return jsonisable

    def json(self, indent=None, separators=None) -> str:
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        return RuleDescriptor(
            id=Buffer.__from_json_object__(json_object['id']),
            field_descriptors=[RuleFieldDescriptor.__from_json_object__(rfd_json) for rfd_json in json_object['field_descriptors']],
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return RuleDescriptor.__from_json_object__(json_object=json_object)

@dataclass
class Context:
    id: str
    description: str
    interface_id: str
    ruleset: List[RuleDescriptor]

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id,
            'description': self.description,
            'interface_id': self.interface_id,
            'ruleset': [ rule_field_descriptor.__json__() for rule_field_descriptor in self.ruleset ]
        }
        return jsonisable

    def json(self, indent=None, separators=None) -> str:
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object):
        return Context(
            id=json_object['id'],
            description=json_object['description'],
            interface_id=json_object['interface_id'],
            ruleset=[RuleDescriptor.__from_json_object__(rd_json) for rd_json in json_object['ruleset']],
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return Context.__from_json_object__(json_object=json_object)