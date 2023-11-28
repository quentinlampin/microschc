"""
definitions of data models and literals mentioned in RFC 8724 [1] but not specified.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from dataclasses import dataclass
from enum import Enum
import json
from typing import List

from microschc.rfc8724 import RuleDescriptor


class ParserDefinitions(str, Enum): 
    PAYLOAD = 'Payload'


@dataclass
class Context:
    id: str
    description: str
    interface_id: str
    parser_id: str
    ruleset: List[RuleDescriptor]

    def __repr__(self) -> str:
        content_repr:str = f"id:{self.id} description:{self.description} interface_id: {self.interface_id} parser_id: {self.parser_id} rules: {len(self.ruleset)}"
        return content_repr

    def __json__(self) -> dict:
        jsonisable: dict = {
            'id': self.id,
            'description': self.description,
            'interface_id': self.interface_id,
            'parser_id': self.parser_id,
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
            parser_id=json_object['parser_id'],
            ruleset=[RuleDescriptor.__from_json_object__(rd_json) for rd_json in json_object['ruleset']],
        )

    def from_json(json_str: str):
        json_object = json.loads(json_str)
        return Context.__from_json_object__(json_object=json_object)