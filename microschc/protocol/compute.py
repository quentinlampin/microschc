from typing import Dict

from microschc.protocol import ComputeFunctionType

from .ipv6 import IPv6ComputeFunctions, IPv6Fields
from .udp import UDPComputeFunctions, UDPFields

ComputeFunctions: Dict[str, ComputeFunctionType] = {
    IPv6Fields.PAYLOAD_LENGTH: IPv6ComputeFunctions[IPv6Fields.PAYLOAD_LENGTH],
    UDPFields.LENGTH: UDPComputeFunctions[UDPFields.LENGTH]
}