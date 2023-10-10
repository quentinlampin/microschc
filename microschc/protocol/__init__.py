from typing import Callable, Dict, List, Tuple

from microschc.binary import Buffer
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType


from .ipv6 import IPv6ComputeFunctions, IPv6Fields
from .udp import UDPComputeFunctions, UDPFields

ComputeFunctions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]] = {
    IPv6Fields.PAYLOAD_LENGTH: IPv6ComputeFunctions[IPv6Fields.PAYLOAD_LENGTH],
    UDPFields.LENGTH: UDPComputeFunctions[UDPFields.LENGTH],
    UDPFields.CHECKSUM: UDPComputeFunctions[UDPFields.CHECKSUM]
}



