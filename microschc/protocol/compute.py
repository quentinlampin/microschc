from typing import Set
from typing import Callable, Dict, List, Tuple
from microschc.binary.buffer import Buffer

ComputeFunctionType = Callable[[List[Tuple[str, Buffer]], int], Buffer]
ComputeFunctionDependenciesType = Set[str]