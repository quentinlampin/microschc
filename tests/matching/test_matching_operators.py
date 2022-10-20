from dataclasses import Field
from microschc.matching.operators import equal, ignore, most_significant_bits, match_mapping
from microschc.rfc8724 import FieldDescriptor

def test_equal():
    """test: equal matching operator
    The test instanciate an IPv6 parser and checks for import errors
    """
    FieldDescriptor: FieldDescriptor = FieldDescriptor()