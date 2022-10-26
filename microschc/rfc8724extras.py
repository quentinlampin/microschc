"""
definitions of literals described in RFC 8724 [1] whose values are not specified.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""


from enum import Enum


class StacksImplementation(str, Enum):
    IPV6_UDP_COAP = 'IPv6-UDP-CoAP'

class ParserDefinitions(str, Enum): 
    PAYLOAD = 'Payload'