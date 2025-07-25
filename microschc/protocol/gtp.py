"""
GTPv2-U header parser

Parser for the CoGTPv2-UAP protocol header as defined in 3GPP TS 29.274 [1].

[1] "3GPP TS 29.274: Universal Mobile Telecommunications System (UMTS);LTE;3GPP Evolved Packet System (EPS);Evolved General Packet Radio Service (GPRS)Tunnelling Protocol for Control plane (GTPv2-C);Stage 3(3GPP TS 29.274 version 8.12.0 Release 8) "
[2] "3GPP TS 29.276: Evolved Packet System (EPS); Optimized handover procedures and protocols between E-UTRAN access and cdma2000 HRPD Access; Stage 3 (3GPP TS 29.276 version 15.0.0 Release 15) https://www.etsi.org/deliver/etsi_ts/129200_129299/129276/15.00.00_60/ts_129276v150000p.pdf"
[3] "3GPP TS 29.060: Universal Mobile Telecommunications System (UMTS); General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP)across the Gn and Gp interface : https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf
[2] "https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol#GTP-U_-_GTP_user_data_tunneling"
"""

from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser, ParserError
from microschc.protocol.registry import REGISTER_PARSER, ProtocolsIDs
from microschc.rfc8724 import HeaderDescriptor

from microschc.protocol.gtp_v1 import GTPv1Parser
from microschc.protocol.gtp_v2 import GTPv2Parser

"""
Header V1
 0                                                                       1                   2                   3
 0 1 2     3           4           5           6           7         8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version | Protocol  | Reserved  | Extension | Sequence  | N-PDU   |   Message     |     Message Length            |
|         |  Type     |           |  Header   |  Number   | Number  |    Type       |                               |
|         |           |           |   Flag    |   Flag    | Flag    |               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                 TEID (only if T=1)                                                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sequence Number                                          |    N_PDU      | Next extension|
|                                                                                   |    Number     |   header type |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Next Extention Header (v1)
 0                       1                   2                   3
 0 1 2 3 4 5 6 7     8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Extention Length  | Contents                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ...                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ...                                               | Next extension|
|                                                   |   header type |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Header V2
 0                                             1                   2                   3
 0 1 2     3                4      5 6 7   8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version | Piggybacking  | TEID  | Spare | Message Type  |       Message Length          |
|         |  flag(P)      |flag(T)|       |               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                 TEID (only if T=1)                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Sequence Number                                |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



"""

GTP_HEADER_ID = 'GTP'

class GtpParser(HeaderParser):

    def __init__(self, predict_next:bool=False, ) -> None:
        super().__init__(name=GTP_HEADER_ID, predict_next=predict_next)
       

    def match(self, buffer: Buffer) -> bool:
        return (buffer.length >= 32)

    def parse(self, buffer: Buffer) -> HeaderDescriptor:

        if buffer.length < 64:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 64')

        # version: 3 bits
        version: Buffer = buffer[0:3]

        if version.value() == 1:
            parser = GTPv1Parser(self.predict_next)
        elif version.value() == 2:
            parser = GTPv2Parser(self.predict_next)
        else:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 64')
        
        header_descriptor = parser.parse(buffer)
        return header_descriptor
    

REGISTER_PARSER(protocol_id=ProtocolsIDs.GTP, parser_class=GtpParser)
