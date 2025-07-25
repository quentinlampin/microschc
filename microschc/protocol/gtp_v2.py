"""
GTPv2 parser

Parser for the CoGTPv2-UAP protocol header as defined in 3GPP TS 29.274 [1].

[1] "3GPP TS 29.274: Universal Mobile Telecommunications System (UMTS);LTE;3GPP Evolved Packet System (EPS);Evolved General Packet Radio Service (GPRS)Tunnelling Protocol for Control plane (GTPv2-C);Stage 3(3GPP TS 29.274 version 8.12.0 Release 8): https://www.etsi.org/deliver/etsi_TS/129200_129299/129274/08.12.00_60/ts_129274v081200p.pdf "
[2] "3GPP TS 29.276: Evolved Packet System (EPS); Optimized handover procedures and protocols between E-UTRAN access and cdma2000 HRPD Access; Stage 3 (3GPP TS 29.276 version 15.0.0 Release 15) https://www.etsi.org/deliver/etsi_ts/129200_129299/129276/15.00.00_60/ts_129276v150000p.pdf"
[3] "3GPP TS 29.060: Universal Mobile Telecommunications System (UMTS); General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP)across the Gn and Gp interface : https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf
"""


from microschc.compat import StrEnum
from typing import List, Tuple, Callable
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser, ParserError

from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


"""
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

GTP_HEADER_ID = 'GTPv2'

class GTPv2Fields(StrEnum):
    VERSION                 = f'{GTP_HEADER_ID}:Version'
    # header v2
    PIGGYBACKING_FLAG       = f'{GTP_HEADER_ID}:Piggybacking Flag'
    TEID_FLAG               = f'{GTP_HEADER_ID}:TEID Flag'
    SPARE                   = f'{GTP_HEADER_ID}:Spare'

    MESSAGE_TYPE            = f'{GTP_HEADER_ID}:Message Type'    
    MESSAGE_LENGTH          = f'{GTP_HEADER_ID}:Message Length'
    TEID                    = f'{GTP_HEADER_ID}:TEID'
    SEQUENCE_NUMBER         = f'{GTP_HEADER_ID}:Sequence Number'

    INFORMATION_ELEMENT     = f'{GTP_HEADER_ID}:Information Element'
    IE_TYPE                 = f'{INFORMATION_ELEMENT}:Type'
    IE_LENGTH               = f'{INFORMATION_ELEMENT}:Length'
    IE_SPARE                = f'{INFORMATION_ELEMENT}:Spare'
    IE_INSTANCE             = f'{INFORMATION_ELEMENT}:Instance'
    IE_CONTENT              = f'{INFORMATION_ELEMENT}:Content'

GTPv2MessageType = {
    1 : "Echo Request",
    2 : "Echo Response",
    3 : "Version Not Supported",
    # 4-16: S101 interface, TS 29.276.
    4 : "Direct Transfer Request message",
    5 : "Direct Transfer Response message",
    6 : "Notification Request message",
    7 : "Notification Response message",
    # 8-16 For future S101 interface use

    # 17-24: S121 interface, TS 29.276.
    17 : "RIM Information Transfer",
    #18-24 For future S121 interface use

    # 25-31: Sv interface, TS 29.280.
    25 : "SRVCC PS to CS Request",
    26 : "SRVCC PS to CS Response",
    27 : "SRVCC PS to CS Complete Notification",
    28 : "SRVCC PS to CS Complete Acknowledge",
    29 : "SRVCC PS to CS Cancel Notification",
    30 : "SRVCC PS to CS Cancel Acknowledge",
    31 : "SRVCC CS to PS Request",

    # SGSN/MME/ TWAN/ePDG to PGW (S4/S11, S5/S8, S2a, S2b)
    32: "create session req",
    33: "create session res",
    36: "delete session req",
    37: "delete session res",

    # SGSN/MME/ePDG to PGW (S4/S11, S5/S8, S2b)
    34: "modify bearer req",
    35: "modify bearer res",

    # MME to PGW (S11, S5/S8)
    40: "remote ue report notif",
    41: "remote ue report ack",

    # SGSN/MME to PGW (S4/S11, S5/S8)
    38: "change notif req",
    39: "change notif res",
    # 42-46: For future use.
    164: "resume notif",
    165: "resume ack",

    # Messages without explicit response
    64: "modify bearer cmd",
    65: "modify bearer failure indic",
    66: "delete bearer cmd",
    67: "delete bearer failure indic",
    68: "bearer resource cmd",
    69: "bearer resource failure indic",
    70: "downlink data notif failure indic",
    71: "trace session activation",
    72: "trace session deactivation",
    73: "stop paging indic",
    # 74-94: For future use.

    # PGW to SGSN/MME/ TWAN/ePDG (S5/S8, S4/S11, S2a, S2b)
    95: "create bearer req",
    96: "create bearer res",
    97: "update bearer req",
    98: "update bearer res",
    99: "delete bearer req",
    100: "delete bearer res",

    # PGW to MME, MME to PGW, SGW to PGW, SGW to MME, PGW to TWAN/ePDG,
    # TWAN/ePDG to PGW (S5/S8, S11, S2a, S2b)
    101: "delete pdn connection set req",
    102: "delete pdn connection set res",

    # PGW to SGSN/MME (S5, S4/S11)
    103: "pgw downlink triggering notif",
    104: "pgw downlink triggering ack",
    # 105-127: For future use.

    # MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN, MME to AMF,
    # AMF to MME (S3/S10/S16/N26)
    128: "identification req",
    129: "identification res",
    130: "context req",
    131: "context res",
    132: "context ack",
    133: "forward relocation req",
    134: "forward relocation res",
    135: "forward relocation complete notif",
    136: "forward relocation complete ack",
    137: "forward access context notif",
    138: "forward access context ack",
    139: "relocation cancel req",
    140: "relocation cancel res",
    141: "configuration transfer tunnel",
    # 142-148: For future use.
    152: "ran information relay",

    # SGSN to MME, MME to SGSN (S3)
    149: "detach notif",
    150: "detach ack",
    151: "cs paging indic",
    153: "alert mme notif",
    154: "alert mme ack",
    155: "ue activity notif",
    156: "ue activity ack",
    157: "isr status indic",
    158: "ue registration query req",
    159: "ue registration query res",

    # SGSN/MME to SGW, SGSN to MME (S4/S11/S3)
    # SGSN to SGSN (S16), SGW to PGW (S5/S8)
    162: "suspend notif",
    163: "suspend ack",

    # SGSN/MME to SGW (S4/S11)
    160: "create forwarding tunnel req",
    161: "create forwarding tunnel res",
    166: "create indirect data forwarding tunnel req",
    167: "create indirect data forwarding tunnel res",
    168: "delete indirect data forwarding tunnel req",
    169: "delete indirect data forwarding tunnel res",
    170: "realease bearers req",
    171: "realease bearers res",
    # 172-175: For future use

    # SGW to SGSN/MME (S4/S11)
    176: "downlink data notif",
    177: "downlink data notif ack",
    179: "pgw restart notif",
    180: "pgw restart notif ack",

    # SGW to SGSN (S4)
    # 178: Reserved. Allocated in earlier version of the specification.
    # 181-199: For future use.

    # SGW to PGW, PGW to SGW (S5/S8)
    200: "update pdn connection set req",
    201: "update pdn connection set res",
    # 202-210: For future use.

    # MME to SGW (S11)
    211: "modify access bearers req",
    212: "modify access bearers res",
    # 213-230: For future use.

    # MBMS GW to MME/SGSN (Sm/Sn)
    231: "mbms session start req",
    232: "mbms session start res",
    233: "mbms session update req",
    234: "mbms session update res",
    235: "mbms session stop req",
    236: "mbms session stop res",
    # 237-239: For future use.

    # Other
    # 240-247: Reserved for Sv interface (see also types 25 to 31, and
    #          TS 29.280).
    240 : "SRVCC CS to PS Response",
    241 : "SRVCC CS to PS Complete Notification",
    242 : "SRVCC CS to PS Complete Acknowledge",
    243 : "SRVCC CS to PS Cancel Notification",
    244 : "SRVCC CS to PS Cancel Acknowledge",
    # 248-255: For future use.
    }

def ie_parser_generic(
        content_length:int,
        buffer:Buffer,
        ie_type_id:str
) -> List[FieldDescriptor]:
    header_fields:List[FieldDescriptor] = [
        FieldDescriptor(id=ie_type_id, position=0, value=buffer[0:content_length])
    ]
    return header_fields

IEType = {
    1: ("IMSI",ie_parser_generic),
    2: ("Cause",ie_parser_generic),
    3: ("Recovery Restart",ie_parser_generic),
    71: ("APN",ie_parser_generic),
    72: ("AMBR",ie_parser_generic),
    73: ("EPS Bearer ID",ie_parser_generic),
    74: ("IP Address",ie_parser_generic),
    75: ("MEI",ie_parser_generic),
    76: ("MSISDN",ie_parser_generic),
    77: ("Indication",ie_parser_generic),
    78: ("Protocol Configuration Options",ie_parser_generic),
    79: ("PAA",ie_parser_generic),
    80: ("Bearer QoS",ie_parser_generic),
    81: ("Flow Quality of Service (Flow QoS)",ie_parser_generic),
    82: ("RAT",ie_parser_generic),
    83: ("Serving Network",ie_parser_generic),
    84: ("Bearer TFT",ie_parser_generic),
    85: ("Traffic Aggregation Description (TAD)",ie_parser_generic),
    86: ("ULI",ie_parser_generic),
    87: ("F-TEID",ie_parser_generic),
    88: ("TMSI",ie_parser_generic),
    89: ("Global CN-Id ",ie_parser_generic),
    90: ("S103 PDN Data Forwarding Info (S103PDF) ",ie_parser_generic),
    91: ("S1-U Data Forwarding Info (S1UDF) ",ie_parser_generic),
    92: ("Delay Value ",ie_parser_generic),
    93: ("Bearer Context",ie_parser_generic),
    94: ("Charging ID",ie_parser_generic),
    95: ("Charging Characteristics",ie_parser_generic),
    96: ("Trace Information ",ie_parser_generic),
    97: ("Bearer Flags",ie_parser_generic),
    # 98: reserved
    99: ("PDN Type",ie_parser_generic),
    100: ("PDN Type Procedure Transaction ID",ie_parser_generic),
    101: ("DRX Parameter",ie_parser_generic),
    102: ("UE Network Capability",ie_parser_generic),
    103: ("MM Context (GSM Key and Triplets)",ie_parser_generic),
    104: ("MM Context (UMTS Key, Used Cipher and Quintuplets)",ie_parser_generic),
    105: ("MM Context (GSM Key, Used Cipher and  Quintuplets) ",ie_parser_generic),
    106: ("MM Context (UMTS Key and Quintuplets)",ie_parser_generic),
    107: ("MM Context (EPS Security Context and Quadruplets)",ie_parser_generic),
    108: ("MM Context (UMTS Key, Quadruplets and Quintuplets)",ie_parser_generic),
    109: ("PDN Connection",ie_parser_generic),
    110: ("PDU Numbers",ie_parser_generic),
    111: ("P-TMSI Variable",ie_parser_generic),
    112: ("P-TMSI Signature",ie_parser_generic),
    113: ("Hop Counter Variable",ie_parser_generic),
    114: ("UE Time zone",ie_parser_generic),
    115: ("Trace Reference",ie_parser_generic),
    116: ("Complete Request Message",ie_parser_generic),
    117: ("GUTI",ie_parser_generic),
    118: ("F-Container",ie_parser_generic),
    119: ("F-Cause",ie_parser_generic),
    120: ("Selected PLMN ID",ie_parser_generic), 
    121: ("Target Identification",ie_parser_generic),
    # 122: Reserved
    123: ("Packet Flow ID",ie_parser_generic),
    124: ("RAB Context",ie_parser_generic),
    125: ("Source RNC PDCP Context",ie_parser_generic),
    126: ("Port Number",ie_parser_generic),
    127: ("APN Restriction",ie_parser_generic),
    128: ("Selection Mode",ie_parser_generic),
    129: ("Source Identification",ie_parser_generic),
    # 130: Reserved
    131: ("Change Reporting Action",ie_parser_generic), 
    132: ("FQ-CSID",ie_parser_generic),
    133: ("Channel needed",ie_parser_generic),
    134: ("eMLPP Priority",ie_parser_generic),
    135: ("Node Type",ie_parser_generic),
    136: ("Fully Qualified Domain Name (FQDN)",ie_parser_generic),
    137: ("Transaction Identifier (TI)",ie_parser_generic),

    144: ("RFSP Index",ie_parser_generic),
    145: ("UCI",ie_parser_generic),
    155: ("Allocation/Retention Priority (ARP)",ie_parser_generic),
    
    161: ("Max MBR/APN-AMBR (MMBR),",ie_parser_generic),
    163: ("Additional Protocol Configuration Options",ie_parser_generic),
    170: ("ULI Timestamp",ie_parser_generic),
    172: ("RAN/NAS Cause",ie_parser_generic),
    186: ("Paging and Service Information",ie_parser_generic),
    197: ("Extended Protocol Configuration Options",ie_parser_generic),
    202: ("UP Function Selection Indication Flags",ie_parser_generic),
    255: ("Private Extension",ie_parser_generic),
}

class GTPv2Parser(HeaderParser):

    def __init__(self, predict_next:bool=False, ) -> None:
        super().__init__(name=GTP_HEADER_ID, predict_next=predict_next)

    def parse(self, buffer: Buffer) -> HeaderDescriptor:
        """ parse gtp header v2
        Manage gtp v2 header
            0                                             1                   2                   3
            0 1 2     3                4      5 6 7   8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Version | Piggybacking  | TEID  | Spare | Message Type  |       Message Length          |
            |         |  flag(P)      |flag(T)|       |               |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                 TEID (only if T=1)                                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                          Sequence Number                                |  Spare        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        Args:
            buffer (Buffer): the binary buffer

        Returns:
            HeaderDescriptor: 
        """
        
        if buffer.length < 64:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 64')
       
        # version: 3 bits
        version: Buffer = buffer[0:3]
        if int(version.value()) != 2 :
            raise ParserError(buffer=buffer, message=f'invalid version {int(version.value())} != 1')
        piggybackinf_flag:Buffer = buffer[3:4]
        teid_flag:Buffer = buffer[4:5]
        spare:Buffer = buffer[5:8]
        message_type:Buffer = buffer[8:16]
        message_type_id = GTPv2Fields.MESSAGE_TYPE
        if message_type.value() in GTPv2MessageType:
            message_type_id += ": " + GTPv2MessageType[int(message_type.value())]
        message_length:Buffer = buffer[16:32]
        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv2Fields.VERSION,       position=0, value=version),
            FieldDescriptor(id=GTPv2Fields.PIGGYBACKING_FLAG, position=0, value=piggybackinf_flag),
            FieldDescriptor(id=GTPv2Fields.TEID_FLAG, position=0, value=teid_flag),
            FieldDescriptor(id=GTPv2Fields.SPARE, position=0, value=spare),
            FieldDescriptor(id=message_type_id, position=0, value=message_type),
            FieldDescriptor(id=GTPv2Fields.MESSAGE_LENGTH, position=0, value=message_length),
        ]
        pos = 32
        if int(teid_flag.value()) == 1 :
            teid:Buffer = buffer[32:64]
            header_fields.append(FieldDescriptor(id=GTPv2Fields.TEID, position=0, value=teid))
            pos = 64
        
        sequence_number:Buffer = buffer[pos:pos+24]
        pos+=24
        header_fields.append(FieldDescriptor(id=GTPv2Fields.SEQUENCE_NUMBER, position=0, value=sequence_number))
        spare_2:Buffer = buffer[pos:pos+8]
        pos+=8
        header_fields.append(FieldDescriptor(id=GTPv2Fields.SPARE, position=0, value=spare_2))
        
        informations_elements:Buffer =buffer[pos:]
        while informations_elements.length > 0 :
            ie_field_desciptor_list, pos = self._parse_information_element(informations_elements)
            for fielDescriptor in ie_field_desciptor_list :
                header_fields.append(fielDescriptor)
            informations_elements:Buffer =informations_elements[pos:]

        header_descriptor: HeaderDescriptor = HeaderDescriptor(
            id=GTP_HEADER_ID,
            length=buffer.length,
            fields=header_fields
        )
        return header_descriptor

    def _parse_information_element(self,buffer:Buffer) -> Tuple[List[FieldDescriptor], int]: 
        """parse fixed Information Element

        Args:
            buffer (Buffer): Buffer to be parsed

        octet   0 1 2         3 4 5 6             7 
               +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
           1   |         Type = xxx (decimal)     |
               +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
        2 to 3 |           Length = n             |
               +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
           4   |      Spare    |    Instance      |
               +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
      5 to n+4 | IE specific data                 |
               |     or content of a grouped IE   |
               +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+

        Returns:
            Tuple[List[FieldDescriptor], int]: the FieldDescriptor and the byte consumed
        """
        if buffer.length < 32:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 32')
        
        ie_type:Buffer = buffer[0:8]
        ie_type_value = int(ie_type.value())
        ie_length:Buffer = buffer[8:24]
        ie_length_value = int(ie_length.value())
        ie_spare:Buffer = buffer[24:28]
        ie_instance:Buffer = buffer[28:32]
        pos = 32
        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv2Fields.IE_TYPE,position=0, value=ie_type),
            FieldDescriptor(id=GTPv2Fields.IE_LENGTH,position=0, value=ie_length),
            FieldDescriptor(id=GTPv2Fields.IE_SPARE,position=0, value=ie_spare),
            FieldDescriptor(id=GTPv2Fields.IE_INSTANCE,position=0, value=ie_instance),
        ]
        # get the id of information message from type
        if ie_type_value not in IEType:
            ie_type_id = f'IE-Type-{ie_type_value}'
            ie_parser = ie_parser_generic
        else:
            ie_type_id, ie_parser = IEType[ie_type_value]

        # set the if of content
        ie_type_id = f'{GTPv2Fields.IE_CONTENT}-{ie_type_id}'
        # compute the byte length
        content_length = ie_length_value*8
        if content_length > 0 :
            field_descriptor_list = ie_parser(content_length,buffer[pos:],ie_type_id)
            for field_descriptor in field_descriptor_list:
                header_fields.append(field_descriptor)
            pos+=content_length
        
        return header_fields,pos

 

