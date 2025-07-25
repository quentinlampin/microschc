"""
GTPv1 parser

Parser for the CoGTPv1 protocol header as defined in 3GPP TS 29.060 [1].
And extension [2]

[1] "3GPP TS 29.060: Universal Mobile Telecommunications System (UMTS); General Packet Radio Service (GPRS); GPRS Tunnelling Protocol (GTP)across the Gn and Gp interface : https://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf
[2] "3GPP TS 29.281 version 15.7.0 Release 15 : https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/15.07.00_60/ts_129281v150700p.pdf"
"""


from microschc.compat import StrEnum
from typing import List, Tuple,Callable
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser, ParserError

from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


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

"""

GTP_HEADER_ID:str = 'GTPv1'
GTP_MESSAGE_G_PDU:int = 255

class GTPv1Fields(StrEnum):
    VERSION                 = f'{GTP_HEADER_ID}:Version'
    
    # header v1
    PROTOCOL_TYPE           = f'{GTP_HEADER_ID}:Protocol Type'
    RESERVED                = f'{GTP_HEADER_ID}:Reserved'           
    EXTENSION_HEADER_FLAG   = f'{GTP_HEADER_ID}:Extension Header Flag'
    SEQUENCE_NUMBER_FLAG    = f'{GTP_HEADER_ID}:Sequence Number Flag'
    N_PDU_NUMBER_FLAG       = f'{GTP_HEADER_ID}:N-PDU Number Flag'
    N_PDU_NUMBER            = f'{GTP_HEADER_ID}:N-PDU Number'
    NEXT_EXTENSION_HEADER_TYPE = f'{GTP_HEADER_ID}:Next extention header type'
    EXTENSION_LENGTH        = f'{GTP_HEADER_ID}:Extension Length'
    EXTENTION_CONTENT       = f'{GTP_HEADER_ID}:Extension content'

    MESSAGE_TYPE            = f'{GTP_HEADER_ID}:Message Type'    
    MESSAGE_LENGTH          = f'{GTP_HEADER_ID}:Message Length'
    TEID                    = f'{GTP_HEADER_ID}:TEID'
    SEQUENCE_NUMBER         = f'{GTP_HEADER_ID}:Sequence Number'

    INFORMATION_ELEMENT     = f'{GTP_HEADER_ID}:Information Element'
    IE_TYPE                 = f'{INFORMATION_ELEMENT}:Type'
    IE_LENGTH               = f'{INFORMATION_ELEMENT}:Length'
    IE_CONTENT              = f'{INFORMATION_ELEMENT}:Content'

    T_PDU                   = f'{INFORMATION_ELEMENT}:T-PDU'

GTPv1MessageType = {
    1 : "Echo Request",
    2 : "Echo Response",
    3 : "Version Not Supported",
    16: "Create PDP Context Request",
    17: "Create PDP Context Response",
    18: "Update PDP Context Request",
    19: "Update PDP Context Response",
    20: "Delete PDP Context Request",
    21: "Delete PDP Context Response",
    22: "Initiate PDP Context Activation Request",
    23: "Initiate PDP Context Activation Response",
    26: "Error Indication",
    27: "PDU Notification Request",
    28: "PDU Notification Response",
    29: "PDU Notification Reject Request",
    30: "PDU Notification Reject Response",
    31: "Supported Extension Headers Notification",
    32: "Send Routeing Information for GPRS Request",
    33: "Send Routeing Information for GPRS Response",
    34: "Failure Report Request",
    35: "Failure Report Response",
    36: "Note MS GPRS Present Request",
    37: "Note MS GPRS Present Response",
    # [TODO] to be completed
    254: "End Marker ",
    GTP_MESSAGE_G_PDU: "G-PDU"}

def ie_parser_generic_variable(
        content_length:int,
        buffer:Buffer,
        ie_type_id:str
) -> List[FieldDescriptor]:
        """default information element variable parser

        Args:
            content_length (int): the length of information element in byte
            buffer (Buffer): the buffer to be parsed

        Returns:
            List[FieldDescriptor]
        """
        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=ie_type_id, position=0, value=buffer[0:content_length])
        ]
        
        return header_fields

def ie_parser_end_user_address(
        content_length:int,
        buffer:Buffer,
        ie_type_id:str
) -> List[FieldDescriptor]:
    """parse End User Address  

    octet  0 1 2   3 4 5 6                  7 
          +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
      1   | spare   | PDP Type Organization  |
          +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
      2   |         PDP Type Number          |
          +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
     3-n  |         PDP Address.             |
          +-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+
    
    [TODO] Implement all case of adresse : see chapter 7.7.27 in [1]
    """
    spare:Buffer = buffer[0:4]
    pdp_type_oragnisation:Buffer = buffer[4:8]
    pdp_type_number:Buffer = buffer[8:16]
    pdp_address:Buffer = buffer[16:content_length]
    header_fields:List[FieldDescriptor] = [
        FieldDescriptor(id=f'{GTPv1Fields.INFORMATION_ELEMENT}:spare', position=0, value=spare),
        FieldDescriptor(id=f'{GTPv1Fields.INFORMATION_ELEMENT}:PDP Type Organization', position=0, value=pdp_type_oragnisation),
        FieldDescriptor(id=f'{GTPv1Fields.INFORMATION_ELEMENT}:PDP Type Number', position=0, value=pdp_type_number),
        FieldDescriptor(id=f'{GTPv1Fields.INFORMATION_ELEMENT}:PDP Address', position=0, value=pdp_address),
    ]

    return header_fields




IETypeValue = {
    1: ("Cause",1),
    2: ("IMSI",8),
    3: ("Routeing Area Identity (RAI)",6),
    4: ("Temporary Logical Link Identity (TLLI)",4),
    5: ("Packet TMSI (P-TMSI)",4),
    8: ("Reordering Required",1),
    9: ("Authentication Triplet",28),
    11: ("MAP Cause",1),
    12: ("P-TMSI Signature",3),
    13: ("MS Validated",1),
    14: ("Recovery",1),
    15: ("Selection Mode",1),
    16: ("Tunnel Endpoint Identifier Data I",4),
    17: ("Tunnel Endpoint Identifier Control Plane",4),
    18: ("Tunnel Endpoint Identifier Data II",5),
    19: ("Teardown Ind",1),
    20: ("NSAPI",1),
    21: ("RANAP Cause",1),
    22: ("RAB Context",9),
    23: ("Radio Priority SMS",1),
    24: ("Radio Priority",1),
    25: ("Packet Flow Id",2),
    26: ("Charging Characteristics",2),
    27: ("Trace Reference",2),
    28: ("Trace Type",2),
    29: ("MS Not Reachable Reason",1),
    127: ("Charging ID",4),
    145: ("PDP Context Prioritization",0)
}

IETypeLengthValue = {
    128: ("End User Address",ie_parser_end_user_address),
    128: ("End User Address",ie_parser_generic_variable),
    129: ("MM Context",ie_parser_generic_variable),
    130: ("PDP Context",ie_parser_generic_variable),
    131: ("Access Point Name",ie_parser_generic_variable), 
    132: ("Protocol Configuration Options",ie_parser_generic_variable),
    133: ("GSN Address",ie_parser_generic_variable),
    134: ("MS International PSTN/ISDN Number (MSISDN)",ie_parser_generic_variable),
    135: ("Quality of Service Profile",ie_parser_generic_variable),
    136: ("Authentication Quintuplet",ie_parser_generic_variable),
    137: ("Traffic Flow Template",ie_parser_generic_variable),
    138: ("Target Identification",ie_parser_generic_variable),
    139: ("UTRAN Transparent Container",ie_parser_generic_variable),
    140: ("RAB Setup Information",ie_parser_generic_variable),
    141: ("Extension Header Type List",ie_parser_generic_variable),
    142: ("Trigger Id",ie_parser_generic_variable),
    143: ("OMC Identity",ie_parser_generic_variable),
    144: ("RAN Transparent Container",ie_parser_generic_variable),
    145: ("PDP Context Prioritization",ie_parser_generic_variable),
    146: ("Additional RAB Setup Information",ie_parser_generic_variable),
    147: ("SGSN Number",ie_parser_generic_variable),
    148: ("Common Flags",ie_parser_generic_variable),
    149: ("APN Restriction",ie_parser_generic_variable),
    150: ("Radio Priority LCS",ie_parser_generic_variable),
    151: ("RAT Type",ie_parser_generic_variable),
    152: ("User Location Information",ie_parser_generic_variable),
    153: ("MS Time Zone",ie_parser_generic_variable),
    154: ("IMEI(SV)",ie_parser_generic_variable),
    155: ("CAMEL Charging Information Container",ie_parser_generic_variable),
    156: ("MBMS UE Context",ie_parser_generic_variable),
    157: ("Temporary Mobile Group Identity (TMGI)",ie_parser_generic_variable),
    158: ("RIM Routing Address",ie_parser_generic_variable),
    159: ("MBMS Protocol Configuration Options",ie_parser_generic_variable),
    160: ("MBMS Service Area",ie_parser_generic_variable),

}

class GTPv1Parser(HeaderParser):

    def __init__(self, predict_next:bool=False, ) -> None:
        super().__init__(name=GTP_HEADER_ID, predict_next=predict_next)

    def parse(self, buffer: Buffer) -> HeaderDescriptor:
        """ parse gtp header v1
        Manage gtp v1 header
            0                                                                       1                   2                   3
            0 1 2     3           4           5           6           7         8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Version | Protocol  | Reserved  | Extension | Sequence  | N-PDU   |   Message     |     Message Length            |
            |         |  Type     |    = 0    |  Header   |  Number   | Number  |    Type       |                               |
            |         |           |           |   Flag    |   Flag    | Flag    |               |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                 TEID                                                                              |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                          Sequence Number                                          |    N_PDU      | Next extension|
            |                                                                                   |    Number     |   header type |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        Args:
            buffer (Buffer): the binary buffer

        Returns:
            HeaderDescriptor: 
        """
        if buffer.length < 64:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 64')
        # version: 3 bits
        version: Buffer = buffer[0:3]
        if int(version.value()) != 1 :
            raise ParserError(buffer=buffer, message=f'invalid version {int(version.value())} != 1')
        protocol_type:Buffer = buffer[3:4]
        reserved:Buffer = buffer[4:5]
        if reserved.value() != 0 :
            raise ParserError(buffer=buffer, message=f'GTP V1 reserved value  {reserved.value()} != 0 ')
        extension_header_flag:Buffer = buffer[5:6]
        sequence_number_flag:Buffer = buffer[6:7]
        n_pdu_number_flag:Buffer = buffer[7:8]
        message_type:Buffer = buffer[8:16]
        message_type_id = GTPv1Fields.MESSAGE_TYPE
        message_type_id_value = int(message_type.value())
        if message_type.value() in GTPv1MessageType:
            message_type_id += ": " + GTPv1MessageType[message_type_id_value]
        message_length:Buffer = buffer[16:32]
        message_length_value:int = int(message_length.value())

        teid:Buffer = buffer[32:64]

        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv1Fields.VERSION,       position=0, value=version),
            FieldDescriptor(id=GTPv1Fields.PROTOCOL_TYPE, position=0, value=protocol_type),
            FieldDescriptor(id=GTPv1Fields.RESERVED, position=0, value=reserved),
            FieldDescriptor(id=GTPv1Fields.EXTENSION_HEADER_FLAG, position=0, value=extension_header_flag),
            FieldDescriptor(id=GTPv1Fields.SEQUENCE_NUMBER_FLAG, position=0, value=sequence_number_flag),
            FieldDescriptor(id=GTPv1Fields.N_PDU_NUMBER_FLAG, position=0, value=n_pdu_number_flag),
            FieldDescriptor(id=message_type_id, position=0, value=message_type),
            FieldDescriptor(id=GTPv1Fields.MESSAGE_LENGTH, position=0, value=message_length),
            FieldDescriptor(id=GTPv1Fields.TEID, position=0, value=teid),
        ]

        pos = 64
        if extension_header_flag.value() == 1 or sequence_number_flag.value() == 1 or n_pdu_number_flag.value() == 1 :
            sequence_number:Buffer = buffer[64:80]
            n_pdu_number:Buffer = buffer[80:88]
            next_extension_header_type:Buffer = buffer[88:96]
            header_fields.append(FieldDescriptor(id=GTPv1Fields.SEQUENCE_NUMBER, position=0, value=sequence_number))
            header_fields.append(FieldDescriptor(id=GTPv1Fields.N_PDU_NUMBER, position=0, value=n_pdu_number))
            header_fields.append(FieldDescriptor(id=GTPv1Fields.NEXT_EXTENSION_HEADER_TYPE, position=0, value=next_extension_header_type))
            pos = 96

            if next_extension_header_type.value() != 0 :
                listHeader, newpos = self._parse_v1_extention_header(buffer=buffer[pos:])
                pos += newpos
                for fielDescriptor in listHeader :
                    header_fields.append(fielDescriptor)

        informations_elements:Buffer =buffer[pos:]
        # if the message type is not G-PDU, we have informations elements
        if message_type_id_value != GTP_MESSAGE_G_PDU :
            while informations_elements.length > 0 :
                ie_field_desciptor_list, pos = self._parse_information_element(informations_elements)
                for fielDescriptor in ie_field_desciptor_list :
                    header_fields.append(fielDescriptor)
                informations_elements:Buffer =informations_elements[pos:]
        # if we have G-PDU, we have a T-PDU
        else:
            header_fields.append(FieldDescriptor(id=GTPv1Fields.T_PDU, position=0, value=informations_elements))

        header_descriptor: HeaderDescriptor = HeaderDescriptor(
            id=GTP_HEADER_ID,
            length=buffer.length,
            fields=header_fields
        )
        return header_descriptor

    def _parse_v1_extention_header(self, buffer:Buffer) -> Tuple[List[FieldDescriptor], int]:
        """ parse extention header for gtp v1

        Next Extention Header (v1)

        octet   0 1 2 3 4 5 6                     7 
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           1   |         Extention Length          |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        2 to m |           Contents                |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         m + 1 |           Next extension          |
               |            header type            |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            The length of the Extension header shall be defined in a variable length of 4 octets, 
            i.e. m+1 = n*4 octets, where n is a positive integer.
        Args:
            buffer (Buffer): the buffer with extention header

        Returns:
            Tuple[List[FieldDescriptor], int]: _description_
        """
        extension_length:Buffer = buffer[0:8]
        pos=8
        length=(int(extension_length.value())*4 -2 )*8
        extension_content:Buffer = buffer[pos:pos+length]
        pos+=length
        next_extension_header_type:Buffer = buffer[pos:pos+8]
        
        next_extension_header_type_value =int(next_extension_header_type.value())
        pos+=8

        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv1Fields.EXTENSION_LENGTH, position=0, value=extension_length),
            FieldDescriptor(id=GTPv1Fields.EXTENTION_CONTENT, position=0, value=extension_content),
            FieldDescriptor(id=GTPv1Fields.NEXT_EXTENSION_HEADER_TYPE, position=0, value=next_extension_header_type)]
        
        if next_extension_header_type_value != 0 :
            listHeader, newpos = self._parse_v1_extention_header(buffer=buffer[pos:])
            pos += newpos
            for fielDescriptor in listHeader :
                header_fields.append(fielDescriptor)

        return header_fields,pos

    def _parse_information_element(self,buffer:Buffer) -> Tuple[List[FieldDescriptor], int]: 
        """parse fixed Information Element

        Args:
            buffer (Buffer): Buffer to be parsed
            0 1 2 3 4 5 6 7  
            +-+-+-+-+-+-+-+-+
            |     Type      |
            +-+-+-+-+-+-+-+-+
            | ...           |
            ...
            |               |
            +-+-+-+-+-+-+-+-+

        Returns:
            Tuple[List[FieldDescriptor], int]: the FieldDescriptor and the byte consumed
        """
        ie_type:Buffer = buffer[0:8]
        pos=8
        ie_type_value = int(ie_type.value())
        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv1Fields.IE_TYPE,position=0, value=ie_type)
        ]
        # check if this is Type Value content
        if ie_type_value < 128 :
            if ie_type_value in IETypeValue:
                ie_type_id, ie_length_oct = IETypeValue[ie_type_value]
                ie_length = ie_length_oct * 8
                # We have fixed length information element
                if ie_length > 0 :
                    header_fields.append(FieldDescriptor(id=f'{GTP_HEADER_ID}:{ie_type_id}',position=0, value=buffer[pos:pos+ie_length]))
                pos+=ie_length
            else:
                raise ParserError(buffer=buffer,message=f'Unknown Information Element Type {ie_type_value}')
        # we have TLV content
        else:
            ie_type_id = f'{GTP_HEADER_ID}:unknown'
            ie_func_parse = ie_parser_generic_variable
            if ie_type_value in IETypeLengthValue :
                ie_type_id, ie_func_parse = IETypeLengthValue[ie_type_value]
                ie_type_id = f'{GTP_HEADER_ID}:{ie_type_id}'
            field_descriptor_list,content_length = self._parse_variable_information_element(buffer[pos:],ie_type_id=ie_type_id,ie_parser=ie_func_parse)
            pos+=content_length
            for field_descriptor in field_descriptor_list:
                header_fields.append(field_descriptor)

        return header_fields,pos
    
    def _parse_variable_information_element(
        self,
        buffer:Buffer,
        ie_type_id:str,
        ie_parser:Callable[[int,Buffer,str],List[FieldDescriptor]]
    ) -> Tuple[List[FieldDescriptor], int]:
        """
            0                    1             
            0 1 2 3 4 5 6 7  8 9 0 1 2 3 4 5 6 
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Length                          |
            ...
        Args:
            buffer (Buffer): _description_

        Returns:
            Tuple[List[FieldDescriptor], int]: _description_
        """
        size_ie_length=16
        ie_length:Buffer = buffer[0:size_ie_length]
        header_fields:List[FieldDescriptor] = [
            FieldDescriptor(id=GTPv1Fields.IE_LENGTH,position=0, value=ie_length),
        ]
        # compute the byte length of content
        content_length= int(ie_length.value())*8
        # parse variable information header
        if content_length > 0 :
            field_descriptor_list = ie_parser(content_length,buffer[size_ie_length:],ie_type_id)
            for field_descriptor in field_descriptor_list:
                header_fields.append(field_descriptor)

        return header_fields,size_ie_length+content_length
 

