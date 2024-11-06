""" 
TCP parser

currently, only for pdml parser
"""
from typing import List

from microschc.parser import PdmlLayerParser
from microschc.rfc8724 import FieldDescriptor
from microschc.binary.buffer import Buffer

PDML_FIELD_SEGMENT_DATA_ID = 'segment_data'

class TcpPdmlLayerParser(PdmlLayerParser):

    def __init__(self, debug:bool = False):
        listFieldToNotParse:list =  ['flags','window_size_value','window_size_scalefactor']
        super().__init__(listFieldToNotParse=listFieldToNotParse, debug=debug)
    
    def specificListFieldDescriptorAction(self, listFieldDescriptor) -> tuple[List[FieldDescriptor],Buffer]:
        payload:Buffer 
        segmentDataId:str = self.LayerName +'.'+PDML_FIELD_SEGMENT_DATA_ID
        listFieldDescriptor,payload = super().specificListFieldDescriptorAction(listFieldDescriptor)
        # [TODO] to be verified
        # In tcp, you could have PDML_FIELD_SEGMENT_DATA_ID field, if payload present it was contained in payload, otherwise we set it has payload
        for fd in listFieldDescriptor:
            if fd.id == segmentDataId:
                listFieldDescriptor.remove(fd)
                if not payload:
                    payload = fd.value

        return listFieldDescriptor,payload
