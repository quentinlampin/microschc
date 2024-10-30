"""This module contains functions to parse PDML XML WireShark in into PacketDescriptor"""
import pathlib,inspect,binascii,re
from lxml import etree, objectify
from typing import List

from microschc.rfc8724 import PacketDescriptor,HeaderDescriptor,FieldDescriptor,DirectionIndicator
from microschc.binary.buffer import Buffer

PDML_ROOT_TAG:str = 'pdml'
PDML_PACKET_TAG: str = 'packet'
PDML_LAYER_TAG = 'proto'
PDML_FIELD_PAYLOAD_ID = 'payload'

DEFAULT_LAYER_TO_IGNORE = ["geninfo","frame"]

class PdmlLayerParser():

    def __init__(self,depth:int=1,ShowHide:bool=False,listFieldToNotParse:list[str]=[],listFieldToParse:list[str]=[],debug:bool=False):
        """ Generic Layer Parser 

        Args:
            depth (int, optional): the field child depth max . Defaults to 1 (just mange the field not her childs)
            ShowHide (bool, optional): Define if we parse the field with hide attribue set to 'yes'. Defaults to False.
            listFieldToNotParse (list[str], optional): List of field name (without layer name) to ignore. Defaults to [].
            listFieldToParse (list[str], optional): lits of field we only parse. Defaults to [] = all the field are parsed.
            debug (bool, optional): set if we log debug informations. Defaults to False.
        """        
        self.depth:int = depth
        self.ShowHide:bool = ShowHide
        self.listFieldToNotParse = listFieldToNotParse
        self.listFieldToParse = listFieldToParse
        self.debug:bool = debug

    def parse(self,layer:objectify.ObjectifiedElement) -> tuple[HeaderDescriptor,Buffer]:
        """ Parser a pdml Layer ( proto in xml )

        Args:
            layer (objectify.ObjectifiedElement): the elements who contain the layer

        Raises:
            PyPdmlParserError: on error parsing
            lxml.etree.XMLSyntaxError: invalid xml file

        Returns:
            tuple[HeaderDescriptor,Buffer]: return the HeaderDescriptor computed and payload:Buffer if present in layer
        """        
        # Check if we have a pdml layer object
        if layer.tag != PDML_LAYER_TAG:
            raise PyPdmlParserError('PdmlLayerParser.parse()',f"Not a LAYER PDML object: object.tag={layer.tag} =! PDML Layer={PDML_LAYER_TAG}")
        
        self.LayerName:str = layer.attrib['name']
        self._log(f" - {layer.tag} {self.LayerName}")

        field:objectify.ObjectifiedElement
        listFieldDescriptor:List[FieldDescriptor] = []

        for field in layer.getchildren():
            listFieldDescriptor += self.packetFieldParse(field,self.depth,self.ShowHide)
        
        
        # compute the length and remove payload if present
        fd:FieldDescriptor
        size:int = 0
        payload:Buffer = None
        payloadId:str = self.LayerName +'.'+PDML_FIELD_PAYLOAD_ID
        for fd in listFieldDescriptor:
            if fd.id == payloadId:
                listFieldDescriptor.remove(fd)
                payload = fd.value
            else:
                value:Buffer = fd.value
                size = size + value.length

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=self.LayerName,
            length=size,
            fields=listFieldDescriptor
        )
        self._log(f'  -> hd={header_descriptor},{PDML_FIELD_PAYLOAD_ID}={payload}')

        return header_descriptor,payload
    
    def packetFieldParse(self,field:objectify.ObjectifiedElement,depth:int,showHide:bool) -> list[FieldDescriptor]:
        """ Parse field and his childs

        Args:
            field (objectify.ObjectifiedElement): element who contain a field
            depth (int): the depth the we manage, if 1 we only manage the field, if > 1 we manage the childs of this field
            showHide (bool): manage the field who have hide attribute set at 'yes'

        Returns:
            list[FieldDescriptor]: list of FieldDescriptor associated to all the field we have decoded
        """        
        longName:str = field.attrib['name']
        name:str = longName.removeprefix(self.LayerName+'.')
        size:int = int(field.attrib['size'])
        hide:bool = False
        if not showHide and 'hide' in field.attrib :
            hide = True if field.attrib['hide'] == "yes" else False

        listFieldDescriptor:list[FieldDescriptor] = []
        
        childs = field.getchildren()
        if depth > 1 and len(childs) > 0:
            # self._log((f'     {name} childs={childs}')
            for child in childs:
                listFieldDescriptor = listFieldDescriptor + self.packetFieldParse(child,depth-1,showHide)
        elif len(self.listFieldToParse) > 0 and name not in self.listFieldToParse:
            pass
        elif size > 0 and not hide and name not in self.listFieldToNotParse:
            resultats:str = field.attrib['value']
            value:bytes = self._binary_value(field.attrib['value'])
            showname = field.attrib['showname']
            if ' = ' in showname :
                resultats = ''.join(re.findall(r'(0|1)', showname.split(' = ')[0]))
                size = len(resultats)
                value = int(resultats, 2).to_bytes((len(resultats) + 7) // 8, byteorder='big')
            else:
                # convert to bits size
                size = size * 8
            self._log(f"   {longName} val={resultats} nb bytes={size} binary={value}")

            buff:Buffer = Buffer(value,length=size)
            fd:FieldDescriptor = FieldDescriptor(id=longName,position=0, value=buff)
            listFieldDescriptor.append(fd)

        return listFieldDescriptor

    def _binary_value(self,str_raw_value:str) -> bytes:
        """convert str raw value to bytes 

        Args:
            str_raw_value (str): the str raw value to convert

        Returns:
            bytes: the bytes convertion
        """        
        if len(str_raw_value) % 2 == 1:
            str_raw_value = '0' + str_raw_value

        return binascii.unhexlify(str_raw_value)
    
    def _log(self,msg:str):
        """log method if debug aneble

        Args:
            msg (str): message to log
        """  
        if self.debug :
            print(msg)

class PdmlParser():
    def __init__(self,direction:DirectionIndicator=DirectionIndicator.DOWN,dictLayerParser:dict[str:PdmlLayerParser]={},listIgnoreLayer:list[str]=DEFAULT_LAYER_TO_IGNORE,debug:bool=False):
        """ Create a Pdml Parser with option to decode 

        Args:
            direction (DirectionIndicator, optional): the direction of packet. Default DirectionIndicator.DOWN
            dictLayerParser (dict, optional): dict name layer:PdmlLayerParser. If not defined for a layer, we use default PdmlLayerParser. Defaults to {}.
            listIgnoreLayer (list, optional): List of layer to ignore. Defaults to DEFAULT_LAYER_TO_IGNORE.          
        """            
        
        # set direction
        self.direction = direction
        # Specific Layer Parser
        self.dictLayerParser:dict[str:PdmlLayerParser] = dictLayerParser
        # list of layer to ignore
        self.listIgnoreLayer:list[str] = listIgnoreLayer
        # a default layer parser if none defined in dictLayerParser for the layer
        self.defautLayerParser:PdmlLayerParser = PdmlLayerParser(debug=debug)
        self.debug:bool = debug
        
    def parseFromString(self,xmlStr:str) -> list[PacketDescriptor]:
        """Parse pdml string

        Args:
            xmlStr (str): the string contain pdml 

        Raises:
            PyPdmlParserError: Error on PDML 
            lxml.etree.XMLSyntaxError: invalid xml file

        Returns:
            list[PacketDescriptor]: _description_
        """        
        parser = etree.XMLParser(recover=True, encoding='utf-8')
        xml_pdml:etree._ElementTree = objectify.fromstring(xml=xmlStr,parser=parser)
        return self._parseXmlPdml(xml_pdml=xml_pdml)

    def parseFromFile(self,pdmlFileName:str) -> list[PacketDescriptor]:
        """Parse the XML file

        Args:
            pdmlFileName (str): the filename string of pdml file
        Raises:
            FileNotFoundError: File Not found error, or pdmlFileName is a directory
            PermissionError: We don’t have enough privilige to read pdmlFileName
            PyPdmlParserError: Error on PDML File
            lxml.etree.XMLSyntaxError: invalid xml file

        Returns:
            PacketDescriptor: The List of PacketDescriptor parsed from PDML XML File
            
        """
        self.input_filepath = pathlib.Path(pdmlFileName)
        # Check fileName
        if not self.input_filepath.exists():
            raise FileNotFoundError(f"[Errno 2] No such file or directory: {self.input_filepath}")
        if not self.input_filepath.is_file():
            raise FileNotFoundError(f"{self.input_filepath} is a directory")
        try:
            with self.input_filepath.open("rb"):
                pass
        except PermissionError:
            raise PermissionError(f"Permission denied for file {self.input_filepath}")

        xml_pdml:etree._ElementTree = objectify.parse(self.input_filepath)
        # Check if we have a pdml file
        if xml_pdml.getroot().tag != PDML_ROOT_TAG:
            raise PyPdmlParserError(inspect.stack()[0].function,f"Not a XML PDML file: {self.input_filepath}")
        self._log('Pdml file')
        
        return self._parseXmlPdml(xml_pdml=xml_pdml)
    
    def _parseXmlPdml(self,xml_pdml:etree._ElementTree) -> list[PacketDescriptor]:
        """parse xml etree._ElementTree 

        Args:
            xml_pdml (etree._ElementTree): element created by objectify from pdml

        Raises:
            PyPdmlParserError: Error on PDML 
            lxml.etree.XMLSyntaxError: invalid xml file
        Returns:
            list[PacketDescriptor]: list of all PacketDescriptor created from pdml
        """        
        packet:objectify.ObjectifiedElement
        listOfPacketDeciptor:list[PacketDescriptor]=[]
        # parse all packet of file
        for packet in xml_pdml.xpath('packet'):
            listOfPacketDeciptor.append(self._packetParse(packet))
        
        return listOfPacketDeciptor

    def _packetParse(self,packet:objectify.ObjectifiedElement) -> PacketDescriptor:
        """ Parse padml packet element
        Args:
            packet (objectify.ObjectifiedElement): the packet element

        Raises:
            IOError: if not a good pdml packet element
            PyPdmlParserError: Error on PDML 
            lxml.etree.XMLSyntaxError: invalid xml file
        Returns:
            PacketDescriptor: the PacketDescriptor created from a pdml packet
        """        
        layer:objectify.ObjectifiedElement
        if packet.tag != PDML_PACKET_TAG:
            raise PyPdmlParserError(inspect.stack()[0].function,f"Not a PDML {PDML_PACKET_TAG} : {packet.tag}")
        self._log(packet.tag)

        header_descriptors:list[HeaderDescriptor] = []
        header_descriptor:HeaderDescriptor
        buffer:Buffer = None
        for layer in packet.getchildren():
            header_descriptor, buffer = self._packetLayerParse(layer)
            if header_descriptor :
                header_descriptors.append(header_descriptor)
        
        packet_fields: List[FieldDescriptor] = []

        for header_descriptor in header_descriptors:
            header_fields:List[FieldDescriptor] = [FieldDescriptor(id=f.id, value=f.value, position=f.position)  for f in header_descriptor.fields]
            packet_fields += header_fields
        
        #[TODO] see the creation of packet_descriptor : we have'nt the raw os the packet
        if not buffer:
            buffer = Buffer(content=b'', length=0)
        
        packet_descriptor: PacketDescriptor = PacketDescriptor(
            direction=self.direction,
            fields=packet_fields,
            payload=buffer,
        )
        self._log(f' ->pd={packet_descriptor}')
        return packet_descriptor
            
    def _packetLayerParse(self,layer:objectify.ObjectifiedElement) -> tuple[HeaderDescriptor,Buffer]:
        """ send layer object to the good PdmlLayerParser

        Args:
            layer (objectify.ObjectifiedElement): The layer 

        Returns:
            tuple[HeaderDescriptor,Buffer]: the HeaderDescriptor of layer and Payload if present.
        """        
        name:str = layer.attrib['name']
        # check if the layer must be ignored
        if name in self.listIgnoreLayer:
            # print(f'  _packetLayer : Ignoring Layer {name}')
            return None,None
        parser:PdmlLayerParser = self.defautLayerParser
        if name in self.dictLayerParser:
            parser = self.dictLayerParser[name]
        return parser.parse(layer)
            

    def _log(self,msg:str):
        """log method if debug aneble

        Args:
            msg (str): message to log
        """        
        if self.debug :
            print(msg)

class PyPdmlParserError(Exception):
    def __init__(self, funcName:str, message:str=''):
        exception_message: str = f"pdml error in {funcName}: {message}"
        print(exception_message)
        super().__init__(exception_message)