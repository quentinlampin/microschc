"""SCHC packet capture support using python-pcapng.

This module provides functionality to capture and write SCHC packets
to pcapng files, which can be analyzed using tools like Wireshark.
"""

from typing import List

from pcapng import FileScanner, FileWriter
from pcapng.blocks import EnhancedPacket, Block, SectionHeader, InterfaceDescription

from microschc import __version__ as microschc_version
from microschc.binary import Buffer
from microschc.rfc8724 import PacketDescriptor, DirectionIndicator


ETHERNET_HEADER_LENGTH = 14

def packet_filter(block: Block) -> bool:
    """Filter for PCAPng EnhancedPacket.
    
    Args:
        block (Block): PCAPng block
        
    Returns:
        bool: True is block is an EnhancedPacket
    """
    return isinstance(block, EnhancedPacket)


def packets_list(filepath: str, header_offset:int = ETHERNET_HEADER_LENGTH) -> List[Buffer]:
    """Parses a PCAPng file and returns a list of packet buffers.

    Args:
        filepath (str): filepath of the dataset. The expected dataset format is PCAPng
        header_offset (14): location of the first byte to parse (default is 14, skip Ethernet header)

    Returns:
        List[Buffer]: List of packet buffers
    """
    
    with open(filepath, 'rb') as fp:
            # retrieve all SCHC context packets
            scanner: FileScanner = FileScanner(fp)
            packets:List[Buffer] = [
                Buffer(
                    content=p.packet_data[header_offset:],
                    length=(p.packet_len-header_offset)*8
                ) for p in filter(packet_filter, scanner)
            ]
    return packets

class SCHCPCAPWriter:
    """Class for writing SCHC packets to pcapng files.
    
    This class provides a convenient way to save SCHC packets to pcapng files,
    which can be opened and analyzed with network packet analysis tools.
    """
    
    def __init__(self, filename, context:str=None):
        """Initialize a pcapng writer for SCHC packets.
        
        Args:
            filename: The path to the pcapng file to create or append to.
            context: Optional SCHC context as JSON string.
        """
        self.filename = filename
        self._file = None
        self._writer = None
        self._count = 0
        
    def __enter__(self):
        """Open the pcapng file when entering the context manager."""
        
        self._section_header:SectionHeader = SectionHeader(
            options={     
                "shb_hardware": "artificial",
                "shb_os": "python",
                "shb_userappl": "microschc" 
            }
        )
        self._interface_description:InterfaceDescription = self._section_header.new_member(
            InterfaceDescription,
            link_type=143,
            options={
                "if_description": "microschc",
                "if_os": "Python"
            },
        )
        
        self._file = open(self.filename, 'wb')
        self._writer = FileWriter(self._file, self._section_header)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the pcapng file when exiting the context manager."""
        if self._file:
            self._file.close()
        
            
    def write_packet(self, packet: PacketDescriptor):
        """Write a SCHC packet to the pcapng file.
        
        Args:
            packet: A PacketDescriptor object containing the SCHC packet to write.
            
        Raises:
            RuntimeError: If the writer is not initialized (use with context manager).
        """
        if not self._writer:
            raise RuntimeError("Writer not initialized. Use with context manager.")
            
        # Extract raw packet data
        raw_data = packet.raw.content
        
        # Add direction as a comment
        direction = "Uplink" if packet.direction == DirectionIndicator.UP else "Downlink"
        enhanced_packet = self._section_header.new_member(
            EnhancedPacket,
            comment=f"SCHC Packet Capture generated by microschc {microschc_version}",
            interface_id=0,
            timestamp=self._count,
            captured_len=len(raw_data),
            packet_len=len(raw_data),
            packet_data=raw_data,
            direction=direction
        )

        self._writer.write_block(enhanced_packet)
        self._count += 1

def save_packet(packet: PacketDescriptor, filename: str):
    """Convenience function to save a single SCHC packet to a pcapng file.
    
    Args:
        packet: The PacketDescriptor to save.
        filename: The path to the pcapng file to create or append to.
    """
    with SCHCPCAPWriter(filename) as writer:
        writer.write_packet(packet)

