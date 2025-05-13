"""Tests for the optional pcapng module.

These tests are skipped if python-pcapng is not available.
"""

import os
import tempfile
from typing import List
import pytest

from microschc.extras import has_pcapng
from microschc.binary.buffer import Buffer, Padding
from microschc.rfc8724 import PacketDescriptor, DirectionIndicator

@pytest.mark.skipif(not has_pcapng, reason="python-pcapng is not available")
def test_schc_pcap_writer(tmpdir):
    from microschc.extras.io.pcapng import SCHCPCAPWriter
    from microschc.extras.io.pcapng import packets_list
    
    tempdir = tmpdir.mkdir("pcapng")
    temp_file_name = os.path.join(tempdir, "test.pcapng")
    
    
    packet_up = PacketDescriptor(
        direction= DirectionIndicator.UP,
        fields=[],
        payload=Buffer(content=b'Test payload', length=12*8)
    )
    
    with SCHCPCAPWriter(temp_file_name) as writer:
        writer.write_packet(packet_up)
    
    # Verify the file was created and has content
    assert os.path.exists(temp_file_name)
    assert os.path.getsize(temp_file_name) > 0
    
    packets: List[Buffer] = packets_list(temp_file_name, header_offset=0)
    assert len(packets) == 1
    assert packets[0].content == b'Test payload'
    assert packets[0].length == 12*8
    assert packets[0].padding == Padding.LEFT
    
@pytest.mark.skipif(not has_pcapng, reason="python-pcapng is not available")
def test_pcap_save_packet(tmpdir):
    from microschc.extras.io.pcapng import save_packet
    
    tempdir = tmpdir.mkdir("pcapng")
    temp_file_name = os.path.join(tempdir, "test.pcapng")
    
    packet_up = PacketDescriptor(
        direction= DirectionIndicator.UP,
        fields=[],
        payload=Buffer(content=b'Test payload', length=12*8)
    )
    save_packet(packet_up, temp_file_name)
    # Verify the file was created and has content
    assert os.path.exists(temp_file_name)
    assert os.path.getsize(temp_file_name) > 0
    