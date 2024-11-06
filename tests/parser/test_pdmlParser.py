from microschc.parser import PdmlParser,PyPdmlParserError
from microschc.protocol.registry import PDML_SPECIFIC_PARSER

from microschc.rfc8724 import PacketDescriptor,FieldDescriptor
from microschc.binary import Buffer

from typing import List

def test_pdmlParser_file_open():
    pdmlFileName:str = 'FakeFile.pdml'
    # test false file name
    pdmlParser:PdmlParser = PdmlParser()
    try:
        pdmlParser.parseFromFile(pdmlFileName=pdmlFileName)
        assert False
    except PyPdmlParserError:
        assert True
    # test directory
    pdmlFileName:str = '/home/'
    try:
        pdmlParser.parseFromFile(pdmlFileName=pdmlFileName)
        assert False
    except PyPdmlParserError:
        assert True

def test_pdmlParser_src():
    pdmlEthIpTcp:str = """
<pdml version="0" creator="wireshark/2.0.5" time="Sat Sep 17 01:03:30 2016" capture_file="/tmp/wireshark_pcapng_enp0s7_20160917010155_Pejnei">
<packet>
  <proto name="geninfo" pos="0" showname="General information" size="74">
    <field name="num" pos="0" show="718" showname="Number" value="2ce" size="74"/>
    <field name="len" pos="0" show="74" showname="Frame Length" value="4a" size="74"/>
    <field name="caplen" pos="0" show="74" showname="Captured Length" value="4a" size="74"/>
    <field name="timestamp" pos="0" show="Sep 17, 2016 01:01:58.228537153 PDT" showname="Captured Time" value="1474099318.228537153" size="74"/>
  </proto>
  <proto name="frame" showname="Frame 718: 74 bytes on wire (592 bits), 74 bytes captured (592 bits) on interface 0" size="74" pos="0">
    <field name="frame.interface_id" showname="Interface id: 0 (enp0s7)" size="0" pos="0" show="0"/>
    <field name="frame.encap_type" showname="Encapsulation type: Ethernet (1)" size="0" pos="0" show="1"/>
    <field name="frame.time" showname="Arrival Time: Sep 17, 2016 01:01:58.228537153 PDT" size="0" pos="0" show="Sep 17, 2016 01:01:58.228537153 PDT"/>
    <field name="frame.offset_shift" showname="Time shift for this packet: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_epoch" showname="Epoch Time: 1474099318.228537153 seconds" size="0" pos="0" show="1474099318.228537153"/>
    <field name="frame.time_delta" showname="Time delta from previous captured frame: 0.000118753 seconds" size="0" pos="0" show="0.000118753"/>
    <field name="frame.time_delta_displayed" showname="Time delta from previous displayed frame: 0.000000000 seconds" size="0" pos="0" show="0.000000000"/>
    <field name="frame.time_relative" showname="Time since reference or first frame: 2.407821300 seconds" size="0" pos="0" show="2.407821300"/>
    <field name="frame.number" showname="Frame Number: 718" size="0" pos="0" show="718"/>
    <field name="frame.len" showname="Frame Length: 74 bytes (592 bits)" size="0" pos="0" show="74"/>
    <field name="frame.cap_len" showname="Capture Length: 74 bytes (592 bits)" size="0" pos="0" show="74"/>
    <field name="frame.marked" showname="Frame is marked: False" size="0" pos="0" show="0"/>
    <field name="frame.ignored" showname="Frame is ignored: False" size="0" pos="0" show="0"/>
    <field name="frame.protocols" showname="Protocols in frame: eth:ethertype:ip:tcp" size="0" pos="0" show="eth:ethertype:ip:tcp"/>
    <field name="frame.coloring_rule.name" showname="Coloring Rule Name: HTTP" size="0" pos="0" show="HTTP"/>
    <field name="frame.coloring_rule.string" showname="Coloring Rule String: http || tcp.port == 80 || http2" size="0" pos="0" show="http || tcp.port == 80 || http2"/>
  </proto>
  <proto name="eth" showname="Ethernet II, Src: Elitegro_dd:12:cd (00:19:21:dd:12:cd), Dst: Broadcom_de:ad:05 (00:10:18:de:ad:05)" size="14" pos="0">
    <field name="eth.dst" showname="Destination: Broadcom_de:ad:05 (00:10:18:de:ad:05)" size="6" pos="0" show="00:10:18:de:ad:05" value="001018dead05">
      <field name="eth.dst_resolved" showname="Destination (resolved): Broadcom_de:ad:05" hide="yes" size="6" pos="0" show="Broadcom_de:ad:05" value="001018dead05"/>
      <field name="eth.addr" showname="Address: Broadcom_de:ad:05 (00:10:18:de:ad:05)" size="6" pos="0" show="00:10:18:de:ad:05" value="001018dead05"/>
      <field name="eth.addr_resolved" showname="Address (resolved): Broadcom_de:ad:05" hide="yes" size="6" pos="0" show="Broadcom_de:ad:05" value="001018dead05"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="0" show="0" value="0" unmaskedvalue="001018"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="0" show="0" value="0" unmaskedvalue="001018"/>
    </field>
    <field name="eth.src" showname="Source: Elitegro_dd:12:cd (00:19:21:dd:12:cd)" size="6" pos="6" show="00:19:21:dd:12:cd" value="001921dd12cd">
      <field name="eth.src_resolved" showname="Source (resolved): Elitegro_dd:12:cd" hide="yes" size="6" pos="6" show="Elitegro_dd:12:cd" value="001921dd12cd"/>
      <field name="eth.addr" showname="Address: Elitegro_dd:12:cd (00:19:21:dd:12:cd)" size="6" pos="6" show="00:19:21:dd:12:cd" value="001921dd12cd"/>
      <field name="eth.addr_resolved" showname="Address (resolved): Elitegro_dd:12:cd" hide="yes" size="6" pos="6" show="Elitegro_dd:12:cd" value="001921dd12cd"/>
      <field name="eth.lg" showname=".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)" size="3" pos="6" show="0" value="0" unmaskedvalue="001921"/>
      <field name="eth.ig" showname=".... ...0 .... .... .... .... = IG bit: Individual address (unicast)" size="3" pos="6" show="0" value="0" unmaskedvalue="001921"/>
    </field>
    <field name="eth.type" showname="Type: IPv4 (0x0800)" size="2" pos="12" show="0x00000800" value="0800"/>
  </proto>
  <proto name="ip" showname="Internet Protocol Version 4, Src: 192.168.222.3, Dst: 193.108.181.130" size="20" pos="14">
    <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="14" show="4" value="4" unmaskedvalue="45"/>
    <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="14" show="20" value="45"/>
    <field name="ip.dsfield" showname="Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)" size="1" pos="15" show="0x00000000" value="00">
      <field name="ip.dsfield.dscp" showname="0000 00.. = Differentiated Services Codepoint: Default (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
      <field name="ip.dsfield.ecn" showname=".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)" size="1" pos="15" show="0" value="0" unmaskedvalue="00"/>
    </field>
    <field name="ip.len" showname="Total Length: 60" size="2" pos="16" show="60" value="003c"/>
    <field name="ip.id" showname="Identification: 0x8784 (34692)" size="2" pos="18" show="0x00008784" value="8784"/>
    <field name="ip.flags" showname="Flags: 0x02 (Don&#x27;t Fragment)" size="1" pos="20" show="0x00000002" value="40">
      <field name="ip.flags.rb" showname="0... .... = Reserved bit: Not set" size="1" pos="20" show="0" value="40"/>
      <field name="ip.flags.df" showname=".1.. .... = Don&#x27;t fragment: Set" size="1" pos="20" show="1" value="40"/>
      <field name="ip.flags.mf" showname="..0. .... = More fragments: Not set" size="1" pos="20" show="0" value="40"/>
    </field>
    <field name="ip.frag_offset" showname="Fragment offset: 0" size="2" pos="20" show="0" value="4000"/>
    <field name="ip.ttl" showname="Time to live: 64" size="1" pos="22" show="64" value="40"/>
    <field name="ip.proto" showname="Protocol: TCP (6)" size="1" pos="23" show="6" value="06"/>
    <field name="ip.checksum" showname="Header checksum: 0x9d9c [validation disabled]" size="2" pos="24" show="0x00009d9c" value="9d9c">
      <field name="ip.checksum_good" showname="Good: False" size="2" pos="24" show="0" value="9d9c"/>
      <field name="ip.checksum_bad" showname="Bad: False" size="2" pos="24" show="0" value="9d9c"/>
    </field>
    <field name="ip.src" showname="Source: 192.168.222.3" size="4" pos="26" show="192.168.222.3" value="c0a8de03"/>
    <field name="ip.addr" showname="Source or Destination Address: 192.168.222.3" hide="yes" size="4" pos="26" show="192.168.222.3" value="c0a8de03"/>
    <field name="ip.src_host" showname="Source Host: 192.168.222.3" hide="yes" size="4" pos="26" show="192.168.222.3" value="c0a8de03"/>
    <field name="ip.host" showname="Source or Destination Host: 192.168.222.3" hide="yes" size="4" pos="26" show="192.168.222.3" value="c0a8de03"/>
    <field name="ip.dst" showname="Destination: 193.108.181.130" size="4" pos="30" show="193.108.181.130" value="c16cb582"/>
    <field name="ip.addr" showname="Source or Destination Address: 193.108.181.130" hide="yes" size="4" pos="30" show="193.108.181.130" value="c16cb582"/>
    <field name="ip.dst_host" showname="Destination Host: 193.108.181.130" hide="yes" size="4" pos="30" show="193.108.181.130" value="c16cb582"/>
    <field name="ip.host" showname="Source or Destination Host: 193.108.181.130" hide="yes" size="4" pos="30" show="193.108.181.130" value="c16cb582"/>
  </proto>
  <proto name="tcp" showname="Transmission Control Protocol, Src Port: 55394 (55394), Dst Port: 80 (80), Seq: 0, Len: 0" size="40" pos="34">
    <field name="tcp.srcport" showname="Source Port: 55394" size="2" pos="34" show="55394" value="d862"/>
    <field name="tcp.dstport" showname="Destination Port: 80" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.port" showname="Source or Destination Port: 55394" hide="yes" size="2" pos="34" show="55394" value="d862"/>
    <field name="tcp.port" showname="Source or Destination Port: 80" hide="yes" size="2" pos="36" show="80" value="0050"/>
    <field name="tcp.stream" showname="Stream index: 11" size="0" pos="34" show="11"/>
    <field name="tcp.len" showname="TCP Segment Len: 0" size="1" pos="46" show="0" value="a0"/>
    <field name="tcp.seq" showname="Sequence number: 0    (relative sequence number)" size="4" pos="38" show="0" value="ffe57d2d"/>
    <field name="tcp.ack" showname="Acknowledgment number: 0" size="4" pos="42" show="0" value="00000000"/>
    <field name="tcp.hdr_len" showname="Header Length: 40 bytes" size="1" pos="46" show="40" value="a0"/>
    <field name="tcp.flags" showname="Flags: 0x002 (SYN)" size="2" pos="46" show="0x00000002" value="2" unmaskedvalue="a002">
      <field name="tcp.flags.res" showname="000. .... .... = Reserved: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="a0"/>
      <field name="tcp.flags.ns" showname="...0 .... .... = Nonce: Not set" size="1" pos="46" show="0" value="0" unmaskedvalue="a0"/>
      <field name="tcp.flags.cwr" showname=".... 0... .... = Congestion Window Reduced (CWR): Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.ecn" showname=".... .0.. .... = ECN-Echo: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.urg" showname=".... ..0. .... = Urgent: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.ack" showname=".... ...0 .... = Acknowledgment: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.push" showname=".... .... 0... = Push: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.reset" showname=".... .... .0.. = Reset: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.syn" showname=".... .... ..1. = Syn: Set" size="1" pos="47" show="1" value="1" unmaskedvalue="02">
        <field name="_ws.expert" showname="Expert Info (Chat/Sequence): Connection establish request (SYN): server port 80" size="0" pos="47">
          <field name="tcp.connection.syn" showname="Connection establish request (SYN): server port 80" size="0" pos="0" show="" value=""/>
          <field name="_ws.expert.message" showname="Message: Connection establish request (SYN): server port 80" hide="yes" size="0" pos="0" show="Connection establish request (SYN): server port 80"/>
          <field name="_ws.expert.severity" showname="Severity level: Chat" size="0" pos="0" show="0x00200000"/>
          <field name="_ws.expert.group" showname="Group: Sequence" size="0" pos="0" show="0x02000000"/>
        </field>
      </field>
      <field name="tcp.flags.fin" showname=".... .... ...0 = Fin: Not set" size="1" pos="47" show="0" value="0" unmaskedvalue="02"/>
      <field name="tcp.flags.str" showname="TCP Flags: **********S*" size="2" pos="46" show="**********S*" value="a002"/>
    </field>
    <field name="tcp.window_size_value" showname="Window size value: 29200" size="2" pos="48" show="29200" value="7210"/>
    <field name="tcp.window_size" showname="Calculated window size: 29200" size="2" pos="48" show="29200" value="7210"/>
    <field name="tcp.checksum" showname="Checksum: 0x64e6 [validation disabled]" size="2" pos="50" show="0x000064e6" value="64e6">
      <field name="tcp.checksum_good" showname="Good Checksum: False" size="2" pos="50" show="0" value="64e6"/>
      <field name="tcp.checksum_bad" showname="Bad Checksum: False" size="2" pos="50" show="0" value="64e6"/>
    </field>
    <field name="tcp.urgent_pointer" showname="Urgent pointer: 0" size="2" pos="52" show="0" value="0000"/>
    <field name="tcp.options" showname="Options: (20 bytes), Maximum segment size, SACK permitted, Timestamps, No-Operation (NOP), Window scale" size="20" pos="54" show="02:04:05:b4:04:02:08:0a:0a:fe:fa:a9:00:00:00:00:01:03:03:07" value="020405b40402080a0afefaa90000000001030307">
      <field name="tcp.options.mss" showname="Maximum segment size: 1460 bytes" size="4" pos="54" show="" value="">
        <field name="tcp.option_kind" showname="Kind: Maximum Segment Size (2)" size="1" pos="54" show="2" value="02"/>
        <field name="tcp.option_len" showname="Length: 4" size="1" pos="55" show="4" value="04"/>
        <field name="tcp.options.mss_val" showname="MSS Value: 1460" size="2" pos="56" show="1460" value="05b4"/>
      </field>
      <field name="tcp.options.sack_perm" showname="TCP SACK Permitted Option: True" size="2" pos="58" show="1" value="0402">
        <field name="tcp.option_kind" showname="Kind: SACK Permitted (4)" size="1" pos="58" show="4" value="04"/>
        <field name="tcp.option_len" showname="Length: 2" size="1" pos="59" show="2" value="02"/>
      </field>
      <field name="" show="Timestamps: TSval 184482473, TSecr 0" size="10" pos="60" value="080a0afefaa900000000">
        <field name="tcp.option_kind" showname="Kind: Time Stamp Option (8)" size="1" pos="60" show="8" value="08"/>
        <field name="tcp.option_len" showname="Length: 10" size="1" pos="61" show="10" value="0a"/>
        <field name="tcp.options.timestamp.tsval" showname="Timestamp value: 184482473" size="4" pos="62" show="184482473" value="0afefaa9"/>
        <field name="tcp.options.timestamp.tsecr" showname="Timestamp echo reply: 0" size="4" pos="66" show="0" value="00000000"/>
      </field>
      <field name="" show="No-Operation (NOP)" size="1" pos="70" value="01">
        <field name="tcp.options.type" showname="Type: 1" size="1" pos="70" show="1" value="01">
          <field name="tcp.options.type.copy" showname="0... .... = Copy on fragmentation: No" size="1" pos="70" show="0" value="0" unmaskedvalue="01"/>
          <field name="tcp.options.type.class" showname=".00. .... = Class: Control (0)" size="1" pos="70" show="0" value="0" unmaskedvalue="01"/>
          <field name="tcp.options.type.number" showname="...0 0001 = Number: No-Operation (NOP) (1)" size="1" pos="70" show="1" value="1" unmaskedvalue="01"/>
        </field>
      </field>
      <field name="" show="Window scale: 7 (multiply by 128)" size="3" pos="71" value="030307">
        <field name="tcp.option_kind" showname="Kind: Window Scale (3)" size="1" pos="71" show="3" value="03"/>
        <field name="tcp.option_len" showname="Length: 3" size="1" pos="72" show="3" value="03"/>
        <field name="tcp.options.wscale.shift" showname="Shift count: 7" size="1" pos="73" show="7" value="07"/>
        <field name="tcp.options.wscale.multiplier" showname="Multiplier: 128" size="1" pos="73" show="128" value="07"/>
      </field>
    </field>
  </proto>
</packet>
"""
    parser = PdmlParser(dictLayerParser=PDML_SPECIFIC_PARSER)
    liste:list[PacketDescriptor] = parser.parseFromString(pdmlEthIpTcp)

    assert len(liste) == 1 , "The list of PacketDescriptor must contain one PacketDescriptor"
    
    Pa:PacketDescriptor = liste[0]
    key:list = []
    for fi in Pa.fields:
        key.append(fi.id)

    # check eth
    for id in ['eth.dst','eth.src','eth.type']:
        assert id in key , f"the eth id='{id}' must be in PacketDescriptor field : [{key}]"

    # check ip
    for id in ['ip.version', 'ip.hdr_len', 'ip.dsfield', 'ip.len', 'ip.id', 'ip.flags', 'ip.frag_offset','ip.ttl','ip.proto','ip.checksum', 'ip.src','ip.dst']:
        assert id in key , f"the ip id='{id}' must be in PacketDescriptor field : [{key}]"
    
    fi:FieldDescriptor = getFieldByName('ip.version')
    assert  fi.value == Buffer(content=b'\x04', length=4) , f"the field='{fi.id}' have an incorrect value={fi.value}/{b'\x04'}"
    fi:FieldDescriptor = getFieldByName('ip.src')
    assert  fi.value == Buffer(content=b'\xc1l\xb5\x82', length=32) , f"the field='{fi.id}' have an incorrect value={fi.value}/{b'\xc1l\xb5\x82'}"

    # check tcp
    for id in ['tcp.srcport', 'tcp.dstport', 'tcp.len', 'tcp.seq', 'tcp.ack', 'tcp.hdr_len', 'tcp.window_size', 'tcp.checksum', 'tcp.urgent_pointer', 'tcp.options']:
        assert id in key , f"the tcp id='{id}' must be in PacketDescriptor field : [{key}]"

    pass

def getFieldByName(fieldName:str,listeField:List[FieldDescriptor]) -> FieldDescriptor:
    fi:FieldDescriptor
    for fi in listeField:
        if fi.id == fieldName:
            return fi
    return None