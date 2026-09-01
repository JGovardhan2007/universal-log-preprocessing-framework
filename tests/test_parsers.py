"""
Unit Tests for Track 2: Declarative YAML Parsers & Loader
"""

import pytest
from core_engine.parser_loader import ParserLoader



@pytest.fixture
def loader():
    return ParserLoader(parsers_dir="parsers")


def test_parsers_loaded_count(loader):
    # Expect at least 5 standard vendor parsers
    assert len(loader.parsers) >= 5
    assert "cisco_asa" in loader.parsers
    assert "paloalto_panos" in loader.parsers
    assert "fortinet_fortigate" in loader.parsers
    assert "checkpoint_fw" in loader.parsers
    assert "pfsense_suricata" in loader.parsers


def test_cisco_asa_parsing(loader):
    parser = loader.parsers["cisco_asa"]
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.15/44123 dst inside:192.168.1.50/80"
    
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "203.0.113.15"
    assert tokens.get("src_port") == "44123"
    assert tokens.get("src_zone") == "outside"
    assert tokens.get("dst_ip") == "192.168.1.50"
    assert tokens.get("dst_port") == "80"
    assert tokens.get("dst_zone") == "inside"
    assert parser.map_disposition(tokens.get("action")) == "Blocked"


def test_cisco_asa_built_connection(loader):
    parser = loader.parsers["cisco_asa"]
    raw = "%ASA-6-302013: Built inbound TCP connection 987654 for outside:198.51.100.22/52140 (198.51.100.22/52140) to inside:10.0.0.5/443 (10.0.0.5/443)"
    
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "198.51.100.22"
    assert tokens.get("src_port") == "52140"
    assert tokens.get("dst_ip") == "10.0.0.5"
    assert tokens.get("dst_port") == "443"
    assert parser.map_disposition(tokens.get("action")) == "Allowed"


def test_paloalto_panos_parsing(loader):
    parser = loader.parsers["paloalto_panos"]
    raw = "1,2026/09/01 08:30:15,001801000001,TRAFFIC,drop,1,2026/09/01 08:30:15,192.168.1.100,10.0.0.1,0.0.0.0,0.0.0.0,Rule-Block,trust,untrust,ethernet1/1,ethernet1/2,Log-Forward,2026/09/01 08:30:15,12345,1,54321,80,0,0,0x0,tcp,deny,120,60,60,1,2026/09/01 08:30:00,15,any,0,0,0,0,,US,IN,0,1,0"
    
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "192.168.1.100"
    assert tokens.get("dst_ip") == "10.0.0.1"
    assert tokens.get("src_port") == "54321"
    assert tokens.get("dst_port") == "80"
    assert tokens.get("src_zone") == "trust"
    assert tokens.get("dst_zone") == "untrust"
    assert parser.map_disposition(tokens.get("action")) == "Blocked"


def test_fortinet_fortigate_parsing(loader):
    parser = loader.parsers["fortinet_fortigate"]
    raw = 'date=2026-09-01 time=08:30:00 devname="FGT60D" devid="FGT60D12345678" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=192.168.1.50 srcport=54321 srcintf="port1" dstip=10.0.0.5 dstport=443 dstintf="port2" proto=6 action="accept" sentbyte=1200'
    
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("srcip") == "192.168.1.50"
    assert tokens.get("srcport") == "54321"
    assert tokens.get("dstip") == "10.0.0.5"
    assert tokens.get("dstport") == "443"
    assert tokens.get("srcintf") == "port1"
    assert tokens.get("dstintf") == "port2"
    assert parser.map_disposition(tokens.get("action")) == "Allowed"


def test_pfsense_suricata_json_parsing(loader):
    parser = loader.parsers["pfsense_suricata"]
    raw = '{"timestamp":"2026-09-01T08:30:00.123456+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,"dest_ip":"203.0.113.80","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET SCAN"}}'
    
    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "192.168.1.50"
    assert tokens.get("src_port") == 54321
    assert tokens.get("dst_ip") == "203.0.113.80"
    assert tokens.get("dst_port") == 80
    assert parser.map_disposition(tokens.get("action")) == "Blocked"
