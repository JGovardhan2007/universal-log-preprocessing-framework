"""
Unit Tests for Phase 2 Parsers (Linux Auth & Suricata IDS)
"""

from core_engine.parser_loader import ParserLoader


def test_linux_auth_ssh_failed():
    loader = ParserLoader("parsers")
    assert "linux_auth" in loader.parsers
    parser = loader.parsers["linux_auth"]
    raw = "Sep 1 08:30:15 server1 sshd[12345]: Failed password for invalid user admin from 203.0.113.88 port 54321 ssh2"

    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("user") == "admin"
    assert tokens.get("src_ip") == "203.0.113.88"
    assert tokens.get("src_port") == "54321"
    assert parser.map_disposition(tokens.get("action")) == "Blocked"


def test_linux_auth_ssh_accepted():
    loader = ParserLoader("parsers")
    parser = loader.parsers["linux_auth"]
    raw = "Sep 1 08:30:20 server1 sshd[12346]: Accepted password for root from 192.168.1.50 port 49152 ssh2"

    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("user") == "root"
    assert tokens.get("src_ip") == "192.168.1.50"
    assert parser.map_disposition(tokens.get("action")) == "Allowed"


def test_suricata_ids_alert():
    loader = ParserLoader("parsers")
    assert "suricata_ids" in loader.parsers
    parser = loader.parsers["suricata_ids"]
    raw = '{"timestamp":"2026-09-01T08:30:00.123456+0000","event_type":"alert","src_ip":"198.51.100.99","src_port":44444,"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET EXPLOIT Apache Struts RCE","category":"Web Application Attack","severity":1}}'

    assert parser.matches_signature(raw) is True
    tokens = parser.parse(raw)
    assert tokens is not None
    assert tokens.get("src_ip") == "198.51.100.99"
    assert tokens.get("dst_ip") == "10.0.0.1"
    assert tokens.get("signature") == "ET EXPLOIT Apache Struts RCE"
    assert parser.map_disposition(tokens.get("action")) == "Blocked"

