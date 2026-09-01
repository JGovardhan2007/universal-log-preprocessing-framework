"""
Unit Tests for Offline GeoIP & ASN Resolver (PRD FR-6)
"""

from core_engine.geoip_resolver import GeoIPResolver


def test_internal_rfc1918_ips():
    geo = GeoIPResolver()
    res_10 = geo.resolve("10.50.1.20")
    assert res_10["is_internal"] is True
    assert "India" in res_10["country"]

    res_192 = geo.resolve("192.168.1.100")
    assert res_192["is_internal"] is True
    assert res_192["country_code"] == "IN-LAN"

    res_172 = geo.resolve("172.16.5.10")
    assert res_172["is_internal"] is True


def test_external_test_ips():
    geo = GeoIPResolver()
    res_us = geo.resolve("203.0.113.15")
    assert res_us["is_internal"] is False
    assert res_us["country"] == "United States"
    assert res_us["country_code"] == "US"

    res_de = geo.resolve("198.51.100.88")
    assert res_de["is_internal"] is False
    assert res_de["country"] == "Germany"


def test_malformed_and_edge_ips():
    geo = GeoIPResolver()
    res_unknown = geo.resolve("0.0.0.0")
    assert res_unknown["country"] == "Unknown"

    res_err = geo.resolve("invalid-ip-address")
    assert res_err["country"] == "Malformed IP"

