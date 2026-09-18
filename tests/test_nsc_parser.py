"""
Tests for nsc_parser pure functions (Module 13a) - real Android
Network Security Config XML shapes per Google's documented schema.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from app.plugins.installed.network_security_config.nsc_parser import analyze_network_security_config


def test_base_config_cleartext_true_flagged_high():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="true" />
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "base-config" in findings[0].title


def test_base_config_cleartext_false_not_flagged():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="false" />
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert findings == []


def test_domain_config_cleartext_flagged_medium_with_domain_name():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <domain-config cleartextTrafficPermitted="true">
            <domain includeSubdomains="true">insecure.example.com</domain>
        </domain-config>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "insecure.example.com" in findings[0].title


def test_user_trust_anchor_in_base_config_flagged():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="user" />
                <certificates src="system" />
            </trust-anchors>
        </base-config>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert len(findings) == 1
    assert "User-added CA" in findings[0].title
    assert findings[0].severity == "high"


def test_system_only_trust_anchor_not_flagged():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="system" />
            </trust-anchors>
        </base-config>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert findings == []


def test_debug_overrides_user_trust_anchor_not_flagged():
    """debug-overrides only applies to debuggable builds -- normal dev tooling, not a release weakness."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="false">
            <trust-anchors>
                <certificates src="system" />
            </trust-anchors>
        </base-config>
        <debug-overrides>
            <trust-anchors>
                <certificates src="user" />
            </trust-anchors>
        </debug-overrides>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert findings == []


def test_secure_config_produces_no_findings():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config cleartextTrafficPermitted="false">
            <trust-anchors>
                <certificates src="system" />
            </trust-anchors>
        </base-config>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert findings == []


def test_multiple_domain_configs_each_evaluated_independently():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <domain-config cleartextTrafficPermitted="true">
            <domain>insecure.example.com</domain>
        </domain-config>
        <domain-config cleartextTrafficPermitted="false">
            <domain>secure.example.com</domain>
        </domain-config>
    </network-security-config>"""
    findings = analyze_network_security_config(xml)
    assert len(findings) == 1
    assert "insecure.example.com" in findings[0].title


def test_malformed_xml_raises_parse_error():
    with pytest.raises(ET.ParseError):
        analyze_network_security_config("<network-security-config><unclosed>")
