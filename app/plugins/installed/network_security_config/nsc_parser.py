"""
app.plugins.installed.network_security_config.nsc_parser
============================================================

Pure parsing of Android's Network Security Config XML
(``res/xml/network_security_config.xml``, referenced from the manifest
via ``android:networkSecurityConfig``). This is Google's own
documented XML schema (developer.android.com/training/articles/security-config)
-- original parsing/checks against a public format, not derived from
any specific existing tool's source.

Checks:
* ``cleartextTrafficPermitted="true"`` in ``base-config`` (applies
  broadly) or ``domain-config`` (scoped to specific domains).
* ``<trust-anchors><certificates src="user"/>`` -- trusts user-added
  CA certificates, which is what makes MITM-proxy interception
  (Burp/mitmproxy) possible; fine for a ``debug-overrides`` block
  (dev-only), a real weakening of TLS protection if present in
  ``base-config``/``domain-config`` (applies to release builds too).

Deliberately only inspects direct children of the root
``<network-security-config>`` element (``base-config``/
``domain-config``), which naturally excludes anything nested inside
``<debug-overrides>`` -- that section only takes effect on debuggable
builds and is a normal, expected part of development tooling, not a
release-build weakness.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkConfigFinding:
    title: str
    severity: str  # "high" | "medium" | "info"
    description: str
    recommendation: str
    finding_key: str | None = None


def analyze_network_security_config(xml_text: str) -> list[NetworkConfigFinding]:
    """Parse a network_security_config.xml string and return findings. Raises ET.ParseError on malformed XML."""
    findings: list[NetworkConfigFinding] = []
    root = ET.fromstring(xml_text)

    base_config = root.find("base-config")
    if base_config is not None:
        findings.extend(_check_cleartext(base_config, scope="base-config (applies to all domains by default)"))
        findings.extend(_check_user_trust_anchors(base_config, scope="base-config"))

    for domain_config in root.findall("domain-config"):
        domains = [d.text for d in domain_config.findall("domain") if d.text]
        scope = f"domain-config ({', '.join(domains)})" if domains else "domain-config"
        findings.extend(_check_cleartext(domain_config, scope=scope))
        findings.extend(_check_user_trust_anchors(domain_config, scope=scope))

    return findings


def _check_cleartext(config_el, scope: str) -> list[NetworkConfigFinding]:
    if config_el.get("cleartextTrafficPermitted") != "true":
        return []
    severity = "high" if scope.startswith("base-config") else "medium"
    return [
        NetworkConfigFinding(
            title=f"Cleartext traffic permitted ({scope})",
            finding_key="android.cleartext_traffic",
            severity=severity,
            description=f'cleartextTrafficPermitted="true" in {scope} allows unencrypted HTTP traffic, '
                         "which can be intercepted or modified by anyone on the network path.",
            recommendation='Set cleartextTrafficPermitted="false" and use HTTPS for all endpoints.',
        )
    ]


def _check_user_trust_anchors(config_el, scope: str) -> list[NetworkConfigFinding]:
    trust_anchors = config_el.find("trust-anchors")
    if trust_anchors is None:
        return []
    findings = []
    for cert in trust_anchors.findall("certificates"):
        if cert.get("src") == "user":
            findings.append(
                NetworkConfigFinding(
                    title=f"User-added CA certificates trusted ({scope})",
                    finding_key="android.user_ca_trusted",
                    severity="high",
                    description=f'{scope} includes <certificates src="user"/>, meaning any CA certificate '
                                 "the device user installs (including one from an attacker who gets it "
                                 "installed, or a MITM proxy tool) will be trusted for TLS validation.",
                    recommendation='Remove src="user" from release-build trust-anchors (keep it only inside '
                                   "<debug-overrides> for development proxy interception).",
                )
            )
    return findings
