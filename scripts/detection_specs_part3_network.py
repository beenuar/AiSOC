"""
Detection Pack v1 - Part 3 / Network (50 new specs)
===================================================

Native network detection rules covering DNS, HTTP/TLS, tunnels, lateral
movement, authentication-protocol abuse and exfiltration patterns. These
extend the network rules in ``detection_specs.NETWORK`` (~30 stable rules).
"""

from __future__ import annotations

from detection_specs_part3_helpers import (  # type: ignore[import-not-found]
    FP_AUTOMATION,
    FP_BACKUP,
    FP_BREAK_GLASS,
    FP_FORENSIC,
    FP_PATCH,
    FP_PENTEST,
    FP_TUNING,
    S,
)


# ---------------------------------------------------------------------------
# DNS (12)
# ---------------------------------------------------------------------------
DNS_RULES: list[dict] = [
    S(slug="net-dns-newly-registered-domain", name="DNS Query For Newly Registered Domain (NRD)",
      severity="medium", mitre=["t1071.004"], product="dns", service="resolver",
      when={"event_type": "dns_query", "domain_age_days_lt": 7},
      fp=["Brand-new SaaS launch (rare; verify business need)"], playbook="tpl-command-and-control"),
    S(slug="net-dns-idn-homoglyph", name="DNS Query For Homoglyph Of Internal Brand",
      severity="high", mitre=["t1583.001"], product="dns", service="resolver",
      when={"event_type": "dns_query", "homoglyph_score_gt": 0.85},
      fp=["Authorized brand-protection scan"], playbook="tpl-initial-access"),
    S(slug="net-dns-nxdomain-spike", name="High Volume Of NXDOMAIN Responses From Single Host",
      severity="medium", mitre=["t1568.002"], product="dns", service="resolver",
      when={"event_type": "dns_response", "rcode": "NXDOMAIN", "count_5min_gt": 200, "src_role": "endpoint"},
      fp=["Malformed in-house tooling (educate)"], playbook="tpl-command-and-control"),
    S(slug="net-dns-any-query-spike", name="DNS Query Type ANY Volume From Single Host",
      severity="medium", mitre=["t1018"], product="dns", service="resolver",
      when={"event_type": "dns_query", "qtype": "ANY", "count_5min_gt": 50},
      fp=["Approved DNS audit run"], playbook="tpl-discovery"),
    S(slug="net-dns-dga-shannon", name="DNS Query With High-Entropy Subdomain (DGA Indicator)",
      severity="high", mitre=["t1568.002"], product="dns", service="resolver",
      when={"event_type": "dns_query", "subdomain_entropy_gt": 4.0, "subdomain_length_gt": 16},
      fp=["CDN with hashed hostnames (allow-listed)"], playbook="tpl-command-and-control"),
    S(slug="net-dns-large-txt-response", name="Large DNS TXT Response (Possible C2)",
      severity="high", mitre=["t1071.004"], product="dns", service="resolver",
      when={"event_type": "dns_response", "qtype": "TXT", "response_size_bytes_gt": 512},
      fp=["DKIM/SPF audit"], playbook="tpl-command-and-control"),
    S(slug="net-dns-tunnel-pattern-len", name="DNS Tunnel Indicator: Long Hex Subdomain Sequence",
      severity="high", mitre=["t1071.004"], product="dns", service="resolver",
      when={"event_type": "dns_query", "subdomain_hex_ratio_gt": 0.9, "subdomain_length_gt": 30},
      fp=["DNSSEC validation lookups"], playbook="tpl-command-and-control"),
    S(slug="net-dns-doh-non-resolver", name="DNS-Over-HTTPS Egress To Non-Sanctioned Resolver",
      severity="high", mitre=["t1572"], product="proxy", service="tls",
      when={"event_type": "tls_session", "destination_port": 443, "sni_endswith_any": ["dns.adguard.com", "cloudflare-dns.com", "dns.google"], "sanctioned_doh": False},
      fp=["Engineer with personal DoH config (educate)"], playbook="tpl-command-and-control"),
    S(slug="net-dns-dot-non-resolver", name="DNS-Over-TLS Egress To Public IP",
      severity="medium", mitre=["t1572"], product="proxy", service="tls",
      when={"event_type": "tls_session", "destination_port": 853, "destination_is_internal": False},
      fp=["Approved upstream resolver"], playbook="tpl-command-and-control"),
    S(slug="net-dns-tor-onion", name="DNS Query For .onion Address",
      severity="critical", mitre=["t1090.003"], product="dns", service="resolver",
      when={"event_type": "dns_query", "domain_endswith": ".onion"},
      fp=["Threat-intel research workstation (allow-listed)"], playbook="tpl-command-and-control"),
    S(slug="net-dns-fast-flux", name="DNS Fast-Flux Pattern (Many A Records, Short TTL)",
      severity="medium", mitre=["t1568.001"], product="dns", service="resolver",
      when={"event_type": "dns_response", "answer_count_gt": 8, "ttl_seconds_lt": 60},
      fp=["Major CDN edge"], playbook="tpl-command-and-control"),
    S(slug="net-dns-rebinding", name="DNS Rebinding Indicator (Public→RFC1918 In Same TTL Window)",
      severity="high", mitre=["t1090"], product="dns", service="resolver",
      when={"event_type": "dns_response", "rebinding_detected": True},
      fp=["IPv6 transition technologies"], playbook="tpl-initial-access"),
]


# ---------------------------------------------------------------------------
# HTTP / TLS (12)
# ---------------------------------------------------------------------------
HTTP_TLS_RULES: list[dict] = [
    S(slug="net-http-connect-public-ip", name="HTTP CONNECT Method Toward Public IP",
      severity="high", mitre=["t1090"], product="proxy", service="http",
      when={"event_type": "http_request", "method": "CONNECT", "destination_is_internal": False},
      fp=["Sanctioned outbound proxy (allow-listed)"], playbook="tpl-command-and-control"),
    S(slug="net-http-userag-powershell", name="HTTP User-Agent Matches PowerShell Default",
      severity="high", mitre=["t1071.001"], product="proxy", service="http",
      when={"event_type": "http_request", "user_agent_contains": "WindowsPowerShell"},
      fp=[FP_AUTOMATION], playbook="tpl-command-and-control"),
    S(slug="net-http-userag-curl-internal", name="curl/wget User-Agent From Workstation Subnet",
      severity="medium", mitre=["t1071.001"], product="proxy", service="http",
      when={"event_type": "http_request", "user_agent_startswith_any": ["curl/", "Wget/"], "src_role": "workstation"},
      fp=["Engineer ad-hoc workflow"], playbook="tpl-command-and-control"),
    S(slug="net-http-host-header-ip", name="HTTP Host Header Is IP Literal",
      severity="medium", mitre=["t1071.001"], product="proxy", service="http",
      when={"event_type": "http_request", "host_is_ip_literal": True},
      fp=["Internal microservice without DNS"], playbook="tpl-command-and-control"),
    S(slug="net-tls-old-client-version", name="TLS Client Offered TLS 1.0 Or 1.1",
      severity="medium", mitre=["t1573.002"], product="proxy", service="tls",
      when={"event_type": "tls_session", "client_version_in": ["TLSv1.0", "TLSv1.1"]},
      fp=["Legacy line-of-business app (allow-listed)"], playbook="tpl-defense-evasion"),
    S(slug="net-tls-no-sni", name="HTTPS Connection To IP Without SNI",
      severity="medium", mitre=["t1573.002"], product="proxy", service="tls",
      when={"event_type": "tls_session", "sni_present": False, "destination_is_internal": False},
      fp=["IoT device with broken TLS stack"], playbook="tpl-command-and-control"),
    S(slug="net-tls-self-signed-egress", name="Self-Signed Certificate Presented On Public IP",
      severity="high", mitre=["t1573.002"], product="proxy", service="tls",
      when={"event_type": "tls_session", "cert_self_signed": True, "destination_is_internal": False},
      fp=["Misconfigured small SaaS vendor"], playbook="tpl-command-and-control"),
    S(slug="net-tls-suspicious-cipher", name="TLS Negotiated Weak Cipher Suite",
      severity="medium", mitre=["t1600.001"], product="proxy", service="tls",
      when={"event_type": "tls_session", "negotiated_cipher_contains_any": ["NULL", "EXPORT", "RC4", "DES"]},
      fp=["Legacy device support"], playbook="tpl-defense-evasion"),
    S(slug="net-jarm-cobalt-strike", name="JARM Fingerprint Matches Known Cobalt Strike Profile",
      severity="critical", mitre=["t1573.002"], product="proxy", service="tls",
      when={"event_type": "tls_session", "jarm_in": ["07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1", "07d19d12d21d21d00042d43d00043d4f51b7c8b9af6b1c7c2a3d4e5f6a7b8c9"]},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
    S(slug="net-jarm-sliver", name="JARM Fingerprint Matches Known Sliver Profile",
      severity="critical", mitre=["t1573.002"], product="proxy", service="tls",
      when={"event_type": "tls_session", "jarm_in": ["3fd3fd0003fd3fd03fd3fd3fd3fd3fd3a458a375eef0c576d23a7bab9a9fb1"]},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
    S(slug="net-http-gzip-mime-mismatch", name="HTTP Response MIME And Content-Encoding Mismatch",
      severity="medium", mitre=["t1027"], product="proxy", service="http",
      when={"event_type": "http_response", "mime_type_in": ["application/octet-stream"], "content_encoding": "gzip", "filename_endswith_any": [".jpg", ".png", ".gif"]},
      fp=["Misconfigured CDN"], playbook="tpl-command-and-control"),
    S(slug="net-http-large-post-from-workstation", name="Large HTTP POST From Workstation To Public IP",
      severity="medium", mitre=["t1041"], product="proxy", service="http",
      when={"event_type": "http_request", "method": "POST", "request_size_bytes_gt": 50000000, "src_role": "workstation", "destination_is_internal": False},
      fp=["Sanctioned cloud upload"], playbook="tpl-exfiltration"),
]


# ---------------------------------------------------------------------------
# Tunnels / proxy (8)
# ---------------------------------------------------------------------------
TUNNEL_RULES: list[dict] = [
    S(slug="net-ssh-reverse-tunnel", name="Outbound SSH With -R Reverse-Tunnel Flag",
      severity="high", mitre=["t1572"], product="proxy", service="ssh",
      when={"event_type": "ssh_command", "argv_contains": "-R"},
      fp=["Engineer working with vendor"], playbook="tpl-command-and-control"),
    S(slug="net-tor-egress-corp", name="Tor Connection From Corporate Workstation",
      severity="high", mitre=["t1090.003"], product="proxy", service="tls",
      when={"event_type": "tls_session", "destination_in_known_tor_relay": True, "src_role": "workstation"},
      fp=["Threat-intel research workstation"], playbook="tpl-command-and-control"),
    S(slug="net-icmp-large-payload", name="ICMP Echo With Unusually Large Payload",
      severity="medium", mitre=["t1095"], product="proxy", service="icmp",
      when={"event_type": "icmp", "payload_size_bytes_gt": 1024},
      fp=["MTU diagnostic"], playbook="tpl-command-and-control"),
    S(slug="net-gre-from-non-network-device", name="GRE Tunnel Initiated By Non-Network Host",
      severity="medium", mitre=["t1572"], product="proxy", service="netflow",
      when={"event_type": "flow", "protocol_number": 47, "src_role_in": ["workstation", "server"]},
      fp=["Approved overlay agent"], playbook="tpl-command-and-control"),
    S(slug="net-wireguard-handshake-from-user", name="WireGuard Handshake From User Workstation",
      severity="medium", mitre=["t1572"], product="proxy", service="netflow",
      when={"event_type": "flow", "destination_port": 51820, "src_role": "workstation"},
      fp=["Approved corporate VPN tier"], playbook="tpl-command-and-control"),
    S(slug="net-vpn-from-datacenter", name="Corporate VPN Login Originating From Datacenter ASN",
      severity="medium", mitre=["t1078.004"], product="vpn", service="auth",
      when={"event_type": "vpn_auth", "src_asn_type": "hosting"},
      fp=["Mobile carrier identified as hosting (false positive)"], playbook="tpl-credential-access"),
    S(slug="net-tor-introduction-onion", name="Tor Introduction To Hidden Service From Corp Host",
      severity="critical", mitre=["t1090.003"], product="proxy", service="tls",
      when={"event_type": "tor_circuit_intro", "circuit_purpose": "HS_CLIENT_INTRO"},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
    S(slug="net-cloudflared-tunnel-egress", name="Cloudflared Tunnel Started From Workstation",
      severity="medium", mitre=["t1572"], product="proxy", service="netflow",
      when={"event_type": "tls_session", "sni_endswith_any": ["argotunnel.com", "tcp.cfargotunnel.com"], "src_role": "workstation"},
      fp=["Authorized engineering tunnel"], playbook="tpl-command-and-control"),
]


# ---------------------------------------------------------------------------
# Lateral / SMB / RPC (10)
# ---------------------------------------------------------------------------
LATERAL_RULES: list[dict] = [
    S(slug="net-smbv1-egress", name="SMB Version 1 Negotiated In Network Flow",
      severity="high", mitre=["t1021.002"], product="firewall", service="netflow",
      when={"event_type": "smb_negotiate", "dialect": "SMB 1.0"},
      fp=["Legacy printer / NAS (allow-listed)"], playbook="tpl-defense-evasion"),
    S(slug="net-smb-write-netlogon", name="SMB Write To NETLOGON Share",
      severity="critical", mitre=["t1570"], product="firewall", service="netflow",
      when={"event_type": "smb_write", "share_name": "NETLOGON"},
      fp=["AD admin GPO push from PAW"], playbook="tpl-lateral-movement"),
    S(slug="net-smb-write-sysvol", name="SMB Write To SYSVOL Share From Non-DC",
      severity="high", mitre=["t1570"], product="firewall", service="netflow",
      when={"event_type": "smb_write", "share_name": "SYSVOL", "src_role_neq": "domain-controller"},
      fp=["Authorised AD migration tool"], playbook="tpl-lateral-movement"),
    S(slug="net-ntlm-relay-pattern", name="NTLM Relay Indicator (Same Challenge Reused Across Hosts)",
      severity="critical", mitre=["t1557.001"], product="firewall", service="netflow",
      when={"event_type": "ntlm_auth", "challenge_reused_across_hosts": True},
      fp=["NTLM relay tested in lab"], playbook="tpl-credential-access"),
    S(slug="net-rpc-remote-registry", name="RPC Remote Registry Write From Workstation Subnet",
      severity="high", mitre=["t1112"], product="firewall", service="rpc",
      when={"event_type": "rpc_call", "interface": "winreg", "operation": "BaseRegSetValue", "src_role": "workstation"},
      fp=["IT remote support tool"], playbook="tpl-lateral-movement"),
    S(slug="net-rpc-task-scheduler-remote", name="RPC Task Scheduler Create From Workstation",
      severity="high", mitre=["t1053.005"], product="firewall", service="rpc",
      when={"event_type": "rpc_call", "interface": "atsvc", "src_role": "workstation"},
      fp=["IT remote support tool"], playbook="tpl-persistence"),
    S(slug="net-winrm-ssl-from-workstation", name="WinRM HTTPS From Workstation To DC",
      severity="high", mitre=["t1021.006"], product="firewall", service="netflow",
      when={"event_type": "flow", "destination_port_in": [5985, 5986], "src_role": "workstation", "destination_role": "domain-controller"},
      fp=["Authorised AD admin from PAW"], playbook="tpl-lateral-movement"),
    S(slug="net-cobalt-strike-named-pipe", name="Cobalt Strike Default Named Pipe Pattern",
      severity="critical", mitre=["t1573.002"], product="firewall", service="netflow",
      when={"event_type": "smb_pipe", "pipe_name_in": ["msagent_", "MSSE-", "postex_", "status_"]},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
    S(slug="net-sliver-named-pipe", name="Sliver Default Named Pipe Pattern",
      severity="critical", mitre=["t1573"], product="firewall", service="netflow",
      when={"event_type": "smb_pipe", "pipe_name_startswith": "sliver_"},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
    S(slug="net-empire-default-uri", name="Empire C2 Default URI Pattern Observed",
      severity="critical", mitre=["t1071.001"], product="proxy", service="http",
      when={"event_type": "http_request", "uri_endswith_any": ["/admin/get.php", "/news.php", "/login/process.php"]},
      fp=[FP_PENTEST], playbook="tpl-command-and-control"),
]


# ---------------------------------------------------------------------------
# Auth / protocol abuse (5)
# ---------------------------------------------------------------------------
AUTH_RULES: list[dict] = [
    S(slug="net-kerberos-rc4-ticket", name="Kerberos Service Ticket Issued With RC4 Encryption",
      severity="high", mitre=["t1558.003"], product="windows", service="kerberos",
      when={"event_id": 4769, "ticket_encryption_type": "0x17"},
      fp=["Legacy app forced RC4 (allow-listed)"], playbook="tpl-credential-access"),
    S(slug="net-kerberos-pre-auth-disabled", name="Kerberos Account With Pre-Auth Disabled Used",
      severity="high", mitre=["t1558.004"], product="windows", service="kerberos",
      when={"event_id": 4768, "preauth_required": False},
      fp=["Legacy SCM service account (must be ticketed)"], playbook="tpl-credential-access"),
    S(slug="net-radius-pap-clear", name="RADIUS Authentication Used PAP (Cleartext Password)",
      severity="high", mitre=["t1110"], product="radius", service="auth",
      when={"event_type": "radius_auth", "auth_method": "PAP"},
      fp=["Legacy device that only supports PAP (must be ticketed)"], playbook="tpl-credential-access"),
    S(slug="net-ldap-signing-disabled", name="LDAP Signing Disabled On Domain Controller",
      severity="high", mitre=["t1557.001"], product="windows", service="ldap",
      when={"event_id": 2889, "ldap_signing_required": False},
      fp=["Vendor agent that doesn't sign (deprecated)"], playbook="tpl-credential-access"),
    S(slug="net-ldap-bloodhound-pattern", name="LDAP Search Pattern Matches BloodHound Collection",
      severity="high", mitre=["t1087.002"], product="windows", service="ldap",
      when={"event_type": "ldap_search", "filter_contains_any": ["objectCategory=group", "objectClass=user", "trustedDomain"], "search_count_5min_gt": 100},
      fp=[FP_PENTEST], playbook="tpl-discovery"),
]


# ---------------------------------------------------------------------------
# Exfil / wireless / misc (3)
# ---------------------------------------------------------------------------
EXFIL_WIRELESS_RULES: list[dict] = [
    S(slug="net-icmp-high-entropy-payload", name="ICMP Echo With High-Entropy Payload",
      severity="high", mitre=["t1095"], product="firewall", service="netflow",
      when={"event_type": "icmp", "payload_entropy_gt": 7.5, "payload_size_bytes_gt": 64},
      fp=["MTU diagnostic"], playbook="tpl-exfiltration"),
    S(slug="net-dhcp-starvation", name="DHCP Starvation: Rapid Lease Churn From Single MAC Range",
      severity="high", mitre=["t1498"], product="firewall", service="dhcp",
      when={"event_type": "dhcp", "leases_per_minute_per_relay_gt": 200},
      fp=["Conference / event Wi-Fi"], playbook="tpl-impact"),
    S(slug="net-stp-topology-change-from-edge", name="STP Topology Change Advertised By Edge Port",
      severity="medium", mitre=["t1498"], product="switch", service="stp",
      when={"event_type": "stp_tcn", "ingress_port_role": "edge"},
      fp=["Approved network change"], playbook="tpl-impact"),
]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
NETWORK_EXTRA: list[dict] = (
    DNS_RULES
    + HTTP_TLS_RULES
    + TUNNEL_RULES
    + LATERAL_RULES
    + AUTH_RULES
    + EXFIL_WIRELESS_RULES
)


__all__ = [
    "NETWORK_EXTRA",
    "DNS_RULES",
    "HTTP_TLS_RULES",
    "TUNNEL_RULES",
    "LATERAL_RULES",
    "AUTH_RULES",
    "EXFIL_WIRELESS_RULES",
]
