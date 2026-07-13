import socket
import ssl
import re
import json
import time
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse

from django.conf import settings
from django.utils import timezone as dj_timezone
from apps.core.constants import SeverityChoices
from apps.core.exceptions import ExternalAPIError, ScanError


class PublicIntelligenceInspector:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def inspect(self, scan_job, domain) -> List[Dict]:
        findings = []
        provider = None
        try:
            provider = self._detect_email_provider([])
        except Exception:
            provider = None

        if provider:
            findings.append({
                'title': 'Email provider detected',
                'description': f'Email provider identified as {provider}',
                'severity': SeverityChoices.INFO,
            })

        return findings

    def _detect_email_provider(self, mx_records) -> Optional[str]:
        for record in mx_records or []:
            value = str(record.get('value') or record.get('host') or '').lower()
            if 'aspmx' in value or 'google' in value:
                return 'google_workspace'
            if 'outlook' in value or 'protection.outlook.com' in value:
                return 'microsoft_365'
            if 'office365' in value:
                return 'microsoft_365'
        return None

    def _extract_certificate_subdomains(self, entries) -> List[str]:
        subdomains = []
        seen = set()

        for entry in entries or []:
            values = []
            name_value = entry.get('name_value') or ''
            common_name = entry.get('common_name') or ''

            if isinstance(name_value, str):
                values.extend([item.strip() for item in name_value.splitlines() if item.strip()])
            if isinstance(common_name, str) and common_name.strip():
                values.append(common_name.strip())

            for value in values:
                normalized = self._normalize_hostname(value)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    subdomains.append(normalized)

        return sorted(subdomains)

    def _normalize_hostname(self, value: str) -> Optional[str]:
        if not value:
            return None

        normalized = value.strip().lower().replace('http://', '').replace('https://', '').strip('/')
        if normalized.startswith('*.'):
            return f"www.{normalized[2:]}"
        if normalized.startswith('www.'):
            normalized = normalized[4:]
        if normalized.startswith('.'):
            normalized = normalized[1:]
        return normalized if normalized else None


class DNSInspector:
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def inspect(self, scan_job, domain) -> List[Dict]:
        from apps.discovery.services import DNSResolver
        from apps.domains.models import Domain
        from apps.reconnaissance.models import Finding, EmailSecurityRecord
        
        findings = []
        resolver = DNSResolver(self.timeout)
        
        dns_records = resolver.resolve_all(domain.name)
        
        spf_records = [r for r in dns_records.get('TXT', []) if 'v=spf1' in r.get('value', '')]
        dmarc_records = [r for r in dns_records.get('TXT', []) if 'v=DMARC1' in r.get('value', '')]
        dkim_records = dns_records.get('DKIM', [])
        
        mx_records = dns_records.get('MX', [])
        a_records = dns_records.get('A', [])
        aaaa_records = dns_records.get('AAAA', [])
        
        if not spf_records:
            findings.append(self._create_finding(
                scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.HIGH,
                'SPF Record Missing',
                'No SPF record found. This allows email spoofing.',
                'Add SPF TXT record: v=spf1 include:_spf.google.com ~all',
                impact_score=-15
            ))
        else:
            for spf in spf_records:
                parsed = self._parse_spf(spf['value'])
                if parsed['policy'] == 'PERMISSIVE':
                    findings.append(self._create_finding(
                        scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                        'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'email_security',
                        SeverityChoices.CRITICAL,
                        'SPF Policy Too Permissive',
                        f"SPF uses +all mechanism: {parsed['all_mechanism']}",
                        'Change SPF to use ~all or -all mechanism',
                        impact_score=-15
                    ))
        
        if not dmarc_records:
            findings.append(self._create_finding(
                scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.HIGH,
                'DMARC Record Missing',
                'No DMARC record found. Email spoofing not prevented.',
                'Add DMARC TXT record: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com',
                impact_score=-15
            ))
        else:
            for dmarc in dmarc_records:
                parsed = self._parse_dmarc(dmarc['value'])
                if parsed['policy'] == 'none':
                    findings.append(self._create_finding(
                        scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                        'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'email_security',
                        SeverityChoices.HIGH,
                        'DMARC Policy Not Enforced',
                        f"DMARC policy is p=none: {parsed['policy']}",
                        'Set DMARC policy to p=quarantine or p=reject',
                        impact_score=-10
                    ))
        
        if not dkim_records:
            findings.append(self._create_finding(
                scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.MEDIUM,
                'DKIM Records Missing',
                'No DKIM records found. Email authenticity not verified.',
                'Configure DKIM signing for outbound email',
                impact_score=-10
            ))
        
        zone_transfer = resolver.check_zone_transfer(domain.name)
        if zone_transfer['vulnerable']:
            for ns in zone_transfer['nameservers']:
                findings.append(self._create_finding(
                    scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                    'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'infrastructure_hygiene',
                    SeverityChoices.HIGH,
                    'DNS Zone Transfer Allowed',
                    f"Zone transfer allowed on {ns['nameserver']}",
                    'Disable zone transfers or restrict to authorized servers',
                    impact_score=-10
                ))
        
        wildcard = resolver.check_wildcard_dns(domain.name)
        if wildcard:
            findings.append(self._create_finding(
                scan_job, domain, 'dns_intelligence', 'domain', domain.name,
                'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'exposure_surface',
                SeverityChoices.LOW,
                'Wildcard DNS Record',
                'Wildcard DNS record found. May expose unintended subdomains.',
                'Review wildcard DNS necessity',
                impact_score=-5
            ))
        
        return findings
    
    def _parse_spf(self, spf_value):
        parts = spf_value.split()
        all_mechanism = next((p for p in parts if p in ['+all', '-all', '~all', '?all']), None)
        policy = 'PERMISSIVE' if all_mechanism == '+all' else 'SOFT_FAIL' if all_mechanism == '~all' else 'HARD_FAIL' if all_mechanism == '-all' else 'NEUTRAL'
        return {'policy': policy, 'all_mechanism': all_mechanism}
    
    def _parse_dmarc(self, dmarc_value):
        tags = {}
        for part in dmarc_value.split(';'):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                tags[k.strip()] = v.strip()
        return {
            'policy': tags.get('p', 'none'),
            'sp': tags.get('sp', tags.get('p', 'none')),
            'pct': int(tags.get('pct', 100))
        }
    
    def _create_finding(self, scan_job, domain, source_layer, asset_type, asset_value,
                       signal_type, signal_category, dimension, severity,
                       title, description, remediation, impact_score):
        return {
            'scan_job': scan_job,
            'asset': domain,
            'source_layer': source_layer,
            'source_provider': 'dnspython',
            'asset_type': asset_type,
            'asset_value': asset_value,
            'signal_type': signal_type,
            'signal_category': signal_category,
            'dimension': dimension,
            'severity': severity,
            'confidence': 100,
            'title': title,
            'description': description,
            'finding_summary': description,
            'impact_score': impact_score,
            'remediation_action': remediation,
            'remediation_priority': 1 if impact_score <= -15 else 2 if impact_score <= -10 else 3,
            'references': [],
        }


class SSLInspector:
    def __init__(self, timeout=15):
        self.timeout = timeout
    
    def inspect(self, scan_job, domain) -> List[Dict]:
        findings = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((domain.name, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain.name) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    findings.extend(self._check_certificate(scan_job, domain, cert))
                    findings.extend(self._check_protocol(scan_job, domain, protocol))
                    findings.extend(self._check_cipher(scan_job, domain, cipher))
                    findings.extend(self._check_hsts(scan_job, domain, ssock))
                    
        except ssl.SSLError as e:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'misconfiguration', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.CRITICAL,
                'SSL Certificate Error',
                f'SSL verification failed: {str(e)}',
                'Fix SSL certificate configuration',
                impact_score=-20
            ))
        except socket.timeout:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'absence', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.HIGH,
                'SSL Connection Timeout',
                'SSL connection timed out',
                'Check server SSL configuration and firewall',
                impact_score=-10
            ))
        except Exception as e:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'absence', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.MEDIUM,
                'SSL Connection Failed',
                f'Could not establish SSL connection: {str(e)}',
                'Verify SSL is properly configured on port 443',
                impact_score=-10
            ))
        
        return findings
    
    def _check_certificate(self, scan_job, domain, cert) -> List[Dict]:
        findings = []
        
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_after = not_after.replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        
        if days_remaining < 0:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'expiration', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.CRITICAL,
                'SSL Certificate Expired',
                f'Certificate expired {abs(days_remaining)} days ago',
                'Renew SSL certificate immediately',
                impact_score=-20
            ))
        elif days_remaining < 30:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'expiration', 'CERTIFICATE_VALID', 'infrastructure_hygiene',
                SeverityChoices.HIGH,
                'SSL Certificate Expiring Soon',
                f'Certificate expires in {days_remaining} days',
                'Renew SSL certificate before expiry',
                impact_score=-10
            ))
        elif days_remaining < 60:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'expiration', 'CERTIFICATE_VALID', 'infrastructure_hygiene',
                SeverityChoices.MEDIUM,
                'SSL Certificate Expiring',
                f'Certificate expires in {days_remaining} days',
                'Schedule SSL certificate renewal',
                impact_score=-5
            ))
        
        issuer = dict(x[0] for x in cert['issuer'])
        if issuer.get('commonName', '').lower().find('letsencrypt') >= 0:
            pass
        elif issuer.get('commonName', '').lower().find('self') >= 0:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'misconfiguration', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.CRITICAL,
                'Self-Signed Certificate',
                'Certificate is self-signed, not trusted by browsers',
                'Obtain certificate from trusted CA',
                impact_score=-20
            ))
        
        san = cert.get('subjectAltName', [])
        domains = [x[1] for x in san if x[0] == 'DNS']
        if not domains:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'misconfiguration', 'CERTIFICATE_INVALID', 'infrastructure_hygiene',
                SeverityChoices.MEDIUM,
                'No Subject Alternative Names',
                'Certificate lacks SAN extension',
                'Reissue certificate with proper SAN',
                impact_score=-5
            ))
        
        return findings
    
    def _check_protocol(self, scan_job, domain, protocol) -> List[Dict]:
        findings = []
        if protocol in ['TLSv1', 'TLSv1.1']:
            findings.append(self._create_finding(
                scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                'misconfiguration', 'SERVICE_VULNERABLE', 'infrastructure_hygiene',
                SeverityChoices.HIGH,
                f'Deprecated TLS Protocol ({protocol})',
                f'Server supports deprecated {protocol}',
                'Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3',
                impact_score=-10
            ))
        return findings
    
    def _check_cipher(self, scan_job, domain, cipher) -> List[Dict]:
        findings = []
        if cipher:
            cipher_name = cipher[0]
            if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']):
                findings.append(self._create_finding(
                    scan_job, domain, 'certificate_intelligence', 'domain', domain.name,
                    'misconfiguration', 'SERVICE_VULNERABLE', 'infrastructure_hygiene',
                    SeverityChoices.HIGH,
                    'Weak Cipher Suite',
                    f'Server supports weak cipher: {cipher_name}',
                    'Disable weak cipher suites',
                    impact_score=-10
                ))
        return findings
    
    def _check_hsts(self, scan_job, domain, ssock) -> List[Dict]:
        findings = []
        try:
            headers = ssock.getpeercert()
            hsts_found = False
            for ext in cert.get('extensions', []):
                if ext[0] == 'strict-transport-security':
                    hsts_found = True
                    break
        except:
            pass
        
        if not hsts_found:
            findings.append(self._create_finding(
                scan_job, domain, 'http_security', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'infrastructure_hygiene',
                SeverityChoices.HIGH,
                'HSTS Header Missing',
                'Strict-Transport-Security header not present',
                'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                impact_score=-10
            ))
        return findings
    
    def _create_finding(self, scan_job, domain, source_layer, asset_type, asset_value,
                       signal_type, signal_category, dimension, severity,
                       title, description, remediation, impact_score):
        return {
            'scan_job': scan_job,
            'asset': domain,
            'source_layer': source_layer,
            'source_provider': 'ssl',
            'asset_type': asset_type,
            'asset_value': asset_value,
            'signal_type': signal_type,
            'signal_category': signal_category,
            'dimension': dimension,
            'severity': severity,
            'confidence': 100,
            'title': title,
            'description': description,
            'finding_summary': description,
            'impact_score': impact_score,
            'remediation_action': remediation,
            'remediation_priority': 1 if impact_score <= -15 else 2 if impact_score <= -10 else 3,
            'references': [],
        }


class EmailSecurityInspector:
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def inspect(self, scan_job, domain) -> List[Dict]:
        from apps.discovery.services import DNSResolver
        
        findings = []
        resolver = DNSResolver(self.timeout)
        
        spf_records = resolver.resolve(domain.name, 'TXT')
        spf_record = next((r for r in spf_records if 'v=spf1' in r.get('value', '')), None)
        
        dmarc_records = resolver.resolve(f"_dmarc.{domain.name}", 'TXT')
        dmarc_record = dmarc_records[0] if dmarc_records else None
        
        mx_records = resolver.resolve(domain.name, 'MX')
        
        if spf_record:
            parsed_spf = self._parse_spf(spf_record['value'])
            if parsed_spf['policy'] == 'PERMISSIVE':
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'email_security',
                    SeverityChoices.CRITICAL,
                    'SPF Policy Allows All Senders',
                    f"SPF record uses +all: {spf_record['value']}",
                    'Change SPF to use -all or ~all',
                    impact_score=-15
                ))
            elif parsed_spf['policy'] == 'SOFT_FAIL':
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'email_security',
                    SeverityChoices.MEDIUM,
                    'SPF Uses Soft Fail',
                    f"SPF record uses ~all: {spf_record['value']}",
                    'Consider changing to -all for stricter policy',
                    impact_score=-5
                ))
        else:
            findings.append(self._create_finding(
                scan_job, domain, 'email_security', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.HIGH,
                'No SPF Record',
                'No SPF record published for domain',
                'Add SPF TXT record',
                impact_score=-15
            ))
        
        if dmarc_record:
            parsed_dmarc = self._parse_dmarc(dmarc_record['value'])
            if parsed_dmarc['policy'] == 'none':
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'email_security',
                    SeverityChoices.HIGH,
                    'DMARC Policy Not Enforced',
                    f"DMARC policy is p=none: {dmarc_record['value']}",
                    'Change DMARC policy to p=quarantine or p=reject',
                    impact_score=-15
                ))
            elif parsed_dmarc['policy'] == 'quarantine':
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'presence', 'SECURITY_CONTROL_PRESENT', 'email_security',
                    SeverityChoices.INFO,
                    'DMARC Quarantine Policy Active',
                    f"DMARC policy is p=quarantine",
                    'Consider upgrading to p=reject for maximum protection',
                    impact_score=5
                ))
            elif parsed_dmarc['policy'] == 'reject':
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'presence', 'SECURITY_CONTROL_PRESENT', 'email_security',
                    SeverityChoices.INFO,
                    'DMARC Reject Policy Active',
                    f"DMARC policy is p=reject",
                    'Excellent email authentication configuration',
                    impact_score=10
                ))
        else:
            findings.append(self._create_finding(
                scan_job, domain, 'email_security', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.HIGH,
                'No DMARC Record',
                'No DMARC policy published',
                'Add DMARC TXT record with p=reject',
                impact_score=-15
            ))
        
        dkim_selectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim']
        dkim_found = False
        for selector in dkim_selectors:
            dkim_records = resolver.resolve(f"{selector}._domainkey.{domain.name}", 'TXT')
            if dkim_records:
                dkim_found = True
                findings.append(self._create_finding(
                    scan_job, domain, 'email_security', 'domain', domain.name,
                    'presence', 'SECURITY_CONTROL_PRESENT', 'email_security',
                    SeverityChoices.INFO,
                    'DKIM Selector Found',
                    f"DKIM selector '{selector}' found",
                    'DKIM is configured',
                    impact_score=5
                ))
                break
        
        if not dkim_found:
            findings.append(self._create_finding(
                scan_job, domain, 'email_security', 'domain', domain.name,
                'absence', 'SECURITY_CONTROL_ABSENT', 'email_security',
                SeverityChoices.MEDIUM,
                'No DKIM Selectors Found',
                'No common DKIM selectors found',
                'Configure DKIM signing for outbound email',
                impact_score=-10
            ))
        
        return findings
    
    def _parse_spf(self, spf_value):
        parts = spf_value.split()
        all_mechanism = next((p for p in parts if p in ['+all', '-all', '~all', '?all']), None)
        policy = 'PERMISSIVE' if all_mechanism == '+all' else 'SOFT_FAIL' if all_mechanism == '~all' else 'HARD_FAIL' if all_mechanism == '-all' else 'NEUTRAL'
        return {'policy': policy, 'all_mechanism': all_mechanism}
    
    def _parse_dmarc(self, dmarc_value):
        tags = {}
        for part in dmarc_value.split(';'):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                tags[k.strip()] = v.strip()
        return {
            'policy': tags.get('p', 'none'),
            'sp': tags.get('sp', tags.get('p', 'none')),
            'pct': int(tags.get('pct', 100))
        }
    
    def _create_finding(self, scan_job, domain, source_layer, asset_type, asset_value,
                       signal_type, signal_category, dimension, severity,
                       title, description, remediation, impact_score):
        return {
            'scan_job': scan_job,
            'asset': domain,
            'source_layer': source_layer,
            'source_provider': 'dns_inspection',
            'asset_type': asset_type,
            'asset_value': asset_value,
            'signal_type': signal_type,
            'signal_category': signal_category,
            'dimension': dimension,
            'severity': severity,
            'confidence': 100,
            'title': title,
            'description': description,
            'finding_summary': description,
            'impact_score': impact_score,
            'remediation_action': remediation,
            'remediation_priority': 1 if impact_score <= -15 else 2 if impact_score <= -10 else 3,
            'references': [],
        }


class WebSecurityInspector:
    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TrustScan/1.0 (Digital Trust Scanner)'
        })
    
    def inspect(self, scan_job, domain) -> List[Dict]:
        from apps.reconnaissance.models import Finding, HTTPResponse, SecurityHeaderFinding
        
        findings = []
        
        for scheme in ['https', 'http']:
            url = f"{scheme}://{domain.name}"
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                http_response = HTTPResponse.objects.create(
                    scan_job=scan_job,
                    asset=domain,
                    url=url,
                    method='GET',
                    status_code=response.status_code,
                    response_time_ms=int(response.elapsed.total_seconds() * 1000),
                    request_headers=dict(response.request.headers),
                    response_headers=dict(response.headers),
                    response_body_size=len(response.content),
                    final_url=response.url,
                )
                
                if scheme == 'https':
                    findings.extend(self._check_security_headers(scan_job, domain, http_response, response.headers))
                    findings.extend(self._check_cookies(scan_job, domain, response.cookies))
                
                if response.history:
                    for i, resp in enumerate(response.history):
                        findings.append(self._create_finding(
                            scan_job, domain, 'http_security', 'domain', domain.name,
                            'presence', 'SECURITY_CONTROL_PRESENT', 'exposure_surface',
                            SeverityChoices.LOW,
                            f'Redirect Chain Step {i+1}',
                            f'Redirects from {resp.url} to {response.url}',
                            'Review redirect chain for security',
                            impact_score=-1
                        ))
                
                if scheme == 'http' and response.status_code == 200:
                    findings.append(self._create_finding(
                        scan_job, domain, 'http_security', 'domain', domain.name,
                        'exposure', 'ASSET_EXPOSED', 'exposure_surface',
                        SeverityChoices.MEDIUM,
                        'HTTP Accessible',
                        'Site accessible via unencrypted HTTP',
                        'Redirect all HTTP traffic to HTTPS',
                        impact_score=-5
                    ))
                
            except requests.RequestException:
                pass
        
        return findings
    
    def _check_security_headers(self, scan_job, domain, http_response, headers) -> List[Dict]:
        findings = []
        security_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'check': lambda v: 'max-age' in v,
                'severity_missing': SeverityChoices.HIGH,
                'severity_weak': SeverityChoices.MEDIUM,
                'impact': -10
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'check': lambda v: len(v) > 10,
                'severity_missing': SeverityChoices.MEDIUM,
                'severity_weak': SeverityChoices.LOW,
                'impact': -5
            },
            'X-Frame-Options': {
                'name': 'X-Frame-Options',
                'check': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'],
                'severity_missing': SeverityChoices.MEDIUM,
                'severity_weak': SeverityChoices.LOW,
                'impact': -5
            },
            'X-Content-Type-Options': {
                'name': 'X-Content-Type-Options',
                'check': lambda v: v.lower() == 'nosniff',
                'severity_missing': SeverityChoices.LOW,
                'severity_weak': SeverityChoices.INFO,
                'impact': -2
            },
            'Referrer-Policy': {
                'name': 'Referrer-Policy',
                'check': lambda v: len(v) > 0,
                'severity_missing': SeverityChoices.LOW,
                'severity_weak': SeverityChoices.INFO,
                'impact': -2
            },
            'Permissions-Policy': {
                'name': 'Permissions-Policy',
                'check': lambda v: len(v) > 0,
                'severity_missing': SeverityChoices.INFO,
                'severity_weak': SeverityChoices.INFO,
                'impact': -1
            },
        }
        
        for header_name, config in security_headers.items():
            header_value = headers.get(header_name, '')
            if header_value:
                if config['check'](header_value):
                    findings.append(self._create_finding(
                        scan_job, domain, 'http_security', 'domain', domain.name,
                        'presence', 'SECURITY_CONTROL_PRESENT', 'infrastructure_hygiene',
                        SeverityChoices.INFO,
                        f'{config["name"]} Header Present',
                        f'{header_name}: {header_value[:100]}',
                        'Header properly configured',
                        impact_score=2
                    ))
                else:
                    findings.append(self._create_finding(
                        scan_job, domain, 'http_security', 'domain', domain.name,
                        'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'infrastructure_hygiene',
                        config['severity_weak'],
                        f'{config["name"]} Header Weak',
                        f'{header_name}: {header_value[:100]}',
                        f'Strengthen {config["name"]} header',
                        impact_score=config['impact'] // 2
                    ))
            else:
                findings.append(self._create_finding(
                    scan_job, domain, 'http_security', 'domain', domain.name,
                    'absence', 'SECURITY_CONTROL_ABSENT', 'infrastructure_hygiene',
                    config['severity_missing'],
                    f'{config["name"]} Header Missing',
                    f'{header_name} header not present',
                    f'Add {header_name} header',
                    impact_score=config['impact']
                ))
        
        return findings
    
    def _check_cookies(self, scan_job, domain, cookies) -> List[Dict]:
        findings = []
        for cookie in cookies:
            if cookie.secure and cookie.get('httponly'):
                continue
            
            issues = []
            if not cookie.secure:
                issues.append('Missing Secure flag')
            if not cookie.get('httponly'):
                issues.append('Missing HttpOnly flag')
            if cookie.get('samesite', '').lower() not in ['strict', 'lax', 'none']:
                issues.append('Missing or weak SameSite attribute')
            
            if issues:
                findings.append(self._create_finding(
                    scan_job, domain, 'http_security', 'domain', domain.name,
                    'misconfiguration', 'SECURITY_CONTROL_MISCONFIGURED', 'infrastructure_hygiene',
                    SeverityChoices.MEDIUM,
                    f'Cookie Security Issues: {cookie.name}',
                    '; '.join(issues),
                    'Set Secure, HttpOnly, and SameSite=Strict/Lax on cookies',
                    impact_score=-5
                ))
        
        return findings
    
    def _create_finding(self, scan_job, domain, source_layer, asset_type, asset_value,
                       signal_type, signal_category, dimension, severity,
                       title, description, remediation, impact_score):
        return {
            'scan_job': scan_job,
            'asset': domain,
            'source_layer': source_layer,
            'source_provider': 'http_inspection',
            'asset_type': asset_type,
            'asset_value': asset_value,
            'signal_type': signal_type,
            'signal_category': signal_category,
            'dimension': dimension,
            'severity': severity,
            'confidence': 90,
            'title': title,
            'description': description,
            'finding_summary': description,
            'impact_score': impact_score,
            'remediation_action': remediation,
            'remediation_priority': 1 if impact_score <= -15 else 2 if impact_score <= -10 else 3,
            'references': [],
        }


class TechnologyProfiler:
    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TrustScan/1.0 (Digital Trust Scanner)'
        })
    
    def inspect(self, scan_job, domain) -> List[Dict]:
        from apps.reconnaissance.models import Finding, TechnologyFingerprint
        
        findings = []
        
        try:
            response = self.session.get(f"https://{domain.name}", timeout=self.timeout)
            headers = dict(response.headers)
            html = response.text
            
            techs = self._detect_technologies(headers, html)
            
            for tech in techs:
                TechnologyFingerprint.objects.update_or_create(
                    scan_job=scan_job,
                    asset=domain,
                    category=tech['category'],
                    name=tech['name'],
                    version=tech['version'],
                    defaults={
                        'confidence': tech['confidence'],
                        'detection_method': tech['method'],
                        'evidence': tech['evidence'],
                        'cpe': tech.get('cpe', ''),
                    }
                )
                
                if tech.get('outdated', False):
                    findings.append(self._create_finding(
                        scan_job, domain, 'technology_detection', 'domain', domain.name,
                        'misconfiguration', 'SERVICE_VULNERABLE', 'infrastructure_hygiene',
                        SeverityChoices.HIGH if tech['version'] else SeverityChoices.MEDIUM,
                        f'Outdated Technology: {tech["name"]} {tech["version"]}',
                        f'Detected {tech["name"]} version {tech["version"]} which may be outdated',
                        f'Update {tech["name"]} to latest version',
                        impact_score=-10
                    ))
                else:
                    findings.append(self._create_finding(
                        scan_job, domain, 'technology_detection', 'domain', domain.name,
                        'presence', 'SECURITY_CONTROL_PRESENT', 'infrastructure_hygiene',
                        SeverityChoices.INFO,
                        f'Technology Detected: {tech["name"]} {tech["version"]}',
                        f'Identified {tech["name"]} via {tech["method"]}',
                        'Keep software updated',
                        impact_score=1
                    ))
        
        except requests.RequestException:
            pass
        
        return findings
    
    def _detect_technologies(self, headers, html) -> List[Dict]:
        techs = []
        
        server = headers.get('Server', '')
        if server:
            techs.append({
                'category': 'server',
                'name': self._extract_name(server),
                'version': self._extract_version(server),
                'confidence': 90,
                'method': 'header',
                'evidence': {'Server': server},
            })
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            techs.append({
                'category': 'framework',
                'name': self._extract_name(powered_by),
                'version': self._extract_version(powered_by),
                'confidence': 90,
                'method': 'header',
                'evidence': {'X-Powered-By': powered_by},
            })
        
        tech_signatures = {
            'WordPress': {
                'patterns': ['wp-content', 'wp-includes', 'wordpress'],
                'category': 'cms',
            },
            'Django': {
                'patterns': ['csrfmiddlewaretoken', 'django'],
                'category': 'framework',
            },
            'React': {
                'patterns': ['react', 'React', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'category': 'javascript',
            },
            'Vue.js': {
                'patterns': ['vue.js', 'vuejs', 'Vue', '__VUE__'],
                'category': 'javascript',
            },
            'Angular': {
                'patterns': ['ng-app', 'angular', 'Angular'],
                'category': 'framework',
            },
            'jQuery': {
                'patterns': ['jquery', 'jQuery'],
                'category': 'javascript',
            },
            'Bootstrap': {
                'patterns': ['bootstrap', 'Bootstrap'],
                'category': 'css',
            },
            'Cloudflare': {
                'patterns': ['cloudflare', '__cfduid'],
                'category': 'cdn',
            },
            'Google Analytics': {
                'patterns': ['google-analytics', 'gtag', 'ga('],
                'category': 'analytics',
            },
            'Google Tag Manager': {
                'patterns': ['googletagmanager', 'GTM-'],
                'category': 'analytics',
            },
            'php': {
                'patterns': ['X-Powered-By: PHP'],
                'category': 'language',
            },
            'nginx': {
                'patterns': ['nginx'],
                'category': 'server',
            },
            'Apache': {
                'patterns': ['apache', 'Apache'],
                'category': 'server',
            },
        }
        
        for name, config in tech_signatures.items():
            for pattern in config['patterns']:
                if pattern.lower() in html.lower() or pattern in str(headers):
                    techs.append({
                        'category': config['category'],
                        'name': name,
                        'version': '',
                        'confidence': 70,
                        'method': 'html',
                        'evidence': {'pattern': pattern},
                    })
                    break
        
        return techs
    
    def _extract_name(self, text):
        match = re.match(r'([A-Za-z0-9\-\.]+)', text)
        return match.group(1) if match else text.split('/')[0]
    
    def _extract_version(self, text):
        match = re.search(r'(\d+(?:\.\d+)+)', text)
        return match.group(1) if match else ''
    
    def _create_finding(self, scan_job, domain, source_layer, asset_type, asset_value,
                       signal_type, signal_category, dimension, severity,
                       title, description, remediation, impact_score):
        return {
            'scan_job': scan_job,
            'asset': domain,
            'source_layer': source_layer,
            'source_provider': 'technology_profiler',
            'asset_type': asset_type,
            'asset_value': asset_value,
            'signal_type': signal_type,
            'signal_category': signal_category,
            'dimension': dimension,
            'severity': severity,
            'confidence': 70,
            'title': title,
            'description': description,
            'finding_summary': description,
            'impact_score': impact_score,
            'remediation_action': remediation,
            'remediation_priority': 3,
            'references': [],
        }


from apps.core.constants import SeverityChoices