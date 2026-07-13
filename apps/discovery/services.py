import dns.resolver
import dns.exception
import dns.query
import dns.zone
import socket
import ssl
import json
import re
import time
import requests
import whois
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone as dj_timezone
from apps.core.exceptions import ExternalAPIError, ScanError


class DNSResolver:
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SPF', 'DMARC', 'DKIM']
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    
    def resolve_all(self, domain: str) -> Dict[str, List[Dict]]:
        results = {}
        for record_type in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results[record_type] = self._parse_answers(answers, record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                results[record_type] = []
            except dns.exception.Timeout:
                results[record_type] = [{'error': 'timeout'}]
            except Exception as e:
                results[record_type] = [{'error': str(e)}]
        return results
    
    def _parse_answers(self, answers, record_type: str) -> List[Dict]:
        results = []
        for rdata in answers:
            if record_type == 'MX':
                results.append({
                    'priority': rdata.preference,
                    'value': str(rdata.exchange).rstrip('.'),
                    'ttl': answers.rrset.ttl if answers.rrset else 0
                })
            elif record_type == 'SOA':
                results.append({
                    'mname': str(rdata.mname).rstrip('.'),
                    'rname': str(rdata.rname).rstrip('.'),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum,
                    'ttl': answers.rrset.ttl if answers.rrset else 0
                })
            elif record_type == 'CAA':
                results.append({
                    'flags': rdata.flags,
                    'tag': rdata.tag,
                    'value': str(rdata.value),
                    'ttl': answers.rrset.ttl if answers.rrset else 0
                })
            else:
                results.append({
                    'value': str(rdata).rstrip('.'),
                    'ttl': answers.rrset.ttl if answers.rrset else 0
                })
        return results
    
    def check_zone_transfer(self, domain: str) -> Dict:
        results = {'vulnerable': False, 'nameservers': []}
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_name)
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=self.timeout))
                    if zone:
                        results['vulnerable'] = True
                        results['nameservers'].append({
                            'nameserver': ns_name,
                            'ip': ns_ip,
                            'records_count': len(zone)
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return results
    
    def check_wildcard_dns(self, domain: str) -> bool:
        try:
            random_sub = f"wildcard-test-{int(time.time())}.{domain}"
            self.resolver.resolve(random_sub, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            return False


class CertificateFetcher:
    CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
    CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TrustScan/1.0 (Digital Trust Scanner)'
        })
    
    def fetch_from_crtsh(self, domain: str) -> List[Dict]:
        url = self.CRT_SH_URL.format(domain=domain)
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise ExternalAPIError(f"crt.sh fetch failed: {str(e)}")
        except json.JSONDecodeError:
            return []
    
    def fetch_from_certspotter(self, domain: str, api_key: str = None) -> List[Dict]:
        if not api_key:
            return []
        
        url = self.CERTSPOTTER_URL.format(domain=domain)
        headers = {'Authorization': f'Bearer {api_key}'}
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return []
    
    def parse_certificate(self, cert_data: Dict, source: str = 'crt.sh') -> Optional[Dict]:
        try:
            if source == 'crt.sh':
                not_before = datetime.fromisoformat(cert_data.get('not_before', '').replace('Z', '+00:00'))
                not_after = datetime.fromisoformat(cert_data.get('not_after', '').replace('Z', '+00:00'))
                
                return {
                    'subdomain': cert_data.get('common_name', ''),
                    'all_domains': cert_data.get('name_value', '').split('\n'),
                    'issuer': cert_data.get('issuer_ca_id', ''),
                    'issuer_name': cert_data.get('issuer_name', ''),
                    'not_before': not_before,
                    'not_after': not_after,
                    'serial_number': cert_data.get('serial_number', ''),
                    'signature_algorithm': '',
                    'public_key_algorithm': '',
                    'public_key_size': 0,
                    'is_valid': not_after > datetime.now(timezone.utc),
                    'is_self_signed': False,
                    'is_wildcard': cert_data.get('common_name', '').startswith('*.'),
                    'days_until_expiry': (not_after - datetime.now(timezone.utc)).days,
                    'source': 'crt.sh'
                }
        except Exception:
            pass
        return None


class WhoisFetcher:
    def __init__(self, timeout=30):
        self.timeout = timeout
    
    def fetch(self, domain: str) -> Dict:
        try:
            w = whois.whois(domain, timeout=self.timeout)
            return self._parse_whois(w)
        except Exception as e:
            return {'error': str(e), 'raw_whois': ''}
    
    def _parse_whois(self, w) -> Dict:
        def get_first(val):
            if isinstance(val, list):
                return val[0] if val else None
            return val
        
        def parse_date(val):
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            if isinstance(val, str):
                for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y', '%Y%m%d']:
                    try:
                        return datetime.strptime(val.strip(), fmt)
                    except ValueError:
                        continue
            return None
        
        return {
            'registrar': get_first(w.registrar) or '',
            'registrar_iana_id': str(get_first(w.registrar_iana_id) or ''),
            'registrar_url': get_first(w.registrar_url) or '',
            'registrant_name': get_first(w.name) or '',
            'registrant_organization': get_first(w.org) or '',
            'registrant_email': get_first(w.emails) or '',
            'registrant_phone': get_first(w.phones) or '',
            'registrant_country': get_first(w.country) or '',
            'registrant_state': get_first(w.state) or '',
            'registrant_city': get_first(w.city) or '',
            'admin_contact': self._parse_contact(w.admin) if hasattr(w, 'admin') else {},
            'tech_contact': self._parse_contact(w.tech) if hasattr(w, 'tech') else {},
            'billing_contact': self._parse_contact(w.billing) if hasattr(w, 'billing') else {},
            'name_servers': [ns.lower().rstrip('.') for ns in (w.name_servers or [])],
            'status': list(w.status) if w.status else [],
            'creation_date': parse_date(get_first(w.creation_date)),
            'expiry_date': parse_date(get_first(w.expiration_date)),
            'updated_date': parse_date(get_first(w.updated_date)),
            'dnssec': bool(get_first(w.dnssec)),
            'privacy_protection': self._check_privacy(w),
            'raw_whois': get_first(w.text) or '',
        }
    
    def _parse_contact(self, contact) -> Dict:
        if not contact:
            return {}
        if isinstance(contact, list):
            contact = contact[0]
        if not isinstance(contact, dict):
            return {}
        return {
            'name': contact.get('name', ''),
            'organization': contact.get('org', ''),
            'email': contact.get('email', ''),
            'phone': contact.get('phone', ''),
            'country': contact.get('country', ''),
            'state': contact.get('state', ''),
            'city': contact.get('city', ''),
        }
    
    def _check_privacy(self, w) -> bool:
        emails = w.emails or []
        privacy_keywords = ['privacy', 'protection', 'proxy', 'whoisguard', 'domainsbyproxy', 'contactprivacy']
        for email in emails:
            if any(kw in email.lower() for kw in privacy_keywords):
                return True
        return False


class PassiveDNSFetcher:
    def __init__(self, securitytrails_key: str = None, virustotal_key: str = None):
        self.securitytrails_key = securitytrails_key
        self.virustotal_key = virustotal_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TrustScan/1.0 (Digital Trust Scanner)'
        })
    
    def fetch_securitytrails(self, domain: str) -> List[Dict]:
        if not self.securitytrails_key:
            return []
        
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {'apikey': self.securitytrails_key}
        try:
            response = self.session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json().get('records', [])
        except requests.RequestException:
            return []
    
    def fetch_virustotal(self, domain: str) -> List[Dict]:
        if not self.virustotal_key:
            return []
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
        headers = {'x-apikey': self.virustotal_key}
        try:
            response = self.session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get('data', [])
        except requests.RequestException:
            return []


class SubdomainEnumerator:
    def __init__(self, wordlist_path: str = None):
        self.wordlist_path = wordlist_path
        self.common_subdomains = self._load_wordlist()
    
    def _load_wordlist(self) -> List[str]:
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                pass
        
        return [
            'www', 'mail', 'webmail', 'email', 'smtp', 'pop', 'imap',
            'admin', 'administrator', 'manage', 'management', 'portal',
            'api', 'api2', 'api3', 'v1', 'v2', 'v3', 'rest', 'graphql',
            'app', 'apps', 'application', 'mobile', 'm', 'wap',
            'dev', 'development', 'test', 'testing', 'staging', 'stage',
            'prod', 'production', 'live', 'release',
            'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongo', 'redis',
            'ftp', 'sftp', 'files', 'download', 'uploads', 'media', 'static', 'assets',
            'cdn', 'cdn1', 'cdn2', 'cloud', 'aws', 'azure', 'gcp',
            'vpn', 'remote', 'rdp', 'ssh', 'shell', 'terminal',
            'monitor', 'monitoring', 'metrics', 'prometheus', 'grafana',
            'log', 'logs', 'logging', 'kibana', 'elasticsearch',
            'ci', 'jenkins', 'gitlab', 'github', 'bitbucket', 'build', 'deploy',
            'pay', 'payment', 'billing', 'invoice', 'checkout', 'shop', 'store',
            'secure', 'security', 'auth', 'login', 'sso', 'oauth', 'saml',
            'support', 'help', 'docs', 'documentation', 'wiki', 'kb', 'knowledge',
            'blog', 'news', 'press', 'media', 'marketing', 'campaign',
            'internal', 'intranet', 'corp', 'corporate', 'employee', 'staff',
            'partner', 'vendor', 'supplier', 'client', 'customer',
            'old', 'legacy', 'archive', 'backup', 'bak', 'temp', 'tmp',
            'beta', 'alpha', 'preview', 'demo', 'sandbox', 'playground',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
            'mx', 'mx1', 'mx2', 'mx3', 'smtp', 'imap', 'pop3',
            'autodiscover', 'autoconfig', 'msoid', 'lyncdiscover',
            'cpanel', 'whm', 'webdisk', 'webmail', 'roundcube', 'horde',
            'phpmyadmin', 'pma', 'mysql', 'sql', 'adminer', 'dbadmin',
            'git', 'svn', 'hg', 'repo', 'repos', 'source', 'code',
            'docker', 'registry', 'k8s', 'kubernetes', 'kube', 'rancher',
            'jenkins', 'ci', 'cd', 'pipeline', 'build', 'artifact',
            'vault', 'secret', 'key', 'config', 'consul', 'etcd',
            'rabbitmq', 'kafka', 'queue', 'msg', 'message', 'event',
            'search', 'elastic', 'solr', 'algolia', 'index',
            'cache', 'redis', 'memcached', 'varnish', 'nginx', 'apache',
            'proxy', 'lb', 'loadbalancer', 'haproxy', 'traefik',
        ]
    
    def enumerate(self, domain: str, resolver: DNSResolver) -> List[str]:
        found = []
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = resolver.resolver.resolve(full_domain, 'A')
                if answers:
                    found.append(full_domain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except dns.exception.Timeout:
                pass
        return found


class DiscoveryService:
    def __init__(self):
        self.dns_resolver = DNSResolver()
        self.cert_fetcher = CertificateFetcher()
        self.whois_fetcher = WhoisFetcher()
        self.passive_dns = PassiveDNSFetcher(
            securitytrails_key=getattr(settings, 'SECURITYTRAILS_API_KEY', None),
            virustotal_key=getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        )
        self.subdomain_enum = SubdomainEnumerator()
    
    def run_discovery(self, domain: str, scan_job_id: str) -> Dict:
        start_time = time.time()
        discovery_map = {
            'domain': domain,
            'root_domain': domain,
            'tld': domain.split('.')[-1],
            'registration': {},
            'dns_records': {},
            'discovered_subdomains': [],
            'certificate_log_entries': [],
            'ip_addresses': [],
            'passive_dns_history': [],
            'errors': [],
            'warnings': [],
        }
        
        try:
            discovery_map['registration'] = self.whois_fetcher.fetch(domain)
        except Exception as e:
            discovery_map['errors'].append(f"WHOIS error: {str(e)}")
        
        try:
            discovery_map['dns_records'] = self.dns_resolver.resolve_all(domain)
        except Exception as e:
            discovery_map['errors'].append(f"DNS error: {str(e)}")
        
        try:
            crt_sh_results = self.cert_fetcher.fetch_from_crtsh(domain)
            cert_entries = []
            for entry in crt_sh_results:
                parsed = self.cert_fetcher.parse_certificate(entry, 'crt.sh')
                if parsed:
                    cert_entries.append(parsed)
            discovery_map['certificate_log_entries'] = cert_entries
        except Exception as e:
            discovery_map['errors'].append(f"Certificate fetch error: {str(e)}")
        
        try:
            enum_subs = self.subdomain_enum.enumerate(domain, self.dns_resolver)
            discovery_map['discovered_subdomains'] = enum_subs
        except Exception as e:
            discovery_map['errors'].append(f"Subdomain enumeration error: {str(e)}")
        
        discovery_map['discovery_duration_ms'] = int((time.time() - start_time) * 1000)
        return discovery_map