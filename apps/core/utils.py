import re
import hashlib
import secrets
import uuid
from urllib.parse import urlparse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .constants import (
    AssetTypeChoices, SourceLayerChoices, SignalTypeChoices,
    SeverityChoices, DNSRecordType, EmailSecurityRecord
)


def generate_verification_token(length=32):
    return secrets.token_urlsafe(length)


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def generate_scan_job_id():
    return str(uuid.uuid4())


def validate_domain(domain):
    if not domain:
        raise ValidationError('Domain cannot be empty.')
    
    domain = domain.lower().strip()
    domain = domain.replace('http://', '').replace('https://', '').strip('/')
    
    if '://' in domain:
        domain = urlparse(domain).netloc
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if not domain_pattern.match(domain):
        raise ValidationError(f'Invalid domain format: {domain}')
    
    return domain


def extract_root_domain(domain):
    domain = validate_domain(domain)
    parts = domain.split('.')
    if len(parts) > 2:
        if parts[-2] in ('co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'go', 'or'):
            return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def validate_email_address(email):
    try:
        validate_email(email)
        return email.lower()
    except ValidationError:
        raise ValidationError(f'Invalid email format: {email}')


def infer_email_provider(email):
    domain = email.split('@')[-1].lower()
    providers = {
        'gmail.com': 'Google',
        'googlemail.com': 'Google',
        'outlook.com': 'Microsoft',
        'hotmail.com': 'Microsoft',
        'live.com': 'Microsoft',
        'yahoo.com': 'Yahoo',
        'yahoo.co.uk': 'Yahoo',
        'aol.com': 'AOL',
        'icloud.com': 'Apple',
        'me.com': 'Apple',
        'protonmail.com': 'Proton',
        'zoho.com': 'Zoho',
        'yandex.com': 'Yandex',
        'mail.ru': 'Mail.ru',
    }
    return providers.get(domain, 'Unknown')


def parse_spf_record(txt_record):
    if not txt_record or not txt_record.startswith('v=spf1'):
        return None
    
    mechanisms = []
    for part in txt_record.split():
        if part.startswith(('include:', 'a:', 'mx:', 'ip4:', 'ip6:', 'ptr:', 'exists:')):
            mechanisms.append(part)
        elif part in ('+all', '-all', '~all', '?all'):
            mechanisms.append(('qualifier', part))
    
    qualifier = '~all'
    for mech in mechanisms:
        if isinstance(mech, tuple):
            qualifier = mech[1]
    
    return {
        'version': 'spf1',
        'mechanisms': [m for m in mechanisms if not isinstance(m, tuple)],
        'qualifier': qualifier,
        'policy': 'PERMISSIVE' if qualifier == '+all' else 
                  'SOFT_FAIL' if qualifier == '~all' else
                  'HARD_FAIL' if qualifier == '-all' else 'NEUTRAL',
    }


def parse_dmarc_record(txt_record):
    if not txt_record or not txt_record.startswith('v=DMARC1'):
        return None
    
    policy = 'none'
    pct = 100
    rua = []
    ruf = []
    sp = None
    adkim = 'r'
    aspf = 'r'
    
    for part in txt_record.split(';'):
        part = part.strip()
        if part.startswith('p='):
            policy = part[2:]
        elif part.startswith('pct='):
            pct = int(part[4:])
        elif part.startswith('rua='):
            rua = [x.strip() for x in part[4:].split(',')]
        elif part.startswith('ruf='):
            ruf = [x.strip() for x in part[4:].split(',')]
        elif part.startswith('sp='):
            sp = part[3:]
        elif part.startswith('adkim='):
            adkim = part[6:]
        elif part.startswith('aspf='):
            aspf = part[5:]
    
    return {
        'version': 'DMARC1',
        'policy': policy,
        'percentage': pct,
        'rua': rua,
        'ruf': ruf,
        'subdomain_policy': sp,
        'adkim': adkim,
        'aspf': aspf,
    }


def parse_dkim_selector(txt_record):
    if not txt_record:
        return None
    return {
        'selector': 'default',
        'public_key': txt_record,
        'algorithm': 'rsa',
    }


def extract_subdomain_pattern(subdomain):
    sensitive_keywords = [
        'admin', 'administrator', 'panel', 'dashboard', 'control',
        'phpmyadmin', 'pma', 'mysql', 'database', 'db',
        'api', 'api-v1', 'api-v2', 'rest', 'graphql',
        'staging', 'stage', 'test', 'dev', 'development',
        'pay', 'payment', 'billing', 'checkout', 'shop',
        'secure', 'security', 'auth', 'login', 'sso',
        'vpn', 'remote', 'rdp', 'ssh', 'ftp',
        'mail', 'webmail', 'owa', 'autodiscover',
        'cpanel', 'whm', 'plesk', 'directadmin',
        'jenkins', 'gitlab', 'github', 'bitbucket',
        'monitor', 'grafana', 'prometheus', 'kibana',
        'backup', 'storage', 's3', 'blob',
    ]
    
    subdomain_lower = subdomain.lower()
    for keyword in sensitive_keywords:
        if keyword in subdomain_lower:
            return keyword
    return None


def normalize_ip(ip):
    if ':' in ip and '.' not in ip:
        return ip.lower()
    return ip


def is_private_ip(ip):
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('169.254.0.0', '169.254.255.255'),
    ]
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        for start, end in private_ranges:
            if ipaddress.ip_address(start) <= ip_obj <= ipaddress.ip_address(end):
                return True
    except ValueError:
        pass
    return False


def calculate_confidence_score(layers_with_data, total_layers=12, high_confidence_signals=0, total_signals=0):
    base_confidence = (layers_with_data / total_layers) * 100
    if total_signals > 0:
        data_quality = (high_confidence_signals / total_signals) * 100
    else:
        data_quality = 0
    return round((base_confidence * 0.6) + (data_quality * 0.4))


def sanitize_filename(filename):
    return re.sub(r'[^\w\s.-]', '', filename).strip()


def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def truncate_text(text, max_length=500):
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + '...'