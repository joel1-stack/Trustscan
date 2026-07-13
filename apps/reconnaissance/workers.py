from celery import shared_task
from django.utils import timezone
from apps.reconnaissance.inspectors import (
    DNSInspector, SSLInspector, EmailSecurityInspector,
    WebSecurityInspector, TechnologyProfiler
)
from apps.core.exceptions import ScanError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_reconnaissance(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    
    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f"Scan job {scan_job_id} not found")
    
    scan_job.start_phase('reconnaissance')
    
    domain = scan_job.domain
    all_findings = []
    
    inspectors = [
        ('dns', DNSInspector()),
        ('ssl', SSLInspector()),
        ('email', EmailSecurityInspector()),
        ('web', WebSecurityInspector()),
        ('technology', TechnologyProfiler()),
    ]
    
    for name, inspector in inspectors:
        try:
            findings = inspector.inspect(scan_job, domain)
            all_findings.extend(findings)
        except Exception as e:
            Finding.objects.create(
                scan_job=scan_job,
                asset=domain,
                source_layer='reconnaissance',
                source_provider=name,
                asset_type='domain',
                asset_value=domain.name,
                signal_type='absence',
                signal_category='SECURITY_CONTROL_ABSENT',
                dimension='infrastructure_hygiene',
                severity='medium',
                confidence=50,
                title=f'{name.title()} Inspector Failed',
                description=f'Inspector {name} encountered an error: {str(e)}',
                finding_summary=f'{name} inspection failed',
                impact_score=-1,
                remediation_action=f'Check {name} inspector configuration',
                remediation_priority=5,
            )
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for finding_data in all_findings:
        severity = finding_data.get('severity', 'info')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        Finding.objects.create(**finding_data)
    
    scan_job.findings_count = len(all_findings)
    scan_job.critical_count = severity_counts['critical']
    scan_job.high_count = severity_counts['high']
    scan_job.medium_count = severity_counts['medium']
    scan_job.low_count = severity_counts['low']
    scan_job.info_count = severity_counts['info']
    scan_job.reconnaissance_completed_at = timezone.now()
    scan_job.save(update_fields=[
        'findings_count', 'critical_count', 'high_count', 'medium_count', 
        'low_count', 'info_count', 'reconnaissance_completed_at'
    ])
    
    return {
        'status': 'completed',
        'scan_job_id': scan_job_id,
        'findings_count': len(all_findings),
        'severity_counts': severity_counts,
    }


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_dns_inspection(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.reconnaissance.inspectors import DNSInspector
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    inspector = DNSInspector()
    findings = inspector.inspect(scan_job, domain)
    
    for finding_data in findings:
        Finding.objects.create(**finding_data)
    
    return {'status': 'completed', 'findings': len(findings)}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_ssl_inspection(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.reconnaissance.inspectors import SSLInspector
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    inspector = SSLInspector()
    findings = inspector.inspect(scan_job, domain)
    
    for finding_data in findings:
        Finding.objects.create(**finding_data)
    
    return {'status': 'completed', 'findings': len(findings)}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_email_security_inspection(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.reconnaissance.inspectors import EmailSecurityInspector
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    inspector = EmailSecurityInspector()
    findings = inspector.inspect(scan_job, domain)
    
    for finding_data in findings:
        Finding.objects.create(**finding_data)
    
    return {'status': 'completed', 'findings': len(findings)}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_web_security_inspection(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.reconnaissance.inspectors import WebSecurityInspector
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    inspector = WebSecurityInspector()
    findings = inspector.inspect(scan_job, domain)
    
    for finding_data in findings:
        Finding.objects.create(**finding_data)
    
    return {'status': 'completed', 'findings': len(findings)}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_technology_profiling(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding, TechnologyFingerprint
    from apps.reconnaissance.inspectors import TechnologyProfiler
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    inspector = TechnologyProfiler()
    findings = inspector.inspect(scan_job, domain)
    
    for finding_data in findings:
        Finding.objects.create(**finding_data)
    
    return {'status': 'completed', 'findings': len(findings)}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_exposure_detection(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding, Asset
    from apps.core.constants import SeverityChoices
    import shodan
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    shodan_key = getattr(settings, 'SHODAN_API_KEY', None)
    if not shodan_key:
        return {'status': 'skipped', 'reason': 'Shodan API key not configured'}
    
    api = shodan.Shodan(shodan_key)
    
    assets = Asset.objects.filter(scan_job=scan_job, asset_type__in=['domain', 'subdomain', 'ip_address'])
    
    for asset in assets:
        try:
            if asset.asset_type == 'ip_address':
                host = api.host(asset.value)
            else:
                try:
                    import socket
                    ip = socket.gethostbyname(asset.value)
                    host = api.host(ip)
                except:
                    continue
            
            for port_info in host.get('data', []):
                port = port_info.get('port')
                service = port_info.get('product', 'unknown')
                version = port_info.get('version', '')
                
                if port in [21, 22, 23, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 27017]:
                    Finding.objects.create(
                        scan_job=scan_job,
                        asset=asset,
                        source_layer='reputation_intelligence',
                        source_provider='shodan',
                        asset_type=asset.asset_type,
                        asset_value=asset.value,
                        signal_type='exposure',
                        signal_category='ASSET_EXPOSED',
                        dimension='exposure_surface',
                        severity=SeverityChoices.HIGH,
                        confidence=90,
                        title=f'Exposed Service: {service} on port {port}',
                        description=f'{service} {version} exposed on port {port}',
                        finding_summary=f'Publicly accessible {service} on port {port}',
                        impact_score=-10,
                        remediation_action=f'Restrict access to port {port} or disable {service} if not needed',
                        remediation_priority=2,
                        raw_data=port_info,
                    )
        
        except shodan.APIError:
            continue
        except Exception:
            continue
    
    return {'status': 'completed'}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_reputation_check(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.core.constants import SeverityChoices
    import requests
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    checks = [
        ('google_safe_browsing', 'Google Safe Browsing', f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "")}'),
        ('virustotal', 'VirusTotal', f'https://www.virustotal.com/api/v3/domains/{domain.name}'),
    ]
    
    for provider_name, display_name, url in checks:
        try:
            if provider_name == 'google_safe_browsing':
                payload = {
                    "client": {"clientId": "trustscan", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"https://{domain.name}"}]
                    }
                }
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200 and response.json().get('matches'):
                    Finding.objects.create(
                        scan_job=scan_job,
                        asset=domain,
                        source_layer='reputation_intelligence',
                        source_provider=provider_name,
                        asset_type='domain',
                        asset_value=domain.name,
                        signal_type='reputation',
                        signal_category='REPUTATION_NEGATIVE',
                        dimension='reputation_trust',
                        severity=SeverityChoices.CRITICAL,
                        confidence=95,
                        title=f'Malicious Activity Detected by {display_name}',
                        description=f'Domain flagged by {display_name}',
                        finding_summary=f'Domain listed as malicious on {display_name}',
                        impact_score=-20,
                        remediation_action='Investigate and clean up domain reputation',
                        remediation_priority=1,
                    )
            
            elif provider_name == 'virustotal':
                headers = {'x-apikey': getattr(settings, 'VIRUSTOTAL_API_KEY', '')}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                        Finding.objects.create(
                            scan_job=scan_job,
                            asset=domain,
                            source_layer='reputation_intelligence',
                            source_provider=provider_name,
                            asset_type='domain',
                            asset_value=domain.name,
                            signal_type='reputation',
                            signal_category='REPUTATION_NEGATIVE',
                            dimension='reputation_trust',
                            severity=SeverityChoices.HIGH,
                            confidence=90,
                            title=f'Suspicious Activity Detected by {display_name}',
                            description=f'Domain flagged: {stats.get("malicious", 0)} malicious, {stats.get("suspicious", 0)} suspicious',
                            finding_summary=f'Domain has suspicious reputation on {display_name}',
                            impact_score=-10,
                            remediation_action='Investigate and request review from VirusTotal',
                            remediation_priority=2,
                        )
        except Exception:
            pass
    
    return {'status': 'completed'}


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_breach_check(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.core.constants import SeverityChoices
    import requests
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain
    
    hibp_key = getattr(settings, 'HIBP_API_KEY', None)
    if not hibp_key:
        return {'status': 'skipped', 'reason': 'HIBP API key not configured'}
    
    headers = {'hibp-api-key': hibp_key, 'User-Agent': 'TrustScan'}
    
    try:
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breaches?domain={domain.name}',
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            breaches = response.json()
            for breach in breaches:
                Finding.objects.create(
                    scan_job=scan_job,
                    asset=domain,
                    source_layer='breach_intelligence',
                    source_provider='haveibeenpwned',
                    asset_type='domain',
                    asset_value=domain.name,
                    signal_type='breach',
                    signal_category='CREDENTIAL_COMPROMISED',
                    dimension='breach_history',
                    severity=SeverityChoices.HIGH,
                    confidence=95,
                    title=f'Breach: {breach.get("Name", "Unknown")}',
                    description=f'Domain found in {breach.get("Name")} breach on {breach.get("BreachDate")}. Data: {", ".join(breach.get("DataClasses", []))}',
                    finding_summary=f'Domain compromised in {breach.get("Name")} breach',
                    impact_score=-15,
                    remediation_action='Force password reset for affected accounts, monitor for credential stuffing',
                    remediation_priority=1,
                    raw_data=breach,
                    expires_at=timezone.now() + timedelta(days=365),
                )
    except Exception:
        pass
    
    return {'status': 'completed'}