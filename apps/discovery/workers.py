from celery import shared_task
from django.utils import timezone
from apps.discovery.services import DiscoveryService
from apps.core.exceptions import ScanError
from celery import shared_task
from django.utils import timezone
from apps.discovery.services import DiscoveryService
from apps.core.exceptions import ScanError
from apps.scanner.models import ScanJob, ScanPhaseLog


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_discovery(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    
    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f"Scan job {scan_job_id} not found")
    
    scan_job.start_phase('discovery')
    
    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='discovery',
        status='started'
    )
    
    try:
        service = DiscoveryService()
        domain = scan_job.domain.name
        
        discovery_result = service.run_discovery(domain, scan_job_id)
        
        scan_job.discovery_map = discovery_result
        scan_job.discovery_duration_seconds = discovery_result.get('discovery_duration_ms', 0) // 1000
        scan_job.discovery_completed_at = timezone.now()
        scan_job.save(update_fields=[
            'discovery_map', 'discovery_duration_seconds', 'discovery_completed_at'
        ])
        
        ScanPhaseLog.objects.filter(
            scan_job=scan_job, phase='discovery'
        ).update(
            status='completed',
            completed_at=timezone.now(),
            duration_seconds=discovery_result.get('discovery_duration_ms', 0) // 1000,
            findings_count=len(discovery_result.get('discovered_subdomains', []))
        )
        
        return {
            'status': 'completed',
            'scan_job_id': scan_job_id,
            'discovery_map': discovery_result
        }
        
    except Exception as e:
        scan_job.transition_to('failed', f"Discovery failed: {str(e)}")
        ScanPhaseLog.objects.filter(
            scan_job=scan_job, phase='discovery'
        ).update(
            status='failed',
            completed_at=timezone.now(),
            error_message=str(e)
        )
        raise


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def run_dns_resolution(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.discovery.models import DNSRecord, Asset
    from apps.discovery.services import DNSResolver
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain.name
    
    resolver = DNSResolver()
    dns_results = resolver.resolve_all(domain)
    
    asset, _ = Asset.objects.get_or_create(
        scan_job=scan_job,
        asset_type='domain',
        normalized_value=domain.lower(),
        defaults={
            'domain': scan_job.domain,
            'value': domain,
            'source': 'dns_intelligence',
        }
    )
    
    for record_type, records in dns_results.items():
        for record in records:
            DNSRecord.objects.update_or_create(
                asset=asset,
                record_type=record_type,
                name=record.get('name', domain),
                value=record.get('value', ''),
                defaults={
                    'scan_job': scan_job,
                    'ttl': record.get('ttl', 0),
                    'priority': record.get('priority'),
                    'resolver': record.get('resolver', '8.8.8.8'),
                    'query_time_ms': record.get('query_time_ms', 0),
                }
            )
    
    return {'dns_records_count': sum(len(r) for r in dns_results.values())}


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def run_certificate_fetch(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.discovery.models import CertificateLogEntry, Asset
    from apps.discovery.services import CertificateFetcher
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain.name
    
    fetcher = CertificateFetcher()
    cert_entries = fetcher.fetch_all(domain)
    
    asset, _ = Asset.objects.get_or_create(
        scan_job=scan_job,
        asset_type='certificate',
        normalized_value=domain.lower(),
        defaults={
            'domain': scan_job.domain,
            'value': domain,
            'source': 'certificate_intelligence',
        }
    )
    
    saved_count = 0
    for entry in cert_entries:
        parsed = fetcher.parse_certificate(entry, entry.get('source', 'crt.sh'))
        if parsed:
            CertificateLogEntry.objects.update_or_create(
                scan_job=scan_job,
                subdomain=parsed.get('subdomain', ''),
                serial_number=parsed.get('serial_number', ''),
                defaults={
                    'asset': asset,
                    'issuer': parsed.get('issuer', ''),
                    'not_before': parsed.get('not_before'),
                    'not_after': parsed.get('not_after'),
                    'san_domains': parsed.get('all_domains', []),
                    'ct_log_source': parsed.get('source', ''),
                }
            )
            saved_count += 1
    
    return {'certificates_found': saved_count}


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_whois_fetch(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.discovery.models import WhoisRecord, Asset
    from apps.discovery.services import WhoisFetcher
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain.name
    
    fetcher = WhoisFetcher()
    whois_data = fetcher.fetch(domain)
    
    asset, _ = Asset.objects.get_or_create(
        scan_job=scan_job,
        asset_type='domain',
        normalized_value=domain.lower(),
        defaults={
            'domain': scan_job.domain,
            'value': domain,
            'source': 'domain_intelligence',
        }
    )
    
    WhoisRecord.objects.update_or_create(
        scan_job=scan_job,
        asset=asset,
        defaults={
            'registrar': whois_data.get('registrar'),
            'creation_date': whois_data.get('creation_date'),
            'expiry_date': whois_data.get('expiry_date'),
            'updated_date': whois_data.get('updated_date'),
            'name_servers': whois_data.get('name_servers', []),
            'status': whois_data.get('status', []),
            'dnssec': whois_data.get('dnssec', False),
            'privacy_protection': whois_data.get('privacy_protection', False),
            'raw_whois': whois_data.get('raw_whois', ''),
        }
    )
    
    return {'whois_fetched': True}


@shared_task(bind=True, max_retries=2, default_retry_delay=120)
def run_passive_dns_fetch(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.discovery.models import Asset
    from apps.discovery.services import PassiveDNSFetcher
    
    scan_job = ScanJob.objects.get(id=scan_job_id)
    domain = scan_job.domain.name
    
    fetcher = PassiveDNSFetcher(
        securitytrails_key=getattr(settings, 'SECURITYTRAILS_API_KEY', None),
        virustotal_key=getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    )
    
    results = []
    
    st_results = fetcher.fetch_securitytrails(domain)
    for record in st_results:
        results.append({
            'subdomain': record.get('hostname', ''),
            'ip': record.get('ip', ''),
            'first_seen': record.get('first_seen'),
            'last_seen': record.get('last_seen'),
            'source': 'securitytrails'
        })
    
    vt_results = fetcher.fetch_virustotal(domain)
    for record in vt_results:
        results.append({
            'subdomain': record.get('id', ''),
            'source': 'virustotal'
        })
    
    asset, _ = Asset.objects.get_or_create(
        scan_job=scan_job,
        asset_type='subdomain',
        normalized_value=domain.lower(),
        defaults={
            'domain': scan_job.domain,
            'value': domain,
            'source': 'asset_discovery',
        }
    )
    
    return {'passive_dns_records': len(results)}