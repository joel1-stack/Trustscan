from celery import shared_task
from django.utils import timezone
from apps.intelligence.engine import ThreatEngine, ThreatCampaign
from apps.scanner.models import ScanJob
from apps.intelligence.models import IntelligenceBrief, Benchmark, ThreatIntel, CVEFeed
from apps.core.exceptions import ScanError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_intelligence(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reconnaissance.models import Finding
    from apps.correlation.models import Correlation
    from apps.scoring.models import TrustScore
    from apps.intelligence.models import IntelligenceBrief, Benchmark, ThreatIntel, CVEFeed
    from apps.intelligence.engine import ThreatEngine
    
    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f"Scan job {scan_job_id} not found")
    
    scan_job.start_phase('intelligence')
    
    domain = scan_job.domain
    trust_score = TrustScore.objects.filter(scan_job=scan_job).first()
    if not trust_score:
        return {'status': 'skipped', 'reason': 'No trust score found'}
    
    findings = list(Finding.objects.filter(scan_job=scan_job, deleted_at__isnull=True, is_false_positive=False))
    correlations = list(Correlation.objects.filter(scan_job=scan_job, deleted_at__isnull=True))
    
    industry = domain.industry
    tld = domain.tld
    
    benchmarks = _get_benchmarks(industry, tld, trust_score.overall)
    
    trends = _calculate_trends(domain, trust_score)
    
    threat_engine = ThreatEngine()
    threat_context = _get_threat_context(domain, findings, correlations)
    
    regulatory = _get_regulatory_status(domain, findings, trust_score)
    
    predictions = _generate_predictions(domain, findings, trust_score)
    
    IntelligenceBrief.objects.create(
        scan_job=scan_job,
        domain=domain,
        trust_score=trust_score,
        industry=industry,
        industry_average=benchmarks.get('industry_average', 0),
        industry_percentile=benchmarks.get('industry_percentile', 50),
        industry_total_domains=benchmarks.get('industry_total', 0),
        tld_average=benchmarks.get('tld_average', 0),
        tld_percentile=benchmarks.get('tld_percentile', 50),
        previous_scan_date=trends.get('previous_scan_date'),
        previous_score=trends.get('previous_score'),
        score_change=trends.get('score_change', 0),
        score_change_percentage=trends.get('score_change_percentage', 0),
        new_findings=trends.get('new_findings', 0),
        resolved_findings=trends.get('resolved_findings', 0),
        worsened_findings=trends.get('worsened_findings', 0),
        improved_findings=trends.get('improved_findings', 0),
        trend_direction=trends.get('trend_direction', 'stable'),
        active_campaigns=threat_context.get('active_campaigns', []),
        new_cves=threat_context.get('new_cves', []),
        regional_threats=threat_context.get('regional_threats', []),
        threat_summary=threat_context.get('threat_summary', ''),
        regulation='Kenya Data Protection Act 2019',
        compliance_level=regulatory.get('compliance_level', 'partial'),
        compliance_gaps=regulatory.get('gaps', []),
        next_review_date=regulatory.get('next_review_date'),
        risk_window=predictions.get('risk_window', '6 months'),
        incident_probability=predictions.get('incident_probability', 0.5),
        primary_risk_vector=predictions.get('primary_risk_vector', ''),
        mitigation_urgency=predictions.get('mitigation_urgency', 'medium'),
    )
    
    scan_job.intelligence_completed_at = timezone.now()
    scan_job.save(update_fields=['intelligence_completed_at'])
    
    return {
        'status': 'completed',
        'scan_job_id': scan_job_id,
        'benchmarks': benchmarks,
        'trends': trends,
        'threats_found': len(threat_context.get('active_campaigns', [])),
    }


def _get_benchmarks(industry, tld, current_score):
    from apps.intelligence.models import Benchmark
    from django.db.models import Avg
    
    qs = Benchmark.objects.filter(
        industry=industry,
        period_start__gte=timezone.now() - timezone.timedelta(days=30)
    )
    
    if tld:
        qs = qs.filter(tld=tld)
    else:
        qs = qs.filter(tld='')
    
    if not qs.exists():
        return {
            'industry_average': 58,
            'industry_percentile': 50,
            'industry_total': 0,
            'tld_average': 52,
            'tld_percentile': 50,
        }
    
    latest = qs.latest('period_start')
    
    if current_score >= latest.percentiles.get('p90', 90):
        percentile = 90
    elif current_score >= latest.percentiles.get('p75', 75):
        percentile = 75
    elif current_score >= latest.percentiles.get('p50', 50):
        percentile = 50
    elif current_score >= latest.percentiles.get('p25', 25):
        percentile = 25
    else:
        percentile = 10
    
    return {
        'industry_average': float(latest.average_score),
        'industry_percentile': percentile,
        'industry_total': latest.sample_size,
        'tld_average': float(latest.average_score),
        'tld_percentile': percentile,
    }


def _calculate_trends(domain, trust_score):
    from apps.scoring.models import TrustScore
    from django.db.models import Avg
    
    previous_scores = TrustScore.objects.filter(
        domain=domain
    ).exclude(id=trust_score.id).order_by('-calculated_at')
    
    if not previous_scores.exists():
        return {
            'previous_scan_date': None,
            'previous_score': None,
            'score_change': 0,
            'score_change_percentage': 0,
            'new_findings': 0,
            'resolved_findings': 0,
            'worsened_findings': 0,
            'improved_findings': 0,
            'trend_direction': 'stable',
        }
    
    prev = previous_scores.first()
    change = trust_score.overall - prev.overall
    pct_change = (change / prev.overall * 100) if prev.overall > 0 else 0
    
    if change > 10:
        direction = 'improving'
    elif change < -10:
        direction = 'declining'
    else:
        direction = 'stable'
    
    return {
        'previous_scan_date': prev.calculated_at,
        'previous_score': prev.overall,
        'score_change': change,
        'score_change_percentage': round(pct_change, 2),
        'new_findings': 0,
        'resolved_findings': 0,
        'worsened_findings': 0,
        'improved_findings': 0,
        'trend_direction': direction,
    }


def _get_threat_context(domain, findings, correlations):
    from apps.intelligence.models import ThreatIntel, ThreatCampaign, CVEFeed
    
    active_campaigns = []
    campaigns = ThreatCampaign.objects.filter(
        is_active=True,
        last_activity__gte=timezone.now() - timezone.timedelta(days=30)
    )
    
    for campaign in campaigns:
        targets_tld = domain.tld in campaign.target_tlds
        targets_sector = domain.industry in campaign.target_sectors
        
        if targets_tld or targets_sector:
            active_campaigns.append({
                'name': campaign.name,
                'target': f"{', '.join(campaign.target_sectors)} / {', '.join(campaign.target_tlds)}",
                'relevance': f"Campaign targets {domain.industry} / {domain.tld}",
                'last_activity': campaign.last_activity.isoformat(),
            })
    
    new_cves = []
    techs = set()
    for f in findings:
        if f.source_layer == 'technology_detection':
            techs.update(f.normalized_data.get('technologies', []))
    
    for tech in techs:
        cves = CVEFeed.objects.filter(
            affected_products__icontains=tech,
            published_date__gte=timezone.now() - timezone.timedelta(days=7),
            severity__in=['high', 'critical']
        )[:5]
        for cve in cves:
            new_cves.append({
                'cve_id': cve.cve_id,
                'product': tech,
                'severity': cve.severity,
                'cvss_score': float(cve.cvss_score) if cve.cvss_score else 0,
                'published_date': cve.published_date.isoformat(),
            })
    
    regional_threats = []
    for intel in ThreatIntel.objects.filter(
        is_active=True,
        expires_at__gt=timezone.now()
    )[:10]:
        regional_threats.append({
            'description': intel.description,
            'recommendation': 'Monitor and implement mitigations',
        })
    
    return {
        'active_campaigns': active_campaigns,
        'new_cves': new_cves,
        'regional_threats': regional_threats,
        'threat_summary': f"Found {len(active_campaigns)} active campaigns targeting your sector/TLD. {len(new_cves)} new critical CVEs affecting your tech stack.",
    }


def _get_regulatory_status(domain, findings, trust_score):
    gaps = []
    
    if domain.industry == 'financial_services':
        gaps.append("CBK Guidelines: Email security for customer communication - DMARC policy not enforced")
    
    ssl_missing = any(
        f.source_layer == 'certificate_intelligence' and f.severity in ['high', 'critical']
        for f in findings
    )
    if ssl_missing:
        gaps.append("Kenya Data Protection Act 2019: SSL required for data transmission")
    
    admin_exposed = any(
        f.asset_type == 'subdomain' and 'admin' in f.asset_value.lower() and f.severity in ['high', 'critical']
        for f in findings
    )
    if admin_exposed:
        gaps.append("Kenya Data Protection Act 2019: Access controls for personal data - Admin panel publicly accessible")
    
    return {
        'compliance_level': 'compliant' if len(gaps) == 0 else 'partial',
        'gaps': gaps,
        'next_review_date': timezone.now() + timezone.timedelta(days=90),
    }


def _generate_predictions(domain, findings, trust_score):
    risk_score = 100 - trust_score.overall
    
    base_prob = min(risk_score / 100, 0.9)
    
    if trust_score.email_security < 30:
        base_prob += 0.2
    if trust_score.exposure_surface < 30:
        base_prob += 0.15
    if trust_score.breach_history < 30:
        base_prob += 0.15
    
    prob = min(base_prob, 0.95)
    
    vectors = []
    if trust_score.email_security < 50:
        vectors.append('Email spoofing leading to credential theft')
    if trust_score.exposure_surface < 50:
        vectors.append('Exposed admin panel or sensitive services')
    if trust_score.breach_history < 50:
        vectors.append('Credential stuffing from previous breaches')
    
    primary_vector = vectors[0] if vectors else 'General attack surface exposure'
    
    if prob > 0.7:
        urgency = 'critical'
    elif prob > 0.5:
        urgency = 'high'
    elif prob > 0.3:
        urgency = 'medium'
    else:
        urgency = 'low'
    
    return {
        'risk_window': '6 months',
        'incident_probability': round(prob, 2),
        'primary_risk_vector': primary_vector,
        'mitigation_urgency': urgency,
    }


@shared_task
def update_benchmarks():
    from apps.intelligence.engine import BenchmarkEngine
    engine = BenchmarkEngine()
    engine.update_all()
    return {'status': 'completed'}


@shared_task
def update_threat_intel():
    from apps.intelligence.models import ThreatIntel
    from apps.intelligence.engine import ThreatEngine
    
    engine = ThreatEngine()
    added = engine.fetch_from_sources()
    return {'status': 'completed', 'added': added}


@shared_task
def update_cve_feed():
    from apps.intelligence.models import CVEFeed
    import requests
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'pubStartDate': (timezone.now() - timezone.timedelta(days=7)).isoformat() + 'Z',
        'resultsPerPage': 100,
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        added = 0
        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            cve_id = cve['id']
            
            CVEFeed.objects.update_or_create(
                cve_id=cve_id,
                defaults={
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                    'published_date': cve.get('published', ''),
                    'modified_date': cve.get('lastModified', ''),
                    'source': 'NVD',
                    'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
            added += 1
        
        return {'status': 'completed', 'added': added}
    except Exception as e:
        return {'status': 'failed', 'error': str(e)}