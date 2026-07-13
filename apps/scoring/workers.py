"""
Scoring engine Celery workers.
"""
from celery import shared_task
from django.utils import timezone

from apps.core.exceptions import ScanError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_scoring(self, scan_job_id: str, correlations_data: list = None):
    from apps.scanner.models import ScanJob
    from apps.correlation.models import Correlation
    from apps.scoring.engine import ScoringEngine
    from apps.scoring.models import TrustScore, DimensionScore

    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f'Scan job {scan_job_id} not found')

    scan_job.start_phase('scoring')
    scan_job.save(update_fields=['current_phase', 'phase_started_at'])

    engine = ScoringEngine()
    score_data = engine.calculate(scan_job)

    # Persist the TrustScore
    dimensions = score_data['dimensions']
    trust_score = TrustScore.objects.create(
        scan_job=scan_job,
        domain=scan_job.domain,
        overall=score_data['overall'],
        status=score_data['status'],
        email_security=dimensions.get('email_security', 100),
        infrastructure_hygiene=dimensions.get('infrastructure_hygiene', 100),
        exposure_surface=dimensions.get('exposure_surface', 100),
        breach_history=dimensions.get('breach_history', 100),
        reputation_trust=dimensions.get('reputation_trust', 100),
        identity_integrity=dimensions.get('identity_integrity', 100),
        confidence=score_data['confidence'],
        scoring_version='2026.1',
        critical_count=score_data['severity_counts'].get('critical', 0),
        high_count=score_data['severity_counts'].get('high', 0),
        medium_count=score_data['severity_counts'].get('medium', 0),
        low_count=score_data['severity_counts'].get('low', 0),
        info_count=score_data['severity_counts'].get('info', 0),
        correlation_count=score_data['correlation_count'],
        top_risks=score_data['top_risks'],
        top_actions=score_data['top_actions'],
        layers_evaluated=score_data.get('layers_evaluated', []),
        layers_with_data=score_data.get('layers_with_data', 0),
    )

    # Per-dimension records
    for dim_name, dim_score in dimensions.items():
        DimensionScore.objects.create(
            trust_score=trust_score,
            dimension=dim_name,
            score=dim_score,
            base_score=100,
            confidence=score_data['confidence'],
        )

    # Update the previous score / trend on the scan job
    scan_job.trust_score_value = trust_score.overall
    scan_job.score_status = trust_score.status
    scan_job.dimension_scores = dimensions
    scan_job.confidence_level = trust_score.confidence
    scan_job.scoring_completed_at = timezone.now()
    scan_job.save(update_fields=[
        'trust_score_value', 'score_status', 'dimension_scores',
        'confidence_level', 'scoring_completed_at',
    ])

    # Cache current score on domain for fast lookups
    domain = scan_job.domain
    domain.current_trust_score = trust_score.overall
    domain.current_score_status = trust_score.status
    domain.save(update_fields=['current_trust_score', 'current_score_status'])

    return {
        'status': 'completed',
        'scan_job_id': scan_job_id,
        'overall': trust_score.overall,
        'status_label': trust_score.status,
        'dimensions': dimensions,
        'confidence': trust_score.confidence,
    }


@shared_task
def update_domain_trend(domain_id: str):
    """Recalculate the trust score trend for a single domain."""
    from apps.domains.models import Domain
    from apps.scoring.models import TrustScore

    try:
        domain = Domain.objects.get(id=domain_id)
    except Domain.DoesNotExist:
        return {'status': 'error', 'reason': 'domain not found'}

    scores = list(
        TrustScore.objects.filter(domain=domain)
        .order_by('-calculated_at')
        .values_list('overall', flat=True)[:10]
    )

    if len(scores) < 2:
        return {'status': 'skipped', 'reason': 'insufficient data'}

    latest, previous = scores[0], scores[1]
    diff = latest - previous

    trend = 'stable'
    if diff > 5:
        trend = 'improving'
    elif diff < -5:
        trend = 'declining'

    # These fields may not exist on the model yet — update safely
    update_fields = {}
    if hasattr(domain, 'trust_score_trend'):
        domain.trust_score_trend = trend
        update_fields['trust_score_trend'] = trend
    if hasattr(domain, 'trust_score_velocity'):
        domain.trust_score_velocity = diff
        update_fields['trust_score_velocity'] = diff

    if update_fields:
        domain.save(update_fields=list(update_fields.keys()))

    return {'status': 'completed', 'trend': trend, 'change': diff}


@shared_task
def recalculate_all_scores():
    """Queue re-scoring for completed scan jobs that are missing a TrustScore."""
    from apps.scanner.models import ScanJob
    from apps.scoring.models import TrustScore

    scored_job_ids = TrustScore.objects.values_list('scan_job_id', flat=True)
    unscored = ScanJob.objects.filter(
        status='completed',
    ).exclude(id__in=scored_job_ids)[:50]

    count = 0
    for job in unscored:
        run_scoring.delay(str(job.id))
        count += 1

    return f'Queued {count} jobs for scoring'
