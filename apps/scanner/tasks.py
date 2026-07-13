"""
Scan orchestration tasks.
Each phase hands off to the next via a dedicated Celery task so every
phase is independently retryable and traceable.
"""
from celery import shared_task
from django.db import models
from django.utils import timezone

from apps.core.exceptions import ScanError, AuthorizationError


# ------------------------------------------------------------------ #
#  Constants (avoid circular imports from scanner.models at module    #
#  level — we import inside each task)                                #
# ------------------------------------------------------------------ #
STATUS_AUTHORIZED = 'authorized'
STATUS_DISCOVERING = 'discovering'
STATUS_RECONNAISSING = 'reconnaissing'
STATUS_CORRELATING = 'correlating'
STATUS_SCORING = 'scoring'
STATUS_INTELLIGENCING = 'intelligencing'
STATUS_REPORTING = 'reporting'
STATUS_COMPLETED = 'completed'
STATUS_FAILED = 'failed'
STATUS_TIMEOUT = 'timeout'


# ------------------------------------------------------------------ #
#  Orchestrator                                                        #
# ------------------------------------------------------------------ #

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def orchestrate_scan(self, scan_job_id: str):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.discovery.workers import run_discovery

    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f'Scan job {scan_job_id} not found')

    if scan_job.status != STATUS_AUTHORIZED:
        scan_job.transition_to(STATUS_FAILED, 'Scan must be in AUTHORIZED state to start')
        return {'status': 'failed', 'reason': 'not_authorized'}

    scan_job.start()
    scan_job.transition_to(STATUS_DISCOVERING)

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='discovery',
        status='started',
        started_at=timezone.now(),
    )

    try:
        run_discovery.delay(str(scan_job.id))
    except Exception as exc:
        scan_job.transition_to(STATUS_FAILED, f'Discovery queue error: {exc}')
        raise


# ------------------------------------------------------------------ #
#  Phase callbacks                                                     #
# ------------------------------------------------------------------ #

@shared_task(bind=True)
def handle_discovery_complete(self, scan_job_id: str, discovery_map: dict):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.reconnaissance.workers import run_reconnaissance

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.discovery_map = discovery_map
    scan_job.start_phase('reconnaissance')
    scan_job.save(update_fields=['discovery_map', 'current_phase', 'phase_started_at'])

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='discovery'
    ).update(
        status='completed',
        completed_at=timezone.now(),
        findings_count=len(discovery_map.get('discovered_subdomains', [])),
    )

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='reconnaissance',
        status='started',
        started_at=timezone.now(),
    )

    run_reconnaissance.delay(str(scan_job.id))


@shared_task(bind=True)
def handle_reconnaissance_complete(self, scan_job_id: str, findings_summary: dict):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.correlation.workers import run_correlation

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.findings_count = findings_summary.get('total', 0)
    scan_job.critical_count = findings_summary.get('critical', 0)
    scan_job.high_count = findings_summary.get('high', 0)
    scan_job.medium_count = findings_summary.get('medium', 0)
    scan_job.low_count = findings_summary.get('low', 0)
    scan_job.info_count = findings_summary.get('info', 0)
    scan_job.start_phase('correlation')
    scan_job.save(update_fields=[
        'findings_count', 'critical_count', 'high_count',
        'medium_count', 'low_count', 'info_count',
        'current_phase', 'phase_started_at',
    ])

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='reconnaissance'
    ).update(
        status='completed',
        completed_at=timezone.now(),
        findings_count=findings_summary.get('total', 0),
    )

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='correlation',
        status='started',
        started_at=timezone.now(),
    )

    run_correlation.delay(str(scan_job.id))


@shared_task(bind=True)
def handle_correlation_complete(self, scan_job_id: str, correlations: list):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.scoring.workers import run_scoring

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.start_phase('scoring')
    scan_job.save(update_fields=['current_phase', 'phase_started_at'])

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='correlation'
    ).update(status='completed', completed_at=timezone.now())

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='scoring',
        status='started',
        started_at=timezone.now(),
    )

    run_scoring.delay(str(scan_job.id), correlations)


@shared_task(bind=True)
def handle_scoring_complete(self, scan_job_id: str, trust_score_data: dict):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.intelligence.workers import run_intelligence

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.trust_score_value = trust_score_data.get('overall')
    scan_job.score_status = trust_score_data.get('status')
    scan_job.dimension_scores = trust_score_data.get('dimensions', {})
    scan_job.confidence_level = trust_score_data.get('confidence', 0)
    scan_job.start_phase('intelligence')
    scan_job.save(update_fields=[
        'trust_score_value', 'score_status',
        'dimension_scores', 'confidence_level',
        'current_phase', 'phase_started_at',
    ])

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='scoring'
    ).update(status='completed', completed_at=timezone.now())

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='intelligence',
        status='started',
        started_at=timezone.now(),
    )

    run_intelligence.delay(str(scan_job.id))


@shared_task(bind=True)
def handle_intelligence_complete(self, scan_job_id: str, intelligence_brief: dict):
    from apps.scanner.models import ScanJob, ScanPhaseLog
    from apps.reports.workers import generate_reports

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.start_phase('reporting')
    scan_job.save(update_fields=['current_phase', 'phase_started_at'])

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='intelligence'
    ).update(status='completed', completed_at=timezone.now())

    ScanPhaseLog.objects.create(
        scan_job=scan_job,
        phase='reporting',
        status='started',
        started_at=timezone.now(),
    )

    generate_reports.delay(str(scan_job.id))


@shared_task(bind=True)
def handle_reports_complete(self, scan_job_id: str, reports: list):
    from apps.scanner.models import ScanJob, ScanPhaseLog

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.transition_to(STATUS_COMPLETED)

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase='reporting'
    ).update(status='completed', completed_at=timezone.now())

    # Update the domain cache
    domain = scan_job.domain
    domain.last_scanned_at = timezone.now()
    domain.last_scan_status = STATUS_COMPLETED
    domain.scan_count = models.F('scan_count') + 1
    if scan_job.trust_score_value is not None:
        domain.current_trust_score = scan_job.trust_score_value
        domain.current_score_status = scan_job.score_status
    domain.save(update_fields=[
        'last_scanned_at', 'last_scan_status',
        'scan_count', 'current_trust_score', 'current_score_status',
    ])

    return {'status': 'completed', 'scan_job_id': str(scan_job.id)}


# ------------------------------------------------------------------ #
#  Failure handler                                                     #
# ------------------------------------------------------------------ #

@shared_task(bind=True, max_retries=3)
def handle_scan_failure(self, scan_job_id: str, phase: str, error_message: str, error_details=None):
    from apps.scanner.models import ScanJob, ScanPhaseLog

    scan_job = ScanJob.objects.get(id=scan_job_id)
    scan_job.transition_to(STATUS_FAILED, error_message)

    ScanPhaseLog.objects.filter(
        scan_job=scan_job, phase=phase
    ).update(
        status='failed',
        completed_at=timezone.now(),
        error_message=error_message,
    )

    return {'status': 'failed', 'phase': phase, 'error': error_message}


# ------------------------------------------------------------------ #
#  Maintenance tasks                                                   #
# ------------------------------------------------------------------ #

@shared_task
def schedule_recurring_scans():
    from apps.scanner.models import ScanJob, ScanSchedule
    from dateutil.relativedelta import relativedelta
    from datetime import timedelta

    now = timezone.now()
    due = ScanSchedule.objects.filter(is_active=True, next_run_at__lte=now)

    count = 0
    for schedule in due:
        scan_job = ScanJob.objects.create(
            domain=schedule.domain,
            schedule=schedule,
            scan_type=getattr(schedule, 'scan_type', 'full'),
            trigger_source='scheduled',
            authorization_verified=True,
        )
        orchestrate_scan.delay(str(scan_job.id))

        schedule.last_run_at = now
        freq = schedule.frequency
        if freq == 'daily':
            schedule.next_run_at = now + timedelta(days=1)
        elif freq == 'weekly':
            schedule.next_run_at = now + timedelta(weeks=1)
        elif freq == 'monthly':
            schedule.next_run_at = now + relativedelta(months=1)
        elif freq == 'quarterly':
            schedule.next_run_at = now + relativedelta(months=3)
        schedule.save(update_fields=['last_run_at', 'next_run_at'])
        count += 1

    return f'Scheduled {count} scans'


@shared_task
def cleanup_stale_scan_jobs():
    from apps.scanner.models import ScanJob
    from datetime import timedelta

    threshold = timezone.now() - timedelta(minutes=30)
    active_statuses = [
        STATUS_DISCOVERING, STATUS_RECONNAISSING, STATUS_CORRELATING,
        STATUS_SCORING, STATUS_INTELLIGENCING, STATUS_REPORTING,
    ]
    stale = ScanJob.objects.filter(
        status__in=active_statuses,
        phase_started_at__lt=threshold,
    )

    for job in stale:
        job.transition_to(STATUS_TIMEOUT, 'Scan phase timed out after 30 minutes')

    return f'Cleaned up {stale.count()} stale jobs'


@shared_task
def retry_failed_scans():
    from apps.scanner.models import ScanJob

    failed = list(
        ScanJob.objects.filter(
            status=STATUS_FAILED,
        )
        .filter(retry_count__lt=models.F('max_retries'))
        [:10]
    )

    for job in failed:
        job.retry_count += 1
        job.status = 'pending'
        job.error_message = ''
        job.save(update_fields=['retry_count', 'status', 'error_message'])
        orchestrate_scan.delay(str(job.id))

    return f'Retrying {len(failed)} failed scans'
