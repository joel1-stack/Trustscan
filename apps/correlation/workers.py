"""
Correlation engine Celery workers.
"""
from typing import Dict, List

from celery import shared_task
from django.utils import timezone

from apps.correlation.engine import CorrelationEngine
from apps.core.exceptions import ScanError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_correlation(self, scan_job_id: str, findings_summary: Dict = None):
    from apps.scanner.models import ScanJob
    from apps.correlation.models import Correlation, PatternMatch

    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ScanError(f"Scan job {scan_job_id} not found")

    scan_job.start_phase('correlation')

    engine = CorrelationEngine()
    correlations, pattern_matches = engine.evaluate(scan_job)

    for corr_data in correlations:
        Correlation.objects.create(**corr_data)

    for match_data in pattern_matches:
        PatternMatch.objects.create(
            scan_job=scan_job,
            rule_id=match_data.get('rule_id', ''),
            matched=match_data['matched'],
            matched_findings=match_data['matched_findings'],
            matched_signals=match_data['matched_signals'],
            evaluation_result=match_data['evaluation_result'],
        )

    scan_job.correlation_count = len(correlations)
    scan_job.correlation_completed_at = timezone.now()
    scan_job.save(update_fields=['correlation_count', 'correlation_completed_at'])

    return {
        'status': 'completed',
        'scan_job_id': scan_job_id,
        'correlations_found': len(correlations),
        'patterns_evaluated': len(pattern_matches),
    }


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def evaluate_correlation_rules(self, scan_job_id: str, rule_ids: List[str] = None):
    from apps.scanner.models import ScanJob
    from apps.correlation.models import Correlation, CorrelationRule, PatternMatch
    from apps.reconnaissance.models import Finding

    scan_job = ScanJob.objects.get(id=scan_job_id)

    if rule_ids:
        rules = CorrelationRule.objects.filter(pattern_id__in=rule_ids, is_active=True)
    else:
        rules = CorrelationRule.objects.filter(is_active=True)

    findings = list(Finding.objects.filter(scan_job=scan_job).select_related('asset'))
    findings_cache: Dict = {}
    for f in findings:
        key = (f.source_layer, f.signal_category, f.dimension, f.severity)
        findings_cache.setdefault(key, []).append(f)

    for rule in rules:
        matched = False
        matched_findings: List[str] = []
        matched_signals: List[Dict] = []

        for condition in rule.condition.get('required_signals', []):
            matches = _find_matching(condition, findings_cache)
            for m in matches:
                matched_findings.append(str(m.id))
                matched_signals.append({
                    'source_layer': m.source_layer,
                    'signal_category': m.signal_category,
                    'severity': m.severity,
                    'dimension': m.dimension,
                    'title': m.title,
                })

        required = len(rule.condition.get('required_signals', []))
        logic = rule.condition.get('logic', 'AND')
        conditions_met = len(matched_findings)

        if logic == 'AND':
            matched = conditions_met >= required
        elif logic == 'OR':
            matched = conditions_met > 0
        else:
            matched = conditions_met >= (required // 2) + 1

        PatternMatch.objects.update_or_create(
            scan_job=scan_job,
            rule=rule,
            defaults={
                'matched': matched,
                'matched_findings': matched_findings,
                'matched_signals': matched_signals,
                'evaluation_result': {
                    'matched': matched,
                    'conditions_met': conditions_met,
                },
            },
        )

        if matched:
            Correlation.objects.update_or_create(
                scan_job=scan_job,
                pattern_id=rule.pattern_id,
                defaults={
                    'pattern_name': rule.name,
                    'risk_level': rule.risk_level,
                    'narrative': rule.narrative_template,
                    'short_description': rule.name,
                    'contributing_findings': matched_findings,
                    'contributing_signals': matched_signals,
                    'affected_dimensions': rule.affected_dimensions,
                    'remediation_priority': rule.remediation_priority,
                    'remediation_steps': rule.remediation_steps,
                    'estimated_score_impact': rule.estimated_score_impact,
                    'confidence': 85,
                },
            )

    return {'status': 'completed', 'rules_evaluated': rules.count()}


def _find_matching(condition: Dict, findings_cache: Dict) -> List:
    """Return all findings that satisfy the given condition dict."""
    import re

    matches: List = []
    source_layer = condition.get('source_layer')
    signal_category = condition.get('signal_category')
    dimension = condition.get('dimension')
    severity = condition.get('severity', [])
    asset_value_pattern = condition.get('asset_value_pattern')

    for (sl, sc, dim, sev), findings in findings_cache.items():
        if source_layer and sl != source_layer:
            continue
        if signal_category and sc != signal_category:
            continue
        if dimension and dim != dimension:
            continue
        if severity and sev not in severity:
            continue

        if asset_value_pattern:
            for f in findings:
                if re.search(asset_value_pattern, f.asset_value, re.IGNORECASE):
                    matches.append(f)
        else:
            matches.extend(findings)

    return matches


@shared_task
def cleanup_old_correlations():
    from apps.correlation.models import Correlation, PatternMatch
    from datetime import timedelta

    cutoff = timezone.now() - timedelta(days=90)
    deleted_corr = Correlation.objects.filter(created_at__lt=cutoff).delete()
    deleted_match = PatternMatch.objects.filter(created_at__lt=cutoff).delete()

    return (
        f'Cleaned up {deleted_corr[0]} correlations '
        f'and {deleted_match[0]} pattern matches'
    )
