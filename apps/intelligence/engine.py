"""
TrustScan Intelligence Engine
Adds context, benchmarks, trends, threat intel, and regulatory mapping
on top of the raw Trust Score.
"""
import bisect
from typing import Dict, List, Any

from django.utils import timezone
from django.db.models import Avg, Count, StdDev, Min, Max

from apps.core.constants import IndustryChoices, DimensionChoices, TrustScoreStatusChoices


class IntelligenceEngine:
    """Orchestrates all intelligence sub-engines and returns an IntelligenceBrief dict."""

    def __init__(self) -> None:
        self.benchmark_cache: Dict = {}

    def generate_brief(self, scan_job, trust_score) -> Dict[str, Any]:
        return {
            'scan_job_id': str(scan_job.id),
            'trust_score_id': str(trust_score.id),
            'benchmarks': self._calculate_benchmarks(scan_job, trust_score),
            'trends': self._calculate_trends(scan_job, trust_score),
            'threat_context': self._get_threat_context(scan_job, trust_score),
            'regulatory_status': self._check_regulatory_compliance(scan_job, trust_score),
            'predictions': self._generate_predictions(scan_job, trust_score),
            'generated_at': timezone.now().isoformat(),
        }

    # ------------------------------------------------------------------ #
    #  Benchmarks                                                          #
    # ------------------------------------------------------------------ #

    def _calculate_benchmarks(self, scan_job, trust_score) -> Dict:
        from apps.scoring.models import TrustScore as TS

        domain = scan_job.domain
        industry = getattr(domain, 'industry', None) or IndustryChoices.OTHER
        tld = getattr(domain, 'tld', '')

        industry_qs = TS.objects.filter(
            domain__industry=industry,
            domain__is_deleted=False,
        )
        tld_qs = TS.objects.filter(
            domain__tld=tld,
            domain__is_deleted=False,
        )

        industry_stats = industry_qs.aggregate(
            avg=Avg('overall'), count=Count('id'),
            min=Min('overall'), max=Max('overall'),
        )
        tld_stats = tld_qs.aggregate(
            avg=Avg('overall'), count=Count('id'),
            min=Min('overall'), max=Max('overall'),
        )

        all_scores = sorted(
            TS.objects.filter(domain__is_deleted=False).values_list('overall', flat=True)
        )

        percentile = 0
        if all_scores:
            idx = bisect.bisect_left(all_scores, trust_score.overall)
            percentile = round((idx / len(all_scores)) * 100)

        return {
            'industry': industry,
            'industry_average': round(industry_stats['avg'] or 0, 1),
            'industry_percentile': percentile,
            'tld_average': round(tld_stats['avg'] or 0, 1),
            'tld_percentile': percentile,
            'total_scanned_domains': len(all_scores),
        }

    # ------------------------------------------------------------------ #
    #  Trends                                                              #
    # ------------------------------------------------------------------ #

    def _calculate_trends(self, scan_job, trust_score) -> Dict:
        from apps.scoring.models import TrustScore as TS
        from apps.scanner.models import ScanJob

        previous = list(
            TS.objects.filter(
                domain=scan_job.domain,
                calculated_at__lt=trust_score.calculated_at,
            ).order_by('-calculated_at')[:3]
        )

        if not previous:
            return {
                'previous_scan_date': None,
                'previous_score': None,
                'score_change': 0,
                'new_findings': 0,
                'resolved_findings': 0,
                'trend_direction': 'STABLE',
            }

        prev_score = previous[0]
        score_change = trust_score.overall - prev_score.overall

        if score_change > 5:
            direction = 'IMPROVING'
        elif score_change < -5:
            direction = 'DECLINING'
        else:
            direction = 'STABLE'

        prev_scan = (
            ScanJob.objects.filter(
                domain=scan_job.domain,
                completed_at__lt=scan_job.started_at,
                status='completed',
            )
            .order_by('-completed_at')
            .first()
        )

        new_findings = resolved_findings = 0
        if prev_scan:
            current_titles = set(scan_job.findings.values_list('title', flat=True))
            prev_titles = set(prev_scan.findings.values_list('title', flat=True))
            new_findings = len(current_titles - prev_titles)
            resolved_findings = len(prev_titles - current_titles)

        return {
            'previous_scan_date': (
                prev_score.calculated_at.isoformat()
                if prev_score.calculated_at else None
            ),
            'previous_score': prev_score.overall,
            'score_change': score_change,
            'new_findings': new_findings,
            'resolved_findings': resolved_findings,
            'trend_direction': direction,
        }

    # ------------------------------------------------------------------ #
    #  Threat context                                                      #
    # ------------------------------------------------------------------ #

    def _get_threat_context(self, scan_job, trust_score) -> Dict:
        from apps.intelligence.models import ThreatIntel

        domain_name = scan_job.domain.name
        root = '.'.join(domain_name.split('.')[-2:]) if '.' in domain_name else domain_name
        now = timezone.now()

        active_intel = ThreatIntel.objects.filter(
            is_active=True,
            expires_at__gt=now,
        )

        campaigns = []
        for intel in active_intel.filter(indicator_value__icontains=root)[:5]:
            campaigns.append({
                'name': intel.title,
                'target': intel.indicator_value,
                'relevance': intel.description,
                'severity': intel.severity,
            })

        cves = []
        for intel in active_intel.filter(indicator_type='cve')[:10]:
            cves.append({
                'cve_id': intel.indicator_value,
                'product': intel.title,
                'severity': intel.severity,
                'description': (intel.description or '')[:200],
            })

        return {
            'active_campaigns': campaigns,
            'new_cves': cves,
            'regional_threats': [],
        }

    # ------------------------------------------------------------------ #
    #  Regulatory compliance                                               #
    # ------------------------------------------------------------------ #

    def _check_regulatory_compliance(self, scan_job, trust_score) -> Dict:
        from apps.intelligence.models import RegulatoryMapping
        from apps.reconnaissance.models import Finding

        findings = Finding.objects.filter(scan_job=scan_job, is_deleted=False)
        finding_keys = {
            (f.source_layer, f.signal_category, f.severity)
            for f in findings
        }

        mappings = RegulatoryMapping.objects.filter(is_active=True, jurisdiction='KE')
        gaps: List[str] = []

        for mapping in mappings:
            failure_signals = getattr(mapping, 'failure_signals', []) or []
            for signal in failure_signals:
                if tuple(signal) in finding_keys:
                    gap = getattr(mapping, 'compliance_gap_template', '')
                    if gap:
                        gaps.append(gap)
                    break

        if not gaps:
            level = 'COMPLIANT'
        elif len(gaps) <= 2:
            level = 'PARTIAL'
        else:
            level = 'NON_COMPLIANT'

        next_review = (timezone.now() + timezone.timedelta(days=90)).date().isoformat()

        return {
            'regulation': 'Kenya Data Protection Act 2019',
            'compliance_level': level,
            'gaps': gaps,
            'next_review_date': next_review,
        }

    # ------------------------------------------------------------------ #
    #  Predictions                                                         #
    # ------------------------------------------------------------------ #

    def _generate_predictions(self, scan_job, trust_score) -> Dict:
        critical = trust_score.critical_count
        high = trust_score.high_count
        dimensions = trust_score.dimensions  # uses the @property on TrustScore

        min_dim = min(dimensions.values()) if dimensions else 100

        risk_score = (critical * 0.4) + (high * 0.2) + ((100 - min_dim) * 0.1)
        probability = round(min(0.95, max(0.05, risk_score / 100)), 2)

        vectors: List[str] = []
        if dimensions.get(DimensionChoices.EMAIL_SECURITY, 100) < 50:
            vectors.append('Email spoofing leading to credential theft')
        if dimensions.get(DimensionChoices.EXPOSURE_SURFACE, 100) < 50:
            vectors.append('Exposed services vulnerable to exploitation')
        if dimensions.get(DimensionChoices.BREACH_HISTORY, 100) < 50:
            vectors.append('Credential reuse from previous breaches')
        if not vectors:
            vectors.append('General security hygiene improvements needed')

        urgency = 'HIGH' if probability > 0.7 else ('MEDIUM' if probability > 0.4 else 'LOW')

        return {
            'risk_window': '6 months',
            'incident_probability': probability,
            'primary_risk_vector': vectors[0],
            'mitigation_urgency': urgency,
        }


# ------------------------------------------------------------------ #
#  Benchmark Engine (standalone — used by management tasks)          #
# ------------------------------------------------------------------ #

class BenchmarkEngine:
    """Recalculates aggregate benchmarks for all industry × TLD combinations."""

    TLDS = [None, 'com', 'ke', 'org', 'net', 'co']

    def update_benchmarks(self) -> int:
        from apps.intelligence.models import Benchmark
        from apps.scoring.models import TrustScore
        from apps.core.constants import IndustryChoices

        updated = 0
        for industry in IndustryChoices.values:
            for tld in self.TLDS:
                qs = TrustScore.objects.filter(
                    domain__industry=industry,
                    domain__is_deleted=False,
                    calculated_at__gte=timezone.now() - timezone.timedelta(days=30),
                )
                if tld:
                    qs = qs.filter(domain__tld=tld)

                if qs.count() < 10:
                    continue

                stats = qs.aggregate(
                    avg=Avg('overall'),
                    min=Min('overall'),
                    max=Max('overall'),
                    std=StdDev('overall'),
                )

                sorted_scores = list(qs.order_by('overall').values_list('overall', flat=True))
                n = len(sorted_scores)
                percentiles: Dict[str, int] = {}
                for p in [10, 25, 50, 75, 90, 95, 99]:
                    idx = max(0, min(n - 1, int(n * p / 100)))
                    percentiles[f'p{p}'] = sorted_scores[idx]

                period_start = timezone.now().replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )

                Benchmark.objects.update_or_create(
                    industry=industry,
                    tld=tld or '',
                    period_start=period_start,
                    defaults={
                        'period_end': timezone.now(),
                        'sample_size': n,
                        'average_score': round(stats['avg'] or 0, 2),
                        'median_score': percentiles.get('p50', 0),
                        'std_deviation': round(stats['std'] or 0, 2),
                        'percentiles': percentiles,
                        'top_score': stats['max'] or 0,
                        'bottom_score': stats['min'] or 0,
                    },
                )
                updated += 1

        return updated


# ------------------------------------------------------------------ #
#  Threat Engine                                                       #
# ------------------------------------------------------------------ #

class ThreatEngine:
    """Fetches ThreatIntel records relevant to a domain's findings."""

    def get_relevant_threats(self, domain, findings) -> List:
        from apps.intelligence.models import ThreatIntel

        now = timezone.now()
        relevant = []

        for finding in findings:
            if finding.source_layer == 'breach_intelligence':
                relevant.extend(
                    ThreatIntel.objects.filter(
                        is_active=True,
                        indicator_type='email',
                        indicator_value__icontains=finding.asset_value,
                        expires_at__gt=now,
                    )
                )
            elif finding.source_layer == 'reputation_intelligence':
                relevant.extend(
                    ThreatIntel.objects.filter(
                        is_active=True,
                        indicator_type='domain',
                        indicator_value__icontains=finding.asset_value,
                        expires_at__gt=now,
                    )
                )

        return relevant
