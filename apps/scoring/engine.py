"""
TrustScan Scoring Engine
Converts reconnaissance findings and correlations into a weighted Trust Score.
"""
from typing import Dict, List, Any

from apps.core.constants import DimensionChoices, TrustScoreStatusChoices


class ScoringEngine:
    """
    Rule-based Trust Score calculator.
    Every point change is explainable and auditable.
    """

    DIMENSION_WEIGHTS: Dict[str, float] = {
        DimensionChoices.EMAIL_SECURITY: 0.20,
        DimensionChoices.INFRASTRUCTURE_HYGIENE: 0.15,
        DimensionChoices.EXPOSURE_SURFACE: 0.15,
        DimensionChoices.BREACH_HISTORY: 0.15,
        DimensionChoices.REPUTATION_TRUST: 0.15,
        DimensionChoices.IDENTITY_INTEGRITY: 0.20,
    }

    # Direct penalty per severity of a single finding
    SEVERITY_IMPACTS: Dict[str, int] = {
        'critical': -20,
        'high': -10,
        'medium': -5,
        'low': -2,
        'info': 1,
    }

    # Multiplicative penalty when a correlation pattern fires
    CORRELATION_PENALTIES: Dict[str, float] = {
        'critical': 0.70,
        'high': 0.85,
        'medium': 0.95,
        'low': 1.00,
    }

    # If any single dimension falls below this floor it caps the overall score
    FLOOR_THRESHOLD = 30
    FLOOR_CAP = 50

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def calculate(self, scan_job) -> Dict[str, Any]:
        """
        Main entry point.  Returns a dict that maps directly onto TrustScore
        model fields.
        """
        from apps.reconnaissance.models import Finding
        from apps.correlation.models import Correlation

        findings: List = list(
            Finding.objects.filter(
                scan_job=scan_job,
                is_deleted=False,
                is_false_positive=False,
            ).select_related('asset')
        )

        correlations: List = list(
            Correlation.objects.filter(
                scan_job=scan_job,
                is_deleted=False,
            )
        )

        # ---- Phase 1: initialise all dimensions at 100 ---- #
        dimensions: Dict[str, int] = {
            DimensionChoices.EMAIL_SECURITY: 100,
            DimensionChoices.INFRASTRUCTURE_HYGIENE: 100,
            DimensionChoices.EXPOSURE_SURFACE: 100,
            DimensionChoices.BREACH_HISTORY: 100,
            DimensionChoices.REPUTATION_TRUST: 100,
            DimensionChoices.IDENTITY_INTEGRITY: 100,
        }

        dimension_details: Dict[str, Any] = {}

        for dimension in list(dimensions.keys()):
            dim_findings = [f for f in findings if f.dimension == dimension]
            signal_impact = 0
            penalties: List[Dict] = []
            bonuses: List[Dict] = []

            for finding in dim_findings:
                impact = getattr(finding, 'impact_score', None)
                if impact is None:
                    impact = self.SEVERITY_IMPACTS.get(finding.severity, 0)

                if impact < 0:
                    penalties.append({
                        'finding_id': str(finding.id),
                        'title': finding.title,
                        'impact': impact,
                        'severity': finding.severity,
                    })
                elif impact > 0:
                    bonuses.append({
                        'finding_id': str(finding.id),
                        'title': finding.title,
                        'impact': impact,
                    })
                signal_impact += impact

            dimensions[dimension] = max(0, min(100, 100 + signal_impact))
            dimension_details[dimension] = {
                'base_score': 100,
                'signal_impact': signal_impact,
                'final_before_correlations': dimensions[dimension],
                'signal_penalties': penalties,
                'signal_bonuses': bonuses,
                'correlation_penalties': [],
            }

        # ---- Phase 2: apply correlation multipliers ---- #
        for correlation in correlations:
            penalty = self.CORRELATION_PENALTIES.get(correlation.risk_level, 1.0)
            affected = getattr(correlation, 'affected_dimensions', []) or []
            for dim in affected:
                if dim in dimensions:
                    old_score = dimensions[dim]
                    dimensions[dim] = max(0, min(100, int(old_score * penalty)))
                    dimension_details[dim]['correlation_penalties'].append({
                        'correlation_id': str(correlation.id),
                        'pattern': correlation.pattern_name,
                        'risk_level': correlation.risk_level,
                        'penalty_factor': penalty,
                        'old_score': old_score,
                        'new_score': dimensions[dim],
                    })

        # ---- Phase 3: floor protection ---- #
        floor_triggered = any(s < self.FLOOR_THRESHOLD for s in dimensions.values())

        # ---- Phase 4: weighted overall ---- #
        overall = round(
            sum(
                dimensions[dim] * weight
                for dim, weight in self.DIMENSION_WEIGHTS.items()
            )
        )

        if floor_triggered:
            overall = min(overall, self.FLOOR_CAP)

        overall = max(0, min(100, overall))

        confidence = self._calculate_confidence(findings)

        severity_counts = {
            'critical': sum(1 for f in findings if f.severity == 'critical'),
            'high': sum(1 for f in findings if f.severity == 'high'),
            'medium': sum(1 for f in findings if f.severity == 'medium'),
            'low': sum(1 for f in findings if f.severity == 'low'),
            'info': sum(1 for f in findings if f.severity == 'info'),
        }

        layers_evaluated: List[str] = list({f.source_layer for f in findings})

        return {
            'overall': overall,
            'status': self._get_status(overall),
            'dimensions': dimensions,
            'dimension_details': dimension_details,
            'confidence': confidence,
            'severity_counts': severity_counts,
            'correlation_count': len(correlations),
            'top_risks': self._identify_top_risks(findings, correlations),
            'top_actions': self._generate_top_actions(findings, correlations),
            'layers_evaluated': layers_evaluated,
            'layers_with_data': len(layers_evaluated),
        }

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _calculate_confidence(self, findings: List) -> int:
        total_layers = 12
        layers_with_data = len({f.source_layer for f in findings})
        base_confidence = (layers_with_data / total_layers) * 100

        total = len(findings) if findings else 1
        high_confidence = sum(1 for f in findings if getattr(f, 'confidence', 0) >= 80)
        data_quality = (high_confidence / total) * 100

        return round((base_confidence * 0.6) + (data_quality * 0.4))

    def _get_status(self, overall: int) -> str:
        if overall >= 90:
            return TrustScoreStatusChoices.EXCELLENT
        if overall >= 70:
            return TrustScoreStatusChoices.GOOD
        if overall >= 50:
            return TrustScoreStatusChoices.FAIR
        if overall >= 30:
            return TrustScoreStatusChoices.POOR
        return TrustScoreStatusChoices.CRITICAL

    def _identify_top_risks(self, findings: List, correlations: List) -> List[Dict]:
        risks: List[Dict] = []

        for corr in correlations:
            risks.append({
                'type': 'correlation',
                'pattern': corr.pattern_name,
                'risk_level': corr.risk_level,
                'description': corr.narrative,
                'affected_dimensions': getattr(corr, 'affected_dimensions', []),
                'estimated_impact': getattr(corr, 'estimated_score_impact', 0),
            })

        for f in [x for x in findings if x.severity == 'critical'][:5]:
            risks.append({
                'type': 'finding',
                'title': f.title,
                'severity': f.severity,
                'dimension': f.dimension,
                'description': getattr(f, 'finding_summary', f.title),
                'remediation': getattr(f, 'remediation_action', ''),
            })

        for f in [x for x in findings if x.severity == 'high'][:3]:
            risks.append({
                'type': 'finding',
                'title': f.title,
                'severity': f.severity,
                'dimension': f.dimension,
                'description': getattr(f, 'finding_summary', f.title),
                'remediation': getattr(f, 'remediation_action', ''),
            })

        return risks[:10]

    def _generate_top_actions(self, findings: List, correlations: List) -> List[Dict]:
        actions: List[Dict] = []

        for corr in [c for c in correlations if c.risk_level == 'critical']:
            for i, step in enumerate(getattr(corr, 'remediation_steps', [])):
                actions.append({
                    'priority': len(actions) + 1,
                    'action': step,
                    'correlation': corr.pattern_name,
                    'impact': getattr(corr, 'estimated_score_impact', 0),
                    'effort': 'High' if i == 0 else 'Medium',
                })

        for f in [x for x in findings if x.severity == 'critical' and getattr(x, 'remediation_action', '')][:5]:
            actions.append({
                'priority': len(actions) + 1,
                'action': f.remediation_action,
                'finding': f.title,
                'impact': getattr(f, 'impact_score', -20),
                'effort': getattr(f, 'remediation_effort', 'Medium'),
            })

        for f in [x for x in findings if x.severity == 'high' and getattr(x, 'remediation_action', '')][:3]:
            actions.append({
                'priority': len(actions) + 1,
                'action': f.remediation_action,
                'finding': f.title,
                'impact': getattr(f, 'impact_score', -10),
                'effort': getattr(f, 'remediation_effort', 'Medium'),
            })

        # Deduplicate by action text
        seen: set = set()
        unique: List[Dict] = []
        for a in actions:
            key = a['action']
            if key not in seen:
                seen.add(key)
                unique.append(a)

        return unique[:10]
