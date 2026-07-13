import uuid
from django.db import models
from django.utils import timezone
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    SeverityChoices, RiskLevelChoices, CorrelationPatternChoices,
    RemediationPriorityChoices, DimensionChoices
)


class Correlation(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='correlations'
    )
    
    pattern_id = models.CharField(
        max_length=20,
        choices=CorrelationPatternChoices.choices,
        db_index=True
    )
    pattern_name = models.CharField(max_length=100)
    
    risk_level = models.CharField(
        max_length=10,
        choices=RiskLevelChoices.choices,
        db_index=True
    )
    
    narrative = models.TextField()
    short_description = models.CharField(max_length=255)
    
    contributing_findings = models.JSONField(default=list)
    contributing_signals = models.JSONField(default=list)
    
    affected_dimensions = models.JSONField(default=list)
    
    remediation_priority = models.PositiveSmallIntegerField(
        choices=RemediationPriorityChoices.choices,
        default=RemediationPriorityChoices.HIGH
    )
    remediation_steps = models.JSONField(default=list)
    estimated_score_impact = models.SmallIntegerField(default=0)
    
    confidence = models.PositiveSmallIntegerField(default=0)
    is_suppressed = models.BooleanField(default=False)
    suppression_reason = models.TextField(blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'correlation_correlation'
        verbose_name = 'Correlation'
        verbose_name_plural = 'Correlations'
        ordering = ['-risk_level', '-created_at']
        indexes = [
            models.Index(fields=['scan_job', 'risk_level']),
            models.Index(fields=['pattern_id']),
        ]

    def __str__(self):
        return f"{self.pattern_name} ({self.risk_level})"


class CorrelationRule(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    pattern_id = models.CharField(max_length=20, unique=True)
    
    risk_level = models.CharField(max_length=10, choices=RiskLevelChoices.choices)
    
    condition = models.JSONField()
    logic_expression = models.TextField()
    
    narrative_template = models.TextField()
    affected_dimensions = models.JSONField(default=list)
    
    remediation_priority = models.PositiveSmallIntegerField(
        choices=RemediationPriorityChoices.choices,
        default=RemediationPriorityChoices.HIGH
    )
    remediation_steps = models.JSONField(default=list)
    estimated_score_impact = models.SmallIntegerField(default=0)
    
    is_active = models.BooleanField(default=True)
    version = models.CharField(max_length=20, default='1.0')
    
    applies_to_scan_types = models.JSONField(default=list)
    required_layers = models.JSONField(default=list)
    
    tags = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'correlation_rule'
        verbose_name = 'Correlation Rule'
        verbose_name_plural = 'Correlation Rules'

    def __str__(self):
        return f"{self.name} ({self.pattern_id})"


class PatternMatch(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='pattern_matches'
    )
    rule = models.ForeignKey(
        CorrelationRule,
        on_delete=models.CASCADE,
        related_name='matches'
    )
    
    matched_findings = models.JSONField(default=list)
    matched_signals = models.JSONField(default=list)
    
    evaluation_result = models.JSONField(default=dict)
    matched = models.BooleanField(default=False)
    
    evaluation_time_ms = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = 'correlation_patternmatch'
        verbose_name = 'Pattern Match'
        verbose_name_plural = 'Pattern Matches'
        unique_together = [['scan_job', 'rule']]

    def __str__(self):
        return f"{self.rule.name} - {'MATCHED' if self.matched else 'NO MATCH'}"