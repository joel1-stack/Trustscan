import uuid
from django.db import models
from django.utils import timezone
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    DimensionChoices, TrustScoreStatusChoices
)


class TrustScore(UUIDTimestampedSoftDeleteModel):
    scan_job = models.OneToOneField(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='trust_score_obj'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='trust_scores'
    )
    
    overall = models.PositiveSmallIntegerField(default=0, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=TrustScoreStatusChoices.choices,
        default=TrustScoreStatusChoices.FAIR,
        db_index=True
    )
    
    email_security = models.PositiveSmallIntegerField(default=100)
    infrastructure_hygiene = models.PositiveSmallIntegerField(default=100)
    exposure_surface = models.PositiveSmallIntegerField(default=100)
    breach_history = models.PositiveSmallIntegerField(default=100)
    reputation_trust = models.PositiveSmallIntegerField(default=100)
    identity_integrity = models.PositiveSmallIntegerField(default=100)
    
    confidence = models.PositiveSmallIntegerField(default=0)
    scoring_version = models.CharField(max_length=20, default='2026.1')
    
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)
    correlation_count = models.PositiveIntegerField(default=0)
    
    top_risks = models.JSONField(default=list)
    top_actions = models.JSONField(default=list)
    
    calculated_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    previous_score = models.PositiveSmallIntegerField(null=True, blank=True)
    score_change = models.SmallIntegerField(default=0)
    
    layers_evaluated = models.JSONField(default=list)
    layers_with_data = models.PositiveSmallIntegerField(default=0)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'scoring_trustscore'
        verbose_name = 'Trust Score'
        verbose_name_plural = 'Trust Scores'
        ordering = ['-calculated_at']
        indexes = [
            models.Index(fields=['domain', '-calculated_at']),
            models.Index(fields=['overall']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.domain} - {self.overall} ({self.status})"

    @property
    def dimensions(self):
        return {
            DimensionChoices.EMAIL_SECURITY: self.email_security,
            DimensionChoices.INFRASTRUCTURE_HYGIENE: self.infrastructure_hygiene,
            DimensionChoices.EXPOSURE_SURFACE: self.exposure_surface,
            DimensionChoices.BREACH_HISTORY: self.breach_history,
            DimensionChoices.REPUTATION_TRUST: self.reputation_trust,
            DimensionChoices.IDENTITY_INTEGRITY: self.identity_integrity,
        }

    def get_dimension_display(self, dimension):
        values = {
            DimensionChoices.EMAIL_SECURITY: self.email_security,
            DimensionChoices.INFRASTRUCTURE_HYGIENE: self.infrastructure_hygiene,
            DimensionChoices.EXPOSURE_SURFACE: self.exposure_surface,
            DimensionChoices.BREACH_HISTORY: self.breach_history,
            DimensionChoices.REPUTATION_TRUST: self.reputation_trust,
            DimensionChoices.IDENTITY_INTEGRITY: self.identity_integrity,
        }
        return values.get(dimension, 0)


class DimensionScore(UUIDTimestampedSoftDeleteModel):
    trust_score = models.ForeignKey(
        TrustScore,
        on_delete=models.CASCADE,
        related_name='dimension_scores'
    )
    
    dimension = models.CharField(max_length=30, choices=DimensionChoices.choices)
    score = models.PositiveSmallIntegerField(default=100)
    base_score = models.PositiveSmallIntegerField(default=100)
    
    signal_penalties = models.JSONField(default=list)
    signal_bonuses = models.JSONField(default=list)
    correlation_penalties = models.JSONField(default=list)
    
    critical_findings = models.PositiveIntegerField(default=0)
    high_findings = models.PositiveIntegerField(default=0)
    medium_findings = models.PositiveIntegerField(default=0)
    low_findings = models.PositiveIntegerField(default=0)
    info_findings = models.PositiveIntegerField(default=0)
    
    signals_evaluated = models.PositiveIntegerField(default=0)
    correlations_applied = models.PositiveIntegerField(default=0)
    
    confidence = models.PositiveSmallIntegerField(default=0)
    data_completeness = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'scoring_dimensionscore'
        verbose_name = 'Dimension Score'
        verbose_name_plural = 'Dimension Scores'
        unique_together = [['trust_score', 'dimension']]

    def __str__(self):
        return f"{self.trust_score} - {self.dimension}: {self.score}"


class ScoringRule(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=100)
    description = models.TextField()
    
    dimension = models.CharField(max_length=30, choices=DimensionChoices.choices)
    
    condition = models.JSONField()
    impact = models.SmallIntegerField()
    severity_threshold = models.CharField(
        max_length=10,
        choices=[
            ('info', 'Info'),
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        default='medium'
    )
    
    applies_to_layers = models.JSONField(default=list)
    applies_to_signal_types = models.JSONField(default=list)
    applies_to_signal_categories = models.JSONField(default=list)
    
    weight = models.DecimalField(max_digits=3, decimal_places=2, default=1.00)
    is_bonus = models.BooleanField(default=False)
    
    is_active = models.BooleanField(default=True)
    version = models.CharField(max_length=20, default='1.0')
    priority = models.PositiveSmallIntegerField(default=100)
    
    tags = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'scoring_rule'
        verbose_name = 'Scoring Rule'
        verbose_name_plural = 'Scoring Rules'
        ordering = ['dimension', 'priority']

    def __str__(self):
        return f"{self.dimension} - {self.name} ({'+' if self.is_bonus else ''}{self.impact})"


class ScoringAlgorithmVersion(UUIDTimestampedSoftDeleteModel):
    version = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    
    dimension_weights = models.JSONField()
    rule_version = models.CharField(max_length=20)
    
    is_active = models.BooleanField(default=False)
    is_deprecated = models.BooleanField(default=False)
    deprecated_at = models.DateTimeField(null=True, blank=True)
    
    effective_from = models.DateTimeField()
    effective_until = models.DateTimeField(null=True, blank=True)
    
    changelog = models.TextField(blank=True)
    migration_notes = models.TextField(blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'scoring_algorithmversion'
        verbose_name = 'Scoring Algorithm Version'
        verbose_name_plural = 'Scoring Algorithm Versions'
        ordering = ['-effective_from']

    def __str__(self):
        return f"{self.name} v{self.version}"