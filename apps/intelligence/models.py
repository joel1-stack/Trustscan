import uuid
from django.db import models
from django.utils import timezone
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    IndustryChoices, ComplianceLevelChoices, TrendDirectionChoices,
    ThreatCategory
)


class IntelligenceBrief(UUIDTimestampedSoftDeleteModel):
    scan_job = models.OneToOneField(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='intelligence_brief'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='intelligence_briefs'
    )
    trust_score = models.ForeignKey(
        'scoring.TrustScore',
        on_delete=models.CASCADE,
        related_name='intelligence_briefs'
    )
    
    industry = models.CharField(max_length=30, choices=IndustryChoices.choices)
    industry_average = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    industry_percentile = models.PositiveSmallIntegerField(default=50)
    industry_rank = models.PositiveIntegerField(null=True, blank=True)
    industry_total_domains = models.PositiveIntegerField(default=0)
    
    tld_average = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    tld_percentile = models.PositiveSmallIntegerField(default=50)
    
    previous_scan_date = models.DateTimeField(null=True, blank=True)
    previous_score = models.PositiveSmallIntegerField(null=True, blank=True)
    score_change = models.SmallIntegerField(default=0)
    score_change_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    new_findings = models.PositiveIntegerField(default=0)
    resolved_findings = models.PositiveIntegerField(default=0)
    worsened_findings = models.PositiveIntegerField(default=0)
    improved_findings = models.PositiveIntegerField(default=0)
    trend_direction = models.CharField(max_length=20, choices=TrendDirectionChoices.choices, default=TrendDirectionChoices.STABLE)
    
    active_campaigns = models.JSONField(default=list)
    new_cves = models.JSONField(default=list)
    regional_threats = models.JSONField(default=list)
    threat_summary = models.TextField(blank=True)
    
    regulation = models.CharField(max_length=100, default='Kenya Data Protection Act 2019')
    compliance_level = models.CharField(max_length=20, choices=ComplianceLevelChoices.choices, default=ComplianceLevelChoices.NOT_ASSESSED)
    compliance_gaps = models.JSONField(default=list)
    next_review_date = models.DateTimeField(null=True, blank=True)
    
    risk_window = models.CharField(max_length=50, default='6 months')
    incident_probability = models.DecimalField(max_digits=3, decimal_places=2, default=0)
    primary_risk_vector = models.CharField(max_length=255, blank=True)
    mitigation_urgency = models.CharField(max_length=10, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='medium')
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'intelligence_intelligencebrief'
        verbose_name = 'Intelligence Brief'
        verbose_name_plural = 'Intelligence Briefs'
        ordering = ['-created_at']

    def __str__(self):
        return f"Intelligence Brief for {self.domain} ({self.scan_job.id})"


class Benchmark(UUIDTimestampedSoftDeleteModel):
    industry = models.CharField(max_length=30, choices=IndustryChoices.choices, db_index=True)
    tld = models.CharField(max_length=50, blank=True, db_index=True)
    
    period_start = models.DateTimeField(db_index=True)
    period_end = models.DateTimeField()
    
    sample_size = models.PositiveIntegerField(default=0)
    average_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    median_score = models.PositiveSmallIntegerField(default=0)
    std_deviation = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    percentiles = models.JSONField(default=dict)
    top_score = models.PositiveSmallIntegerField(default=0)
    bottom_score = models.PositiveSmallIntegerField(default=0)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'intelligence_benchmark'
        verbose_name = 'Benchmark'
        verbose_name_plural = 'Benchmarks'
        unique_together = [['industry', 'tld', 'period_start']]
        ordering = ['-period_start']

    def __str__(self):
        return f"Benchmark: {self.industry}/{self.tld or 'all'} ({self.period_start.date()})"


class ThreatIntel(UUIDTimestampedSoftDeleteModel):
    indicator_type = models.CharField(max_length=30, choices=[
        ('domain', 'Domain'),
        ('ip', 'IP Address'),
        ('email', 'Email'),
        ('url', 'URL'),
        ('hash', 'File Hash'),
        ('cve', 'CVE'),
    ])
    indicator_value = models.CharField(max_length=500, db_index=True)
    
    threat_category = models.CharField(max_length=30, choices=ThreatCategory.choices)
    severity = models.CharField(max_length=10, choices=[
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ])
    confidence = models.PositiveSmallIntegerField(default=50)
    
    source = models.CharField(max_length=100)
    source_url = models.URLField(blank=True)
    
    description = models.TextField(blank=True)
    context = models.JSONField(default=dict)
    
    tags = models.JSONField(default=list)
    iocs = models.JSONField(default=list)
    
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    is_false_positive = models.BooleanField(default=False)
    
    related_domains = models.ManyToManyField(
        'domains.Domain',
        related_name='threat_intel',
        blank=True
    )

    class Meta:
        db_table = 'intelligence_threatintel'
        verbose_name = 'Threat Intelligence'
        verbose_name_plural = 'Threat Intelligence'
        indexes = [
            models.Index(fields=['indicator_type', 'indicator_value']),
            models.Index(fields=['is_active', 'expires_at']),
            models.Index(fields=['threat_category']),
        ]

    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value} ({self.threat_category})"


class CVEFeed(UUIDTimestampedSoftDeleteModel):
    cve_id = models.CharField(max_length=20, unique=True, db_index=True)
    description = models.TextField()
    
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, blank=True)
    severity = models.CharField(max_length=10, choices=[
        ('none', 'None'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ])
    
    affected_products = models.JSONField(default=list)
    affected_versions = models.JSONField(default=list)
    fixed_versions = models.JSONField(default=list)
    
    references = models.JSONField(default=list)
    cwe_ids = models.JSONField(default=list)
    
    published_date = models.DateTimeField()
    modified_date = models.DateTimeField()
    
    is_kev = models.BooleanField(default=False)
    epss_score = models.DecimalField(max_digits=4, decimal_places=3, default=0)
    
    source = models.CharField(max_length=50, default='NVD')
    source_url = models.URLField(blank=True)

    class Meta:
        db_table = 'intelligence_cvefeed'
        verbose_name = 'CVE Feed'
        verbose_name_plural = 'CVE Feeds'
        ordering = ['-published_date']

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"


class ThreatCampaign(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    threat_actor = models.CharField(max_length=255, blank=True)
    target_sectors = models.JSONField(default=list)
    target_countries = models.JSONField(default=list)
    target_tlds = models.JSONField(default=list)
    
    tactics = models.JSONField(default=list)
    techniques = models.JSONField(default=list)
    procedures = models.JSONField(default=list)
    
    iocs = models.JSONField(default=list)
    detection_rules = models.JSONField(default=list)
    
    first_seen = models.DateTimeField()
    last_activity = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    
    confidence = models.PositiveSmallIntegerField(default=50)
    attribution = models.CharField(max_length=100, blank=True)
    
    source = models.CharField(max_length=100)
    source_url = models.URLField(blank=True)

    class Meta:
        db_table = 'intelligence_threatcampaign'
        verbose_name = 'Threat Campaign'
        verbose_name_plural = 'Threat Campaigns'
        ordering = ['-last_activity']

    def __str__(self):
        return self.name


class RegulatoryMapping(UUIDTimestampedSoftDeleteModel):
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='regulatory_mappings'
    )
    regulation = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='identified')
    notes = models.TextField(blank=True)

    class Meta:
        db_table = 'intelligence_regulatorymapping'
        verbose_name = 'Regulatory Mapping'
        verbose_name_plural = 'Regulatory Mappings'

    def __str__(self):
        return f"{self.domain} - {self.regulation}"