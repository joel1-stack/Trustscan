import uuid
from django.db import models
from django.utils import timezone
from django.conf import settings
from apps.core.models import UUIDTimestampedModel, SoftDeleteModel
from apps.core.constants import (
    ScanTypeChoices, ScanStatusChoices, AuthorizationStatusChoices,
    SeverityChoices, RiskLevelChoices, TrendDirectionChoices
)


class ScanSchedule(UUIDTimestampedModel, SoftDeleteModel):
    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
    ]

    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='scan_schedules'
    )
    name = models.CharField(max_length=100)
    scan_type = models.CharField(max_length=30, choices=ScanTypeChoices.choices, default=ScanTypeChoices.DOMAIN_FULL)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES, default='weekly')
    day_of_week = models.PositiveSmallIntegerField(null=True, blank=True)
    day_of_month = models.PositiveSmallIntegerField(null=True, blank=True)
    hour = models.PositiveSmallIntegerField(default=2)
    minute = models.PositiveSmallIntegerField(default=0)
    timezone = models.CharField(max_length=50, default='Africa/Nairobi')
    is_active = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True, db_index=True)
    notification_channels = models.JSONField(default=list)
    created_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_schedules'
    )

    class Meta:
        db_table = 'scanner_schedule'
        verbose_name = 'Scan Schedule'
        verbose_name_plural = 'Scan Schedules'
        ordering = ['next_run_at']

    def __str__(self):
        return f"{self.domain} - {self.frequency} {self.scan_type}"


class ScanJob(UUIDTimestampedModel):
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='scan_jobs'
    )
    schedule = models.ForeignKey(
        ScanSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan_jobs'
    )
    scan_type = models.CharField(max_length=30, choices=ScanTypeChoices.choices, default=ScanTypeChoices.DOMAIN_FULL)
    trigger_source = models.CharField(max_length=30, choices=[
        ('manual', 'Manual'),
        ('scheduled', 'Scheduled'),
        ('api', 'API'),
        ('webhook', 'Webhook'),
    ], default='manual')
    triggered_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='triggered_scans'
    )
    
    status = models.CharField(
        max_length=20,
        choices=ScanStatusChoices.choices,
        default=ScanStatusChoices.PENDING,
        db_index=True
    )
    previous_status = models.CharField(max_length=20, choices=ScanStatusChoices.choices, blank=True)
    status_changed_at = models.DateTimeField(auto_now_add=True)
    
    authorization_verified = models.BooleanField(default=False)
    authorization_status = models.CharField(
        max_length=30,
        choices=AuthorizationStatusChoices.choices,
        blank=True
    )
    authorization_scope = models.JSONField(default=list)
    
    celery_task_id = models.CharField(max_length=100, blank=True)
    celery_parent_id = models.CharField(max_length=100, blank=True)
    
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)
    
    current_phase = models.CharField(max_length=30, blank=True)
    phase_started_at = models.DateTimeField(null=True, blank=True)
    phase_progress = models.PositiveSmallIntegerField(default=0)
    
    error_message = models.TextField(blank=True)
    error_details = models.JSONField(default=dict)
    retry_count = models.PositiveSmallIntegerField(default=0)
    max_retries = models.PositiveSmallIntegerField(default=3)
    
    findings_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    info_count = models.PositiveIntegerField(default=0)
    
    trust_score = models.PositiveSmallIntegerField(null=True, blank=True)
    score_status = models.CharField(max_length=20, blank=True)
    dimension_scores = models.JSONField(default=dict)
    confidence_level = models.PositiveSmallIntegerField(default=0)
    
    reports_generated = models.JSONField(default=list)
    notifications_sent = models.JSONField(default=list)
    
    metadata = models.JSONField(default=dict)
    tags = models.JSONField(default=list)

    class Meta:
        db_table = 'scanner_scanjob'
        verbose_name = 'Scan Job'
        verbose_name_plural = 'Scan Jobs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['domain', 'status']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['triggered_by', 'status']),
            models.Index(fields=['celery_task_id']),
        ]

    def __str__(self):
        return f"Scan #{str(self.id)[:8]} - {self.domain} - {self.status}"

    @property
    def is_terminal(self):
        return self.status in ScanStatusChoices.TERMINAL_STATES

    @property
    def is_active(self):
        return self.status in ScanStatusChoices.ACTIVE_STATES

    @property
    def can_cancel(self):
        return self.is_active and not self.is_terminal

    def transition_to(self, new_status, error_message=''):
        self.previous_status = self.status
        self.status = new_status
        self.status_changed_at = timezone.now()
        if error_message:
            self.error_message = error_message
        if new_status in ScanStatusChoices.TERMINAL_STATES:
            self.completed_at = timezone.now()
            if self.started_at:
                self.duration_seconds = int((self.completed_at - self.started_at).total_seconds())
        self.save(update_fields=[
            'previous_status', 'status', 'status_changed_at',
            'error_message', 'completed_at', 'duration_seconds'
        ])

    def start(self):
        self.started_at = timezone.now()
        self.status_changed_at = timezone.now()
        self.save(update_fields=['started_at', 'status_changed_at'])

    def start_phase(self, phase_name):
        self.current_phase = phase_name
        self.phase_started_at = timezone.now()
        self.phase_progress = 0
        self.save(update_fields=['current_phase', 'phase_started_at', 'phase_progress'])

    def update_phase_progress(self, progress):
        self.phase_progress = progress
        self.save(update_fields=['phase_progress'])


class ScanPhaseLog(UUIDTimestampedModel):
    scan_job = models.ForeignKey(
        ScanJob,
        on_delete=models.CASCADE,
        related_name='phase_logs'
    )
    phase = models.CharField(max_length=30)
    status = models.CharField(max_length=20, choices=[
        ('started', 'Started'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
    ])
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.PositiveIntegerField(null=True, blank=True)
    findings_count = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'scanner_phaselog'
        verbose_name = 'Scan Phase Log'
        verbose_name_plural = 'Scan Phase Logs'
        ordering = ['created_at']

    def __str__(self):
        return f"{self.scan_job} - {self.phase} - {self.status}"


class ScanComparison(UUIDTimestampedModel):
    scan_job = models.ForeignKey(
        ScanJob,
        on_delete=models.CASCADE,
        related_name='comparisons'
    )
    previous_scan_job = models.ForeignKey(
        ScanJob,
        on_delete=models.CASCADE,
        related_name='next_comparisons'
    )
    score_change = models.SmallIntegerField(default=0)
    score_change_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    new_findings = models.PositiveIntegerField(default=0)
    resolved_findings = models.PositiveIntegerField(default=0)
    worsened_findings = models.PositiveIntegerField(default=0)
    improved_findings = models.PositiveIntegerField(default=0)
    new_critical = models.PositiveIntegerField(default=0)
    new_high = models.PositiveIntegerField(default=0)
    trend_direction = models.CharField(max_length=20, choices=TrendDirectionChoices.choices)
    comparison_data = models.JSONField(default=dict)

    class Meta:
        db_table = 'scanner_comparison'
        verbose_name = 'Scan Comparison'
        verbose_name_plural = 'Scan Comparisons'
        unique_together = [['scan_job', 'previous_scan_job']]

    def __str__(self):
        return f"{self.scan_job} vs {self.previous_scan_job} - {self.trend_direction}"